import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The W fields of the recovery result: with `ok` only, the key as the store holds it,
/// the phrase; path A leaves `recoveryWords` out by default. Synthetic record and the stand-in KDF of
/// RecoveryRestoreTests; no real argon2id is run here.
final class NativeResultWalletFieldsTests: XCTestCase {
	private let code = "Ab3dE5fG7hJ9kL1mN3pQ5r"        // 22 base62 characters
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private var store: RecoveryRestoreTests.MemoryKeyStore!
	private var events: [[String: Any]] = []
	private var savedRegistry: BeamioRecoveryRegistryReading?
	private var savedKDF: BeamioNativeRecovery.KeyDerivation?
	private var savedHost: ((String) -> Bool)?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		store = RecoveryRestoreTests.MemoryKeyStore()
		savedRegistry = BeamioNativeRecovery.registry
		savedKDF = BeamioNativeRecovery.keyDerivation
		savedHost = BeamioNativeRecovery.onRecoveryRequired
		BeamioNativeRecovery.keyDerivation = RecoveryRestoreTests.StandInKDF()
		BeamioNativeRecovery.onRecoveryRequired = { _ in true }
		events = []
	}

	override func tearDown() {
		BeamioConetChatModule.closeRecoveryPage()
		_ = drain()
		BeamioNativeRecovery.registry = savedRegistry
		BeamioNativeRecovery.keyDerivation = savedKDF
		BeamioNativeRecovery.onRecoveryRequired = savedHost
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// Lets the main queue deliver the events posted asynchronously, then returns every event received since the page opened.
	private func drain() -> [[String: Any]] {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	/// Opens the recovery page as the bridge does, and forgets the ack.
	private func openPage(reqId: String) {
		BeamioConetChatModule.handleCommand(["type": "nativeRecoveryOpen", "reqId": reqId], emit: { [weak self] event in
			let payload = (event["event"] as? [String: Any]) ?? event
			// a new pointer is announced by a passcodeState event (reason account_switch): not what these tests count
			if payload["type"] as? String == "passcodeState" { return }
			self?.events.append(payload)
		})
		_ = drain()
		events = []
	}

	/// The `{img, stored}` record of `phrase`, encrypted under SHA-256 of `code`: the stand-in KDF's output for that password.
	private func record(code: String) throws -> String {
		let phraseBase64 = Data(phrase.utf8).base64EncodedString()
		let key = Data(SHA256.hash(data: Data(code.utf8)))
		let sealed = try AES.GCM.seal(Data(phraseBase64.utf8), using: SymmetricKey(data: key)).combined!
		let object: [String: Any] = [
			"img": sealed.base64EncodedString(),
			"stored": ["algo": "argon2id", "v": 19, "salt": Data("salt-salt-salt!".utf8).base64EncodedString(), "hash": "synthetic", "m": 8192, "t": 1, "p": 1],
		]
		return try JSONSerialization.data(withJSONObject: object).base64EncodedString()
	}

	/// T-226, T-232, 25.52Y.152: a path A restore that ends `ok` answers the flat {type, reqId, code, eoa}; no wallet or PGP field is carried.
	func testTheOkResultCarriesNoWalletFieldOnPathA() throws {
		BeamioNativeRecovery.registry = RecoveryRestoreTests.FixedRegistry(record: try record(code: code))
		openPage(reqId: "R-W1")
		XCTAssertEqual(BeamioNativeRecovery.restore(.recoveryCode(code), store: store), .ok(eoa: account))
		BeamioNativeRecovery.finish(.ok, eoa: account)
		let sent = drain()
		XCTAssertEqual(sent.count, 1, "one result per page")
		let result = sent.first ?? [:]
		XCTAssertEqual(Set(result.keys), ["type", "reqId", "code", "eoa"], "the ok answer is flat: code and eoa only")
		XCTAssertEqual(result["eoa"] as? String, account)
		XCTAssertNil(result["privateKeyArmor"])
		XCTAssertNil(result["mnemonicPhrase"])
		XCTAssertNil(result["recoveryWords"])
	}

	/// Path B has no recovery code; the ok answer carries no wallet field either (25.52Y.152).
	func testPathBCarriesNoWalletField() throws {
		BeamioNativeRecovery.registry = RecoveryRestoreTests.FixedRegistry(record: try record(code: code))
		let savedAttempts = BeamioNativeRecovery.attempts
		BeamioNativeRecovery.attempts = RecoveryRestoreTests.MemoryAttempts()
		defer { BeamioNativeRecovery.attempts = savedAttempts }
		openPage(reqId: "R-W2")
		let outcome = BeamioNativeRecovery.restore(.account(name: "alice", password: Array(code.utf8)), store: store)
		XCTAssertEqual(outcome, .ok(eoa: account))
		BeamioNativeRecovery.finish(.ok, eoa: account)
		let result = drain().first ?? [:]
		XCTAssertEqual(Set(result.keys), ["type", "reqId", "code", "eoa"])
		XCTAssertNil(result["mnemonicPhrase"])
		XCTAssertNil(result["privateKeyArmor"])
		XCTAssertNil(result["recoveryWords"])
	}

	/// A failed attempt holds nothing: its result carries no W field.
	func testAFailureCarriesNoWalletFields() throws {
		BeamioNativeRecovery.registry = RecoveryRestoreTests.FixedRegistry(record: "")
		openPage(reqId: "R-W3")
		XCTAssertEqual(BeamioNativeRecovery.restore(.recoveryCode(code), store: store), .failed(.notFound))
		BeamioNativeRecovery.finish(.notFound)
		let result = drain().first ?? [:]
		XCTAssertEqual(Set(result.keys), ["type", "reqId", "code"])
	}

	/// The W fields go only to the account the engine restored: an `ok` for another account carries none.
	func testTheHeldWalletIsOnlyForTheRestoredAccount() throws {
		BeamioNativeRecovery.registry = RecoveryRestoreTests.FixedRegistry(record: try record(code: code))
		openPage(reqId: "R-W4")
		XCTAssertEqual(BeamioNativeRecovery.restore(.recoveryCode(code), store: store), .ok(eoa: account))
		let other = "0x0000000000000000000000000000000000000001"
		BeamioNativeRecovery.finish(.ok, eoa: other)
		let result = drain().first ?? [:]
		XCTAssertEqual(result["eoa"] as? String, other)
		XCTAssertNil(result["privateKeyArmor"])
		XCTAssertNil(result["mnemonicPhrase"])
	}

	/// The native observer gets the recovery result without the W fields; the WebView gets them whole (see above).
	func testTheObserverGetsTheRecoveryResultWithoutTheWalletFields() throws {
		var observed: [[String: Any]] = []
		let saved = BeamioConetChatModule.nativeObserver
		BeamioConetChatModule.nativeObserver = { payload in observed.append((payload["event"] as? [String: Any]) ?? [:]) }
		defer { BeamioConetChatModule.nativeObserver = saved }
		BeamioNativeRecovery.registry = RecoveryRestoreTests.FixedRegistry(record: try record(code: code))
		openPage(reqId: "R-W5")
		_ = BeamioNativeRecovery.restore(.recoveryCode(code), store: store)
		BeamioNativeRecovery.finish(.ok, eoa: account)
		_ = drain()
		let last = observed.last ?? [:]
		XCTAssertEqual(last["code"] as? String, "ok")
		XCTAssertNil(last["privateKeyArmor"])
		XCTAssertNil(last["mnemonicPhrase"])
		XCTAssertNil(last["recoveryWords"])
	}
}
