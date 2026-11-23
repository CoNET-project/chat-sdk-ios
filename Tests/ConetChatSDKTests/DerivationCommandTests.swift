import Foundation
import XCTest
@testable import ConetChatSDK

/// The bridge answers of C5 `deriveSubkeys`, W7 `ephemeralSign`, and the refusal of C1 `historySign` (spec,
///). The gate is G2 with the public BIP-39 test key in the native store. The vector values come from
/// DERIVATION_VECTORS (skipped without it).
final class DerivationCommandTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let otherAccount = "0x1111111111111111111111111111111111111111"
	private var savedStore: BeamioChatWalletKeyStoring?
	private var store = DerivationKeyStore()

	final class DerivationKeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = DerivationKeyStore()
		BeamioNativeWallet.keyStore = store
		let privateKey = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
		store.keys[account] = privateKey
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioVoiceEphemeral.clear(sid: sid)
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private let sid = "0123456789abcdef0123456789abcdef"
	private let wk = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw="

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["DERIVATION_VECTORS"] else {
			throw XCTSkip("set DERIVATION_VECTORS to interface/protocol/derivation-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			events.append((event["event"] as? [String: Any]) ?? event)
		})
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	func testDeriveSubkeysAnswersTheFourSubkeysAndNoRoot() throws {
		let vectors = try vectorRoot()
		let cases = try XCTUnwrap(vectors["cases"] as? [[String: Any]])
		let d07 = try XCTUnwrap(cases.first { $0["id"] as? String == "D-07" }?["expect"] as? [String: Any])
		let d06 = try XCTUnwrap(cases.first { $0["id"] as? String == "D-06" }?["expect"] as? [String: Any])
		let events = dispatch(["type": "deriveSubkeys", "reqId": 9001])
		let answer = try XCTUnwrap(events.first)
		XCTAssertEqual(answer["ok"] as? Bool, true)
		let result = try XCTUnwrap(answer["result"] as? [String: Any])
		XCTAssertEqual(Set(result.keys), ["kId", "kIdx", "dek", "kcv"], "only the four subkeys are returned (25.43.6)")
		XCTAssertEqual(result["kId"] as? String, d07["kId"] as? String)
		XCTAssertEqual(result["kIdx"] as? String, d07["kIdx"] as? String)
		XCTAssertEqual(result["dek"] as? String, d07["dek"] as? String)
		XCTAssertEqual(result["kcv"] as? String, d07["kcv"] as? String)
		XCTAssertFalse(result.values.contains { ($0 as? String) == (d06["RDB"] as? String) }, "R_db is not returned")
	}

	func testDeriveSubkeysForAnotherAccountIsRefused() {
		BeamioConetChatSignBroker.setSignerEoa(account)
		let events = dispatch(["type": "deriveSubkeys", "reqId": 9002, "eoa": otherAccount])
		XCTAssertEqual(events.first?["error"] as? String, "address_mismatch")
		XCTAssertNil(events.first?["result"])
	}

	func testEphemeralSignForAnUnknownChannelIsUnknownChannel() {
		let events = dispatch(["type": "ephemeralSign", "reqId": 9003, "sid": "ffffffffffffffffffffffffffffffff",
		                       "wk": wk, "relayKeyId": "SYN-PGPKEYID-A-0001", "timestamp": 1762992000])
		XCTAssertEqual(events.first?["error"] as? String, "unknown_channel")
	}

	func testEphemeralSignRefusesMalformedInputs() {
		BeamioVoiceEphemeral.register(sid: sid, privateKey: [UInt8](repeating: 0x5a, count: 32))
		let base: [String: Any] = ["type": "ephemeralSign", "reqId": 9004, "sid": sid, "wk": wk,
		                           "relayKeyId": "SYN-PGPKEYID-A-0001", "timestamp": 1762992000]
		var uppercaseSid = base
		uppercaseSid["sid"] = sid.uppercased()
		var shortWk = base
		shortWk["wk"] = "AAAA"
		var payKind = base
		payKind["kind"] = "voicePay"
		var textTime = base
		textTime["timestamp"] = "1762992000"
		for body in [uppercaseSid, shortWk, payKind, textTime] {
			XCTAssertEqual(dispatch(body).first?["error"] as? String, "bad_request")
		}
	}

	func testEphemeralSignListenMatchesTheVector() throws {
		let vectors = try vectorRoot()
		let cases = try XCTUnwrap(vectors["cases"] as? [[String: Any]])
		let w01 = try XCTUnwrap(cases.first { $0["id"] as? String == "W-01" }?["expect"] as? [String: Any])
		let tk = [UInt8](repeating: 0x5a, count: 32)
		XCTAssertTrue(BeamioVoiceEphemeral.register(sid: sid, privateKey: tk))
		let events = dispatch(["type": "ephemeralSign", "reqId": 9005, "sid": sid, "wk": wk,
		                       "relayKeyId": "syn-pgpkeyid-a-0001", "timestamp": 1762992000])
		let answer = try XCTUnwrap(events.first)
		XCTAssertEqual(answer["ok"] as? Bool, true)
		let result = try XCTUnwrap(answer["result"] as? [String: Any])
		XCTAssertEqual(result["temp"] as? String, w01["temp"] as? String)
		XCTAssertEqual(result["tempSig"] as? String, w01["tempSig"] as? String)
		XCTAssertEqual(Set(result.keys), ["temp", "tempSig"], "no key material is returned")
	}

	func testHistorySignStaysRefusedOnTheBridge() {
		let events = dispatch(["type": "historySign", "reqId": 9006])
		XCTAssertEqual(events.first?["error"] as? String, "not_supported")
		XCTAssertNil(events.first?["result"])
	}
	private func vectorExpect(_ id: String) throws -> [String: Any] {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return try XCTUnwrap(cases.first { $0["id"] as? String == id }?["expect"] as? [String: Any])
	}

	/// W2 in-process: the subkeys {DEK, K_idx, K_id}, equal to the D-07 values of the vector. No root is returned.
	func testLocalSubkeysAnswerTheVectorSubkeys() throws {
		let d07 = try vectorExpect("D-07")
		let result = try XCTUnwrap(BeamioConetChatModule.localSubkeys(account: account))
		XCTAssertEqual(Set(result.keys), ["DEK", "K_idx", "K_id"])
		XCTAssertEqual(result["DEK"] as? String, d07["dek"] as? String)
		XCTAssertEqual(result["K_idx"] as? String, d07["kIdx"] as? String)
		XCTAssertEqual(result["K_id"] as? String, d07["kId"] as? String)
	}

	/// W3 in-process: indexEncKey and genesisCid, equal to the D-02 and D-03 values of the vector.
	func testProtocolValuesAnswerTheVectorValues() throws {
		BeamioConetChatSignBroker.setSignerEoa(account)
		defer { BeamioConetChatSignBroker.clearSigner() }
		let d02 = try vectorExpect("D-02")
		let d03 = try vectorExpect("D-03")
		let result = try XCTUnwrap(BeamioConetChatModule.protocolValues(account: account))
		XCTAssertEqual(Set(result.keys), ["indexEncKey", "genesisCid"])
		XCTAssertEqual(result["indexEncKey"], d02["indexEncKey"] as? String)
		XCTAssertEqual(result["genesisCid"], d03["genesisCid"] as? String)
	}

	/// W2 and W3 are not bridge commands and have no PWA caller. The bridge answers them as unknown, with no
	/// key material, for the account and for another account alike.
	func testW2AndW3AreNotBridgeCommands() {
		for type in ["deriveLocalKeys", "protocolKeys"] {
			for eoa in [account, "0x1111111111111111111111111111111111111111"] {
				let events = dispatch(["type": type, "reqId": 9400, "eoa": eoa])
				XCTAssertEqual(events.first?["error"] as? String, "unknown_command", type)
				XCTAssertNil(events.first?["result"], type)
			}
		}
	}
}
