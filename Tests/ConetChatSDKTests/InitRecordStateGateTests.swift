#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The native record and `init`. The record state decides the refusal of the
/// read-back: absent is `no_key`, unreadable is `not_ready` (the record exists and cannot be read now), and a key that derives another address
/// is `not_ready` too. At G1 and G2 an `init` that names another account, or none, is `address_mismatch`: nothing is written, the session is
/// unchanged and no event is emitted. An `init` for the session's own account at G2 is idempotent: `ready`, no change. Synthetic data only.
final class InitRecordStateGateTests: XCTestCase {
	/// The test store: the record is present when a key is held, and the state follows from it (the default of).
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var writes = 0
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	/// A record that exists and cannot be read now: the storage is locked or damaged. `read` returns nothing, and the state is unreadable.
	final class UnreadableStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { nil }
		var writes = 0
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			return false
		}
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .unreadable }
	}

	/// The derivation test key (synthetic, public test material) derives this address.
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let other = "0x2222222222222222222222222222222222222222"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private let declared = [BeamioConetChatModule.identityNativeKeysCapability]
	private var savedStore: BeamioChatWalletKeyStoring!
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func initPayload(_ eoa: String) -> [String: Any] {
		["identity": ["eoaAddress": eoa] as [String: Any]]
	}

	/// The events of one reqId, after the main queue has drained.
	private func answersFor(_ reqId: Int) -> [[String: Any]] {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		return events.compactMap { $0["event"] as? [String: Any] }.filter { $0["reqId"] as? Int == reqId }
	}

	private func errors(_ reqId: Int) -> [String?] {
		answersFor(reqId).filter { $0["type"] as? String == "ack" }.map { $0["error"] as? String }
	}

	private func readyCount(_ reqId: Int) -> Int {
		answersFor(reqId).filter { $0["type"] as? String == "ready" }.count
	}

	func testAnUnreadableRecordAnswersNotReadyWithoutAnyChange() {
		let store = UnreadableStore()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "an unreadable record still exists, so the device is G1")
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 1101, "payload": initPayload(account)], capabilities: declared)
		XCTAssertEqual(errors(1101), ["not_ready"], "unreadable is not_ready, not no_key")
		XCTAssertEqual(readyCount(1101), 0)
		XCTAssertEqual(store.writes, 0)
		XCTAssertNil(BeamioConetChatModule.testCurrentSession())
	}

	/// a stored key that derives another address, for an account whose EOA matches, answers `not_ready`. Nothing is written, deleted or
	/// transferred, the gate stays G1, and no session starts. `record_mismatch` is not an init answer.
	func testAKeyThatDerivesAnotherAddressIsNotReadyAndNothingChanges() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[other] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: other, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 1102, "payload": initPayload(other)], capabilities: declared)
		XCTAssertEqual(errors(1102), ["not_ready"], "a key that derives another address is not_ready for init")
		XCTAssertEqual(readyCount(1102), 0)
		XCTAssertEqual(store.writes, 0, "nothing is written")
		XCTAssertEqual(store.keys[other], keyData, "nothing is deleted or transferred")
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "the gate stays G1")
		XCTAssertNil(BeamioConetChatModule.testCurrentSession(), "no session starts")
	}

	func testAnInitForAnotherAccountAtG2IsAddressMismatchAndChangesNothing() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		let before = BeamioConetChatModule.testCurrentSession()
		XCTAssertNotNil(before)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1103, "payload": initPayload(other)], emit: { _ in })
		XCTAssertEqual(errors(1103), ["address_mismatch"], "G2, another account: address_mismatch, not no_key")
		XCTAssertEqual(answersFor(1103).count, 1, "exactly one answer, no event")
		XCTAssertEqual(readyCount(1103), 0)
		XCTAssertEqual(store.writes, 0, "nothing is written")
		let after = BeamioConetChatModule.testCurrentSession()
		XCTAssertTrue(before === after, "the session is not replaced")
		XCTAssertEqual(after?.eoa, account)
		XCTAssertEqual(after?.ready, true)
	}

	func testAnInitWithoutAnAccountAtG2IsAddressMismatch() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1104, "payload": [String: Any]()], emit: { _ in })
		XCTAssertEqual(errors(1104), ["address_mismatch"])
		XCTAssertEqual(readyCount(1104), 0)
		XCTAssertEqual(store.writes, 0)
	}

	func testAnInitWithoutAnAccountAtG1IsAddressMismatch() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1105, "payload": [String: Any]()], emit: { _ in })
		XCTAssertEqual(errors(1105), ["address_mismatch"])
		XCTAssertNil(BeamioConetChatModule.testCurrentSession())
	}

	/// The session's own account at G2: `ready`, and the same session object (idempotent,).
	func testTheSessionsOwnAccountAtG2IsIdempotent() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		let before = BeamioConetChatModule.testCurrentSession()
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1106, "payload": initPayload(account)], emit: { _ in })
		XCTAssertEqual(readyCount(1106), 1, "ready, once")
		XCTAssertEqual(errors(1106), [], "no refusal")
		XCTAssertTrue(before === BeamioConetChatModule.testCurrentSession(), "the session is not replaced")
		XCTAssertEqual(store.writes, 0)
	}

	/// an EOA that is not the lower-case canonical form is bad_identity at G1 and G2, and is not compared.
	func testAnUpperCaseEoaIsBadIdentityAtG1AndG2() {
		let upper = "0x" + account.dropFirst(2).uppercased()
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1110, "payload": initPayload(upper)], emit: { _ in })
		XCTAssertEqual(errors(1110), ["bad_identity"], "G1: an upper-case EOA is bad_identity, not address_mismatch")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		let before = BeamioConetChatModule.testCurrentSession()
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1111, "payload": initPayload(upper)], emit: { _ in })
		XCTAssertEqual(errors(1111), ["bad_identity"], "G2: the same answer")
		XCTAssertEqual(readyCount(1111), 0)
		XCTAssertTrue(before === BeamioConetChatModule.testCurrentSession(), "the session is not changed")
		XCTAssertEqual(store.writes, 0)
	}

	/// an identity object with no EOA is address_mismatch at G1 and at G2.
	func testAnIdentityWithoutAnEoaIsAddressMismatchAtG1AndG2() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1112, "payload": ["identity": [String: Any]()]], emit: { _ in })
		XCTAssertEqual(errors(1112), ["address_mismatch"], "G1")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1113, "payload": ["identity": [String: Any]()]], emit: { _ in })
		XCTAssertEqual(errors(1113), ["address_mismatch"], "G2")
	}

	/// a public field at the top of the payload, with no identity object, is missing_identity at G1 and at G2.
	func testPublicFieldsAtTheTopLevelAreMissingIdentityAtG1AndG2() {
		let store = Store()
		BeamioNativeWallet.keyStore = store
		store.keys[account] = keyData
		let payload: [String: Any] = ["eoa": account, "pgpPublicKeyArmored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nTEST-ONLY-SYNTHETIC\n-----END PGP PUBLIC KEY BLOCK-----"]
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1114, "payload": payload], emit: { _ in })
		XCTAssertEqual(errors(1114), ["missing_identity"], "G1")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1115, "payload": payload], emit: { _ in })
		XCTAssertEqual(errors(1115), ["missing_identity"], "G2")
		XCTAssertEqual(readyCount(1115), 0)
	}

	/// at G2 a storage-derived Locked record answers not_ready, once, even though the session is ready.
	func testAStorageLockedRecordAtG2IsNotReadyEvenWithAReadySession() {
		BeamioNativeWallet.keyStore = UnreadableStore()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 1116, "payload": initPayload(account)], emit: { _ in })
		XCTAssertEqual(errors(1116), ["not_ready"])
		XCTAssertEqual(readyCount(1116), 0, "no ok answer")
	}
}
#endif
