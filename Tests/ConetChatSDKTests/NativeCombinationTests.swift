#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// the combinations the native-keys declaration rests on. `init` runs through its real path, with
/// the capability list given explicitly (the static declaration is made only after the audit). Each combination is observed through the
/// acks, the `ready` event and `walletStatus`. Synthetic key bytes and addresses only; no key material is returned.
final class NativeCombinationTests: XCTestCase {
	/// In-memory native key store (the wallet module's store in tests).
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:] {
			didSet { BeamioNativeKeySnapshot.invalidate() }
		}
		var phases: [String: BeamioChatMigrationPhase] = [:]
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
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	/// The account whose key the test store holds: the derivation test key (synthetic, public test material) derives this address.
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private let other = "0x2222222222222222222222222222222222222222"
	private let declared = [BeamioConetChatModule.identityNativeKeysCapability]
	private let undeclared = ["inbound.deferAck"]
	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		// Isolation (test-only): the account pointer lives in its own defaults suite, and the native-key snapshot is judged again for this store.
		// Without this, a snapshot or pointer left by an earlier test class answers the init of this one (order-dependent failures).
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		store = Store()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		BeamioOpenPgpHost.testForceNotReady = false
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioOpenPgpHost.testForceNotReady = false
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	// MARK: - helpers

	/// The init of a test: the account, and the `nodes` list that G1 requires. The list is synthetic.
	private func initPayload(_ eoa: String) -> [String: Any] {
		["identity": ["eoaAddress": eoa] as [String: Any],
		 "nodes": [["ip": "203.0.113.7", "domain": "node.example.invalid", "region": "test", "armoredPublicKey": "synthetic"]] as [[String: Any]]]
	}

	/// The error of each ack for this reqId, nil for an ok answer.
	private func ackErrors(_ reqId: Int) -> [String?] {
		events.compactMap { out -> String?? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack",
			      event["reqId"] as? Int == reqId else { return nil }
			return .some(event["error"] as? String)
		}
	}

	private func ackResult(_ reqId: Int) -> [String: Any]? {
		events.compactMap { out -> [String: Any]? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack",
			      event["reqId"] as? Int == reqId else { return nil }
			return event["result"] as? [String: Any]
		}.last
	}

	private func readyCount(_ reqId: Int) -> Int {
		events.filter { out in
			guard let event = out["event"] as? [String: Any] else { return false }
			return event["type"] as? String == "ready" && event["reqId"] as? Int == reqId
		}.count
	}

	/// Runs the main run loop until the condition holds or the timeout passes.
	private func waitUntil(_ timeout: TimeInterval = 60, _ condition: () -> Bool) -> Bool {
		let deadline = Date().addingTimeInterval(timeout)
		while !condition() && Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		return condition()
	}

	/// Waits until the reqId has an ack (a refusal) or a ready event (a success: the page reads init's answer from `ready`).
	private func waitForAnswer(_ reqId: Int, timeout: TimeInterval = 60) -> Bool {
		waitUntil(timeout) { !self.ackErrors(reqId).isEmpty || self.readyCount(reqId) > 0 }
	}

	/// `walletStatus` through the command, as the page sends it.
	private func walletStatus(_ reqId: Int) -> [String: Any]? {
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": reqId], emit: { _ in })
		_ = waitUntil(5) { self.ackResult(reqId) != nil }
		return ackResult(reqId)
	}

	// MARK: - declared, with a key

	/// Restore: the key is written and the pointer set, the session has not run init, so the page sees not_ready (G1). `init` with
	/// the capability reaches G2 (ready after the read-back), and the account is the restored one.
	func testADeclaredBuildWithARestoredKeyReachesG2WithoutARestart() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		XCTAssertEqual(walletStatus(900)?["status"] as? String, "no_key", "before the restore there is no record (G0)")
		store.keys[account] = keyData
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(walletStatus(901)?["status"] as? String, "not_ready", "the restored record, before init: G1")
		XCTAssertEqual(walletStatus(901)?["notReadyReason"] as? String, "g1_uninitialized", "G1 names its reason (25.52Y.117, Y.118)")
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 902, "payload": initPayload(account)], capabilities: declared)
		XCTAssertTrue(waitUntil { self.readyCount(902) > 0 }, "init succeeds: the ready event answers it")
		XCTAssertEqual(readyCount(902), 1, "ready is announced once, after the read-back")
		XCTAssertTrue(ackErrors(902).isEmpty, "a success is not an ack error")
		let status = walletStatus(903)
		XCTAssertEqual(status?["status"] as? String, "unlocked", "G2: the session is ready for the record's account")
		XCTAssertEqual(status?["accountKey"] as? String, account + ":default", "the wallet address is unchanged by the restore")
	}

	/// Cold start and retry: a relaunch keeps the record (G1), `init` reaches G2 again with the same account, and a second `init` (retry) is
	/// answered ok without a second ready.
	func testAColdStartAndARetryReachG2WithTheSameAccount() {
		store.keys[account] = keyData
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 910, "payload": initPayload(account)], capabilities: declared)
		XCTAssertTrue(waitUntil { self.readyCount(910) > 0 }, "the first init reaches ready")
		XCTAssertEqual(walletStatus(911)?["accountKey"] as? String, account + ":default")
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 912, "payload": initPayload(account)], capabilities: declared)
		XCTAssertTrue(waitUntil { self.readyCount(912) > 0 || !self.ackErrors(912).isEmpty }, "a retry answers")
		XCTAssertTrue(ackErrors(912).isEmpty, "a retry on a ready session is not refused")
		XCTAssertEqual(walletStatus(913)?["accountKey"] as? String, account + ":default", "the address is unchanged after the retry")
	}

	// MARK: - declared, without a key, or refused

	/// Declared, no native key: the gate answers no_key before any payload is read (G0).
	func testDeclaredWithoutAKeyIsNoKey() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 920, "payload": initPayload(account)], emit: { _ in })
		XCTAssertTrue(waitForAnswer(920, timeout: 5))
		XCTAssertEqual(ackErrors(920).first ?? "unanswered", "no_key")
		XCTAssertEqual(store.writes, 0, "nothing is stored")
	}

	/// The payload's account is not the record's account: refused with address_mismatch (step 4), and the session stays not ready.
	func testAnEoaThatDiffersFromTheRecordIsRefused() {
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 930, "payload": initPayload(other)], emit: { _ in })
		XCTAssertTrue(waitForAnswer(930, timeout: 5))
		XCTAssertEqual(ackErrors(930).first ?? "unanswered", "address_mismatch")
		XCTAssertEqual(walletStatus(931)?["status"] as? String, "not_ready", "a refused init does not make the session ready")
	}

	/// A key in the store that does not derive the account: init answers not_ready. No session changes.
	func testAKeyForAnotherAddressIsRecordMismatchAndNotReady() {
		store.keys[account] = Data(repeating: 0x42, count: 32)
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 942, "payload": initPayload(account)], capabilities: declared)
		XCTAssertTrue(waitForAnswer(942), "init answers")
		XCTAssertEqual(ackErrors(942).first ?? "unanswered", "not_ready", ": not record_mismatch")
		XCTAssertEqual(readyCount(942), 0, "ready is never true for a key that does not derive the account")
		XCTAssertEqual(walletStatus(943)?["status"] as? String, "not_ready")
	}

	/// Declared, no key in the store (called past the gate): init answers no_key and nothing is stored.
	func testDeclaredInitWithoutAKeyAnswersNoKey() {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 944, "payload": initPayload(account)], capabilities: declared)
		XCTAssertTrue(waitForAnswer(944), "init answers")
		XCTAssertEqual(ackErrors(944).first ?? "unanswered", "no_key")
		XCTAssertEqual(store.writes, 0)
	}

	/// The OpenPGP host cannot boot: init answers openpgp_not_ready and the session is not ready (G1).
	func testOpenPgpNotReadyIsRefusedAndTheSessionIsNotReady() {
		store.keys[account] = keyData
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioOpenPgpHost.testForceNotReady = true
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 940, "payload": initPayload(account)], capabilities: declared)
		XCTAssertTrue(waitForAnswer(940), "init answers")
		XCTAssertEqual(ackErrors(940).first ?? "unanswered", "openpgp_not_ready")
		XCTAssertEqual(readyCount(940), 0, "no ready without the host")
		XCTAssertEqual(walletStatus(941)?["status"] as? String, "not_ready")
	}

	// MARK: - not declared

	/// Not declared: the capability branch is not taken, but a private-key field is still refused by name, with no state change (S-1, T-103).
	func testUndeclaredStillRefusesAPrivateKeyField() {
		store.keys[account] = keyData
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		let payload: [String: Any] = ["identity": ["eoaAddress": account, "privateKeyHex": "synthetic"] as [String: Any]]
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 950, "payload": payload], capabilities: undeclared)
		XCTAssertTrue(waitForAnswer(950, timeout: 5))
		XCTAssertEqual(ackErrors(950).first ?? "unanswered", "key_over_bridge_refused")
		XCTAssertEqual(store.writes, 0, "init stores nothing")
	}
}
#endif
