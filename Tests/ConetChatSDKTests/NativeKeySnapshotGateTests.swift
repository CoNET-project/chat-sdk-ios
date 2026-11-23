#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Takeover item 1 (interface 25.52Y.70 第 4 项, 25.52Y.75). The gate answers that the native-key snapshot gives must equal the answers of the former
/// per-command judgement, one test per state: G0, G1, G2, the passcode lock, a damaged record, and a write followed at once by a command.
///
/// Each answer is compared as its canonical JSON (the whole ack event, sorted keys). The expected strings are the answers the pre-change commit
/// gives in the same states (recorded by running this file there). The one deliberate change is the walletStatus of a damaged record in
/// G1: `notReadyReason: "unreadable"` (25.52Y.39 第 9 項 (b), 25.52Y.42 (k)(3)); its test states the change. Synthetic keys and addresses only.
final class NativeKeySnapshotGateTests: XCTestCase {
	/// The account of the synthetic key (public derivation test material), and the key bytes. No key material is printed.
	/// Since the mnemonic ownership rule (Y.163 items 31 and 32) an account is a valid mnemonic record: the synthetic account is the one a public BIP-39 test phrase derives.
	private var account: String { ValidTestAccounts.accountA.eoa }
	private var keyData: Data { ValidTestAccounts.accountA.key }
	private var keyHex: String { keyData.map { String(format: "%02x", $0) }.joined() }
	/// Bytes that do not derive `account`: a record listed under the account and judged corrupt.
	private let damagedKey = Data(repeating: 0x11, count: 32)

	/// The passcode vault stand-ins, as `GateLockedStateTests` uses them (synthetic; the identity hardware is not a security control).
	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		var data: [String: Data] = [:]
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	/// A page-copy directory of this test alone, so no answer depends on an earlier run and no real copy is written.
	private var shellDirectory: URL?

	/// The key storage of the test page copies (in memory; no Keychain item is made).
	final class GateShellKeys: BeamioShellRecord.KeyStorage {
		var keys: [String: Data] = [:]
		func readKey(account: String) -> BeamioShellRecord.KeyRead {
			guard let key = keys[account] else { return .notFound }
			return .found(key)
		}
		@discardableResult
		func writeKey(account: String, _ key: Data) -> Bool {
			keys[account] = key
			return true
		}
	}

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		ClearPendingIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioConetChatSignBroker.clearSigner()
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("gate-shell-\(UUID().uuidString)", isDirectory: true)
		shellDirectory = directory
		BeamioShellRecord.EncryptedShellRecordStore.testProductionOverride = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: GateShellKeys())
	}

	override func tearDown() {
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		BeamioShellRecord.EncryptedShellRecordStore.testProductionOverride = nil
		if let shellDirectory { try? FileManager.default.removeItem(at: shellDirectory) }
		ClearPendingIsolation.end()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	// MARK: - helpers

	/// Sends one command and returns the ack events it produced, after the main queue has drained.
	private func send(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	/// The canonical JSON of the ack for this reqId, or "none" when there is no ack (or more than one: the test then fails on the count).
	private func answer(_ events: [[String: Any]], _ reqId: Int) -> String {
		let acks = events.filter { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
		guard acks.count == 1, let event = acks.first,
		      let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
			let all = (try? JSONSerialization.data(withJSONObject: events, options: [.sortedKeys])).map { String(decoding: $0, as: UTF8.self) } ?? "unserialisable"
			return "none (\(acks.count) acks, \(events.count) events: \(all))"
		}
		return String(decoding: data, as: UTF8.self)
	}

	/// The answers of the two commands the gate decides for a record (walletStatus and shellRecordRead), and of one command outside them
	/// (passcodeStatus, live judgement). Each is sent once, with its own reqId.
	private func gateAnswers(_ base: Int) -> (status: String, read: String, passcode: String) {
		let statusEvents = send(["type": "walletStatus", "reqId": base])
		let readEvents = send(["type": "shellRecordRead", "reqId": base + 1])
		let passcodeEvents = send(["type": "passcodeStatus", "reqId": base + 2])
		return (answer(statusEvents, base), answer(readEvents, base + 1), answer(passcodeEvents, base + 2))
	}

	/// A store holding one key record for `eoa`, judged by the store's own rule (the key must derive the account).
	private func storeWith(_ eoa: String, key: Data) -> MemoryNativeKeyStore {
		let store = MemoryNativeKeyStore()
		if key == keyData { ValidTestAccounts.install(store) } else {
			// a damaged record: the mnemonic item of the account is there, but it is another account's phrase, so it does not derive the account
			store.keys[eoa] = key
			_ = store.writeItem(.mnemonic, eoa: eoa, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseB))
		}
		return store
	}

	// MARK: - the states

	/// G0: no native record and no pointer. walletStatus answers no_key.
	func testG0AnswersAreUnchanged() {
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g0)
		let got = gateAnswers(9100)
		XCTAssertEqual(got.status, #"{"ok":true,"reqId":9100,"result":{"status":"no_key"},"type":"ack"}"#)
		XCTAssertEqual(got.read, #"{"ok":true,"reqId":9101,"result":{"code":"absent"},"type":"ack"}"#)
		XCTAssertEqual(got.passcode, #"{"ok":true,"reqId":9102,"result":{"hasKey":false,"locked":false,"nativeLocked":true,"set":false,"walletState":"absent"},"type":"ack"}"#)
	}

	/// G1: the record is on the device (pointer and a valid key), and this session has not completed init.
	func testG1AnswersAreUnchanged() {
		BeamioNativeWallet.keyStore = storeWith(account, key: keyData)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		let got = gateAnswers(9200)
		XCTAssertEqual(got.status, #"{"ok":true,"reqId":9200,"result":{"notReadyReason":"g1_uninitialized","status":"not_ready"},"type":"ack"}"#)
		XCTAssertEqual(got.read, #"{"ok":true,"reqId":9201,"result":{"code":"not_ready","notReadyReason":"g1_uninitialized","retryable":true},"type":"ack"}"#, "v159 section 179.1: the reason and that a retry can help")
		XCTAssertEqual(got.passcode, #"{"ok":true,"reqId":9202,"result":{"hasKey":true,"locked":false,"nativeLocked":true,"set":false,"walletState":"present"},"type":"ack"}"#, "G1: nativeLocked is true (v45 s50)")
	}

	/// G2: the record is on the device and this session is ready for its account.
	func testG2AnswersAreUnchanged() {
		BeamioNativeWallet.keyStore = storeWith(account, key: keyData)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		let got = gateAnswers(9300)
		XCTAssertEqual(got.status, #"{"ok":true,"reqId":9300,"result":{"accountKey":"\#(account):default","status":"unlocked"},"type":"ack"}"#)
		XCTAssertEqual(got.read, #"{"ok":true,"reqId":9301,"result":{"code":"ok","record":{"mnemonicPhrase":"\#(ValidTestAccounts.phraseA)","profiles":[{"keyID":"\#(account)","privateKeyArmor":"0x\#(keyHex)"}],"rev":1,"schemaVersion":2},"schemaVersion":1},"type":"ack"}"#)
		XCTAssertEqual(got.passcode, #"{"ok":true,"reqId":9302,"result":{"hasKey":true,"locked":false,"nativeLocked":false,"set":false,"walletState":"present"},"type":"ack"}"#)
	}

	/// The passcode lock, in G2: the account is locked by its passcode record, so every answer is `locked`, never not_ready (25.52Y.70 第 4 項 (b)).
	func testPasscodeLockAnswersAreUnchanged() {
		BeamioNativeWallet.keyStore = storeWith(account, key: keyData)
		let records = MemoryRecords()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[account] = (try? JSONEncoder().encode(passcodeRecord)) ?? Data()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked)
		let got = gateAnswers(9400)
		// 25.52Y.118: no accountKey. replaces the earlier `locked` / `passcode_required` answer (frozen protocol §4) with the real state:
		// `not_ready`, the reason `passcode_not_provided`, retryable.
		XCTAssertEqual(got.status, #"{"ok":true,"reqId":9400,"result":{"notReadyReason":"passcode_not_provided","retryable":true,"status":"not_ready"},"type":"ack"}"#)
		// a passcode record whose bundle has not been provided is a real storage state: not_ready with its reason, retryable.
		XCTAssertEqual(got.read, #"{"ok":true,"reqId":9401,"result":{"code":"not_ready","notReadyReason":"passcode_not_provided","retryable":true},"type":"ack"}"#)
		XCTAssertFalse(got.read.contains("storage_locked"), "no application-level lock word: \(got.read)")
		XCTAssertEqual(got.passcode, #"{"ok":true,"reqId":9402,"result":{"hasKey":true,"locked":true,"nativeLocked":true,"set":true,"walletState":"present"},"type":"ack"}"#)
	}

	/// A damaged record: the key listed under the pointer's account does not derive it. The snapshot judges it at the event, so it is never
	/// counted as present. The shell record answer is the former one (the same bytes). walletStatus in G1 now carries `notReadyReason: "unreadable"`.
	func testDamagedRecordAnswersNotReadyWithUnreadableReason() {
		BeamioNativeWallet.keyStore = storeWith(account, key: damagedKey)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "the record is listed, so the device is G1 (as before)")
		let got = gateAnswers(9500)
		XCTAssertEqual(got.status, #"{"ok":true,"reqId":9500,"result":{"notReadyReason":"unreadable","status":"not_ready"},"type":"ack"}"#,
		               "the one change: the earlier answer was {\"status\":\"not_ready\"} without the reason")
		XCTAssertEqual(got.read, #"{"ok":true,"reqId":9501,"result":{"code":"migrating"},"type":"ack"}"#)
		XCTAssertEqual(got.passcode, #"{"ok":true,"reqId":9502,"result":{"hasKey":true,"locked":false,"nativeLocked":true,"set":false,"walletState":"not_ready"},"type":"ack"}"#)
	}

	/// A write followed at once by a command: the record is written after the pointer, and the very next command sees it (G1, not G0).
	func testAWriteIsSeenByTheNextCommand() {
		let store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9600]), 9600),
		               #"{"ok":true,"reqId":9600,"result":{"status":"no_key"},"type":"ack"}"#, "before the write: G0")
		ValidTestAccounts.install(store)
		let after = gateAnswers(9610)
		XCTAssertEqual(after.status, #"{"ok":true,"reqId":9610,"result":{"notReadyReason":"g1_uninitialized","status":"not_ready"},"type":"ack"}"#, "immediately after the write: G1")
		XCTAssertEqual(after.read, #"{"ok":true,"reqId":9611,"result":{"code":"not_ready","notReadyReason":"g1_uninitialized","retryable":true},"type":"ack"}"#)
		XCTAssertEqual(after.passcode, #"{"ok":true,"reqId":9612,"result":{"hasKey":true,"locked":false,"nativeLocked":true,"set":false,"walletState":"present"},"type":"ack"}"#, "G1: nativeLocked is true (v45 s50, e8553cd)")
	}
}
#endif
