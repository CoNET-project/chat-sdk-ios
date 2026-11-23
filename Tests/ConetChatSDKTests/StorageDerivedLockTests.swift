#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// 25.52Y.83 (takeover, 2026-11-15): a half-finished store. `Locked(marker_missing)`: the key record exists, the mnemonic is there, and neither
/// mark is. `Locked(record_missing)`: the commit mark exists and the key record is gone. Each answers the family names and the page opens `not_ready`,
/// once; walletStatus answers `not_ready` with `notReadyReason: "unreadable"`; nothing answers no_key or locked; nothing is written, generated or
/// overwritten, and the records stay. A key record with no marks is not a storage-derived lock (25.52Y.39 (j)), and that control keeps its answers.
/// Synthetic keys and phrases only.
final class StorageDerivedLockTests: XCTestCase {
	/// A key store that keeps the key records and the mark items (mnemonic, commit, intent) as the import does. Writes are counted.
	final class MarkStore: BeamioChatMnemonicKeyStoring, BeamioNativeMarkReading {
		var keys: [String: Data] = [:] {
			didSet { BeamioNativeKeySnapshot.invalidate() }
		}
		var items: [String: Data] = [:] {
			didSet { BeamioNativeKeySnapshot.invalidate() }
		}
		var writes = 0

		private func itemKey(_ kind: BeamioChatWalletItemKind, _ eoa: String) -> String {
			"\(kind.rawValue):\(eoa.lowercased())"
		}
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func delete(eoa: String) {
			writes += 1
			keys[eoa.lowercased()] = nil
		}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		/// The mnemonic ownership rule (Y.163 items 31 and 32): the store lists the owners of its mnemonic items.
		func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? {
			items.keys.filter { $0.hasPrefix("mnemonic:") }.map { BeamioChatKeyCreation(owner: String($0.dropFirst("mnemonic:".count)), created: nil) }
		}
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? {
			keys.map { (pair: (key: String, value: Data)) -> BeamioChatKeyEntryCheck in
				guard let address = BeamioNativeEthSigner.address(privateKey: [UInt8](pair.value)), address.lowercased() == pair.key else {
					return .corrupt
				}
				return .valid(eoa: pair.key)
			}
		}
		func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
			items[itemKey(kind, eoa)] == nil ? .absent : .present
		}
		func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
			writes += 1
			items[itemKey(kind, eoa)] = value
			return true
		}
		func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? { items[itemKey(kind, eoa)] }
		func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
			writes += 1
			items[itemKey(kind, eoa)] = nil
			return true
		}
		func intentOwners() -> [String]? {
			items.keys.filter { $0.hasPrefix("intent:") }.map { String($0.dropFirst("intent:".count)) }
		}
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private var savedStore: BeamioChatWalletKeyStoring!
	private var shellDirectory: URL?

	final class Shell: BeamioShellRecord.KeyStorage {
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
		BeamioConetChatSignBroker.clearSigner()
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("storage-lock-shell-\(UUID().uuidString)", isDirectory: true)
		shellDirectory = directory
		BeamioShellRecord.EncryptedShellRecordStore.testProductionOverride = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: Shell())
	}

	override func tearDown() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		BeamioNativeKeySnapshot.markStore = BeamioNativeMarkReadingNone()
		BeamioShellRecord.EncryptedShellRecordStore.testProductionOverride = nil
		if let shellDirectory { try? FileManager.default.removeItem(at: shellDirectory) }
		ClearPendingIsolation.end()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

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

	/// The canonical JSON of the one ack for this reqId, or "none (n events)" when the reqId has no single ack.
	private func answer(_ events: [[String: Any]], _ reqId: Int) -> String {
		let acks = events.filter { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
		guard acks.count == 1, let event = acks.first,
		      let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
			return "none (\(events.count) events)"
		}
		return String(decoding: data, as: UTF8.self)
	}

	private func notReadyAnswer(_ reqId: Int) -> String {
		#"{"error":"not_ready","ok":false,"reqId":\#(reqId),"type":"ack"}"#
	}

	/// The shell record read under a storage-derived lock (v159 section 179.1, v162 section 182): its not_ready is a result (ok:true) carrying the reason and that a retry cannot help.
	private func storageLockedReadAnswer(_ reqId: Int) -> String {
		#"{"ok":true,"reqId":\#(reqId),"result":{"code":"not_ready","notReadyReason":"storage_locked","retryable":false},"type":"ack"}"#
	}

	private func unreadableAnswer(_ reqId: Int) -> String {
		#"{"ok":true,"reqId":\#(reqId),"result":{"notReadyReason":"unreadable","status":"not_ready"},"type":"ack"}"#
	}

	/// The family names, the page opens and the key-setup names: each answers `not_ready` exactly once, and nothing else.
	private func assertFamiliesAnswerNotReadyOnce(from base: Int, file: StaticString = #filePath, line: UInt = #line) {
		let names = ["historySign", "pgpDecryptInbound", "walletSignMessage", "pgpRestoreEvaluate", "init", "nativeAccountCreateOpen"]
		for (offset, name) in names.enumerated() {
			let reqId = base + offset
			let events = send(["type": name, "reqId": reqId, "payload": ["identity": ["eoaAddress": account] as [String: Any]] as [String: Any]])
			XCTAssertEqual(events.count, 1, "\(name): exactly one event", file: file, line: line)
			XCTAssertEqual(answer(events, reqId), notReadyAnswer(reqId), "\(name): not_ready, once, no no_key and no locked", file: file, line: line)
		}
	}

	/// `Locked(marker_missing)`: the record is there, the mnemonic is there, the commit and intent marks are not. The session is G1.
	func testMarkerMissingAnswersNotReadyOnceAndChangesNothing() {
		let store = MarkStore()
		store.keys[account] = keyData
		store.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .markerMissing)
		let keysBefore = store.keys
		let itemsBefore = store.items
		let writesBefore = store.writes

		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9800]), 9800), unreadableAnswer(9800), "walletStatus: unreadable, not no_key")
		assertFamiliesAnswerNotReadyOnce(from: 9810)
		XCTAssertEqual(answer(send(["type": "shellRecordRead", "reqId": 9830]), 9830), storageLockedReadAnswer(9830))

		XCTAssertEqual(store.writes, writesBefore, "nothing is written, generated or deleted")
		XCTAssertEqual(store.keys, keysBefore, "the key record is kept")
		XCTAssertEqual(store.items, itemsBefore, "the mark items are kept")
	}

	/// `Locked(record_missing)`: the commit mark exists, the key record does not. The pointer names the account, so this is not G0 (no_key).
	func testRecordMissingAnswersNotReadyOnceAndChangesNothing() {
		let store = MarkStore()
		store.items["commit:\(account)"] = Data(#"{"v":1,"eoa":"\#(account)","committedAt":"2026-11-15T00:00:00Z"}"#.utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .recordMissing)
		let keysBefore = store.keys
		let itemsBefore = store.items
		let writesBefore = store.writes

		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9900]), 9900), unreadableAnswer(9900), "walletStatus: unreadable, not no_key")
		assertFamiliesAnswerNotReadyOnce(from: 9910)
		XCTAssertEqual(answer(send(["type": "shellRecordRead", "reqId": 9930]), 9930), storageLockedReadAnswer(9930))

		XCTAssertEqual(store.writes, writesBefore, "no key is generated, and nothing is overwritten")
		XCTAssertTrue(store.keys.isEmpty, "no key appears")
		XCTAssertEqual(store.items, itemsBefore, "the commit mark is kept")
	}

	/// Y.88 class A (storage lock): hello and passcodeStatus keep their normal answers.
	func testClassAKeepsItsAnswersUnderTheStorageLock() {
		let store = MarkStore()
		store.keys[account] = keyData
		store.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .markerMissing)
		XCTAssertEqual(answer(send(["type": "hello", "reqId": 9940]), 9940).contains("not_ready"), false, "hello is answered before the gate")
		XCTAssertFalse(answer(send(["type": "passcodeStatus", "reqId": 9941]), 9941).contains("\"error\":\"not_ready\""))
	}

	/// Y.88 class D (storage lock): a history read answers ok with source not_ready and no data (25.52DL).
	func testClassDHistoryReadAnswersSourceNotReadyUnderTheStorageLock() {
		let store = MarkStore()
		store.keys[account] = keyData
		store.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(answer(send(["type": "historyRead", "reqId": 9950]), 9950),
		               #"{"ok":true,"reqId":9950,"result":{"source":"not_ready"},"type":"ack"}"#)
	}

	/// Y.88 class B (storage lock): the three entry commands answer not_ready once, and nothing is read or written.
	func testClassBEntryOpensAnswerNotReadyOnceUnderTheStorageLock() {
		let store = MarkStore()
		store.keys[account] = keyData
		store.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .markerMissing)
		let writes = store.writes
		let keys = store.keys
		XCTAssertEqual(answer(send(["type": "nativeAccountCreateOpen", "reqId": 9970]), 9970), notReadyAnswer(9970))
		XCTAssertEqual(answer(send(["type": "nativeImportOpen", "reqId": 9971]), 9971), #"{"error":"unknown_command","ok":false,"reqId":9971,"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "nativeRecoveryOpen", "reqId": 9972]), 9972), notReadyAnswer(9972))
		XCTAssertEqual(store.writes, writes, "the entry opens write nothing")
		XCTAssertEqual(store.keys, keys, "the entry opens keep the key record")
	}

	/// Y.88 class C (storage lock): identityPublic and walletSendTransaction answer not_ready once, never no_key.
	func testClassCFamilyCommandsAnswerNotReadyOnceUnderTheStorageLock() {
		let store = MarkStore()
		store.keys[account] = keyData
		store.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(answer(send(["type": "identityPublic", "reqId": 9980]), 9980), notReadyAnswer(9980))
		XCTAssertEqual(answer(send(["type": "walletSendTransaction", "reqId": 9981]), 9981), notReadyAnswer(9981))
	}

	/// Y.88 class E (storage lock): key-store commands answer not_ready once, and clearIdentity deletes nothing.
	func testClassEKeyStoreCommandsAnswerNotReadyOnceUnderTheStorageLock() {
		let store = MarkStore()
		store.keys[account] = keyData
		store.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		let writes = store.writes
		let keys = store.keys
		XCTAssertEqual(answer(send(["type": "send", "reqId": 9960]), 9960), notReadyAnswer(9960))
		XCTAssertEqual(answer(send(["type": "clearIdentity", "reqId": 9961]), 9961), notReadyAnswer(9961))
		XCTAssertEqual(store.writes, writes, "nothing is deleted or written")
		XCTAssertEqual(store.keys, keys)
	}

	/// A complete valid account (key, a mnemonic that derives it, and its commit mark) with no session yet: not a storage-derived lock, and walletStatus keeps its G1 answer.
	/// (The control was a key record with no marks; since Y.163 items 31 and 32 a key alone is no account, see the next test.)
	private func installCompleteAccount(_ store: MarkStore) -> String {
		let acct = ValidTestAccounts.accountA
		store.keys[acct.eoa] = acct.key
		store.items["mnemonic:\(acct.eoa)"] = BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA)
		store.items["commit:\(acct.eoa)"] = Data(#"{"v":1,"eoa":"\#(acct.eoa)","committedAt":"2026-11-15T00:00:00Z"}"#.utf8)
		return acct.eoa
	}

	func testAKeyWithNoMarksIsNotStorageDerivedLocked() {
		let store = MarkStore()
		let eoa = installCompleteAccount(store)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		XCTAssertNil(BeamioNativeKeySnapshot.current()?.storageLock)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9950]), 9950),
		               #"{"ok":true,"reqId":9950,"result":{"notReadyReason":"g1_uninitialized","status":"not_ready"},"type":"ack"}"#)
	}

	/// A key record with no mnemonic is no account (Y.163 items 31 and 32): no lock, and walletStatus answers no_key.
	func testAKeyOnlyRecordIsNoAccountAndNotAStorageDerivedLock() {
		let store = MarkStore()
		store.keys[account] = keyData
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertNil(BeamioNativeKeySnapshot.current()?.storageLock)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9952]), 9952), #"{"ok":true,"reqId":9952,"result":{"status":"no_key"},"type":"ack"}"#)
	}

	/// 25.52Y.117 / Y.118: walletStatus at G1 (no completed init) answers `not_ready` with `notReadyReason: "g1_uninitialized"`.
	func testG1UninitializedNamesItsReason() {
		let store = MarkStore()
		let eoa = installCompleteAccount(store)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.markStore = store
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		let ack = send(["type": "walletStatus", "reqId": 9951]).first { $0["type"] as? String == "ack" }
		let result = ack?["result"] as? [String: Any]
		XCTAssertEqual(result?["status"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "g1_uninitialized")
	}
}
#endif
