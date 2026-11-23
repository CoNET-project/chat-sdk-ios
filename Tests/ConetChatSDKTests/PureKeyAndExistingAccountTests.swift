#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Takeover batch 2 item B (25.52Y.83 production path, 25.52Y.92, 25.52X.4). The key store here is production-shaped: it keeps the key records
/// but not the mark items, as `BeamioPasscodeWalletStore` does. The marks are read from `BeamioNativeKeySnapshot.markStore`. Synthetic keys only;
/// the shell record store is a temporary directory.
final class PureKeyAndExistingAccountTests: XCTestCase {
	/// The production shape: key records only. It does not conform to `BeamioChatMnemonicKeyStoring`, so the mark items are not reachable through it.
	final class KeyOnlyStore: BeamioChatWalletKeyStoring {
		let inner: StorageDerivedLockTests.MarkStore
		/// True: the store lists no mnemonic account (a store that keeps key records only and knows it: a key is no account, Y.163 items 31 and 32). False (default): it does not list at all,
		/// which fails closed (every state unreadable), as the tests that rely on that expect.
		let listsNoMnemonics: Bool
		init(inner: StorageDerivedLockTests.MarkStore, listsNoMnemonics: Bool = false) { self.inner = inner; self.listsNoMnemonics = listsNoMnemonics }
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { listsNoMnemonics ? [] : nil }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { listsNoMnemonics ? .absent : .unreadable }
		func write(eoa: String, key: Data) -> Bool { inner.write(eoa: eoa, key: key) }
		func read(eoa: String) -> Data? { inner.read(eoa: eoa) }
		func delete(eoa: String) { inner.delete(eoa: eoa) }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { inner.read(eoa: eoa) == nil ? .absent : .present }
		func hasAnyKeyRecord() -> Bool { !inner.keys.isEmpty }
		func enumerateKeyOwners() -> [String]? { Array(inner.keys.keys) }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { inner.enumerateKeyEntries() }
	}

	/// A mark store whose commit mark cannot be read.
	struct UnreadableCommitMarks: BeamioNativeMarkReading {
		func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
			kind == .commit ? .unreadable : .absent
		}
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let other = "0x2222222222222222222222222222222222222222"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private var savedStore: BeamioChatWalletKeyStoring!
	private var shellDirectory: URL?
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		ClearPendingIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioConetChatSignBroker.clearSigner()
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("pure-key-shell-\(UUID().uuidString)", isDirectory: true)
		shellDirectory = directory
		BeamioShellRecord.EncryptedShellRecordStore.testProductionOverride = BeamioShellRecord.EncryptedShellRecordStore(
			directory: directory, keys: StorageDerivedLockTests.Shell())
		events = []
	}

	override func tearDown() {
		BeamioNativeKeySnapshot.pinUnknownForTests(false)
		BeamioConetChatModule.closeRecoveryPage()
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

	private func drainMain() {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
	}

	private func send(_ body: [String: Any]) -> [[String: Any]] {
		var out: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			out.append((payload["event"] as? [String: Any]) ?? payload)
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return out
	}

	private func answer(_ events: [[String: Any]], _ reqId: Int) -> String {
		let acks = events.filter { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
		guard acks.count == 1, let event = acks.first,
		      let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
			return "none (\(events.count) events)"
		}
		return String(decoding: data, as: UTF8.self)
	}

	private func unreadableAnswer(_ reqId: Int) -> String {
		#"{"ok":true,"reqId":\#(reqId),"result":{"notReadyReason":"unreadable","status":"not_ready"},"type":"ack"}"#
	}

	private func notReadyAnswer(_ reqId: Int) -> String {
		#"{"error":"not_ready","ok":false,"reqId":\#(reqId),"type":"ack"}"#
	}

	/// Y.92 positive, as the mnemonic ownership rule (Y.163 items 31 and 32) leaves it: a readable private key with no intent, mnemonic, commit or digest is the old pure-key record. It is
	/// accepted as a record that is neither a lock nor unreadable; it is no account either, so walletStatus answers no_key.
	func testAPureKeyRecordWithNoMarkIsAcceptedWithoutALock() {
		let markStore = StorageDerivedLockTests.MarkStore()
		markStore.keys[account] = keyData
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: markStore, listsNoMnemonics: true)
		BeamioNativeKeySnapshot.markStore = markStore
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertNil(BeamioNativeKeySnapshot.current()?.storageLock, "a pure-key record is not storage-derived locked")
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.unreadable, false)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 10100]), 10100),
		               #"{"ok":true,"reqId":10100,"result":{"status":"no_key"},"type":"ack"}"#, "a key alone is no account: no_key, not unreadable")
	}

	/// Y.92 negative: an intent with no commit mark is not a pure-key record. The key is unreadable, nothing is generated or overwritten.
	func testAnIntentWithoutACommitMarkIsUnreadableNotAPureKey() {
		let markStore = StorageDerivedLockTests.MarkStore()
		markStore.keys[account] = keyData
		markStore.items["intent:\(account)"] = Data(#"{"v":1,"eoa":"\#(account)","phase":"begun"}"#.utf8)
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: markStore)
		BeamioNativeKeySnapshot.markStore = markStore
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .markerMissing, "intent without commit is marker_missing")
		let writes = markStore.writes
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 10110]), 10110), unreadableAnswer(10110))
		XCTAssertEqual(answer(send(["type": "identityPublic", "reqId": 10111]), 10111), notReadyAnswer(10111))
		XCTAssertEqual(markStore.writes, writes, "nothing is written or generated")
		XCTAssertEqual(markStore.keys[account], keyData, "the key is kept")
	}

	/// B proof on the production shape: a mnemonic with no commit mark is marker_missing, although the key store cannot reach the marks.
	func testAMnemonicWithoutACommitMarkLocksOnTheProductionStoreShape() {
		let markStore = StorageDerivedLockTests.MarkStore()
		markStore.keys[account] = keyData
		markStore.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: markStore)
		BeamioNativeKeySnapshot.markStore = markStore
		XCTAssertNil(BeamioNativeWallet.keyStore as? BeamioChatMnemonicKeyStoring, "the key store does not keep the marks")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .markerMissing)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 10120]), 10120), unreadableAnswer(10120))
		XCTAssertEqual(answer(send(["type": "identityPublic", "reqId": 10121]), 10121), notReadyAnswer(10121))
	}

	/// A complete record (key, mnemonic and commit) is not locked.
	func testACompleteRecordIsNotLocked() {
		let markStore = StorageDerivedLockTests.MarkStore()
		markStore.keys[account] = keyData
		markStore.items["mnemonic:\(account)"] = Data("synthetic phrase for the test only".utf8)
		markStore.items["commit:\(account)"] = Data(#"{"v":1,"eoa":"\#(account)","committedAt":"2026-11-15T00:00:00Z"}"#.utf8)
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: markStore)
		BeamioNativeKeySnapshot.markStore = markStore
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertNil(BeamioNativeKeySnapshot.current()?.storageLock)
	}

	/// record_missing on the production shape: the commit mark exists and the key record is gone.
	func testRecordMissingLocksOnTheProductionStoreShape() {
		let markStore = StorageDerivedLockTests.MarkStore()
		markStore.items["commit:\(account)"] = Data(#"{"v":1,"eoa":"\#(account)","committedAt":"2026-11-15T00:00:00Z"}"#.utf8)
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: markStore, listsNoMnemonics: true)
		BeamioNativeKeySnapshot.markStore = markStore
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.storageLock, .recordMissing)
		XCTAssertTrue(markStore.keys.isEmpty, "no key appears")
	}

	/// A commit mark that cannot be read is unreadable (fail closed), not a storage lock and not no_key.
	func testAnUnreadableMarkIsUnreadableNotALock() {
		let markStore = StorageDerivedLockTests.MarkStore()
		markStore.keys[account] = keyData
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: markStore)
		BeamioNativeKeySnapshot.markStore = UnreadableCommitMarks()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertNil(BeamioNativeKeySnapshot.current()?.storageLock)
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.unreadable, true)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 10130]), 10130), unreadableAnswer(10130))
	}

	// MARK: - 25.52X.4 already_exists carries the public account

	/// The account of the key on the device: the pointer names it, the key reads, and it derives that account. The pointer is persisted.
	func testTheExistingKeyAccountIsDerivedAndPersisted() {
		let store = StorageDerivedLockTests.MarkStore()
		store.keys[account] = keyData
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(BeamioNativeRecovery.existingKeyAccount(store: store), account)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account)
	}

	/// With no pointer, the account is named only when exactly one valid mnemonic account has a key (Y.163 items 31 and 32: a key alone is no account).
	func testWithoutAPointerTheOnlyKeyOwnerIsNamed() {
		let store = MemoryNativeKeyStore()
		let acct = ValidTestAccounts.install(store)
		BeamioNativeAccountPointer.clear()
		XCTAssertEqual(BeamioNativeRecovery.existingKeyAccount(store: store), acct.eoa)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), acct.eoa, "the derived account is persisted")
		// a key alone names nobody and moves no pointer
		let keyOnly = StorageDerivedLockTests.MarkStore()
		keyOnly.keys[account] = keyData
		BeamioNativeAccountPointer.clear()
		XCTAssertNil(BeamioNativeRecovery.existingKeyAccount(store: KeyOnlyStore(inner: keyOnly, listsNoMnemonics: true)))
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "no pointer is set from a key alone")
	}

	/// A key that does not derive the account it is kept under gives no account, and the pointer is not moved.
	func testAKeyThatDoesNotDeriveItsAccountGivesNoAccount() {
		let store = StorageDerivedLockTests.MarkStore()
		store.keys[other] = keyData
		BeamioNativeAccountPointer.set(other)
		XCTAssertNil(BeamioNativeRecovery.existingKeyAccount(store: store))
		XCTAssertEqual(BeamioNativeAccountPointer.get(), other)
	}

	/// No readable key, no account: the pointer names an account whose key is absent.
	func testNoReadableKeyGivesNoAccount() {
		let store = StorageDerivedLockTests.MarkStore()
		BeamioNativeAccountPointer.set(account)
		XCTAssertNil(BeamioNativeRecovery.existingKeyAccount(store: store))
	}

	/// The already_exists answer of the recovery page carries the eoa, derived and persisted natively. The shell's value is not used.
	func testAnAlreadyExistsAnswerCarriesTheEoaOnlyWhenPersisted() {
		let store = StorageDerivedLockTests.MarkStore()
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: store)
		BeamioNativeKeySnapshot.markStore = store
		BeamioNativeAccountPointer.set(account)
		BeamioNativeRecovery.onRecoveryRequired = { _ in true }
		defer { BeamioNativeRecovery.onRecoveryRequired = nil }
		var sent: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "nativeRecoveryOpen", "reqId": "R-AE-1"], emit: { payload in
			sent.append((payload["event"] as? [String: Any]) ?? payload)
		})
		store.keys[account] = keyData
		XCTAssertTrue(BeamioNativeRecovery.finish(.alreadyExists, eoa: other))
		drainMain()
		let result = sent.last { $0["type"] as? String == "nativeRecoveryResult" }
		XCTAssertEqual(result?["code"] as? String, "already_exists")
		XCTAssertEqual(result?["eoa"] as? String, account, "the derived account, not the shell's value")
	}

	/// When the key does not derive the account, already_exists carries no eoa.
	func testAnAlreadyExistsAnswerWithoutAPersistedAccountCarriesNoEoa() {
		let store = StorageDerivedLockTests.MarkStore()
		BeamioNativeWallet.keyStore = KeyOnlyStore(inner: store)
		BeamioNativeKeySnapshot.markStore = store
		BeamioNativeAccountPointer.set(other)
		BeamioNativeRecovery.onRecoveryRequired = { _ in true }
		defer { BeamioNativeRecovery.onRecoveryRequired = nil }
		var sent: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "nativeRecoveryOpen", "reqId": "R-AE-2"], emit: { payload in
			sent.append((payload["event"] as? [String: Any]) ?? payload)
		})
		store.keys[other] = keyData
		XCTAssertTrue(BeamioNativeRecovery.finish(.alreadyExists))
		drainMain()
		let result = sent.last { $0["type"] as? String == "nativeRecoveryResult" }
		XCTAssertEqual(result?["code"] as? String, "already_exists")
		XCTAssertNil(result?["eoa"], "no eoa when the derivation fails")
	}

	/// The capability pair is declared together, kpresent first, in the shipped list; it is not a QA-only switch (25.52Y.93 (c),
	/// 25.52Y.121; project requirement). kpresent is never declared alone.
	func testTheNativeKeyPairIsDeclaredTogetherInTheShippedList() {
		let shipped = BeamioConetChatProtocol.capabilities
		let kpresent = shipped.firstIndex(of: "identity.kpresent.v1")
		let nativeKeys = shipped.firstIndex(of: "identity.native-keys.v1")
		XCTAssertNotNil(kpresent, "kpresent is declared")
		XCTAssertNotNil(nativeKeys, "native-keys is declared")
		if let kpresent, let nativeKeys {
			XCTAssertEqual(nativeKeys, kpresent + 1, "kpresent immediately precedes native-keys")
		}
		let qa = BeamioConetChatProtocol.qaCapabilities
		XCTAssertFalse(qa.contains("identity.kpresent.v1"), "the pair is not a QA-only declaration")
		XCTAssertFalse(qa.contains("identity.native-keys.v1"), "the pair is not a QA-only declaration")
	}
}
#endif
