#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// SNAP-01..SNAP-07 (v225): the cleanup over the production environment (`BeamioAccountCleanupProduction.environment`): the real pointer in the (in-memory) defaults, a real key of the
/// active account in the key store, and the production snapshot, listings and deletions over isolated stores. What is injected is only what a test keychain cannot produce (a Secure Enclave
/// lookup that fails, SNAP-04) or a failing key delete of the page-copy store (a storage fault). Synthetic accounts only.
final class AccountCleanupSnapshotTests: XCTestCase {
	/// The old accounts are valid mnemonic accounts (their addresses derive from public test phrases): a mnemonic residue that does not verify is kept, not deleted (v230 section 250, UNV-01..03).
	private var old: String { ValidTestAccounts.accountB.eoa }
	private var other: String { ValidTestAccounts.accountC.eoa }
	private let activeKey = Data(repeating: 0x42, count: 32)
	private let switchKey = Data(repeating: 0x43, count: 32)
	private var active: String { (BeamioNativeEthSigner.address(privateKey: [UInt8](activeKey)) ?? "").lowercased() }
	private var switchTo: String { (BeamioNativeEthSigner.address(privateKey: [UInt8](switchKey)) ?? "").lowercased() }

	private var raw = MemoryNativeKeyStore()
	private var pgp: Set<String> = []
	private var listFails = false
	private var pageDir: URL!, chatDir: URL!
	private var innerKeys = BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage()
	private var failingKeys: SnapKeys!
	private var pages: BeamioShellRecord.EncryptedShellRecordStore!
	private var chat: BeamioConetChatLocalStore!
	private var pageKeyNames: Set<String> = []
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		raw = MemoryNativeKeyStore(); pgp = []; listFails = false; pageKeyNames = []
		let base = FileManager.default.temporaryDirectory.appendingPathComponent("cleanup-snap-\(UUID().uuidString)", isDirectory: true)
		pageDir = base.appendingPathComponent("pages", isDirectory: true); chatDir = base.appendingPathComponent("chat", isDirectory: true)
		try? FileManager.default.createDirectory(at: pageDir, withIntermediateDirectories: true)
		try? FileManager.default.createDirectory(at: chatDir, withIntermediateDirectories: true)
		innerKeys = BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage()
		failingKeys = SnapKeys(inner: innerKeys)
		pages = BeamioShellRecord.EncryptedShellRecordStore(directory: pageDir, keys: failingKeys)
		chat = BeamioConetChatLocalStore(rootDirectory: chatDir)
		// the active account: its key record, a valid mnemonic state, the pointer and an established session
		raw.keys[active] = activeKey
		XCTAssertTrue(raw.writeItem(.mnemonic, eoa: active, value: Data([1])))   // a mnemonic record: the gate's record account needs one
		BeamioNativeWallet.keyStore = raw
		BeamioNativeAccountPointer.set(active)
		BeamioConetChatSignBroker.setSignerEoa(active)
		BeamioConetChatModule.setNativeGateForTests(account: active, sessionReady: true)
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.end()
		try? FileManager.default.removeItem(at: pageDir.deletingLastPathComponent())
		super.tearDown()
	}

	private func stores() -> BeamioAccountCleanupProduction.Stores {
		BeamioAccountCleanupProduction.Stores(
			walletRaw: raw,
			walletNames: { self.listFails ? nil : Array(self.raw.rawAccounts.keys) + Array(self.raw.mnemonic.items.keys) + self.raw.keys.keys.map { "walletKey:" + $0 } },
			pageCopies: pages, chat: chat,
			fileExists: { BeamioShellRecord.fileExistence(at: $0) },
			pgpKAccounts: { self.pgp.sorted().map { "K.v1|\($0)|default" } },
			pageKeyAccounts: { self.pageKeyNames.sorted() },
			hardwareAccounts: { [] },
			pgpState: { self.pgp.contains($0) ? .present : .absent },
			pgpClear: { self.pgp.remove($0) },
			ownerRead: { .absent }, ownerRemove: { true },
			inboxFileExists: { false }, inboxClear: { true }, signalsFileExists: { false }, signalsClear: { true }
		)
	}

	/// The production environment. The mnemonic state of the active account is the one seam a test double needs (the read-back reads it once per run).
	private func productionEnv(passcode: BeamioAccountCleanup.PasscodeItems? = nil) -> BeamioAccountCleanup.Environment {
		raw.mnemonicStateScript[active] = Array(repeating: .valid, count: 20)
		var e = BeamioAccountCleanupProduction.environment(stores: stores())
		e.passcode = passcode
		return e
	}

	private func run(_ env: BeamioAccountCleanup.Environment) -> [String: Any] {
		BeamioAccountCleanup.run(accountKey: active, idempotencyKey: "snap", env: env).ack(reqId: 1)
	}

	private func result(_ ack: [String: Any]) -> (pending: Bool?, kept: Int?) {
		let r = ack["result"] as? [String: Any]
		return (r?["cleanupPending"] as? Bool, r?["keptUnattributed"] as? Int)
	}

	/// A raw wallet item with one byte; the mnemonic item of an old account of this file holds that account's phrase (so that it verifies).
	private func put(_ name: String) {
		if name == "mnemonic:\(old)" { XCTAssertTrue(raw.writeItem(.mnemonic, eoa: old, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseB))); return }
		if name == "mnemonic:\(other)" { XCTAssertTrue(raw.writeItem(.mnemonic, eoa: other, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseC))); return }
		XCTAssertTrue(raw.rawWrite(account: name, bytes: Data([1])))
	}
	/// the published walletKey is never deletable, so it is not part of the deletable names
	private func walletNames(_ o: String) -> [String] { ["mnemonic:\(o)", "commit:\(o)", "phase:\(o)"] }
	private func seedWallet(_ o: String) { for n in walletNames(o) { put(n) } }
	private func walletLeft(_ o: String) -> Bool { walletNames(o).contains { raw.rawRead(account: $0) != .absent } }

	private func seedPage(_ account: String) {
		try? Data([1, 2, 3]).write(to: pages.fileURL(in: pageDir, account))
		XCTAssertTrue(innerKeys.writeKey(account: account, Data(repeating: 7, count: 32)))
		pageKeyNames.insert(account)
	}

	private func seedLibrary(_ account: String, unsent: Bool = false) throws {
		let db = try ChatLocalSQLite(path: chat.databasePath(for: account))
		try db.exec("CREATE TABLE msg (pending_publish INTEGER)")
		if unsent { try db.exec("INSERT INTO msg VALUES (1)") }
		db.close()
	}

	// SNAP-01: one snapshot per reading: the pointer is read once for the pointer and the address derived from it, and the run never asks the two separate closures
	func testSNAP01_OneSnapshotReadsThePointerOnce() {
		let counting = CountingDefaults(inner: BeamioNativeAccountPointer.defaults)
		BeamioNativeAccountPointer.defaults = counting
		seedWallet(old); pgp.insert(other)
		var env = productionEnv()
		let snapshot = env.activeSnapshot
		counting.reads = 0
		let one = snapshot()
		XCTAssertEqual(counting.reads, 1, "pointer and derived address come from one read")
		XCTAssertEqual(one.pointer.lowercased(), one.derived?.lowercased(), "and agree")
		var snapshots = 0
		var deltas: [Int] = []
		env.activeSnapshot = { snapshots += 1; let before = counting.reads; let r = snapshot(); deltas.append(counting.reads - before); return r }
		let ack = run(env)
		XCTAssertEqual(ack["ok"] as? Bool, true, "\(ack)")
		// the environment has no separate pointer or address reader at all (activeSnapshot is a required field of the struct): "never read apart" is guaranteed by the compiler
		XCTAssertGreaterThan(snapshots, 0)
		XCTAssertEqual(deltas, Array(repeating: 1, count: snapshots), "each snapshot is exactly one read of the pointer")
	}

	// The scan of libraries that match no account takes the verified active account from the caller: it does not read the pointer (the residue scan too: keptResidue goes through
	// scanAccountNames and orphanLibraries, both over the stores and the key store, never the pointer).
	func testTheOrphanAndResidueScansDoNotReadThePointer() throws {
		let counting = CountingDefaults(inner: BeamioNativeAccountPointer.defaults)
		BeamioNativeAccountPointer.defaults = counting
		try seedLibrary(old)
		let env = productionEnv()
		counting.reads = 0
		let kept = env.unattributedKept(active)
		XCTAssertEqual(counting.reads, 0, "the scan did not read the pointer")
		XCTAssertEqual(kept?.count, 1, "the library of no known account is listed")
		counting.reads = 0
		_ = BeamioAccountCleanupProduction.keptResidue(stores: stores(), keyStore: raw, activeAccount: active)
		_ = BeamioAccountCleanupProduction.scanAccountNames(stores: stores(), keyStore: raw)
		_ = BeamioAccountCleanupProduction.discoveredAccounts(stores: stores(), keyStore: raw)
		XCTAssertEqual(counting.reads, 0, "the residue scan, the name scan and the account discovery did not read the pointer")
		_ = try seedLibraryOfActive()
		XCTAssertEqual(env.unattributedKept(active)?.count, 1, "the active account's library is known from the argument, not listed")
	}

	private func seedLibraryOfActive() throws -> Bool { try seedLibrary(active); return true }

	// SNAP-02: the pointer changes after a snapshot (a real switch in the production defaults and key store): account_mismatch, stop, what was deleted stays deleted
	func testSNAP02_PointerChangeAfterTheSnapshotStopsWithAccountMismatch() {
		seedWallet(old); seedWallet(other)
		var env = productionEnv()
		let inner = env.delete
		var switched = false
		env.delete = { item in
			let done = inner(item)
			if !switched {
				switched = true
				self.raw.keys[self.switchTo] = self.switchKey
				BeamioNativeAccountPointer.set(self.switchTo)
			}
			return done
		}
		let ack = run(env)
		XCTAssertEqual(ack["ok"] as? Bool, false); XCTAssertEqual(ack["error"] as? String, "account_mismatch")
		XCTAssertEqual(result(ack).pending, false); XCTAssertEqual(result(ack).kept, 0)
		XCTAssertFalse(walletLeft(old), "the first old account was cleaned before the switch")
		XCTAssertTrue(walletLeft(other), "the second was never started")
	}

	// SNAP-03: one item fails, the other accounts are still cleaned: clear_incomplete with cleanupPending
	func testSNAP03_AnItemFailureKeepsOnlyItselfAndOthersAreCleaned() {
		seedPage(old); seedWallet(old); seedWallet(other); pgp.insert(other)
		failingKeys.failDelete = true   // the page-copy key of `old` cannot be deleted
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, false); XCTAssertEqual(ack["error"] as? String, "clear_incomplete")
		XCTAssertEqual(result(ack).pending, true)
		XCTAssertEqual(pages.pageCopyExists(account: old), true, "the failed item stays")
		XCTAssertFalse(walletLeft(old), "the rest of the same account went")
		XCTAssertFalse(walletLeft(other)); XCTAssertTrue(pgp.contains(other), "the other account's PGP record is kept; its wallet items are cleaned")
		failingKeys.failDelete = false
		XCTAssertEqual(run(productionEnv())["ok"] as? Bool, true, "a repeat finishes")
	}

	// SNAP-04: a Secure Enclave key that cannot be read keeps that account's mark and the run goes on (a test keychain holds no keys: this lookup is the one injected state)
	func testSNAP04_ASecureEnclaveLookupFailureKeepsThatEntryAndContinues() {
		var records: Set<String> = [old, other]
		let pc = BeamioAccountCleanup.PasscodeItems(
			recordState: { records.contains($0) ? .present(Data([1])) : .absent }, deleteRecord: { records.remove($0) },
			hardwareState: { _ in .absent }, deleteHardware: { _ in },
			stagingState: { _ in .absent }, stagingModified: { _ in nil }, deleteStaging: { _ in },
			writeInProgress: { _ in false }, processStart: Date(),
			seKeyState: { $0 == self.old ? .unknown : .absent }
		)
		seedWallet(old); seedWallet(other)
		let ack = run(productionEnv(passcode: pc))
		XCTAssertEqual(ack["error"] as? String, "clear_incomplete"); XCTAssertEqual(result(ack).pending, true)
		XCTAssertFalse(records.contains(other), "the other account's passcode record went")
		XCTAssertFalse(walletLeft(old) || walletLeft(other))
	}

	// SNAP-05: an enumeration source that cannot be read: not_ready before any deletion
	func testSNAP05_EnumerationReadFailureIsNotReadyWithNoDeletion() {
		seedWallet(old); seedPage(other); pgp.insert(other)
		listFails = true
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, false); XCTAssertEqual(ack["error"] as? String, "not_ready")
		XCTAssertEqual(result(ack).pending, false); XCTAssertEqual(result(ack).kept, 0)
		listFails = false
		XCTAssertTrue(walletLeft(old)); XCTAssertEqual(pages.pageCopyExists(account: other), true); XCTAssertTrue(pgp.contains(other))
	}

	// SNAP-06: a library with an unsent message is kept and counted, answer ok, nothing pending
	func testSNAP06_AnUnsentLibraryIsKeptAndCountedAndTheAnswerIsOk() throws {
		try seedLibrary(old, unsent: true)
		seedWallet(old)
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, true, "\(ack)"); XCTAssertEqual(result(ack).pending, false); XCTAssertEqual(result(ack).kept, 1)
		XCTAssertTrue(FileManager.default.fileExists(atPath: chat.databasePath(for: old)))
		XCTAssertFalse(walletLeft(old))
	}

	// SNAP-07: an unsent library kept together with a single item failure: clear_incomplete, pending, the unsent library still counted
	func testSNAP07_UnsentKeptPlusAnItemFailureIsClearIncomplete() throws {
		try seedLibrary(old, unsent: true)
		seedPage(other); seedWallet(other)
		failingKeys.failDelete = true
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, false); XCTAssertEqual(ack["error"] as? String, "clear_incomplete")
		XCTAssertEqual(result(ack).pending, true); XCTAssertEqual(result(ack).kept, 1)
		XCTAssertTrue(FileManager.default.fileExists(atPath: chat.databasePath(for: old)))
		XCTAssertFalse(walletLeft(other))
	}

	// MARK: - UNV-01..03 (v230 section 250): a mnemonic residue that is readable but cannot be verified is not an exact attribution

	/// A mnemonic item of the old account that reads but does not verify (here: another account's phrase under this account's name; UNV-03 below: an envelope that names the account).
	private func unverifiableMnemonic(of eoa: String, _ payload: Data) {
		XCTAssertTrue(raw.writeItem(.mnemonic, eoa: eoa, value: payload))
		XCTAssertEqual(raw.mnemonicAccountState(owner: eoa), .invalid)
	}

	func testUNV01_UnverifiableResidueIsKeptCountedAndNotPending() {
		unverifiableMnemonic(of: old, BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA))   // another account's phrase: it reads but does not derive `old`
		put("intent:\(old)")   // another exactly attributable item of the same account
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, true, "\(ack)")
		XCTAssertEqual(result(ack).pending, false, "not a retryable state")
		XCTAssertEqual(result(ack).kept, 1, "the residue is counted in keptUnattributed")
		XCTAssertEqual(raw.itemState(.mnemonic, eoa: old), .present, "the residue stays")
		XCTAssertEqual(raw.rawRead(account: "intent:\(old)"), .absent, "the same account's other exactly attributable item goes as usual")
	}

	func testUNV02_OtherOldAccountsAreStillCleared() {
		unverifiableMnemonic(of: old, BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA))   // another account's phrase: it reads but does not derive `old`
		seedPage(other); pgp.insert(other); seedWallet(other)
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, true, "\(ack)")
		XCTAssertEqual(result(ack).kept, 2, "the unverifiable residue and the kept PGP record of the other old account")
		XCTAssertEqual(pages.pageCopyExists(account: other), false)
		XCTAssertTrue(pgp.contains(other), "the PGP record is kept")
		XCTAssertFalse(walletLeft(other), "the other old account is cleaned although the residue is kept")
		XCTAssertEqual(raw.itemState(.mnemonic, eoa: old), .present)
	}

	func testUNV03_TheEnvelopeEoaIsNotProof() {
		// the residue's envelope names the account (an eoa field equal to the old account) but its phrase does not verify
		let envelope = Data(#"{"v":1,"eoa":"\#(old)","phrase":"not a valid phrase at all"}"#.utf8)
		unverifiableMnemonic(of: old, envelope)
		let ack = run(productionEnv())
		XCTAssertEqual(ack["ok"] as? Bool, true, "\(ack)")
		XCTAssertEqual(result(ack).pending, false)
		XCTAssertEqual(result(ack).kept, 1, "an eoa field in the envelope does not make the residue exactly attributable")
		XCTAssertEqual(raw.itemState(.mnemonic, eoa: old), .present, "kept")
	}
}

private final class SnapKeys: BeamioShellRecord.KeyStorage {
	let inner: BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage
	var failDelete = false
	init(inner: BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage) { self.inner = inner }
	func readKey(account: String) -> BeamioShellRecord.KeyRead { inner.readKey(account: account) }
	func writeKey(account: String, _ key: Data) -> Bool { inner.writeKey(account: account, key) }
	func deleteKey(account: String) -> Bool { failDelete ? false : inner.deleteKey(account: account) }
}

/// Counts the reads of the account pointer (every `string` or `object` read of its key); everything else goes through.
private final class CountingDefaults: BeamioDefaultsStoring {
	let inner: BeamioDefaultsStoring
	var reads = 0
	init(inner: BeamioDefaultsStoring) { self.inner = inner }
	private func count(_ key: String) { if key == "beamio.native.account.v1" { reads += 1 } }
	func object(forKey key: String) -> Any? { count(key); return inner.object(forKey: key) }
	func string(forKey key: String) -> String? { count(key); return inner.string(forKey: key) }
	func dictionary(forKey key: String) -> [String: Any]? { inner.dictionary(forKey: key) }
	func integer(forKey key: String) -> Int { inner.integer(forKey: key) }
	func double(forKey key: String) -> Double { inner.double(forKey: key) }
	func bool(forKey key: String) -> Bool { inner.bool(forKey: key) }
	func set(_ value: Any?, forKey key: String) { inner.set(value, forKey: key) }
	func removeObject(forKey key: String) { inner.removeObject(forKey: key) }
}
#endif
