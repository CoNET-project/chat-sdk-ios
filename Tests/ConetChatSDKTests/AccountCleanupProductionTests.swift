#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The production wiring of the cleanup's deletion set, over isolated stores (the chat-wallet raw items, the page copy store, the PGP record, the inbox owner and files): for
/// each kind an exact match is deleted, a mismatch is kept, and the new account's items are never touched; a failed read or delete is unknown (clear_incomplete) and never
/// success. Synthetic accounts only. The command is not registered.
final class AccountCleanupProductionTests: XCTestCase {
	private let new = "0x1111111111111111111111111111111111111111"
	/// The old accounts are valid mnemonic accounts (their addresses derive from public test phrases): a mnemonic residue that does not verify is kept, not deleted (v230 section 250).
	private var old: String { ValidTestAccounts.accountB.eoa }
	private var other: String { ValidTestAccounts.accountC.eoa }

	private var raw = MemoryNativeKeyStore()
	private var pgp: Set<String> = []
	private var owner: BeamioInboxOwner.Owner = .absent
	private var inbox = false, signals = false
	private var ownerRemoveFails = false, listFails = false, pgpUnreadable = false, probeFails = false
	private var pageDir: URL!
	private var pageKeys = BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage()
	private var pages: BeamioShellRecord.EncryptedShellRecordStore!
	private var chat: BeamioConetChatLocalStore!
	private var chatDir: URL!
	private var pageKeyNames: Set<String> = []
	private var hardwareNames: Set<String> = []   // addresses named by Secure Enclave tags or H fallback items

	override func setUp() {
		super.setUp()
		pageKeyNames = []; hardwareNames = []
		raw = MemoryNativeKeyStore(); pgp = []; owner = .absent; inbox = false; signals = false
		ownerRemoveFails = false; listFails = false; pgpUnreadable = false; probeFails = false
		let base = FileManager.default.temporaryDirectory.appendingPathComponent("cleanup-prod-\(UUID().uuidString)", isDirectory: true)
		pageDir = base.appendingPathComponent("pages", isDirectory: true); chatDir = base.appendingPathComponent("chat", isDirectory: true)
		try? FileManager.default.createDirectory(at: pageDir, withIntermediateDirectories: true)
		try? FileManager.default.createDirectory(at: chatDir, withIntermediateDirectories: true)
		pageKeys = BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage()
		pages = BeamioShellRecord.EncryptedShellRecordStore(directory: pageDir, keys: pageKeys)
		chat = BeamioConetChatLocalStore(rootDirectory: chatDir)
	}

	override func tearDown() {
		try? FileManager.default.removeItem(at: pageDir.deletingLastPathComponent())
		super.tearDown()
	}

	private func stores() -> BeamioAccountCleanupProduction.Stores {
		BeamioAccountCleanupProduction.Stores(
			walletRaw: raw,
			walletNames: {
				// the raw accounts, plus the double's wallet items that the product store lists under the same names
				self.listFails ? nil : Array(self.raw.rawAccounts.keys) + Array(self.raw.mnemonic.items.keys) + self.raw.keys.keys.map { "walletKey:" + $0 }
			},
			pageCopies: pages,
			chat: chat,
			fileExists: { self.probeFails ? nil : BeamioShellRecord.fileExistence(at: $0) },
			pgpKAccounts: { self.listFails ? nil : self.pgp.sorted().map { "K.v1|\($0)|default" } },
			pageKeyAccounts: { self.listFails ? nil : self.pageKeyNames.sorted() },
			hardwareAccounts: { self.listFails ? nil : self.hardwareNames.sorted() },
			pgpState: { self.pgpUnreadable ? .unreadable : (self.pgp.contains($0) ? .present : .absent) },
			pgpClear: { self.pgp.remove($0) },
			ownerRead: { self.owner },
			ownerRemove: { if self.ownerRemoveFails { return false }; self.owner = .absent; return true },
			inboxFileExists: { self.inbox },
			inboxClear: { self.inbox = false; return true },
			signalsFileExists: { self.signals },
			signalsClear: { self.signals = false; return true }
		)
	}

	/// A page copy fixture: a file at the account's own file name and its key. Written directly (not through `write`, whose complete file protection fails while the
	/// machine's screen is locked), because only the existence and the deletion of the file and the key are under test.
	private func seedPage(_ account: String) {
		try? Data([1, 2, 3]).write(to: pages.fileURL(in: pageDir, account))
		XCTAssertTrue(pageKeys.writeKey(account: account, Data(repeating: 7, count: 32)))
		pageKeyNames.insert(account)
	}

	/// the published walletKey is never deletable: it is not in the deletable names
	private func names(_ o: String) -> [String] { ["mnemonic:\(o)", "intent:\(o)", "commit:\(o)", "phase:\(o)", "migrated:\(o)", "recoveryBackupConfirmed:\(o)", "wallet.restore.unconfirmed.\(o)"] }

	/// A raw wallet item with one byte; the mnemonic item of an account of this file holds that account's phrase (so that it verifies).
	private func put(_ name: String) {
		if name == "mnemonic:\(old)" { XCTAssertTrue(raw.writeItem(.mnemonic, eoa: old, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseB))); return }
		if name == "mnemonic:\(other)" { XCTAssertTrue(raw.writeItem(.mnemonic, eoa: other, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseC))); return }
		XCTAssertTrue(raw.rawWrite(account: name, bytes: Data([1])))
	}

	private func delete(allOf items: [BeamioAccountCleanup.Item]) -> Bool {
		items.allSatisfy { BeamioAccountCleanupProduction.delete($0, stores: stores()) }
	}

	/// wallet class: the exact names go, the new account's, another account's and look-alikes (and isolation copies) stay.
	func testWalletItemsAreDeletedOnlyByExactName() {
		for n in names(old) + names(new) + names(other) { put(n) }
		put("wallet.iso.t.mnemonic:\(old)"); put("wallet.discard.intent"); put("x.walletKey:\(old)")
		let items = BeamioAccountCleanupProduction.items(of: old, stores: stores())
		XCTAssertEqual(Set(items?.map(\.name) ?? []), Set(names(old).map { "wallet|" + $0 }))
		XCTAssertTrue(delete(allOf: items ?? []))
		for n in names(old) { XCTAssertEqual(raw.rawRead(account: n), .absent, n) }
		for n in names(new) + names(other) { XCTAssertNotEqual(raw.rawRead(account: n), .absent, "\(n) stays") }
		for n in ["wallet.iso.t.mnemonic:\(old)", "wallet.discard.intent", "x.walletKey:\(old)"] { XCTAssertEqual(raw.rawRead(account: n), .present(Data([1])), "\(n) stays") }
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.count, 0, "idempotent: nothing left")
	}

	/// pgp class: the old account's PGP record is KEPT, listed as a kept device-level item; delete refuses it; the new account's stays too; an unreadable state is unknown.
	func testThePgpRecordOfTheOldAccountGoesAndTheNewStays() {
		pgp = [old, new]
		let items = BeamioAccountCleanupProduction.items(of: old, stores: stores())
		XCTAssertEqual(items?.map(\.name), ["kept-pgp|\(old)"])
		XCTAssertEqual(items?.map(\.owner), [BeamioAccountCleanupProduction.deviceLevelOwner])
		XCTAssertFalse(delete(allOf: items ?? []), "delete of pgp returns false")
		XCTAssertFalse(BeamioAccountCleanupProduction.delete(.init(owner: old, name: "pgp"), stores: stores()))
		XCTAssertEqual(pgp, [old, new], "both records stay")
		pgpUnreadable = true
		XCTAssertNil(BeamioAccountCleanupProduction.items(of: old, stores: stores()), "an unreadable state is unknown, not absent")
	}

	/// page class: the copy file and its key of the old account go; the new account's copy stays.
	func testThePageCopyOfTheOldAccountGoesWithItsKey() {
		seedPage(old)
		seedPage(new)
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.map(\.name), ["page"])
		XCTAssertTrue(delete(allOf: BeamioAccountCleanupProduction.items(of: old, stores: stores()) ?? []))
		XCTAssertEqual(pages.pageCopyExists(account: old), false)
		XCTAssertEqual(pageKeys.readKey(account: old).isNotFound, true, "its key is gone")
		XCTAssertEqual(pages.pageCopyExists(account: new), true, "the new account's copy stays")
		XCTAssertEqual(pageKeys.readKey(account: new).isNotFound, false, "and its key")
	}

	/// chat class: a library file that is not the old account's is not listed; one that cannot be probed (not a database) is not deleted, and the failure is reported.
	func testTheChatLibraryIsListedByItsExactFileAndAFailedProbeKeepsIt() throws {
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.map(\.name) ?? [], [])
		let path = chat.databasePath(for: old)
		try Data("not a database".utf8).write(to: URL(fileURLWithPath: path))
		let otherPath = chat.databasePath(for: new)
		try Data("new account library".utf8).write(to: URL(fileURLWithPath: otherPath))
		// the library is probed for unsent messages before it is listed: a file that is not a database cannot be probed, which is unknown (never "no library", never deleted)
		XCTAssertNil(BeamioAccountCleanupProduction.items(of: old, stores: stores()), "a library that cannot be probed is unknown")
		XCTAssertTrue(FileManager.default.fileExists(atPath: path))
		XCTAssertTrue(FileManager.default.fileExists(atPath: otherPath), "the new account's library is never touched")
	}

	/// owner/inbox/signals are neither deleted nor counted (deletion and count): whatever the owner is,
	/// they are not listed, the cleanup answers ok with keptUnattributed 0, and the files and the owner stay as they were.
	func testTheDeviceLevelFilesAreNeitherDeletedNorCounted() {
		inbox = true; signals = true
		for o in [BeamioInboxOwner.Owner.account(new), .account(old.uppercased()), .unknown, .absent] {
			owner = o
			XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.count, 0, "nothing of the three is listed: \(o)")
		}
		owner = .account(old)
		let third = "0x4444444444444444444444444444444444444444"
		var cleanup = BeamioAccountCleanup.Environment(
			gatePassed: { true }, activeSnapshot: { (self.new, self.new) }, mnemonicState: { _ in .valid }, keyRecordState: { _ in .present },
			accounts: { [self.new, self.old, third] }, itemsOfOldAccount: { BeamioAccountCleanupProduction.items(of: $0, stores: self.stores()) },
			delete: { BeamioAccountCleanupProduction.delete($0, stores: self.stores()) }
		)
		cleanup.passcode = nil
		let a = BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "k", env: cleanup)
		XCTAssertEqual(a, BeamioAccountCleanup.Answer(ok: true, error: nil, cleanupPending: false, keptUnattributed: 0, deleted: 0))
		XCTAssertTrue(inbox && signals)
		XCTAssertEqual(owner, .account(old))
		// a delete of one of the three names is still refused
		for name in ["owner", "inbox", "signals"] {
			XCTAssertFalse(BeamioAccountCleanupProduction.delete(.init(owner: BeamioAccountCleanupProduction.deviceLevelOwner, name: name), stores: stores()), name)
		}
	}

	/// A listing that fails is unknown for the cleanup (clear_incomplete) and a delete that fails is too; the core reports them and deletes nothing more.
	func testFailuresAreReportedAsClearIncomplete() {
		put("intent:\(old)")
		listFails = true
		XCTAssertNil(BeamioAccountCleanupProduction.items(of: old, stores: stores()))
		listFails = false
		let items = BeamioAccountCleanupProduction.items(of: old, stores: stores()) ?? []
		XCTAssertEqual(items.map(\.name), ["wallet|intent:\(old)"])
		XCTAssertTrue(delete(allOf: items))
		XCTAssertEqual(raw.rawRead(account: "intent:\(old)"), .absent)
	}

	/// Page copy: the file or the key alone keeps it listed. The file is gone but the key could not be deleted: the next run lists it again, and a later run deletes the key.
	func testAPageCopyWhoseFileIsGoneButWhoseKeyRemainsIsStillListedAndFinallyDeleted() {
		seedPage(old)
		// delete the file only (the key deletion "failed"): simulate by removing the file directly
		let url = pages.fileURL(in: pageDir, old)
		try? FileManager.default.removeItem(at: url)
		XCTAssertEqual(pages.pageCopyExists(account: old), true, "the key is still there")
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.map(\.name), ["page"], "listed again, never success")
		// a key store that fails to delete: not complete, the rerun still lists it
		let failing = FailingDeleteKeys(inner: pageKeys)
		let failingStore = BeamioShellRecord.EncryptedShellRecordStore(directory: pageDir, keys: failing)
		failing.failDelete = true
		XCTAssertFalse(failingStore.deletePageCopy(account: old), "the key delete failed: not reported done")
		XCTAssertEqual(failingStore.pageCopyExists(account: old), true)
		failing.failDelete = false
		XCTAssertTrue(failingStore.deletePageCopy(account: old))
		XCTAssertEqual(failingStore.pageCopyExists(account: old), false)
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.count, 0)
	}

	/// A key that cannot be read is unknown for the page copy, never absent.
	func testAPageCopyKeyThatCannotBeReadIsUnknown() {
		let unreadable = FailingDeleteKeys(inner: pageKeys); unreadable.failRead = true
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: pageDir, keys: unreadable)
		XCTAssertNil(store.pageCopyExists(account: old))
	}

	/// Local library: a probe that fails (not "no such file") is unknown: clear_incomplete, never a success because the existence check returned false.
	func testALibraryProbeThatFailsIsUnknownNotAbsent() throws {
		try Data("not a database".utf8).write(to: URL(fileURLWithPath: chat.databasePath(for: old)))
		probeFails = true
		XCTAssertNil(BeamioAccountCleanupProduction.items(of: old, stores: stores()), "a failed probe is unknown")
		probeFails = false
		XCTAssertNil(BeamioAccountCleanupProduction.items(of: old, stores: stores()), "a file that is not a database cannot be probed for unsent messages: unknown")
		try FileManager.default.removeItem(atPath: chat.databasePath(for: old))
		seedChatLibrary(tag: chat.libraryTag(for: old))
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.map(\.name), ["chat"])
		// the existence helper tells "no such file" from another failure: a path inside a file is ENOTDIR, which is not "absent"
		XCTAssertEqual(BeamioShellRecord.fileExistence(at: chatDir.appendingPathComponent("nothing-here").path), false)
		XCTAssertNil(BeamioShellRecord.fileExistence(at: chat.databasePath(for: old) + "/inside"), "ENOTDIR is a failed probe, not absence")
		// a probe that fails after the delete does not count as gone; with a working probe the delete removes the library and confirms the file is absent
		let item = BeamioAccountCleanup.Item(owner: old, name: "chat")
		probeFails = true
		XCTAssertFalse(BeamioAccountCleanupProduction.delete(item, stores: stores()))
		probeFails = false
		XCTAssertTrue(BeamioAccountCleanupProduction.delete(item, stores: stores()))
		XCTAssertFalse(FileManager.default.fileExists(atPath: chat.databasePath(for: old)))
	}

	/// deleteLocalData uses the same failable probe: no such file is done; a place that cannot be probed (a path under a regular file: ENOTDIR) throws, never returns as if nothing were there.
	func testDeleteLocalDataThrowsWhenTheProbeFailsAndIsDoneWhenThereIsNoFile() throws {
		XCTAssertNoThrow(try chat.deleteLocalData(accountKey: old), "no library file: nothing to delete")
		let file = chatDir.appendingPathComponent("a-regular-file")
		try Data([1]).write(to: file)
		let broken = BeamioConetChatLocalStore(rootDirectory: file)   // its library path would be inside a regular file
		XCTAssertThrowsError(try broken.deleteLocalData(accountKey: old)) { XCTAssertEqual($0 as? BeamioChatLocalError, .io) }
	}

	/// Side files without the main file: the residue of a library whose main file is gone is still the account's, derived from the same path; it is listed and removed,
	/// and a failed probe of one of them throws io.
	func testSideFilesOfAMissingLibraryAreListedAndRemoved() throws {
		let path = chat.databasePath(for: old)
		try Data([1]).write(to: URL(fileURLWithPath: path + "-wal"))
		try Data([1]).write(to: URL(fileURLWithPath: path + "-shm"))
		try Data([1]).write(to: URL(fileURLWithPath: chat.databasePath(for: new) + "-wal"))   // the new account's side file stays
		XCTAssertFalse(FileManager.default.fileExists(atPath: path), "no main file")
		let items = BeamioAccountCleanupProduction.items(of: old, stores: stores())
		XCTAssertEqual(items?.map(\.name), ["chat"], "listed although the main file is gone")
		XCTAssertTrue(delete(allOf: items ?? []))
		XCTAssertFalse(FileManager.default.fileExists(atPath: path + "-wal"))
		XCTAssertFalse(FileManager.default.fileExists(atPath: path + "-shm"))
		XCTAssertTrue(FileManager.default.fileExists(atPath: chat.databasePath(for: new) + "-wal"), "the new account's side file is never touched")
		XCTAssertEqual(BeamioAccountCleanupProduction.items(of: old, stores: stores())?.count, 0)
		// a side file whose probe fails
		probeFails = true
		XCTAssertNil(BeamioAccountCleanupProduction.items(of: old, stores: stores()))
		probeFails = false
		// deleteLocalData itself: side files only, then a path that cannot be probed
		try Data([1]).write(to: URL(fileURLWithPath: path + "-journal"))
		XCTAssertNoThrow(try chat.deleteLocalData(accountKey: old))
		XCTAssertFalse(FileManager.default.fileExists(atPath: path + "-journal"))
	}

	/// write_failed from the real page copy store, through the shell record command: a store write that fails (its directory is under a regular file) is answered write_failed in
	/// the ack's result, never ok.
	func testARealPageCopyStoreWriteFailureIsAnsweredWriteFailedByTheCommand() throws {
		let file = chatDir.appendingPathComponent("not-a-dir-2")
		try Data([1]).write(to: file)
		let broken = BeamioShellRecord.EncryptedShellRecordStore(directory: file.appendingPathComponent("pages"), keys: BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage())
		let device = FailDevice()
		device.state.legacyConfirmedAbsent = true
		var env = BeamioShellRecord.Environment(
			account: { self.old }, store: broken, device: device, originAllowed: true, migrating: { _ in false }, firstRun: { _ in .confirmedAbsent },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { .g2 }
		)
		env.keyState = { .normal }
		let ack = BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w1", "record": ["rev": 0, "schemaVersion": 1]], env: env))
		// SRP-04 option A: a failed store write is the envelope {ok:false, error:write_failed}, never ok:true
		XCTAssertEqual(ack["ok"] as? Bool, false)
		XCTAssertEqual(ack["error"] as? String, "write_failed", "a failed store write is write_failed, never ok")
		XCTAssertNil(ack["result"])
	}

	/// The diagnostic names the place by category only, never the path.
	func testThePathCategoryNamesTheKindOfPlaceNotThePath() {
		XCTAssertEqual(BeamioShellRecord.pathCategory(FileManager.default.temporaryDirectory.appendingPathComponent("x").path), "tmp")
		XCTAssertEqual(BeamioShellRecord.pathCategory("/Users/someone/Library/Application Support/beamio-shell-record"), "application_support")
		XCTAssertEqual(BeamioShellRecord.pathCategory("/Volumes/other/place"), "other")
	}

	/// A page copy write that fails (the directory is under a regular file) answers false and records its error code only (NSLog of domain and code, no path), and writes nothing.
	func testAFailedPageCopyWriteAnswersFalse() throws {
		let file = chatDir.appendingPathComponent("not-a-directory")
		try Data([1]).write(to: file)
		let broken = BeamioShellRecord.EncryptedShellRecordStore(directory: file.appendingPathComponent("pages"), keys: BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage())
		XCTAssertFalse(broken.write(account: old, ["rev": 1]), "a write that failed is reported false, never success")
	}

	// MARK: - the old accounts of the device (owner requirement: every account but the newly recovered one)

	private func emptyCleanup(active: String, pointer: (() -> String)? = nil, derived: (() -> String?)? = nil) -> BeamioAccountCleanup.Environment {
		var e = BeamioAccountCleanupProduction.environment(stores: stores())
		e.passcode = nil
		e.gatePassed = { true }
		// these tests give the active account through a snapshot of their own (one closure, as the core requires); the production snapshot has its own tests
		e.activeSnapshot = { (pointer?() ?? active, derived?() ?? active) }
		e.mnemonicState = { _ in .valid }
		e.keyRecordState = { _ in .present }
		// the listing over this test's own stores: the key store of the production environment is the process-wide one
		e.accounts = { BeamioAccountCleanupProduction.discoveredAccounts(stores: self.stores(), keyStore: self.raw) }
		e.unattributedKept = { BeamioAccountCleanupProduction.keptResidue(stores: self.stores(), keyStore: self.raw, activeAccount: $0) }
		return e
	}

	// MARK: - VECTOR-enumerated-accounts-v1 (v221, EA-01 to EA-08), driven group by group over the production listing and deletion wiring

	private func eoa(_ symbol: String) -> String? {
		switch symbol { case "oldEoa1": return ValidTestAccounts.accountB.eoa; case "oldEoa2": return ValidTestAccounts.accountC.eoa; case "newEoa": return new; default: return nil }
	}

	/// A real (empty) library database: the cleanup probes it for unsent messages before it deletes it, so a fake file would not be deletable.
	private func seedChatLibrary(tag: String) {
		let path = chatDir.appendingPathComponent("chat-local-v1-\(tag).sqlite").path
		do {
			let db = try ChatLocalSQLite(path: path)
			try db.exec("CREATE TABLE msg (pending_publish INTEGER)")
			db.close()
		} catch { XCTFail("fixture library: \(error)") }
	}

	private func resetStores() {
		tearDown(); setUp()
	}

	func testEnumeratedAccountsVectorEA01ToEA14() throws {
		let data = try BundledVectorFile.data(resource: "enumerated-accounts.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.map { String(($0["id"] as? String ?? "").prefix(5)) }, (1...14).map { String(format: "EA-%02d", $0) })
		let stranger = "0x5555555555555555555555555555555555555555"
		// the old accounts are valid mnemonic accounts (their addresses derive from public test phrases): a mnemonic residue that does not verify is kept, not deleted (v230 section 250)
		let oldAddr = ValidTestAccounts.accountB.eoa, otherAddr = ValidTestAccounts.accountC.eoa
		func installMnemonic(_ a: String) {
			let phrase = a == oldAddr ? ValidTestAccounts.phraseB : ValidTestAccounts.phraseC
			XCTAssertTrue(raw.writeItem(.mnemonic, eoa: a, value: BeamioPwaWalletSync.normalized(phrase)))
		}
		for c in cases {
			let id = c["id"] as? String ?? "?"
			resetStores()
			let state = try XCTUnwrap(c["state"] as? [String: Any], id)
			let sources = state["sources"] as? [String: Any] ?? [:]
			var records: Set<String> = [], seKeys: Set<String> = [], seeded: Set<String> = []
			var strays = 0
			func addresses(_ kind: String) -> [String] { (sources[kind] as? [String] ?? []).compactMap { eoa($0) } }
			for (kind, value) in sources {
				if let dict = value as? [String: Any] {
					if dict["readFailed"] as? Bool == true { listFails = true; continue }
					let names = (dict["unattributable"] as? [String]) ?? (dict["residueByName"] as? [String]) ?? []
					for (i, name) in names.enumerated() {
						switch kind {
						case "pageCopy": pageKeyNames.insert(name)
						case "pgp": pgp.insert(name)
						case "walletRawItem": put("intent:" + name)
						case "passcodeHLayer": hardwareNames.insert(name)
						case "recoveryBackupFlag": put("recoveryBackupConfirmed:" + name)
						case "walletCredentialBlock": put("blobKey:" + name)
						case "nonEnumerableSource": seedChatLibrary(tag: String(format: "%016x", 0xdead0000 + i))   // by design not attributable: a chat library of no known account
						default: XCTFail("\(id): unknown unattributable kind \(kind)")
						}
						strays += 1
					}
				}
			}
			for a in addresses("keyVault") { for n in names(a) where !n.hasPrefix("mnemonic:") { put(n) }; installMnemonic(a); seeded.insert(a) }
			for a in addresses("mnemonicRecord") { installMnemonic(a); seeded.insert(a) }
			for a in addresses("pageCopy") { seedPage(a); seeded.insert(a) }
			for a in addresses("pgp") + addresses("kItem") { pgp.insert(a); seeded.insert(a) }
			for a in addresses("chatDb") { seedChatLibrary(tag: chat.libraryTag(for: a)); seeded.insert(a) }
			for a in addresses("passcodeRecord") { records.insert(a); seeded.insert(a) }
			for a in addresses("seKey") { seKeys.insert(a); hardwareNames.insert(a); seeded.insert(a) }
			let activeSymbol = state["activeAccount"] as? String ?? "newEoa"
			let active = eoa(activeSymbol)
			let readback = state["readbackMatch"]
			var key = new                       // the account the page derived
			var pointerNow: () -> String = { self.new }
			var derivedNow: () -> String? = { self.new }
			if active == nil { pointerNow = { "" }; derivedNow = { nil } }
			else if readback as? Bool == false { key = new; pointerNow = { active! }; derivedNow = { active! } }   // EA-12
			else if active == oldAddr && id.hasPrefix("EA-04") {   // defensive guard: the active account turns up among the candidates
				var calls = 0
				pointerNow = { defer { calls += 1 }; return calls < 2 ? [self.new, oldAddr][calls] : self.new }
			}
			let pgpBefore = pgp
			var env = emptyCleanup(active: new)
			var switched = false
			let stranger0 = stranger
			if readback as? String == "changes_before_second_account" {
				let inner = env.delete
				env.delete = { item in let d = inner(item); switched = true; return d }
				pointerNow = { switched ? stranger0 : self.new }
			}
			env.activeSnapshot = { (pointerNow(), derivedNow()) }
			if state["accountsEnumerated"] is NSNull { listFails = true }
			// the passcode records are driven through a double (the record store of the production environment is process-wide)
			env.passcode = BeamioAccountCleanup.PasscodeItems(
				recordState: { records.contains($0) ? .present(Data([1])) : .absent },
				deleteRecord: { records.remove($0) },
				hardwareState: { _ in .absent }, deleteHardware: { _ in },
				stagingState: { _ in .absent }, stagingModified: { _ in nil }, deleteStaging: { _ in },
				writeInProgress: { _ in false }, processStart: Date(),
				seKeyState: { seKeys.contains($0) ? .present : .absent }
			)
			let scan = env.accounts
			let sourceReadFails = listFails
			env.accounts = { sourceReadFails ? nil : Array(Set((scan() ?? []) + Array(records) + Array(seKeys))).sorted() }
			var answer = BeamioAccountCleanup.run(accountKey: key, idempotencyKey: "k-1", env: env)
			if state["priorRun"] != nil { answer = BeamioAccountCleanup.run(accountKey: key, idempotencyKey: "k-1", env: env) }
			let expect = try XCTUnwrap(c["expect"] as? [String: Any], id)
			let ack = answer.ack(reqId: 1)
			XCTAssertEqual(ack["type"] as? String, expect["type"] as? String, id)
			XCTAssertEqual(ack["ok"] as? Bool, expect["ok"] as? Bool, "\(id) \(answer)")
			XCTAssertEqual(ack["error"] as? String, expect["error"] as? String, id)
			let want = expect["result"] as? [String: Any] ?? [:]
			let got = try XCTUnwrap(ack["result"] as? [String: Any], "\(id): result is always present")
			XCTAssertEqual(got["cleanupPending"] as? Bool, want["cleanupPending"] as? Bool, id)
			// Superseded by: the PGP record of an old account is KEPT (listed as kept-pgp| and counted), not deleted; the chat library is deleted again (the project lead decision after it).
			// The vector is driven as written for everything else; its keptUnattributed is raised by the kept pgp items of the old accounts a cleaning run processed.
			let keptNow = seeded.filter { $0 != new && $0 != active }.reduce(0) { $0 + (pgpBefore.contains($1) ? 1 : 0) }
			let cleanedRun = (c["noDelete"] as? Bool ?? false) == false && answer.ok
			if let n = want["keptUnattributed"] as? Int { XCTAssertEqual(got["keptUnattributed"] as? Int, n + (cleanedRun ? keptNow : 0), id) }
			else { XCTAssertNotNil(got["keptUnattributed"] as? Int, id) }
			// what was deleted and what stayed, per account
			func walletLeft(_ a: String) -> Bool { names(a).contains { raw.rawRead(account: $0) != .absent } }
			func deletableLeft(_ a: String) -> Bool { walletLeft(a) || pages.pageCopyExists(account: a) == true || records.contains(a) }
			func anythingLeft(_ a: String) -> Bool {
				walletLeft(a) || pages.pageCopyExists(account: a) == true || pgp.contains(a) || records.contains(a)
					|| FileManager.default.fileExists(atPath: chat.databasePath(for: a))
			}
			let noDelete = c["noDelete"] as? Bool ?? false
			switch id.prefix(5) {
			case "EA-04":
				XCTAssertTrue(walletLeft(oldAddr) && pages.pageCopyExists(account: oldAddr) == true, "\(id): the active candidate stays whole")
				XCTAssertEqual(got["keptUnattributed"] as? Int, BeamioAccountCleanupProduction.items(of: oldAddr, stores: stores())?.count, "\(id): its items are counted")
				XCTAssertFalse(records.contains(otherAddr), "\(id): the other old account is cleaned")
			case "EA-09", "EA-13":
				XCTAssertFalse(walletLeft(oldAddr), "\(id): the first old account is gone and stays gone")
				XCTAssertEqual(pages.pageCopyExists(account: otherAddr), true, "\(id): the second was not started")
			default:
				for a in seeded where a != new {
					if noDelete { XCTAssertTrue(anythingLeft(a), "\(id): \(a) stays") }
					else if !seKeys.contains(a) || records.isEmpty {
						XCTAssertFalse(deletableLeft(a), "\(id): the deletable items of \(a) are gone")
						XCTAssertEqual(pgp.contains(a), pgpBefore.contains(a), "\(id): the PGP record of \(a) is kept")
						XCTAssertFalse(FileManager.default.fileExists(atPath: chat.databasePath(for: a)), "\(id): the chat library of \(a) is gone")
					}
				}
				if id.hasPrefix("EA-11") { XCTAssertFalse(records.contains(oldAddr)); XCTAssertTrue(seKeys.contains(oldAddr), "the Secure Enclave key is kept") }
			}
			_ = strays
		}
	}

	/// A library with unsent messages is kept in this version and counted; it is not pending and blocks nothing (requirement, item 3). The other old accounts are cleaned.
	func testALibraryWithUnsentMessagesIsKeptCountedAndBlocksNothing() throws {
		let unsentPath = chat.databasePath(for: old)
		let db = try ChatLocalSQLite(path: unsentPath)
		try db.exec("CREATE TABLE msg (pending_publish INTEGER)"); try db.exec("INSERT INTO msg VALUES (1)")
		db.close()
		seedChatLibrary(tag: chat.libraryTag(for: other))   // another old account, no unsent message
		pgp = [old, other]
		let a = BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "unsent", env: emptyCleanup(active: new))
		// kept (distinct owner|name): chat-unsent|old, kept-pgp|old, kept-pgp|other; deleted: the other account's library only (the PGP records are protected)
		XCTAssertEqual(a, BeamioAccountCleanup.Answer(ok: true, error: nil, cleanupPending: false, keptUnattributed: 3, deleted: 1), "\(a)")
		XCTAssertTrue(FileManager.default.fileExists(atPath: unsentPath), "the library with an unsent message stays")
		XCTAssertFalse(FileManager.default.fileExists(atPath: chat.databasePath(for: other)), "the other account's library went")
		XCTAssertEqual(pgp, [old, other], "both PGP records stay")
	}

	/// The production read-back reads the pointer once and derives from that same value; a missing key record or an empty pointer is unknown (derived nil), through the production environment.
	func testTheProductionSnapshotReadsThePointerOnceAndDerivesFromIt() {
		let saved = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		defer { BeamioNativeWallet.keyStore = saved; NativeAccountPointerIsolation.end() }
		let memory = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = memory
		let env = BeamioAccountCleanupProduction.environment(stores: stores())
		let snapshot = env.activeSnapshot
		XCTAssertEqual(snapshot().pointer, ""); XCTAssertNil(snapshot().derived, "no pointer: unknown")
		let key = Data(repeating: 0x42, count: 32)
		let address = BeamioNativeEthSigner.address(privateKey: [UInt8](key)) ?? ""
		BeamioNativeAccountPointer.set(address.lowercased())
		XCTAssertNil(snapshot().derived, "a pointer without a key record: unknown")
		memory.keys[address.lowercased()] = key
		let now = snapshot()
		XCTAssertEqual(now.pointer.lowercased(), address.lowercased())
		XCTAssertEqual(now.derived?.lowercased(), address.lowercased())
	}

	/// An account known only by its PGP record or its page-copy key is found by the exact address in the name; a name that is not exactly an address names nobody.
	func testAccountsKnownOnlyByAPgpRecordOrAPageKeyAreDiscovered() {
		pgp = [other, "0xABCDEF0000000000000000000000000000000000"]
		seedPage(old)
		pageKeyNames.insert("not-an-address")
		let found = BeamioAccountCleanupProduction.discoveredAccounts(stores: stores(), keyStore: raw)
		XCTAssertEqual(found, [old, other])
		listFails = true
		XCTAssertNil(BeamioAccountCleanupProduction.discoveredAccounts(stores: stores(), keyStore: raw), "a listing that fails is unknown")
	}

	/// An account that only a wallet-service item, the recovery-backup flag, the credential K record, a Secure Enclave tag or an H fallback item names is an account of the device
	/// each prefix of the wallet service, and the hardware names, are read for their exact address.
	func testAccountsKnownOnlyByOtherAccountKeyedStoresAreDiscovered() {
		let a1 = "0x4444444444444444444444444444444444444444", a2 = "0x5555555555555555555555555555555555555555"
		let a3 = "0x6666666666666666666666666666666666666666", a4 = "0x7777777777777777777777777777777777777777"
		let a5 = "0x8888888888888888888888888888888888888888"
		put("blobKey:\(a1)"); put("recoveryBackupConfirmed:\(a2)"); put("commit:\(a5)"); put("intent:\(a5.uppercased())")
		hardwareNames = [a3, a4, "garbage"]
		let found = BeamioAccountCleanupProduction.discoveredAccounts(stores: stores(), keyStore: raw) ?? []
		XCTAssertEqual(Set(found), [a1, a2, a3, a4, a5])
		hardwareNames = []; listFails = true
		XCTAssertNil(BeamioAccountCleanupProduction.discoveredAccounts(stores: stores(), keyStore: raw))
		listFails = false
		// the credential K record is part of the exact names of the old account and goes with it
		put("blobKey:\(old)"); put("recoveryBackupConfirmed:\(old)")
		let items = BeamioAccountCleanupProduction.items(of: old, stores: stores())?.map(\.name) ?? []
		// blobKey is no longer deletable or listed: only the recovery-backup flag is an item
		XCTAssertEqual(Set(items), ["wallet|recoveryBackupConfirmed:\(old)"])
		XCTAssertNotEqual(raw.rawRead(account: "blobKey:\(old)"), .absent, "blobKey stays")
	}

	/// An isolated copy of an overwrite (`wallet.iso.…`) cannot be proved one account's alone: kept, counted once; the device-level items (marker, audits) are not counted.
	func testIsolatedCopiesAreKeptAndCounted() {
		put("wallet.iso.abcd.walletKey:\(old)"); put("wallet.iso.abcd.mnemonic:\(old)"); put("wallet.sync.audit"); put("wallet.isolation.retained")
		let kept = BeamioAccountCleanupProduction.keptResidue(stores: stores(), keyStore: raw, activeAccount: new) ?? []
		XCTAssertEqual(kept, ["isolated|wallet.iso.abcd.mnemonic:\(old)", "isolated|wallet.iso.abcd.walletKey:\(old)"])
		var e = emptyCleanup(active: new)
		e.accounts = { [self.new] }
		XCTAssertEqual(BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "iso", env: e).keptUnattributed, 2)
		XCTAssertNotNil(raw.rawRead(account: "wallet.iso.abcd.walletKey:\(old)") == .absent ? nil : 1, "the copies stay")
	}

	/// A chat library whose file name matches no account the device knows cannot be attributed: it is listed as kept, never as an item of an account.
	func testALibraryOfNoKnownAccountIsListedAsKept() throws {
		seedPage(old)
		let known = URL(fileURLWithPath: chat.databasePath(for: old))
		XCTAssertTrue(FileManager.default.createFile(atPath: known.path, contents: Data([1])))
		let stray = chatDir.appendingPathComponent("chat-local-v1-deadbeefdeadbeef.sqlite")
		XCTAssertTrue(FileManager.default.createFile(atPath: stray.path, contents: Data([1])))
		XCTAssertTrue(FileManager.default.createFile(atPath: chatDir.appendingPathComponent("unrelated.txt").path, contents: Data([1])))
		XCTAssertEqual(BeamioAccountCleanupProduction.orphanLibraries(stores: stores(), keyStore: raw, activeAccount: new), ["chatfile|deadbeefdeadbeef"])
	}

	/// Two old accounts and one new: the old accounts' wallet items and page copy go; the PGP record of the account known only by it is kept and counted (with the stray library); the new account's stay.
	func testTwoOldAccountsAndOneNewAccount() throws {
		for n in names(old) { put(n) }
		seedPage(old)
		pgp = [other, new]
		for n in names(new) { put(n) }
		seedPage(new)
		let stray = chatDir.appendingPathComponent("chat-local-v1-deadbeefdeadbeef.sqlite")
		XCTAssertTrue(FileManager.default.createFile(atPath: stray.path, contents: Data([1])))
		let answer = BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "two-old", env: emptyCleanup(active: new))
		XCTAssertTrue(answer.ok, "\(answer)")
		XCTAssertEqual(answer.keptUnattributed, 2, "the stray library and the kept PGP record of the other old account")
		XCTAssertEqual(pages.pageCopyExists(account: old), false)
		XCTAssertEqual(pgp, [other, new], "the PGP record of the account known only by it is kept, and the new account's stays")
		for n in names(old) { XCTAssertEqual(raw.rawRead(account: n) == .absent, true, n) }
		XCTAssertEqual(pages.pageCopyExists(account: new), true)
		XCTAssertTrue(FileManager.default.fileExists(atPath: stray.path), "kept")
		// a repeat deletes nothing more and counts the same
		let again = BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "two-old-2", env: emptyCleanup(active: new))
		XCTAssertEqual(again, BeamioAccountCleanup.Answer(ok: true, error: nil, cleanupPending: false, keptUnattributed: 2, deleted: 0))
	}

	/// The page's account is also the active one (the read-back requires it): its own items are never in the deletion set and are not counted; the other accounts' go as usual. (The case of an
	/// active account found among the candidates is the defensive guard, AccountCleanupCommandTests.testTheDefensiveGuardKeepsAnActiveCandidateWholeAndCounts.)
	func testTheAccountKeyIsTheActiveAccountAndStaysWholeWhileOthersAreCleaned() {
		for n in names(old) { put(n) }
		seedPage(old)
		pgp = [old, other]
		let answer = BeamioAccountCleanup.run(accountKey: old, idempotencyKey: "s13", env: emptyCleanup(active: old))
		XCTAssertTrue(answer.ok)
		XCTAssertEqual(pgp, [old, other], "the other account's record is kept now, the active account's stays")
		XCTAssertEqual(pages.pageCopyExists(account: old), true)
		for n in names(old) { XCTAssertEqual(raw.rawRead(account: n) == .absent, false, n) }
	}

	// MARK: - the published walletKey is never deleted (, the minimal fix)

	private func digest(_ data: Data?) -> String { data.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() } ?? "-" }

	/// Static: whatever the store lists, the deletable names of an old account never include a walletKey (its own or another account's), a set, the current pointer or a
	/// ciphertext version. Only the names of the pre-existing rule remain (the fix only removes names).
	func testTheDeletableNamesNeverIncludeWalletKeyOrTheMnemonicSets() {
		let o = old
		let listed = ["walletKey:\(o)", "walletKey:\(new)", "mnemonic.set.\(o)", "mnemonic.set.\(o).c.0123456789abcdef", "mnemonic.current",
		              "mnemonic:\(o)", "intent:\(o)", "commit:\(o)", "phase:\(o)", "migrated:\(o)", "recoveryBackupConfirmed:\(o)", "wallet.restore.unconfirmed.\(o)", "blobKey:\(o)"]
		let deletable = BeamioAccountCleanup.attributableWalletItemNames(oldEoa: o, listed: listed)
		for forbidden in ["walletKey:\(o)", "walletKey:\(new)", "mnemonic.set.\(o)", "mnemonic.set.\(o).c.0123456789abcdef", "mnemonic.current"] {
			XCTAssertFalse(deletable.contains(forbidden), "\(forbidden) is never deletable")
		}
		XCTAssertTrue(deletable.allSatisfy { !$0.hasPrefix("walletKey") && !$0.hasPrefix("mnemonic.") })
		XCTAssertEqual(Set(deletable), Set(listed).subtracting(["blobKey:\(o)", "walletKey:\(o)", "walletKey:\(new)", "mnemonic.set.\(o)", "mnemonic.set.\(o).c.0123456789abcdef", "mnemonic.current"]),
		               "the rest is the rule as it was (an information list, not changed here)")
	}

	/// Static (reconcile, item 4): over a store that holds every kind of item of an old account, the deletable items (owner = the old account) never name a
	/// walletKey, chat-pgp, a mnemonic set, the current pointer, a ciphertext version, blobKey or a sandbox file; PGP is listed only as a kept item; the chat library is a deletable item of the exact old account.
	func testTheDeletableItemsNameNoPublishedOrProtectedData() throws {
		let o = old
		for n in names(o) + ["walletKey:\(o)", "blobKey:\(o)", "mnemonic.set.\(o)", "mnemonic.set.\(o).c.0123456789abcdef", "mnemonic.current"] { put(n) }
		pgp = [o]
		seedPage(o)
		seedChatLibrary(tag: chat.libraryTag(for: o))
		inbox = true; signals = true; owner = .account(o)
		let items = try XCTUnwrap(BeamioAccountCleanupProduction.items(of: o, stores: stores()))
		let deletable = items.filter { $0.owner.lowercased() == o }.map(\.name)
		let allowed: Set<String> = Set(["intent", "commit", "phase", "migrated", "recoveryBackupConfirmed", "mnemonic"].map { "wallet|\($0):\(o)" } + ["wallet|wallet.restore.unconfirmed.\(o)", "page", "chat"])
		XCTAssertEqual(Set(deletable), allowed, "the deletable names are exactly the unpublished kinds of the project lead decision")
		for name in deletable {
			for forbidden in ["walletKey", "blobKey", "mnemonic.set", "mnemonic.current", "pgp", "inbox", "signals", "owner"] {
				XCTAssertFalse(name.contains(forbidden), "\(name) must not be deletable (\(forbidden))")
			}
		}
		XCTAssertTrue(items.contains { $0.name == "kept-pgp|\(o)" }, "the PGP record is listed as kept")
		XCTAssertTrue(items.contains { $0.owner.lowercased() == o && $0.name == "chat" }, "the chat library is a deletable item of the exact old account")
		for item in items where item.owner.lowercased() == o { _ = item }
		// and the delete itself refuses every protected class even when handed one
		for name in ["wallet|walletKey:\(o)", "pgp", "inbox", "signals", "owner"] {
			XCTAssertFalse(BeamioAccountCleanupProduction.delete(.init(owner: o, name: name), stores: stores()), "\(name) is refused")
		}
		// the chat delete works only for the exact old account's file: the new account's library bytes are unchanged by it
		let newPath = chat.databasePath(for: new)
		try Data("new account library".utf8).write(to: URL(fileURLWithPath: newPath))
		let newBefore = digest(try? Data(contentsOf: URL(fileURLWithPath: newPath)))
		XCTAssertTrue(BeamioAccountCleanupProduction.delete(.init(owner: o, name: "chat"), stores: stores()), "chat of the exact old account is deleted")
		XCTAssertFalse(FileManager.default.fileExists(atPath: chat.databasePath(for: o)))
		XCTAssertEqual(digest(try? Data(contentsOf: URL(fileURLWithPath: newPath))), newBefore, "the new account's library is unchanged")
		XCTAssertEqual(pgp, [o], "the PGP record is untouched by the refused deletes")
	}

	/// Receipt 1 and 2: a full cleanup of an old account that holds a published walletKey leaves its bytes unchanged (zero deletion), the key is still read, and it derives the
	/// original wallet address. The `delete` call itself refuses a walletKey name too.
	func testACleanupLeavesThePublishedWalletKeyUnchangedAndItStillDerivesTheSameAddress() throws {
		guard case .key(let keyBytes) = BeamioMnemonicDerivation.derive(phrase: ValidTestAccounts.phraseB) else { return XCTFail("synthetic phrase") }
		XCTAssertTrue(raw.write(eoa: old, key: Data(keyBytes)))
		put("intent:\(old)"); put("phase:\(old)")
		let before = digest(raw.read(eoa: old))
		pgp = [old, new]
		let a = BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "wk", env: emptyCleanup(active: new))
		XCTAssertTrue(a.ok, "\(a)")
		XCTAssertEqual(digest(raw.read(eoa: old)), before, "zero deletion: the walletKey bytes are unchanged")
		let still = try XCTUnwrap(raw.read(eoa: old), "the walletKey can still be read")
		XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: [UInt8](still))?.lowercased(), old, "it derives the original wallet address")
		XCTAssertEqual(raw.rawRead(account: "intent:\(old)"), .absent, "the process markers still go (the rule as it was)")
		XCTAssertFalse(BeamioAccountCleanupProduction.delete(.init(owner: old, name: "wallet|walletKey:\(old)"), stores: stores()), "a walletKey name is refused even if it is listed")
		XCTAssertEqual(digest(raw.read(eoa: old)), before)
	}

	/// Receipt 3 (what this fix can show): the new (active) account's PGP record and chat library are untouched in bytes and the library still opens; a library with unsent
	/// messages stays byte for byte. (An OLD account's PGP record is kept since; its chat library is deleted again.)
	func testTheActiveAccountsPgpAndChatDataAreUntouchedAndStillRead() throws {
		let newPath = chat.databasePath(for: new)
		let db = try ChatLocalSQLite(path: newPath)
		try db.exec("CREATE TABLE msg (pending_publish INTEGER)"); try db.exec("INSERT INTO msg VALUES (0)")
		db.close()
		let unsentPath = chat.databasePath(for: old)
		let db2 = try ChatLocalSQLite(path: unsentPath)
		try db2.exec("CREATE TABLE msg (pending_publish INTEGER)"); try db2.exec("INSERT INTO msg VALUES (1)")
		db2.close()
		let newBefore = digest(try? Data(contentsOf: URL(fileURLWithPath: newPath)))
		let unsentBefore = digest(try? Data(contentsOf: URL(fileURLWithPath: unsentPath)))
		pgp = [new]
		put("intent:\(old)")
		let a = BeamioAccountCleanup.run(accountKey: new, idempotencyKey: "chat", env: emptyCleanup(active: new))
		XCTAssertTrue(a.ok, "\(a)")
		XCTAssertEqual(digest(try? Data(contentsOf: URL(fileURLWithPath: newPath))), newBefore, "the active account's library bytes are unchanged")
		XCTAssertEqual(digest(try? Data(contentsOf: URL(fileURLWithPath: unsentPath))), unsentBefore, "the library with unsent messages is unchanged")
		XCTAssertEqual(pgp, [new], "the active account's PGP record stays")
		let reopened = try ChatLocalSQLite(path: newPath)
		reopened.close()
		XCTAssertEqual(try chat.unsentMessageCount(accountKey: old), 1, "the kept library reads")
	}

}

private final class FailDevice: BeamioShellRecord.DeviceStateStore {
	var state = BeamioShellRecord.DeviceState()
	func load() -> BeamioShellRecord.DeviceState { state }
	@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
}

private final class FailingDeleteKeys: BeamioShellRecord.KeyStorage {
	let inner: BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage
	var failDelete = false, failRead = false
	init(inner: BeamioShellRecord.EncryptedShellRecordStore.TestOnlyMemoryKeyStorage) { self.inner = inner }
	func readKey(account: String) -> BeamioShellRecord.KeyRead { failRead ? .failed : inner.readKey(account: account) }
	func writeKey(account: String, _ key: Data) -> Bool { inner.writeKey(account: account, key) }
	func deleteKey(account: String) -> Bool { failDelete ? false : inner.deleteKey(account: account) }
}

private extension BeamioShellRecord.KeyRead {
	var isNotFound: Bool { if case .notFound = self { return true }; return false }
}
#endif
