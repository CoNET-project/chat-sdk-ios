import XCTest
@testable import ConetChatSDK

/// The explicit restore (25.52Y.163 r2.5.19, 第 28、29 项): `restoreWrite` appends an entry and never changes the pointer; `restoreConfirm` points
/// the account at the restored EOA after the user's mark. The phrases are the BIP-39 test phrases; no key bytes are asserted in text.
final class RestoreWriteConfirmTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func eoa(_ phrase: String) -> String {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else {
			preconditionFailure("the test phrase derives an account")
		}
		return derived.eoa
	}

	private func restoreWrite(_ phrase: String, explicit: Bool = true, g2: Bool = false) -> BeamioNativeRestore.Answer {
		BeamioNativeRestore.restoreWrite(phrase: phrase, userExplicit: explicit, sessionIsG2: g2, store: store)
	}

	// 第 29(c) 項: without the explicit mark nothing is written, and the pointer is not set.
	func testWithoutTheExplicitMarkNothingIsWritten() {
		let writes = store.mutationCount
		XCTAssertEqual(restoreWrite(phraseA, explicit: false), .badRequest)
		XCTAssertEqual(BeamioNativeRestore.restoreConfirm(eoa: eoa(phraseA), userExplicit: false, store: store), .badRequest)
		XCTAssertEqual(store.mutationCount, writes, "nothing is written")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the pointer is not set")
	}

	// 第 28(d)1–2: the write appends the entry, reads it back, and leaves the pointer unchanged.
	func testRestoreWriteAppendsAndLeavesThePointerAlone() {
		XCTAssertEqual(restoreWrite(phraseA), .ok(eoa: eoa(phraseA)))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa(phraseA)), BeamioPwaWalletSync.normalized(phraseA))
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the write does not change the pointer")
	}

	// 第 28(c): a name already held is already_exists with its eoa, and nothing is written.
	func testAHeldNameIsAlreadyExistsAndNothingIsWritten() {
		XCTAssertEqual(restoreWrite(phraseA), .ok(eoa: eoa(phraseA)))
		let writes = store.mutationCount
		XCTAssertEqual(restoreWrite(phraseA), .alreadyExists(eoa: eoa(phraseA)))
		XCTAssertEqual(store.mutationCount, writes, "the held entry is not written again")
	}

	// 第 28(c): an entry of another name is kept as it is; the restore only appends.
	func testAnotherAccountIsKeptAsItIs() {
		XCTAssertEqual(restoreWrite(phraseB), .ok(eoa: eoa(phraseB)))
		let kept = store.readItem(.mnemonic, eoa: eoa(phraseB))
		XCTAssertNotNil(kept)
		XCTAssertEqual(restoreWrite(phraseA), .ok(eoa: eoa(phraseA)))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa(phraseB)), kept, "the other entry is not rewritten")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa(phraseA)), BeamioPwaWalletSync.normalized(phraseA))
	}

	// 第 28(e): an unlocked session answers already_exists and writes nothing.
	func testAnUnlockedSessionAnswersAlreadyExistsAndWritesNothing() {
		let writes = store.mutationCount
		XCTAssertEqual(restoreWrite(phraseA, g2: true), .alreadyExists(eoa: nil))
		XCTAssertEqual(store.mutationCount, writes)
	}

	// 第 28(a): an unreadable mnemonic record is not_ready, and the restore writes nothing.
	func testAnUnreadableRecordAnswersNotReadyAndWritesNothing() {
		XCTAssertEqual(restoreWrite(phraseB), .ok(eoa: eoa(phraseB)))
		store.mnemonic.failRead.insert(.mnemonic)
		let writes = store.mutationCount
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		XCTAssertEqual(store.mutationCount, writes, "nothing is written while the state is unreadable")
	}

	// 第 28(b): material that is not a valid mnemonic is import_failed, and nothing is written.
	func testInvalidMaterialIsImportFailedAndWritesNothing() {
		let writes = store.mutationCount
		XCTAssertEqual(restoreWrite("not a recovery phrase at all"), .importFailed)
		XCTAssertEqual(store.mutationCount, writes)
	}

	// 第 28(d)3–4: after the user's mark, restoreConfirm points the account at the restored EOA; the checked write reads back.
	func testRestoreConfirmSetsThePointerToTheRestoredAccount() {
		XCTAssertEqual(restoreWrite(phraseA), .ok(eoa: eoa(phraseA)))
		XCTAssertEqual(BeamioNativeRestore.restoreConfirm(eoa: eoa(phraseA), userExplicit: true, store: store), .ok(eoa: eoa(phraseA)))
		XCTAssertEqual(BeamioNativeAccountPointer.get(), eoa(phraseA))
	}

	// 第 28(d)4: a confirm for an account with no valid entry is not_ready, and the pointer is unchanged.
	func testRestoreConfirmOfAnAbsentEntryIsNotReadyAndKeepsThePointer() {
		XCTAssertEqual(BeamioNativeRestore.restoreConfirm(eoa: eoa(phraseA), userExplicit: true, store: store), .notReady)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "")
	}

	// 第 28(d)1: a write that fails before anything is written leaves no entry and answers import_failed.
	func testAFailedFirstWriteLeavesNoEntry() {
		store.failMutationAt = store.mutationCount + 1
		XCTAssertEqual(restoreWrite(phraseA), .importFailed)
		store.failMutationAt = nil
		XCTAssertNil(store.readItem(.mnemonic, eoa: eoa(phraseA)), "no entry is left behind")
	}

	private func marker(_ phrase: String) -> BeamioChatRawItem {
		store.rawRead(account: BeamioNativeRestore.unconfirmedAccount(eoa(phrase)))
	}

	// 第 28(d)2 (project ruling): a failed read-back keeps the entry and marks it unconfirmed. Nothing is rolled back, and the answer is not_ready.
	func testAFailedReadBackKeepsTheEntryAndMarksItUnconfirmed() {
		store.mnemonic.failRead.insert(.mnemonic)
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		store.mnemonic.failRead = []
		XCTAssertNotNil(store.readItem(.key, eoa: eoa(phraseA)), "the written key is kept")
		XCTAssertEqual(store.itemState(.intent, eoa: eoa(phraseA)), .absent, "the intent is removed, so no start-up rollback runs")
		XCTAssertNotEqual(marker(phraseA), .absent, "the entry is marked unconfirmed")
		// The mark keeps the entry out of the judgement: it is unreadable, never a valid account, and the preread is unknown.
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: store).readFailed, "an unconfirmed entry is not judged valid")
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .unknown,
		               "the unconfirmed entry is not silently selected")
	}

	// 第 28(d)2 (project ruling): the mark clears only after a verified read-back. An unverified confirm keeps the mark.
	func testTheMarkClearsOnlyAfterAVerifiedReadBack() {
		store.mnemonic.failRead.insert(.mnemonic)
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		store.mnemonic.failRead = []
		XCTAssertEqual(BeamioNativeRestore.restoreConfirm(eoa: eoa(phraseA), userExplicit: true, store: store), .notReady,
		               "an entry without its commit does not verify")
		XCTAssertNotEqual(marker(phraseA), .absent, "the mark stays")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the pointer is unchanged")
		// The record completes (its commit is written) and the read-back verifies: the confirm clears the mark and sets the pointer.
		XCTAssertTrue(store.writeItem(.commit, eoa: eoa(phraseA), value: Data(#"{"v":1}"#.utf8)))
		XCTAssertEqual(BeamioNativeRestore.restoreConfirm(eoa: eoa(phraseA), userExplicit: true, store: store), .ok(eoa: eoa(phraseA)))
		XCTAssertEqual(marker(phraseA), .absent, "a verified confirm clears the mark")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), eoa(phraseA))
	}

	// 第 28(d)2 (project ruling): a retry of the same restore that verifies clears the mark, and answers already_exists with nothing written.
	func testARetryThatVerifiesClearsTheMark() {
		store.mnemonic.failRead.insert(.mnemonic)
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		store.mnemonic.failRead = []
		XCTAssertTrue(store.writeItem(.commit, eoa: eoa(phraseA), value: Data(#"{"v":1}"#.utf8)))
		XCTAssertEqual(restoreWrite(phraseA), .alreadyExists(eoa: eoa(phraseA)))
		XCTAssertEqual(marker(phraseA), .absent, "the verified retry clears the mark")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the retry does not set the pointer")
	}

	// 残留裁定 (1): a failed removal of the intent keeps the entry marked; the start-up keeps it and removes the intent. Nothing is rolled back.
	func testAFailedIntentRemovalKeepsTheMarkedEntryAtStartup() {
		store.mnemonic.failRead.insert(.mnemonic)
		store.mnemonic.failDelete.insert(.intent)
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		store.mnemonic.failRead = []
		store.mnemonic.failDelete = []
		XCTAssertEqual(store.itemState(.intent, eoa: eoa(phraseA)), .present, "the intent stays beside the mark")
		XCTAssertNotEqual(marker(phraseA), .absent, "the mark is written before the intent removal")
		XCTAssertNotNil(store.readItem(.key, eoa: eoa(phraseA)))
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertNotNil(store.readItem(.key, eoa: eoa(phraseA)), "the start-up does not roll the kept entry back")
		XCTAssertNotNil(store.readItem(.mnemonic, eoa: eoa(phraseA)), "the kept mnemonic is not rolled back")
		XCTAssertEqual(store.itemState(.intent, eoa: eoa(phraseA)), .absent, "the start-up removes the intent")
		XCTAssertNotEqual(marker(phraseA), .absent, "the mark stays")
	}

	// 残留裁定 (2): a failed mark keeps the intent and the records, answers not_ready, and the next start retries the mark. No rollback.
	func testAFailedMarkKeepsTheIntentAndTheNextStartRetriesIt() {
		store.mnemonic.failRead.insert(.mnemonic)
		let base = store.mutationCount
		// The keep path mutates four times: the intent, the key, the mnemonic, and then the mark, which fails here.
		store.failMutationAt = base + 4
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		store.failMutationAt = nil
		store.mnemonic.failRead = []
		XCTAssertEqual(store.itemState(.intent, eoa: eoa(phraseA)), .present, "the intent is kept")
		XCTAssertNotNil(store.readItem(.key, eoa: eoa(phraseA)), "the records are kept")
		XCTAssertEqual(marker(phraseA), .absent, "the mark was not written")
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertNotEqual(marker(phraseA), .absent, "the next start retries and writes the mark")
		XCTAssertEqual(store.itemState(.intent, eoa: eoa(phraseA)), .absent, "the intent is removed once the mark is in place")
		XCTAssertNotNil(store.readItem(.key, eoa: eoa(phraseA)), "not rolled back")
	}

	// 残留裁定 (3): the start-up never rolls a kept restore entry back, however often it runs.
	func testTheStartupNeverRollsBackAKeptEntry() {
		store.mnemonic.failRead.insert(.mnemonic)
		XCTAssertEqual(restoreWrite(phraseA), .notReady)
		store.mnemonic.failRead = []
		for _ in 0..<3 {
			BeamioNativeKeyImport.reconcileIntents(store: store)
			XCTAssertNotNil(store.readItem(.key, eoa: eoa(phraseA)), "the key stays")
			XCTAssertNotNil(store.readItem(.mnemonic, eoa: eoa(phraseA)), "the mnemonic stays")
			XCTAssertNotEqual(marker(phraseA), .absent, "the entry stays marked, so it is never selected")
		}
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: store).readFailed, "the marked entry is not judged valid")
	}
}
