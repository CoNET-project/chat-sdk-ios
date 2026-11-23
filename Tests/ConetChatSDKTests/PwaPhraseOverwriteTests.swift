import XCTest
@testable import ConetChatSDK

/// The PWA write of `pwaWalletSync` (25.52Y.163 r2.5.19 第 59(3) 项; r2.5.21 decided order, project requirement). Accounts are synthetic:
/// A (old), B (new), C (a second new one). The phrases are BIP-39 test phrases; no key material is asserted in text.
///
/// Cases follow `spec-59e-synthetic-vectors.v2.json` (SO-01 to SO-14). SO-15 is the existing empty-signal rule (PwaEmptySignalDiscardTests).
/// SO-16 (user clear, pending decision (b)) and SO-17 (a clear without a user action) are not implemented: no clear path exists, so nothing is tested.
final class PwaPhraseOverwriteTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private let phraseC = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var nextSeq: Int64 = 100

	override func setUp() {
		super.setUp()
		// This class tests the withdrawn overwrite and sealing format of the phrase write (never published). The production phrase write goes into the set storage
		// (finalized section 1); the test seam turns the old write on here only.
		BeamioPwaWalletSync.legacyPhraseWriteForTests = true
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		useFreshStore()
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioPwaWalletSync.legacyPhraseWriteForTests = false
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioPwaPhraseOverwrite.wrapAliasProbe = { _ in .present }
		BeamioPwaPhraseOverwrite.enumerationSucceeds = { $0.enumerateKeyOwners() != nil }
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func useFreshStore() {
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
	}

	private func account(_ phrase: String) -> (eoa: String, key: Data) {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else {
			preconditionFailure("the test phrase derives an account")
		}
		return derived
	}

	/// The three records of an account, written the way an import writes them, and its K record.
	private func seed(_ phrase: String) {
		let a = account(phrase)
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phrase)))
		XCTAssertTrue(store.writeItem(.commit, eoa: a.eoa, value: Data(#"{"v":1}"#.utf8)))
		// The K record of the account (a stand-in payload: the overwrite copies and restores bytes, it does not read K).
		store.rawAccounts[BeamioWalletCredentialBlob.account(a.eoa)] = Data("k-record-of-the-account".utf8)
	}

	private func sync(_ phrase: String, eoaClaim: String? = nil) -> [String: Any] {
		nextSeq += 1
		var body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "trustedOrigin": true,
		                           "seq": NSNumber(value: nextSeq), "phrase": phrase]
		if let eoaClaim { body["eoa"] = eoaClaim }
		return BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)
	}

	private func syncResult(_ answer: [String: Any]) -> String? {
		(answer["result"] as? [String: Any])?["sync"] as? String
	}

	private func resultCode(_ answer: [String: Any]) -> String? {
		answer["error"] as? String
	}

	private func resultReason(_ answer: [String: Any]) -> String? {
		answer["reason"] as? String
	}

	/// The raw state of the records of an account (key, mnemonic, commit, K), in a fixed order; `.absent` for a missing one.
	private func snapshot(_ eoa: String) -> [BeamioChatRawItem] {
		BeamioPwaPhraseOverwrite.ownerAccounts(eoa, store: store).map { store.rawRead(account: $0) }
	}

	private func presentBytes(_ items: [BeamioChatRawItem]) -> [Data] {
		items.compactMap { item -> Data? in
			if case .present(let bytes) = item { return bytes }
			return nil
		}
	}

	/// The payloads of every isolation copy on the device.
	private func isolatedValues() -> [Data] {
		store.rawAccounts.filter { $0.key.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) }.map { $0.value }
	}

	/// The entries of `isolation.retained`, in the order they were written.
	private func retainedEntries() -> [[String: Any]] {
		guard case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.retainedAccount) else { return [] }
		return (try? JSONSerialization.jsonObject(with: bytes) as? [[String: Any]]) ?? []
	}

	private func markerPhase() -> String? {
		guard case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount),
		      let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any]
		else { return nil }
		return object["phase"] as? String
	}

	private func assertNoMarker(file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "no intent marker is left", file: file, line: line)
	}

	private func assertNothingOfNewAccount(_ eoa: String, file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertEqual(snapshot(eoa), [.absent, .absent, .absent, .absent], "nothing of the new account is left", file: file, line: line)
	}

	/// Moves the mnemonic record of an account to an isolation copy by hand, the way a seal does, and writes a marker of the given phase.
	private func stageSealedMnemonic(of oldPhrase: String, tag: String, phase: String, digestOf bytes: Data? = nil) -> (copy: String, live: String) {
		let old = account(oldPhrase).eoa
		let live = store.accountName(.mnemonic, eoa: old)
		let copy = BeamioPwaPhraseOverwrite.isolationPrefix + tag + "." + live
		let original = BeamioPwaWalletSync.normalized(oldPhrase)
		XCTAssertTrue(store.rawWrite(account: copy, bytes: bytes ?? original))
		XCTAssertTrue(store.rawDelete(account: live))
		let newEoa = account(phraseB).eoa
		let marker: [String: Any] = [
			"v": 1, "phase": phase, "eoa": newEoa, "tag": tag, "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [old], "moves": [["from": live, "to": copy, "digest": BeamioPwaPhraseOverwrite.digest(original)]],
		]
		let data = try! JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])
		XCTAssertTrue(store.rawWrite(account: BeamioPwaPhraseOverwrite.markerAccount, bytes: data))
		return (copy, live)
	}

	// 第 59(3)(b): an absent account is created.
	func testAnAbsentAccountIsCreatedAndSynced() {
		let answer = sync(phraseA)
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(syncResult(answer), "updated")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: account(phraseA).eoa), BeamioPwaWalletSync.normalized(phraseA))
	}

	// 第 59(3)(c) (SO-13): the same account and the same phrase are idempotent: nothing is written, no seal, no audit.
	func testTheSamePhraseIsIdempotentAndWritesNothing() {
		seed(phraseA)
		let writes = store.mutationCount
		let answer = sync(phraseA)
		XCTAssertEqual(syncResult(answer), "idempotent")
		XCTAssertEqual(store.mutationCount, writes, "an idempotent sync writes nothing")
		XCTAssertNil(store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount], "no audit row")
	}

	// SO-14: the phrase must derive the PWA's account; a mismatch is bad_request, before any seal or marker.
	func testAMismatchedAccountClaimIsBadRequestBeforeAnySeal() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let writes = store.mutationCount
		let answer = sync(phraseB, eoaClaim: oldEoa)
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual((answer["error"] as? String), "bad_request")
		XCTAssertEqual(store.mutationCount, writes, "nothing is written, no marker")
		assertNoMarker()
		XCTAssertEqual(snapshot(oldEoa).count, 4)
	}

	// SO-01: a different record is overwritten; the old records are sealed (renamed, not deleted), the copies hold the old bytes, the marker is
	// removed, `isolation.retained` records the overwrite, and the account reads as valid.
	func testSuccessfulOverwriteKeepsTheCopiesAndRecordsRetained() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originals = snapshot(oldEoa)
		let answer = sync(phraseB)
		XCTAssertEqual(syncResult(answer), "updated")
		XCTAssertEqual(snapshot(oldEoa), [.absent, .absent, .absent, .absent], "the live old records are sealed aside")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: newEoa), BeamioPwaWalletSync.normalized(phraseB))
		XCTAssertEqual(isolatedValues().count, 4, "one isolated copy per old record, K included")
		XCTAssertEqual(Set(isolatedValues()), Set(presentBytes(originals)), "the copies hold the old bytes")
		assertNoMarker()
		let entries = retainedEntries()
		XCTAssertEqual(entries.count, 1)
				XCTAssertEqual(entries.first?["oldEoa"] as? String, oldEoa)
		XCTAssertNil(entries.first?["oldKeyID"], "v3.3: the keyID is not stored; oldEoa is the account")
		let names = Set(entries.first?["isolatedNames"] as? [String] ?? [])
		XCTAssertEqual(names.count, 4, "the isolated names of the old record")
		XCTAssertTrue(names.allSatisfy { store.rawRead(account: $0) != .absent }, "each named copy is on the device")
		XCTAssertEqual((entries.first?["oldSha"] as? [String])?.count, 4)
		XCTAssertNotNil(entries.first?["auditRef"])
		if case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount) {
			XCTAssertEqual((try? JSONSerialization.jsonObject(with: bytes) as? [Any])?.count, 4, "one audit row per sealed record")
		} else {
			XCTFail("the audit is written before any rename")
		}
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .valid, "after success the state is known (retained), not unknown")
		XCTAssertEqual(reading.eoa, newEoa)
	}

	// 第 59(3)(d): an unreadable record of the same account is write_failed with internal_state, and nothing is written.
	func testAnUnreadableRecordAnswersInternalStateAndWritesNothing() {
		seed(phraseA)
		store.mnemonic.failRead.insert(.mnemonic)
		let writes = store.mutationCount
		let answer = sync(phraseA)
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state")
		XCTAssertEqual(store.mutationCount, writes, "nothing is written")
	}

	// SO-02: the sealed copy does not match its digest on read-back. Sealing failed, the old records are restored from the live names (never
	// touched), the bad copy is removed, the new account is not written, and the answer is retryable.
	func testASealReadbackFailureRestoresTheOldRecordAndWritesNothing() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originals = snapshot(oldEoa)
		store.corruptWritePrefixes = [BeamioPwaPhraseOverwrite.isolationPrefix]
		let answer = sync(phraseB)
		store.corruptWritePrefixes = []
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "the internal label sealing_failed is not sent")
		XCTAssertEqual(snapshot(oldEoa), originals, "the old records are byte for byte as before")
		assertNothingOfNewAccount(newEoa)
		XCTAssertTrue(isolatedValues().isEmpty, "the failed seal leaves no copy")
		assertNoMarker()
	}

	// SO-03 (v3.1 step 5): the old account's mnemonic record does not open to the old account, and it is not confirmed lost. That is unknown before any
	// seal: nothing is renamed, no marker is written, and the answer is retryable.
	func testAnUnopenableOldRecordIsUnknownBeforeAnySealAndNothingChanges() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: oldEoa, value: BeamioPwaWalletSync.normalized(phraseB)))
		let originals = snapshot(oldEoa)
		let answer = sync(phraseB)
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "unknown before the seal: not openable and not confirmed lost")
		XCTAssertEqual(snapshot(oldEoa), originals, "the old records are byte for byte as before")
		assertNothingOfNewAccount(newEoa)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
	}

	// SO-04: the first write of the new account fails with nothing written: the sealed copies return to their names; retryable.
	func testAFailedFirstNewWriteRestoresTheOldRecord() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originals = snapshot(oldEoa)
		store.failWriteAccounts = [store.accountName(.key, eoa: newEoa)]
		let answer = sync(phraseB)
		store.failWriteAccounts = []
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "storage_write")
		XCTAssertEqual(snapshot(oldEoa), originals, "the old records are back under their names")
		assertNothingOfNewAccount(newEoa)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
	}

	// SO-05: a write fails after the key of the new account is written: a new name holds data, so both sides are kept, the marker stays, the state is
	// unknown, nothing is deleted.
	func testAPartialNewWriteKeepsBothSidesAndTheMarker() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		store.failWriteAccounts = [store.accountName(.mnemonic, eoa: newEoa)]
		let answer = sync(phraseB)
		store.failWriteAccounts = []
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "rollback pending")
		XCTAssertEqual(snapshot(oldEoa), [.absent, .absent, .absent, .absent], "the old live records stay sealed, not restored")
		XCTAssertEqual(isolatedValues().count, 4, "the copies are kept")
		XCTAssertEqual(markerPhase(), "pending", "the marker stays")
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .valid, "2026-11-17: the sealed copy of the old account holds a valid phrase, so the window does not block the reading")
	}

	// SO-06: the new records do not read back: readback_mismatch with a new name holding data. Both sides kept, marker stays, state unknown.
	func testAReadbackMismatchWithANewNameKeepsBothSides() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		store.dropWriteAccounts = [store.accountName(.mnemonic, eoa: newEoa)]
		let answer = sync(phraseB)
		store.dropWriteAccounts = []
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "the internal label readback_mismatch is not sent")
		XCTAssertEqual(isolatedValues().count, 4)
		XCTAssertEqual(snapshot(oldEoa), [.absent, .absent, .absent, .absent])
		XCTAssertEqual(markerPhase(), "pending", "the marker stays")
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .valid, "2026-11-17: the sealed copy of the old account holds a valid phrase, so the window does not block the reading")
	}

	// SO-07: the new records do not read back and no new name holds data: the old records are restored; retryable.
	func testAReadbackMismatchWithNoNewNameRestoresTheOldRecord() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originals = snapshot(oldEoa)
		store.dropWriteAccounts = [store.accountName(.key, eoa: newEoa), store.accountName(.mnemonic, eoa: newEoa),
		                           store.accountName(.commit, eoa: newEoa)]
		let answer = sync(phraseB)
		store.dropWriteAccounts = []
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "the internal label readback_mismatch is not sent")
		XCTAssertEqual(snapshot(oldEoa), originals)
		assertNothingOfNewAccount(newEoa)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
	}

	// The committed marker cannot be written: the state is unknown, nothing is cleaned up, the copies stay; the next start finishes the commit.
	func testACommittedMarkerWriteFailureIsUnknownAndTheRecoveryFinishes() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		store.failRawWriteContaining = "\"phase\":\"committed\""
		let answer = sync(phraseB)
		store.failRawWriteContaining = nil
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state")
		XCTAssertEqual(isolatedValues().count, 4, "the copies are kept")
		XCTAssertEqual(markerPhase(), "pending")
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .valid, "2026-11-17: the sealed copy of the old account holds a valid phrase, so the window does not block the reading")
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		assertNoMarker()
		XCTAssertEqual(store.readItem(.mnemonic, eoa: newEoa), BeamioPwaWalletSync.normalized(phraseB))
		XCTAssertEqual(snapshot(oldEoa), [.absent, .absent, .absent, .absent])
		XCTAssertEqual(isolatedValues().count, 4)
		XCTAssertEqual(retainedEntries().count, 1)
	}

	// 第 59(3)(e)(7): an interruption at every mutating call of the overwrite. For each interruption, the recovery at the next start settles the state to
	// one of two: the new record is in place (copies and the retained entry kept, marker removed), or the old record is restored byte for byte and
	// nothing of the new account is left.
	func testAnInterruptionAtAnyMutationSettlesToOneOfTwoStates() {
		useFreshStore()
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originals = snapshot(oldEoa)
		let base = store.mutationCount
		XCTAssertEqual(syncResult(sync(phraseB)), "updated", "a clean overwrite succeeds")
		let total = store.mutationCount - base
		XCTAssertGreaterThan(total, 6, "the overwrite makes several mutations")
		for n in 1...total {
			useFreshStore()
			seed(phraseA)
			store.failMutationAt = store.mutationCount + n
			let answer = sync(phraseB)
			store.failMutationAt = nil
			// Whatever the answer, the recovery at the next start settles what is left.
			let settled = BeamioPwaPhraseOverwrite.recoverAtStart(store: store)
			let newInPlace = store.readItem(.mnemonic, eoa: newEoa) == BeamioPwaWalletSync.normalized(phraseB)
			// Settled-state assertions for interruption points 17 and 18 (review 2026-11-17): the settled state is the new one, with exactly one valid
			// account, every old record in an isolation name, and the marker settled.
			if n == 17 || n == 18 {
				XCTAssertTrue(settled && newInPlace, "interruption \(n): settles to the new state")
				XCTAssertEqual(store.mnemonicAccountState(owner: newEoa), .valid, "interruption \(n): the new account is valid")
				XCTAssertNotEqual(store.mnemonicAccountState(owner: oldEoa), .valid, "interruption \(n): the old account is not a second valid account")
				XCTAssertEqual(isolatedValues().count, 4, "interruption \(n): every old record is in an isolation name")
				XCTAssertEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "interruption \(n): the marker is settled")
			}
			if !settled {
				// Kept (spec v2 section three): a new name holds data, so both sides stay, the marker stays and the state is unknown.
				XCTAssertNotEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "interruption \(n): the marker stays")
				XCTAssertEqual(isolatedValues().count, 4, "interruption \(n): copies kept")
				XCTAssertEqual(snapshot(oldEoa), [.absent, .absent, .absent, .absent], "interruption \(n): old live records stay sealed")
				XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .unknown,
				               "interruption \(n): the state is unknown")
				XCTAssertEqual(resultCode(answer), "write_failed", "interruption \(n): a failed answer")
			} else if newInPlace {
				assertNoMarker()
				XCTAssertEqual(Set(isolatedValues()), Set(presentBytes(originals)), "interruption \(n): copies kept with the old bytes")
				XCTAssertEqual(isolatedValues().count, 4, "interruption \(n): one copy per old record")
				XCTAssertEqual(snapshot(oldEoa), [.absent, .absent, .absent, .absent], "interruption \(n): old live records sealed aside")
				XCTAssertEqual(retainedEntries().count, 1, "interruption \(n): one retained entry")
			} else {
				XCTAssertEqual(resultCode(answer), "write_failed", "interruption \(n): a failed answer")
				XCTAssertEqual(snapshot(oldEoa), originals, "interruption \(n): the old record is restored byte for byte")
				assertNothingOfNewAccount(newEoa)
				XCTAssertTrue(isolatedValues().isEmpty || isolatedValues().count >= 4, "interruption \(n): no copy after a rollback, or the window keeps the four sealed copies and the partial new records")
				XCTAssertTrue(retainedEntries().isEmpty, "interruption \(n): no retained entry for a rolled-back overwrite")
				assertNoMarker()
			}
		}
	}

	// SO-08: interrupted after the seal and before the new write (new name empty, copy digest matches): the startup restores the old record; the copy
	// returns to its name; an audit row says so; the marker goes.
	func testStartupRestoresASealedRecordWhenNoNewNameHoldsData() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let originals = snapshot(oldEoa)
		let staged = stageSealedMnemonic(of: phraseA, tag: "t8", phase: "prepared")
		XCTAssertEqual(store.rawRead(account: staged.live), .absent)
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		XCTAssertEqual(snapshot(oldEoa), originals, "the old record is back, byte for byte")
		XCTAssertEqual(store.rawRead(account: staged.copy), .absent)
		assertNoMarker()
		if case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount) {
			XCTAssertTrue(String(decoding: bytes, as: UTF8.self).contains("recovery_restore"), "the restore is audited")
		} else {
			XCTFail("the restore is audited")
		}
	}

	// SO-09: interrupted after the new write and before the marker is settled: the startup rolls forward (retained entry), keeps the copy, clears
	// the marker.
	func testStartupRollsForwardWhenTheNewRecordIsConsistent() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let oldBytes = BeamioPwaWalletSync.normalized(phraseA)
		let staged = stageSealedMnemonic(of: phraseA, tag: "t9", phase: "prepared")
		seed(phraseB)
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: newEoa), BeamioPwaWalletSync.normalized(phraseB))
		XCTAssertEqual(store.rawRead(account: staged.copy), .present(oldBytes), "the copy is kept")
		XCTAssertEqual(retainedEntries().count, 1)
		assertNoMarker()
		// The staged record is the mnemonic only; the other old records were never moved in this staging.
		XCTAssertEqual(snapshot(oldEoa)[1], .absent)
	}

	// SO-10: the new name is empty and the copy does not match its digest: nothing is restored, the marker stays, the copy stays.
	func testStartupKeepsAMismatchingCopyAndTheMarker() {
		seed(phraseA)
		let staged = stageSealedMnemonic(of: phraseA, tag: "t10", phase: "pending", digestOf: Data("not-the-old-bytes".utf8))
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		XCTAssertEqual(store.rawRead(account: staged.live), .absent, "the live name stays empty")
		XCTAssertNotEqual(store.rawRead(account: staged.copy), .absent, "the copy stays")
		XCTAssertEqual(markerPhase(), "pending", "the marker stays")
	}

// SO-11 / SO-04 of v1 (superseded in its unknown rule by -59E-halfwrite, 2026-11-17): while the intent marker exists, reading never renames, deletes or opens a copy.
	func testReadingWhileTheMarkerExistsChangesNothing() {
		seed(phraseA)
		let staged = stageSealedMnemonic(of: phraseA, tag: "t11", phase: "pending")
		let writes = store.mutationCount
		for _ in 0..<3 {
			let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
			XCTAssertEqual(reading.state, .valid, "2026-11-17: a marker does not block the reading; the sealed copy holds a valid phrase")
		}
		XCTAssertEqual(store.mutationCount, writes, "reads write, rename and delete nothing")
		XCTAssertEqual(store.rawRead(account: staged.copy), .present(BeamioPwaWalletSync.normalized(phraseA)), "the copy is not opened or moved by a read")
		XCTAssertEqual(store.rawRead(account: staged.live), .absent)
	}

	// SO-12: after success the state is known (retained), and three reads change no file.
	func testRetainedStateIsKnownAfterSuccessAndReadsChangeNothing() {
		seed(phraseA)
		let newEoa = account(phraseB).eoa
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		let writes = store.mutationCount
		for _ in 0..<3 {
			let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
			XCTAssertEqual(reading.state, .valid)
			XCTAssertEqual(reading.eoa, newEoa)
		}
		XCTAssertEqual(store.mutationCount, writes)
		XCTAssertEqual(isolatedValues().count, 4)
	}

	// SO-13 (after success): a startup and a same-account sync keep the copies and write nothing.
	func testStartupAndSameAccountSyncKeepTheCopies() {
		seed(phraseA)
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		let writes = store.mutationCount
		let answer = sync(phraseB)
		XCTAssertEqual(syncResult(answer), "idempotent")
		XCTAssertEqual(store.mutationCount, writes, "an idempotent sync writes nothing")
		XCTAssertEqual(isolatedValues().count, 4, "the copies are still there")
		XCTAssertEqual(retainedEntries().count, 1, "the retained entry is not repeated")
	}

	// SO-19: the second of the records fails to seal (its removal). The first is restored byte for byte, nothing new is written, and the answer is retryable.
	func testAFailedSecondSealRestoresTheFirstAndWritesNothing() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originals = snapshot(oldEoa)
		let base = store.mutationCount
		// The marker is the 1st mutation; each record then costs three (audit, copy, removal of the live name). The 6th is the removal of the 2nd record (its rename fails before the audit row).
		store.failMutationAt = base + 6
		let answer = sync(phraseB)
		store.failMutationAt = nil
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "the internal label sealing_failed is not sent")
		XCTAssertEqual(snapshot(oldEoa), originals, "every old record is back under its name, byte for byte")
		assertNothingOfNewAccount(newEoa)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
	}

	// SO-20: the second record fails to seal and the restore of the first also fails: both sides stay, the marker stays, the state is unknown.
	func testAFailedRestoreKeepsBothSidesAndTheMarker() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let base = store.mutationCount
		store.failMutationAt = base + 6
		store.failWriteAccounts = [store.accountName(.key, eoa: oldEoa)]
		let answer = sync(phraseB)
		store.failMutationAt = nil
		store.failWriteAccounts = []
		XCTAssertEqual(resultCode(answer), "write_failed")
		XCTAssertEqual(resultReason(answer), "internal_state", "rollback pending")
		XCTAssertEqual(isolatedValues().count, 1, "the first copy stays")
		XCTAssertNotEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "the marker stays")
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .valid, "2026-11-17: the sealed copy of the old account holds a valid phrase, so the window does not block the reading")
		assertNothingOfNewAccount(newEoa)
	}

	// SO-22A: the old record does not open and is confirmed lost (the WK seam says so). The overwrite proceeds: the new account is written and marked;
	// the old bytes stay isolated and none is deleted; the audit records the loss.
	func testAConfirmedLostOldRecordIsOverwrittenAndItsBytesStayIsolated() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: oldEoa, value: Data("not a recovery phrase".utf8)))
		// Section four, condition 3: no readable key either. Condition 2 (the wrap alias missing) comes from the seam; condition 1 (enumeration) is the default.
		XCTAssertTrue(store.rawDelete(account: store.accountName(.key, eoa: oldEoa)))
		let originals = snapshot(oldEoa)
		BeamioPwaPhraseOverwrite.wrapAliasProbe = { $0 == oldEoa ? .itemNotFound : .present }
		let b = account(phraseB)
		let result = BeamioPwaPhraseOverwrite.run(eoa: newEoa, phrase: BeamioPwaWalletSync.normalized(phraseB), key: b.key, owners: [oldEoa],
		                                          store: store, utc: "2026-11-17T00:00:00Z", tag: "t22a")
		XCTAssertEqual(result, .updated)
		XCTAssertEqual(Set(isolatedValues()), Set(presentBytes(originals)), "the old bytes stay isolated; none is deleted")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: newEoa), BeamioPwaWalletSync.normalized(phraseB))
		assertNoMarker()
		XCTAssertEqual(retainedEntries().count, 1)
		if case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount) {
			XCTAssertTrue(String(decoding: bytes, as: UTF8.self).contains("pwa_sync_confirmed_lost"), "the loss is audited")
		} else {
			XCTFail("the audit is written")
		}
	}

	// SO-22B: the old record does not open and is not confirmed lost: unknown. Nothing is written, sealed or renamed; the answer is retryable.
	func testAnUnknownOldRecordWritesNothingAndIsRetryable() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		// aead_failed is a read failure (the record cannot be decrypted), not a readable invalid phrase: an unreadable item.
		store.mnemonic.failRead.insert(.mnemonic)
		let originals = snapshot(oldEoa)
		let writes = store.mutationCount
		let b = account(phraseB)
		let result = BeamioPwaPhraseOverwrite.run(eoa: newEoa, phrase: BeamioPwaWalletSync.normalized(phraseB), key: b.key, owners: [oldEoa],
		                                          store: store, utc: "2026-11-17T00:00:00Z", tag: "t22b")
		XCTAssertEqual(result, .internalState)
		XCTAssertEqual(store.mutationCount, writes, "nothing is written")
		XCTAssertEqual(snapshot(oldEoa), originals)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
		assertNothingOfNewAccount(newEoa)
	}

	// SO-23: isolation.retained holds only the six non-secret fields, under its own key, and not in the wallet record or the audit file.
	func testIsolationRetainedHoldsOnlyTheSixNonSecretFields() {
		seed(phraseA)
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		let entries = retainedEntries()
		XCTAssertEqual(entries.count, 1)
		XCTAssertEqual(Set((entries.first ?? [:]).keys), ["oldEoa", "time", "auditRef", "isolatedNames", "oldSha"])
		guard case .present(let raw) = store.rawRead(account: BeamioPwaPhraseOverwrite.retainedAccount) else {
			return XCTFail("the retained record is stored under its own key")
		}
		let text = String(decoding: raw, as: UTF8.self)
		// The isolated names are account names, and the copy names carry the record kind ("mnemonic:", "walletKey:"); the forbidden check is on the
		// field names and on the secret words that could only appear as content.
		for forbidden in ["phrase", "privateKey", "password", "passcode", "pgpPrivateKey", "ciphertext"] {
			XCTAssertFalse(text.contains(forbidden), "no \(forbidden) in the retained record")
		}
		XCTAssertFalse(entries.contains { $0.keys.contains("pin") }, "no pin field")
		if case .present(let audit) = store.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount) {
			XCTAssertFalse(String(decoding: audit, as: UTF8.self).contains("isolation.retained"), "not in the audit file")
		}
	}

	// SO-22C / SO-22D: the keystore enumeration fails (or the keystore is not available): the state is unknown, so nothing is written, sealed or renamed.
	func testAFailedEnumerationOrUnavailableKeystoreIsUnknownAndWritesNothing() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: oldEoa, value: Data("not a recovery phrase".utf8)))
		XCTAssertTrue(store.rawDelete(account: store.accountName(.key, eoa: oldEoa)))
		let originals = snapshot(oldEoa)
		BeamioPwaPhraseOverwrite.wrapAliasProbe = { $0 == oldEoa ? .itemNotFound : .present }
		BeamioPwaPhraseOverwrite.enumerationSucceeds = { _ in false }
		let writes = store.mutationCount
		let b = account(phraseB)
		let result = BeamioPwaPhraseOverwrite.run(eoa: newEoa, phrase: BeamioPwaWalletSync.normalized(phraseB), key: b.key, owners: [oldEoa],
		                                          store: store, utc: "2026-11-17T00:00:00Z", tag: "t22c")
		XCTAssertEqual(result, .internalState)
		XCTAssertEqual(store.mutationCount, writes, "nothing is written, sealed or renamed")
		XCTAssertEqual(snapshot(oldEoa), originals)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
	}

	/// The SDK side of "an old native account does not hold the page": a pwaWalletSync over an existing other account answers at once with a
	/// definite word, once, with no retry loop inside the SDK (a retry is the PWA's decision). Success: `updated`, the old records sealed and kept.
	/// An old account whose record cannot be judged: `write_failed` with the fixed reason `internal_state`, nothing written.
	func testASyncOverAnOldAccountAnswersADefiniteWordOnceAndWithinABound() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let started = Date()
		let ok = sync(phraseB)
		XCTAssertLessThan(Date().timeIntervalSince(started), 5, "the answer comes back within a bound")
		XCTAssertEqual(syncResult(ok), "updated", "a definite result code")
		XCTAssertFalse(isolatedValues().isEmpty, "the old account was sealed, not deleted")
		XCTAssertNotNil(store.readItem(.mnemonic, eoa: account(phraseB).eoa))
		// a second old account that cannot be judged: nothing is written, one answer, a fixed reason word
		useFreshStore()
		seed(phraseA)
		store.mnemonic.failRead.insert(.mnemonic)
		let writes = store.mutationCount
		let begun = Date()
		let answer = sync(phraseC)
		XCTAssertLessThan(Date().timeIntervalSince(begun), 5)
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "write_failed")
		XCTAssertEqual(answer["reason"] as? String, "internal_state")
		XCTAssertEqual(store.mutationCount, writes, "nothing was written, and the SDK did not try again")
		XCTAssertNil(store.readItem(.mnemonic, eoa: account(phraseC).eoa))
		_ = oldEoa
	}

	// SO-24: every failed overwrite answers one of the two fixed words on the wire; the internal labels are not sent.
	func testEveryFailedOverwriteAnswersAFixedWireWord() {
		let all: [BeamioPwaPhraseOverwrite.Result] = [.writeFailed, .sealingFailed, .readbackMismatch, .internalState]
		for result in all {
			let reason = BeamioPwaWalletSync.wireReason(result)
			XCTAssertTrue(["internal_state", "storage_write"].contains(reason ?? ""), "\(result) answers a fixed word")
			for forbidden in ["sealing_failed", "readback_mismatch", "rollback_pending", "unknown_loss", "not_settled", "readback_failed"] {
				XCTAssertNotEqual(reason, forbidden)
			}
		}
		XCTAssertNil(BeamioPwaWalletSync.wireReason(.updated))
	}

	// SO-25: a window (the new key is written, the new mnemonic is not, the marker has no newRecordSha) met at a restart. The partial new record is
	// moved aside (kept, audited); the old record is restored from its sealed copy (the copy is kept); the marker goes; nothing is deleted.
	func testAWindowAtRestartRestoresTheOldRecordAndKeepsTheCopies() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let oldBytes = BeamioPwaWalletSync.normalized(phraseA)
		let staged = stageSealedMnemonic(of: phraseA, tag: "t25", phase: "pending")
		let b = account(phraseB)
		XCTAssertTrue(store.writeItem(.key, eoa: newEoa, value: b.key))
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: oldEoa), oldBytes, "the old record is back under its name")
		XCTAssertEqual(store.rawRead(account: staged.copy), .present(oldBytes), "the sealed copy is kept")
		let partialNew = store.accountName(.key, eoa: newEoa)
		XCTAssertEqual(store.rawRead(account: partialNew), .absent, "the partial new record is not under the fixed name")
		XCTAssertEqual(isolatedValues().count, 2, "the sealed copy and the partial new record, both kept")
		XCTAssertTrue(retainedEntries().isEmpty, "no retained entry: the overwrite did not complete")
		assertNoMarker()
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .valid,
		               "the old account is in place and known")
	}

	// SO-22F (v3.3): a keystore error other than itemNotFound on the wrap alias is not a loss: unknown, nothing written, nothing renamed.
	func testAnOtherKeystoreErrorOnTheAliasIsUnknownAndWritesNothing() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: oldEoa, value: Data("not a recovery phrase".utf8)))
		XCTAssertTrue(store.rawDelete(account: store.accountName(.key, eoa: oldEoa)))
		let originals = snapshot(oldEoa)
		BeamioPwaPhraseOverwrite.wrapAliasProbe = { _ in .otherError }
		let writes = store.mutationCount
		let b = account(phraseB)
		let result = BeamioPwaPhraseOverwrite.run(eoa: newEoa, phrase: BeamioPwaWalletSync.normalized(phraseB), key: b.key, owners: [oldEoa],
		                                          store: store, utc: "2026-11-17T00:00:00Z", tag: "t22f")
		XCTAssertEqual(result, .internalState)
		XCTAssertEqual(store.mutationCount, writes)
		XCTAssertEqual(snapshot(oldEoa), originals)
		XCTAssertTrue(isolatedValues().isEmpty)
		assertNoMarker()
	}

	/// The SO-25 starting state: the old account's mnemonic is sealed (its live name empty), the new key is written, and the marker is pending.
	private func windowState() {
		useFreshStore()
		seed(phraseA)
		_ = stageSealedMnemonic(of: phraseA, tag: "t25", phase: "pending")
		let b = account(phraseB)
		XCTAssertTrue(store.writeItem(.key, eoa: b.eoa, value: b.key))
	}

	// SO-25b (v3.3): a recovery interrupted at any of its mutations finishes on the next start, to the same final state as one uninterrupted run.
	func testARecoveryInterruptedAtAnyMutationFinishesToTheSameState() {
		windowState()
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let base = store.mutationCount
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		let total = store.mutationCount - base
		XCTAssertGreaterThan(total, 2)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: oldEoa), BeamioPwaWalletSync.normalized(phraseA))
		XCTAssertEqual(isolatedValues().count, 2, "the sealed copy and the partial new record are kept")
		assertNoMarker()
		let finalKeys = store.keys
		let finalRaw = store.rawAccounts.filter { !$0.key.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) && $0.key != BeamioPwaPhraseOverwrite.auditAccount }
		for n in 1...total {
			windowState()
			store.failMutationAt = store.mutationCount + n
			_ = BeamioPwaPhraseOverwrite.recoverAtStart(store: store)
			store.failMutationAt = nil
			XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "interruption \(n): the next start finishes")
			XCTAssertEqual(store.readItem(.mnemonic, eoa: oldEoa), BeamioPwaWalletSync.normalized(phraseA), "interruption \(n): the old record is back")
			XCTAssertEqual(isolatedValues().count, 2, "interruption \(n): the copy and the partial new record are kept")
			assertNoMarker()
			XCTAssertEqual(store.keys, finalKeys, "interruption \(n): same key records as one run")
			XCTAssertEqual(store.rawAccounts.filter { !$0.key.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) && $0.key != BeamioPwaPhraseOverwrite.auditAccount }, finalRaw,
			               "interruption \(n): same raw records as one run")
			XCTAssertNil(store.keys[newEoa.lowercased()], "interruption \(n): the new key is not under the fixed name")
		}
	}

	// SO-25c (v3.3.1): the recovery fails because a sealed copy does not match its digest. Rollback pending: every file is kept and nothing moves; one
	// automatic attempt per launch, the code recorded, no loop; the user's retry entry runs the recovery again and succeeds once the copy is intact.
	func testAFailedRecoveryKeepsEverythingAndRetriesOncePerLaunch() {
		windowState()
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let originalCopy = store.rawAccounts.first { $0.key.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) }
		let copyName = originalCopy?.key ?? ""
		let good = originalCopy?.value ?? Data()
		store.rawAccounts[copyName] = Data("corrupt sealed mnemonic".utf8)
		let filesBefore = store.rawAccounts
		let keysBefore = store.keys
		BeamioPwaPhraseOverwrite.resetStartupForTests()
		BeamioPwaPhraseOverwrite.settleOnceAtStart(store: store)
		XCTAssertEqual(BeamioPwaPhraseOverwrite.lastRecoveryErrorCode, "rollback_pending")
		XCTAssertEqual(store.rawAccounts, filesBefore, "a failed recovery moves nothing")
		XCTAssertEqual(store.keys, keysBefore)
		assertNotNoMarker()
		let mutations = store.mutationCount
		BeamioPwaPhraseOverwrite.settleOnceAtStart(store: store)
		XCTAssertEqual(store.mutationCount, mutations, "the same launch makes no second automatic attempt")
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "the attempt is still refused while the copy is corrupt")
		XCTAssertEqual(store.rawAccounts, filesBefore, "still nothing moves")
		// The user's retry entry, after the copy is intact again.
		store.rawAccounts[copyName] = good
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "the user retry completes the recovery")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: oldEoa), BeamioPwaWalletSync.normalized(phraseA))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: newEoa), nil)
		assertNoMarker()
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .valid)
	}

	private func assertNotNoMarker(file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertNotEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "the marker stays", file: file, line: line)
	}

	// Restricted preread return: the validated phrase and the eoa come back only for a native
	// `valid` (PHRASE_ONLY included); unknown and unreadable never carry a phrase; and no phrase reaches the audit, the retained record or the marker.
	func testPrereadReturnsThePhraseOnlyWhenValidAndNeverWhenUnknownOrUnreadable() {
		seed(phraseA)
		let eoa = account(phraseA).eoa
		let valid = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 20, "trustedOrigin": true,
		                                        "seq": NSNumber(value: Int64(2000))], snapshotKnown: true, storageLocked: false)
		let validResult = valid["result"] as? [String: Any]
		XCTAssertEqual(validResult?["code"] as? String, "ok")
		XCTAssertEqual(validResult?["eoa"] as? String, eoa)
		XCTAssertEqual(validResult?["mnemonic"] as? String, phraseA, "a valid native record returns its validated phrase")

		// PHRASE_ONLY: the phrase is readable and the key record is absent: still valid.
		XCTAssertTrue(store.rawDelete(account: store.accountName(.key, eoa: eoa)))
		let phraseOnly = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 21, "trustedOrigin": true,
		                                             "seq": NSNumber(value: Int64(2001))], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((phraseOnly["result"] as? [String: Any])?["mnemonic"] as? String, phraseA, "PHRASE_ONLY is valid, phrase returned")
		store.keys[eoa] = account(phraseA).key

		let unknown = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 22, "trustedOrigin": true,
		                                          "seq": NSNumber(value: Int64(2002))], snapshotKnown: false, storageLocked: false)
		XCTAssertEqual((unknown["result"] as? [String: Any])?["code"] as? String, "read_error")
		XCTAssertNil((unknown["result"] as? [String: Any])?["phrase"], "unknown carries no phrase")

		// A new epoch drops the published reading, so the unreadable store is read now.
		_ = BeamioPwaPreread.advance(pending: false)
		store.mnemonic.failRead.insert(.mnemonic)
		let unreadable = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 23, "trustedOrigin": true,
		                                             "seq": NSNumber(value: Int64(2003))], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((unreadable["result"] as? [String: Any])?["code"] as? String, "read_error")
		XCTAssertNil((unreadable["result"] as? [String: Any])?["phrase"], "unreadable carries no phrase")
		store.mnemonic.failRead = []
	}

	// -59E-mnemonic-is-account-credential (2026-11-17): a clear "no valid phrase" is absent. The enumeration succeeded and only a key record
	// or a wallet record is left (no mnemonic). Nothing is cleaned up.
	func testExplicitlyNoValidPhraseIsAbsentWithoutAPhrase() {
		let keyOnly = account(phraseA)
		XCTAssertTrue(store.writeItem(.key, eoa: keyOnly.eoa, value: keyOnly.key))
		XCTAssertTrue(store.writeItem(.commit, eoa: keyOnly.eoa, value: Data(#"{"v":1}"#.utf8)))
		let raw = store.rawAccounts
		let keys = store.keys
		_ = BeamioPwaPhraseOverwrite.ownerAccounts(keyOnly.eoa, store: store)
		_ = BeamioPwaPhraseOverwrite.recoverAtStart(store: store)
		_ = BeamioPwaPreread.advance(pending: false)
		let answer = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 40, "trustedOrigin": true,
		                                         "seq": NSNumber(value: Int64(4000))], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "confirmed_missing", "a clear no-phrase answer is absent")
		XCTAssertNil((answer["result"] as? [String: Any])?["phrase"], "absent carries no phrase")
		XCTAssertNil((answer["result"] as? [String: Any])?["eoa"])
		XCTAssertEqual(store.keys, keys, "nothing is cleaned up")
		XCTAssertEqual(store.rawAccounts, raw)
	}

	// The same account with only a wallet record (the isolation record) left: still a clear absence, not unknown.
	func testOnlyAWalletRecordLeftIsAbsentWithoutAPhrase() {
		let eoa = account(phraseB).eoa
		store.rawAccounts[BeamioWalletCredentialBlob.account(eoa)] = Data("k-record-only".utf8)
		_ = BeamioPwaPreread.advance(pending: false)
		let answer = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 41, "trustedOrigin": true,
		                                         "seq": NSNumber(value: Int64(4100))], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "confirmed_missing")
		XCTAssertNil((answer["result"] as? [String: Any])?["phrase"])
	}

	// A failed enumeration (the keystore cannot list its items) is unknown, never absent, and carries no phrase.
	func testAFailedEnumerationIsUnknownNotAbsent() {
		seed(phraseA)
		store.mnemonic.enumerationFails = true
		_ = BeamioPwaPreread.advance(pending: false)
		let answer = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 42, "trustedOrigin": true,
		                                         "seq": NSNumber(value: Int64(4200))], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "read_error", "a failed enumeration is unknown")
		XCTAssertNil((answer["result"] as? [String: Any])?["phrase"], "unknown carries no phrase")
		store.mnemonic.enumerationFails = false
	}

	// E7 (the): a mnemonic record that is readable but not a valid phrase is absent, not unknown. The record is kept.
	func testAReadableButInvalidPhraseRecordIsAbsentAndIsKept() {
		let eoa = account(phraseA).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: eoa, value: Data("not a recovery phrase at all".utf8)))
		let raw = store.mnemonic.items
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .absent, "a readable invalid phrase is absent (onboarding)")
		XCTAssertNil(reading.phrase)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data("not a recovery phrase at all".utf8), "the record is kept, not deleted")
		XCTAssertEqual(store.mnemonic.items, raw, "nothing is written or deleted by the reading")
	}

	// E7: a checksum-invalid phrase (twelve words that fail the BIP-39 checksum) is the same case: absent, kept.
	func testAChecksumInvalidPhraseRecordIsAbsentAndIsKept() {
		let eoa = account(phraseA).eoa
		let bad = Data("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon".utf8)
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: eoa, value: bad))
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .absent)
		XCTAssertNil(reading.phrase)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), bad, "the record is kept")
	}

	// E7-5 P-05: only a key record is left, and the enumeration fails: unknown, never absent, nothing changes.
	func testAKeyOnlyWithAFailedEnumerationIsUnknown() {
		let keyOnly = account(phraseA)
		XCTAssertTrue(store.writeItem(.key, eoa: keyOnly.eoa, value: keyOnly.key))
		store.mnemonic.enumerationFails = true
		_ = BeamioPwaPreread.advance(pending: false)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .unknown, "P-05: an enumeration that fails is unknown")
		store.mnemonic.enumerationFails = false
	}

	// E7-7 P-08 and E7-7 note 1: a readable corrupt phrase is not overwritten. A new account is written only after the corrupt record is isolated and
	// sealed (kept); the corrupt bytes are kept under an isolation name, and the audit names them as kept.
	func testACorruptRecordIsSealedAndKeptBeforeANewAccountIsWritten() {
		let corrupt = Data("not a recovery phrase at all".utf8)
		let corruptEoa = account(phraseA).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: corruptEoa, value: corrupt))
		let answer = sync(phraseB)
		XCTAssertEqual(syncResult(answer), "updated", "the new account is written after the corrupt record is sealed")
		XCTAssertTrue(isolatedValues().contains(corrupt), "the corrupt bytes are kept under an isolation name")
		XCTAssertEqual(store.rawRead(account: store.accountName(.mnemonic, eoa: corruptEoa)), .absent, "the live corrupt name is sealed aside")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: account(phraseB).eoa), BeamioPwaWalletSync.normalized(phraseB))
		XCTAssertTrue(auditRows().contains { ($0["reason"] as? String) == "pwa_sync_corrupt_kept" }, "the audit names the kept record")
		assertNoMarker()
	}

	// E7.1: one valid phrase and a corrupt record elsewhere: valid, the valid account is returned, and the corrupt record is kept.
	func testOneValidPhraseWithACorruptRecordIsValidAndTheCorruptIsKept() {
		seed(phraseA)
		let validEoa = account(phraseA).eoa
		let corruptEoa = account(phraseB).eoa
		let corrupt = Data("not a recovery phrase at all".utf8)
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: corruptEoa, value: corrupt))
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .valid)
		XCTAssertEqual(reading.eoa, validEoa, "the one valid account is returned")
		XCTAssertEqual(reading.phrase, phraseA)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: corruptEoa), corrupt, "the corrupt record is kept")
	}

	// E71-06: one valid phrase, a corrupt record, and a read failure elsewhere: unknown (a read failure is not a corrupt record). Nothing is changed.
	func testAReadFailureAlongsideAValidAndACorruptRecordIsUnknown() {
		seed(phraseA)
		let corruptEoa = account(phraseB).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: corruptEoa, value: Data("not a recovery phrase".utf8)))
		store.mnemonic.failRead.insert(.mnemonic)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .unknown, "E71-06: a read failure anywhere is unknown")
		store.mnemonic.failRead = []
	}

	// E71-07: no valid phrase, only a corrupt record, and the pointer names that corrupt record: absent, the record is kept.
	func testOnlyACorruptRecordPointedAtByThePointerIsAbsentAndKept() {
		let corruptEoa = account(phraseB).eoa
		let corrupt = Data("not a recovery phrase".utf8)
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: corruptEoa, value: corrupt))
		BeamioNativeAccountPointer.set(corruptEoa)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .absent, "E71-07: no valid phrase is absent")
		XCTAssertNil(reading.phrase)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: corruptEoa), corrupt, "the corrupt record is kept")
	}

	// E7.1: a pointer that names another account than the one valid phrase is unknown.
	func testAPointerNamingAnotherAccountIsUnknown() {
		seed(phraseA)
		let corruptEoa = account(phraseB).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: corruptEoa, value: Data("not a recovery phrase".utf8)))
		BeamioNativeAccountPointer.set(corruptEoa)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .unknown, "the pointer names an account that has no valid phrase")
	}

	// E7.1: a pointer that names the one valid account is valid.
	func testAPointerNamingTheValidAccountIsValid() {
		seed(phraseA)
		let validEoa = account(phraseA).eoa
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: account(phraseB).eoa, value: Data("not a recovery phrase".utf8)))
		BeamioNativeAccountPointer.set(validEoa)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .valid)
		XCTAssertEqual(reading.eoa, validEoa)
	}

	// E7.1: two valid phrases keep the multi-account rule: unknown.
	func testTwoValidPhrasesAreUnknownUnderTheMultiAccountRule() {
		seed(phraseA)
		seed(phraseB)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .unknown)
	}

	// Sealed old phrase: after the overwrite the sealed copy of the old mnemonic reads back byte for byte (its digest), and the phrase in it derives the
	// old address A, which is the keyID of the old account. Nothing is deleted.
	func testTheSealedOldPhraseReadsBackAndDerivesTheOldAddress() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let liveName = store.accountName(.mnemonic, eoa: oldEoa)
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		XCTAssertEqual(store.rawRead(account: liveName), .absent, "the live old name is sealed aside")
		let sealed = isolatedValues().filter { $0 == BeamioPwaWalletSync.normalized(phraseA) }
		XCTAssertEqual(sealed.count, 1, "the sealed copy holds the old phrase bytes")
		let text = String(decoding: sealed[0], as: UTF8.self)
		let derived = BeamioPwaWalletSync.derivedAccount(phrase: text)
		XCTAssertEqual(derived?.eoa, oldEoa, "the sealed phrase derives the old address A, the keyID of the old account")
		XCTAssertNotNil(retainedEntries().first?["oldEoa"])
		XCTAssertEqual(retainedEntries().first?["oldEoa"] as? String, oldEoa)
	}

	// Window, two copies unreadable (2026-11-17 counter-example): the start holds a valid phrase A, the sealed mnemonic copy and the sealed key copy
	// cannot be opened to A, and the new key is written before the new mnemonic (interrupted). Restart: nothing rolls forward, every file is kept,
	// the marker stays, no roll-forward audit is written, the state is rollback_pending.
	func testAWindowWithBothSealedCopiesUnopenableKeepsEverythingAndRollsNothingForward() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let bogus = Data("sealed bytes that do not open".utf8)
		let mnemonicLive = store.accountName(.mnemonic, eoa: oldEoa)
		let keyLive = store.accountName(.key, eoa: oldEoa)
		let mnemonicCopy = BeamioPwaPhraseOverwrite.isolationPrefix + "t-two." + mnemonicLive
		let keyCopy = BeamioPwaPhraseOverwrite.isolationPrefix + "t-two." + keyLive
		XCTAssertTrue(store.rawWrite(account: mnemonicCopy, bytes: bogus))
		XCTAssertTrue(store.rawWrite(account: keyCopy, bytes: bogus))
		XCTAssertTrue(store.rawDelete(account: mnemonicLive))
		XCTAssertTrue(store.rawDelete(account: keyLive))
		let marker: [String: Any] = [
			"v": 1, "phase": "pending", "eoa": newEoa, "tag": "t-two", "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [oldEoa], "moves": [
				["from": mnemonicLive, "to": mnemonicCopy, "digest": BeamioPwaPhraseOverwrite.digest(BeamioPwaWalletSync.normalized(phraseA))],
				["from": keyLive, "to": keyCopy, "digest": BeamioPwaPhraseOverwrite.digest(bogus)],
			],
		]
		XCTAssertTrue(store.rawWrite(account: BeamioPwaPhraseOverwrite.markerAccount,
		                             bytes: try! JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])))
		XCTAssertTrue(store.writeItem(.key, eoa: newEoa, value: account(phraseB).key), "the new key is written; the new mnemonic is not")
		let raw = store.rawAccounts
		let keys = store.keys
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "rollback_pending, not settled")
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "the next start cannot settle it either")
		XCTAssertEqual(store.rawAccounts, raw, "every file is kept; nothing rolls forward or back")
		XCTAssertEqual(store.keys, keys)
		XCTAssertNotEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "the window is not closed")
		XCTAssertTrue(auditRows().isEmpty, "no roll-forward audit")
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .absent, "2026-11-17: the copies hold no readable phrase (E7), so onboarding; nothing is deleted")
	}

	// E7 unknown: a storage lock makes the reading unknown, whatever the records say (nothing is read as absent).
	func testAStorageLockIsUnknownNotAbsent() {
		let keyOnly = account(phraseA)
		XCTAssertTrue(store.writeItem(.key, eoa: keyOnly.eoa, value: keyOnly.key))
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: true, store: store).state, .unknown)
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: false, storageLocked: false, store: store).state, .unknown)
	}

	// B' (2026-11-17): the 0.1.8 signature with the key as 0x-hex text gives the same output as the byte API for the same 32 bytes (same EIP-191 digest,
	// same RFC 6979 signature), and an invalid key text gives nil. Two calls are the same (deterministic).
	func testTheHexKeySignatureEqualsTheByteSignature() {
		let hexKey = "0x" + String(repeating: "11", count: 32)
		let bytes = BeamioNativeEthSigner.keyBytes(fromHex: hexKey)
		XCTAssertNotNil(bytes)
		let viaHex = BeamioNativeEthSigner.signEip191(privateKeyHex: hexKey, message: "hello")
		let viaBytes = BeamioNativeEthSigner.signEip191(privateKey: bytes ?? [], message: "hello")
		XCTAssertNotNil(viaHex)
		XCTAssertEqual(viaHex, viaBytes, "the same key gives the same signature")
		XCTAssertEqual(viaHex, BeamioNativeEthSigner.signEip191(privateKeyHex: hexKey, message: "hello"), "deterministic")
		XCTAssertEqual(viaHex?.count, 2 + 130, "0x + r + s + v, 65 bytes")
		XCTAssertNil(BeamioNativeEthSigner.signEip191(privateKeyHex: "0x" + String(repeating: "zz", count: 32), message: "hello"), "a non-hex key is refused")
		XCTAssertNil(BeamioNativeEthSigner.signEip191(privateKeyHex: "0x1234", message: "hello"), "a short key is refused")
		XCTAssertNil(BeamioNativeEthSigner.keyBytes(fromHex: "0x" + String(repeating: "00", count: 32)), "the zero key is not a valid key")
	}

	// Log and record hygiene: after an overwrite, the audit, the retained record and the marker hold names, times and digests, never the phrase.
	func testNoPhraseReachesTheAuditRetainedRecordOrMarker() {
		seed(phraseA)
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		let words = ["abandon", "legal", "winner", "thank", "wave", "sausage"]
		let auditText = rawText(account: BeamioPwaPhraseOverwrite.auditAccount)
		let retainedText = rawText(account: BeamioPwaPhraseOverwrite.retainedAccount)
		for word in words {
			XCTAssertFalse(auditText.contains(word), "no phrase word in the audit")
			XCTAssertFalse(retainedText.contains(word), "no phrase word in the retained record")
		}
	}

	// Errata E1: a preread request that carries `phrase` (or any credential field) is key_over_bridge_refused, after the origin check.
	func testAPrereadWithACredentialFieldIsRefusedWithoutReading() {
		seed(phraseA)
		let answer = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 7, "trustedOrigin": true,
		                                         "seq": NSNumber(value: Int64(900)), "phrase": phraseA],
		                                        snapshotKnown: true, storageLocked: false)
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "key_over_bridge_refused")
		XCTAssertNil(answer["result"], "no state and no phrase is returned")
		let untrusted = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 8, "seq": NSNumber(value: Int64(901))],
		                                           snapshotKnown: true, storageLocked: false)
		XCTAssertEqual(untrusted["error"] as? String, "untrusted_source", "the origin is checked first")
	}

	// Errata E2-1: a window whose sealed copy does not open to its old EOA is neither restored nor rolled forward; every file stays.
	func testAWindowWhoseSealedCopyDoesNotOpenToTheOldAccountChangesNothing() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let live = store.accountName(.mnemonic, eoa: oldEoa)
		let bogus = Data("not a recovery phrase".utf8)
		let copy = BeamioPwaPhraseOverwrite.isolationPrefix + "t25e." + live
		XCTAssertTrue(store.rawWrite(account: copy, bytes: bogus))
		XCTAssertTrue(store.rawDelete(account: live))
		let marker: [String: Any] = [
			"v": 1, "phase": "pending", "eoa": newEoa, "tag": "t25e", "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [oldEoa], "moves": [["from": live, "to": copy, "digest": BeamioPwaPhraseOverwrite.digest(bogus)]],
		]
		XCTAssertTrue(store.rawWrite(account: BeamioPwaPhraseOverwrite.markerAccount,
		                             bytes: try! JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])))
		let b = account(phraseB)
		XCTAssertTrue(store.writeItem(.key, eoa: newEoa, value: b.key))
		let raw = store.rawAccounts
		let keys = store.keys
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "rollback pending, not settled")
		XCTAssertEqual(store.rawAccounts, raw, "nothing is restored, rolled forward or deleted")
		XCTAssertEqual(store.keys, keys)
		XCTAssertEqual(markerPhase(), "pending", "the marker stays")
	}

	// Errata E3: seq 0 is a legal non-negative integer. It is current until a higher seq is accepted; after one, a lower seq is stale and an
	// equal seq is current.
	func testSeqZeroIsLegalAndStaleOnlyBelowTheAcceptedMaximum() {
		BeamioPwaWalletSync.restartForTests()
		XCTAssertEqual(BeamioPwaSeq.parse(NSNumber(value: Int64(0))), 0)
		XCTAssertTrue(BeamioPwaWalletSync.isCurrent(0), "no seq accepted yet: zero is current")
		BeamioPwaWalletSync.recordAccepted(1)
		XCTAssertFalse(BeamioPwaWalletSync.isCurrent(0), "zero after one is stale")
		XCTAssertTrue(BeamioPwaWalletSync.isCurrent(1), "an equal seq is current")
		XCTAssertNil(BeamioPwaSeq.parse(NSNumber(value: -1)), "a negative seq is bad_request")
		BeamioPwaWalletSync.restartForTests()
	}

	// E4: a leftover overwrite marker (rollback_pending) or discard intent (DISCARD_PENDING) is a settlement lock; a clean store is not.
	func testASettlementLeftoverIsALockAndACleanStoreIsNot() {
		XCTAssertFalse(BeamioPwaPhraseOverwrite.settlementLockPending(store: store))
		XCTAssertTrue(store.rawWrite(account: BeamioPwaPhraseOverwrite.markerAccount, bytes: Data("{}".utf8)))
		XCTAssertTrue(BeamioPwaPhraseOverwrite.settlementLockPending(store: store))
		XCTAssertTrue(store.rawDelete(account: BeamioPwaPhraseOverwrite.markerAccount))
		XCTAssertTrue(store.rawWrite(account: BeamioNarrowDiscardStore.intentAccount, bytes: Data("{}".utf8)))
		XCTAssertTrue(BeamioPwaPhraseOverwrite.settlementLockPending(store: store))
		XCTAssertTrue(store.rawDelete(account: BeamioNarrowDiscardStore.intentAccount))
		XCTAssertFalse(BeamioPwaPhraseOverwrite.settlementLockPending(store: store))
	}

	private func rawText(account: String) -> String {
		guard case .present(let bytes) = store.rawRead(account: account) else { return "" }
		return String(decoding: bytes, as: UTF8.self)
	}

	/// Audit rows of the isolation renames (the window rows), in order.
	private func auditRows() -> [[String: Any]] {
		guard case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount) else { return [] }
		return (try? JSONSerialization.jsonObject(with: bytes) as? [[String: Any]]) ?? []
	}

	// Window counter-example (the project lead, 2026-11-17): the sealed copy cannot be opened to A, or opens to B. The new key is written, the new mnemonic is not
	// (interrupted), then a restart, a second restart, and the user's retry (a pwaWalletSync write). Nothing rolls forward, every file is kept, no
	// roll-forward audit is written, the marker stays (the window is not closed), and the state is rollback_pending.
	func testAWindowWhoseSealedCopyDoesNotOpenToAOrOpensToBRollsNothingForward() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let phraseBBytes = BeamioPwaWalletSync.normalized(phraseB)
		let live = store.accountName(.mnemonic, eoa: oldEoa)
		let copy = BeamioPwaPhraseOverwrite.isolationPrefix + "t-counter." + live
		// The sealed copy holds B's phrase, and the marker records that same digest: it opens to B, not to A.
		XCTAssertTrue(store.rawWrite(account: copy, bytes: phraseBBytes))
		XCTAssertTrue(store.rawDelete(account: live))
		let marker: [String: Any] = [
			"v": 1, "phase": "pending", "eoa": newEoa, "tag": "t-counter", "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [oldEoa], "moves": [["from": live, "to": copy, "digest": BeamioPwaPhraseOverwrite.digest(phraseBBytes)]],
		]
		XCTAssertTrue(store.rawWrite(account: BeamioPwaPhraseOverwrite.markerAccount,
		                             bytes: try! JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])))
		let b = account(phraseB)
		XCTAssertTrue(store.writeItem(.key, eoa: newEoa, value: b.key), "the new key is written; the new mnemonic is not (interrupted)")
		let raw = store.rawAccounts
		let keys = store.keys
		// Restart 1 and restart 2 (automatic, one attempt each; the attempt is refused and recorded), then the user's retry.
		BeamioPwaPhraseOverwrite.resetStartupForTests()
		BeamioPwaPhraseOverwrite.settleOnceAtStart(store: store)
		XCTAssertEqual(BeamioPwaPhraseOverwrite.lastRecoveryErrorCode, "rollback_pending")
		BeamioPwaPhraseOverwrite.settleOnceAtStart(store: store)
		let retry = BeamioPwaWalletSync.answer(["type": "pwaWalletSync", "reqId": 31, "trustedOrigin": true,
		                                        "seq": NSNumber(value: Int64(3100)), "phrase": phraseB],
		                                       snapshotKnown: true, storageLocked: false)
		XCTAssertEqual(retry["error"] as? String, "write_failed", "the retry is refused, not completed")
		XCTAssertEqual(retry["reason"] as? String, "internal_state")
		XCTAssertEqual(store.rawAccounts, raw, "every file is kept, nothing is renamed, restored or deleted")
		XCTAssertEqual(store.keys, keys)
		XCTAssertNotEqual(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount), .absent, "the window is not closed")
		XCTAssertTrue(auditRows().isEmpty, "no roll-forward or restore audit is written")
		XCTAssertEqual(store.rawRead(account: live), .absent, "the old name is not written with B's phrase")
		XCTAssertNil(store.readItem(.mnemonic, eoa: newEoa), "the new mnemonic is not rolled forward")
	}

	// E2 addendum SO-25d: a window whose old live name holds other content. The content is renamed to an isolation name first (audited, kept), then the
	// sealed record is written back and read back; the final content is the old bytes; nothing is deleted.
	func testAWindowOverGarbageIsolatesTheGarbageFirstAndRestoresTheOldBytes() {
		seed(phraseA)
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let staged = stageSealedMnemonic(of: phraseA, tag: "t25d", phase: "pending")
		let garbage = Data("garbage that is neither the old nor the new record".utf8)
		XCTAssertTrue(store.rawWrite(account: staged.live, bytes: garbage))
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: oldEoa), BeamioPwaWalletSync.normalized(phraseA), "the final content is the old bytes")
		XCTAssertEqual(store.rawRead(account: staged.copy), .present(BeamioPwaWalletSync.normalized(phraseA)), "the sealed copy is kept")
		XCTAssertTrue(isolatedValues().contains(garbage), "the garbage is kept under an isolation name")
		XCTAssertTrue(auditRows().contains { ($0["reason"] as? String) == "window_isolated" && ($0["sha"] as? String) == BeamioPwaPhraseOverwrite.digest(garbage) },
		              "the rename of the garbage is audited, with its digest")
		XCTAssertTrue(retainedEntries().isEmpty)
		assertNoMarker()
		XCTAssertNil(store.readItem(.mnemonic, eoa: newEoa))
	}

	// E2 addendum SO-25e: the rename of a partial cannot be done. Nothing is overwritten, nothing is audited, the copies and the partial stay, and the
	// state is rollback_pending (the marker stays).
	func testAFailedPartialRenameOverwritesNothingAndAuditsNothing() {
		windowState()
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let base = store.mutationCount
		// Mutations of the recovery: the marker (1), then the copy of the partial new key (2). The second fails.
		store.failMutationAt = base + 2
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		store.failMutationAt = nil
		XCTAssertNotNil(store.keys[newEoa.lowercased()], "the partial new key stays under its name")
		XCTAssertEqual(store.rawRead(account: store.accountName(.mnemonic, eoa: oldEoa)), .absent, "the old name is not overwritten")
		XCTAssertTrue(auditRows().isEmpty, "a failed rename is not audited")
		XCTAssertEqual(isolatedValues().count, 1, "only the sealed copy is there; the failed copy is undone")
		assertNotNoMarker()
	}

	// E2 addendum SO-25f (decided by the project lead): the rename succeeds and its audit row fails. Nothing is rolled back and nothing is deleted; the next
	// start writes the missing audit row (matched by name, idempotent) and the recovery finishes as in SO-25d.
	func testAMissingAuditRowAfterARenameIsBackfilledOnTheNextStart() {
		windowState()
		let oldEoa = account(phraseA).eoa
		let newEoa = account(phraseB).eoa
		let partialKey = store.accountName(.key, eoa: newEoa)
		let base = store.mutationCount
		// Mutations: the marker (1), the copy (2), the removal of the live name (3), the audit row (4). The audit row fails.
		store.failMutationAt = base + 4
		XCTAssertFalse(BeamioPwaPhraseOverwrite.recoverAtStart(store: store))
		store.failMutationAt = nil
		XCTAssertNil(store.keys[newEoa.lowercased()], "the rename stays; it is not rolled back")
		XCTAssertEqual(isolatedValues().count, 2, "the partial's isolation copy and the sealed copy are both kept")
		XCTAssertFalse(auditRows().contains { ($0["from"] as? String) == partialKey }, "the audit row is missing after the first start")
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "the next start backfills and finishes")
		XCTAssertTrue(auditRows().contains { ($0["from"] as? String) == partialKey && ($0["reason"] as? String) == "window_isolated" },
		              "the backfilled row names the renamed record")
		XCTAssertEqual(auditRows().filter { ($0["from"] as? String) == partialKey }.count, 1, "the backfill is idempotent: one row")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: oldEoa), BeamioPwaWalletSync.normalized(phraseA))
		XCTAssertEqual(isolatedValues().count, 2)
		assertNoMarker()
	}

	// SO-26 (E5.1-2), as the product has it since a2767b6 (2026-11-19, BeamioPwaWalletSync.swift:498-512): a PHRASE_ONLY residue (the pointer account has a readable phrase and no key record)
	// is repaired in place when the page syncs the SAME account's phrase (the key is derived back, nothing else changes), and another account's phrase answers write_failed / internal_state
	// with nothing sealed, renamed, marked or audited; the residue reads back unchanged.
	func testPhraseOnlyResidueIsRepairedForTheSameAccountAndRefusedForAnother() {
		seed(phraseA)
		let residue = account(phraseA).eoa
		XCTAssertTrue(store.rawDelete(account: store.accountName(.key, eoa: residue)))
		BeamioNativeAccountPointer.set(residue)
		XCTAssertEqual(BeamioPwaWalletSync.phraseOnlyResidueEOA(store: store), residue)
		// the same account: the residue is repaired in place
		let same = sync(phraseA)
		XCTAssertEqual(same["ok"] as? Bool, true, "the same account's phrase repairs its own residue")
		XCTAssertNotNil(store.keys[residue], "the key is derived back")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: residue), BeamioPwaWalletSync.normalized(phraseA), "the phrase is unchanged")
		XCTAssertNil(BeamioPwaWalletSync.phraseOnlyResidueEOA(store: store), "no residue is left")
		// another account with a fresh residue: refused, nothing changes
		XCTAssertTrue(store.rawDelete(account: store.accountName(.key, eoa: residue)))
		let raw = store.rawAccounts
		let keys = store.keys
		let mutations = store.mutationCount
		let other = sync(phraseB)
		XCTAssertEqual(other["ok"] as? Bool, false, "another account's phrase is not accepted over a residue")
		XCTAssertEqual(other["error"] as? String, "write_failed")
		XCTAssertEqual(other["reason"] as? String, "internal_state")
		XCTAssertEqual(store.mutationCount, mutations, "nothing is written, renamed or deleted")
		XCTAssertEqual(store.rawAccounts, raw)
		XCTAssertEqual(store.keys, keys)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: residue), BeamioPwaWalletSync.normalized(phraseA), "the residue phrase is unchanged")
		assertNoMarker()
		XCTAssertTrue(retainedEntries().isEmpty)
	}

	// IOS-SHELL-BRIDGE-01: the public engine entry returns one bare ack; the shell wraps it, the SDK never does.
	func testTheEngineEntryReturnsABareAck() {
		seed(phraseA)
		let answer = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 11, seq: 1000, eoa: account(phraseB).eoa, phrase: phraseB)
		XCTAssertEqual(answer["type"] as? String, "ack")
		XCTAssertEqual(answer["reqId"] as? Int, 11)
		XCTAssertNil(answer["chatModuleEvent"], "no wrapper")
		XCTAssertEqual(syncResult(answer), "updated")
		let again = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 12, seq: 1001, eoa: account(phraseB).eoa, phrase: phraseB)
		XCTAssertEqual(syncResult(again), "idempotent", "the same account with the same phrase answers idempotent")
		let preread = BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: 13, seq: 1002)
		XCTAssertEqual(preread["type"] as? String, "ack")
		XCTAssertEqual((preread["result"] as? [String: Any])?["code"] as? String, "ok")
	}

	// A second overwrite (B to C) seals only the current account's records; the copies of the first overwrite stay.
	func testASecondOverwriteKeepsTheEarlierCopies() {
		seed(phraseA)
		let oldA = account(phraseA).eoa
		let bEoa = account(phraseB).eoa
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		let copiesOfA = isolatedValues()
		XCTAssertEqual(syncResult(sync(phraseC)), "updated")
		// A has four copies (key, mnemonic, commit, K); B has three (no K record was written for B).
		XCTAssertEqual(isolatedValues().count, 7, "the copies of A and of B are both kept")
		XCTAssertTrue(copiesOfA.allSatisfy { isolatedValues().contains($0) }, "A's copies are untouched by the second overwrite")
		let entries = retainedEntries()
		XCTAssertEqual(entries.count, 2)
		XCTAssertEqual(entries.last?["oldEoa"] as? String, bEoa)
		XCTAssertEqual(entries.first?["oldEoa"] as? String, oldA)
	}
}
