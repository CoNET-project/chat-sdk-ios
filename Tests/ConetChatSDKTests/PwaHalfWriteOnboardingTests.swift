import XCTest
@testable import ConetChatSDK

/// The preread of a half-written overwrite (-59E-halfwrite-ignorable-onboarding, 2026-11-17). A half-written window, an old or present intent
/// marker and an audit trail never block the reading. Every place that may carry a phrase is read: the live mnemonic items and the copies that the
/// registers name. A valid phrase anywhere is `valid`; no valid phrase, with every place read, is `absent` (onboarding); a read failure is `unknown`.
/// Nothing is written, renamed or deleted by the reading. Accounts are synthetic (A, B, C); the phrases are BIP-39 test phrases.
final class PwaHalfWriteOnboardingTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private let phraseC = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedShellReader: ((String) -> BeamioShellRecord.ShellRecordRead)?
	/// The shell-side encrypted copies of this test, by account (E9.3.1 seam).
	private var shellRecords: [String: BeamioShellRecord.ShellRecordRead] = [:]
	private var savedDeterministic: ((String) -> Bool)?

	override func setUp() {
		super.setUp()
		// This class tests the withdrawn overwrite and sealing format of the phrase write (never published). The production phrase write goes into the set storage
		// (finalized section 1); the test seam turns the old write on here only.
		BeamioPwaWalletSync.legacyPhraseWriteForTests = true
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		savedShellReader = BeamioPwaWalletSync.shellCopyReader
		shellRecords = [:]
		BeamioPwaWalletSync.shellCopyReader = { [unowned self] account in self.shellRecords[account.lowercased()] ?? .absent }
		savedDeterministic = BeamioPwaWalletSync.shellCopyDeterministic
		BeamioPwaWalletSync.shellCopyDeterministic = { _ in true }
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioPwaWalletSync.legacyPhraseWriteForTests = false
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioPwaWalletSync.shellCopyReader = savedShellReader ?? { BeamioShellRecord.EncryptedShellRecordStore.production.read(account: $0) }
		BeamioPwaWalletSync.shellCopyDeterministic = savedDeterministic ?? { BeamioShellRecord.EncryptedShellRecordStore.production.readFailureIsDeterministic(account: $0) }
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func owner(_ phrase: String) -> String {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { preconditionFailure("the test phrase derives an account") }
		return derived.eoa
	}

	private var eoaA: String { owner(phraseA) }
	private var eoaB: String { owner(phraseB) }

	/// A key record only (a private key is not an account, 第 31、32 项).
	private func seedKeyOnly(_ phrase: String) {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { return }
		XCTAssertTrue(store.writeItem(.key, eoa: derived.eoa, value: derived.key))
	}

	private func liveMnemonic(_ phrase: String) {
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: owner(phrase), value: BeamioPwaWalletSync.normalized(phrase)))
	}

	/// An overwrite marker of one owner: the mnemonic record is moved to its isolation name in `moves`.
	private func marker(phase: String, owner: String, moves: [(from: String, to: String)]) -> Data {
		let object: [String: Any] = [
			"v": 1, "phase": phase, "eoa": owner, "tag": "t1", "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [owner], "partials": [],
			"moves": moves.map { ["from": $0.from, "to": $0.to, "digest": "0"] },
		]
		return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
	}

	private func isolationName(_ owner: String) -> String {
		BeamioPwaPhraseOverwrite.isolationPrefix + "t1." + store.accountName(.mnemonic, eoa: owner)
	}

	private func reading() -> BeamioPwaWalletSync.Reading {
		BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
	}

	// MARK: - No phrase anywhere: onboarding (absent)

	func testHalfWrittenWindowWithNoPhraseReadsAbsent() {
		// The mnemonic of A was moved aside and the new record was not written: a half-written window with only the key record left.
		seedKeyOnly(phraseA)
		let moveFrom = store.accountName(.mnemonic, eoa: eoaA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(moveFrom, isolationName(eoaA))])
		XCTAssertEqual(reading().state, .absent, "a half-written window with no phrase is onboarding, not a block")
		// Nothing was renamed, written or deleted by the reading.
		XCTAssertNotNil(store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount])
		XCTAssertEqual(store.rawRead(account: moveFrom), .absent)
	}

	func testOldCommittedMarkerWithNoPhraseReadsAbsent() {
		seedKeyOnly(phraseA)
		let moveFrom = store.accountName(.mnemonic, eoa: eoaA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "committed", owner: eoaA,
		                                                                  moves: [(moveFrom, isolationName(eoaA))])
		store.rawAccounts[isolationName(eoaA)] = Data("not a phrase".utf8)
		XCTAssertEqual(reading().state, .absent, "an old marker and a copy with no valid phrase: onboarding")
		XCTAssertNotNil(store.rawAccounts[isolationName(eoaA)], "the copy is kept")
	}

	func testCopyOfAnotherOwnerPhraseIsNotAnAccountAndReadsAbsent() {
		// A copy filed under C's name holds A's phrase: the owner check fails, so it is not an account.
		let eoaC = "0x00000000000000000000000000000000000000c3"
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaC,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaC), isolationName(eoaC))])
		store.rawAccounts[isolationName(eoaC)] = BeamioPwaWalletSync.normalized(phraseA)
		XCTAssertEqual(reading().state, .absent)
	}

	// MARK: - A valid phrase anywhere: valid

	func testHalfWrittenWindowWithLivePhraseReadsValidNotUnknown() {
		liveMnemonic(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		let r = reading()
		XCTAssertEqual(r.state, .valid, "a present marker no longer blocks the reading")
		XCTAssertEqual(r.eoa, eoaA)
		XCTAssertEqual(r.phrase, phraseA)
	}

	func testSealedCopyWithValidPhraseReadsValidThroughTheMarker() {
		// The live record is gone (moved aside); its sealed copy still holds the valid phrase: the account is recoverable, so the reading is valid.
		seedKeyOnly(phraseB)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.eoa, eoaA)
		XCTAssertEqual(r.phrase, phraseA)
	}

	func testSealedCopyNamedOnlyByTheAuditReadsValid() {
		// No marker (it was settled and removed); the audit row still names the copy.
		let audit: [[String: String]] = [["from": store.accountName(.mnemonic, eoa: eoaA), "to": isolationName(eoaA), "utc": "2026-11-17T00:00:00Z"]]
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = (try? JSONSerialization.data(withJSONObject: audit)) ?? Data()
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.phrase, phraseA)
	}

	func testSameAccountInLiveAndCopyReadsValidWithOnePhrase() {
		liveMnemonic(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "committed", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.eoa, eoaA)
		XCTAssertEqual(r.phrase, phraseA)
	}

	func testLivePhraseIsTheAccountOverACopyOfAnotherAccount() {
		// The live mnemonic is the account; the old account's copy in the window does not make it unknown (a copy counts only when no live one is valid).
		liveMnemonic(phraseB)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		XCTAssertEqual(reading().state, .valid)
	}

	// MARK: - Read failures: unknown

	func testUnparseableMarkerIsUnknown() {
		// The marker cannot be read as a marker: the copies it names are not known, so nothing can be said.
		seedKeyOnly(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = Data("not a marker".utf8)
		XCTAssertEqual(reading().state, .unknown)
	}

	func testUnparseableAuditIsUnknown() {
		seedKeyOnly(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = Data("not an audit".utf8)
		XCTAssertEqual(reading().state, .unknown)
	}

	func testFailedMnemonicListingIsUnknownWhateverTheMarkerSays() {
		store.mnemonic.enumerationFails = true
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		XCTAssertEqual(reading().state, .unknown)
	}

	func testLockedOrUnknownSnapshotIsUnknownWithoutReading() {
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = Data("not a marker".utf8)
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: false, storageLocked: false, store: store).state, .unknown)
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: true, store: store).state, .unknown)
	}

	// MARK: - Nothing is changed by the reading

	func testReadingLeavesEveryRegisterAndCopyAsItWas() {
		seedKeyOnly(phraseA)
		let markerBytes = marker(phase: "prepared", owner: eoaA,
		                         moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = markerBytes
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		let before = store.rawAccounts
		_ = reading()
		_ = BeamioPwaWalletSync.preread(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(store.rawAccounts, before, "no register, copy or key record is renamed, written or deleted by a reading")
	}

	// MARK: - E9.2 (E92-06): several valid copies of different accounts, no valid current record

	/// An audit row that seals one copy (the `from` is the live mnemonic name, the `to` the isolation name) at `utc`.
	private func auditRow(owner: String, utc: String?) -> [String: String] {
		var row: [String: String] = ["from": store.accountName(.mnemonic, eoa: owner), "to": isolationName(owner), "reason": "window_isolated"]
		if let utc { row["utc"] = utc }
		return row
	}

	private func seedAudit(_ rows: [[String: String]]) {
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = (try? JSONSerialization.data(withJSONObject: rows)) ?? Data()
	}

	func testTwoCopiesOfDifferentAccountsTakeTheLatestSealingByAuditTime() {
		let eoaC = owner(phraseC)
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		store.rawAccounts[isolationName(eoaC)] = BeamioPwaWalletSync.normalized(phraseC)
		seedAudit([auditRow(owner: eoaA, utc: "2026-11-17T01:00:00Z"), auditRow(owner: eoaC, utc: "2026-11-17T02:00:00Z")])
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.eoa, eoaC, "the copy sealed most recently by the audit timestamp")
		XCTAssertEqual(r.phrase, phraseC)
	}

	func testTheLatestSealingWinsWhicheverCopyIsOlder() {
		let eoaC = owner(phraseC)
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		store.rawAccounts[isolationName(eoaC)] = BeamioPwaWalletSync.normalized(phraseC)
		seedAudit([auditRow(owner: eoaC, utc: "2026-11-17T01:00:00Z"), auditRow(owner: eoaA, utc: "2026-11-17T02:00:00Z")])
		XCTAssertEqual(reading().eoa, eoaA)
	}

	func testEqualSealingTimestampsAreUnknown() {
		let eoaC = owner(phraseC)
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		store.rawAccounts[isolationName(eoaC)] = BeamioPwaWalletSync.normalized(phraseC)
		seedAudit([auditRow(owner: eoaA, utc: "2026-11-17T01:00:00Z"), auditRow(owner: eoaC, utc: "2026-11-17T01:00:00Z")])
		XCTAssertEqual(reading().state, .unknown, "equal timestamps: nothing is chosen silently")
	}

	func testAMissingSealingTimestampIsUnknown() {
		let eoaC = owner(phraseC)
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		store.rawAccounts[isolationName(eoaC)] = BeamioPwaWalletSync.normalized(phraseC)
		seedAudit([auditRow(owner: eoaA, utc: "2026-11-17T01:00:00Z"), auditRow(owner: eoaC, utc: nil)])
		XCTAssertEqual(reading().state, .unknown)
	}

	func testAValidCurrentRecordWinsOverTwoCopiesAndNoCopyIsChosen() {
		let eoaC = owner(phraseC)
		liveMnemonic(phraseB)
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		store.rawAccounts[isolationName(eoaC)] = BeamioPwaWalletSync.normalized(phraseC)
		seedAudit([auditRow(owner: eoaA, utc: "2026-11-17T01:00:00Z"), auditRow(owner: eoaC, utc: "2026-11-17T01:00:00Z")])
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.eoa, owner(phraseB), "E9.2-1: the current record decides; the copies are not consulted")
	}

	func testAValidCurrentRecordDoesNotReadTheCopies() {
		// E9.2-2: with a valid current record the copies are not read, so a copy that would make the reading unknown changes nothing.
		liveMnemonic(phraseB)
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = Data("not an audit".utf8)
		XCTAssertEqual(reading().state, .valid, "an unreadable audit only matters when the current record is not valid")
	}

	// MARK: - E9.3.1: the shell-side encrypted copy is at the position of the current record

	private func shellRecord(_ phrase: String) -> BeamioShellRecord.ShellRecordRead {
		.record(["rev": 1, "schemaVersion": 2, "profiles": [], "mnemonicPhrase": phrase])
	}

	/// E93-01: the shell copy holds a valid phrase: recovered from the second position.
	func testE9301ShellCopyWithValidPhraseIsRecovered() {
		seedKeyOnly(phraseA)
		shellRecords[eoaA.lowercased()] = shellRecord(phraseA)
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.eoa, eoaA)
		XCTAssertEqual(r.phrase, phraseA)
	}

	/// E93-02: the shell copy cannot be read and no unfinished write names it: unknown, no jump to a sealed copy.
	func testE9302UnreadableShellCopyIsUnknownAndDoesNotJumpToASealedCopy() {
		seedKeyOnly(phraseA)
		shellRecords[eoaA.lowercased()] = .unreadable
		store.rawAccounts[isolationName(eoaC())] = BeamioPwaWalletSync.normalized(phraseC)
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = try! JSONSerialization.data(withJSONObject: [auditRow(owner: eoaC(), utc: "2026-11-17T01:00:00Z")])
		XCTAssertEqual(reading().state, .unknown)
	}

	/// E93-03: the shell copy is unreadable and the marker (pending) names it as this write's unfinished record: ignored; with nothing else, onboarding.
	func testE9303PendingUnreadableShellCopyIsIgnored() {
		seedKeyOnly(phraseA)
		shellRecords[eoaA.lowercased()] = .unreadable
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		XCTAssertEqual(reading().state, .absent, "the unfinished write is not a failure; nothing else holds a phrase: onboarding")
	}

	/// E93-04: the shell copy is empty (key-only record): counted as no phrase here; with nothing else, onboarding.
	func testE9304EmptyShellCopyIsNoPhraseAndOnboarding() {
		shellRecords[eoaA.lowercased()] = .record(["rev": 1, "schemaVersion": 2, "profiles": [], "mnemonicPhrase": ""])
		XCTAssertEqual(reading().state, .absent)
	}

	/// E93-05: the current record and the shell copy both valid, different accounts: unknown.
	func testE9305CurrentAndShellCopyOfDifferentAccountsAreUnknown() {
		liveMnemonic(phraseB)
		seedKeyOnly(phraseA)
		shellRecords[eoaA.lowercased()] = shellRecord(phraseA)
		XCTAssertEqual(reading().state, .unknown)
	}

	/// E93-06: the current record and the shell copy both valid, same account: valid.
	func testE9306CurrentAndShellCopyOfTheSameAccountAreValid() {
		liveMnemonic(phraseA)
		shellRecords[eoaA.lowercased()] = shellRecord(phraseA)
		let r = reading()
		XCTAssertEqual(r.state, .valid)
		XCTAssertEqual(r.eoa, eoaA)
	}

	/// E9.2.1 (E92-06c): the latest sealing's copy cannot be read and an earlier copy is valid: unknown, not the earlier one. The memory double reads the
	/// payload `unreadable-copy` as an unreadable copy (a test seam; the product store does this with a failed unwrap).
	func testE92_06cAnUnreadableLatestCopyIsUnknownNotTheEarlierOne() {
		let eoaC = self.eoaC()
		store.rawAccounts[isolationName(eoaA)] = BeamioPwaWalletSync.normalized(phraseA)
		store.rawAccounts[isolationName(eoaC)] = Data("unreadable-copy".utf8)
		seedAudit([auditRow(owner: eoaA, utc: "2026-11-17T01:00:00Z"), auditRow(owner: eoaC, utc: "2026-11-17T02:00:00Z")])
		XCTAssertEqual(reading().state, .unknown)
	}

	private func eoaC() -> String { owner(phraseC) }

	// MARK: - Transient read failures are unknown, never absent (2026)

	/// A transient keychain failure (a locked keychain, before the first unlock) of a mnemonic named by a pending marker is a read failure: unknown,
	/// the data kept, retry. It is not ignored as an unfinished write.
	func testATransientReadFailureOfAPendingMnemonicIsUnknownNotAbsent() {
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: eoaA, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.failRawWriteContaining = nil
		store.mnemonic.failReadOwners.insert(eoaA.lowercased())
		store.transientReadOwners.insert(eoaA.lowercased())
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		XCTAssertEqual(reading().state, .unknown, "a transient failure before the first unlock is unknown, not onboarding")
		XCTAssertNotNil(store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount], "the marker is kept")
	}

	/// The same item with a deterministic failure (it does not decode) and a pending marker is the unfinished write: ignored, absent.
	func testADeterministicReadFailureOfAPendingMnemonicIsIgnoredAsAbsent() {
		seedKeyOnly(phraseA)
		store.mnemonic.failReadOwners.insert(eoaA.lowercased())
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA,
		                                                                  moves: [(store.accountName(.mnemonic, eoa: eoaA), isolationName(eoaA))])
		XCTAssertEqual(reading().state, .absent)
	}

	/// The shell copy with a transient failure (its key is not loadable) under a pending marker is unknown, not ignored.
	func testATransientShellCopyFailureUnderAPendingMarkerIsUnknown() {
		seedKeyOnly(phraseA)
		BeamioPwaWalletSync.shellCopyDeterministic = { _ in false }
		shellRecords[eoaA.lowercased()] = .unreadable
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = marker(phase: "pending", owner: eoaA, moves: [])
		XCTAssertEqual(reading().state, .unknown)
	}

	// MARK: - E9.1 write-path verifications (E91-07, E91-08): executed, not declared

	private var writeSeq: Int64 = 500

	/// A residue marker of a write to `newOwner` that began over `oldOwner`'s records: the new account is the marker's account, the old owner is listed,
	/// and nothing is moved yet (the residue is the old owner's key record).
	private func residueMarker(newOwner: String, oldOwner: String) -> Data {
		let object: [String: Any] = ["v": 1, "phase": "pending", "eoa": newOwner, "tag": "residue", "source": "pwaWalletSync",
		                             "utc": "2026-11-17T00:00:00Z", "owners": [oldOwner], "partials": [], "moves": []]
		return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
	}

	private func answerWrite(_ phrase: String) -> [String: Any] {
		writeSeq += 1
		return BeamioPwaWalletSync.answer(["type": "pwaWalletSync", "reqId": 1, "trustedOrigin": true,
		                                   "seq": NSNumber(value: writeSeq), "phrase": phrase], snapshotKnown: true, storageLocked: false)
	}

	/// E91-07: residue (a key record and a pending marker) with the start at onboarding; a new account is written. The write succeeds, and every old
	/// residue is in an isolation name, nothing is deleted, and the audit has a row for each isolated record.
	func testE9107ResidueAtOnboardingThenANewAccountWriteSucceedsAndDeletesNothing() {
		seedKeyOnly(phraseA)
		let eoaA = owner(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = residueMarker(newOwner: owner(phraseB), oldOwner: eoaA)
		XCTAssertEqual(reading().state, .absent, "the residue is onboarding")
		let keysBefore = store.keys.count
		let answer = answerWrite(phraseB)
		let result = (answer["result"] as? [String: Any])?["sync"] as? String
		XCTAssertEqual(result, "updated", "E91-07: the new account is written after the residue")
		XCTAssertGreaterThanOrEqual(store.keys.count + store.rawAccounts.keys.filter { $0.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) }.count, keysBefore,
		                            "no residue is deleted: the key is kept or isolated")
		XCTAssertNotNil(store.keys[eoaA.lowercased()], "the old owner's key record is kept (live; nothing is deleted)")
	}

	/// E91-08: residue with a pending marker and a failed write of the new record: write_failed with the storage reason; every record is kept, and no
	/// record is deleted.
	func testE9108ResidueAndAFailedWriteAnswersWriteFailedAndKeepsEverything() {
		seedKeyOnly(phraseA)
		let eoaA = owner(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = residueMarker(newOwner: owner(phraseB), oldOwner: eoaA)
		let keysBefore = store.keys
		store.failWriteAccounts = [store.accountName(.mnemonic, eoa: owner(phraseB))]
		let answer = answerWrite(phraseB)
		store.failWriteAccounts = []
		XCTAssertEqual(answer["error"] as? String, "write_failed", "E91-08: write_failed")
		// E91-08 (a) (project requirement, retracting the earlier import-clause ruling): the sync path answers write_failed / storage_write for a failed write
		// of the new record (v3.2 step 6). The test pins that reason.
		XCTAssertEqual((answer["error"] as? String), "write_failed", "E91-08: write_failed")
		XCTAssertEqual((answer["reason"] as? String) ?? (answer["result"] as? [String: Any])?["reason"] as? String, "storage_write",
		               "E91-08 (a): storage_write, as the vector and v3.2 step 6 state")
		XCTAssertNil(store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount], "the live marker is isolated, not deleted")
		XCTAssertTrue(store.rawAccounts.keys.contains { $0.hasPrefix("wallet.sync.marker.iso.") },
		              "the marker bytes are kept under an isolation name")
	}

	/// E91-08 split (project ruling, final): on pwaWalletSync, a refused write of the new mnemonic is write_failed / storage_write; a write that is accepted
	/// but does not read back is internal_state. The two are distinguished here.
	func testE9108WriteRefusedIsStorageWriteButAReadBackMismatchIsInternalState() {
		seedKeyOnly(phraseA)
		let eoaA = owner(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = residueMarker(newOwner: owner(phraseB), oldOwner: eoaA)
		store.failWriteAccounts = [store.accountName(.mnemonic, eoa: owner(phraseB))]
		let refused = answerWrite(phraseB)
		store.failWriteAccounts = []
		XCTAssertEqual(refused["error"] as? String, "write_failed")
		XCTAssertEqual((refused["reason"] as? String) ?? (refused["result"] as? [String: Any])?["reason"] as? String, "storage_write",
		               "a refused write is storage_write")

		// A fresh residue: the write is accepted but the new record does not read back.
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		seedKeyOnly(phraseA)
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = residueMarker(newOwner: owner(phraseB), oldOwner: eoaA)
		store.dropWriteAccounts = [store.accountName(.mnemonic, eoa: owner(phraseB))]
		let mismatch = answerWrite(phraseB)
		store.dropWriteAccounts = []
		XCTAssertEqual(mismatch["error"] as? String, "write_failed")
		XCTAssertEqual((mismatch["reason"] as? String) ?? (mismatch["result"] as? [String: Any])?["reason"] as? String, "internal_state",
		               "a read-back mismatch is internal_state")
	}
}
