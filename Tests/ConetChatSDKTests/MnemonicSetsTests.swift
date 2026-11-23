import XCTest
@testable import ConetChatSDK

/// The no-passcode state of the mnemonic (finalized section 1): per-mnemonic sets, a `current` pointer, keychain mode with a new name prefix,
/// write and read back before `current` moves, old sets kept, honest failure answers. Synthetic phrases only.
final class MnemonicSetsTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var nextSeq: Int64 = 900

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func eoa(_ phrase: String) -> String { BeamioPwaWalletSync.derivedAccount(phrase: phrase)!.eoa }

	private func save(_ phrase: String) -> BeamioMnemonicSets.Save {
		BeamioMnemonicSets.save(phrase: phrase, store: store, utc: "2026-11-22T00:00:00Z")
	}

	private func setBytes(_ phrase: String) -> Data? {
		if case .present(let b) = store.rawRead(account: BeamioMnemonicSets.setName(eoa(phrase))) { return b }
		return nil
	}

	private func sync(_ phrase: String) -> [String: Any] {
		nextSeq += 1
		let body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "trustedOrigin": true, "seq": NSNumber(value: nextSeq), "phrase": phrase]
		return BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)
	}

	private func preread() -> [String: Any]? {
		nextSeq += 1
		let body: [String: Any] = ["type": "nativeMnemonicPreread", "reqId": 2, "trustedOrigin": true, "seq": NSNumber(value: nextSeq)]
		return (BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)["result"] as? [String: Any])
	}

	func testTheFirstMnemonicIsWrittenAsASetInKeychainModeAndBecomesCurrent() throws {
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .confirmedMissing, "nothing yet: the only confirmed absence")
		XCTAssertEqual(save(phraseA), .updated)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .ok(eoa: eoa(phraseA), phrase: phraseA))
		let object = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(setBytes(phraseA))) as? [String: Any])
		XCTAssertEqual(object["mode"] as? String, "keychain", "keychain mode: no Secure Enclave wrap")
		XCTAssertEqual(object["v"] as? Int, 1)
		XCTAssertEqual(object["eoa"] as? String, eoa(phraseA))
		XCTAssertNil(object["blob"], "no wrapped blob")
		XCTAssertEqual(Set(store.rawAccounts.keys), [BeamioMnemonicSets.setName(eoa(phraseA)), BeamioMnemonicSets.currentName], "only the new names are used")
	}

	func testTheSameMnemonicAgainIsIdempotentAndChangesNoByte() {
		XCTAssertEqual(save(phraseA), .updated)
		let before = store.rawAccounts
		XCTAssertEqual(save(phraseA), .idempotent)
		XCTAssertEqual(store.rawAccounts, before, "nothing is rewritten")
	}

	func testADifferentMnemonicIsWrittenFirstThenCurrentMovesAndTheOldSetStaysByteForByte() {
		XCTAssertEqual(save(phraseA), .updated)
		let oldBytes = setBytes(phraseA)
		XCTAssertEqual(save(phraseB), .updated)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .ok(eoa: eoa(phraseB), phrase: phraseB))
		XCTAssertEqual(setBytes(phraseA), oldBytes, "the old set is kept byte for byte")
		XCTAssertNotNil(setBytes(phraseB))
		// back to the first one: the pointer moves, no set is rewritten or lost
		let bBytes = setBytes(phraseB)
		XCTAssertEqual(save(phraseA), .updated)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .ok(eoa: eoa(phraseA), phrase: phraseA))
		XCTAssertEqual(setBytes(phraseB), bBytes)
		XCTAssertEqual(setBytes(phraseA), oldBytes)
	}

	func testAFailedSetWriteLeavesCurrentAndTheOldSetAsTheyWere() {
		XCTAssertEqual(save(phraseA), .updated)
		let before = store.rawAccounts
		store.failWriteAccounts.insert(BeamioMnemonicSets.setName(eoa(phraseB)))
		XCTAssertEqual(save(phraseB), .failed("storage_write"))
		XCTAssertEqual(store.rawAccounts, before, "nothing changed")
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .ok(eoa: eoa(phraseA), phrase: phraseA), "current did not move")
	}

	func testAFailedPointerWriteKeepsTheOldPointerAndTheNewSetStays() {
		XCTAssertEqual(save(phraseA), .updated)
		store.failWriteAccounts.insert(BeamioMnemonicSets.currentName)
		XCTAssertEqual(save(phraseB), .failed("storage_write"))
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .ok(eoa: eoa(phraseA), phrase: phraseA), "current stays on the first mnemonic")
		XCTAssertNotNil(setBytes(phraseB), "the written set is kept (nothing is deleted)")
	}

	func testAnInvalidPhraseIsABadRequestAndWritesNothing() {
		XCTAssertEqual(save("not a mnemonic at all"), .badRequest)
		XCTAssertTrue(store.rawAccounts.isEmpty)
	}

	func testTheReadAnswersAreDistinctAndOnlyAnAbsentPointerIsConfirmedMissing() {
		XCTAssertEqual(save(phraseA), .updated)
		// a pointer that is damaged: unknown, kept
		store.rawAccounts[BeamioMnemonicSets.currentName] = Data("garbage".utf8)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .unknown)
		// a pointer without its set: unknown, not absent
		store.rawAccounts[BeamioMnemonicSets.currentName] = Data(#"{"eoa":"0x2222222222222222222222222222222222222222","v":1}"#.utf8)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .unknown)
		// a set whose phrase does not derive its address: verify failed
		let wrong = eoa(phraseB)
		store.rawAccounts[BeamioMnemonicSets.setName(wrong)] = Data(#"{"eoa":"\#(wrong)","mode":"keychain","phrase":"\#(phraseA)","utc":"x","v":1}"#.utf8)
		store.rawAccounts[BeamioMnemonicSets.currentName] = Data(#"{"eoa":"\#(wrong)","v":1}"#.utf8)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .verifyFailed)
		// a read that fails: a read error
		store.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .readError)
		XCTAssertNotEqual(BeamioMnemonicSets.current(store: store), .confirmedMissing)
	}

	func testThePwaSyncWritesTheSetAndThePrereadReturnsTheCurrentMnemonic() {
		let answer = sync(phraseA)
		XCTAssertEqual((answer["result"] as? [String: Any])?["sync"] as? String, "updated")
		XCTAssertEqual(Set(store.rawAccounts.keys), [BeamioMnemonicSets.setName(eoa(phraseA)), BeamioMnemonicSets.currentName],
		               "the sync writes only the set storage: no marker, no isolation copy, no device record")
		let read = preread()
		XCTAssertEqual(read?["code"] as? String, "ok")
		XCTAssertEqual(read?["mnemonic"] as? String, phraseA)
		XCTAssertEqual(read?["eoa"] as? String, eoa(phraseA))
		XCTAssertEqual((sync(phraseA)["result"] as? [String: Any])?["sync"] as? String, "idempotent")
		XCTAssertEqual((sync(phraseB)["result"] as? [String: Any])?["sync"] as? String, "updated")
		XCTAssertEqual(preread()?["mnemonic"] as? String, phraseB, "current moved to the new mnemonic")
		XCTAssertNotNil(setBytes(phraseA), "the old set is kept")
	}

	func testTheReadingIsUnknownNotAbsentWhenCurrentCannotBeReadOrIsDamaged() {
		_ = sync(phraseA)
		store.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .unknown, "a read failure is never reported as absent")
		store.failRawReadAccounts.removeAll()
		store.rawAccounts[BeamioMnemonicSets.currentName] = Data("garbage".utf8)
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .unknown, "a damaged pointer is never reported as absent")
		XCTAssertNotNil(setBytes(phraseA), "the set is kept")
	}

	func testWithNoSetAndNoOtherRecordThePrereadIsAbsent() {
		XCTAssertEqual(preread()?["code"] as? String, "confirmed_missing")
	}

	/// the Data copies of the phrase and of the derived key that a save makes are wiped, and the answers do not change
	func testASaveWipesTheDataCopiesOfThePhraseAndTheKey() {
		let phraseLength = BeamioPwaWalletSync.normalized(phraseA).count
		BeamioWipeProbe.start()
		XCTAssertEqual(save(phraseA), .updated)
		XCTAssertEqual(save(phraseA), .idempotent)
		let events = BeamioWipeProbe.stop()
		XCTAssertTrue(events.allSatisfy { $0.allZero }, "every wiped buffer is zero afterwards")
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == 32 && $0.hadNonZero }.count, 2, "the derived key of each save is wiped")
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength && $0.hadNonZero }.count, 2, "the normalized phrase of each save is wiped")
	}

	// MARK:: the preread answers only the current record as it is (preread-returns-current-record-as-is.v1)

	private func prrCase(_ prefix: String) throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: "preread-returns-current-record-as-is.v1")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return try XCTUnwrap(cases.first { ($0["id"] as? String ?? "").hasPrefix(prefix) }, prefix)
	}

	/// PRR-01 and PRR-05: a plaintext current is returned as it is, with no passcode, no unlock and no SDK session (none exists in this test)
	func testPRR01AndPRR05APlaintextCurrentIsReturnedAsItIsWithoutAnyGate() throws {
		XCTAssertEqual((try prrCase("PRR-01")["expect"] as? [String: Any])?["code"] as? String, "ok")
		_ = sync(phraseA)
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		let result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertEqual(result["mnemonic"] as? String, phraseA)
		XCTAssertEqual(result["eoa"] as? String, eoa(phraseA))
		XCTAssertNil(result["state"], "the old state shape is gone")
		XCTAssertNil(result["phrase"])
		XCTAssertNotEqual(result["code"] as? String, "passcode_not_provided", "PRR-05: not gated by the passcode state")
	}

	/// PRR-03: the empty store is a confirmed absence, and it is not a bridge fault; a record of only a private key (no mnemonic) is the same
	func testPRR03TheEmptyAndTheKeyOnlyStoreAreConfirmedMissing() throws {
		XCTAssertEqual((try prrCase("PRR-03")["expect"] as? [String: Any])?["code"] as? String, "confirmed_missing")
		var result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, "confirmed_missing")
		// a key without a mnemonic (the published walletKey kind) is no account: still a confirmed absence
		let key = BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!
		XCTAssertTrue(store.writeItem(.key, eoa: key.eoa, value: key.key))
		BeamioPwaWalletSync.restartForTests()
		result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, "confirmed_missing", "key_only is confirmed_missing")
	}

	/// PRR-04: a read failure is read_error, never a confirmed absence, and the data is kept
	func testPRR04AReadFailureIsReadErrorAndTheDataIsKept() throws {
		XCTAssertEqual((try prrCase("PRR-04")["expect"] as? [String: Any])?["code"] as? String, "read_error")
		_ = sync(phraseA)
		let before = store.rawAccounts
		store.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		BeamioPwaWalletSync.restartForTests()
		let result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, "read_error")
		XCTAssertNotEqual(result["code"] as? String, "confirmed_missing")
		XCTAssertNil(result["mnemonic"])
		XCTAssertEqual(store.rawAccounts, before, "the data is kept")
	}

	/// PRR-07: a passcode state of another command is not the preread answer: with the passcode bundle not provided the preread still answers from the store
	func testPRR07ThePasscodeStateOfAnotherCommandDoesNotOverrideThePreread() throws {
		XCTAssertEqual(try prrCase("PRR-07")["passcodeStateDoesNotOverridePreread"] as? Bool, true)
		_ = sync(phraseA)
		let result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertNil(result["notReadyReason"])
	}

	/// MCF3-09 (mnemonic-cipher-format.v4): confirmed_missing is distinct from read_error; the empty store is the only confirmed absence
	func testMCF309ConfirmedMissingIsDistinct() throws {
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let cases = try XCTUnwrap((try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any]))["cases"] as? [[String: Any]])
		let want = try XCTUnwrap(cases.first { ($0["id"] as? String ?? "").hasPrefix("MCF3-09") }?["expect"] as? [String: Any])
		let result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, want["code"] as? String)
		XCTAssertEqual(result["code"] as? String, "confirmed_missing")
	}

	/// MCF3-10 (mnemonic-cipher-format.v4): a read failure is read_error, never confirmed_missing, and the data is kept
	func testMCF310ReadErrorIsDistinctAndDataKept() throws {
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let cases = try XCTUnwrap((try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any]))["cases"] as? [[String: Any]])
		let want = try XCTUnwrap(cases.first { ($0["id"] as? String ?? "").hasPrefix("MCF3-10") }?["expect"] as? [String: Any])
		_ = sync(phraseA)
		let before = store.rawAccounts
		store.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		BeamioPwaWalletSync.restartForTests()
		let result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, want["code"] as? String)
		XCTAssertEqual(want["dataKept"] as? Bool, true)
		XCTAssertEqual(store.rawAccounts, before, "the data is kept")
	}

	// MARK: - write-fault-shape-independent.v3 (mustPass, shell cases MS-W1, MS-W2, MS-R1)

	private func faultCase(_ id: String) throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: "write-fault-shape-independent.v3")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let shell = try XCTUnwrap((root["mustPass"] as? [String: Any])?["shellCases"] as? [[String: Any]])
		return try XCTUnwrap(shell.first { ($0["id"] as? String) == id }, id)
	}

	/// MS-W1: the write of a new set fails: current stays on set A and A's bytes are unchanged, nothing is switched
	func testMSW1AFailedWriteOfANewSetDoesNotSwitchCurrent() throws {
		XCTAssertEqual(try faultCase("MS-W1")["kind"] as? String, "write_fault_no_switch")
		XCTAssertEqual(save(phraseA), .updated)
		let aBefore = setBytes(phraseA), currentBefore = store.rawAccounts[BeamioMnemonicSets.currentName]
		store.failWriteAccounts.insert(BeamioMnemonicSets.setName(eoa(phraseB)))
		guard case .failed = save(phraseB) else { return XCTFail("the write fault is reported, never success") }
		XCTAssertEqual(store.rawAccounts[BeamioMnemonicSets.currentName], currentBefore, "current is not switched")
		XCTAssertEqual(setBytes(phraseA), aBefore, "set A's bytes are unchanged")
		XCTAssertEqual(BeamioMnemonicSets.current(store: store), .ok(eoa: eoa(phraseA), phrase: phraseA))
	}

	/// MS-W2: the read-back of the new set differs: current stays on A, A is unchanged
	func testMSW2AReadBackMismatchDoesNotSwitchCurrent() throws {
		XCTAssertEqual(try faultCase("MS-W2")["kind"] as? String, "write_fault_readback_mismatch_no_switch")
		XCTAssertEqual(save(phraseA), .updated)
		let aBefore = setBytes(phraseA), currentBefore = store.rawAccounts[BeamioMnemonicSets.currentName]
		store.corruptWritePrefixes = [BeamioMnemonicSets.setName(eoa(phraseB))]
		guard case .failed = save(phraseB) else { return XCTFail("a read-back mismatch is reported, never success") }
		XCTAssertEqual(store.rawAccounts[BeamioMnemonicSets.currentName], currentBefore, "current is not switched")
		XCTAssertEqual(setBytes(phraseA), aBefore, "set A's bytes are unchanged")
	}

	/// MS-R1: a read fault keeps the data: nothing is written or deleted, and the answer is read_error, never confirmed_missing
	func testMSR1AReadFaultKeepsTheData() throws {
		XCTAssertEqual(try faultCase("MS-R1")["kind"] as? String, "read_fault_keeps_data")
		_ = sync(phraseA)
		let before = store.rawAccounts
		store.failRawReadAccounts.insert(BeamioMnemonicSets.setName(eoa(phraseA)))
		BeamioPwaWalletSync.restartForTests()
		let result = try XCTUnwrap(preread())
		XCTAssertNotEqual(result["code"] as? String, "confirmed_missing")
		XCTAssertNotEqual(result["code"] as? String, "ok")
		XCTAssertEqual(store.rawAccounts, before, "nothing deleted, nothing written")
	}
}
