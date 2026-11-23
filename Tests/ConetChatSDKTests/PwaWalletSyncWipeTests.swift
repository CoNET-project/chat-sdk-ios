#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The byte copies of the phrase and the key that the pwaWalletSync write makes are wiped when they are no longer used, and the answers are unchanged.
/// A Swift String cannot be zeroed (an accepted limit); these tests cover the Data copies: the derived key, the normalized phrase and the read-back.
final class PwaWalletSyncWipeTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var nextSeq: Int64 = 500

	override func setUp() {
		super.setUp()
		// withdrawn overwrite and sealing format (never published): the test seam turns the old phrase write on here only
		BeamioPwaWalletSync.legacyPhraseWriteForTests = true
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioPwaPhraseOverwrite.wrapAliasProbe = { _ in .present }
		BeamioPwaPhraseOverwrite.enumerationSucceeds = { $0.enumerateKeyOwners() != nil }
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioPwaWalletSync.legacyPhraseWriteForTests = false
		_ = BeamioWipeProbe.stop()
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioPwaPhraseOverwrite.wrapAliasProbe = { _ in .present }
		BeamioPwaPhraseOverwrite.enumerationSucceeds = { $0.enumerateKeyOwners() != nil }
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func seed(_ phrase: String) {
		let a = BeamioPwaWalletSync.derivedAccount(phrase: phrase)!
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phrase)))
		XCTAssertTrue(store.writeItem(.commit, eoa: a.eoa, value: Data(#"{"v":1}"#.utf8)))
		store.rawAccounts[BeamioWalletCredentialBlob.account(a.eoa)] = Data("k-record-of-the-account".utf8)
	}

	private func sync(_ phrase: String) -> [String: Any] {
		nextSeq += 1
		let body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "trustedOrigin": true, "seq": NSNumber(value: nextSeq), "phrase": phrase]
		return BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)
	}

	private func syncResult(_ answer: [String: Any]) -> String? { (answer["result"] as? [String: Any])?["sync"] as? String }

	func testOverwriteWipesTheKeyThePhraseAndTheReadBackAndStaysUpdated() {
		seed(phraseA)
		let b = BeamioPwaWalletSync.derivedAccount(phrase: phraseB)!
		let phraseLength = BeamioPwaWalletSync.normalized(phraseB).count
		BeamioWipeProbe.start()
		let answer = sync(phraseB)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual(syncResult(answer), "updated", "the answer is unchanged")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: b.eoa), BeamioPwaWalletSync.normalized(phraseB), "the new record is the phrase")
		XCTAssertEqual(store.readItem(.key, eoa: b.eoa), b.key, "the new key is the derived key")
		XCTAssertTrue(events.allSatisfy { $0.allZero }, "every wiped buffer is zero afterwards")
		// the derived key (32 bytes) of the request, the normalized phrase, and the read-back key and phrase
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == 32 && $0.hadNonZero }.count, 2, "the derived key and the read-back key are wiped")
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength && $0.hadNonZero }.count, 2, "the normalized phrase and the read-back phrase are wiped")
	}

	func testIdempotentWritePathWipesItsCopiesAndStaysIdempotent() {
		seed(phraseB)
		let phraseLength = BeamioPwaWalletSync.normalized(phraseB).count
		BeamioWipeProbe.start()
		let answer = sync(phraseB)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual(syncResult(answer), "idempotent")
		XCTAssertTrue(events.allSatisfy { $0.allZero })
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == 32 && $0.hadNonZero }.count, 1, "the derived key is wiped")
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength && $0.hadNonZero }.count, 1, "the normalized phrase is wiped")
	}

	func testRefusedWriteStillWipesTheDerivedKey() {
		nextSeq += 1
		let body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "trustedOrigin": true, "seq": NSNumber(value: nextSeq),
		                           "phrase": phraseB, "eoa": "0x0000000000000000000000000000000000000001"]
		BeamioWipeProbe.start()
		let answer = BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual(answer["error"] as? String, "bad_request")
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == 32 && $0.hadNonZero && $0.allZero }.count, 1)
	}

	// MARK: the other copies the reading and the repair make

	private func phraseLength(_ phrase: String) -> Int { BeamioPwaWalletSync.normalized(phrase).count }

	func testIdempotentPathAlsoWipesTheStoredPayload() {
		seed(phraseB)
		BeamioWipeProbe.start()
		_ = sync(phraseB)
		let events = BeamioWipeProbe.stop()
		// the normalized request phrase and the payload read back from the store: two buffers of the phrase length
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength(phraseB) && $0.hadNonZero && $0.allZero }.count, 2)
	}

	func testPhraseOnlyRepairWipesStoredWantAndKeyAndStaysUpdated() {
		let a = BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioWipeProbe.start()
		let answer = sync(phraseA)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual(syncResult(answer), "updated", "the repair answer is unchanged")
		XCTAssertEqual(store.read(eoa: a.eoa), a.key, "the key is written")
		XCTAssertTrue(events.allSatisfy { $0.allZero })
		// the stored payload, the request phrase and the stored phrase normalized: three buffers of the phrase length; the key of the stored phrase
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength(phraseA) && $0.hadNonZero }.count, 3)
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == 32 && $0.hadNonZero }.count, 2)
	}

	func testReadingOfCurrentRecordWipesTheItemPayload() {
		seed(phraseB)
		BeamioWipeProbe.start()
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual(reading.state, .valid, "the reading is unchanged")
		XCTAssertEqual(reading.phrase, phraseB)
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength(phraseB) && $0.hadNonZero && $0.allZero }.count, 1)
	}

	/// Only sealed copies remain (the new account's records are gone): the reading answers from the copy and wipes the copy buffers and the payloads.
	func testReadingFromSealedCopyWipesTheCopyBuffers() {
		seed(phraseA)
		XCTAssertEqual(syncResult(sync(phraseB)), "updated")
		let b = BeamioPwaWalletSync.derivedAccount(phrase: phraseB)!
		for kind in [BeamioChatWalletItemKind.key, .mnemonic, .commit] { XCTAssertTrue(store.deleteItem(kind, eoa: b.eoa)) }
		BeamioNativeAccountPointer.clear()
		BeamioWipeProbe.start()
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual(reading.state, .valid, "the reading is unchanged")
		XCTAssertEqual(reading.phrase, phraseA)
		XCTAssertTrue(events.allSatisfy { $0.allZero })
		// the sealed payload of the item (judged) and the copy buffer of the phrase
		XCTAssertGreaterThanOrEqual(events.filter { $0.count > 0 && $0.hadNonZero }.count, 2)
	}

	func testEmptySignalTakesTheReadingWithoutHoldingItAndStaysAccepted() {
		seed(phraseB)
		nextSeq += 1
		let body: [String: Any] = ["type": "pwaEmptySignal", "reqId": 1, "trustedOrigin": true, "seq": NSNumber(value: nextSeq), "pwaState": "explicit_empty"]
		BeamioWipeProbe.start()
		let answer = BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false, nativeReadSeq: nextSeq)
		let events = BeamioWipeProbe.stop()
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "ok", "the signal is accepted as before")
		XCTAssertNotNil(store.readItem(.mnemonic, eoa: BeamioPwaWalletSync.derivedAccount(phrase: phraseB)!.eoa), "nothing is removed")
		XCTAssertGreaterThanOrEqual(events.filter { $0.count == phraseLength(phraseB) && $0.hadNonZero && $0.allZero }.count, 1, "the reading wiped its payload")
	}
}
#endif
