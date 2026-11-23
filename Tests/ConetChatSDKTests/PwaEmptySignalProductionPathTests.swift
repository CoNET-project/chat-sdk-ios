import XCTest
@testable import ConetChatSDK

/// The production path of `pwaEmptySignal` (iOS review 2026-11-17, condition 1). The signal enters through `BeamioConetChatModule.handleCommand`, which
/// takes the native reading at the signal and passes its seq to the discard gate. No test seam is used in the positive and negative cases below; the
/// seam is only used to check the helper's nil cases. Synthetic keys only; no Keychain item is touched (memory store).
final class PwaEmptySignalProductionPathTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?

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

	/// An explicitly empty signal through the production command entry.
	private func emptySignal(seq: Int) {
		BeamioConetChatModule.handleCommand(["type": "pwaEmptySignal", "reqId": 7, "trustedOrigin": true,
		                                     "seq": NSNumber(value: seq), "pwaState": "explicit_empty"], emit: { _ in })
	}

	/// Both sides explicitly empty: a private-key record and no mnemonic. The production native reading is absent at the signal, and carries its seq.
	// 2026-11-17 project constant (33(5) 不删): the production path takes its reading with the signal seq as before, but the discard removes nothing.
	func testTheProductionPathKeepsThePrivateKeyRecordWhenTheNativeReadCarriesTheSignalSeq() {
		store.keys[account] = Data(repeating: 0x11, count: 32)
		emptySignal(seq: 100)
		XCTAssertFalse(store.keys.isEmpty, "the private-key record is kept: a signal never removes a record")
	}

	/// A valid mnemonic on the device: the native reading is valid, so the discard is blocked on the production path.
	func testTheProductionPathKeepsTheRecordWhenTheNativeStateIsValid() {
		_ = BeamioNativeRestore.restoreWrite(phrase: phrase, userExplicit: true, sessionIsG2: false, store: store)
		let before = store.keys
		emptySignal(seq: 100)
		XCTAssertEqual(store.keys, before, "a valid mnemonic on the device blocks the discard")
	}

	/// The helper's nil cases: a reading that cannot be taken carries no seq, so the gate refuses the discard. A non-integer seq carries none either.
	func testTheReadSeqIsNilWhenTheReadingCannotBeTaken() {
		let body: [String: Any] = ["seq": NSNumber(value: 100)]
		XCTAssertNil(BeamioPwaWalletSync.snapshotReadSeq(body: body, snapshotKnown: false, storageLocked: false, store: store), "snapshot unknown")
		XCTAssertNil(BeamioPwaWalletSync.snapshotReadSeq(body: body, snapshotKnown: true, storageLocked: true, store: store), "storage locked")
		XCTAssertNil(BeamioPwaWalletSync.snapshotReadSeq(body: ["seq": "x"], snapshotKnown: true, storageLocked: false, store: store), "bad seq")
		XCTAssertEqual(BeamioPwaWalletSync.snapshotReadSeq(body: body, snapshotKnown: true, storageLocked: false, store: store), 100,
		               "a reading taken at the signal carries the signal's seq")
	}
}
