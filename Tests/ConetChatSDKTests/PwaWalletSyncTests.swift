import XCTest
@testable import ConetChatSDK

/// The PWA sync commands (25.52Y.163 r2.4 to r2.5.17, 第 46、49、53、56、58 项): the seq ledger, the trusted origin, the closed answers,
/// and the three-value preread. Synthetic values only; no key material.
final class PwaWalletSyncTests: XCTestCase {
	override func setUp() {
		super.setUp()
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func code(_ answer: [String: Any]) -> String? {
		(answer["result"] as? [String: Any])?["code"] as? String
	}

	private func error(_ answer: [String: Any]) -> String? {
		answer["error"] as? String
	}

	private func sync(seq: Any?, trusted: Bool = true, snapshotKnown: Bool = true, locked: Bool = false) -> [String: Any] {
		var body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1,
		                           "phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]
		if let seq { body["seq"] = seq }
		if trusted { body["trustedOrigin"] = true }
		return BeamioPwaWalletSync.answer(body, snapshotKnown: snapshotKnown, storageLocked: locked)
	}

	// SQ-05 and SQ-06: the two commands share one ledger; an older seq is stale in either order.
	func testAnEarlierSeqAfterALaterOneIsStaleInEitherOrder() {
		BeamioPwaWalletSync.recordAccepted(5)
		XCTAssertFalse(BeamioPwaWalletSync.isCurrent(4), "SQ-05, SQ-06: seq 4 after 5 is stale")
		XCTAssertEqual(error(sync(seq: 4)), "stale_seq")
	}

	// SQ-07: an equal seq is current.
	func testAnEqualSeqIsCurrent() {
		BeamioPwaWalletSync.recordAccepted(5)
		XCTAssertTrue(BeamioPwaWalletSync.isCurrent(5), "SQ-07")
	}

	// SQ-08: a restart clears the in-process ledger; the PWA's persisted seq keeps rising, so nothing rolls back.
	func testARestartClearsTheLedger() {
		BeamioPwaWalletSync.recordAccepted(5)
		BeamioPwaWalletSync.restartForTests()
		XCTAssertTrue(BeamioPwaWalletSync.isCurrent(6), "SQ-08: a later seq is accepted after the restart")
	}

	// Seq range (25.52Y.163 r2.5.6, BeamioPwaSeq): 0, 1.8e12 and 2^53−1 are valid; 1.0, a negative, 2^53 and a missing value are not.
	// A valid seq reaches the write (covered by PwaPhraseOverwriteTests); the parse is checked here without touching the store.
	func testTheSeqRangeIsAcceptedAsSpecified() {
		for seq: Any in [NSNumber(value: Int64(0)), NSNumber(value: Int64(1_800_000_000_000)), NSNumber(value: Int64(9_007_199_254_740_991))] {
			XCTAssertNotNil(BeamioPwaSeq.parse(seq), "a valid seq")
		}
		for seq: Any? in [NSNumber(value: 1.0), NSNumber(value: Int64(-1)), NSNumber(value: Int64(9_007_199_254_740_992)), nil] {
			XCTAssertNil(BeamioPwaSeq.parse(seq), "an invalid seq")
			XCTAssertEqual(error(sync(seq: seq)), "bad_request", "an invalid seq is bad_request")
		}
	}

	// 第 46(5)(6) 项: without the shell's trustedOrigin, the answer is untrusted_source for both sync and the empty signal.
	func testAnUntrustedRequestIsRefused() {
		XCTAssertEqual(error(sync(seq: 3, trusted: false)), "untrusted_source")
		let emptySignal = BeamioPwaWalletSync.answer(
			["type": "pwaEmptySignal", "reqId": 2, "seq": 3, "pwaState": "explicit_empty"], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual(error(emptySignal), "untrusted_source")
	}

	// 第 49(1) 项: a not-ready internal state is write_failed with reason internal_state, and nothing is written.
	func testANotReadyStateFailsClosedWithAReason() {
		let answer = sync(seq: 3, snapshotKnown: false)
		XCTAssertEqual(error(answer), "write_failed")
		XCTAssertEqual(answer["reason"] as? String, "internal_state")
	}

	// 第 46(7) 项: an untrusted preread is ok false with untrusted_source, and never a state.
	func testAnUntrustedPrereadGivesNoState() {
		let answer = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 4], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual(error(answer), "untrusted_source")
		XCTAssertNil(answer["result"])
	}

	// 第 31(3) 项 (r2.5.17): a readable store with no mnemonic is absent; an unknown snapshot is unknown and reads nothing.
	func testThePrereadIsAbsentOnAReadableEmptyStore() {
		let store = MemoryNativeKeyStore()
		XCTAssertEqual(BeamioPwaWalletSync.preread(snapshotKnown: true, storageLocked: false, store: store), .absent)
	}

	func testThePrereadIsUnknownWhileTheSnapshotIsUnknown() {
		let store = MemoryNativeKeyStore()
		XCTAssertEqual(BeamioPwaWalletSync.preread(snapshotKnown: false, storageLocked: false, store: store), .unknown)
		XCTAssertEqual(BeamioPwaWalletSync.preread(snapshotKnown: true, storageLocked: true, store: store), .unknown)
	}

	/// 第 59(2)(a) 项: the preread answers `result.state`; an unknown native state is `unknown`, with no phrase.
	func testThePrereadAnswerIsTheStateOfTheReading() {
		let answer = BeamioPwaWalletSync.answer(
			["type": "nativeMnemonicPreread", "reqId": 5, "trustedOrigin": true, "seq": NSNumber(value: Int64(1))],
			snapshotKnown: false, storageLocked: false)
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "read_error")
		XCTAssertNil((answer["result"] as? [String: Any])?["phrase"])
	}
}
