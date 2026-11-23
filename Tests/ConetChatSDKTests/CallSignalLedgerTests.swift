#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// call-control signals have their own delivery state per (callId, sessionId). Synthetic data only.
final class CallSignalLedgerTests: XCTestCase {
	private var ledgerURL: URL {
		BeamioInboxFile.folder!.appendingPathComponent("call_signals_v1.json")
	}

	override func setUp() {
		super.setUp()
		BeamioConetChatCallLedger.clear()
	}

	override func tearDown() {
		BeamioConetChatCallLedger.clear()
		super.tearDown()
	}

	func testADeliveredKeyIsRecordedPerCallAndSession() {
		let a = BeamioConetChatCallLedger.key(callId: "call-1", sessionId: "sess-1")
		let b = BeamioConetChatCallLedger.key(callId: "call-1", sessionId: "sess-2")
		XCTAssertFalse(BeamioConetChatCallLedger.delivered(a))
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(a))
		XCTAssertTrue(BeamioConetChatCallLedger.delivered(a), "the mark is read back from disk")
		XCTAssertFalse(BeamioConetChatCallLedger.delivered(b), "the same callId with another session is a different signal")
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(a), "marking again is harmless")
	}

	/// An unreadable ledger is not marked, and its unreadable file is left as it was.
	func testAnUnreadableLedgerIsNotMarked() {
		let garbage = Data("not a ledger".utf8)
		try! garbage.write(to: ledgerURL)
		let key = BeamioConetChatCallLedger.key(callId: "call-2", sessionId: "sess-1")
		XCTAssertFalse(BeamioConetChatCallLedger.delivered(key))
		XCTAssertFalse(BeamioConetChatCallLedger.markDelivered(key))
		XCTAssertEqual(try! Data(contentsOf: ledgerURL), garbage)
	}

	func testTheHandOverRuleOnlyHandsOverANewCallSignalToARegisteredObserver() {
		XCTAssertTrue(CallSignalRule.shouldHandOver(isCallControl: true, delivered: false, observerRegistered: true))
		XCTAssertFalse(CallSignalRule.shouldHandOver(isCallControl: true, delivered: true, observerRegistered: true), "a delivered key is not again")
		XCTAssertFalse(CallSignalRule.shouldHandOver(isCallControl: true, delivered: false, observerRegistered: false), "no observer: try later")
		XCTAssertFalse(CallSignalRule.shouldHandOver(isCallControl: false, delivered: false, observerRegistered: true), "not a call signal")
	}
}
#endif

#if BEAMIO_TEST_HOOKS
extension CallSignalLedgerTests {
	/// a signal that no layer took yet waits as pending, durably; a delivered key is never pending again.
	func testAPendingSignalWaitsAndThenIsDelivered() {
		let key = BeamioConetChatCallLedger.key(callId: "call-9", sessionId: "sess-9")
		let p = BeamioConetChatCallLedger.Pending(key: key, type: "end", callId: "call-9", sessionId: "sess-9", from: "0xabc")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key), .none)
		XCTAssertTrue(BeamioConetChatCallLedger.markPending(p))
		XCTAssertEqual(BeamioConetChatCallLedger.state(key), .pending, "read back from disk")
		XCTAssertEqual(BeamioConetChatCallLedger.pendingSignals(), [p])
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key))
		XCTAssertEqual(BeamioConetChatCallLedger.state(key), .delivered)
		XCTAssertTrue(BeamioConetChatCallLedger.pendingSignals().isEmpty, "a delivered signal is no longer pending")
	}

	/// A pending mark never overrides a delivered key.
	func testAPendingMarkDoesNotOverrideADeliveredKey() {
		let key = BeamioConetChatCallLedger.key(callId: "call-10", sessionId: "sess-10")
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key))
		let p = BeamioConetChatCallLedger.Pending(key: key, type: "timeout", callId: "call-10", sessionId: "sess-10", from: "0xabc")
		XCTAssertTrue(BeamioConetChatCallLedger.markPending(p))
		XCTAssertEqual(BeamioConetChatCallLedger.state(key), .delivered)
	}
}
#endif

#if BEAMIO_TEST_HOOKS
extension CallSignalLedgerTests {
	/// D5: a claim is held from the hand-over until it is marked or released; a delivered key cannot be claimed.
	func testAClaimIsHeldUntilMarkedOrReleased() {
		let key = BeamioConetChatCallLedger.key(callId: "call-11", sessionId: "sess-11")
		let p = BeamioConetChatCallLedger.Pending(key: key, type: "end", callId: "call-11", sessionId: "sess-11", from: "0xabc")
		XCTAssertTrue(BeamioConetChatCallLedger.claim(p))
		XCTAssertFalse(BeamioConetChatCallLedger.claim(p), "a second path must not hand the same key over at once")
		BeamioConetChatCallLedger.release(key)
		XCTAssertTrue(BeamioConetChatCallLedger.claim(p), "a released claim can be taken again")
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key))
		XCTAssertFalse(BeamioConetChatCallLedger.claim(p), "a delivered key cannot be claimed")
	}
}
#endif
