#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// the retry of an unconfirmed `gossip_delivery_ack`. First after 30 s, doubling, at most 600 s.
final class GossipRetryTests: XCTestCase {
	func testTheRetryDelayDoublesAndStopsAtTenMinutes() {
		let delays = (0 ..< 7).map { GossipRetrySchedule.delay(failures: $0) }
		XCTAssertEqual(delays, [30, 60, 120, 240, 480, 600, 600])
	}
}
#endif

#if BEAMIO_TEST_HOOKS
extension GossipRetryTests {
	/// D1,: an immediate retry that fails does not move the interval sequence: the next wait stays where the sequence has it.
	func testAnImmediateRetryDoesNotMoveTheSequence() {
		var book = BeamioGossipRetryBook()
		let h = "0x" + String(repeating: "7", count: 64)
		_ = book.recordFailure(h)
		_ = book.recordFailure(h)
		let before = GossipRetrySchedule.delay(failures: (book.failures[h] ?? 0) - 1)
		let retry = book.recordFailure(h, advance: false)
		XCTAssertEqual(book.failures[h], 2, "the count is unchanged by an immediate retry")
		XCTAssertEqual(GossipRetrySchedule.delay(failures: retry.failures - 1), before)
	}
}
#endif
