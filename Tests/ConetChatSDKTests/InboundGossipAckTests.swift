#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// a copy of an inbound frame that arrives while its `gossip_delivery_ack` is in flight does not POST again. Once
/// that ack has ended, a copy is acked again (IA-05). Synthetic data only.
final class InboundGossipAckTests: XCTestCase {
	func testAnAckInFlightIsNotPostedAgainUntilItEnds() {
		let hash = "0x" + String(repeating: "7", count: 64)
		XCTAssertTrue(BeamioConetChatModule.beginGossipAck(hash), "the first ack starts")
		XCTAssertFalse(BeamioConetChatModule.beginGossipAck(hash), "a copy meanwhile does not start a second POST")
		BeamioConetChatModule.endGossipAck(hash)
		XCTAssertTrue(BeamioConetChatModule.beginGossipAck(hash), "after the ack ends, a copy is acked again (IA-05)")
		BeamioConetChatModule.endGossipAck(hash)
	}

	func testTwoFramesHaveIndependentAcks() {
		let first = "0x" + String(repeating: "8", count: 64)
		let second = "0x" + String(repeating: "9", count: 64)
		XCTAssertTrue(BeamioConetChatModule.beginGossipAck(first))
		XCTAssertTrue(BeamioConetChatModule.beginGossipAck(second), "an ack in flight for one frame does not hold another")
		BeamioConetChatModule.endGossipAck(first)
		BeamioConetChatModule.endGossipAck(second)
	}
}
#endif
