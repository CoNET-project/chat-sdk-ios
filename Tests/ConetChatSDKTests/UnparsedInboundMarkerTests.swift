#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// a row that is not JSON leaves only its armorHash marker. It is never handed to the page, and a failed
/// write leaves nothing behind. Synthetic data only. The file is the simulator's own inbox.
final class UnparsedInboundMarkerTests: XCTestCase {
	private func hash(_ n: Int) -> String {
		"0x" + String(format: "%064x", n)
	}

	override func setUp() {
		super.setUp()
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.failReads = false
		BeamioConetChatInboxStore.clear()
	}

	override func tearDown() {
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.failReads = false
		BeamioConetChatInboxStore.clear()
		super.tearDown()
	}

	func testAnUnparsedRowLeavesOnlyItsMarker() {
		let first = BeamioConetChatInboxStore.admitMarker(armorHash: hash(1))
		XCTAssertEqual(first, BeamioConetChatInboxStore.Admission(readable: true, known: false, stored: true))
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty, "a marker is never handed to the page")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hash(1)))
		let again = BeamioConetChatInboxStore.admitMarker(armorHash: hash(1))
		XCTAssertTrue(again.known)
		XCTAssertFalse(again.stored, "a repeated copy writes nothing")
	}

	func testAFailedMarkerWriteStoresNothing() {
		BeamioConetChatInboxStore.failWrites = true
		let attempt = BeamioConetChatInboxStore.admitMarker(armorHash: hash(2))
		XCTAssertFalse(attempt.stored)
		BeamioConetChatInboxStore.failWrites = false
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hash(2)))
	}
}
#endif
