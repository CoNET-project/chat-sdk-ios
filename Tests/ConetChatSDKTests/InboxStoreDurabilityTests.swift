#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// the dedupe record is on disk, and a write that fails is reported, not assumed. Every inbox call reads the
/// file (nothing is cached), so a later call answers from disk, which is the restart check here. Synthetic data only.
final class InboxStoreDurabilityTests: XCTestCase {
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
	private let hashA = "0x" + String(repeating: "a", count: 64)

	override func setUp() {
		super.setUp()
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.clear()
	}

	override func tearDown() {
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.clear()
		super.tearDown()
	}

	func testAStoredFrameIsOnDiskAndAnswersTheDedupeQuestion() {
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hashA))
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hashA, armor: armor, viaDomain: "domain.example"))
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hashA), "the record is read back from disk")
		XCTAssertEqual(BeamioConetChatInboxStore.list().map { $0.armorHash }, [hashA])
		// A recorded frame is not written again: put answers true and the inbox still holds one entry.
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hashA, armor: armor, viaDomain: "domain.example"))
		XCTAssertEqual(BeamioConetChatInboxStore.list().count, 1)
	}

	func testAFailedWriteIsReportedAndRecordsNothing() {
		BeamioConetChatInboxStore.failWrites = true
		XCTAssertFalse(BeamioConetChatInboxStore.put(armorHash: hashA, armor: armor, viaDomain: "domain.example"),
		               "a failed write must be reported")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hashA), "a failed write leaves no record")
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty)
	}

	/// After the page confirms, the armor leaves; the record stays, so a redelivery is still recognised.
	func testAConfirmedFrameLeavesTheInboxButKeepsItsRecord() {
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hashA, armor: armor, viaDomain: "domain.example"))
		BeamioConetChatInboxStore.confirm([hashA])
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty, "a confirmed message has nothing to replay")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hashA), "the dedupe record outlives the confirmation")
	}
}
#endif
