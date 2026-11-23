#if BEAMIO_TEST_HOOKS
import Foundation
import XCTest
@testable import ConetChatSDK

/// AK-14 (r3bp): a write whose request is over the limit is refused as the envelope `too_large`, whichever size source the caller gives.
/// The vector harness supplies only a size context; this test supplies the size the shell passes (rawByteCount).
final class ShellRecordSizeLimitTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { true }
		func hasAnyRecord() -> Bool { false }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	override func tearDown() {
		BeamioShellRecord.environmentOverride = nil
		super.tearDown()
	}

	func testAWriteOverTheLimitIsABadRequestWithTheShellsByteCount() {
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { nil }, store: Store(), device: Device(), originAllowed: true,
			migrating: { _ in false }, firstRun: { _ in .notRun }, locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { .g0 }, creationMode: { false }
		)
		let body: [String: Any] = ["type": "shellRecordWrite", "reqId": "w4", "record": ["rev": 0, "schemaVersion": 1]]
		let answer = BeamioShellRecord.handle(body, originAllowed: true, rawByteCount: 2_097_153)
		XCTAssertEqual(answer?["code"] as? String, "bad_request", "v171 section 191: a request over the limit is a bad_request")
	}
}
#endif
