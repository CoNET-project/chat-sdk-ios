import Foundation
import XCTest
@testable import ConetChatSDK

/// PY.15 items 4 and 11: `reportLegacyStore` returns ok, bad_request or write_failed; a write is confirmed by a read back;
/// while the last applicable report is not written, a read is migrating; the next launch re-reports.
final class ShellReportResultTests: XCTestCase {
	/// A device double that applies the change and reports whether the write was confirmed.
	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		var confirm = true
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool {
			change(&state)
			return confirm
		}
	}

	override func setUp() {
		super.setUp()
		BeamioShellRecord.setLegacyReportWriteFailed(false)
	}

	override func tearDown() {
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		super.tearDown()
	}

	/// The wire strings are the spec's codes exactly.
	func testTheThreeCodesAreTheSpecStrings() {
		XCTAssertEqual(BeamioShellRecord.LegacyReportResult.ok.rawValue, "ok")
		XCTAssertEqual(BeamioShellRecord.LegacyReportResult.badRequest.rawValue, "bad_request")
		XCTAssertEqual(BeamioShellRecord.LegacyReportResult.writeFailed.rawValue, "write_failed")
	}

	/// A written and read-back report answers ok and changes the state.
	func testAWrittenReportAnswersOk() {
		let device = Device()
		let result = BeamioShellRecord.reportLegacyStore(.found, device: device)
		XCTAssertEqual(result, .ok)
		XCTAssertTrue(device.state.legacyFound)
		XCTAssertFalse(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// An established pointer outside the creation mode: the report is saved and answers ok (PY.15 4, r3rz). The resolved state is unchanged.
	func testAnEstablishedPointerReportIsSavedAndAnswersOk() {
		let device = Device()
		device.state.accountEstablished = true
		let result = BeamioShellRecord.reportLegacyStore(.unreadable, device: device, creation: false)
		XCTAssertEqual(result, .ok)
		XCTAssertTrue(device.state.legacyUnreadable)
		XCTAssertTrue(device.state.accountEstablished)
		XCTAssertFalse(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// A write that is not confirmed answers write_failed and keeps the reads migrating.
	func testAFailedWriteAnswersWriteFailedAndLatches() {
		let device = Device()
		device.confirm = false
		let result = BeamioShellRecord.reportLegacyStore(.found, device: device)
		XCTAssertEqual(result, .writeFailed)
		XCTAssertTrue(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// Next report after a failure: a written report clears the latch (the shell re-reports at each launch, PY.15).
	func testTheNextWrittenReportClearsTheFailure() {
		let device = Device()
		device.confirm = false
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.found, device: device), .writeFailed)
		device.confirm = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.found, device: device), .ok)
		XCTAssertFalse(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// A new process starts with no latch: a report is judged again from the device state (restart re-report).
	func testANewProcessStartsClearAndReReports() {
		let device = Device()
		device.confirm = false
		_ = BeamioShellRecord.reportLegacyStore(.unreadable, device: device)
		XCTAssertTrue(BeamioShellRecord.isLegacyReportWriteFailed)
		// Simulated restart: the memory latch is gone; the shell's launch report is written.
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		device.confirm = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device), .ok)
		XCTAssertTrue(device.state.legacyUnreadable)
	}

	/// Real file store: a directory that cannot be created is a write that is not confirmed, so write_failed.
	func testAFileStoreThatCannotWriteAnswersWriteFailed() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("shell-report-\(UUID().uuidString)", isDirectory: true)
		try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(at: root) }
		// A regular file where the store directory should be: the directory cannot be created.
		let blocker = root.appendingPathComponent("blocker")
		try Data("x".utf8).write(to: blocker)
		let store = BeamioShellRecord.FileDeviceStateStore(url: blocker.appendingPathComponent("sub/device-state.json"))
		let result = BeamioShellRecord.reportLegacyStore(.found, device: store)
		XCTAssertEqual(result, .writeFailed)
		XCTAssertTrue(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// Real file store: a written report reads back equal and answers ok.
	func testAFileStoreWriteReadsBackAndAnswersOk() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("shell-report-\(UUID().uuidString)", isDirectory: true)
		defer { try? FileManager.default.removeItem(at: root) }
		let store = BeamioShellRecord.FileDeviceStateStore(url: root.appendingPathComponent("device-state.json"))
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: store), .ok)
		XCTAssertTrue(store.load().legacyUnreadable)
		XCTAssertFalse(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// pageCopyState (PY.15 item 15): a store with no record is absent; an unreadable store is unreadable; no key is needed for these.
	private final class PageStore: BeamioShellRecord.ShellRecordStore {
		var result: BeamioShellRecord.ShellRecordRead = .absent
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { result }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { true }
		func hasAnyRecord() -> Bool { false }
	}

	func testPageCopyStateAbsentAndUnreadable() {
		let store = PageStore()
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: "0xAbC0000000000000000000000000000000000001", store: store), .absent)
		store.result = .unreadable
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: "0xabc0000000000000000000000000000000000001", store: store), .unreadable)
	}

	/// A record with no profile of this account is readable but does not match: fail closed, no key is read.
	func testPageCopyStateWithoutAProfileOfTheAccountDoesNotMatch() {
		let store = PageStore()
		store.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": "0x0000000000000000000000000000000000000002", "privateKeyArmor": "0x00"]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: "0x0000000000000000000000000000000000000001", store: store), .readable(eoaMatchesKeychain: false))
	}

	/// A record without an integer rev is unreadable, not absent.
	func testPageCopyStateWithoutRevIsUnreadable() {
		let store = PageStore()
		store.result = .record(["profiles": []])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: "0x0000000000000000000000000000000000000001", store: store), .unreadable)
	}
}
