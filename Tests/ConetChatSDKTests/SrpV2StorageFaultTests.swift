#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// shell-record-passcode-not-provided.v2 (byte copy, pinned): SRP-03 (read, storage fault), SRP-04 (write, storage fault), SRP-05 (read, unknown state) over the
/// real record boundary. SRP-04 (write fault = envelope write_failed) is must-pass since option A; the read fault shapes are unchanged. Synthetic data only.
final class SrpV2StorageFaultTests: XCTestCase {
	private final class FaultyStore: BeamioShellRecord.ShellRecordStore {
		var failRead = true
		var writeCalls = 0
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { failRead ? .unreadable : .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { writeCalls += 1; return false }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let account = PgpMigrationTestSupport.eoa

	override func setUp() {
		super.setUp()
		BeamioShellRecord.resetNotReadyStreakForTests()
		BeamioKeychainFailureNote.setForTests(nil)
	}

	override func tearDown() {
		BeamioShellRecord.resetNotReadyStreakForTests()
		BeamioKeychainFailureNote.setForTests(nil)
		BeamioNativeKeySnapshot.pinUnreadableForTests(false)
		super.tearDown()
	}

	private func vectorCase(_ prefix: String) throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: "shell-record-passcode-not-provided.v2")
		XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), "0833f6ab0d3f2ea7ca1ec2676e993587310c521671187923e7a692121307227b")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return try XCTUnwrap(cases.first { ($0["id"] as? String ?? "").hasPrefix(prefix) }, prefix)
	}

	private func environment(store: BeamioShellRecord.ShellRecordStore, gate: BeamioConetChatModule.NativeGate) -> BeamioShellRecord.Environment {
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		return BeamioShellRecord.Environment(
			account: { self.account }, store: store, device: device, originAllowed: true,
			migrating: { _ in false }, firstRun: { _ in .confirmedAbsent },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { gate }
		)
	}

	private func ack(_ type: String, _ env: BeamioShellRecord.Environment, extra: [String: Any] = [:]) -> [String: Any] {
		var body: [String: Any] = ["type": type, "reqId": 7]
		for (k, v) in extra { body[k] = v }
		return BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(body, env: env))
	}

	/// SRP-03: a record that cannot be read is result.code error, sub record_unreadable; the data is kept (nothing is written)
	func testSRP03ReadStorageFaultIsRecordUnreadable() throws {
		let want = try XCTUnwrap(try vectorCase("SRP-03")["expect"] as? [String: Any])
		let store = FaultyStore()
		let got = ack("shellRecordRead", environment(store: store, gate: .g2))
		print("[SRP-03 actual] \(got)")
		XCTAssertEqual(got["ok"] as? Bool, want["ok"] as? Bool, "SRP-03 ok")
		let wantResult = try XCTUnwrap(want["result"] as? [String: Any])
		let result = got["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["code"] as? String, wantResult["code"] as? String, "SRP-03 code")
		XCTAssertEqual(result["sub"] as? String, wantResult["sub"] as? String, "SRP-03 sub")
		XCTAssertEqual(store.writeCalls, 0, "the data is kept")
	}

	/// SRP-04: a write that the store refuses is write_failed (a true write fault), and it is not the passcode word
	func testSRP04WriteStorageFaultIsWriteFailed() throws {
		let want = try XCTUnwrap(try vectorCase("SRP-04")["expect"] as? [String: Any])
		let store = FaultyStore()
		store.failRead = false
		let got = ack("shellRecordWrite", environment(store: store, gate: .g2), extra: ["record": ["rev": 0, "schemaVersion": 1]])
		print("[SRP-04 actual] \(got)")
		let text = String(describing: got)
		XCTAssertFalse(text.contains("passcode_not_provided"), "SRP-04: not the passcode word")
		// SRP-04 is must-pass since the project owner chose option A: the write fault is the envelope {ok:false, error:"write_failed"}, never ok:true with result.code.
		XCTAssertEqual(got["ok"] as? Bool, want["ok"] as? Bool, "SRP-04 ok")
		XCTAssertEqual(got["error"] as? String, want["error"] as? String, "SRP-04 error")
		XCTAssertNil(got["result"], "no result: the envelope is the failure")
		XCTAssertEqual(store.writeCalls, 1, "the write was attempted once and nothing else was stored")
	}

	/// A write that meets the device-level storage lock (the project lead ruling): the envelope {ok:false, error:write_failed, reason:internal_state}; nothing is
	/// written; the storage lock is judged before a rev conflict; a read keeps not_ready storage_locked.
	func testAWriteMeetingTheStorageLockIsTheEnvelopeWriteFailedAndNothingIsWritten() {
		let store = FaultyStore()
		store.failRead = false
		var env = environment(store: store, gate: .g2)
		env.storageLocked = { true }
		let write = ack("shellRecordWrite", env, extra: ["record": ["rev": 7, "schemaVersion": 1]])   // a rev that would conflict: the lock still comes first
		XCTAssertEqual(write["ok"] as? Bool, false)
		XCTAssertEqual(write["error"] as? String, "write_failed")
		XCTAssertEqual(write["reason"] as? String, "internal_state")
		XCTAssertNil(write["result"])
		XCTAssertEqual(store.writeCalls, 0, "nothing is written")
		let read = ack("shellRecordRead", env)
		XCTAssertEqual(read["ok"] as? Bool, true, "a read keeps its shape")
		XCTAssertEqual((read["result"] as? [String: Any])?["notReadyReason"] as? String, "storage_locked")
	}

	/// SRP-05: an unknown state is not_ready with the reason unreadable (no new `unknown` code), the data is kept
	func testSRP05UnknownStateIsNotReadyUnreadable() throws {
		let want = try XCTUnwrap(try vectorCase("SRP-05")["expect"] as? [String: Any])
		BeamioKeychainFailureNote.setForTests(BeamioKeychainFailureNote.category(of: -25308))   // a transient cause (device locked)
		BeamioNativeKeySnapshot.pinUnreadableForTests(true)
		let store = FaultyStore()
		let got = ack("shellRecordRead", environment(store: store, gate: .g1))
		print("[SRP-05 actual] \(got)")
		XCTAssertEqual(got["ok"] as? Bool, want["ok"] as? Bool, "SRP-05 ok")
		let wantResult = try XCTUnwrap(want["result"] as? [String: Any])
		let result = got["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["code"] as? String, wantResult["code"] as? String, "SRP-05 code")
		XCTAssertEqual(result["notReadyReason"] as? String, wantResult["notReadyReason"] as? String, "SRP-05 reason")
		XCTAssertEqual(result["retryable"] as? Bool, wantResult["retryable"] as? Bool, "SRP-05 retryable")
		XCTAssertNotEqual(result["code"] as? String, "unknown", "no new unknown code")
		XCTAssertEqual(store.writeCalls, 0)
	}
}
#endif
