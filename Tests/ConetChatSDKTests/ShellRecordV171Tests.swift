#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// interface spec v169 to v171: the snapshot-unknown not_ready, the request size as a bad_request, the persistence for reads only,
/// and the data protection of the roster file after a replace. Synthetic values only.
final class ShellRecordV171Tests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { records[account].map { .record($0) } ?? .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { records[account] = record; return true }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let eoa = "0x5e5e000000000000000000000000000000000003"

	override func setUp() { super.setUp(); BeamioShellRecord.resetNotReadyStreakForTests() }
	override func tearDown() { BeamioShellRecord.resetNotReadyStreakForTests(); super.tearDown() }

	private func environment(snapshotKnown: Bool = true, origin: Bool = true) -> BeamioShellRecord.Environment {
		var env = BeamioShellRecord.Environment(
			account: { self.eoa }, store: Store(), device: Device(), originAllowed: origin,
			migrating: { _ in false }, firstRun: { _ in .confirmedAbsent }, locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { .g2 }
		)
		env.snapshotKnown = { snapshotKnown }
		return env
	}

	private func ack(_ body: [String: Any], _ env: BeamioShellRecord.Environment, raw: Int? = nil) -> [String: Any] {
		BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(body, env: env, rawByteCount: raw))
	}

	private func result(_ a: [String: Any]) -> [String: Any] { a["result"] as? [String: Any] ?? [:] }

	func testASnapshotUnknownReadAndWriteAnswerG1UninitializedRetryable() {
		let env = environment(snapshotKnown: false)
		for body in [["type": "shellRecordRead", "reqId": "a"], ["type": "shellRecordWrite", "reqId": "b", "record": ["rev": 1]]] as [[String: Any]] {
			let a = ack(body, env)
			XCTAssertEqual(a["ok"] as? Bool, true)
			XCTAssertEqual(result(a)["code"] as? String, "not_ready")
			XCTAssertEqual(result(a)["notReadyReason"] as? String, "g1_uninitialized")
			XCTAssertEqual(result(a)["retryable"] as? Bool, true)
		}
	}

	func testTheReadCountsAndTheWriteIsNeverConverted() {
		let env = environment(snapshotKnown: false)
		// ten reads of the same reason, then the eleventh is persistent and keeps retryable true
		for n in 1 ... 10 { XCTAssertEqual(result(ack(["type": "shellRecordRead", "reqId": n], env))["code"] as? String, "not_ready", "read \(n)") }
		let eleventh = ack(["type": "shellRecordRead", "reqId": 11], env)
		XCTAssertEqual(result(eleventh)["code"] as? String, "error")
		XCTAssertEqual(result(eleventh)["sub"] as? String, "not_ready_persistent")
		XCTAssertEqual(result(eleventh)["notReadyReason"] as? String, "g1_uninitialized")
		XCTAssertEqual(result(eleventh)["retryable"] as? Bool, true)
		// a write is not counted and never becomes persistent, however many there are
		BeamioShellRecord.resetNotReadyStreakForTests()
		for n in 1 ... 15 {
			let w = ack(["type": "shellRecordWrite", "reqId": n, "record": ["rev": 1]], env)
			XCTAssertEqual(result(w)["code"] as? String, "not_ready", "write \(n)")
		}
	}

	/// v172 section 192.2: the write order is origin, size, reqId, allow-list, PGP key, state gate (not_ready), rev. Under a state gate, content is judged first.
	func testAWritesContentIsJudgedBeforeTheStateGate() {
		var env = environment()
		env.storageLocked = { true }
		let armor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----"
		let key = ack(["type": "shellRecordWrite", "reqId": "k", "record": ["rev": 1, "note": armor]], env)
		XCTAssertEqual(key["ok"] as? Bool, false)
		XCTAssertEqual(key["error"] as? String, "pgp_private_in_payload")
		let extra = ack(["type": "shellRecordWrite", "reqId": "x", "record": ["rev": 1], "surplus": 1], env)
		// an unknown top-level field is a content-level bad_request: ok:true, result.code bad_request, result.names = the field (UF-02), judged before the state gate
		XCTAssertEqual(extra["ok"] as? Bool, true)
		XCTAssertEqual((extra["result"] as? [String: Any])?["code"] as? String, "bad_request")
		XCTAssertEqual((extra["result"] as? [String: Any])?["names"] as? [String], ["surplus"])
		let clean = ack(["type": "shellRecordWrite", "reqId": "c", "record": ["rev": 1, "schemaVersion": 1]], env)
		// the content is judged first; a clean write that meets the device-level storage lock is the envelope write_failed (the project lead ruling)
		XCTAssertEqual(clean["ok"] as? Bool, false)
		XCTAssertEqual(clean["error"] as? String, "write_failed")
		XCTAssertEqual(clean["reason"] as? String, "internal_state")
		XCTAssertNil(clean["result"])
	}

	func testARequestOverTheLimitIsABadRequestInTheEnvelopeAfterTheOrigin() {
		let env = environment()
		let over = BeamioShellRecord.requestLimit + 1
		for type in ["shellRecordRead", "shellRecordWrite"] {
			let a = ack(["type": type, "reqId": "big"], env, raw: over)
			XCTAssertEqual(a["ok"] as? Bool, false, type)
			XCTAssertEqual(a["error"] as? String, "bad_request", type)
			XCTAssertEqual(Set(a.keys), ["type", "reqId", "ok", "error"])
		}
		// the origin comes first
		let refused = ack(["type": "shellRecordWrite", "reqId": "big"], environment(origin: false), raw: over)
		XCTAssertEqual(refused["error"] as? String, "origin_refused")
		// the size comes before the reqId: an oversize request with no reqId is still a bad_request (null reqId in the envelope)
		let noId = ack(["type": "shellRecordRead"], env, raw: over)
		XCTAssertEqual(noId["error"] as? String, "bad_request")
		// at the limit it is accepted
		let atLimit = ack(["type": "shellRecordRead", "reqId": "ok"], env, raw: BeamioShellRecord.requestLimit)
		XCTAssertNotEqual(atLimit["error"] as? String, "bad_request")
		XCTAssertEqual(BeamioShellRecord.requestLimit, 2 * 1024 * 1024)
	}

	func testTheRosterFileKeepsItsProtectionAndBackupExclusionAfterAReplace() throws {
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("roster-prot-\(UUID().uuidString)")
		try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(at: dir) }
		let url = dir.appendingPathComponent("si_roster_v1.json")
		XCTAssertTrue(BeamioInboxFile.replace(url, with: Data("[]".utf8)))
		// the second write goes through replaceItemAt: the target's attributes are set again
		XCTAssertTrue(BeamioInboxFile.replace(url, with: Data("[1]".utf8)))
		let excluded = try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup
		XCTAssertEqual(excluded, true, "excluded from backup after a replace")
		let protection = try FileManager.default.attributesOfItem(atPath: url.path)[.protectionKey] as? FileProtectionType
		if let protection {
			XCTAssertEqual(protection, .completeUntilFirstUserAuthentication)
		} else {
			// the macOS and simulator file systems do not report a data-protection class; the device check is the diagnostic below
			print("[roster-protection] protectionKey is not reported on this platform; read it back on a device: attributesOfItem(atPath: si_roster_v1.json)[.protectionKey]")
		}
	}
}
#endif
