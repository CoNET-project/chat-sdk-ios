#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The not_ready answers of the record commands (interface spec v159 section 179): every one carries its reason and
/// `retryable`; the same reason ten times in a row in one process becomes `error` / `not_ready_persistent`, still with the reason.
final class ShellRecordNotReadyReasonTests: XCTestCase {
	override func setUp() {
		super.setUp()
		BeamioShellRecord.resetNotReadyStreakForTests()
	}

	override func tearDown() {
		BeamioShellRecord.resetNotReadyStreakForTests()
		super.tearDown()
	}

	func testTheReasonsAndWhetherARetryCanHelp() {
		let table: [(String, Bool)] = [("storage_locked", false), ("g1_uninitialized", true), ("ambiguous_accounts", false), ("unreadable", true)]
		XCTAssertEqual(BeamioShellRecord.notReadyStorageLocked, "storage_locked")
		XCTAssertEqual(BeamioShellRecord.notReadyG1Uninitialized, "g1_uninitialized")
		XCTAssertEqual(BeamioShellRecord.notReadyAmbiguousAccounts, "ambiguous_accounts")
		for (reason, retryable) in table {
			let answer = BeamioShellRecord.notReadyAnswer(reason: reason, retryable: retryable, reqId: 7)
			XCTAssertEqual(answer["code"] as? String, "not_ready")
			XCTAssertEqual(answer["notReadyReason"] as? String, reason)
			XCTAssertEqual(answer["retryable"] as? Bool, retryable)
		}
	}

	func testNotReadyIsAResultAndOnlyTheRejectionsAreEnvelopeFailures() {
		// v165 section 185: not_ready (read and write alike) is ok:true with the answer in result
		let ok = BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: 12))
		XCTAssertEqual(ok["ok"] as? Bool, true)
		let result = ok["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "g1_uninitialized")
		XCTAssertEqual(result?["retryable"] as? Bool, true)
		XCTAssertNil(result?["reqId"])
		// conflict keeps currentRev inside result
		let conflict = BeamioShellRecord.ackEnvelope(for: ["code": "conflict", "currentRev": 3, "reqId": 15])
		XCTAssertEqual(conflict["ok"] as? Bool, true)
		XCTAssertEqual((conflict["result"] as? [String: Any])?["currentRev"] as? Int, 3)
		// AK-22: a bad_request that names content paths is a result with the names
		let content = BeamioShellRecord.ackEnvelope(for: ["code": "bad_request", "names": ["profiles[*].foo"], "contentLevel": true, "reqId": 14])
		XCTAssertEqual(content["ok"] as? Bool, true)
		XCTAssertEqual((content["result"] as? [String: Any])?["code"] as? String, "bad_request")
		XCTAssertEqual((content["result"] as? [String: Any])?["names"] as? [String], ["profiles[*].foo"])
		XCTAssertNil((content["result"] as? [String: Any])?["contentLevel"])
		// the rejections are envelope-level and name only their code
		for code in ["origin_refused", "bad_request", "pgp_private_in_payload"] {
			// a bad_request is envelope-level unless its category is tagged content-level: reqId, record and rev answers carry names internally that are never echoed
			let failure = BeamioShellRecord.ackEnvelope(for: ["code": code, "names": ["profiles[0].pgpPrivateKeyArmored"], "reqId": 14])
			XCTAssertEqual(failure["ok"] as? Bool, false, code)
			XCTAssertEqual(failure["error"] as? String, code)
			XCTAssertEqual(Set(failure.keys), ["type", "reqId", "ok", "error"], "\(code): nothing of the payload is echoed")
		}
	}

	func testTheSameReasonTenTimesInARowThenPersistent() {
		for n in 1 ... 10 {
			let out = BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: n))
			XCTAssertEqual(out["code"] as? String, "not_ready", "answer \(n)")
		}
		let eleventh = BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: 11))
		XCTAssertEqual(eleventh["code"] as? String, "error")
		XCTAssertEqual(eleventh["sub"] as? String, "not_ready_persistent")
		XCTAssertEqual(eleventh["notReadyReason"] as? String, "g1_uninitialized", "still with the reason")
		XCTAssertEqual(eleventh["retryable"] as? Bool, true, "the persistent answer keeps the retryable of its reason (SRR2-05)")
		XCTAssertEqual(eleventh["reqId"] as? Int, 11)
		// and it stays persistent while the reason goes on
		XCTAssertEqual(BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: 12))["sub"] as? String, "not_ready_persistent")
		// the envelope of the persistent answer is a result the page reads (ok:true, code error), not a not_ready failure
		let envelope = BeamioShellRecord.ackEnvelope(for: eleventh)
		XCTAssertEqual(envelope["ok"] as? Bool, true)
		XCTAssertEqual((envelope["result"] as? [String: Any])?["sub"] as? String, "not_ready_persistent")
	}

	func testADifferentReasonOrAnotherAnswerEndsTheStreak() {
		for n in 1 ... 9 { _ = BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: n)) }
		// another reason: a new streak of one
		XCTAssertEqual(BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "unreadable", retryable: true, reqId: 20))["code"] as? String, "not_ready")
		// back to the first reason: its streak starts over, so nine more do not reach the limit
		for n in 30 ... 38 { XCTAssertEqual(BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: n))["code"] as? String, "not_ready") }
		// an ordinary answer ends the streak
		_ = BeamioShellRecord.applyPersistenceLimit(["code": "ok", "reqId": 40])
		for n in 50 ... 59 { XCTAssertEqual(BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: n))["code"] as? String, "not_ready", "answer \(n)") }
		// a not_ready with no reason (snapshot unknown) is not counted and ends the streak
		_ = BeamioShellRecord.applyPersistenceLimit(["code": "not_ready", "reqId": 60])
		XCTAssertEqual(BeamioShellRecord.applyPersistenceLimit(BeamioShellRecord.notReadyAnswer(reason: "g1_uninitialized", retryable: true, reqId: 61))["code"] as? String, "not_ready")
	}
}
#endif
