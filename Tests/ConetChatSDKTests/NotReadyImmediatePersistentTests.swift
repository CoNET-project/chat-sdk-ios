import XCTest
@testable import ConetChatSDK

/// only an unreadable reason with retryable false (the cause entitlement or other) is answered as not_ready_persistent at once. Every
/// other reason, retryable or not, waits for the limit (the 11th answer).
final class NotReadyImmediatePersistentTests: XCTestCase {
	override func setUp() { BeamioShellRecord.resetNotReadyStreakForTests() }
	override func tearDown() { BeamioShellRecord.resetNotReadyStreakForTests() }

	private func apply(_ reason: String, retryable: Bool, cause: String? = nil) -> [String: Any] {
		var answer = BeamioShellRecord.notReadyAnswer(reason: reason, retryable: retryable, reqId: 5)
		if let cause { answer["unreadableCause"] = cause }
		return BeamioShellRecord.applyPersistenceLimit(answer)
	}

	func testUnreadableNonTransientCausesAreFinalOnTheFirstAnswer() {
		for cause in [BeamioKeychainFailureNote.entitlement, BeamioKeychainFailureNote.other] {
			BeamioShellRecord.resetNotReadyStreakForTests()
			let a = apply(BeamioShellRecord.notReadyUnreadable, retryable: BeamioKeychainFailureNote.retryable(cause), cause: cause)
			XCTAssertEqual(a["code"] as? String, "error")
			XCTAssertEqual(a["sub"] as? String, "not_ready_persistent")
			XCTAssertEqual(a["notReadyReason"] as? String, "unreadable")
			XCTAssertEqual(a["unreadableCause"] as? String, cause)
			XCTAssertEqual(a["retryable"] as? Bool, false)
		}
	}

	func testStorageLockedAndAmbiguousStillWaitForTheEleventhAnswer() {
		for reason in [BeamioShellRecord.notReadyStorageLocked, BeamioShellRecord.notReadyAmbiguousAccounts] {
			BeamioShellRecord.resetNotReadyStreakForTests()
			for _ in 0..<BeamioShellRecord.notReadyPersistenceLimit {
				let a = apply(reason, retryable: false)
				XCTAssertEqual(a["code"] as? String, "not_ready")
				XCTAssertEqual(a["notReadyReason"] as? String, reason)
			}
			let last = apply(reason, retryable: false)
			XCTAssertEqual(last["sub"] as? String, "not_ready_persistent")
			XCTAssertEqual(last["retryable"] as? Bool, false)
		}
	}

	func testTransientUnreadableAndG1WaitForTheLimit() {
		let transient = BeamioKeychainFailureNote.deviceLocked
		for _ in 0..<BeamioShellRecord.notReadyPersistenceLimit {
			XCTAssertEqual(apply(BeamioShellRecord.notReadyUnreadable, retryable: true, cause: transient)["code"] as? String, "not_ready")
		}
		let last = apply(BeamioShellRecord.notReadyUnreadable, retryable: true, cause: transient)
		XCTAssertEqual(last["sub"] as? String, "not_ready_persistent")
		XCTAssertEqual(last["retryable"] as? Bool, true)
		BeamioShellRecord.resetNotReadyStreakForTests()
		for _ in 0..<BeamioShellRecord.notReadyPersistenceLimit {
			XCTAssertEqual(apply(BeamioShellRecord.notReadyG1Uninitialized, retryable: true)["code"] as? String, "not_ready")
		}
		XCTAssertEqual(apply(BeamioShellRecord.notReadyG1Uninitialized, retryable: true)["sub"] as? String, "not_ready_persistent")
	}

	func testAnswerShapeFollowsSpec259() {
		let a = apply(BeamioShellRecord.notReadyUnreadable, retryable: false, cause: BeamioKeychainFailureNote.entitlement)
		XCTAssertEqual(Set(a.keys), ["code", "sub", "notReadyReason", "retryable", "reqId", "unreadableCause"])
		let envelope = BeamioShellRecord.ackEnvelope(for: a)
		XCTAssertEqual(envelope["ok"] as? Bool, true)
		XCTAssertEqual((envelope["result"] as? [String: Any])?["sub"] as? String, "not_ready_persistent")
	}
}
