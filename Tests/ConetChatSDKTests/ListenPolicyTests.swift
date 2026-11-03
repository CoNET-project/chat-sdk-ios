import XCTest
@testable import ConetChatSDK

/// Mailbox listen: background pause and retry backoff (same cases as Android's ListenPolicyTest).
final class ListenPolicyTests: XCTestCase {
	func testRetryBacksOffExponentiallyUpTo30s() {
		let mid = 0.5 // no jitter
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 1, jitter: mid), 2, accuracy: 0.001)
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 2, jitter: mid), 4, accuracy: 0.001)
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 3, jitter: mid), 8, accuracy: 0.001)
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 4, jitter: mid), 16, accuracy: 0.001)
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 5, jitter: mid), 30, accuracy: 0.001)
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 50, jitter: mid), 30, accuracy: 0.001)
		XCTAssertEqual(BeamioListenPolicy.retryDelay(failures: 0, jitter: mid), 2, accuracy: 0.001)
	}

	func testJitterStaysWithin20PercentAndUnderTheCap() {
		for n in 1...10 {
			let lo = BeamioListenPolicy.retryDelay(failures: n, jitter: 0)
			let hi = BeamioListenPolicy.retryDelay(failures: n, jitter: 0.999)
			let mid = BeamioListenPolicy.retryDelay(failures: n, jitter: 0.5)
			XCTAssertTrue(lo <= mid && mid <= hi)
			XCTAssertGreaterThanOrEqual(lo, mid * 0.8 - 0.001)
			XCTAssertLessThanOrEqual(hi, BeamioListenPolicy.retryMax)
		}
		XCTAssertGreaterThan(BeamioListenPolicy.retryDelay(failures: 4, jitter: 0), 12)
	}

	func testPauseAppliesOnlyInTheBackgroundWithoutACall() {
		XCTAssertTrue(BeamioListenPolicy.pauseApplies(lifecycleKnown: true, inForeground: false, callInProgress: false))
		XCTAssertFalse(BeamioListenPolicy.pauseApplies(lifecycleKnown: true, inForeground: false, callInProgress: true))
		XCTAssertFalse(BeamioListenPolicy.pauseApplies(lifecycleKnown: true, inForeground: true, callInProgress: false))
		XCTAssertTrue(BeamioListenPolicy.pauseApplies(lifecycleKnown: false, inForeground: true, callInProgress: false))
	}

	func testPageResumeDoesNotReopenInTheBackground() {
		XCTAssertFalse(BeamioListenPolicy.pageResumeApplies(lifecycleKnown: true, inForeground: false, callInProgress: false))
		XCTAssertTrue(BeamioListenPolicy.pageResumeApplies(lifecycleKnown: true, inForeground: false, callInProgress: true))
		XCTAssertTrue(BeamioListenPolicy.pageResumeApplies(lifecycleKnown: true, inForeground: true, callInProgress: false))
		XCTAssertTrue(BeamioListenPolicy.pageResumeApplies(lifecycleKnown: false, inForeground: false, callInProgress: false))
	}
}
