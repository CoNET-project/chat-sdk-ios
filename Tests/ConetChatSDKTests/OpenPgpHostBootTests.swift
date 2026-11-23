#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// the OpenPGP host's boot. The first boot of the process gets 8 s; a failed boot is retried once automatically; a launch warm-up
/// starts the page without blocking. Forced boot failures stand in for a slow or failed page start. Synthetic calls only; no key material.
final class OpenPgpHostBootTests: XCTestCase {
	override func tearDown() {
		BeamioOpenPgpHost.testBootFailuresRemaining = 0
		super.tearDown()
	}

	/// The timeouts: the first boot is 8 s; the later boots keep the current 3 s (foreground) and 8 s (background).
	func testTheFirstBootTimeoutIsEightSecondsAndTheLaterOnesAreUnchanged() {
		XCTAssertEqual(BeamioOpenPgpHost.firstBootTimeout, 8)
		XCTAssertEqual(BeamioOpenPgpHost.bootTimeout(foreground: true), 3)
		XCTAssertEqual(BeamioOpenPgpHost.bootTimeout(foreground: false), 8)
	}

	/// A boot that fails once is retried automatically, and the waiting call succeeds on the retry.
	func testAFailedBootIsRetriedOnceAndTheCallSucceeds() {
		BeamioOpenPgpHost.testBootFailuresRemaining = 1
		let host = BeamioOpenPgpHost.makeForTests()
		let done = expectation(description: "ensureReady after one retry")
		var result: Bool?
		host.ensureReady { ok in result = ok; done.fulfill() }
		wait(for: [done], timeout: 30)
		XCTAssertEqual(result, true, "the retry boots the page; the call is answered ok")
	}

	/// Two failed boots (the boot and its one retry): the waiting call is answered with an error (false), not left waiting.
	func testTwoFailedBootsAnswerTheWaitingCallWithAnError() {
		BeamioOpenPgpHost.testBootFailuresRemaining = 2
		let host = BeamioOpenPgpHost.makeForTests()
		let done = expectation(description: "ensureReady after the retry fails")
		var result: Bool?
		host.ensureReady { ok in result = ok; done.fulfill() }
		wait(for: [done], timeout: 30)
		XCTAssertEqual(result, false, "after the single retry fails, the call gets the error")
	}

	/// The launch warm-up returns at once: it does not wait for the page.
	func testTheLaunchWarmUpDoesNotBlock() {
		let started = Date()
		BeamioOpenPgpHost.warmUpAtLaunch()
		XCTAssertLessThan(Date().timeIntervalSince(started), 0.5, "the warm-up returns without waiting for the boot")
	}
}
#endif
