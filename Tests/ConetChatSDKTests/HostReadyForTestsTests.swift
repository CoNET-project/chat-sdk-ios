#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The test seam that makes a host-dependent suite deterministic: it waits for the page, with the boot limit scaled, and says plainly when the host cannot boot.
final class HostReadyForTestsTests: XCTestCase {
	override func tearDown() {
		BeamioOpenPgpHost.testForceNotReady = false
		BeamioOpenPgpHost.testBootTimeoutScale = 1
		super.tearDown()
	}

	func testTheHostBecomesReadyAndVerifyMessageThenAnswers() async throws {
		let readiness = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 90)
		XCTAssertTrue(readiness.ready, "host not ready: \(readiness.reason)")
		XCTAssertEqual(readiness.reason, "")
		XCTAssertGreaterThanOrEqual(BeamioOpenPgpHost.testBootTimeoutScale, 4)
		// a signature that recovers to a known address: the host answers, it does not return nil
		let text = "ready test"
		let key = [UInt8](repeating: 0x11, count: 32)
		let signature = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: key, message: text))
		let expected = try XCTUnwrap(BeamioNativeEthSigner.address(privateKey: key)).lowercased()
		let recovered: String? = await withCheckedContinuation { continuation in
			BeamioOpenPgpHost.shared.verifyMessage(text: text, signature: signature) { continuation.resume(returning: try? $0.get()) }
		}
		XCTAssertEqual(recovered?.lowercased(), expected)
	}

	func testAHostThatCannotBootIsReportedAsNotReadyAndNotAsAVerification() async {
		BeamioOpenPgpHost.testForceNotReady = true
		let started = Date()
		let readiness = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 1)
		XCTAssertFalse(readiness.ready)
		XCTAssertFalse(readiness.reason.isEmpty, "it says why")
		XCTAssertLessThan(Date().timeIntervalSince(started), 5, "it gives up at its own timeout")
	}

	/// Independent review of f12c1f2, point 1: on the verify path a boot timeout was reported as -3 ("not ready"), which `isHostUnavailable` does not
	/// count, so no retry happened. The failure of the boot now reaches the caller as it is: -1, which is unavailable. A separate test host is used (the
	/// forced boot failures apply to it only), and a second verify on a fresh host then answers.
	func testABootTimeoutOnTheVerifyPathIsMinusOneAndUnavailable() throws {
		let key = [UInt8](repeating: 0x33, count: 32)
		let signature = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: key, message: "boot timeout"))
		// both boots (the automatic boot retry and then the failure) time out at once
		BeamioOpenPgpHost.testBootFailuresRemaining = 2
		let host = BeamioOpenPgpHost.makeForTests()
		let done = expectation(description: "verify on a page that cannot boot")
		var outcome: Result<String, Error>?
		DispatchQueue.main.async {
			host.verifyMessage(text: "boot timeout", signature: signature) { outcome = $0; done.fulfill() }
		}
		wait(for: [done], timeout: 60)
		BeamioOpenPgpHost.testBootFailuresRemaining = 0
		guard case .failure(let error)? = outcome else { return XCTFail("a boot that times out cannot verify") }
		XCTAssertEqual((error as NSError).code, -1, "the boot timeout keeps its code on the verify path")
		XCTAssertTrue(BeamioOpenPgpHost.isHostUnavailable(error), "so the caller retries once")
		// the retry on a page that boots answers
		let healthy = BeamioOpenPgpHost.makeForTests()
		let again = expectation(description: "the retry")
		var recovered: String?
		DispatchQueue.main.async {
			healthy.verifyMessage(text: "boot timeout", signature: signature) { recovered = try? $0.get(); again.fulfill() }
		}
		wait(for: [again], timeout: 60)
		XCTAssertEqual(recovered?.lowercased(), BeamioNativeEthSigner.address(privateKey: key)?.lowercased())
	}

	/// The shell's hypothesis (BeamioOpenPgpHost.shared is one WKWebView shared by every suite of the process): a teardown that another suite causes (a logout, an
	/// account switch or a lock reaches `tearDown(reason:)`) fails the verification that is waiting or running on the page, with a failure, never with a
	/// recovered address. A caller that treats `.failure` as a refusal therefore refuses; nothing here can pass.
	func testATeardownDuringAVerifyFailsItAndNeverPassesIt() async throws {
		let readiness = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 90)
		try XCTSkipUnless(readiness.ready, "host not ready: \(readiness.reason)")
		let text = "teardown race"
		let key = [UInt8](repeating: 0x22, count: 32)
		let signature = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: key, message: text))
		var failures = 0, answers = 0
		for _ in 0 ..< 20 {
			let outcome: Result<String, Error> = await withCheckedContinuation { continuation in
				DispatchQueue.main.async {
					BeamioOpenPgpHost.shared.verifyMessage(text: text, signature: signature) { continuation.resume(returning: $0) }
					// the teardown of another suite lands right behind the call
					BeamioOpenPgpHost.shared.tearDown(reason: "another suite")
				}
			}
			switch outcome {
			case .failure: failures += 1
			case .success(let recovered):
				answers += 1
				XCTAssertEqual(recovered.lowercased(), BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), "an answer is the right address, never another")
			}
		}
		print("[host-race] verify under teardown: \(failures) failures, \(answers) answers of 20")
		XCTAssertEqual(failures + answers, 20, "every call completes exactly once")
		XCTAssertGreaterThan(failures, 0, "a teardown right behind the call fails it")
		_ = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 90)
	}
}
#endif

#if BEAMIO_TEST_HOOKS
/// The host failure class, the diagnostic line and the prewarm (project owner's requirement): a retry only for a boot timeout (-1) or a stuck page (-7).
final class HostFailureClassTests: XCTestCase {
	private func error(_ domain: String, _ code: Int) -> NSError { NSError(domain: domain, code: code, userInfo: [NSLocalizedDescriptionKey: "x"]) }

	func testOnlyABootTimeoutOrAStuckPageIsUnavailable() {
		XCTAssertTrue(BeamioOpenPgpHost.isHostUnavailable(error("BeamioOpenPgp", -1)), "boot timeout")
		XCTAssertTrue(BeamioOpenPgpHost.isHostUnavailable(error("BeamioOpenPgp", -7)), "stuck")
		XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(error("BeamioOpenPgp", -8)), "teardown: the account is changing")
		for code in [-2, -3, -4, -5, -6, 0, 1, -9, 7] { XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(error("BeamioOpenPgp", code)), "code \(code)") }
		XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(error("WKErrorDomain", -1)), "another domain with the same code")
		XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(error("WKErrorDomain", -7)))
		XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(error("", -1)))
		struct Plain: Error {}
		XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(Plain()), "a Swift error with no domain of ours")
	}

	func testTheRealFailuresOfTheHostHaveThoseCodes() async throws {
		// a teardown right behind a verify: the failure is -8, which is not unavailable (verified end to end)
		let readiness = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 90)
		try XCTSkipUnless(readiness.ready, "host not ready: \(readiness.reason)")
		let key = [UInt8](repeating: 0x33, count: 32)
		let signature = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: key, message: "class"))
		var seen: [Int] = []
		for _ in 0 ..< 10 {
			let outcome: Result<String, Error> = await withCheckedContinuation { continuation in
				DispatchQueue.main.async {
					BeamioOpenPgpHost.shared.verifyMessage(text: "class", signature: signature) { continuation.resume(returning: $0) }
					BeamioOpenPgpHost.shared.tearDown(reason: "class test")
				}
			}
			if case .failure(let failure) = outcome {
				XCTAssertFalse(BeamioOpenPgpHost.isHostUnavailable(failure), "a teardown is not a retryable failure")
				seen.append((failure as NSError).code)
			}
		}
		XCTAssertTrue(seen.contains(-8), "the failures include the teardown code")
		_ = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 90)
	}

	func testTheDiagnosticLineCarriesOnlyCodeTimeAndRetry() {
		let line = BeamioOpenPgpHost.verifyFailureDiagnostic(error("BeamioOpenPgp", -1), elapsedMs: 8123, retried: true)
		XCTAssertEqual(line, "domain=BeamioOpenPgp code=-1 ms=8123 retried=true")
		// the error text is not in it
		XCTAssertFalse(line.contains("x"), line)
	}

	func testPrewarmBootsThePageWhenEnabledAndIsInertOtherwise() async throws {
		BeamioOpenPgpHost.testPrewarmEnabled = true
		defer { BeamioOpenPgpHost.testPrewarmEnabled = false }
		let before = BeamioOpenPgpHost.shared.resetCount
		let torn = expectation(description: "torn")
		DispatchQueue.main.async {
			BeamioOpenPgpHost.shared.tearDown(reason: "prewarm test")
			DispatchQueue.main.async { torn.fulfill() }
		}
		await fulfillment(of: [torn], timeout: 5)
		XCTAssertGreaterThan(BeamioOpenPgpHost.shared.resetCount, before)
		await MainActor.run { BeamioOpenPgpHost.shared.prewarm() }
		let ready = await BeamioOpenPgpHost.shared.awaitHostReadyForTests(timeoutSeconds: 90)
		XCTAssertTrue(ready.ready, "host not ready: \(ready.reason)")
	}
}
#endif
