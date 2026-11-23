import WebKit
import XCTest
@testable import ConetChatSDK

/// The OpenPGP host must not hang when its WebView content process dies without
/// telling us: every JS call has a watchdog that rebuilds the page and runs the
/// call once more, while normal (also large, also queued) work never trips it.
/// Real WKWebView; run with `swift test` on a Mac or on an iOS simulator.
final class OpenPgpHostWatchdogTests: XCTestCase {
	private typealias Host = BeamioOpenPgpHost
	private var host: Host { .shared }

	private static let keys: [String: [String: String]] = {
		let url = Bundle.module.url(forResource: "chat-daemon-vectors.v1", withExtension: "json")!
		let obj = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
		return obj["keys"] as! [String: [String: String]]
	}()
	private var publicKey: String { Self.keys["userPgp"]!["publicArmored"]! }
	private var privateKey: String { Self.keys["userPgp"]!["privateArmored"]! }

	// MARK: - Helpers (log only sizes and times, never content or keys)

	@discardableResult
	private func timed<T>(
		_ label: String, timeout: TimeInterval = 60,
		_ body: (@escaping (Result<T, Error>) -> Void) -> Void
	) -> (value: T?, ms: Int) {
		let e = expectation(description: label)
		var value: T?
		let t0 = Date()
		var ms = 0
		body { r in
			ms = Int(Date().timeIntervalSince(t0) * 1000)
			if case .success(let v) = r { value = v } else { XCTFail("\(label) failed") }
			e.fulfill()
		}
		wait(for: [e], timeout: timeout)
		return (value, ms)
	}

	private func encrypt(_ text: String, _ label: String) -> (String?, Int) {
		let r: (value: String?, ms: Int) = timed(label) { host.encrypt(plaintext: text, publicKeyArmor: publicKey, completion: $0) }
		return (r.value, r.ms)
	}

	private func killContentProcess(alsoNotify: Bool = false) {
		let e = expectation(description: "kill")
		DispatchQueue.main.async {
			if let wv = self.host.webView {
				_ = wv.perform(Selector(("_killWebContentProcess")))
				if alsoNotify { self.host.webViewWebContentProcessDidTerminate(wv) }
			}
			e.fulfill()
		}
		wait(for: [e], timeout: 5)
	}

	/// Random base64 text (no shortcut from repeated input).
	private func payload(bytes: Int) -> String {
		var raw = [UInt8](repeating: 0, count: bytes * 3 / 4 + 3)
		for i in raw.indices { raw[i] = UInt8.random(in: 0...255) }
		return String(Data(raw).base64EncodedString().prefix(bytes))
	}

	override func tearDown() {
		Host.timeScale = 1
		super.tearDown()
	}

	// MARK: - Pure rule

	func testWatchdogRule() {
		// Returned already.
		XCTAssertEqual(Host.watchdogStep(finished: true, retried: false, window: 4, quietFor: 9, runningFor: 9), .done)
		// Others answered recently: the page is alive, this call is queued; wait the rest.
		XCTAssertEqual(Host.watchdogStep(finished: false, retried: false, window: 4, quietFor: 1, runningFor: 9), .wait(3))
		// Nothing answered for the whole window: rebuild and run again.
		XCTAssertEqual(Host.watchdogStep(finished: false, retried: false, window: 4, quietFor: 4, runningFor: 4), .resetAndRetry)
		// The retry is stuck too: give up instead of looping.
		XCTAssertEqual(Host.watchdogStep(finished: false, retried: true, window: 4, quietFor: 4, runningFor: 4), .fail)
		// The page keeps answering others but never this one: fail at the hard cap.
		XCTAssertEqual(
			Host.watchdogStep(finished: false, retried: false, window: 4, quietFor: 0.1, runningFor: Host.hardCap),
			.fail
		)
	}

	func testLimitsGrowWithSize() {
		XCTAssertEqual(Host.timeout(for: .quick), Host.quickTimeout)
		XCTAssertEqual(Host.timeout(for: .crypto(bytes: 0)), Host.cryptoBaseTimeout)
		// A 2 MB decrypt gets the base plus 2 × seconds-per-MB.
		XCTAssertEqual(Host.timeout(for: .crypto(bytes: 2_000_000)), Host.cryptoBaseTimeout + 2 * Host.cryptoSecondsPerMB, accuracy: 0.001)
	}

	// MARK: - Real WKWebView

	/// Non-normative (不计入一致性结论). The WebView decrypt is removed (r3); the encrypt call that remains is measured, with the same
	/// watchdog. Not a conformance result: nothing here is in the vectors.
	func testMeasuredTimesStayWellUnderTheLimits() throws {
		var worst = 0
		for i in 0..<5 {
			let r = timed("encrypt \(i)") { host.encrypt(plaintext: "measure \(i)", publicKeyArmor: publicKey, completion: $0) }
			XCTAssertNotNil(r.value, "encrypt \(i) completes")
			worst = max(worst, r.ms)
		}
		XCTAssertLessThan(worst, 60_000, "non-normative: each encrypt completes well inside the call timeout")
	}

	/// Non-normative (不计入一致性结论). Many large encrypts queued at once all complete, and the watchdog does not rebuild the page.
	/// The decrypt variant is removed (r3); this keeps the queueing and the watchdog check on the encrypt call that remains.
	func testQueuedLargeEncryptsDoNotTripTheWatchdog() throws {
		let rebuilds = host.watchdogCount
		let big = String(repeating: "x", count: 64 * 1024)
		let all = expectation(description: "queued encrypts")
		all.expectedFulfillmentCount = 6
		var completed = 0
		for i in 0..<6 {
			host.encrypt(plaintext: big + "\(i)", publicKeyArmor: publicKey) { r in
				if case .success = r { completed += 1 }
				all.fulfill()
			}
		}
		wait(for: [all], timeout: 120)
		XCTAssertEqual(completed, 6, "all queued encrypts complete (non-normative)")
		XCTAssertEqual(host.watchdogCount, rebuilds, "the watchdog does not rebuild (non-normative)")
	}

	/// Content process killed with no callback at all: the next call is rescued
	/// by the watchdog (rebuild + one retry) within its window.
	///
	/// The kill (`_killWebContentProcess`, a private selector) is asynchronous and, in a loaded run, can fail to take effect at all: a call answered in about a
	/// millisecond by the still-running old process, and no termination callback within seconds (seen once in a full run: "1 ms", resetCount unchanged for
	/// 5 s). Then the property under test, recovery after the process dies, is not exercised. So the test first proves that a kill took effect (a termination or a
	/// watchdog rescue happened); it tries up to three times, and only when the platform never killed the process is the test skipped, by name and with the
	/// reason. When a kill did take effect, every assertion below holds as before: a real regression of the recovery still fails here.
	func testCallRecoversAfterSilentProcessKill() throws {
		_ = encrypt("warm", "warm")
		for attempt in 1 ... 3 {
			let terminations = host.terminationCount
			let watchdogs = host.watchdogCount
			killContentProcess()
			let (armor, ms) = encrypt("after kill", "after kill")
			print("[watchdog] attempt \(attempt): call after the kill answered in \(ms) ms")
			// the kill took effect when the content process was reported terminated or the watchdog had to rescue the call; wait up to 3 s for either.
			// `resetCount` is not the evidence: it also moves for a boot timeout, a foreground probe, a teardown or a failed call, so a rebuild from
			// another cause could pass for a kill. `terminationCount` moves only for a terminated content process, `watchdogCount` only for a rescue.
			let deadline = Date().addingTimeInterval(3)
			while host.terminationCount <= terminations, host.watchdogCount <= watchdogs, Date() < deadline {
				let tick = expectation(description: "tick")
				DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { tick.fulfill() }
				wait(for: [tick], timeout: 2)
			}
			guard host.terminationCount > terminations || host.watchdogCount > watchdogs else { continue }
			// the premise holds: the call must have recovered, within its window, and the host must be steady afterwards
			XCTAssertTrue(armor?.contains("BEGIN PGP MESSAGE") == true)
			XCTAssertLessThan(Double(ms) / 1000, Host.timeout(for: .crypto(bytes: 100)) + Host.bootTimeout(foreground: false))
			let (_, again) = encrypt("steady", "steady")
			XCTAssertLessThan(Double(again) / 1000, 2)
			return
		}
		throw XCTSkip("the platform did not kill the content process in 3 attempts (no termination and no watchdog rescue): recovery was not exercised")
	}

	/// The evidence of a kill is only a termination: a teardown rebuilds the host (resetCount moves) and leaves terminationCount alone, a reported termination
	/// moves both. This is why the premise of the silent-kill test is not resetCount.
	func testTerminationCountMovesOnlyForATermination() {
		_ = encrypt("warm", "warm")
		var resets = host.resetCount, terminations = host.terminationCount
		// `tearDown` is asynchronous (it hops to the main queue), so the check waits for a second hop behind it
		let torn = expectation(description: "teardown")
		DispatchQueue.main.async {
			self.host.tearDown(reason: "test")
			DispatchQueue.main.async { torn.fulfill() }
		}
		wait(for: [torn], timeout: 5)
		XCTAssertEqual(host.resetCount, resets + 1, "a teardown is a rebuild")
		XCTAssertEqual(host.terminationCount, terminations, "and not a termination")
		_ = encrypt("warm again", "warm again")
		resets = host.resetCount; terminations = host.terminationCount
		let notified = expectation(description: "terminated")
		DispatchQueue.main.async {
			if let wv = self.host.webView { self.host.webViewWebContentProcessDidTerminate(wv) }
			notified.fulfill()
		}
		wait(for: [notified], timeout: 5)
		XCTAssertEqual(host.terminationCount, terminations + 1, "a reported termination moves it")
		XCTAssertEqual(host.resetCount, resets + 1, "and rebuilds the host")
		_ = encrypt("steady", "steady")
	}

	/// Calls already running when the process dies all finish on the rebuilt page.
	func testCallsInFlightMoveToTheRebuiltPage() {
		_ = encrypt("warm", "warm")
		let n = 5
		let all = expectation(description: "in flight")
		all.expectedFulfillmentCount = n
		var ok = 0
		let e = expectation(description: "kill")
		DispatchQueue.main.async {
			for i in 0..<n {
				self.host.encrypt(plaintext: "in flight \(i)", publicKeyArmor: self.publicKey) { r in
					if case .success(let a) = r, a.contains("BEGIN PGP MESSAGE") { ok += 1 }
					all.fulfill()
				}
			}
			// Kill right after they were sent, before any answers.
			DispatchQueue.main.async {
				_ = self.host.webView?.perform(Selector(("_killWebContentProcess")))
				e.fulfill()
			}
		}
		wait(for: [e, all], timeout: 60)
		XCTAssertEqual(ok, n)
	}

	/// The system terminate callback rebuilds at once: no watchdog wait.
	func testTerminateCallbackRebuildsAtOnce() {
		_ = encrypt("warm", "warm")
		let resets = host.resetCount
		killContentProcess(alsoNotify: true)
		XCTAssertEqual(host.resetCount, resets + 1)
		let (armor, ms) = encrypt("after callback", "after callback")
		print("[watchdog] encrypt after terminate callback in \(ms) ms")
		XCTAssertTrue(armor?.contains("BEGIN PGP MESSAGE") == true)
		XCTAssertLessThan(Double(ms) / 1000, Host.timeout(for: .crypto(bytes: 100)))
	}

	// MARK: - Immediate errors from a dead page (real iPhone, RC3b V10)

	func testDeadPageErrorsAreRebuiltButScriptErrorsAreNot() {
		func wk(_ code: WKError.Code, _ message: String? = nil) -> NSError {
			NSError(domain: WKError.errorDomain, code: code.rawValue, userInfo: message.map { ["WKJavaScriptExceptionMessage": $0] } ?? [:])
		}
		// Dead or unusable page: rebuild and retry once.
		XCTAssertTrue(Host.isHostGone(wk(.webContentProcessTerminated)))
		XCTAssertTrue(Host.isHostGone(wk(.webViewInvalidated)))
		XCTAssertTrue(Host.isHostGone(wk(.unknown)))
		XCTAssertTrue(Host.isHostGone(wk(.javaScriptExceptionOccurred)))  // no message: the page died mid-call
		XCTAssertTrue(Host.isHostGone(wk(.javaScriptExceptionOccurred, "ReferenceError: Can't find variable: openpgp")))
		XCTAssertTrue(Host.isHostGone(NSError(domain: "SomeOtherDomain", code: 1)))
		// What a real iPhone returns for a call on a killed page (R14): every script
		// here returns a string, so a live page never gives it.
		XCTAssertTrue(Host.isHostGone(wk(.javaScriptResultTypeIsUnsupported)))
		// The script itself failed: keep the error, no rebuild.
		XCTAssertFalse(Host.isHostGone(wk(.javaScriptExceptionOccurred, "Error: Misformed armored text")))
	}

	/// A script error (bad armor) fails once, quickly, without rebuilding the page.
	/// Kept skipped. Reason: the PGP decrypt script error path is removed (r3); there is no decrypt script left to fail. Non-normative
	/// (不计入一致性结论): it is not a conformance result.
	func testScriptErrorFailsWithoutRebuild() throws {
		try XCTSkipIf(true, "\(BeamioPGPNative.pendingCode): the PGP decrypt script error path is removed (r3); non-normative, 不计入一致性结论")
	}

	// MARK: - Back from the background (RC3c R12: first dial after resume waited 8–10 s)

	func testForegroundCheckRule() {
		// Never started: nothing to check.
		XCTAssertEqual(Host.foregroundStep(bootstrapped: false, ready: false, bootAge: 99), .nothing)
		// Ready page: probe it (a dead one is rebuilt within the probe limit).
		XCTAssertEqual(Host.foregroundStep(bootstrapped: true, ready: true, bootAge: 99), .probe)
		// A boot that started before (often in the background) and never got ready: rebuild now.
		XCTAssertEqual(Host.foregroundStep(bootstrapped: true, ready: false, bootAge: Host.stalledBootAge), .rebuildStalledBoot)
		// A boot that just started: let it finish.
		XCTAssertEqual(Host.foregroundStep(bootstrapped: true, ready: false, bootAge: 0.2), .nothing)
	}

	func testBootLimitIsShortInTheForeground() {
		XCTAssertLessThanOrEqual(Host.bootTimeout(foreground: true), 3)
		XCTAssertGreaterThan(Host.bootTimeout(foreground: false), Host.bootTimeout(foreground: true))
		XCTAssertLessThanOrEqual(Host.foregroundProbeTimeout, 1)
	}
}
