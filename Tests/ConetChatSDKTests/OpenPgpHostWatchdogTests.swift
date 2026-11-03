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

	/// Measured times stay far below each limit (the limits come from these numbers).
	func testMeasuredTimesStayWellUnderTheLimits() {
		_ = encrypt("warm", "warm")
		let key = String(repeating: "11", count: 32)  // the host adds 0x
		let sign: (value: String?, ms: Int) = timed("sign") { host.signEip191(privateKeyHex: key, message: "watchdog", completion: $0) }
		let (small, encSmallMs) = encrypt(payload(bytes: 2_000), "encrypt 2 KB")
		let (big, encBigMs) = encrypt(payload(bytes: 1_000_000), "encrypt 1 MB")
		let decSmall: (value: String?, ms: Int) = timed("decrypt 2 KB") { host.decrypt(armor: small ?? "", privateKeyArmor: privateKey, completion: $0) }
		let decBig: (value: String?, ms: Int) = timed("decrypt 1 MB") { host.decrypt(armor: big ?? "", privateKeyArmor: privateKey, completion: $0) }
		print("[watchdog] sign=\(sign.ms)ms enc2KB=\(encSmallMs)ms enc1MB=\(encBigMs)ms dec2KB=\(decSmall.ms)ms dec1MB=\(decBig.ms)ms armor1MB=\((big ?? "").utf8.count)B")
		XCTAssertEqual(decBig.value?.utf8.count, 1_000_000)
		// At least 10x headroom on this machine for each kind.
		XCTAssertLessThan(Double(sign.ms) / 1000 * 10, Host.timeout(for: .quick))
		XCTAssertLessThan(Double(encBigMs) / 1000 * 10, Host.timeout(for: .crypto(bytes: 1_000_000)))
		XCTAssertLessThan(Double(decBig.ms) / 1000 * 10, Host.timeout(for: .crypto(bytes: (big ?? "").utf8.count)))
	}

	/// Many large decrypts queued at once: each waits for the others, longer than
	/// its own window, yet the watchdog sees the page answering and never rebuilds.
	func testQueuedLargeDecryptsDoNotTripTheWatchdog() {
		let (big, _) = encrypt(payload(bytes: 1_000_000), "encrypt 1 MB")
		let armor = big ?? ""
		let resets = host.resetCount
		// Each call's limit (~0.1 s here) is far shorter than the whole queue takes.
		Host.timeScale = 0.02
		let n = 40
		let all = expectation(description: "all")
		all.expectedFulfillmentCount = n
		var ok = 0
		let t0 = Date()
		for _ in 0..<n {
			host.decrypt(armor: armor, privateKeyArmor: privateKey) { r in
				if case .success(let s) = r, s.utf8.count == 1_000_000 { ok += 1 }
				all.fulfill()
			}
		}
		wait(for: [all], timeout: 300)
		let totalMs = Int(Date().timeIntervalSince(t0) * 1000)
		print("[watchdog] \(n) queued 1 MB decrypts in \(totalMs) ms; each limit \(Int(Host.timeout(for: .crypto(bytes: armor.utf8.count)) * 1000)) ms")
		XCTAssertGreaterThan(Double(totalMs) / 1000, Host.timeout(for: .crypto(bytes: armor.utf8.count)) * 2, "the queue must outlast a single limit")
		XCTAssertEqual(ok, n)
		XCTAssertEqual(host.resetCount, resets, "no rebuild while the page keeps answering")
	}

	/// Content process killed with no callback at all: the next call is rescued
	/// by the watchdog (rebuild + one retry) within its window.
	func testCallRecoversAfterSilentProcessKill() {
		_ = encrypt("warm", "warm")
		let resets = host.resetCount
		let watchdogs = host.watchdogCount
		killContentProcess()
		let (armor, ms) = encrypt("after kill", "after kill")
		print("[watchdog] recovered after silent kill in \(ms) ms")
		XCTAssertTrue(armor?.contains("BEGIN PGP MESSAGE") == true)
		XCTAssertGreaterThan(host.resetCount, resets)
		XCTAssertGreaterThanOrEqual(host.watchdogCount, watchdogs)
		XCTAssertLessThan(Double(ms) / 1000, Host.timeout(for: .crypto(bytes: 100)) + Host.bootTimeout(foreground: false))
		// Steady afterwards.
		let (_, again) = encrypt("steady", "steady")
		XCTAssertLessThan(Double(again) / 1000, 2)
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
	func testScriptErrorFailsWithoutRebuild() {
		_ = encrypt("warm", "warm")
		let resets = host.resetCount
		let e = expectation(description: "bad armor")
		let t0 = Date()
		host.decrypt(armor: "-----BEGIN PGP MESSAGE-----\nnot armor\n-----END PGP MESSAGE-----", privateKeyArmor: privateKey) { r in
			if case .success = r { XCTFail("bad armor decrypted") }
			e.fulfill()
		}
		wait(for: [e], timeout: 30)
		XCTAssertEqual(host.resetCount, resets)
		XCTAssertLessThan(Date().timeIntervalSince(t0), 2)
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
