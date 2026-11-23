import WebKit
import XCTest
@testable import ConetChatSDK

/// the OpenPGP host page
/// - takes no navigation but its first load (a link, a redirect, a location change is cancelled);
/// - has a Content-Security-Policy that lets it connect, load, frame or start a worker with nothing, and runs only the nonce scripts;
/// - opens no window by itself;
/// - is torn down with the lock and with the session, and a call waiting on the page fails instead of re-running.
/// Real WKWebView, synthetic data only (the public key of the chat-daemon vectors). Nothing is sent to any real host: the probes
/// point at `example.invalid`, which the CSP must stop before any lookup.
final class OpenPgpHostHardeningTests: XCTestCase {
	private typealias Host = BeamioOpenPgpHost

	private var host: Host { .shared }

	private static let keys: [String: [String: String]] = {
		let url = Bundle.module.url(forResource: "chat-daemon-vectors.v1", withExtension: "json")!
		let obj = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
		return obj["keys"] as! [String: [String: String]]
	}()
	private var publicKey: String { Self.keys["userPgp"]!["publicArmored"]! }

	// MARK: - Helpers (log only counts and states, never content or keys)

	/// Runs an expression on the page; returns the page's answer, or the error.
	private func run(_ expression: String, _ label: String, timeout: TimeInterval = 15) -> Result<String, Error>? {
		let e = expectation(description: label)
		var out: Result<String, Error>?
		host.runJs(expression, work: .quick) { result in
			out = result
			e.fulfill()
		}
		wait(for: [e], timeout: timeout)
		return out
	}

	/// Lets the main queue run what it has queued (the teardown is asynchronous).
	private func flushMainQueue() {
		let e = expectation(description: "main queue")
		DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { e.fulfill() }
		wait(for: [e], timeout: 3)
	}

	private func bootHost(_ label: String) {
		let e = expectation(description: label)
		var ok = false
		host.ensureReady { ready in
			ok = ready
			e.fulfill()
		}
		wait(for: [e], timeout: 15)
		XCTAssertTrue(ok, label)
	}

	// MARK: - Pure rules (no WebKit)

	func testOnlyTheFirstMainFrameLoadIsAllowed() {
		var policy = OpenPgpNavigationPolicy()
		// Nothing armed: the page takes no navigation.
		XCTAssertFalse(policy.decide(isMainFrame: true))
		XCTAssertEqual(policy.cancelledCount, 1)
		policy.armInitialLoad()
		// A subframe never takes the initial load; the load keeps waiting.
		XCTAssertFalse(policy.decide(isMainFrame: false))
		XCTAssertTrue(policy.initialLoadPending)
		// The first main-frame load is allowed, once.
		XCTAssertTrue(policy.decide(isMainFrame: true))
		XCTAssertFalse(policy.initialLoadPending)
		// Every later navigation is cancelled: a link, a redirect, a second main-frame load, a subframe.
		XCTAssertFalse(policy.decide(isMainFrame: true))
		XCTAssertFalse(policy.decide(isMainFrame: false))
		XCTAssertEqual(policy.cancelledCount, 4)
	}

	func testTheContentSecurityPolicyAllowsNothingButTheNonceScripts() {
		let csp = Host.contentSecurityPolicy(nonce: "0123abcd")
		let parts = csp.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
		XCTAssertEqual(parts.first { $0.hasPrefix("default-src ") }, "default-src 'none'")
		XCTAssertEqual(parts.first { $0.hasPrefix("script-src ") }, "script-src 'nonce-0123abcd'")
		XCTAssertEqual(parts.first { $0.hasPrefix("connect-src ") }, "connect-src 'none'")
		XCTAssertEqual(parts.first { $0.hasPrefix("worker-src ") }, "worker-src 'none'")
		XCTAssertEqual(parts.first { $0.hasPrefix("frame-src ") }, "frame-src 'none'")
		// No inline or eval relaxation, no origin or wildcard source.
		XCTAssertFalse(csp.contains("unsafe"))
		XCTAssertFalse(csp.contains("'self'"))
		XCTAssertFalse(csp.contains("*"))
	}

	func testEachPageGetsItsOwnHexNonce() {
		let a = Host.makeNonce()
		let b = Host.makeNonce()
		XCTAssertEqual(a.count, 32)
		XCTAssertTrue(a.allSatisfy { $0.isHexDigit })
		XCTAssertNotEqual(a, b)
	}

	// MARK: - Real page

	/// The page boots under the CSP (no eval, no unsafe-inline needed) and the OpenPGP library still works.
	func testThePageBootsUnderTheCSPAndEncryptsAMessage() {
		bootHost("boot under CSP")
		let e = expectation(description: "encrypt under CSP")
		var armor: String?
		host.encrypt(plaintext: "csp probe", publicKeyArmor: publicKey) { result in
			if case .success(let s) = result { armor = s }
			e.fulfill()
		}
		wait(for: [e], timeout: 20)
		XCTAssertTrue(armor?.contains("BEGIN PGP MESSAGE") ?? false, "the library must run under the CSP")
	}

	/// Item 1: a location change from the page is cancelled and the page stays where it is.
	func testALocationChangeFromThePageIsCancelled() {
		bootHost("boot for navigation")
		let before = host.blockedNavigationCount
		let result = run("""
		(async () => {
		  window.location.href = 'https://example.invalid/navigate';
		  await new Promise(r => setTimeout(r, 500));
		  return 'done';
		})()
		""", "location change")
		XCTAssertEqual(try? result?.get(), "done")
		XCTAssertGreaterThan(host.blockedNavigationCount, before, "the navigation must reach the policy and be cancelled")
		XCTAssertNotEqual(host.webView?.url?.host, "example.invalid", "the page must not have moved to the target")
	}

	/// Item 2: an outgoing request is stopped by the CSP (connect-src), before any lookup of the host.
	func testAnOutgoingRequestIsStoppedByTheCSP() {
		bootHost("boot for request")
		let result = run("""
		(async () => {
		  const seen = [];
		  document.addEventListener('securitypolicyviolation', e => seen.push(e.violatedDirective));
		  let outcome = 'reached';
		  try { await fetch('https://example.invalid/probe'); } catch (e) { outcome = 'blocked'; }
		  await new Promise(r => setTimeout(r, 300));
		  return outcome + ':' + seen.join(',');
		})()
		""", "fetch under CSP")
		let answer = (try? result?.get()) ?? "no answer"
		XCTAssertTrue(answer.hasPrefix("blocked:"), "the fetch must fail: \(answer)")
		XCTAssertTrue(answer.contains("connect-src"), "the refusal must be a CSP violation of connect-src: \(answer)")
	}

	/// Item 3: the page cannot open a window by itself.
	func testThePageCannotOpenAWindowByItself() {
		bootHost("boot for window")
		let before = host.blockedNavigationCount
		let result = run("""
		(async () => {
		  const w = window.open('https://example.invalid/window', '_blank');
		  await new Promise(r => setTimeout(r, 300));
		  return String(w === null);
		})()
		""", "window.open")
		XCTAssertEqual(try? result?.get(), "true", "window.open must give nothing back")
		XCTAssertNotEqual(host.webView?.url?.host, "example.invalid")
		XCTAssertGreaterThanOrEqual(host.blockedNavigationCount, before)
	}

	/// H1: the page's diagnostics reach the log only as a fixed vocabulary. A message that carries a secret text is never logged.
	func testDiagnosticsCarryOnlyAFixedVocabulary() {
		let secret = "SECRET-PLAINTEXT-7f3a"
		// An error message is never logged, even when it holds text (a parse error can echo a slice of its input).
		XCTAssertEqual(Host.diagnosticDetail(action: "error", body: ["message": secret]), "other")
		XCTAssertEqual(Host.diagnosticDetail(action: "error", body: ["name": "SyntaxError"]), "SyntaxError")
		XCTAssertEqual(Host.diagnosticDetail(action: "error", body: ["name": secret]), "other")
		XCTAssertEqual(Host.diagnosticDetail(action: "error", body: ["name": "libs_missing"]), "libs_missing")
		// A CSP directive is logged only when it is a plain directive name.
		XCTAssertEqual(Host.diagnosticDetail(action: "csp", body: ["directive": "connect-src"]), "connect-src")
		XCTAssertEqual(Host.diagnosticDetail(action: "csp", body: ["directive": "connect-src \(secret)"]), "other")
		XCTAssertEqual(Host.diagnosticDetail(action: "csp", body: ["directive": String(repeating: "a", count: 33)]), "other")
		XCTAssertEqual(Host.diagnosticDetail(action: "csp", body: [:]), "other")
		// Any other action is not logged as text.
		XCTAssertEqual(Host.diagnosticDetail(action: "ready", body: ["message": secret]), "other")
	}

	/// H4: the host's website data store is non-persistent (nothing is kept on disk between runs).
	func testTheHostKeepsNoWebsiteDataOnDisk() throws {
		guard #available(iOS 17.0, macOS 14.0, *) else {
			throw XCTSkip("WKWebsiteDataStore.isPersistent needs iOS 17 or macOS 14")
		}
		bootHost("boot for data store")
		XCTAssertEqual(host.webView?.configuration.websiteDataStore.isPersistent, false)
	}

	// MARK: - Teardown (item 5)

	/// A call waiting on the page fails at once when the host is torn down; it is not re-run on a new page. The next call boots a
	/// fresh page and works.
	func testATeardownFailsTheCallsOnThePageAndTheNextCallBootsAFreshPage() {
		bootHost("boot before teardown")
		let resetsBefore = host.resetCount

		// Never answers: stands for a call stuck on the page.
		let stuck = expectation(description: "stuck call fails")
		var stuckResult: Result<String, Error>?
		host.runJs("new Promise(() => {})", work: .quick) { result in
			stuckResult = result
			stuck.fulfill()
		}
		host.tearDown(reason: "test")
		wait(for: [stuck], timeout: 3)
		guard case .failure(let error)? = stuckResult else {
			return XCTFail("the stuck call must fail after the teardown")
		}
		XCTAssertEqual((error as NSError).localizedDescription, "openpgp host torn down")
		flushMainQueue()
		XCTAssertGreaterThan(host.resetCount, resetsBefore)
		XCTAssertNil(host.webView, "the WebView is released by the teardown")

		// A fresh page after the teardown still encrypts.
		let e = expectation(description: "encrypt after teardown")
		var armor: String?
		host.encrypt(plaintext: "after teardown", publicKeyArmor: publicKey) { result in
			if case .success(let s) = result { armor = s }
			e.fulfill()
		}
		wait(for: [e], timeout: 20)
		XCTAssertTrue(armor?.contains("BEGIN PGP MESSAGE") ?? false)
	}

	/// A logout or an account switch tears the page down (asynchronously; the lock is not held by it). A plain passcode lock does not: a call that rings
	/// while the account is locked still needs its offer opened.
	func testALogoutTearsTheHostDownWithoutHoldingTheLock() {
		bootHost("boot before logout")
		var lines: [String] = []
		let previous = Host.diagnostics
		Host.diagnostics = { lines.append($0) }
		defer { Host.diagnostics = previous }

		BeamioPasscodeSession().lockAll(reason: .logout)
		flushMainQueue()

		XCTAssertTrue(lines.contains { $0.contains("torn down (lock)") }, "the logout must reach the host: \(lines)")
		XCTAssertNil(host.webView)
	}

	func testAPlainPasscodeLockLeavesTheHostUp() {
		bootHost("boot before lock")
		var lines: [String] = []
		let previous = Host.diagnostics
		Host.diagnostics = { lines.append($0) }
		defer { Host.diagnostics = previous }

		BeamioPasscodeSession().lockAll()
		flushMainQueue()

		XCTAssertFalse(lines.contains { $0.contains("torn down") }, "a lock does not tear the host down: \(lines)")
		XCTAssertNotNil(host.webView)
	}
}
