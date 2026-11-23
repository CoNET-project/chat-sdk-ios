import Foundation
import WebKit
#if canImport(UIKit)
import UIKit
#endif

/// The host page's navigation rule. The page is loaded once, from its own string, and that first main-frame load is the
/// only navigation allowed. Links, redirects, subframes and new windows are cancelled. Pure, so the rule is unit-tested without WebKit.
struct OpenPgpNavigationPolicy: Equatable {
	/// Set right before the string load; the first main-frame decision clears it.
	private(set) var initialLoadPending = false
	/// Navigations cancelled so far (a count only, never a URL).
	private(set) var cancelledCount = 0

	mutating func armInitialLoad() {
		initialLoadPending = true
	}

	/// true: allow the navigation. false: cancel it.
	mutating func decide(isMainFrame: Bool) -> Bool {
		if initialLoadPending && isMainFrame {
			initialLoadPending = false
			return true
		}
		cancelledCount += 1
		return false
	}
}

/// Ephemeral WKWebView that runs bundled `openpgp.min.js` + `ethers.umd.min.js`
/// for killed-app voice offer fetch / decrypt / EIP-191 verify.
public final class BeamioOpenPgpHost: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
	public static let shared = BeamioOpenPgpHost()

	/// Optional sink for the host's recovery events (boot, ready, timeouts,
	/// rebuilds, probes): times and states only, never content or keys. A shell
	/// can route it to its own QA log; NSLog always gets them too.
	public static var diagnostics: ((String) -> Void)?

	private static func diag(_ line: String) {
		NSLog("[BeamioOpenPgp] %@", line)
		diagnostics?(line)
	}

	/// Internal read for tests (killing the content process).
	private(set) var webView: WKWebView?
	private var ready = false
	private var pending: [(Result<String, Error>) -> Void] = []
	private var bootstrapped = false
	/// True once a boot has been ready in this process: the first boot gets the longer timeout.
	private var hasBeenReady = false
	/// Automatic retries of a failed boot since the last ready (one retry, then the error).
	private var bootRetries = 0
	/// The page's navigation rule. Reset with each new page.
	private var navigationPolicy = OpenPgpNavigationPolicy()
	/// Navigations the rule has cancelled (diagnostics and tests).
	var blockedNavigationCount: Int { navigationPolicy.cancelledCount }

	private override init() {
		super.init()
		#if canImport(UIKit)
		// Back from the background: the page may have died or stalled while the
		// app was suspended. Check it now, not on the first call's timeout
		// (RC3c R12: the first dial after resume waited 8–10 s).
		NotificationCenter.default.addObserver(
			forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main
		) { [weak self] _ in
			self?.checkAfterForeground()
		}
		#endif
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only: the host reports not ready at once, as a host whose page cannot boot does (openpgp_not_ready).
	static var testForceNotReady = false

	/// Test build only: multiplies the boot timeouts. A suite that runs in many parallel simulator clones, each booting its own WKWebView, can take far longer
	/// than the 8 s of the first boot; the product limits stay as they are.
	static var testBootTimeoutScale: Double = 1

	/// Test build only: the answer of `awaitHostReadyForTests`.
	struct HostReadiness: Equatable {
		let ready: Bool
		/// Why it is not ready (empty when it is): the host did not boot within the limit, or it was forced not ready.
		let reason: String
	}

	/// Test build only: waits until the page is ready (booting it if need be), for at most `timeoutSeconds`. A suite that depends on the host calls this first,
	/// so that a host that cannot boot is reported as "host not ready", with the reason, and not as a failed verification (a nil from `verifyMessage`). Boot
	/// retries and the longer boot limit are in effect while it waits.
	func awaitHostReadyForTests(timeoutSeconds: TimeInterval = 90) async -> HostReadiness {
		Self.testBootTimeoutScale = max(Self.testBootTimeoutScale, 4)
		if Self.testForceNotReady { return HostReadiness(ready: false, reason: "forced not ready (testForceNotReady)") }
		let deadline = Date().addingTimeInterval(timeoutSeconds)
		var attempts = 0
		while Date() < deadline {
			attempts += 1
			let ok: Bool = await withCheckedContinuation { continuation in self.ensureReady { continuation.resume(returning: $0) } }
			if ok { return HostReadiness(ready: true, reason: "") }
			try? await Task.sleep(nanoseconds: 200_000_000)
		}
		return HostReadiness(ready: false, reason: "the page did not signal ready within \(Int(timeoutSeconds)) s (\(attempts) boot attempts)")
	}
	#endif

	// MARK: - Failure class and prewarm (inbound offer verification; project owner's requirement)

	/// Whether `error`, the failure of a host call, says that the host was unavailable and a second try can help: the page did not boot in time (-1) or was stuck
	/// (-7). A teardown (-8: a logout, an account switch, a lock: the account is changing) is not, and neither is any other error (a signature that does not
	/// verify, a script error, a malformed input). A caller retries only when this is true, once, and only within its own time limits.
	public static func isHostUnavailable(_ error: Error) -> Bool {
		let ns = error as NSError
		return ns.domain == "BeamioOpenPgp" && (ns.code == -1 || ns.code == -7)
	}

	/// The diagnostic line of a failed verification, for a caller that retries: the error domain and code, the time it took, and whether this was the retry. No
	/// text, signature, address or call id is in it.
	public static func verifyFailureDiagnostic(_ error: Error, elapsedMs: Int, retried: Bool) -> String {
		let ns = error as NSError
		return "domain=\(ns.domain) code=\(ns.code) ms=\(elapsedMs) retried=\(retried)"
	}

	/// Boots the page now, if it is not up, so that the first call after the app starts or wakes does not wait for a cold boot: call it at the first moment of a
	/// start and of a VoIP wake. It changes no rule of any check. It does nothing in a test build unless `testPrewarmEnabled` is set (the unit tests of other
	/// areas must not boot a WebView as a side effect of a command).
	public func prewarm() {
		#if BEAMIO_TEST_HOOKS
		guard Self.testPrewarmEnabled else { return }
		#endif
		ensureReady { _ in }
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only: lets `prewarm` boot the page.
	static var testPrewarmEnabled = false
	#endif

	public func ensureReady(completion: @escaping (Bool) -> Void) {
		ensureReadyResult { completion((try? $0.get()) != nil) }
	}

	/// Like `ensureReady`, but a failure carries its error: a boot timeout (-1), a teardown (-8), missing scripts (-2). A caller that must tell an
	/// unavailable host (retry can help) from an account change (it cannot) needs the code, so a runJs call returns it instead of a bare "not ready".
	/// A host that is not ready for no recorded reason (the test switch) answers -3.
	func ensureReadyResult(completion: @escaping (Result<Void, Error>) -> Void) {
		// WKWebView / evaluateJavaScript are main-thread-only. Callers (e.g.
		// history keccak on a utility queue) must never complete onto a bg thread
		// and then call into WebKit — that triggers an intentional EXC_BREAKPOINT.
		let notReady = Result<Void, Error>.failure(NSError(domain: "BeamioOpenPgp", code: -3, userInfo: [
			NSLocalizedDescriptionKey: "openpgp host not ready",
		]))
		let finish: (Result<Void, Error>) -> Void = { result in
			if Thread.isMainThread {
				completion(result)
			} else {
				DispatchQueue.main.async { completion(result) }
			}
		}
		#if BEAMIO_TEST_HOOKS
		if Self.testForceNotReady {
			finish(notReady)
			return
		}
		#endif
		if ready {
			finish(.success(()))
			return
		}
		DispatchQueue.main.async {
			if self.ready {
				completion(.success(()))
				return
			}
			self.pending.append { result in
				switch result {
				case .success: completion(.success(()))
				case .failure(let error): completion(self.ready ? .success(()) : .failure(error))
				}
			}
			// Starts the page (and its one boot timer) unless it is already booting.
			self.bootstrapIfNeeded()
		}
	}

	/// Main thread. One timer per boot: the page never signalled ready.
	private func armBootTimer() {
		let generation = self.generation
		var limit = hasBeenReady ? Self.bootTimeout(foreground: Self.appIsActive()) : Self.firstBootTimeout
		#if BEAMIO_TEST_HOOKS
		limit *= Self.testBootTimeoutScale
		#endif
		#if BEAMIO_TEST_HOOKS
		let forcedFailure = self.isTestHost && Self.testBootFailuresRemaining > 0
		if forcedFailure { Self.testBootFailuresRemaining -= 1 }
		let fireAfter: TimeInterval = forcedFailure ? 0.01 : limit
		#else
		let fireAfter: TimeInterval = limit
		#endif
		// The host is a process-wide singleton: a strong capture leaks nothing.
		DispatchQueue.main.asyncAfter(deadline: .now() + fireAfter) {
			guard !self.ready, generation == self.generation else { return }
			Self.diag(String(format: "boot timeout after %ld ms app=%@", Int(limit * 1000), Self.appStateLabel()))
			// one automatic retry of a failed boot. The waiting calls stay queued; only the second failure answers them.
			if self.bootRetries < 1 {
				self.bootRetries += 1
				Self.diag("boot retry after a timeout (one automatic retry)")
				self.resetHost(reason: "boot timeout, retry")
				return
			}
			self.bootRetries = 0
			self.flushPending(.failure(NSError(domain: "BeamioOpenPgp", code: -1, userInfo: [
				NSLocalizedDescriptionKey: "openpgp host timeout",
			])))
			// The page never loaded (its process died while booting): without a
			// reset `bootstrapped` stayed true and every later call failed here.
			self.resetHost(reason: "boot timeout")
		}
	}

	// MARK: - Foreground check

	/// Probe answer limit after the app comes back (a live page answers in ms).
	static let foregroundProbeTimeout: TimeInterval = 1
	/// A boot still waiting for ready this long at foreground counts as stalled.
	static let stalledBootAge: TimeInterval = 1

	/// What to do with the page when the app becomes active. Pure (unit-tested).
	enum ForegroundStep: Equatable {
		case nothing
		/// Ready page: run a tiny script; no answer in time → rebuild.
		case probe
		/// A boot started earlier (often in the background) never signalled ready: rebuild now.
		case rebuildStalledBoot
	}

	static func foregroundStep(bootstrapped: Bool, ready: Bool, bootAge: TimeInterval) -> ForegroundStep {
		if !bootstrapped { return .nothing }
		if ready { return .probe }
		return bootAge >= stalledBootAge ? .rebuildStalledBoot : .nothing
	}

	private func checkAfterForeground() {
		let age = bootStartedAt.map { Date().timeIntervalSince($0) } ?? 0
		switch Self.foregroundStep(bootstrapped: bootstrapped, ready: ready, bootAge: age) {
		case .nothing:
			return
		case .rebuildStalledBoot:
			resetHost(reason: "boot stalled across background (\(Int(age * 1000)) ms)")
		case .probe:
			guard let wv = webView else { return }
			let generation = self.generation
			var answered = false
			let started = Date()
			wv.callAsyncJavaScript("return 1;", arguments: [:], in: nil, in: .page) { outcome in
				answered = true
				guard generation == self.generation else { return }
				switch outcome {
				case .success:
					Self.diag(String(format: "foreground probe ok ms=%ld", Int(Date().timeIntervalSince(started) * 1000)))
				case .failure(let error):
					let ns = error as NSError
					if Self.isHostGone(ns) {
						self.resetHost(reason: "foreground probe failed: domain=\(ns.domain) code=\(ns.code)")
					}
				}
			}
			DispatchQueue.main.asyncAfter(deadline: .now() + Self.foregroundProbeTimeout) {
				guard !answered, generation == self.generation else { return }
				self.resetHost(reason: "foreground probe got no answer")
			}
		}
	}

	static func appIsActive() -> Bool {
		#if canImport(UIKit)
		return Thread.isMainThread ? UIApplication.shared.applicationState == .active : true
		#else
		return true
		#endif
	}

	static func appStateLabel() -> String {
		#if canImport(UIKit)
		guard Thread.isMainThread else { return "?" }
		switch UIApplication.shared.applicationState {
		case .active: return "active"
		case .inactive: return "inactive"
		case .background: return "background"
		@unknown default: return "?"
		}
		#else
		return "-"
		#endif
	}

	/// Encrypt plaintext UTF-8 JSON to an armored OpenPGP message for `publicKeyArmor`.
	public func encrypt(plaintext: String, publicKeyArmor: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  const pk = await openpgp.readKey({ armoredKey: \(jsString(publicKeyArmor)) });
			  const message = await openpgp.createMessage({ text: \(jsString(plaintext)) });
			  return await openpgp.encrypt({ message, encryptionKeys: pk, format: 'armored' });
			})()
			""",
			work: .crypto(bytes: plaintext.utf8.count + publicKeyArmor.utf8.count),
			completion: completion
		)
	}


	/// EIP-191 `verifyMessage(text, signature)` → recovered address (checksummed).
	public func verifyMessage(text: String, signature: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  const addr = ethers.verifyMessage(\(jsString(text)), \(jsString(signature)));
			  return addr;
			})()
			""",
			work: .quick,
			completion: completion
		)
	}

	// S-4: no signing key is ever passed into this WebView. Signing stays in native code (BeamioNativeWallet /
	// BeamioNativeEthSigner); this host only handles public keys, ciphertext and verification.

	/// 1B: PWA already signed `message`; encrypt `{message,signMessage}` base64 → route PGP.
	public func encryptSignedRouteCommand(
		message: String,
		signMessage: String,
		routePublicArmor: String,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		runJs(
			"""
			(async () => {
			  const message = \(jsString(message));
			  const signMessage = \(jsString(signMessage));
			  const literal = btoa(unescape(encodeURIComponent(JSON.stringify({ message, signMessage }))));
			  const publicKey = await openpgp.readKey({ armoredKey: \(jsString(routePublicArmor)) });
			  const pgpMsg = await openpgp.createMessage({ text: literal });
			  const encrypted = await openpgp.encrypt({
			    message: pgpMsg,
			    encryptionKeys: publicKey,
			    config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
			  });
			  return typeof encrypted === 'string' ? encrypted : String(encrypted);
			})()
			""",
			work: .crypto(bytes: message.utf8.count + signMessage.utf8.count),
			completion: completion
		)
	}

	/// Encrypt opaque base64/utf8 literal to a public key (business send / mailbox work).
	func encryptLiteral(text: String, publicKeyArmor: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  const publicKey = await openpgp.readKey({ armoredKey: \(jsString(publicKeyArmor)) });
			  const pgpMsg = await openpgp.createMessage({ text: \(jsString(text)) });
			  const encrypted = await openpgp.encrypt({
			    message: pgpMsg,
			    encryptionKeys: publicKey,
			    config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
			  });
			  return typeof encrypted === 'string' ? encrypted : String(encrypted);
			})()
			""",
			work: .crypto(bytes: text.utf8.count),
			completion: completion
		)
	}

	/// Wrap inner OpenPGP armor to the entry route key (SI peel). Success is the wrapped armor. The inner armor comes back
	/// unchanged only when no outer layer is needed (the entry is the inner recipient's own node, or the inner message
	/// names no key ID). Every other case is a failure: the inner armor is never returned in place of a failed wrap.
	public func wrapArmorToEntryRoute(
		innerArmor: String,
		entryRoutePublicArmor: String,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		// No silent fallback: a wrap that cannot be made is a failure, and the caller skips that entry.
		// It never hands back the inner armor in place of the wrap.
		guard innerArmor.contains("BEGIN PGP MESSAGE") else {
			completion(.failure(NSError(domain: "BeamioOpenPgp", code: -5, userInfo: [
				NSLocalizedDescriptionKey: "wrap_not_armor",
			])))
			return
		}
		guard entryRoutePublicArmor.contains("BEGIN PGP PUBLIC KEY") else {
			completion(.failure(NSError(domain: "BeamioOpenPgp", code: -5, userInfo: [
				NSLocalizedDescriptionKey: "wrap_no_entry_key",
			])))
			return
		}
		runJs(
			"""
			(async () => {
			    const innerArmor = \(jsString(innerArmor));
			    const entryArmor = \(jsString(entryRoutePublicArmor));
			    const entryKey = await openpgp.readKey({ armoredKey: entryArmor });
			    const entryIds = new Set(entryKey.getKeyIDs().map(id => id.toHex().toUpperCase()));
			    const innerMsg = await openpgp.readMessage({ armoredMessage: innerArmor });
			    const innerIds = innerMsg.getEncryptionKeyIDs().map(id => id.toHex().toUpperCase());
			    if (!innerIds.length || innerIds.some(id => entryIds.has(id))) return innerArmor;
			    const pgpMsg = await openpgp.createMessage({ text: innerArmor });
			    const encrypted = await openpgp.encrypt({
			      message: pgpMsg,
			      encryptionKeys: entryKey,
			      config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
			    });
			    const out = typeof encrypted === 'string' ? encrypted : String(encrypted);
			    if (!out.includes('BEGIN PGP MESSAGE')) throw new Error('wrap_not_armor');
			    return out;
			})()
			""",
			work: .crypto(bytes: innerArmor.utf8.count),
			completion: completion
		)
	}


	/// keccak256(utf8(s)) via ethers in the OpenPGP host.
	func keccakUtf8(_ text: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  return ethers.keccak256(ethers.toUtf8Bytes(\(jsString(text))));
			})()
			""",
			work: .crypto(bytes: text.utf8.count),
			completion: completion
		)
	}

	/// Mailbox work: `{ data: innerArmor, NoPush?: true }` encrypted to B route PGP.
	public func wrapArmorToMailboxWork(
		innerArmor: String,
		mailboxRoutePublicArmor: String,
		noPush: Bool,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		runJs(
			"""
			(async () => {
			  const innerArmor = \(jsString(innerArmor));
			  const mailboxKey = await openpgp.readKey({ armoredKey: \(jsString(mailboxRoutePublicArmor)) });
			  const payload = { data: innerArmor };
			  if (\(noPush ? "true" : "false")) payload.NoPush = true;
			  const pgpMsg = await openpgp.createMessage({ text: JSON.stringify(payload) });
			  const encrypted = await openpgp.encrypt({
			    message: pgpMsg,
			    encryptionKeys: mailboxKey,
			    config: { preferredCompressionAlgorithm: openpgp.enums.compression.zlib },
			  });
			  return typeof encrypted === 'string' ? encrypted : String(encrypted);
			})()
			""",
			work: .crypto(bytes: innerArmor.utf8.count),
			completion: completion
		)
	}

	/// Base64(UTF-8(JSON)) then encrypt to recipient user PGP (outbound chat envelope).
	func encryptUtf8JsonBase64(
		jsonObject: [String: Any],
		recipientPublicArmor: String,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		guard let data = try? JSONSerialization.data(withJSONObject: jsonObject),
		      let json = String(data: data, encoding: .utf8)
		else {
			completion(.failure(NSError(domain: "BeamioOpenPgp", code: -6, userInfo: [
				NSLocalizedDescriptionKey: "json_encode",
			])))
			return
		}
		let b64 = Data(json.utf8).base64EncodedString()
		encryptLiteral(text: b64, publicKeyArmor: recipientPublicArmor, completion: completion)
	}

	// MARK: - WKScriptMessageHandler

	public func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
		guard message.name == "BeamioOpenPgp",
		      let body = message.body as? [String: Any],
		      let action = body["action"] as? String
		else { return }
		// A message from a page that was reset (an earlier boot) must not mark the current page ready (retry).
		if let from = message.webView, from !== webView { return }
		if action == "ready" {
			ready = true
			hasBeenReady = true
			bootRetries = 0
			flushPending(.success("ready"))
			Self.diag(String(format: "host ready ms=%ld app=%@", Int((bootStartedAt.map { Date().timeIntervalSince($0) } ?? 0) * 1000),
				Self.appStateLabel())
			)
		} else if action == "csp" || action == "error" {
			// H1: only a fixed vocabulary reaches the log, never a message (a parse error message can carry a slice of
			// the plaintext or the armor).
			Self.diag("page \(action): \(Self.diagnosticDetail(action: action, body: body))")
		}
	}

	// MARK: - Navigation

	/// Only the first main-frame load of the page is allowed (see `OpenPgpNavigationPolicy`). Only counts are logged, never a URL.
	public func webView(
		_ webView: WKWebView,
		decidePolicyFor navigationAction: WKNavigationAction,
		decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
	) {
		let isCurrentMainFrame = webView === self.webView && (navigationAction.targetFrame?.isMainFrame ?? false)
		let allowed = navigationPolicy.decide(isMainFrame: isCurrentMainFrame)
		if !allowed {
			Self.diag("navigation cancelled #\(navigationPolicy.cancelledCount)")
		}
		decisionHandler(allowed ? .allow : .cancel)
	}

	/// The only page-side text that reaches the log (H1). A CSP directive name made of a–z and hyphens, up to 32 characters, or an error
	/// class name from a fixed list. Anything else is `other`.
	static func diagnosticDetail(action: String, body: [String: Any]) -> String {
		switch action {
		case "csp":
			let raw = (body["directive"] as? String) ?? ""
			let plain = !raw.isEmpty && raw.count <= 32 && raw.allSatisfy { ($0 >= "a" && $0 <= "z") || $0 == "-" }
			return plain ? raw : "other"
		case "error":
			let name = (body["name"] as? String) ?? ""
			let known: Set<String> = ["Error", "TypeError", "ReferenceError", "SyntaxError", "RangeError", "EvalError", "URIError",
			                          "libs_missing", "unknown"]
			return known.contains(name) ? name : "other"
		default:
			return "other"
		}
	}

	/// Content-Security-Policy of the host page. Nothing connects, loads, frames or starts a worker. Scripts run only
	/// with this page's nonce, which the three inlined scripts carry. No 'unsafe-inline' and no 'unsafe-eval'.
	static func contentSecurityPolicy(nonce: String) -> String {
		[
			"default-src 'none'",
			"script-src 'nonce-\(nonce)'",
			"connect-src 'none'",
			"img-src 'none'",
			"style-src 'none'",
			"font-src 'none'",
			"media-src 'none'",
			"frame-src 'none'",
			"child-src 'none'",
			"worker-src 'none'",
			"object-src 'none'",
			"manifest-src 'none'",
			"base-uri 'none'",
			"form-action 'none'",
		].joined(separator: "; ")
	}

	/// The page's origin. A secure https origin that no server answers; the CSP refuses every request, so nothing loads from it.
	/// With no base URL (about:blank) both bundled libraries failed to load in the simulator (2026-11-14, 'Script error.' and
	/// 'libs missing'). The cause is not isolated; the https origin was observed to boot and encrypt.
	static let pageOrigin = URL(string: "https://openpgp-host.invalid/")!

	/// A fresh nonce per page (hex, so it is a valid CSP base64-value).
	static func makeNonce() -> String {
		UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
	}

	// MARK: - Teardown

	/// Lock and logout: the page goes, and its JS heap with it (the WebView is released). Asynchronous on purpose: the caller may
	/// hold its own lock. Calls waiting for the page fail, and none is re-run on a new page.
	public func tearDown(reason: String) {
		DispatchQueue.main.async { self.tearDownNow(reason: reason) }
	}

	private func tearDownNow(reason: String) {
		let waiting = pending
		pending.removeAll()
		let calls = Array(inFlight.values)
		inFlight.removeAll()
		// Nothing is pending or in flight now, so the reset boots no new page.
		resetHost(reason: "torn down (\(reason))")
		for callback in waiting { callback(.failure(Self.tornDownError())) }
		for call in calls { call.abandon() }
	}

	private static func tornDownError() -> NSError {
		NSError(domain: "BeamioOpenPgp", code: -8, userInfo: [NSLocalizedDescriptionKey: "openpgp host torn down"])
	}

	// MARK: - Recovery

	/// iOS can end this hidden WebView's content process while the app sits in
	/// the background. The object stays and `ready` stayed true, so every later
	/// sign / encrypt / decrypt failed until the app was relaunched (inbound
	/// messages were dropped meanwhile). Rebuild it instead.
	public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
		#if BEAMIO_TEST_HOOKS
		terminationCount += 1
		#endif
		resetHost(reason: "web content process terminated")
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook only: times the WebView's content process was reported terminated, the one event that says a kill took effect, unlike `resetCount`, which also
	/// moves for a boot timeout, a foreground probe, a teardown or a failed call. Written on the main queue and read by the test: a diagnostic, not a gate.
	private(set) var terminationCount = 0
	#endif

	/// Times the host was rebuilt (diagnostics only).
	public private(set) var resetCount = 0

	/// Main thread. The next call boots a fresh WebView. Calls still waiting on
	/// the old page are moved to the new one at once (they would never return).
	private func resetHost(reason: String) {
		resetCount += 1
		Self.diag(String(format: "host reset #%ld: %@ app=%@", resetCount, reason, Self.appStateLabel()))
		if let wv = webView {
			wv.navigationDelegate = nil
			wv.stopLoading()
			wv.configuration.userContentController.removeScriptMessageHandler(forName: "BeamioOpenPgp")
		}
		webView = nil
		ready = false
		bootstrapped = false
		generation += 1
		bootStartedAt = nil
		let stranded = inFlight
		inFlight.removeAll()
		for (_, call) in stranded { call.rerun() }
		// Callers still waiting for ready: boot the new page now.
		if !pending.isEmpty { bootstrapIfNeeded() }
	}

	// MARK: - Watchdog

	/// What a JS call does: sets how long it may run before the host counts as stuck.
	enum JsWork {
		/// EIP-191 / EIP-712 sign, verify, address: tens of ms.
		case quick
		/// OpenPGP encrypt / decrypt / wrap of about `bytes` of input.
		case crypto(bytes: Int)
	}

	/// The page never signalled ready. A normal boot takes 0.1–0.4 s; in the
	/// background WebKit may hold the page back, so wait longer there.
	static func bootTimeout(foreground: Bool) -> TimeInterval { foreground ? 3 : 8 }
	/// The first boot of the process may be a cold start of the page process (the simulator measured over 3 s); it gets this longer timeout.
	static let firstBootTimeout: TimeInterval = 8

	/// Launch warm-up: starts the page in the background, without a pending call, so the first request does not wait on a cold start.
	/// It never blocks: the boot runs on the main queue after this call returns.
	public static func warmUpAtLaunch() {
		DispatchQueue.main.async { shared.bootstrapIfNeeded() }
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: a host of its own, so a test starts from a cold boot.
	static func makeForTests() -> BeamioOpenPgpHost {
		let host = BeamioOpenPgpHost()
		host.isTestHost = true
		return host
	}
	/// Only a test host takes the forced failures, so the shared host (a warm-up in another test) cannot consume them.
	private var isTestHost = false
	/// Test build only: the next boots fail at once (their timer fires), to test the single automatic retry and the error after it.
	static var testBootFailuresRemaining = 0
#endif
	/// Sign / verify / address. Measured on a Mac (real WKWebView, warm): 5 ms;
	/// the iPhone SE's whole dialer cancel (sign + two encrypts) logs 60–120 ms.
	static let quickTimeout: TimeInterval = 4
	/// Encrypt / decrypt base time, plus `cryptoSecondsPerMB` per MB of input.
	/// Mac: 2 KB 2–4 ms; 1 MB encrypt 20 ms, decrypt (1.36 MB armor) 36 ms.
	static let cryptoBaseTimeout: TimeInterval = 5
	/// ~0.04 s/MB measured; 3 s/MB leaves ~75x for an older iPhone under load.
	static let cryptoSecondsPerMB: TimeInterval = 3
	/// Tests only: shrink every limit to reach the queued / stuck paths quickly.
	static var timeScale: Double = 1
	/// A call that never returns while the page keeps answering others fails here (no reset).
	static let hardCap: TimeInterval = 120

	static func timeout(for work: JsWork) -> TimeInterval {
		let limit: TimeInterval
		switch work {
		case .quick: limit = quickTimeout
		case .crypto(let bytes): limit = cryptoBaseTimeout + Double(max(0, bytes)) / 1_000_000 * cryptoSecondsPerMB
		}
		return limit * timeScale
	}

	/// What the watchdog does when a call's time is up.
	enum WatchdogStep: Equatable {
		/// The call already returned.
		case done
		/// Other calls returned recently: the page is alive, this one waits in its queue.
		case wait(TimeInterval)
		/// No call returned for the whole window: the page is gone. Rebuild, run again.
		case resetAndRetry
		/// Still no answer on the rebuilt page, or past the hard cap: fail this call.
		case fail
	}

	/// Pure rule (unit-tested). `quietFor`: seconds since any call returned on
	/// this page, or since this call started if that is later.
	static func watchdogStep(
		finished: Bool, retried: Bool, window: TimeInterval, quietFor: TimeInterval, runningFor: TimeInterval
	) -> WatchdogStep {
		if finished { return .done }
		if runningFor >= hardCap { return .fail }
		if quietFor < window { return .wait(max(0.05, window - quietFor)) }
		return retried ? .fail : .resetAndRetry
	}

	/// Page generation: bumps on every reset, so a late answer or timer from an
	/// old page never touches the new one.
	private var generation = 0
	/// When the current page's boot started (nil once reset).
	private var bootStartedAt: Date?
	/// Last time any call returned on the current page (main thread).
	private var lastAnswerAt = Date.distantPast
	/// A call running on the current page. `rerun` moves it to a rebuilt page; `abandon` fails it (teardown). Main thread.
	private struct InFlightCall {
		let rerun: () -> Void
		let abandon: () -> Void
	}
	private var inFlight: [Int: InFlightCall] = [:]
	private var nextCallId = 0
	/// Times the watchdog found the page stuck (diagnostics only).
	public private(set) var watchdogCount = 0

	/// A call failed because the page is gone (process ended, page not loaded),
	/// not because the script itself failed. Only a JavaScript exception with its
	/// own message (bad key, bad armor) keeps its result. Everything else is a
	/// dead page, rebuilt once: on a real iPhone a killed content process answers
	/// the call at once (RC3b V10: 5 ms, before the terminate callback) with
	/// "result of an unsupported type" — every script here returns a string, so
	/// that error never comes from a live page.
	static func isHostGone(_ error: NSError) -> Bool {
		let text = (error.userInfo["WKJavaScriptExceptionMessage"] as? String) ?? ""
		// The page reloaded blank: the bundled libraries are missing in it.
		if text.contains("Can't find variable: openpgp") || text.contains("Can't find variable: ethers") {
			return true
		}
		if error.domain == WKError.errorDomain {
			switch WKError.Code(rawValue: error.code) {
			case .javaScriptExceptionOccurred:
				return text.isEmpty
			default:
				return true
			}
		}
		return true
	}

	// MARK: - Private

	private func bootstrapIfNeeded() {
		guard !bootstrapped else { return }
		bootstrapped = true
		bootStartedAt = Date()
		Self.diag(String(format: "host boot start app=%@", Self.appStateLabel()))
		armBootTimer()
		let config = WKWebViewConfiguration()
		// H4: no website data is kept on disk; the page keeps nothing between runs, and this matches "Ephemeral" above.
		config.websiteDataStore = .nonPersistent()
		config.preferences.javaScriptEnabled = true
		// the page may not open windows by itself (no UI delegate is set either, so none opens).
		config.preferences.javaScriptCanOpenWindowsAutomatically = false
		config.userContentController.add(self, name: "BeamioOpenPgp")
		// Runtime WebSocket guard (AGENTS.md): installed before any script of this view runs.
		BeamioWebSocketGuard.install(on: config, handler: BeamioWebSocketGuardHandler.shared)
		let wv = WKWebView(frame: .zero, configuration: config)
		wv.isHidden = true
		wv.navigationDelegate = self
		webView = wv

		// Prefer SPM `Bundle.module`; fall back to host `Bundle.main` (app-copied ChatCrypto).
		let bundles: [Bundle] = [.module, .main]
		var openpgpUrl: URL?
		var ethersUrl: URL?
		for b in bundles {
			openpgpUrl = openpgpUrl
				?? b.url(forResource: "openpgp.min", withExtension: "js", subdirectory: "ChatCrypto")
				?? b.url(forResource: "openpgp.min", withExtension: "js")
			ethersUrl = ethersUrl
				?? b.url(forResource: "ethers.umd.min", withExtension: "js", subdirectory: "ChatCrypto")
				?? b.url(forResource: "ethers.umd.min", withExtension: "js")
		}
		guard let openpgpUrl,
		      let ethersUrl,
		      let openpgpJs = try? String(contentsOf: openpgpUrl, encoding: .utf8),
		      let ethersJs = try? String(contentsOf: ethersUrl, encoding: .utf8)
		else {
			Self.diag("missing bundled openpgp/ethers scripts")
			flushPending(.failure(NSError(domain: "BeamioOpenPgp", code: -2, userInfo: [
				NSLocalizedDescriptionKey: "bundled crypto scripts missing",
			])))
			return
		}

		// CSP with a per-page nonce for the three inlined scripts.
		let nonce = Self.makeNonce()
		let html = """
		<!DOCTYPE html><html><head><meta charset="utf-8"/>
		<meta http-equiv="Content-Security-Policy" content="\(Self.contentSecurityPolicy(nonce: nonce))"/>
		</head><body>
		<script nonce="\(nonce)">
		window.addEventListener('securitypolicyviolation', function(e){ window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'csp', directive: String(e.violatedDirective)}); });
		window.addEventListener('error', function(e){ window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'error', name: (e.error && e.error.name) || 'unknown'}); });
		</script>
		<script nonce="\(nonce)">\(ethersJs)</script>
		<script nonce="\(nonce)">\(openpgpJs)</script>
		<script nonce="\(nonce)">
		(function(){
		  try {
			if (typeof openpgp === 'undefined' || typeof ethers === 'undefined') {
			  window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'error', name:'libs_missing'});
			  return;
			}
			window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'ready'});
		  } catch (e) {
			window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'error', name: (e && e.name) || 'unknown'});
		  }
		})();
		</script>
		</body></html>
		"""
		// The first main-frame load (from this string) is the only navigation the policy allows. The base URL is the secure
		// https origin in `pageOrigin`, not a file URL: the page gets no file origin and reaches no file of the bundle.
		navigationPolicy.armInitialLoad()
		wv.loadHTMLString(html, baseURL: Self.pageOrigin)
	}

	func runJs(
		_ expression: String,
		work: JsWork,
		retried: Bool = false,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		let invoke: () -> Void = { [weak self] in
			guard let self else {
				completion(.failure(NSError(domain: "BeamioOpenPgp", code: -3, userInfo: [
					NSLocalizedDescriptionKey: "openpgp host deallocated",
				])))
				return
			}
			self.ensureReadyResult { readiness in
				// ensureReady always finishes on main; keep evaluateJavaScript there.
				assert(Thread.isMainThread)
				if case .failure(let error) = readiness {
					// the cause stays visible: a boot timeout is -1 (a retry can help), a teardown -8 (the account is changing)
					completion(.failure(error))
					return
				}
				guard let wv = self.webView else {
					completion(.failure(NSError(domain: "BeamioOpenPgp", code: -3, userInfo: [
						NSLocalizedDescriptionKey: "openpgp host not ready",
					])))
					return
				}
				// A killed content process may give no callback at all (neither the
				// call's nor `webViewWebContentProcessDidTerminate`): without this
				// watchdog the call, and everything waiting on it, hangs for good.
				let generation = self.generation
				let callId = self.nextCallId
				self.nextCallId += 1
				let started = Date()
				let window = Self.timeout(for: work)
				var finished = false
				if self.inFlight.isEmpty { self.lastAnswerAt = started }
				// Run once more on a fresh page (or fail if this already was the retry).
				let rerun: () -> Void = {
					guard !finished else { return }
					finished = true
					if retried {
						completion(.failure(NSError(domain: "BeamioOpenPgp", code: -7, userInfo: [
							NSLocalizedDescriptionKey: "openpgp host stuck",
						])))
					} else {
						self.runJs(expression, work: work, retried: true, completion: completion)
					}
				}
				// Teardown (lock, logout): this call fails now, and nothing re-runs it on a new page.
				let abandon: () -> Void = {
					guard !finished else { return }
					finished = true
					completion(.failure(Self.tornDownError()))
				}
				self.inFlight[callId] = InFlightCall(rerun: rerun, abandon: abandon)
				func watch(after delay: TimeInterval) {
					DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
						guard !finished else { return }
						guard generation == self.generation else {
							rerun()
							return
						}
						let now = Date()
						let step = Self.watchdogStep(
							finished: finished,
							retried: retried,
							window: window,
							quietFor: now.timeIntervalSince(max(self.lastAnswerAt, started)),
							runningFor: now.timeIntervalSince(started)
						)
						switch step {
						case .done:
							return
						case .wait(let more):
							watch(after: more)
						case .resetAndRetry:
							self.watchdogCount += 1
							Self.diag(String(format: "watchdog #%ld: no answer for %ld ms (limit %ld ms) app=%@; rebuilding", self.watchdogCount,
								Int(now.timeIntervalSince(started) * 1000),
								Int(window * 1000),
								Self.appStateLabel())
							)
							self.inFlight[callId] = nil
							// Moves every other call on this page to the new one, then this one.
							self.resetHost(reason: "watchdog")
							rerun()
						case .fail:
							self.inFlight[callId] = nil
							finished = true
							Self.diag(String(format: "call gave up after %ld ms (retried=%@)", Int(now.timeIntervalSince(started) * 1000),
								retried ? "yes" : "no"))
							completion(.failure(NSError(domain: "BeamioOpenPgp", code: -7, userInfo: [
								NSLocalizedDescriptionKey: "openpgp host stuck",
							])))
						}
					}
				}
				watch(after: window)
				// Every expression is an `(async => {... })` Promise. Plain
				// `evaluateJavaScript` cannot return a Promise and fails with
				// "JavaScript execution returned a result of an unsupported type",
				// which kept mailbox_listen in a permanent reconnect loop.
				// `callAsyncJavaScript` awaits it and hands back the resolved value.
				wv.callAsyncJavaScript(
					"return await (\(expression));",
					arguments: [:],
					in: nil,
					in: .page
				) { outcome in
					// A late answer from a page the watchdog already replaced is dropped.
					guard !finished else { return }
					finished = true
					if generation == self.generation {
						self.inFlight[callId] = nil
						self.lastAnswerAt = Date()
					}
					switch outcome {
					case .failure(let error):
						let ns = error as NSError
						// The page this call ran on was already replaced (the terminate
						// callback came first): run it once on the new page, whatever the error.
						let pageReplaced = generation != self.generation
						if !retried, pageReplaced || Self.isHostGone(ns) {
							Self.diag(String(format: "call failed on a dead page domain=%@ code=%ld replaced=%@; retrying once", ns.domain,
								ns.code,
								pageReplaced ? "yes" : "no"))
							// Rebuild the WebView (moves the other calls on it) and run this once more.
							if !pageReplaced {
								self.resetHost(reason: "call failed: domain=\(ns.domain) code=\(ns.code)")
							}
							self.runJs(expression, work: work, retried: true, completion: completion)
							return
						}
						// WebKit's localizedDescription is only "A JavaScript exception
						// occurred"; the real text is in WKJavaScriptExceptionMessage.
						let detail = (ns.userInfo["WKJavaScriptExceptionMessage"] as? String) ?? ns.localizedDescription
						completion(.failure(NSError(domain: "BeamioOpenPgp", code: ns.code, userInfo: [
							NSLocalizedDescriptionKey: detail,
						])))
					case .success(let value):
						if let s = value as? String {
							completion(.success(s))
						} else {
							completion(.failure(NSError(domain: "BeamioOpenPgp", code: -4, userInfo: [
								NSLocalizedDescriptionKey: "unexpected js result",
							])))
						}
					}
				}
			}
		}
		if Thread.isMainThread {
			invoke()
		} else {
			DispatchQueue.main.async(execute: invoke)
		}
	}

	private func flushPending(_ result: Result<String, Error>) {
		let callbacks = pending
		pending.removeAll()
		for cb in callbacks {
			cb(result)
		}
	}

	private func jsString(_ raw: String) -> String {
		let escaped = raw
			.replacingOccurrences(of: "\\", with: "\\\\")
			.replacingOccurrences(of: "'", with: "\\'")
			.replacingOccurrences(of: "\n", with: "\\n")
			.replacingOccurrences(of: "\r", with: "\\r")
		return "'\(escaped)'"
	}
}
