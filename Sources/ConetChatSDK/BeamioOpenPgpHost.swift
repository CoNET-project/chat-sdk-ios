import Foundation
import WebKit
#if canImport(UIKit)
import UIKit
#endif

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

	public func ensureReady(completion: @escaping (Bool) -> Void) {
		// WKWebView / evaluateJavaScript are main-thread-only. Callers (e.g.
		// history keccak on a utility queue) must never complete onto a bg thread
		// and then call into WebKit — that triggers an intentional EXC_BREAKPOINT.
		let finish: (Bool) -> Void = { ok in
			if Thread.isMainThread {
				completion(ok)
			} else {
				DispatchQueue.main.async { completion(ok) }
			}
		}
		if ready {
			finish(true)
			return
		}
		DispatchQueue.main.async {
			if self.ready {
				completion(true)
				return
			}
			self.pending.append { result in
				completion((try? result.get()) != nil || self.ready)
			}
			// Starts the page (and its one boot timer) unless it is already booting.
			self.bootstrapIfNeeded()
		}
	}

	/// Main thread. One timer per boot: the page never signalled ready.
	private func armBootTimer() {
		let generation = self.generation
		let limit = Self.bootTimeout(foreground: Self.appIsActive())
		// The host is a process-wide singleton: a strong capture leaks nothing.
		DispatchQueue.main.asyncAfter(deadline: .now() + limit) {
			guard !self.ready, generation == self.generation else { return }
			Self.diag(String(format: "boot timeout after %ld ms app=%@", Int(limit * 1000), Self.appStateLabel()))
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

	/// Decrypt armored ciphertext with recipient user PGP private key.
	public func decrypt(armor: String, privateKeyArmor: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  const sk = await openpgp.readPrivateKey({ armoredKey: \(jsString(privateKeyArmor)) });
			  const message = await openpgp.readMessage({ armoredMessage: \(jsString(armor)) });
			  const { data } = await openpgp.decrypt({ message, decryptionKeys: sk, format: 'utf8' });
			  return typeof data === 'string' ? data : String(data);
			})()
			""",
			work: .crypto(bytes: armor.utf8.count),
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

	// MARK: - Local wallet signer (key from BeamioChatWalletKeychain; never logged)

	/// EIP-191 `personal_sign` of `message` with `privateKeyHex`.
	public func signEip191(privateKeyHex: String, message: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  const w = new ethers.Wallet('0x' + \(jsString(privateKeyHex)));
			  return await w.signMessage(\(jsString(message)));
			})()
			""",
			work: .quick,
			completion: { completion(Self.signatureOrError($0)) }
		)
	}

	/// EIP-712 signature of `{ domain, types, primaryType, message|value }`.
	public func signEip712(privateKeyHex: String, typedData: [String: Any], completion: @escaping (Result<String, Error>) -> Void) {
		guard let data = try? JSONSerialization.data(withJSONObject: typedData),
		      let json = String(data: data, encoding: .utf8)
		else {
			completion(.failure(Self.localSignError))
			return
		}
		runJs(
			"""
			(async () => {
			  const td = JSON.parse(\(jsString(json)));
			  const types = Object.assign({}, td.types || {});
			  delete types.EIP712Domain;
			  const value = td.value || td.message;
			  if (!td.domain || !value) throw new Error('bad_typed_data');
			  const w = new ethers.Wallet('0x' + \(jsString(privateKeyHex)));
			  return await w.signTypedData(td.domain, types, value);
			})()
			""",
			work: .quick,
			completion: { completion(Self.signatureOrError($0)) }
		)
	}

	/// Lower-case address of `privateKeyHex`.
	public func walletAddress(privateKeyHex: String, completion: @escaping (Result<String, Error>) -> Void) {
		runJs(
			"""
			(async () => {
			  return String(new ethers.Wallet('0x' + \(jsString(privateKeyHex))).address).toLowerCase();
			})()
			""",
			work: .quick,
			completion: { result in
				if case .success(let a) = result, a.hasPrefix("0x") { completion(.success(a)) }
				else { completion(.failure(Self.localSignError)) }
			}
		)
	}

	private static let localSignError = NSError(domain: "BeamioOpenPgp", code: -10, userInfo: [
		NSLocalizedDescriptionKey: "local_sign_failed",
	])

	/// Never pass the JS error text on: it could quote its input.
	private static func signatureOrError(_ result: Result<String, Error>) -> Result<String, Error> {
		if case .success(let sig) = result, sig.hasPrefix("0x") { return .success(sig) }
		return .failure(localSignError)
	}

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

	/// Wrap inner OpenPGP armor to entry route key (SI peel). Returns inner on same-node / failure.
	public func wrapArmorToEntryRoute(
		innerArmor: String,
		entryRoutePublicArmor: String,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		if !innerArmor.contains("BEGIN PGP MESSAGE") || entryRoutePublicArmor.isEmpty {
			completion(.success(innerArmor))
			return
		}
		runJs(
			"""
			(async () => {
			  try {
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
			    return out.includes('BEGIN PGP MESSAGE') ? out : innerArmor;
			  } catch (e) {
			    return \(jsString(innerArmor));
			  }
			})()
			""",
			work: .crypto(bytes: innerArmor.utf8.count),
			completion: completion
		)
	}

	/// Decrypt inbound user-PGP armor → UTF-8; also returns keccak256(utf8(armor)) for ACK.
	public func decryptInboundArmor(
		privateKeyArmor: String,
		armor: String,
		completion: @escaping (Result<(text: String, armorHash: String), Error>) -> Void
	) {
		runJs(
			"""
			(async () => {
			  const armor = \(jsString(armor));
			  const sk = await openpgp.readPrivateKey({ armoredKey: \(jsString(privateKeyArmor)) });
			  const message = await openpgp.readMessage({ armoredMessage: armor });
			  const { data } = await openpgp.decrypt({ message, decryptionKeys: sk, format: 'utf8' });
			  const text = typeof data === 'string' ? data : String(data);
			  const hash = ethers.keccak256(ethers.toUtf8Bytes(armor));
			  return JSON.stringify({ text, armorHash: hash });
			})()
			""",
			work: .crypto(bytes: armor.utf8.count)
		) { result in
			switch result {
			case .failure(let err):
				completion(.failure(err))
			case .success(let raw):
				guard let data = raw.data(using: .utf8),
				      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
				      let text = obj["text"] as? String,
				      let hash = obj["armorHash"] as? String
				else {
					completion(.failure(NSError(domain: "BeamioOpenPgp", code: -5, userInfo: [
						NSLocalizedDescriptionKey: "decryptInbound parse",
					])))
					return
				}
				completion(.success((text: text, armorHash: hash)))
			}
		}
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
		if action == "ready" {
			ready = true
			flushPending(.success("ready"))
			Self.diag(String(format: "host ready ms=%ld app=%@", Int((bootStartedAt.map { Date().timeIntervalSince($0) } ?? 0) * 1000),
				Self.appStateLabel())
			)
		}
	}

	// MARK: - Recovery

	/// iOS can end this hidden WebView's content process while the app sits in
	/// the background. The object stays and `ready` stayed true, so every later
	/// sign / encrypt / decrypt failed until the app was relaunched (inbound
	/// messages were dropped meanwhile). Rebuild it instead.
	public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
		resetHost(reason: "web content process terminated")
	}

	/// Times the host was rebuilt (diagnostics only).
	public private(set) var resetCount = 0

	/// Main thread. The next call boots a fresh WebView. Calls still waiting on
	/// the old page are moved to the new one at once (they would never return).
	private func resetHost(reason: String) {
		resetCount += 1
		Self.diag(String(format: "host reset #%ld: %@ app=%@", resetCount, reason, Self.appStateLabel()))
		if let wv = webView {
			wv.navigationDelegate = nil
			wv.configuration.userContentController.removeScriptMessageHandler(forName: "BeamioOpenPgp")
		}
		webView = nil
		ready = false
		bootstrapped = false
		generation += 1
		bootStartedAt = nil
		let stranded = inFlight
		inFlight.removeAll()
		for (_, moveToNewHost) in stranded { moveToNewHost() }
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
	/// Calls running on the current page → "move to the new page" (main thread).
	private var inFlight: [Int: () -> Void] = [:]
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
		config.preferences.javaScriptEnabled = true
		config.userContentController.add(self, name: "BeamioOpenPgp")
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

		let html = """
		<!DOCTYPE html><html><head><meta charset="utf-8"/></head><body>
		<script>\(ethersJs)</script>
		<script>\(openpgpJs)</script>
		<script>
		(function(){
		  try {
			if (typeof openpgp === 'undefined' || typeof ethers === 'undefined') {
			  window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'error', message:'libs missing'});
			  return;
			}
			window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'ready'});
		  } catch (e) {
			window.webkit.messageHandlers.BeamioOpenPgp.postMessage({action:'error', message:String(e)});
		  }
		})();
		</script>
		</body></html>
		"""
		wv.loadHTMLString(html, baseURL: Bundle.module.bundleURL)
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
			self.ensureReady { ok in
				// ensureReady always finishes on main; keep evaluateJavaScript there.
				assert(Thread.isMainThread)
				guard ok, let wv = self.webView else {
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
				self.inFlight[callId] = rerun
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
				// Every expression is an `(async () => { ... })()` Promise. Plain
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
