import Foundation
import WebKit

/// Ephemeral WKWebView that runs bundled `openpgp.min.js` + `ethers.umd.min.js`
/// for killed-app voice offer fetch / decrypt / EIP-191 verify.
public final class BeamioOpenPgpHost: NSObject, WKScriptMessageHandler {
	public static let shared = BeamioOpenPgpHost()

	private var webView: WKWebView?
	private var ready = false
	private var pending: [(Result<String, Error>) -> Void] = []
	private var bootstrapped = false

	private override init() {
		super.init()
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
			self.bootstrapIfNeeded()
			self.pending.append { result in
				completion((try? result.get()) != nil || self.ready)
			}
			// Fallback if scripts never signal ready.
			DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak self] in
				guard let self, !self.ready else { return }
				self.flushPending(.failure(NSError(domain: "BeamioOpenPgp", code: -1, userInfo: [
					NSLocalizedDescriptionKey: "openpgp host timeout",
				])))
			}
		}
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
			completion: completion
		)
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
			"""
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
			NSLog("[BeamioOpenPgp] host ready")
		}
	}

	// MARK: - Private

	private func bootstrapIfNeeded() {
		guard !bootstrapped else { return }
		bootstrapped = true
		let config = WKWebViewConfiguration()
		config.preferences.javaScriptEnabled = true
		config.userContentController.add(self, name: "BeamioOpenPgp")
		let wv = WKWebView(frame: .zero, configuration: config)
		wv.isHidden = true
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
			NSLog("[BeamioOpenPgp] missing bundled openpgp/ethers scripts")
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

	private func runJs(_ expression: String, completion: @escaping (Result<String, Error>) -> Void) {
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
				wv.evaluateJavaScript(expression) { result, error in
					if let error {
						completion(.failure(error))
						return
					}
					if let s = result as? String {
						completion(.success(s))
						return
					}
					completion(.failure(NSError(domain: "BeamioOpenPgp", code: -4, userInfo: [
						NSLocalizedDescriptionKey: "unexpected js result",
					])))
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
