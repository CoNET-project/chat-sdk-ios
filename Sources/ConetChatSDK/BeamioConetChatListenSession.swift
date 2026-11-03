import CryptoKit
import Foundation
import Security

/// Mailbox SSE listen: encrypt `mailbox_listen` to B route PGP, HTTP via entry C ≠ B.
public final class BeamioConetChatListenSession {
	public init() {}

	typealias StatusHandler = (_ status: String, _ detail: String?) -> Void
	/// `armor` is the inbound OpenPGP armor (still encrypted to the user key), kept for the inbox store.
	typealias InboundHandler = (_ plaintext: String, _ armorHash: String, _ viaDomain: String, _ armor: String) -> Void

	private let lock = NSLock()
	private var generation = 0
	private var running = false
	private var paused = false
	private var sseTask: BeamioSiCipherPost.SseHandle?
	/// Last frame from the mailbox that opened with this listen's stream key.
	private var lastSealedFrameAt = Date.distantPast

	/// Seconds since the mailbox last spoke on this listen (handshake, keepalive,
	/// message). Large after the app was suspended: the stream may be gone even
	/// though nothing reported it.
	private func heardMailbox(since: Date) -> Bool {
		lock.lock(); defer { lock.unlock() }
		return lastSealedFrameAt >= since
	}

	func secondsSinceLastMailboxFrame() -> TimeInterval {
		lock.lock(); defer { lock.unlock() }
		return Date().timeIntervalSince(lastSealedFrameAt)
	}

	/// Started and not stopped (it may be paused).
	func isRunning() -> Bool {
		lock.lock(); defer { lock.unlock() }
		return running
	}

	/// Started, not stopped and not paused.
	func isListening() -> Bool {
		lock.lock(); defer { lock.unlock() }
		return running && !paused
	}

	func pause() {
		lock.lock()
		paused = true
		lock.unlock()
		stopCurrentSse()
		// A loop waiting to retry ends now instead of after its backoff.
		retryNow()
	}

	func resume(
		session: BeamioConetChatModule.Session,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) {
		lock.lock()
		paused = false
		lock.unlock()
		start(session: session, onStatus: onStatus, onInbound: onInbound)
	}

	func start(
		session: BeamioConetChatModule.Session,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) {
		lock.lock()
		generation += 1
		let gen = generation
		running = true
		paused = false
		lock.unlock()
		stopCurrentSse()
		onStatus("connecting", nil)
		DispatchQueue.global(qos: .userInitiated).async { [weak self] in
			self?.listenLoop(session: session, gen: gen, onStatus: onStatus, onInbound: onInbound)
		}
	}

	func stop() {
		lock.lock()
		running = false
		generation += 1
		lock.unlock()
		stopCurrentSse()
		retryNow()
	}

	private func stopCurrentSse() {
		lock.lock()
		let task = sseTask
		sseTask = nil
		lock.unlock()
		task?.cancel()
	}

	private func stillAlive(gen: Int) -> Bool {
		lock.lock(); defer { lock.unlock() }
		return running && generation == gen && !paused
	}

	private func listenLoop(
		session: BeamioConetChatModule.Session,
		gen: Int,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) {
		var failures = 0
		while stillAlive(gen: gen) {
			var reopenNow = false
			let tryStarted = Date()
			do {
				reopenNow = try runOneListen(session: session, gen: gen, onStatus: onStatus, onInbound: onInbound)
			} catch {
				if stillAlive(gen: gen) {
					onStatus("reconnecting", error.localizedDescription)
				}
			}
			if !stillAlive(gen: gen) { break }
			// The mailbox answered on this try: the network works, start the backoff over.
			if reopenNow || heardMailbox(since: tryStarted) { failures = 0 } else { failures += 1 }
			onStatus("reconnecting", reopenNow ? "relisten" : "retry")
			// A listen that worked and then dropped reopens at once (new command).
			// Otherwise back off (2 s … 30 s); the network coming back or the app
			// coming to the foreground cuts the wait short (`retryNow`).
			let wait = reopenNow
				? BeamioListenPolicy.relisten
				: BeamioListenPolicy.retryDelay(failures: failures, jitter: Double.random(in: 0..<1))
			if !reopenNow { NSLog("[BeamioConetChat] listen retry in %lds (failures=%ld)", Int(wait), failures) }
			waitBeforeRetry(wait)
		}
	}

	private let retrySignal = NSCondition()
	private var retryKicked = false

	/// Cut a retry wait short (network back, app in the foreground, paused).
	func retryNow() {
		retrySignal.lock()
		retryKicked = true
		retrySignal.broadcast()
		retrySignal.unlock()
	}

	private func waitBeforeRetry(_ seconds: TimeInterval) {
		retrySignal.lock()
		if !retryKicked { _ = retrySignal.wait(until: Date().addingTimeInterval(seconds)) }
		retryKicked = false
		retrySignal.unlock()
	}

	/// One signed `mailbox_listen` (one instanceId) tried on entries until one
	/// works. Returns true when the mailbox answered on a stream that then
	/// dropped: the caller builds a new command instead of reusing this one.
	@discardableResult
	private func runOneListen(
		session: BeamioConetChatModule.Session,
		gen: Int,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) throws -> Bool {
		let ownRoute = session.ownRouteArmoredPublicKey
		guard ownRoute.contains("BEGIN PGP PUBLIC KEY") else {
			throw NSError(domain: "BeamioConetChatListen", code: -1, userInfo: [
				NSLocalizedDescriptionKey: "missing_own_route",
			])
		}
		let mailboxIps = Self.mailboxIps(session: session)

		// Fresh stream key per listen: B seals every SSE frame with it, so the
		// entry relaying the stream cannot read the recipient key ID. Memory only.
		var keyBytes = [UInt8](repeating: 0, count: 32)
		guard SecRandomCopyBytes(kSecRandomDefault, keyBytes.count, &keyBytes) == errSecSuccess else {
			throw NSError(domain: "BeamioConetChatListen", code: -5, userInfo: [
				NSLocalizedDescriptionKey: "stream_key",
			])
		}
		let streamKey = SymmetricKey(data: Data(keyBytes))
		let command: [String: Any] = [
			"command": "mailbox_listen",
			"walletAddress": session.eoa,
			"instanceId": UUID().uuidString,
			"streamKey": Data(keyBytes).base64EncodedString(),
		]
		guard let cmdData = try? JSONSerialization.data(withJSONObject: command),
		      let cmdJson = String(data: cmdData, encoding: .utf8)
		else {
			throw NSError(domain: "BeamioConetChatListen", code: -2, userInfo: [
				NSLocalizedDescriptionKey: "bad_command",
			])
		}

		let sign = try awaitSign(cmdJson)
		let innerArmor = try awaitEncryptSignedRoute(message: cmdJson, signature: sign, route: ownRoute)
		guard stillAlive(gen: gen) else { return false }

		let entries = session.nodes.filter { n in
			guard let ip = BeamioSiCipherPost.normalizeIp(n.ip) else { return false }
			return !mailboxIps.contains(ip)
		}.shuffled()
		guard !entries.isEmpty else {
			throw NSError(domain: "BeamioConetChatListen", code: -3, userInfo: [
				NSLocalizedDescriptionKey: "no_entry_c",
			])
		}

		var lastError: String?
		for entry in entries {
			guard stillAlive(gen: gen) else { return false }
			guard let entryIp = BeamioSiCipherPost.normalizeIp(entry.ip),
			      !BeamioSiCipherPost.isMarkedUnreachable(entryIp),
			      let url = BeamioSiCipherPost.postUrl(for: entryIp)
			else { continue }

			let armored: String
			if entry.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") {
				armored = (try? awaitWrap(inner: innerArmor, entryRoute: entry.armoredPublicKey)) ?? innerArmor
			} else {
				armored = innerArmor
			}

			NSLog("[BeamioConetChat] mailbox_listen entry=%@ domain=%@", entryIp, entry.domain)
			let streamStarted = Date()
			let err = openSse(
				url: url,
				armored: armored,
				streamKey: streamKey,
				session: session,
				gen: gen,
				viaDomain: entry.domain,
				onStatus: onStatus,
				onInbound: onInbound
			)
			if err == nil { return false }
			lastError = err
			if err == "root_stop" || !stillAlive(gen: gen) { return false }
			// The mailbox registered this listen under its instanceId. Reusing this
			// command on another entry lets the old socket's late close remove the
			// new session at the mailbox: build a new command instead.
			if heardMailbox(since: streamStarted) { return true }
		}
		throw NSError(domain: "BeamioConetChatListen", code: -4, userInfo: [
			NSLocalizedDescriptionKey: lastError ?? "all_entries_failed",
		])
	}

	private func openSse(
		url: URL,
		armored: String,
		streamKey: SymmetricKey,
		session: BeamioConetChatModule.Session,
		gen: Int,
		viaDomain: String,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) -> String? {
		let openSem = DispatchSemaphore(value: 0)
		let closedSem = DispatchSemaphore(value: 0)
		var closeReason: String?

		guard let task = BeamioSiCipherPost.postSse(
			url: url,
			armor: armored,
			connectTimeout: 12,
			// The mailbox's sealed keepalive comes every 60–180 s: wait longer than
			// that before calling the stream dead (120 s cut healthy listens).
			idleTimeout: 200,
			onOpen: {
				// HTTP 200 only means the entry took the request. "listening" is
				// reported when the mailbox's sealed handshake frame arrives.
				openSem.signal()
			},
			onEvent: { [weak self] payload in
				guard let frame = Self.openStreamFrame(payload, key: streamKey) else { return }
				if let self {
					self.lock.lock()
					self.lastSealedFrameAt = Date()
					self.lock.unlock()
				}
				self?.handleSsePayload(
					frame,
					session: session,
					viaDomain: viaDomain,
					onStatus: onStatus,
					onInbound: onInbound
				)
			},
			onClosed: { reason in
				closeReason = reason
				openSem.signal()
				closedSem.signal()
			}
		) else {
			return "sse_start_failed"
		}
		lock.lock()
		sseTask = task
		lock.unlock()

		_ = openSem.wait(timeout: .now() + 15)
		if !stillAlive(gen: gen) {
			task.cancel()
			return "root_stop"
		}

		_ = closedSem.wait(timeout: .now() + 60 * 60 * 6)
		lock.lock()
		if sseTask === task { sseTask = nil }
		lock.unlock()
		if !stillAlive(gen: gen) { return "root_stop" }
		return closeReason ?? "server_closed"
	}

	/// Open one mailbox SSE frame with this listen's stream key:
	/// `base64(iv[12] ‖ AES-256-GCM ciphertext ‖ tag[16])`, plaintext JSON padded
	/// with spaces. Every mailbox seals every frame; anything else (plain JSON,
	/// a frame that does not open) is dropped. Never logs the key or contents.
	static func openStreamFrame(_ payload: String, key: SymmetricKey) -> String? {
		let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
		if trimmed.isEmpty { return nil }
		guard trimmed.count >= 40,
		      trimmed.range(of: "^[A-Za-z0-9+/]+={0,2}$", options: .regularExpression) != nil,
		      let blob = Data(base64Encoded: trimmed)
		else {
			NSLog("[BeamioConetChat] mailbox frame not sealed; dropped len=%ld", trimmed.count)
			return nil
		}
		guard let box = try? AES.GCM.SealedBox(combined: blob),
		      let plain = try? AES.GCM.open(box, using: key),
		      let text = String(data: plain, encoding: .utf8)
		else {
			NSLog("[BeamioConetChat] mailbox frame did not open len=%ld", trimmed.count)
			return nil
		}
		return text.trimmingCharacters(in: .whitespacesAndNewlines)
	}

	private func handleSsePayload(
		_ payload: String,
		session: BeamioConetChatModule.Session,
		viaDomain: String,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) {
		let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
		if trimmed.isEmpty { return }
		// Length and shape only. Never log ciphertext or plaintext.
		let isPgp = trimmed.contains("BEGIN PGP MESSAGE")
		NSLog(
			"[BeamioConetChat] sse event len=%ld pgp=%@ via=%@%@",
			trimmed.count,
			isPgp ? "yes" : "no",
			viaDomain,
			// Control frames (handshake / heartbeat) are plain JSON without secrets.
			isPgp ? "" : " head=\(String(trimmed.prefix(300)))"
		)

		if let data = trimmed.data(using: .utf8),
		   let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
			let type = obj["type"] as? String ?? ""
			// The mailbox's first frame: `{status:200, kind:'mailbox', instanceId, nodeWallet, …}`.
			if (obj["kind"] as? String) == "mailbox" || ((obj["ok"] as? Bool) == true && obj["nodeWallet"] != nil) {
				onStatus("listening", "handshake")
				return
			}
			if type == "mailbox_keepalive" || obj["epoch"] != nil || obj["status"] != nil {
				onStatus("listening", "heartbeat")
				return
			}
		}

		guard let armored = Self.findInboundArmor(trimmed),
		      armored.contains("BEGIN PGP MESSAGE")
		else { return }

		Self.decryptArmor(
			session: session,
			armored: armored,
			onFailure: { [weak self] in self?.restartAfterDecryptFailure() }
		) { line, hash in
			onInbound(line, hash, viaDomain, armored)
		}
	}

	private var lastDecryptRestart = Date.distantPast

	/// A message on this stream could not be decrypted (the crypto host failed
	/// even after rebuilding). It was not ACKed, so the mailbox still holds it and
	/// sends it again to a new listen: reopen the stream (at most every 30 s).
	private func restartAfterDecryptFailure() {
		lock.lock()
		let now = Date()
		guard now.timeIntervalSince(lastDecryptRestart) > 30, let task = sseTask else {
			lock.unlock()
			return
		}
		lastDecryptRestart = now
		lock.unlock()
		NSLog("[BeamioConetChat] inbound decrypt failed; reopening the mailbox listen")
		task.cancel()
	}

	/// Decrypt one inbound armor with the session PGP key into the chat line the
	/// app expects (with `_beamioPgpArmorHash`). Also replays the inbox store.
	/// Never logs plaintext.
	static func decryptArmor(
		session: BeamioConetChatModule.Session,
		armored: String,
		onFailure: (() -> Void)? = nil,
		onLine: @escaping (_ line: String, _ armorHash: String) -> Void
	) {
		BeamioOpenPgpHost.shared.decryptInboundArmor(
			privateKeyArmor: session.pgpPrivateKeyArmored,
			armor: armored
		) { result in
			switch result {
			case .failure:
				NSLog("[BeamioConetChat] inbound decrypt failed")
				onFailure?()
			case .success(let dec):
				var line = normalizeInboundPlaintext(dec.text)
				if line.isEmpty { return }
				if var env = jsonObject(line) {
					env["_beamioPgpArmorHash"] = dec.armorHash
					if let data = try? JSONSerialization.data(withJSONObject: env),
					   let s = String(data: data, encoding: .utf8) {
						line = s
					}
				}
				onLine(line, dec.armorHash)
			}
		}
	}

	// MARK: - Crypto helpers (sync wrappers)

	private func awaitSign(_ message: String) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "sign", code: -1))
		BeamioConetChatSignBroker.requestEip191(message: message) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 30)
		return try out.get()
	}

	private func awaitEncryptSignedRoute(message: String, signature: String, route: String) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "enc", code: -1))
		BeamioOpenPgpHost.shared.encryptSignedRouteCommand(
			message: message,
			signMessage: signature,
			routePublicArmor: route
		) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 20)
		let armor = try out.get()
		guard armor.contains("BEGIN PGP MESSAGE") else {
			throw NSError(domain: "BeamioConetChatListen", code: -5, userInfo: [
				NSLocalizedDescriptionKey: "encrypt_route_command_failed",
			])
		}
		return armor
	}

	private func awaitWrap(inner: String, entryRoute: String) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .success(inner)
		BeamioOpenPgpHost.shared.wrapArmorToEntryRoute(
			innerArmor: inner,
			entryRoutePublicArmor: entryRoute
		) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 15)
		return try out.get()
	}

	// MARK: - Static helpers

	static func mailboxIps(session: BeamioConetChatModule.Session) -> Set<String> {
		var set = Set<String>()
		if let ip = BeamioSiCipherPost.normalizeIp(session.mailboxIp) {
			set.insert(ip)
		}
		for n in session.nodes {
			if n.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY"),
			   fingerprintsOverlap(session.ownRouteArmoredPublicKey, n.armoredPublicKey),
			   let ip = BeamioSiCipherPost.normalizeIp(n.ip) {
				set.insert(ip)
			}
		}
		return set
	}

	/// Cheap overlap heuristic: shared key-id hex substrings from armor comments / packets.
	static func fingerprintsOverlap(_ a: String, _ b: String) -> Bool {
		let idsA = extractKeyIdHints(a)
		let idsB = extractKeyIdHints(b)
		return !idsA.isDisjoint(with: idsB) && !idsA.isEmpty
	}

	private static func extractKeyIdHints(_ armor: String) -> Set<String> {
		var out = Set<String>()
		let upper = armor.uppercased()
		let pattern = try? NSRegularExpression(pattern: "[0-9A-F]{16}", options: [])
		let range = NSRange(upper.startIndex ..< upper.endIndex, in: upper)
		pattern?.enumerateMatches(in: upper, options: [], range: range) { match, _, _ in
			guard let match, let r = Range(match.range, in: upper) else { return }
			out.insert(String(upper[r]))
		}
		return out
	}

	static func findInboundArmor(_ payload: String) -> String? {
		let trimmed = payload.trimmingCharacters(in: .whitespacesAndNewlines)
		// JSON first: SI frames carry the armor as an escaped string (`\n`), so a
		// raw substring of the frame is NOT a valid armor and OpenPGP.js rejects it
		// with "Misformed armored text".
		if trimmed.hasPrefix("{") || trimmed.hasPrefix("["),
		   let obj = jsonObject(trimmed),
		   let found = walkArmor(obj, depth: 0) {
			return found
		}
		if trimmed.contains("BEGIN PGP MESSAGE") {
			var raw = trimmed
			if let start = trimmed.range(of: "-----BEGIN PGP MESSAGE-----"),
			   let end = trimmed.range(of: "-----END PGP MESSAGE-----") {
				raw = String(trimmed[start.lowerBound ..< end.upperBound])
			}
			// Armor lifted out of a JSON string still has literal `\n` / `\r` escapes.
			if !raw.contains("\n") {
				raw = raw
					.replacingOccurrences(of: "\\r\\n", with: "\n")
					.replacingOccurrences(of: "\\n", with: "\n")
					.replacingOccurrences(of: "\\r", with: "\n")
			}
			return raw
		}
		guard let obj = jsonObject(trimmed) else { return nil }
		return walkArmor(obj, depth: 0)
	}

	private static func walkArmor(_ obj: [String: Any], depth: Int) -> String? {
		if depth > 6 { return nil }
		for key in ["data", "message", "armor", "ciphertext", "payload"] {
			guard let v = obj[key] else { continue }
			if let s = v as? String {
				if s.contains("BEGIN PGP MESSAGE") { return s }
				if let nested = jsonObject(s), let found = walkArmor(nested, depth: depth + 1) {
					return found
				}
			} else if let nested = v as? [String: Any], let found = walkArmor(nested, depth: depth + 1) {
				return found
			}
		}
		return nil
	}

	static func normalizeInboundPlaintext(_ raw: String) -> String {
		let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
		if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") { return trimmed }
		if let data = Data(base64Encoded: trimmed),
		   let decoded = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
		   decoded.hasPrefix("{") || decoded.hasPrefix("[") {
			return decoded
		}
		return trimmed
	}

	static func jsonObject(_ s: String) -> [String: Any]? {
		guard let data = s.data(using: .utf8),
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else { return nil }
		return obj
	}
}
