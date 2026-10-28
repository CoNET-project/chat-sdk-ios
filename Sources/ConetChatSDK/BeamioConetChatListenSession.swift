import Foundation

/// Mailbox SSE listen: encrypt `mailbox_listen` to B route PGP, HTTP via entry C ≠ B.
public final class BeamioConetChatListenSession {
	public init() {}

	typealias StatusHandler = (_ status: String, _ detail: String?) -> Void
	typealias InboundHandler = (_ plaintext: String, _ armorHash: String, _ viaDomain: String) -> Void

	private let lock = NSLock()
	private var generation = 0
	private var running = false
	private var paused = false
	private var sseTask: BeamioSiCipherPost.SseHandle?
	private let retryMs: UInt64 = 6_000

	func isRunning() -> Bool {
		lock.lock(); defer { lock.unlock() }
		return running
	}

	func pause() {
		lock.lock()
		paused = true
		lock.unlock()
		stopCurrentSse()
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
		while stillAlive(gen: gen) {
			do {
				try runOneListen(session: session, gen: gen, onStatus: onStatus, onInbound: onInbound)
			} catch {
				if stillAlive(gen: gen) {
					onStatus("reconnecting", error.localizedDescription)
				}
			}
			if !stillAlive(gen: gen) { break }
			onStatus("reconnecting", "retry")
			Thread.sleep(forTimeInterval: TimeInterval(retryMs) / 1000.0)
		}
	}

	private func runOneListen(
		session: BeamioConetChatModule.Session,
		gen: Int,
		onStatus: @escaping StatusHandler,
		onInbound: @escaping InboundHandler
	) throws {
		let ownRoute = session.ownRouteArmoredPublicKey
		guard ownRoute.contains("BEGIN PGP PUBLIC KEY") else {
			throw NSError(domain: "BeamioConetChatListen", code: -1, userInfo: [
				NSLocalizedDescriptionKey: "missing_own_route",
			])
		}
		let mailboxIps = Self.mailboxIps(session: session)

		let command: [String: Any] = [
			"command": "mailbox_listen",
			"walletAddress": session.eoa,
			"instanceId": UUID().uuidString,
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
		guard stillAlive(gen: gen) else { return }

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
			guard stillAlive(gen: gen) else { return }
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
			let err = openSse(
				url: url,
				armored: armored,
				session: session,
				gen: gen,
				viaDomain: entry.domain,
				onStatus: onStatus,
				onInbound: onInbound
			)
			if err == nil { return }
			lastError = err
			if err == "root_stop" || !stillAlive(gen: gen) { return }
		}
		throw NSError(domain: "BeamioConetChatListen", code: -4, userInfo: [
			NSLocalizedDescriptionKey: lastError ?? "all_entries_failed",
		])
	}

	private func openSse(
		url: URL,
		armored: String,
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
			idleTimeout: 120,
			onOpen: {
				onStatus("listening", "handshake")
				openSem.signal()
			},
			onEvent: { [weak self] payload in
				self?.handleSsePayload(
					payload,
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
			if type == "mailbox_keepalive" || obj["epoch"] != nil || obj["status"] != nil {
				onStatus("listening", "heartbeat")
				return
			}
			if (obj["ok"] as? Bool) == true && (obj["kind"] != nil || obj["nodeWallet"] != nil) {
				onStatus("listening", "handshake")
				return
			}
		}

		guard let armored = Self.findInboundArmor(trimmed),
		      armored.contains("BEGIN PGP MESSAGE")
		else { return }

		BeamioOpenPgpHost.shared.decryptInboundArmor(
			privateKeyArmor: session.pgpPrivateKeyArmored,
			armor: armored
		) { result in
			switch result {
			case .failure(let err):
				NSLog("[BeamioConetChat] inbound decrypt: %@", err.localizedDescription)
			case .success(let dec):
				var line = Self.normalizeInboundPlaintext(dec.text)
				if line.isEmpty { return }
				if var env = Self.jsonObject(line) {
					env["_beamioPgpArmorHash"] = dec.armorHash
					if let data = try? JSONSerialization.data(withJSONObject: env),
					   let s = String(data: data, encoding: .utf8) {
						line = s
					}
				}
				onInbound(line, dec.armorHash, viaDomain)
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
