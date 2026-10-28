import Foundation
import Network

/// OpenPGP ciphertext POST for the native shell.
/// Target is `http://{Guardian ip}/post` with body `{ "data": armor }` only.
/// The shell picks the entry IP from its roster and never lets the PWA name a URL.
///
/// Entries are reached with plain HTTP/1.1 over TCP port 80 (Network.framework).
/// URLSession answers `NSURLErrorDomain#-1022` (App Transport Security) for every
/// `http://IP` entry on current iOS, even with `NSAllowsArbitraryLoads`, so neither
/// the one-shot POST nor the SSE listen uses URLSession.
public enum BeamioSiCipherPost {
	public struct Result {
		public var ok: Bool
		public var status: Int
		public var body: String
		public var error: String
	}

	public struct RawResponse {
		public var status: Int
		public var body: String
		public var error: String
		public var ms: Int
	}

	private static let stateLock = NSLock()
	/// Higher is better. Unscored reachable nodes start at 80.
	private static var entryScores: [String: Int] = [:]
	/// IPs that failed the reachability test. `getRandomNode` never returns these.
	/// Upper bound for one `post(...)` call across all attempts.
	private static let totalBudgetSeconds: TimeInterval = 13
	private static var unreachableUntil: [String: Date] = [:]
	/// A failed IP stays out of `getRandomNode` this long, then may be probed again.
	private static let unreachableTTL: TimeInterval = 120

	public static func normalizeIp(_ raw: String) -> String? {
		var trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
		guard !trimmed.isEmpty, !trimmed.contains("/"), !trimmed.contains(" ") else { return nil }
		if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
			trimmed = String(trimmed.dropFirst().dropLast())
		}
		if trimmed.contains(":") {
			guard trimmed.filter({ $0 == ":" }).count >= 2, !trimmed.contains(".") else { return nil }
			return trimmed
		}
		let parts = trimmed.split(separator: ".", omittingEmptySubsequences: false)
		guard parts.count == 4 else { return nil }
		for part in parts {
			guard !part.isEmpty, part.count <= 3, part.allSatisfy({ $0.isNumber }) else { return nil }
			if part.count > 1 && part.hasPrefix("0") { return nil }
			guard let n = Int(part), (0 ... 255).contains(n) else { return nil }
		}
		return trimmed
	}

	/// Display / routing URL only. Requests go through `httpRequest` / `postSse`.
	public static func postUrl(for ip: String) -> URL? {
		guard let ip = normalizeIp(ip) else { return nil }
		if ip.contains(":") {
			return URL(string: "http://[\(ip)]/post")
		}
		return URL(string: "http://\(ip)/post")
	}

	// MARK: - Entry scoring

	/// Score one entry after a reachability test, POST or SSE open.
	/// `reachable == false` (no TCP, timeout, no HTTP status) zeroes the score and
	/// keeps the IP out of every later `getRandomNode` result.
	public static func scoreEntry(ip raw: String, reachable: Bool, latencyMs: Int) {
		guard let ip = normalizeIp(raw) else { return }
		stateLock.lock()
		defer { stateLock.unlock() }
		if !reachable {
			unreachableUntil[ip] = Date().addingTimeInterval(unreachableTTL)
			entryScores[ip] = 0
			return
		}
		unreachableUntil.removeValue(forKey: ip)
		let speed = max(1, 500 - min(max(latencyMs, 0), 500))
		let prev = max(entryScores[ip] ?? 80, 1)
		entryScores[ip] = min(2000, prev / 2 + speed)
	}

	public static func isMarkedUnreachable(_ raw: String) -> Bool {
		guard let ip = normalizeIp(raw) else { return false }
		stateLock.lock()
		defer { stateLock.unlock() }
		if let until = unreachableUntil[ip], until > Date() { return true }
		unreachableUntil.removeValue(forKey: ip)
		return false
	}

	/// One roster node that answered an HTTP probe on port 80, weighted to higher
	/// scores. Unreachable IPs are scored out and are never returned.
	public static func getRandomNode(
		nodes: [BeamioChatPgpKeychain.SiNode],
		excludeIps: Set<String>,
		probeTimeout: TimeInterval = 2
	) -> BeamioChatPgpKeychain.SiNode? {
		let blocked = Set(excludeIps.compactMap { normalizeIp($0) })
		stateLock.lock()
		let now = Date()
		unreachableUntil = unreachableUntil.filter { $0.value > now }
		let dead = Set(unreachableUntil.keys)
		let scores = entryScores
		stateLock.unlock()

		var pool: [BeamioChatPgpKeychain.SiNode] = []
		var seen = Set<String>()
		for node in nodes {
			guard let ip = normalizeIp(node.ip), !blocked.contains(ip), !dead.contains(ip), seen.insert(ip).inserted else { continue }
			pool.append(BeamioChatPgpKeychain.SiNode(ip: ip, domain: node.domain, region: node.region))
		}

		var probes = 0
		while !pool.isEmpty && probes < 6 {
			guard let picked = weightedPick(pool, scores: scores) else { return nil }
			probes += 1
			let probe = httpRequest(ip: picked.ip, method: "GET", path: "/", body: nil, timeout: probeTimeout, stopAfterStatusLine: true)
			if probe.status > 0 {
				scoreEntry(ip: picked.ip, reachable: true, latencyMs: probe.ms)
				return picked
			}
			NSLog("[BeamioSiPost] probe ip=%@ failed err=%@ ms=%d", picked.ip, probe.error, probe.ms)
			scoreEntry(ip: picked.ip, reachable: false, latencyMs: probe.ms)
			pool.removeAll { normalizeIp($0.ip) == picked.ip }
		}
		return nil
	}

	private static func weightedPick(
		_ pool: [BeamioChatPgpKeychain.SiNode],
		scores: [String: Int]
	) -> BeamioChatPgpKeychain.SiNode? {
		guard !pool.isEmpty else { return nil }
		let weights = pool.map { node -> Int in
			guard let ip = normalizeIp(node.ip) else { return 1 }
			return max(scores[ip] ?? 80, 1)
		}
		let total = weights.reduce(0, +)
		guard total > 0 else { return pool.randomElement() }
		var draw = Int.random(in: 0 ..< total)
		for (index, weight) in weights.enumerated() {
			draw -= weight
			if draw < 0 { return pool[index] }
		}
		return pool.last
	}

	// MARK: - One-shot POST

	/// Pick reachable, high-score roster IPs (mailbox B and caller excludes dropped)
	/// and POST until one 2xx. Each attempt is `http://{ip}/post`.
	public static func post(
		armor: String,
		nodes: [BeamioChatPgpKeychain.SiNode],
		excludeIps: Set<String>,
		maxAttempts: Int = 4,
		timeout: TimeInterval = 12
	) -> Result {
		let trimmed = armor.trimmingCharacters(in: .whitespacesAndNewlines)
		guard trimmed.contains("BEGIN PGP MESSAGE") else {
			return Result(ok: false, status: 0, body: "", error: "not_pgp")
		}
		guard let body = try? JSONSerialization.data(withJSONObject: ["data": trimmed]) else {
			return Result(ok: false, status: 0, body: "", error: "encode")
		}
		let blocked = Set(excludeIps.compactMap { normalizeIp($0) })
		let roster = nodes.compactMap { node -> BeamioChatPgpKeychain.SiNode? in
			guard let ip = normalizeIp(node.ip), !blocked.contains(ip) else { return nil }
			return BeamioChatPgpKeychain.SiNode(ip: ip, domain: node.domain, region: node.region)
		}
		guard !roster.isEmpty else {
			return Result(ok: false, status: 0, body: "", error: "no_si_roster")
		}

		var skip = excludeIps
		var lastStatus = 0
		var lastErr = ""
		let attempts = max(1, maxAttempts)
		let started = Date()
		for _ in 0 ..< attempts {
			// The PWA bridge waits 15 s for this call. Stay inside that budget.
			let remaining = totalBudgetSeconds - Date().timeIntervalSince(started)
			if remaining < 2.5 { break }
			guard let node = getRandomNode(nodes: roster, excludeIps: skip, probeTimeout: min(2, remaining / 3)) else {
				NSLog("[BeamioSiPost] no reachable entry left")
				return Result(ok: false, status: lastStatus, body: "", error: lastErr.isEmpty ? "post_failed" : lastErr)
			}
			skip.insert(node.ip)
			let left = totalBudgetSeconds - Date().timeIntervalSince(started)
			if left < 1.5 { break }
			let posted = httpRequest(
				ip: node.ip,
				method: "POST",
				path: "/post",
				body: body,
				timeout: min(timeout, left - 0.5),
				stopAfterStatusLine: false
			)
			lastStatus = posted.status
			if !posted.error.isEmpty { lastErr = posted.error }
			if (200 ..< 300).contains(posted.status) {
				let capped = posted.body.count > 48_000 ? String(posted.body.prefix(48_000)) : posted.body
				scoreEntry(ip: node.ip, reachable: true, latencyMs: posted.ms)
				// SI may return HTTP 200 with `{ "ok": false, "error": "…" }`
				// (e.g. voice_uplink target_voice_session_not_found). Trust body.
				if !bodyOk(capped) {
					NSLog("[BeamioSiPost] http 2xx but body ok=false ip=%@ status=%d", node.ip, posted.status)
					continue
				}
				NSLog("[BeamioSiPost] http ip=%@ ok status=%d ms=%d", node.ip, posted.status, posted.ms)
				return Result(ok: true, status: posted.status, body: capped, error: "")
			}
			NSLog("[BeamioSiPost] http ip=%@ post status=%d err=%@ ms=%d", node.ip, posted.status, posted.error, posted.ms)
			if posted.status == 0 {
				scoreEntry(ip: node.ip, reachable: false, latencyMs: posted.ms)
			} else {
				scoreEntry(ip: node.ip, reachable: true, latencyMs: 500)
			}
		}
		NSLog("[BeamioSiPost] http ip failed status=%d tried=%d lastErr=%@", lastStatus, attempts, lastErr.isEmpty ? "-" : lastErr)
		return Result(ok: false, status: lastStatus, body: "", error: lastErr.isEmpty ? "post_failed" : lastErr)
	}

	/// Prefer JSON `ok` / `success` when present; empty or non-JSON 2xx → true.
	private static func bodyOk(_ text: String) -> Bool {
		let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
		guard !trimmed.isEmpty,
		      let data = trimmed.data(using: .utf8),
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else {
			return true
		}
		if let ok = obj["ok"] as? Bool { return ok }
		if let success = obj["success"] as? Bool { return success }
		return true
	}

	// MARK: - Plain HTTP/1.1 over TCP (blocking)

	private final class RawBox {
		let lock = NSLock()
		var finished = false
		var status = 0
		var error = ""
		var buffer = Data()
	}

	/// Blocking HTTP/1.1 request to `ip:80`.
	/// `stopAfterStatusLine` ends as soon as the status line arrives (reachability probe).
	public static func httpRequest(
		ip rawIp: String,
		method: String,
		path: String,
		body: Data?,
		timeout: TimeInterval,
		stopAfterStatusLine: Bool
	) -> RawResponse {
		let started = Date()
		func elapsed() -> Int { Int(Date().timeIntervalSince(started) * 1000) }
		guard let ip = normalizeIp(rawIp), let port = NWEndpoint.Port(rawValue: 80) else {
			return RawResponse(status: 0, body: "", error: "bad_ip", ms: 0)
		}

		let hostHeader = ip.contains(":") ? "[\(ip)]" : ip
		var head = "\(method) \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: BeamioShell/1\r\nAccept: */*\r\nConnection: close\r\n"
		if let body {
			head += "Content-Type: application/json\r\nContent-Length: \(body.count)\r\n"
		}
		head += "\r\n"
		var requestData = Data(head.utf8)
		if let body { requestData.append(body) }

		let params = NWParameters.tcp
		if let tcp = params.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
			tcp.connectionTimeout = max(1, Int(timeout.rounded(.up)))
			tcp.noDelay = true
		}
		let conn = NWConnection(host: NWEndpoint.Host(ip), port: port, using: params)
		let queue = DispatchQueue(label: "beamio.sipost.http")
		let sem = DispatchSemaphore(value: 0)
		let box = RawBox()

		func finish(status: Int, error: String) {
			box.lock.lock()
			if box.finished {
				box.lock.unlock()
				return
			}
			box.finished = true
			box.status = status
			box.error = error
			box.lock.unlock()
			conn.cancel()
			sem.signal()
		}

		func snapshotAndMaybeFinish(isComplete: Bool) -> Bool {
			box.lock.lock()
			let data = box.buffer
			box.lock.unlock()
			guard let parsed = parseHttpResponse(data) else {
				if data.count > 64 * 1024 {
					finish(status: 0, error: "bad_response")
					return true
				}
				return false
			}
			if stopAfterStatusLine {
				finish(status: parsed.status, error: "")
				return true
			}
			if parsed.complete || isComplete {
				finish(status: parsed.status, error: "")
				return true
			}
			return false
		}

		func receiveLoop() {
			conn.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, isComplete, error in
				if let data, !data.isEmpty {
					box.lock.lock()
					box.buffer.append(data)
					box.lock.unlock()
				}
				if snapshotAndMaybeFinish(isComplete: isComplete || error != nil) { return }
				if let error {
					finish(status: 0, error: "recv:\(error)")
					return
				}
				if isComplete {
					finish(status: 0, error: "closed_no_status")
					return
				}
				receiveLoop()
			}
		}

		conn.stateUpdateHandler = { state in
			switch state {
			case .ready:
				conn.send(content: requestData, completion: .contentProcessed { error in
					if let error {
						finish(status: 0, error: "send:\(error)")
						return
					}
					receiveLoop()
				})
			case .failed(let error):
				finish(status: 0, error: "failed:\(error)")
			case .waiting(let error):
				// No route / refused / filtered. Do not sit in NWConnection's retry loop.
				finish(status: 0, error: "waiting:\(error)")
			default:
				break
			}
		}
		conn.start(queue: queue)

		if sem.wait(timeout: .now() + timeout + 0.5) == .timedOut {
			box.lock.lock()
			let alreadyDone = box.finished
			if !alreadyDone {
				box.finished = true
				box.status = 0
				box.error = "timeout"
			}
			box.lock.unlock()
			if !alreadyDone { conn.cancel() }
		}

		box.lock.lock()
		let status = box.status
		let error = box.error
		let buffer = box.buffer
		box.lock.unlock()
		let text = status > 0 ? (parseHttpResponse(buffer)?.bodyText ?? "") : ""
		return RawResponse(status: status, body: text, error: error, ms: elapsed())
	}

	private struct ParsedHttp {
		var status: Int
		var bodyText: String
		var complete: Bool
	}

	/// Status line plus whether the body is complete (Content-Length / chunked end).
	private static func parseHttpResponse(_ data: Data) -> ParsedHttp? {
		guard let headerEnd = data.range(of: Data("\r\n\r\n".utf8)) else {
			guard let lineEnd = data.range(of: Data("\r\n".utf8)),
			      let line = String(data: data[..<lineEnd.lowerBound], encoding: .utf8),
			      let status = statusCode(fromLine: line)
			else { return nil }
			return ParsedHttp(status: status, bodyText: "", complete: false)
		}
		guard let headText = String(data: data[..<headerEnd.lowerBound], encoding: .utf8) else { return nil }
		let lines = headText.components(separatedBy: "\r\n")
		guard let first = lines.first, let status = statusCode(fromLine: first) else { return nil }
		var contentLength: Int?
		var chunked = false
		for line in lines.dropFirst() {
			let lower = line.lowercased()
			if lower.hasPrefix("content-length:") {
				contentLength = Int(line.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces))
			} else if lower.hasPrefix("transfer-encoding:"), lower.contains("chunked") {
				chunked = true
			}
		}
		let bodyData = data[headerEnd.upperBound...]
		let rawBody = String(data: bodyData.prefix(48_000), encoding: .utf8) ?? ""
		var complete = false
		if status == 204 || status == 304 || (100 ..< 200).contains(status) {
			complete = true
		} else if let contentLength {
			complete = bodyData.count >= contentLength
		} else if chunked {
			complete = bodyData.suffix(5) == Data("0\r\n\r\n".utf8)
		}
		let bodyText = chunked ? decodeChunkedText(Data(bodyData)) : rawBody
		return ParsedHttp(status: status, bodyText: bodyText, complete: complete)
	}

	private static func statusCode(fromLine line: String) -> Int? {
		let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
		guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let code = Int(parts[1]) else { return nil }
		return code
	}

	/// Decode a complete-or-partial chunked body into UTF-8 text (best effort).
	private static func decodeChunkedText(_ data: Data) -> String {
		var out = Data()
		var rest = data[...]
		let crlf = Data("\r\n".utf8)
		while let lineEnd = rest.range(of: crlf) {
			let sizeLine = String(data: rest[..<lineEnd.lowerBound], encoding: .utf8) ?? ""
			let hex = sizeLine.split(separator: ";").first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
			guard let size = Int(hex, radix: 16) else { break }
			let start = lineEnd.upperBound
			if size == 0 { break }
			guard rest.distance(from: start, to: rest.endIndex) >= size else {
				out.append(rest[start...])
				break
			}
			let end = rest.index(start, offsetBy: size)
			out.append(rest[start ..< end])
			let after = rest.index(end, offsetBy: min(2, rest.distance(from: end, to: rest.endIndex)))
			rest = rest[after...]
		}
		return String(data: out.prefix(48_000), encoding: .utf8) ?? ""
	}

	// MARK: - Long-lived SSE POST

	/// Handle for a running SSE stream. Call `cancel()` to close it.
	public final class SseHandle {
		private let lock = NSLock()
		private var action: (() -> Void)?
		private var cancelled = false

		fileprivate func install(_ cancel: @escaping () -> Void) {
			lock.lock()
			action = cancel
			let already = cancelled
			lock.unlock()
			if already { cancel() }
		}

		public func cancel() {
			lock.lock()
			cancelled = true
			let a = action
			lock.unlock()
			a?()
		}
	}

	/// Long-lived SSE POST for mailbox listen over plain HTTP/1.1 (chunked or raw body).
	/// Invokes `onEvent` for each SSE data block (joined `data:` lines).
	@discardableResult
	public static func postSse(
		url: URL,
		armor: String,
		connectTimeout: TimeInterval = 12,
		idleTimeout: TimeInterval = 120,
		onOpen: (() -> Void)? = nil,
		onEvent: @escaping (_ payload: String) -> Void,
		onClosed: @escaping (_ error: String?) -> Void
	) -> SseHandle? {
		let trimmed = armor.trimmingCharacters(in: .whitespacesAndNewlines)
		guard trimmed.contains("BEGIN PGP MESSAGE"),
		      let body = try? JSONSerialization.data(withJSONObject: ["data": trimmed])
		else {
			onClosed("not_pgp")
			return nil
		}
		guard let host = url.host, let ip = normalizeIp(host) else {
			onClosed("bad_ip")
			return nil
		}
		var path = url.path.isEmpty ? "/" : url.path
		if let q = url.query, !q.isEmpty { path += "?\(q)" }
		let stream = RawSseStream(
			ip: ip,
			path: path,
			body: body,
			connectTimeout: connectTimeout,
			idleTimeout: idleTimeout,
			onOpen: onOpen,
			onEvent: onEvent,
			onClosed: onClosed
		)
		let handle = SseHandle()
		handle.install { stream.cancel() }
		stream.start()
		return handle
	}
}

/// One SSE connection: POST, parse response headers, decode chunked/raw body, split events.
private final class RawSseStream {
	private let ip: String
	private let path: String
	private let body: Data
	private let connectTimeout: TimeInterval
	private let idleTimeout: TimeInterval
	private let onOpen: (() -> Void)?
	private let onEvent: (String) -> Void
	private let onClosed: (String?) -> Void

	private let queue = DispatchQueue(label: "beamio.sipost.sse")
	private var conn: NWConnection?
	private var timer: DispatchSourceTimer?
	private let lock = NSLock()
	private var closed = false
	private var opened = false
	private var started = Date()
	private var lastActivity = Date()

	private var rx = Data()
	private var headerParsed = false
	private var chunked = false
	private var chunkRemaining: Int?
	private var needChunkCrlf = false
	private var sseBuf = Data()

	init(
		ip: String,
		path: String,
		body: Data,
		connectTimeout: TimeInterval,
		idleTimeout: TimeInterval,
		onOpen: (() -> Void)?,
		onEvent: @escaping (String) -> Void,
		onClosed: @escaping (String?) -> Void
	) {
		self.ip = ip
		self.path = path
		self.body = body
		self.connectTimeout = connectTimeout
		self.idleTimeout = idleTimeout
		self.onOpen = onOpen
		self.onEvent = onEvent
		self.onClosed = onClosed
	}

	func start() {
		guard let port = NWEndpoint.Port(rawValue: 80) else {
			finish("bad_port")
			return
		}
		let hostHeader = ip.contains(":") ? "[\(ip)]" : ip
		var head = "POST \(path) HTTP/1.1\r\nHost: \(hostHeader)\r\nUser-Agent: BeamioShell/1\r\n"
		head += "Content-Type: application/json;charset=UTF-8\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\n"
		head += "Connection: keep-alive\r\nContent-Length: \(body.count)\r\n\r\n"
		var request = Data(head.utf8)
		request.append(body)

		let params = NWParameters.tcp
		if let tcp = params.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
			tcp.connectionTimeout = max(1, Int(connectTimeout.rounded(.up)))
			tcp.noDelay = true
			tcp.enableKeepalive = true
			tcp.keepaliveIdle = 30
		}
		let connection = NWConnection(host: NWEndpoint.Host(ip), port: port, using: params)
		conn = connection
		started = Date()
		lastActivity = Date()

		connection.stateUpdateHandler = { [weak self] state in
			guard let self else { return }
			switch state {
			case .ready:
				connection.send(content: request, completion: .contentProcessed { [weak self] error in
					if let error {
						self?.finish("connect:send:\(error)")
						return
					}
					self?.receiveLoop()
				})
			case .failed(let error):
				self.finish("connect:failed:\(error)")
			case .waiting(let error):
				self.finish("connect:waiting:\(error)")
			default:
				break
			}
		}
		connection.start(queue: queue)

		let t = DispatchSource.makeTimerSource(queue: queue)
		t.schedule(deadline: .now() + 2, repeating: 2)
		t.setEventHandler { [weak self] in self?.tick() }
		timer = t
		t.resume()
	}

	func cancel() {
		finish("cancelled")
	}

	private func tick() {
		lock.lock()
		let isClosed = closed
		let isOpened = opened
		let started = self.started
		let last = lastActivity
		lock.unlock()
		if isClosed { return }
		if !isOpened, Date().timeIntervalSince(started) > connectTimeout + 3 {
			finish("connect:timeout")
			return
		}
		if isOpened, Date().timeIntervalSince(last) > idleTimeout {
			finish("idle_timeout")
		}
	}

	private func receiveLoop() {
		guard let conn else { return }
		conn.receive(minimumIncompleteLength: 1, maximumLength: 32 * 1024) { [weak self] data, _, isComplete, error in
			guard let self else { return }
			if let data, !data.isEmpty {
				self.lock.lock()
				self.lastActivity = Date()
				self.lock.unlock()
				self.consume(data)
			}
			if self.isClosed { return }
			if let error {
				self.finish(self.wasOpened ? "recv:\(error)" : "connect:recv:\(error)")
				return
			}
			if isComplete {
				self.finish(self.wasOpened ? nil : "connect:closed_no_status")
				return
			}
			self.receiveLoop()
		}
	}

	private var isClosed: Bool {
		lock.lock(); defer { lock.unlock() }
		return closed
	}

	private var wasOpened: Bool {
		lock.lock(); defer { lock.unlock() }
		return opened
	}

	private func consume(_ data: Data) {
		rx.append(data)
		if !headerParsed {
			guard let end = rx.range(of: Data("\r\n\r\n".utf8)) else {
				if rx.count > 64 * 1024 { finish("connect:bad_response") }
				return
			}
			let headText = String(data: rx[..<end.lowerBound], encoding: .utf8) ?? ""
			rx.removeSubrange(..<end.upperBound)
			let lines = headText.components(separatedBy: "\r\n")
			let parts = (lines.first ?? "").split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
			guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let status = Int(parts[1]) else {
				finish("connect:bad_status_line")
				return
			}
			guard (200 ..< 300).contains(status) else {
				BeamioSiCipherPost.scoreEntry(ip: ip, reachable: true, latencyMs: 500)
				finish("HTTP \(status)")
				return
			}
			chunked = lines.dropFirst().contains { $0.lowercased().hasPrefix("transfer-encoding:") && $0.lowercased().contains("chunked") }
			headerParsed = true
			let ms = Int(Date().timeIntervalSince(started) * 1000)
			BeamioSiCipherPost.scoreEntry(ip: ip, reachable: true, latencyMs: ms)
			lock.lock()
			opened = true
			lock.unlock()
			onOpen?()
		}
		if chunked { drainChunked() } else { drainRaw() }
	}

	private func drainRaw() {
		if rx.isEmpty { return }
		sseBuf.append(rx)
		rx.removeAll(keepingCapacity: true)
		emitEvents()
	}

	private func drainChunked() {
		let crlf = Data("\r\n".utf8)
		while !isClosed {
			if needChunkCrlf {
				guard rx.count >= 2 else { return }
				rx.removeSubrange(..<(rx.startIndex + 2))
				needChunkCrlf = false
			}
			if chunkRemaining == nil {
				guard let lineEnd = rx.range(of: crlf) else { return }
				let line = String(data: rx[..<lineEnd.lowerBound], encoding: .utf8) ?? ""
				rx.removeSubrange(..<lineEnd.upperBound)
				let hex = line.split(separator: ";").first.map(String.init)?.trimmingCharacters(in: .whitespaces) ?? ""
				guard let size = Int(hex, radix: 16) else {
					finish("bad_chunk")
					return
				}
				if size == 0 {
					finish(nil)
					return
				}
				chunkRemaining = size
			}
			guard let remaining = chunkRemaining else { return }
			if rx.isEmpty { return }
			let take = min(remaining, rx.count)
			sseBuf.append(rx.prefix(take))
			rx.removeSubrange(..<(rx.startIndex + take))
			if take == remaining {
				chunkRemaining = nil
				needChunkCrlf = true
			} else {
				chunkRemaining = remaining - take
			}
			emitEvents()
		}
	}

	private func emitEvents() {
		while let (blockEnd, consume) = nextBoundary() {
			let block = sseBuf.subdata(in: sseBuf.startIndex ..< (sseBuf.startIndex + blockEnd))
			sseBuf.removeSubrange(..<(sseBuf.startIndex + blockEnd + consume))
			if let text = String(data: block, encoding: .utf8) {
				let payload = Self.sseDataPayload(from: text)
				if !payload.isEmpty { onEvent(payload) }
			}
		}
	}

	/// Earliest blank-line boundary (`\n\n` or `\r\n\r\n`) → (block length, separator length).
	private func nextBoundary() -> (Int, Int)? {
		let a = sseBuf.range(of: Data("\r\n\r\n".utf8))
		let b = sseBuf.range(of: Data("\n\n".utf8))
		switch (a, b) {
		case (nil, nil):
			return nil
		case (let r?, nil):
			return (r.lowerBound - sseBuf.startIndex, 4)
		case (nil, let r?):
			return (r.lowerBound - sseBuf.startIndex, 2)
		case (let ra?, let rb?):
			if ra.lowerBound <= rb.lowerBound {
				return (ra.lowerBound - sseBuf.startIndex, 4)
			}
			return (rb.lowerBound - sseBuf.startIndex, 2)
		}
	}

	private static func sseDataPayload(from block: String) -> String {
		let lines = block.split(separator: "\n", omittingEmptySubsequences: false).map {
			$0.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
		}
		let dataLines = lines.filter { $0.hasPrefix("data:") }.map {
			String($0.dropFirst(5)).trimmingCharacters(in: .whitespaces)
		}
		if !dataLines.isEmpty { return dataLines.joined(separator: "\n") }
		return block.trimmingCharacters(in: .whitespacesAndNewlines)
	}

	private func finish(_ err: String?) {
		lock.lock()
		guard !closed else {
			lock.unlock()
			return
		}
		closed = true
		let wasOpen = opened
		lock.unlock()
		timer?.cancel()
		timer = nil
		conn?.cancel()
		conn = nil
		if !wasOpen, let err, err.hasPrefix("connect:") {
			let ms = Int(Date().timeIntervalSince(started) * 1000)
			BeamioSiCipherPost.scoreEntry(ip: ip, reachable: false, latencyMs: ms)
			NSLog("[BeamioSiPost] sse ip=%@ failed err=%@ ms=%d", ip, err, ms)
		}
		onClosed(err)
	}
}
