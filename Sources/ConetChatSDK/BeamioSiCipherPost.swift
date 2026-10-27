import Foundation
import ObjectiveC

/// One-shot OpenPGP ciphertext POST for the native shell.
/// Target is `http://{Guardian ip}/post` with body `{ "data": armor }` only.
/// The shell picks the entry IP from its roster and never lets the PWA name a URL.
public enum BeamioSiCipherPost {
	public struct Result {
		public var ok: Bool
		public var status: Int
		public var body: String
		public var error: String
	}

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

	public static func postUrl(for ip: String) -> URL? {
		guard let ip = normalizeIp(ip) else { return nil }
		if ip.contains(":") {
			return URL(string: "http://[\(ip)]/post")
		}
		return URL(string: "http://\(ip)/post")
	}

	/// Shuffle roster IPs, drop mailbox B and caller excludes, POST until one 2xx.
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
		let blocked = Set(excludeIps.compactMap { normalizeIp($0) })
		var ips = nodes.compactMap { normalizeIp($0.ip) }.filter { !blocked.contains($0) }
		ips = Array(Set(ips)).shuffled()
		guard !ips.isEmpty else {
			return Result(ok: false, status: 0, body: "", error: "no_si_roster")
		}
		guard let body = try? JSONSerialization.data(withJSONObject: ["data": trimmed]) else {
			return Result(ok: false, status: 0, body: "", error: "encode")
		}
		let attempts = ips.prefix(max(1, maxAttempts))
		var lastStatus = 0
		var lastErr = ""
		for ip in attempts {
			guard let url = postUrl(for: ip) else { continue }
			var request = URLRequest(url: url, timeoutInterval: timeout)
			request.httpMethod = "POST"
			request.setValue("application/json", forHTTPHeaderField: "Content-Type")
			request.httpBody = body
			let sem = DispatchSemaphore(value: 0)
			var status = 0
			var text = ""
			var transportErr = ""
			let task = URLSession.shared.dataTask(with: request) { data, response, error in
				status = (response as? HTTPURLResponse)?.statusCode ?? 0
				if let data, let s = String(data: data, encoding: .utf8) {
					text = s
				}
				if let error {
					transportErr = error.localizedDescription
				}
				sem.signal()
			}
			task.resume()
			let waited = sem.wait(timeout: .now() + timeout + 1)
			if waited == .timedOut {
				task.cancel()
				transportErr = transportErr.isEmpty ? "sem_timeout" : transportErr
				NSLog("[BeamioSiPost] ip=%@ sem_timeout", ip)
			}
			lastStatus = status
			if !transportErr.isEmpty { lastErr = transportErr }
			if status == 0, !transportErr.isEmpty {
				NSLog("[BeamioSiPost] ip=%@ status=0 err=%@", ip, transportErr)
			}
			if (200 ..< 300).contains(status) {
				let capped = text.count > 48_000 ? String(text.prefix(48_000)) : text
				// SI may return HTTP 200 with `{ "ok": false, "error": "…" }`
				// (e.g. voice_uplink target_voice_session_not_found). Trust body.
				if !bodyOk(capped) {
					NSLog("[BeamioSiPost] http 2xx but body ok=false status=%d", status)
					continue
				}
				NSLog("[BeamioSiPost] http ip ok status=%d", status)
				return Result(ok: true, status: status, body: capped, error: "")
			}
		}
		NSLog(
			"[BeamioSiPost] http ip failed status=%d tried=%d lastErr=%@",
			lastStatus,
			attempts.count,
			lastErr.isEmpty ? "-" : lastErr
		)
		return Result(
			ok: false,
			status: lastStatus,
			body: "",
			error: lastErr.isEmpty ? "post_failed" : lastErr
		)
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

	/// Long-lived SSE POST for mailbox listen. Caller owns cancel via `task.cancel()`.
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
	) -> URLSessionDataTask? {
		let trimmed = armor.trimmingCharacters(in: .whitespacesAndNewlines)
		guard trimmed.contains("BEGIN PGP MESSAGE"),
		      let body = try? JSONSerialization.data(withJSONObject: ["data": trimmed])
		else {
			onClosed("not_pgp")
			return nil
		}
		var request = URLRequest(url: url, timeoutInterval: idleTimeout)
		request.httpMethod = "POST"
		request.setValue("application/json;charset=UTF-8", forHTTPHeaderField: "Content-Type")
		request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
		request.setValue("keep-alive", forHTTPHeaderField: "Connection")
		request.httpBody = body
		request.timeoutInterval = idleTimeout

		let config = URLSessionConfiguration.ephemeral
		config.timeoutIntervalForRequest = idleTimeout
		config.timeoutIntervalForResource = 60 * 60 * 6
		config.waitsForConnectivity = true
		let delegate = SseStreamDelegate(
			onOpen: onOpen,
			onEvent: onEvent,
			onClosed: onClosed
		)
		let streamSession = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
		let streamTask = streamSession.dataTask(with: request)
		objc_setAssociatedObject(streamTask, &SseStreamDelegate.assocKey, delegate, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
		objc_setAssociatedObject(streamTask, &SseStreamDelegate.sessionKey, streamSession, .OBJC_ASSOCIATION_RETAIN_NONATOMIC)
		streamTask.resume()
		return streamTask
	}
}

private final class SseStreamDelegate: NSObject, URLSessionDataDelegate {
	static var assocKey: UInt8 = 0
	static var sessionKey: UInt8 = 0

	private let onOpen: (() -> Void)?
	private let onEvent: (String) -> Void
	private let onClosed: (String?) -> Void
	private var buffer = Data()
	private var opened = false
	private var closed = false
	private let lock = NSLock()

	init(
		onOpen: (() -> Void)?,
		onEvent: @escaping (String) -> Void,
		onClosed: @escaping (String?) -> Void
	) {
		self.onOpen = onOpen
		self.onEvent = onEvent
		self.onClosed = onClosed
	}

	func urlSession(
		_ session: URLSession,
		dataTask: URLSessionDataTask,
		didReceive response: URLResponse,
		completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
	) {
		let status = (response as? HTTPURLResponse)?.statusCode ?? 0
		if (200 ..< 300).contains(status) {
			lock.lock()
			if !opened {
				opened = true
				lock.unlock()
				onOpen?()
			} else {
				lock.unlock()
			}
			completionHandler(.allow)
		} else {
			finish("HTTP \(status)")
			completionHandler(.cancel)
		}
	}

	func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
		lock.lock()
		buffer.append(data)
		while true {
			guard let range = firstEventBoundary(in: buffer) else { break }
			let blockData = buffer.subdata(in: 0 ..< range.location)
			buffer.removeSubrange(0 ..< (range.location + range.length))
			lock.unlock()
			if let text = String(data: blockData, encoding: .utf8) {
				let payload = sseDataPayload(from: text)
				if !payload.isEmpty { onEvent(payload) }
			}
			lock.lock()
		}
		lock.unlock()
	}

	func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
		if let error {
			finish(error.localizedDescription)
		} else {
			finish(nil)
		}
	}

	private func finish(_ err: String?) {
		lock.lock()
		guard !closed else {
			lock.unlock()
			return
		}
		closed = true
		lock.unlock()
		onClosed(err)
	}

	private func firstEventBoundary(in data: Data) -> NSRange? {
		guard let s = String(data: data, encoding: .utf8) else { return nil }
		if let r = s.range(of: "\r\n\r\n") {
			let loc = s.distance(from: s.startIndex, to: r.lowerBound)
			return NSRange(location: loc, length: 4)
		}
		if let r = s.range(of: "\n\n") {
			let loc = s.distance(from: s.startIndex, to: r.lowerBound)
			return NSRange(location: loc, length: 2)
		}
		return nil
	}

	private func sseDataPayload(from block: String) -> String {
		let lines = block.split(separator: "\n", omittingEmptySubsequences: false).map {
			$0.trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
		}
		let dataLines = lines.filter { $0.hasPrefix("data:") }.map {
			String($0.dropFirst(5)).trimmingCharacters(in: .whitespaces)
		}
		if !dataLines.isEmpty { return dataLines.joined(separator: "\n") }
		return block.trimmingCharacters(in: .whitespacesAndNewlines)
	}
}
