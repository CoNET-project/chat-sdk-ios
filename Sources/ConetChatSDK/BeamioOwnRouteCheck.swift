import CryptoKit
import Foundation

/// Own mailbox route vs the chain record (AddressPGP `searchKey`).
///
/// 2026-11-02 RC3: a listen ran on a mailbox the chain never had. The page had
/// picked a random node after a failed chain read and handed it to the module,
/// so calls and cancels sent to the chain mailbox never arrived. The module now
/// logs the route key ID of every listen and checks it against the chain once a
/// listen starts: a failed read is retried with backoff (never treated as "no
/// record"), and a different chain route wins: the listen reopens on it.
///
/// The route key ID is the key ID of the route key's encryption subkey: that is
/// what AddressPGP stores as `routePgpKeyID` and what SI node domains are named
/// after. Only key IDs are logged, never armor or wallet addresses.
enum BeamioOwnRouteCheck {
	static let addressPgp = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2"
	/// keccak256("searchKey(address)")[0..4]
	private static let searchKeySelector = "052f2778"
	/// Waits between chain reads while they fail (seconds); the last one repeats.
	static let retryDelays: [TimeInterval] = [5, 15, 30, 60, 120, 300]

	enum ChainRoute: Equatable {
		case ok(routeKeyId: String, routeArmor: String)
		/// The read worked; the account has no route on chain.
		case empty
		/// RPC error, timeout, bad reply: unknown, never "no record".
		case error(String)
	}

	enum Verdict: Equatable {
		case match
		case switchTo(routeKeyId: String, routeArmor: String)
		/// Chain has no route: keep listening; registering is the page's job.
		case noRoute
		case retry(String)
	}

	static func verdict(listenArmor: String, chain: ChainRoute) -> Verdict {
		switch chain {
		case .error(let why):
			return .retry(why)
		case .empty:
			return .noRoute
		case .ok(let id, let armor):
			let listenId = routeKeyId(listenArmor)
			let chainId = (id.isEmpty ? routeKeyId(armor) : id).uppercased()
			let same: Bool
			if !listenId.isEmpty, !chainId.isEmpty {
				same = listenId == chainId
			} else {
				same = normalizedArmorBody(listenArmor) == normalizedArmorBody(armor) && !normalizedArmorBody(armor).isEmpty
			}
			return same ? .match : .switchTo(routeKeyId: chainId, routeArmor: armor)
		}
	}

	/// Read until one read works, sleeping `retryDelays` after each failure.
	/// `sleep` returns false to give up (session gone). Returns the last verdict.
	static func reconcile(
		listenArmor: () -> String,
		read: () -> ChainRoute,
		sleep: (TimeInterval) -> Bool,
		onRetry: (String, TimeInterval) -> Void = { _, _ in }
	) -> Verdict {
		var attempt = 0
		while true {
			let v = verdict(listenArmor: listenArmor(), chain: read())
			guard case .retry(let why) = v else { return v }
			let wait = retryDelays[min(attempt, retryDelays.count - 1)]
			attempt += 1
			onRetry(why, wait)
			if !sleep(wait) { return v }
		}
	}

	// MARK: - Key ID

	/// Route key ID (encryption subkey, else primary), upper-case hex; "" if unreadable.
	static func routeKeyId(_ armor: String) -> String {
		guard let bytes = dearmor(armor) else { return "" }
		var primary = ""
		var pos = 0
		while pos < bytes.count {
			let head = Int(bytes[pos])
			if head & 0x80 == 0 { return primary }
			var tag: Int
			var len: Int
			var p = pos + 1
			if head & 0x40 != 0 {
				tag = head & 0x3F
				guard p < bytes.count else { return primary }
				let o1 = Int(bytes[p])
				if o1 < 192 {
					len = o1; p += 1
				} else if o1 < 224 {
					guard p + 1 < bytes.count else { return primary }
					len = ((o1 - 192) << 8) + Int(bytes[p + 1]) + 192; p += 2
				} else if o1 == 255 {
					guard p + 4 < bytes.count else { return primary }
					len = readBe(bytes, p + 1, 4); p += 5
				} else {
					return primary // partial lengths never appear in key packets
				}
			} else {
				tag = (head >> 2) & 0x0F
				switch head & 0x03 {
				case 0:
					guard p < bytes.count else { return primary }
					len = Int(bytes[p]); p += 1
				case 1:
					guard p + 1 < bytes.count else { return primary }
					len = readBe(bytes, p, 2); p += 2
				case 2:
					guard p + 3 < bytes.count else { return primary }
					len = readBe(bytes, p, 4); p += 4
				default:
					return primary
				}
			}
			guard len >= 0, p + len <= bytes.count else { return primary }
			if tag == 6 || tag == 14 {
				let id = keyIdOfPacket(Array(bytes[p ..< p + len]))
				if tag == 14, !id.isEmpty { return id }
				if tag == 6, primary.isEmpty { primary = id }
			}
			pos = p + len
		}
		return primary
	}

	private static func keyIdOfPacket(_ body: [UInt8]) -> String {
		guard let version = body.first else { return "" }
		let len = body.count
		switch version {
		case 4:
			var h = Insecure.SHA1()
			h.update(data: [0x99, UInt8((len >> 8) & 0xFF), UInt8(len & 0xFF)])
			h.update(data: body)
			return hex(Array(h.finalize()).suffix(8))
		case 6:
			var h = SHA256()
			h.update(data: [0x9B, UInt8((len >> 24) & 0xFF), UInt8((len >> 16) & 0xFF), UInt8((len >> 8) & 0xFF), UInt8(len & 0xFF)])
			h.update(data: body)
			return hex(Array(h.finalize()).prefix(8))
		default:
			return ""
		}
	}

	private static func dearmor(_ armor: String) -> [UInt8]? {
		let lines = armor.replacingOccurrences(of: "\r", with: "")
			.components(separatedBy: "\n")
			.map { $0.trimmingCharacters(in: .whitespaces) }
		guard let begin = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK") }),
		      let end = lines.firstIndex(where: { $0.hasPrefix("-----END PGP PUBLIC KEY BLOCK") }),
		      end > begin
		else { return nil }
		let body = lines[(begin + 1) ..< end]
			.filter { !$0.isEmpty && !$0.hasPrefix("=") && !$0.contains(":") }
			.joined()
		guard let data = Data(base64Encoded: body) else { return nil }
		return [UInt8](data)
	}

	private static func normalizedArmorBody(_ armor: String) -> String {
		armor.replacingOccurrences(of: "\r", with: "")
			.components(separatedBy: "\n")
			.map { $0.trimmingCharacters(in: .whitespaces) }
			.filter { !$0.isEmpty && !$0.hasPrefix("-----") && !$0.contains(":") }
			.joined()
	}

	// MARK: - Chain read

	static func searchKeyCallData(eoa: String) -> String? {
		var addr = eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		if addr.hasPrefix("0x") { addr.removeFirst(2) }
		guard addr.count == 40, addr.allSatisfy({ $0.isHexDigit }) else { return nil }
		return "0x\(searchKeySelector)\(String(repeating: "0", count: 24))\(addr)"
	}

	/// ABI-decode `searchKey` → (userPgpKeyID, userPublicKeyArmored, routePgpKeyID, routePublicKeyArmored(base64), routeOnline).
	static func decodeSearchKeyResult(_ resultHex: String) -> ChainRoute {
		var raw = resultHex.trimmingCharacters(in: .whitespacesAndNewlines)
		if raw.hasPrefix("0x") { raw.removeFirst(2) }
		guard !raw.isEmpty, raw.count % 2 == 0 else { return .error("empty_reply") }
		var data = [UInt8]()
		data.reserveCapacity(raw.count / 2)
		var i = raw.startIndex
		while i < raw.endIndex {
			let j = raw.index(i, offsetBy: 2)
			guard let b = UInt8(raw[i ..< j], radix: 16) else { return .error("bad_reply") }
			data.append(b)
			i = j
		}
		guard data.count >= 5 * 32 else { return .error("short_reply") }
		guard let routeId = abiString(data, 2)?.trimmingCharacters(in: .whitespacesAndNewlines),
		      let routeB64 = abiString(data, 3)?.trimmingCharacters(in: .whitespacesAndNewlines)
		else { return .error("bad_reply") }
		if routeId.isEmpty, routeB64.isEmpty { return .empty }
		let compact = routeB64.components(separatedBy: .whitespacesAndNewlines).joined()
		let armor = Data(base64Encoded: compact)
			.flatMap { String(data: $0, encoding: .utf8) }?
			.replacingOccurrences(of: "\r", with: "")
			.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
		guard armor.contains("BEGIN PGP PUBLIC KEY") else { return .empty }
		return .ok(routeKeyId: routeId.uppercased(), routeArmor: armor)
	}

	private static func abiString(_ data: [UInt8], _ index: Int) -> String? {
		guard let off = readWord(data, index * 32), let len = readWord(data, off),
		      off + 32 + len <= data.count
		else { return nil }
		return String(bytes: data[(off + 32) ..< (off + 32 + len)], encoding: .utf8)
	}

	/// One `eth_call` (no `from`). Blocking; call off the main thread.
	static func readChainRoute(rpcUrl: String, eoa: String, timeout: TimeInterval = 8) -> ChainRoute {
		guard let data = searchKeyCallData(eoa: eoa) else { return .error("bad_address") }
		guard let url = URL(string: rpcUrl) else { return .error("bad_rpc_url") }
		let body: [String: Any] = [
			"jsonrpc": "2.0", "id": 1, "method": "eth_call",
			"params": [["to": addressPgp, "data": data], "latest"],
		]
		guard let payload = try? JSONSerialization.data(withJSONObject: body) else { return .error("encode") }
		var req = URLRequest(url: url, timeoutInterval: timeout)
		req.httpMethod = "POST"
		req.setValue("application/json", forHTTPHeaderField: "Content-Type")
		req.httpBody = payload
		let sem = DispatchSemaphore(value: 0)
		let box = Box()
		URLSession(configuration: .ephemeral).dataTask(with: req) { d, resp, err in
			box.set((resp as? HTTPURLResponse)?.statusCode ?? 0, d, err)
			sem.signal()
		}.resume()
		if sem.wait(timeout: .now() + timeout + 2) == .timedOut { return .error("timeout") }
		let (status, d, err) = box.get()
		if let err { return .error((err as NSError).domain + ":\((err as NSError).code)") }
		guard (200 ..< 300).contains(status), let d,
		      let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any]
		else { return .error("HTTP \(status)") }
		if obj["error"] != nil { return .error("rpc_error") }
		return decodeSearchKeyResult(obj["result"] as? String ?? "")
	}

	private final class Box {
		private let lock = NSLock()
		private var value: (Int, Data?, Error?) = (0, nil, nil)
		func set(_ s: Int, _ d: Data?, _ e: Error?) { lock.lock(); value = (s, d, e); lock.unlock() }
		func get() -> (Int, Data?, Error?) { lock.lock(); defer { lock.unlock() }; return value }
	}

	private static func readBe(_ b: [UInt8], _ off: Int, _ n: Int) -> Int {
		var v = 0
		for i in 0 ..< n { v = (v << 8) | Int(b[off + i]) }
		return v
	}

	private static func readWord(_ b: [UInt8], _ off: Int) -> Int? {
		guard off >= 0, off + 32 <= b.count else { return nil }
		for i in 0 ..< 24 where b[off + i] != 0 { return nil }
		var v = 0
		for i in 24 ..< 32 { v = (v << 8) | Int(b[off + i]) }
		return v
	}

	private static func hex<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
		bytes.map { String(format: "%02X", $0) }.joined()
	}
}
