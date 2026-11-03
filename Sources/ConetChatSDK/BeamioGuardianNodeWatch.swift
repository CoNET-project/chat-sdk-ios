import Foundation

/// CoNET DePIN node table, kept by the SDK from the chain (same rules as the
/// CoNET-SI node table watcher, `src/util/guardianNodes.ts`).
///
/// GuardianNodesInfoV6 emits only `deleteIPAddr`; adds and IP/PGP changes write
/// storage without an event. So each poll reads the contract's storage root
/// (`eth_getProof` → `storageHash`) at head − 2 blocks. Only when it differs from
/// the root the current table was built from is the full table read, pinned to
/// that block, every page or nothing. If the RPC stops serving `eth_getProof`,
/// `eth_getLogs` on the contract plus a short block scan are the detector. A full
/// read happens at least once a day. A read that is empty, or drops below half of
/// a 20+ node table without a confirming second read 20 minutes later, is refused.
///
/// The table is cached in the Keychain (`storeChainRoster`), so a push wake starts
/// from the cache at once and checks the chain in the background. Removed nodes
/// leave the entry pool at once; new ones enter only after a probe.
///
/// Polls only while the SDK is active (driven by `BeamioEntryPool`'s refresh).
/// Public RPC only: no wallet, no signature.
public final class BeamioGuardianNodeWatch {
	public static let shared = BeamioGuardianNodeWatch()

	static let contract = "0xBC6b53065b5647261396d002bDBA0d3396E0722f"
	static let getAllNodesSelector = "4272c81e"  // getAllNodes(uint256,uint256)
	static let rpcs = ["https://publicrpc.conet.network", "https://rpc1.conet.network"]
	static let confirmations = 2
	static let pollInterval: TimeInterval = 30
	static let pageSize = 100
	static let maxTxScanBlocks = 30
	static let logsChunk = 4_000
	static let minFullReadInterval: TimeInterval = 60
	static let forceFullReadInterval: TimeInterval = 24 * 3600
	static let failBackoffBase: TimeInterval = 30
	static let failBackoffMax: TimeInterval = 15 * 60
	static let shrinkConfirm: TimeInterval = 20 * 60

	private let queue = DispatchQueue(label: "beamio.guardian.watch")
	private let defaults = UserDefaults.standard
	private let keyRoot = "beamio.guardian.storageRoot"
	private let keyBlock = "beamio.guardian.block"
	private let keyBuiltAt = "beamio.guardian.builtAt"

	private var running = false
	private var lastPoll = Date.distantPast
	private var lastFullRead = Date.distantPast
	private var failures = 0
	private var notBefore = Date.distantPast
	private var proofUnsupported = false
	private var pendingShrink: (count: Int, firstSeen: Date)?

	private init() {}

	/// Called from the entry pool's refresh while the SDK is active.
	func tick() {
		queue.async { [weak self] in
			guard let self else { return }
			if Date().timeIntervalSince(self.lastPoll) >= Self.pollInterval { self.poll(reason: "poll") }
		}
	}

	/// Launch, foreground, push wake: check now (full read at once when no table is cached).
	public func kick() {
		queue.async { [weak self] in self?.poll(reason: "kick") }
	}

	/// On `queue`.
	private func poll(reason: String) {
		guard !running, Date() >= notBefore else { return }
		running = true
		lastPoll = Date()
		defer { running = false }

		guard let head = blockNumber() else { return fail("blockNumber") }
		let target = max(0, head - Self.confirmations)
		let cached = BeamioChatPgpKeychain.loadSiNodes()
		let builtRoot = defaults.string(forKey: keyRoot) ?? ""
		let builtBlock = defaults.integer(forKey: keyBlock)
		let builtAt = Date(timeIntervalSince1970: defaults.double(forKey: keyBuiltAt))

		var changed = cached.isEmpty || builtRoot.isEmpty
		var why = changed ? "no table" : ""
		var root = ""
		if !proofUnsupported {
			switch storageRoot(at: target) {
			case .value(let r):
				root = r
				if r != builtRoot {
					changed = true
					why = why.isEmpty ? "storage root changed" : why
				}
			case .unsupported:
				proofUnsupported = true
				NSLog("[BeamioGuardian] eth_getProof unsupported; using logs and block scan")
			case .failed:
				return fail("getProof")
			}
		}
		if proofUnsupported, !changed, builtBlock > 0, target > builtBlock {
			switch contractTouched(from: builtBlock, to: target) {
			case .some(true):
				changed = true
				why = "contract touched"
			case .some(false):
				break
			case .none:
				return fail("logs")
			}
		}
		if !changed, Date().timeIntervalSince(builtAt) > Self.forceFullReadInterval {
			changed = true
			why = "daily read"
		}
		if !changed {
			failures = 0
			// Nothing to read; remember how far we checked for the log fallback.
			if proofUnsupported { defaults.set(target, forKey: keyBlock) }
			return
		}
		if Date().timeIntervalSince(lastFullRead) < Self.minFullReadInterval, !cached.isEmpty { return }

		lastFullRead = Date()
		guard let rows = readAll(at: target) else { return fail("getAllNodes") }
		if let refusal = shrinkRefusal(before: cached.count, after: rows.count) {
			NSLog("[BeamioGuardian] table refused: %@", refusal)
			return
		}
		let nodes = rows.map(\.node)
		let mailbox = matchMailbox(rows)
		guard BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: mailbox) else { return fail("store") }
		if root.isEmpty, !proofUnsupported, case .value(let r) = storageRoot(at: target) { root = r }
		defaults.set(root, forKey: keyRoot)
		defaults.set(target, forKey: keyBlock)
		defaults.set(Date().timeIntervalSince1970, forKey: keyBuiltAt)
		failures = 0
		let before = Set(cached.map(\.ip))
		let after = Set(nodes.map(\.ip))
		let removed = before.subtracting(after)
		NSLog(
			"[BeamioGuardian] table %@ (%@) block=%d count=%d added=%d removed=%d mailbox=%@",
			reason, why, target, nodes.count, after.subtracting(before).count, removed.count,
			mailbox == nil ? "unchanged" : "matched"
		)
		BeamioEntryPool.shared.nodesChanged(removed: removed)
	}

	private func fail(_ what: String) {
		failures += 1
		let backoff = min(Self.failBackoffMax, Self.failBackoffBase * pow(2, Double(failures - 1)))
		notBefore = Date().addingTimeInterval(backoff)
		NSLog("[BeamioGuardian] %@ failed; retry in %.0fs", what, backoff)
	}

	/// Empty is always refused. A drop below half of a 20+ table needs the same
	/// count again 20 minutes later.
	private func shrinkRefusal(before: Int, after: Int) -> String? {
		if after == 0 { return "empty read (current \(before))" }
		if before < 20 || Double(after) >= Double(before) * 0.5 {
			pendingShrink = nil
			return nil
		}
		if let p = pendingShrink, p.count == after {
			if Date().timeIntervalSince(p.firstSeen) >= Self.shrinkConfirm {
				pendingShrink = nil
				return nil
			}
			return "shrink \(before)→\(after) awaiting confirmation"
		}
		pendingShrink = (after, Date())
		return "shrink \(before)→\(after); needs a second read in 20 min"
	}

	// MARK: - Chain reads

	private enum RootResult {
		case value(String)
		case unsupported
		case failed
	}

	private func blockNumber() -> Int? {
		guard case .ok(let any) = rpc("eth_blockNumber", []), let hex = any as? String else { return nil }
		return Int(hex.dropFirst(2), radix: 16)
	}

	private func storageRoot(at block: Int) -> RootResult {
		switch rpc("eth_getProof", [Self.contract, [], hexQuantity(block)]) {
		case .ok(let any):
			guard let obj = any as? [String: Any],
			      let h = obj["storageHash"] as? String,
			      h.count == 66, h.hasPrefix("0x")
			else { return .failed }
			return .value(h.lowercased())
		case .unsupported:
			return .unsupported
		case .failed:
			return .failed
		}
	}

	/// Fallback detector: any contract log, or (short ranges) any tx to the contract.
	private func contractTouched(from: Int, to: Int) -> Bool? {
		var a = from + 1
		while a <= to {
			let b = min(to, a + Self.logsChunk - 1)
			guard case .ok(let any) = rpc("eth_getLogs", [[
				"address": Self.contract,
				"fromBlock": hexQuantity(a),
				"toBlock": hexQuantity(b),
			]]), let logs = any as? [Any] else { return nil }
			if !logs.isEmpty { return true }
			a = b + 1
		}
		if to - from > Self.maxTxScanBlocks {
			// Too long to scan for calls: read the table to be safe.
			return true
		}
		for n in (from + 1) ... to {
			guard case .ok(let any) = rpc("eth_getBlockByNumber", [hexQuantity(n), true]),
			      let blk = any as? [String: Any]
			else { return nil }
			let txs = blk["transactions"] as? [[String: Any]] ?? []
			if txs.contains(where: { ($0["to"] as? String)?.lowercased() == Self.contract.lowercased() }) {
				return true
			}
		}
		return false
	}

	private struct Row {
		var node: BeamioChatPgpKeychain.SiNode
		var armor: String
	}

	/// Every page at `block`, or nil. A partial list never reaches the table.
	private func readAll(at block: Int) -> [Row]? {
		var all: [Row] = []
		var seen = Set<String>()
		var start = 0
		for _ in 0 ..< 100 {
			var page: [Row]?
			for attempt in 1 ... 3 {
				let data = "0x" + Self.getAllNodesSelector + hex256(start) + hex256(Self.pageSize)
				if case .ok(let any) = rpc("eth_call", [["to": Self.contract, "data": data], hexQuantity(block)]),
				   let hex = any as? String,
				   let blob = Data(hexString: String(hex.dropFirst(2))),
				   let rows = decode(blob) {
					page = rows
					break
				}
				Thread.sleep(forTimeInterval: Double(attempt))
			}
			guard let rows = page else { return nil }
			if rows.isEmpty { return all }
			for r in rows where seen.insert(r.node.ip).inserted { all.append(r) }
			if rows.count < Self.pageSize { return all }
			start += rows.count
		}
		return nil
	}

	private enum RpcResult {
		case ok(Any)
		case unsupported
		case failed
	}

	private func rpc(_ method: String, _ params: [Any]) -> RpcResult {
		let payload: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
		guard let body = try? JSONSerialization.data(withJSONObject: payload) else { return .failed }
		for endpoint in Self.rpcs {
			guard let url = URL(string: endpoint) else { continue }
			var req = URLRequest(url: url, timeoutInterval: 20)
			req.httpMethod = "POST"
			req.setValue("application/json", forHTTPHeaderField: "content-type")
			req.httpBody = body
			let sem = DispatchSemaphore(value: 0)
			var out: RpcResult = .failed
			let task = URLSession.shared.dataTask(with: req) { data, _, _ in
				defer { sem.signal() }
				guard let data, let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
				if let err = obj["error"] as? [String: Any] {
					let code = err["code"] as? Int ?? 0
					let msg = (err["message"] as? String ?? "").lowercased()
					if code == -32601 || msg.contains("not found") || msg.contains("not supported") || msg.contains("does not exist") {
						out = .unsupported
					}
					return
				}
				if let result = obj["result"], !(result is NSNull) { out = .ok(result) }
			}
			task.resume()
			if sem.wait(timeout: .now() + 22) == .timedOut { task.cancel() }
			if case .failed = out { continue }
			return out
		}
		return .failed
	}

	// MARK: - ABI

	/// Dynamic `nodeInfo[]`: id, PGP (base64 armor), PGPKey (domain), ip_addr, region.
	private func decode(_ blob: Data) -> [Row]? {
		let bytes = [UInt8](blob)
		guard let outer = u256(bytes, 0), outer + 32 <= bytes.count else { return nil }
		guard let n = u256(bytes, outer), n <= 1000 else { return nil }
		if n == 0 { return [] }
		let heads = outer + 32
		var out: [Row] = []
		for i in 0 ..< n {
			guard let rel = u256(bytes, heads + 32 * i) else { return nil }
			let tup = heads + rel
			guard tup + 32 * 5 <= bytes.count,
			      let pgp = readString(bytes, tup, word: 1),
			      let pgpKey = readString(bytes, tup, word: 2),
			      let ipRaw = readString(bytes, tup, word: 3),
			      let region = readString(bytes, tup, word: 4)
			else { return nil }
			guard let ip = BeamioSiCipherPost.normalizeIp(ipRaw) else { continue }
			let domain = String(pgpKey.trimmingCharacters(in: .whitespacesAndNewlines).prefix(256))
			let regionTrim = String(region.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
			out.append(Row(node: .init(ip: ip, domain: domain, region: regionTrim), armor: armorFromBase64(pgp)))
		}
		return out
	}

	private func matchMailbox(_ rows: [Row]) -> String? {
		let route = normalizeArmor(BeamioChatPgpKeychain.loadRoutePublicArmor())
		guard route.contains("BEGIN PGP PUBLIC KEY") else { return nil }
		return rows.first { normalizeArmor($0.armor) == route }?.node.ip
	}

	private func armorFromBase64(_ raw: String) -> String {
		var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
			.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		while s.count % 4 != 0 { s += "=" }
		guard let data = Data(base64Encoded: s, options: [.ignoreUnknownCharacters]),
		      let text = String(data: data, encoding: .utf8)
		else { return "" }
		return text
	}

	private func normalizeArmor(_ raw: String) -> String {
		raw.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\r", with: "\n")
			.trimmingCharacters(in: .whitespacesAndNewlines)
	}

	private func hexQuantity(_ n: Int) -> String { "0x" + String(n, radix: 16) }

	private func hex256(_ value: Int) -> String { String(format: "%064x", value) }

	private func u256(_ bytes: [UInt8], _ off: Int) -> Int? {
		guard off >= 0, off + 32 <= bytes.count else { return nil }
		for i in 0 ..< 24 where bytes[off + i] != 0 { return nil }
		var v: UInt64 = 0
		for i in 24 ..< 32 { v = (v << 8) | UInt64(bytes[off + i]) }
		guard v <= UInt64(Int.max) else { return nil }
		return Int(v)
	}

	private func readString(_ bytes: [UInt8], _ tup: Int, word: Int) -> String? {
		guard let rel = u256(bytes, tup + 32 * word) else { return nil }
		let abs = tup + rel
		guard let len = u256(bytes, abs), len < 200_000, abs + 32 + len <= bytes.count else { return nil }
		return String(data: Data(bytes[abs + 32 ..< abs + 32 + len]), encoding: .utf8)
	}
}

private extension Data {
	init?(hexString: String) {
		let chars = Array(hexString.utf8)
		guard chars.count % 2 == 0 else { return nil }
		var out = Data(capacity: chars.count / 2)
		var i = 0
		func nib(_ c: UInt8) -> UInt8? {
			switch c {
			case 48 ... 57: return c - 48
			case 97 ... 102: return c - 87
			case 65 ... 70: return c - 55
			default: return nil
			}
		}
		while i < chars.count {
			guard let hi = nib(chars[i]), let lo = nib(chars[i + 1]) else { return nil }
			out.append(hi << 4 | lo)
			i += 2
		}
		self = out
	}
}
