import CryptoKit
import Foundation

/// Encrypted chat history: AES-GCM fragments on IPFS + a head pointer on the CoNET
/// `ChatIndexRegistry`. Model 1B: the EOA never leaves the PWA; the history master key is
/// derived from an EIP-191 signature requested through `BeamioConetChatSignBroker`.
///
/// Wire-compatible with the TypeScript `@conet.project/chat-sdk` history worker and
/// `chat-sdk-android`:
/// `master = keccak256(utf8(sign("beamio.chat.history.v1|chainId|eoa")))`,
/// `k_i = HKDF(master, "frag|seq|prevCid")`, index key `HKDF(master, "index-enc")`.
///
/// Index records are parsed leniently: the TS worker omits `sendId` when a message has none.
public final class BeamioConetChatHistoryStore {
	struct IndexRecord {
		var seq: Int
		var cid: String
		var prevCid: String
		var ts: Int64
		var peer: String
		var dir: String
		var sendId: String
		var preview: String?
	}

	struct Entry {
		var seq: Int
		var ts: Int64
		var peer: String
		var dir: String
		var sendId: String
		var body: String

		var json: [String: Any] {
			["seq": seq, "ts": NSNumber(value: ts), "peer": peer, "dir": dir, "sendId": sendId, "body": body]
		}
	}

	private struct Pointer {
		var indexHash: String
		var ts: UInt64
		var seq: UInt64
	}

	public typealias LogFn = (_ level: String, _ message: String) -> Void

	private let eoa: String
	private let chainId: Int
	private let conetRpcUrl: String
	private let ipfsBaseUrl: String
	private let ipfsWriteBaseUrl: String
	private let apiBaseUrl: String
	private let registryAddress: String
	private let log: LogFn

	// Mutated only on `queue`.
	private var indexKey: Data?
	private var genesisCid = ""
	private var selfSign = ""
	private var records: [IndexRecord] = []
	private var syncedIndexHash = ""

	/// Cross-lane state (read lane, fetch workers, `isReady`), guarded by `stateLock`.
	private let stateLock = NSLock()
	private var master: Data?
	private var readyFlag = false
	private var everSyncedFlag = false
	private var snapshot: [IndexRecord] = []
	private var plain: [String: Entry] = [:]
	private var emittedCids = Set<String>()
	private var loadsInFlight = 0
	private var destroyed = false

	/// Serial lane for everything that mutates the chain (prepare / load / append / head sync).
	private let queue = DispatchQueue(label: "beamio.conet.chat.history", qos: .utility)
	/// Global corpus reads, independent of `queue`.
	private let readQueue = DispatchQueue(label: "beamio.conet.chat.history.read", qos: .utility)
	/// Bounded parallel IPFS fetch + decrypt.
	private let fetchQueue = DispatchQueue(label: "beamio.conet.chat.history.fetch", qos: .utility, attributes: .concurrent)
	private let fetchSlots = DispatchSemaphore(value: BeamioConetChatHistoryStore.fetchParallelism)
	private let session: URLSession

	private static let fragmentGenesisInfo = "frag-genesis"
	private static let backfillBatch = 20
	private static let fetchParallelism = 6
	private static let materializeTimeout: TimeInterval = 45
	private static let readRestoreWait: TimeInterval = 20
	/// `bytes4(keccak256("getPointer(address)"))`
	private static let selGetPointer = "0x6bd15a9f"
	/// `bytes4(keccak256("nonceOf(address)"))`
	private static let selNonceOf = "0xed2a2d64"

	public init(
		eoa: String,
		chainId: Int,
		conetRpcUrl: String,
		ipfsBaseUrl: String,
		ipfsWriteBaseUrl: String?,
		apiBaseUrl: String,
		registryAddress: String,
		openPgp _: BeamioOpenPgpHost? = nil,
		log: @escaping LogFn
	) {
		self.eoa = eoa.lowercased()
		self.chainId = chainId
		self.conetRpcUrl = conetRpcUrl
		self.ipfsBaseUrl = ipfsBaseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		let write = (ipfsWriteBaseUrl?.isEmpty == false) ? ipfsWriteBaseUrl! : ipfsBaseUrl
		self.ipfsWriteBaseUrl = write.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		self.apiBaseUrl = apiBaseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		self.registryAddress = registryAddress
		self.log = log
		let config = URLSessionConfiguration.ephemeral
		config.requestCachePolicy = .reloadIgnoringLocalCacheData
		config.httpMaximumConnectionsPerHost = BeamioConetChatHistoryStore.fetchParallelism + 2
		self.session = URLSession(configuration: config)
	}

	public func isReady() -> Bool {
		stateLock.lock()
		defer { stateLock.unlock() }
		return readyFlag && !destroyed
	}

	public func destroy() {
		stateLock.lock()
		destroyed = true
		readyFlag = false
		master = nil
		plain.removeAll()
		snapshot = []
		stateLock.unlock()
		queue.async { [weak self] in
			self?.indexKey = nil
			self?.records = []
		}
		session.invalidateAndCancel()
	}

	private var isDestroyed: Bool {
		stateLock.lock()
		defer { stateLock.unlock() }
		return destroyed
	}

	private func publishSnapshot() {
		let copy = records
		stateLock.lock()
		snapshot = copy
		stateLock.unlock()
	}

	// MARK: - Lifecycle

	func prepare(completion: @escaping (Bool) -> Void) {
		queue.async { [weak self] in
			guard let self else { completion(false); return }
			do {
				let domain = "beamio.chat.history.v1|\(self.chainId)|\(self.eoa)"
				let domainSig = try self.awaitEip191(domain)
				// storageFragment checks sign(wallet) against the `wallet` field we send (lowercase).
				self.selfSign = try self.awaitEip191(self.eoa)
				let master = Keccak256.hash(Data(domainSig.utf8))
				self.indexKey = Self.hkdf(master: master, info: "index-enc", length: 32)
				let genesis = Self.hkdf(master: master, info: Self.fragmentGenesisInfo, length: 32)
				self.genesisCid = "0x" + Self.hex(genesis)
				self.stateLock.lock()
				self.master = master
				self.readyFlag = !self.destroyed
				self.stateLock.unlock()
				self.log("info", "[history] ready genesis=\(Self.shortCid(self.genesisCid))")
				completion(true)
			} catch {
				self.log("warn", "[history] prepare failed: \(error.localizedDescription)")
				completion(false)
			}
		}
	}

	// MARK: - Load / read / append

	/// Restore: sync the head pointer, then publish decrypted entries through `emitBuffer`
	/// (tail first, older batches after) — the same `historyBuffer` shape the TS worker emits.
	func load(
		options: [String: Any]?,
		emitBuffer: @escaping (_ peer: String, _ entries: [Entry], _ isTail: Bool) -> Void,
		done: @escaping () -> Void
	) {
		stateLock.lock()
		loadsInFlight += 1
		stateLock.unlock()
		queue.async { [weak self] in
			guard let self else { done(); return }
			defer {
				self.stateLock.lock()
				self.loadsInFlight -= 1
				self.stateLock.unlock()
				done()
			}
			guard self.isReady() else { return }
			let tailOpt = Self.intValue(options?["tailCount"]) ?? 60
			let tailCount = tailOpt > 0 ? tailOpt : 60
			let localOnly = (options?["localOnly"] as? Bool) ?? false
			let emitAll = (options?["emit"] as? String) == "all"
			let peerRaw = String(options?["peer"] as? String ?? "").lowercased()
			let peerFilter: String? = peerRaw.isEmpty ? nil : peerRaw
			if !localOnly { self.syncFromHead() }
			var recs = self.records
			if let peerFilter { recs = recs.filter { $0.peer == peerFilter } }
			let peerKey = peerFilter ?? "all"
			if recs.isEmpty {
				emitBuffer(peerKey, [], true)
				return
			}
			let ordered = recs.sorted { $0.seq < $1.seq }
			let tail = Array(ordered.suffix(tailCount))
			let older = Array(ordered.dropLast(tail.count))
			self.log("info", "[history] load peer=\(peerKey) records=\(ordered.count) tail=\(tail.count) older=\(older.count)")

			func publish(_ batch: [IndexRecord], isTail: Bool) {
				let materialized = self.materializeAll(batch)
				var entries: [Entry] = []
				for (idx, rec) in batch.enumerated() {
					self.stateLock.lock()
					let fresh = self.emittedCids.insert(rec.cid).inserted
					self.stateLock.unlock()
					guard let entry = materialized[idx] else { continue }
					if emitAll || fresh { entries.append(entry) }
				}
				if !entries.isEmpty { emitBuffer(peerKey, entries, isTail) }
			}
			publish(tail, isTail: true)
			var i = older.count
			while i > 0, !self.isDestroyed {
				publish(Array(older[max(0, i - Self.backfillBatch)..<i]), isTail: false)
				i -= Self.backfillBatch
			}
		}
	}

	/// Global read of the decrypted corpus (does not refresh the head pointer). Runs on its own
	/// lane from the last published snapshot, so it answers while an append is still uploading.
	func read(options: [String: Any]?, completion: @escaping ([Entry]) -> Void) {
		readQueue.async { [weak self] in
			guard let self, self.isReady() else { completion([]); return }
			self.awaitRestoreIdle(timeout: Self.readRestoreWait)
			self.stateLock.lock()
			let needsSync = !self.everSyncedFlag && self.snapshot.isEmpty
			self.stateLock.unlock()
			if needsSync {
				// Nothing restored yet: an empty answer would look like "no history".
				let synced = DispatchSemaphore(value: 0)
				self.queue.async {
					self.syncFromHead()
					synced.signal()
				}
				_ = synced.wait(timeout: .now() + Self.readRestoreWait)
			}
			let peerRaw = String(options?["peer"] as? String ?? "").lowercased()
			let query = String(options?["query"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
			let limit = Self.intValue(options?["limit"]) ?? 0
			let terms = query.split(whereSeparator: { $0.isWhitespace }).map(String.init)
			self.stateLock.lock()
			let candidates = self.snapshot.filter { peerRaw.isEmpty || $0.peer == peerRaw }
			self.stateLock.unlock()
			var entries = self.materializeAll(candidates).compactMap { $0 }.filter { entry in
				guard !terms.isEmpty else { return true }
				let text = entry.body.lowercased()
				return terms.allSatisfy { text.contains($0) }
			}
			entries.sort { $0.ts != $1.ts ? $0.ts < $1.ts : $0.seq < $1.seq }
			if limit > 0, entries.count > limit { entries = Array(entries.suffix(limit)) }
			completion(entries)
		}
	}

	/// Append one mirrored entry. Idempotent per `sendId`.
	func append(entry: [String: Any], completion: @escaping (Bool) -> Void) {
		queue.async { [weak self] in
			guard let self else { completion(false); return }
			completion(self.appendUnlocked(entry))
		}
	}

	private func awaitRestoreIdle(timeout: TimeInterval) {
		let deadline = Date().addingTimeInterval(timeout)
		while Date() < deadline {
			stateLock.lock()
			let busy = loadsInFlight > 0
			stateLock.unlock()
			if !busy { return }
			Thread.sleep(forTimeInterval: 0.1)
		}
	}

	// MARK: - Append / sync (queue only)

	private func appendUnlocked(_ entry: [String: Any]) -> Bool {
		stateLock.lock()
		let masterKey = readyFlag && !destroyed ? master : nil
		stateLock.unlock()
		guard let masterKey, let key = indexKey else { return false }
		let rawSendId = String(entry["sendId"] as? String ?? "")
		let sendId = rawSendId.isEmpty ? UUID().uuidString : rawSendId
		// Re-mirroring a conversation re-appends every bubble: skip what the index already has.
		if records.contains(where: { $0.sendId == sendId }) { return true }
		syncFromHead()
		if records.contains(where: { $0.sendId == sendId }) { return true }

		let peer = String(entry["peer"] as? String ?? "").lowercased()
		let dir = String(entry["dir"] as? String ?? "out")
		let body = String(entry["body"] as? String ?? "")
		let ts = Self.int64Value(entry["ts"]) ?? Int64(Date().timeIntervalSince1970 * 1000)
		let seq = records.last.map { $0.seq + 1 } ?? 0
		let prevCid = records.last?.cid ?? genesisCid
		do {
			let fragKey = Self.hkdf(master: masterKey, info: "frag|\(seq)|\(prevCid)", length: 32)
			let cipher = try Self.aesGcmEncrypt(key: fragKey, plaintext: Data(body.utf8))
			let cid = Keccak256.hexUtf8(cipher)
			guard uploadFragment(cipher) != nil else { return false }
			records.append(IndexRecord(
				seq: seq, cid: cid, prevCid: prevCid, ts: ts, peer: peer, dir: dir,
				sendId: sendId, preview: String(body.prefix(80))
			))
			stateLock.lock()
			plain[cid] = Entry(seq: seq, ts: ts, peer: peer, dir: dir, sendId: sendId, body: body)
			emittedCids.insert(cid)
			stateLock.unlock()
			publishSnapshot()
			return persistManifest(key: key)
		} catch {
			log("warn", "[history] append failed: \(error.localizedDescription)")
			return false
		}
	}

	/// Adopt the remote chain, then re-append any local-only entries (fork repair).
	private func syncFromHead() {
		guard let key = indexKey else { return }
		guard let pointer = readOnchainPointer() else { return }
		if pointer.indexHash == syncedIndexHash { return }
		guard let cipher = fetchFragment(hash: pointer.indexHash) else {
			log("warn", "[history] index fetch failed index=\(Self.shortCid(pointer.indexHash))")
			return
		}
		let remote: [String: Any]
		do {
			let json = try Self.aesGcmDecrypt(key: key, b64: cipher)
			guard let obj = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else {
				log("warn", "[history] index is not a JSON object")
				return
			}
			remote = obj
		} catch {
			log("warn", "[history] sync decrypt failed")
			return
		}
		guard Self.intValue(remote["v"]) == 1,
		      String(remote["eoa"] as? String ?? "").lowercased() == eoa
		else {
			log("warn", "[history] index version/owner mismatch")
			return
		}
		let remoteRecords = Self.parseRecords(remote["records"])
		let remoteSendIds = Set(remoteRecords.map(\.sendId).filter { !$0.isEmpty })
		let remoteCids = Set(remoteRecords.map(\.cid))
		let localOnly = records.filter {
			!remoteCids.contains($0.cid) && ($0.sendId.isEmpty || !remoteSendIds.contains($0.sendId))
		}
		records = remoteRecords
		publishSnapshot()
		syncedIndexHash = pointer.indexHash
		stateLock.lock()
		everSyncedFlag = true
		stateLock.unlock()
		log("info", "[history] synced records=\(records.count) localOnly=\(localOnly.count)")
		for rec in localOnly {
			stateLock.lock()
			let entry = plain[rec.cid]
			stateLock.unlock()
			guard let entry else { continue }
			_ = appendUnlocked([
				"peer": entry.peer, "dir": entry.dir, "sendId": entry.sendId,
				"body": entry.body, "ts": NSNumber(value: entry.ts),
			])
		}
	}

	private func persistManifest(key: Data) -> Bool {
		let manifest: [String: Any] = [
			"v": 1,
			"eoa": eoa,
			"updatedAt": NSNumber(value: Int64(Date().timeIntervalSince1970 * 1000)),
			"records": Self.encodeRecords(records),
		]
		do {
			let data = try JSONSerialization.data(withJSONObject: manifest)
			let cipher = try Self.aesGcmEncrypt(key: key, plaintext: data)
			guard let indexHash = uploadFragment(cipher) else { return false }
			let ok = updateOnchainPointer(indexHash: indexHash, recordCount: records.count)
			if ok {
				syncedIndexHash = indexHash
				log("info", "[history] pointer updated records=\(records.count) index=\(Self.shortCid(indexHash))")
			}
			return ok
		} catch {
			log("warn", "[history] persist failed: \(error.localizedDescription)")
			return false
		}
	}

	// MARK: - Fragments

	/// Decrypt `batch` with bounded parallelism (IPFS fetch dominates). Order matches `batch`;
	/// `nil` for fragments that could not be fetched or decrypted.
	private func materializeAll(_ batch: [IndexRecord]) -> [Entry?] {
		if batch.isEmpty { return [] }
		var out = [Entry?](repeating: nil, count: batch.count)
		let outLock = NSLock()
		let group = DispatchGroup()
		for (idx, rec) in batch.enumerated() {
			stateLock.lock()
			let cached = plain[rec.cid]
			stateLock.unlock()
			if let cached {
				out[idx] = cached
				continue
			}
			if isDestroyed { break }
			fetchSlots.wait()
			group.enter()
			fetchQueue.async { [weak self] in
				defer {
					self?.fetchSlots.signal()
					group.leave()
				}
				guard let entry = self?.materialize(rec) else { return }
				outLock.lock()
				out[idx] = entry
				outLock.unlock()
			}
		}
		_ = group.wait(timeout: .now() + Self.materializeTimeout)
		outLock.lock()
		defer { outLock.unlock() }
		return out
	}

	private func materialize(_ rec: IndexRecord) -> Entry? {
		stateLock.lock()
		let cached = plain[rec.cid]
		let masterKey = readyFlag ? master : nil
		stateLock.unlock()
		if let cached { return cached }
		guard let masterKey, let cipher = fetchFragment(hash: rec.cid) else { return nil }
		do {
			let key = Self.hkdf(master: masterKey, info: "frag|\(rec.seq)|\(rec.prevCid)", length: 32)
			let body = try Self.aesGcmDecrypt(key: key, b64: cipher)
			let entry = Entry(seq: rec.seq, ts: rec.ts, peer: rec.peer, dir: rec.dir, sendId: rec.sendId, body: body)
			stateLock.lock()
			plain[rec.cid] = entry
			stateLock.unlock()
			return entry
		} catch {
			log("warn", "[history] record decrypt failed seq=\(rec.seq) cid=\(Self.shortCid(rec.cid))")
			return nil
		}
	}

	// MARK: - Chain / IPFS

	private func readOnchainPointer() -> Pointer? {
		guard let result = ethCall(to: registryAddress, data: Self.selGetPointer + padAddress(eoa)),
		      result.hasPrefix("0x"),
		      result.count >= 2 + 64 * 3
		else { return nil }
		let hex = Array(result.dropFirst(2))
		let indexHash = "0x" + String(hex[0..<64])
		if indexHash == "0x" + String(repeating: "0", count: 64) { return nil }
		func u64(_ offset: Int) -> UInt64 {
			let digits = String(hex[offset..<offset + 64]).drop(while: { $0 == "0" })
			return UInt64(digits.isEmpty ? "0" : String(digits), radix: 16) ?? 0
		}
		return Pointer(indexHash: indexHash, ts: u64(64), seq: u64(128))
	}

	private func updateOnchainPointer(indexHash: String, recordCount: Int) -> Bool {
		guard let nonceHex = ethCall(to: registryAddress, data: Self.selNonceOf + padAddress(eoa)),
		      nonceHex.count >= 66
		else {
			log("warn", "[history] nonceOf failed")
			return false
		}
		let nonce = Self.decimalString(fromHex: String(nonceHex.suffix(64)))
		let ts = UInt64(Date().timeIntervalSince1970 * 1000)
		let message: [String: Any] = [
			"owner": eoa,
			"indexHash": indexHash,
			"ts": String(ts),
			"seq": String(recordCount),
			"nonce": nonce,
		]
		let typedData: [String: Any] = [
			"types": [
				"EIP712Domain": [
					["name": "name", "type": "string"],
					["name": "version", "type": "string"],
					["name": "chainId", "type": "uint256"],
					["name": "verifyingContract", "type": "address"],
				],
				"SetPointer": [
					["name": "owner", "type": "address"],
					["name": "indexHash", "type": "bytes32"],
					["name": "ts", "type": "uint64"],
					["name": "seq", "type": "uint64"],
					["name": "nonce", "type": "uint256"],
				],
			],
			"primaryType": "SetPointer",
			"domain": [
				"name": "ChatIndexRegistry",
				"version": "1",
				"chainId": chainId,
				"verifyingContract": registryAddress,
			],
			// `value` is what the PWA signer reads; `message` is the EIP-712 JSON spelling.
			"value": message,
			"message": message,
		]
		let signature: String
		do {
			signature = try awaitEip712(typedData)
		} catch {
			log("warn", "[history] SetPointer sign failed: \(error.localizedDescription)")
			return false
		}
		var body = message
		body["signature"] = signature
		let (status, _) = httpPostJson(url: "\(apiBaseUrl)/setChatIndexPointer", body: body, timeout: 30)
		if !(200..<300).contains(status) {
			log("warn", "[history] setChatIndexPointer HTTP \(status)")
			return false
		}
		return true
	}

	@discardableResult
	private func uploadFragment(_ cipherB64: String) -> String? {
		let contentHash = Keccak256.hexUtf8(cipherB64)
		let body: [String: Any] = ["wallet": eoa, "signMessage": selfSign, "image": cipherB64]
		let (status, _) = httpPostJson(url: "\(ipfsWriteBaseUrl)/storageFragment", body: body, timeout: 45)
		if !(200..<300).contains(status) {
			log("warn", "[history] storageFragment HTTP \(status)")
			return nil
		}
		return contentHash
	}

	private func fetchFragment(hash: String) -> String? {
		guard var comps = URLComponents(string: "\(ipfsBaseUrl)/getFragment") else { return nil }
		comps.queryItems = [URLQueryItem(name: "hash", value: hash)]
		guard let url = comps.url else { return nil }
		var req = URLRequest(url: url, timeoutInterval: 30)
		req.httpMethod = "GET"
		let (status, data) = perform(req, timeout: 35)
		guard (200..<300).contains(status), let data,
		      let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
		      !text.isEmpty
		else { return nil }
		return text
	}

	private func ethCall(to: String, data: String) -> String? {
		let payload: [String: Any] = [
			"jsonrpc": "2.0",
			"id": 1,
			"method": "eth_call",
			"params": [["to": to, "data": data], "latest"],
		]
		let (status, body) = httpPostJson(url: conetRpcUrl, body: payload, timeout: 20)
		guard (200..<300).contains(status), let body,
		      let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
		      let result = obj["result"] as? String,
		      result.hasPrefix("0x")
		else { return nil }
		return result
	}

	private func httpPostJson(url: String, body: [String: Any], timeout: TimeInterval) -> (Int, Data?) {
		guard let u = URL(string: url), let payload = try? JSONSerialization.data(withJSONObject: body) else {
			return (0, nil)
		}
		var req = URLRequest(url: u, timeoutInterval: timeout)
		req.httpMethod = "POST"
		req.setValue("application/json", forHTTPHeaderField: "Content-Type")
		req.httpBody = payload
		return perform(req, timeout: timeout + 5)
	}

	private func perform(_ req: URLRequest, timeout: TimeInterval) -> (Int, Data?) {
		if isDestroyed { return (0, nil) }
		let sem = DispatchSemaphore(value: 0)
		let box = ResponseBox()
		session.dataTask(with: req) { data, response, _ in
			box.set(status: (response as? HTTPURLResponse)?.statusCode ?? 0, data: data)
			sem.signal()
		}.resume()
		if sem.wait(timeout: .now() + timeout) == .timedOut { return (0, nil) }
		return box.get()
	}

	private final class ResponseBox {
		private let lock = NSLock()
		private var status = 0
		private var data: Data?
		func set(status: Int, data: Data?) {
			lock.lock()
			self.status = status
			self.data = data
			lock.unlock()
		}
		func get() -> (Int, Data?) {
			lock.lock()
			defer { lock.unlock() }
			return (status, data)
		}
	}

	// MARK: - Signing

	private func awaitEip191(_ message: String) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "sign", code: -1, userInfo: [NSLocalizedDescriptionKey: "sign_timeout"]))
		BeamioConetChatSignBroker.requestEip191(message: message) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 35)
		return try out.get()
	}

	private func awaitEip712(_ typedData: [String: Any]) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "sign", code: -1, userInfo: [NSLocalizedDescriptionKey: "sign_timeout"]))
		BeamioConetChatSignBroker.requestEip712(typedData: typedData) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 35)
		return try out.get()
	}

	// MARK: - Records

	static func parseRecords(_ raw: Any?) -> [IndexRecord] {
		guard let arr = raw as? [Any] else { return [] }
		var out: [IndexRecord] = []
		out.reserveCapacity(arr.count)
		for item in arr {
			guard let o = item as? [String: Any] else { continue }
			let cid = String(o["cid"] as? String ?? "")
			if cid.isEmpty { continue }
			let preview = o["preview"] as? String
			out.append(IndexRecord(
				seq: intValue(o["seq"]) ?? 0,
				cid: cid,
				prevCid: String(o["prevCid"] as? String ?? ""),
				ts: int64Value(o["ts"]) ?? 0,
				peer: String(o["peer"] as? String ?? "").lowercased(),
				dir: String(o["dir"] as? String ?? "out"),
				sendId: String(o["sendId"] as? String ?? ""),
				preview: (preview?.isEmpty == false) ? preview : nil
			))
		}
		return out.sorted { $0.seq != $1.seq ? $0.seq < $1.seq : $0.cid < $1.cid }
	}

	static func encodeRecords(_ list: [IndexRecord]) -> [[String: Any]] {
		list.map { r in
			var o: [String: Any] = [
				"seq": r.seq,
				"cid": r.cid,
				"prevCid": r.prevCid,
				"ts": NSNumber(value: r.ts),
				"peer": r.peer,
				"dir": r.dir,
				"sendId": r.sendId,
			]
			if let preview = r.preview { o["preview"] = preview }
			return o
		}
	}

	static func intValue(_ v: Any?) -> Int? {
		if let n = v as? NSNumber { return n.intValue }
		if let s = v as? String { return Int(s) }
		return nil
	}

	static func int64Value(_ v: Any?) -> Int64? {
		if let n = v as? NSNumber { return n.int64Value }
		if let s = v as? String { return Int64(s) }
		return nil
	}

	// MARK: - Crypto helpers

	static func hkdf(master: Data, info: String, length: Int) -> Data {
		let derived = HKDF<SHA256>.deriveKey(
			inputKeyMaterial: SymmetricKey(data: master),
			salt: Data(),
			info: Data(info.utf8),
			outputByteCount: length
		)
		return derived.withUnsafeBytes { Data($0) }
	}

	static func aesGcmEncrypt(key: Data, plaintext: Data) throws -> String {
		let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key))
		guard let combined = sealed.combined else {
			throw NSError(domain: "aes", code: -1, userInfo: [NSLocalizedDescriptionKey: "no_combined"])
		}
		return combined.base64EncodedString()
	}

	static func aesGcmDecrypt(key: Data, b64: String) throws -> String {
		guard let combined = Data(base64Encoded: b64) else {
			throw NSError(domain: "aes", code: -2, userInfo: [NSLocalizedDescriptionKey: "b64"])
		}
		let box = try AES.GCM.SealedBox(combined: combined)
		let pt = try AES.GCM.open(box, using: SymmetricKey(data: key))
		guard let s = String(data: pt, encoding: .utf8) else {
			throw NSError(domain: "aes", code: -3, userInfo: [NSLocalizedDescriptionKey: "utf8"])
		}
		return s
	}

	static func hex(_ data: Data) -> String {
		data.map { String(format: "%02x", $0) }.joined()
	}

	/// Big-endian hex (no 0x) → decimal string, for uint256 nonces.
	static func decimalString(fromHex hex: String) -> String {
		var limbs: [UInt64] = [0] // base 1e9, little-endian
		for ch in hex {
			guard let v = ch.hexDigitValue else { continue }
			var carry = UInt64(v)
			for i in 0..<limbs.count {
				let cur = limbs[i] * 16 + carry
				limbs[i] = cur % 1_000_000_000
				carry = cur / 1_000_000_000
			}
			while carry > 0 {
				limbs.append(carry % 1_000_000_000)
				carry /= 1_000_000_000
			}
		}
		var s = String(limbs.last ?? 0)
		for limb in limbs.dropLast().reversed() {
			let part = String(limb)
			s += String(repeating: "0", count: 9 - part.count) + part
		}
		return s
	}

	private func padAddress(_ addr: String) -> String {
		var a = addr.lowercased()
		if a.hasPrefix("0x") { a = String(a.dropFirst(2)) }
		return String(repeating: "0", count: max(0, 64 - a.count)) + a
	}

	private static func shortCid(_ cid: String) -> String {
		guard cid.count > 14 else { return cid }
		return String(cid.prefix(10)) + "…" + String(cid.suffix(4))
	}
}

/// Keccak-256 (Ethereum flavour, padding 0x01). Native, so a multi-MB index cipher never has
/// to round-trip through the JS engine.
enum Keccak256 {
	private static let roundConstants: [UInt64] = [
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
		0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
		0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
		0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
		0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	]
	/// Rotation offsets indexed by lane `x + 5 * y`.
	private static let rotations: [UInt64] = [
		0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
	]

	@inline(__always)
	private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
		n == 0 ? x : (x << n) | (x >> (64 - n))
	}

	private static func permute(_ a: inout [UInt64]) {
		var b = [UInt64](repeating: 0, count: 25)
		var c = [UInt64](repeating: 0, count: 5)
		for round in 0..<24 {
			for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
			for x in 0..<5 {
				let d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
				for y in 0..<5 { a[x + 5 * y] ^= d }
			}
			for x in 0..<5 {
				for y in 0..<5 {
					let i = x + 5 * y
					b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[i], rotations[i])
				}
			}
			for y in 0..<5 {
				for x in 0..<5 {
					a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y])
				}
			}
			a[0] ^= roundConstants[round]
		}
	}

	static func hash(_ data: Data) -> Data {
		let rate = 136
		var state = [UInt64](repeating: 0, count: 25)
		var msg = [UInt8](data)
		msg.append(0x01)
		while msg.count % rate != 0 { msg.append(0) }
		msg[msg.count - 1] |= 0x80
		var offset = 0
		while offset < msg.count {
			for i in 0..<(rate / 8) {
				var lane: UInt64 = 0
				for j in 0..<8 { lane |= UInt64(msg[offset + i * 8 + j]) << UInt64(8 * j) }
				state[i] ^= lane
			}
			permute(&state)
			offset += rate
		}
		var out = [UInt8]()
		out.reserveCapacity(32)
		for i in 0..<4 {
			for j in 0..<8 { out.append(UInt8((state[i] >> UInt64(8 * j)) & 0xff)) }
		}
		return Data(out)
	}

	static func hexUtf8(_ text: String) -> String {
		"0x" + BeamioConetChatHistoryStore.hex(hash(Data(text.utf8)))
	}
}
