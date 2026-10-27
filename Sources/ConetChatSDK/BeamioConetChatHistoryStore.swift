import CryptoKit
import Foundation

/// Chat history (encrypt IPFS fragments + ChatIndexRegistry SetPointer). 1B: EOA signs via SignBroker.
public final class BeamioConetChatHistoryStore {
	struct IndexRecord: Codable {
		var seq: Int
		var cid: String
		var prevCid: String
		var ts: Int64
		var peer: String
		var dir: String
		var sendId: String
		var preview: String?
	}

	struct IndexManifest: Codable {
		var v: Int
		var eoa: String
		var updatedAt: Int64
		var records: [IndexRecord]
	}

	struct HistoryEntry {
		var seq: Int
		var ts: Int64
		var peer: String
		var dir: String
		var sendId: String
		var body: String
	}

	public typealias LogFn = (_ level: String, _ message: String) -> Void

	private let eoa: String
	private let chainId: Int
	private let conetRpcUrl: String
	private let ipfsBaseUrl: String
	private let ipfsWriteBaseUrl: String
	private let apiBaseUrl: String
	private let registryAddress: String
	private let openPgp: BeamioOpenPgpHost
	private let log: LogFn

	private var master: Data?
	private var indexKey: Data?
	private var genesisCid = ""
	private var selfSign = ""
	private var ready = false
	private var manifest: IndexManifest?
	private let queue = DispatchQueue(label: "beamio.conet.chat.history", qos: .utility)

	private static let fragmentGenesisInfo = "frag-genesis"
	private static let registryReadAbiGetPointer =
		"0x" // filled via eth_call encode below
	/// keccak256("getPointer(address)")[:4]
	private static let selGetPointer = "0x6bd15a9f"
	/// keccak256("nonceOf(address)")[:4]
	private static let selNonceOf = "0xed2a2d64"

	public init(
		eoa: String,
		chainId: Int,
		conetRpcUrl: String,
		ipfsBaseUrl: String,
		ipfsWriteBaseUrl: String?,
		apiBaseUrl: String,
		registryAddress: String,
		openPgp: BeamioOpenPgpHost,
		log: @escaping LogFn
	) {
		self.eoa = eoa.lowercased()
		self.chainId = chainId
		self.conetRpcUrl = conetRpcUrl
		self.ipfsBaseUrl = ipfsBaseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		self.ipfsWriteBaseUrl = (ipfsWriteBaseUrl ?? ipfsBaseUrl).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		self.apiBaseUrl = apiBaseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
		self.registryAddress = registryAddress
		self.openPgp = openPgp
		self.log = log
	}

	func prepare(completion: @escaping (Bool) -> Void) {
		queue.async { [weak self] in
			guard let self else { completion(false); return }
			let domain = "beamio.chat.history.v1|\(self.chainId)|\(self.eoa)"
			let domainSig: String
			do {
				domainSig = try self.awaitEip191(domain)
			} catch {
				self.log("warn", "[history] domain sign failed: \(error.localizedDescription)")
				completion(false)
				return
			}
			do {
				self.selfSign = try self.awaitEip191(self.eoa.hasPrefix("0x") ? self.checksumLike(self.eoa) : self.eoa)
			} catch {
				// storageFragment wants sign(wallet.address) — use checksummed if possible; fallback lower
				do {
					self.selfSign = try self.awaitEip191(self.eoa)
				} catch {
					self.log("warn", "[history] selfSign failed")
					completion(false)
					return
				}
			}
			let masterHex: String
			do {
				masterHex = try self.awaitKeccak(domainSig)
			} catch {
				self.log("warn", "[history] keccak master failed")
				completion(false)
				return
			}
			guard let master = Self.hexToData(masterHex) else {
				completion(false)
				return
			}
			self.master = master
			do {
				self.indexKey = try Self.hkdf(master: master, info: "index-enc", length: 32)
				let genesis = try Self.hkdf(master: master, info: Self.fragmentGenesisInfo, length: 32)
				self.genesisCid = "0x" + genesis.map { String(format: "%02x", $0) }.joined()
				self.ready = true
				self.log("info", "[history] ready genesis=\(Self.shortCid(self.genesisCid))")
				completion(true)
			} catch {
				self.log("warn", "[history] hkdf failed: \(error.localizedDescription)")
				completion(false)
			}
		}
	}

	func load(options: [String: Any]?, completion: @escaping ([[String: Any]]) -> Void) {
		queue.async { [weak self] in
			guard let self, self.ready else { completion([]); return }
			_ = self.syncFromHeadUnlocked()
			let tail = (options?["tailCount"] as? Int) ?? 60
			let records = self.manifest?.records ?? []
			let slice = Array(records.suffix(tail))
			var entries: [[String: Any]] = []
			for rec in slice {
				if let entry = self.materialize(rec) {
					entries.append([
						"seq": entry.seq,
						"ts": entry.ts,
						"peer": entry.peer,
						"dir": entry.dir,
						"sendId": entry.sendId,
						"body": entry.body,
					])
				}
			}
			completion(entries)
		}
	}

	func read(options: [String: Any]?, completion: @escaping ([[String: Any]]) -> Void) {
		load(options: options, completion: completion)
	}

	func append(entry: [String: Any], completion: @escaping (Bool) -> Void) {
		queue.async { [weak self] in
			guard let self, self.ready, let indexKey = self.indexKey, let master = self.master else {
				completion(false)
				return
			}
			let peer = String(entry["peer"] as? String ?? "").lowercased()
			let dir = String(entry["dir"] as? String ?? "out")
			let sendId = String(entry["sendId"] as? String ?? UUID().uuidString)
			let body = String(entry["body"] as? String ?? "")
			let ts = (entry["ts"] as? NSNumber)?.int64Value ?? Int64(Date().timeIntervalSince1970 * 1000)
			var records = self.manifest?.records ?? []
			let seq = records.count
			let prevCid = seq == 0 ? self.genesisCid : records[seq - 1].cid
			do {
				let fragKey = try Self.hkdf(master: master, info: "frag|\(seq)|\(prevCid)", length: 32)
				let cipher = try Self.aesGcmEncrypt(key: fragKey, plaintext: Data(body.utf8))
				let cid = try self.awaitKeccakSync(cipher)
				guard self.uploadFragment(cipher) != nil else {
					completion(false)
					return
				}
				records.append(IndexRecord(
					seq: seq,
					cid: cid,
					prevCid: prevCid,
					ts: ts,
					peer: peer,
					dir: dir,
					sendId: sendId,
					preview: String(body.prefix(80))
				))
				let next = IndexManifest(
					v: 1,
					eoa: self.eoa,
					updatedAt: Int64(Date().timeIntervalSince1970 * 1000),
					records: records
				)
				let ok = self.persistManifest(next, indexKey: indexKey)
				completion(ok)
			} catch {
				self.log("warn", "[history] append failed: \(error.localizedDescription)")
				completion(false)
			}
		}
	}

	// MARK: - Sync / persist

	@discardableResult
	private func syncFromHeadUnlocked() -> Bool {
		guard ready, let indexKey else { return false }
		guard let pointer = readOnchainPointer() else { return false }
		guard let cipher = fetchFragment(hash: pointer.indexHash) else { return false }
		do {
			let json = try Self.aesGcmDecrypt(key: indexKey, b64: cipher)
			guard let data = json.data(using: .utf8),
			      let remote = try? JSONDecoder().decode(IndexManifest.self, from: data),
			      remote.v == 1,
			      remote.eoa.lowercased() == eoa
			else { return false }
			let local = manifest?.records ?? []
			let merged = unionMerge(local: local, remote: remote.records)
			manifest = IndexManifest(v: 1, eoa: eoa, updatedAt: Date().timeIntervalSince1970.milliseconds, records: merged)
			_ = persistManifest(manifest!, indexKey: indexKey, skipRemoteIfUnchanged: true)
			log("info", "[history] synced records=\(merged.count)")
			return true
		} catch {
			log("warn", "[history] sync decrypt failed")
			return false
		}
	}

	private func persistManifest(
		_ next: IndexManifest,
		indexKey: Data,
		skipRemoteIfUnchanged: Bool = false
	) -> Bool {
		do {
			let data = try JSONEncoder().encode(next)
			guard let json = String(data: data, encoding: .utf8) else { return false }
			let cipher = try Self.aesGcmEncrypt(key: indexKey, plaintext: Data(json.utf8))
			guard let indexHash = uploadFragment(cipher) else { return false }
			if !skipRemoteIfUnchanged {
				_ = updateOnchainPointer(indexHash: indexHash, manifest: next)
			} else {
				_ = updateOnchainPointer(indexHash: indexHash, manifest: next)
			}
			manifest = next
			return true
		} catch {
			log("warn", "[history] persist failed: \(error.localizedDescription)")
			return false
		}
	}

	private func materialize(_ rec: IndexRecord) -> HistoryEntry? {
		guard let master, let cipher = downloadFragment(cid: rec.cid) else { return nil }
		do {
			let key = try Self.hkdf(master: master, info: "frag|\(rec.seq)|\(rec.prevCid)", length: 32)
			let pt = try Self.aesGcmDecrypt(key: key, b64: cipher)
			return HistoryEntry(seq: rec.seq, ts: rec.ts, peer: rec.peer, dir: rec.dir, sendId: rec.sendId, body: pt)
		} catch {
			return nil
		}
	}

	private func unionMerge(local: [IndexRecord], remote: [IndexRecord]) -> [IndexRecord] {
		var byKey: [String: IndexRecord] = [:]
		for r in local + remote {
			let k = r.sendId.isEmpty ? "cid:\(r.cid)" : "send:\(r.sendId)"
			if byKey[k] == nil { byKey[k] = r }
		}
		return byKey.values.sorted { a, b in
			if a.seq != b.seq { return a.seq < b.seq }
			return a.cid < b.cid
		}
	}

	// MARK: - Chain / IPFS

	private struct Pointer {
		var indexHash: String
		var ts: UInt64
		var seq: UInt64
	}

	private func readOnchainPointer() -> Pointer? {
		let owner = padAddress(eoa)
		// getPointer(address) → (bytes32 indexHash, uint64 ts, uint64 seq, uint64 updatedAt)
		let data = Self.selGetPointer + owner
		guard let result = ethCall(to: registryAddress, data: data),
		      result.hasPrefix("0x"),
		      result.count >= 2 + 64 * 3
		else { return nil }
		let hex = String(result.dropFirst(2))
		let indexHash = "0x" + String(hex.prefix(64))
		if indexHash == "0x" + String(repeating: "0", count: 64) { return nil }
		func u64(_ offset: Int) -> UInt64 {
			let start = hex.index(hex.startIndex, offsetBy: offset)
			let end = hex.index(start, offsetBy: 64)
			return UInt64(String(hex[start..<end]), radix: 16) ?? 0
		}
		return Pointer(indexHash: indexHash, ts: u64(64), seq: u64(128))
	}

	private func updateOnchainPointer(indexHash: String, manifest: IndexManifest) -> Bool {
		let nonceData = Self.selNonceOf + padAddress(eoa)
		guard let nonceHex = ethCall(to: registryAddress, data: nonceData),
		      nonceHex.count >= 66
		else {
			log("warn", "[history] nonceOf failed")
			return false
		}
		let nonce = String(nonceHex.suffix(64))
		let nonceDec = UInt64(nonce, radix: 16) ?? 0
		let ts = UInt64(Date().timeIntervalSince1970 * 1000)
		let seq = UInt64(manifest.records.count)
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
			"message": [
				"owner": eoa,
				"indexHash": indexHash,
				"ts": String(ts),
				"seq": String(seq),
				"nonce": String(nonceDec),
			],
		]
		let signature: String
		do {
			signature = try awaitEip712(typedData)
		} catch {
			log("warn", "[history] SetPointer sign failed")
			return false
		}
		let url = URL(string: "\(apiBaseUrl)/setChatIndexPointer")!
		var req = URLRequest(url: url, timeoutInterval: 30)
		req.httpMethod = "POST"
		req.setValue("application/json", forHTTPHeaderField: "Content-Type")
		let body: [String: Any] = [
			"owner": eoa,
			"indexHash": indexHash,
			"ts": String(ts),
			"seq": String(seq),
			"nonce": String(nonceDec),
			"signature": signature,
		]
		req.httpBody = try? JSONSerialization.data(withJSONObject: body)
		let sem = DispatchSemaphore(value: 0)
		var status = 0
		URLSession.shared.dataTask(with: req) { _, response, _ in
			status = (response as? HTTPURLResponse)?.statusCode ?? 0
			sem.signal()
		}.resume()
		_ = sem.wait(timeout: .now() + 30)
		if !(200..<300).contains(status) {
			log("warn", "[history] setChatIndexPointer HTTP \(status)")
			return false
		}
		return true
	}

	@discardableResult
	private func uploadFragment(_ cipherB64: String) -> String? {
		let contentHash: String
		do {
			contentHash = try awaitKeccakSync(cipherB64)
		} catch {
			return nil
		}
		let url = URL(string: "\(ipfsWriteBaseUrl)/storageFragment")!
		var req = URLRequest(url: url, timeoutInterval: 45)
		req.httpMethod = "POST"
		req.setValue("application/json", forHTTPHeaderField: "Content-Type")
		let body: [String: Any] = [
			"wallet": eoa,
			"signMessage": selfSign,
			"image": cipherB64,
		]
		req.httpBody = try? JSONSerialization.data(withJSONObject: body)
		let sem = DispatchSemaphore(value: 0)
		var ok = false
		URLSession.shared.dataTask(with: req) { _, response, _ in
			let status = (response as? HTTPURLResponse)?.statusCode ?? 0
			ok = (200..<300).contains(status)
			sem.signal()
		}.resume()
		_ = sem.wait(timeout: .now() + 45)
		return ok ? contentHash : nil
	}

	private func downloadFragment(cid: String) -> String? {
		fetchFragment(hash: cid)
	}

	private func fetchFragment(hash: String) -> String? {
		guard var comps = URLComponents(string: "\(ipfsBaseUrl)/getFragment") else { return nil }
		comps.queryItems = [URLQueryItem(name: "hash", value: hash)]
		guard let url = comps.url else { return nil }
		var req = URLRequest(url: url, timeoutInterval: 30)
		req.httpMethod = "GET"
		req.cachePolicy = .reloadIgnoringLocalCacheData
		let sem = DispatchSemaphore(value: 0)
		var text = ""
		var status = 0
		URLSession.shared.dataTask(with: req) { data, response, _ in
			status = (response as? HTTPURLResponse)?.statusCode ?? 0
			if let data, let s = String(data: data, encoding: .utf8) { text = s.trimmingCharacters(in: .whitespacesAndNewlines) }
			sem.signal()
		}.resume()
		_ = sem.wait(timeout: .now() + 30)
		guard (200..<300).contains(status), !text.isEmpty else { return nil }
		return text
	}

	private func ethCall(to: String, data: String) -> String? {
		let url = URL(string: conetRpcUrl)!
		var req = URLRequest(url: url, timeoutInterval: 20)
		req.httpMethod = "POST"
		req.setValue("application/json", forHTTPHeaderField: "Content-Type")
		let payload: [String: Any] = [
			"jsonrpc": "2.0",
			"id": 1,
			"method": "eth_call",
			"params": [["to": to, "data": data], "latest"],
		]
		req.httpBody = try? JSONSerialization.data(withJSONObject: payload)
		let sem = DispatchSemaphore(value: 0)
		var result: String?
		URLSession.shared.dataTask(with: req) { data, _, _ in
			defer { sem.signal() }
			guard let data,
			      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
			      let r = obj["result"] as? String
			else { return }
			result = r
		}.resume()
		_ = sem.wait(timeout: .now() + 20)
		return result
	}

	// MARK: - Crypto helpers

	private func awaitEip191(_ message: String) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "sign", code: -1))
		BeamioConetChatSignBroker.requestEip191(message: message) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 30)
		return try out.get()
	}

	private func awaitEip712(_ typedData: [String: Any]) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "sign", code: -1))
		BeamioConetChatSignBroker.requestEip712(typedData: typedData) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 30)
		return try out.get()
	}

	private func awaitKeccak(_ text: String) throws -> String {
		let sem = DispatchSemaphore(value: 0)
		var out: Result<String, Error> = .failure(NSError(domain: "keccak", code: -1))
		openPgp.keccakUtf8(text) { result in
			out = result
			sem.signal()
		}
		_ = sem.wait(timeout: .now() + 10)
		return try out.get()
	}

	private func awaitKeccakSync(_ text: String) throws -> String {
		try awaitKeccak(text)
	}

	private static func hkdf(master: Data, info: String, length: Int) throws -> Data {
		let key = SymmetricKey(data: master)
		let derived = HKDF<SHA256>.deriveKey(
			inputKeyMaterial: key,
			salt: Data(),
			info: Data(info.utf8),
			outputByteCount: length
		)
		return derived.withUnsafeBytes { Data($0) }
	}

	private static func aesGcmEncrypt(key: Data, plaintext: Data) throws -> String {
		let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key))
		guard let combined = sealed.combined else {
			throw NSError(domain: "aes", code: -1, userInfo: [NSLocalizedDescriptionKey: "no_combined"])
		}
		return combined.base64EncodedString()
	}

	private static func aesGcmDecrypt(key: Data, b64: String) throws -> String {
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

	private static func hexToData(_ hex: String) -> Data? {
		var h = hex.lowercased()
		if h.hasPrefix("0x") { h = String(h.dropFirst(2)) }
		guard h.count % 2 == 0 else { return nil }
		var data = Data()
		var idx = h.startIndex
		while idx < h.endIndex {
			let next = h.index(idx, offsetBy: 2)
			guard let b = UInt8(h[idx..<next], radix: 16) else { return nil }
			data.append(b)
			idx = next
		}
		return data
	}

	private func padAddress(_ addr: String) -> String {
		var a = addr.lowercased()
		if a.hasPrefix("0x") { a = String(a.dropFirst(2)) }
		return String(repeating: "0", count: max(0, 64 - a.count)) + a
	}

	private func checksumLike(_ lower: String) -> String {
		// PWA recovers checksummed; for selfSign we pass lower — SignBroker uses session wallet.
		return lower
	}

	private static func shortCid(_ cid: String) -> String {
		guard cid.count > 14 else { return cid }
		return String(cid.prefix(10)) + "…" + String(cid.suffix(4))
	}
}

private extension TimeInterval {
	var milliseconds: Int64 { Int64(self * 1000) }
}
