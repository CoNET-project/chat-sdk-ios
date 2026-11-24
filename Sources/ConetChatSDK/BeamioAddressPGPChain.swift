import Foundation

/// The read-only chain source of P-IMP-PGP. Two view calls on AddressPGP, at one block:
/// `_pgpKeys(address)` → (pgpKeyID, publicKeyArmored, encrypKeyArmored, exists) no sender needed. `publicKeyArmored` is the armor or its base64 text; the snapshot always holds bare armor.
/// `getEncryptedPrivateKey` → the encrypted backup, read from msg.sender, so `from` must be the account
/// Only `eth_blockNumber` and `eth_call` are sent, over https. No write method exists in this file. The contract address,
/// the chain and the RPC are configuration: the recommendation (`0x684b…`, RPC rpc1) is pending the
/// project confirmation, so nothing is configured by default. Without a configuration every read fails
/// as `unconfigured`, which the restore flow reports as `undetermined` (retry), never as "no record".
/// Tests inject `transport`; no test reaches a real chain.
public enum AddressPGPChain {
	public struct Configuration: Equatable {
		/// The AddressPGP contract (0x-prefixed, 40 hex digits).
		public var contract: String
		/// The chain id the contract is deployed on (CoNET L1: 224422 in).
		public var chainId: Int
		/// The JSON-RPC endpoint. Must be https.
		public var rpcURL: URL

		public init(contract: String, chainId: Int, rpcURL: URL) {
			self.contract = contract
			self.chainId = chainId
			self.rpcURL = rpcURL
		}

		/// Nil unless the address is well formed and the endpoint is https.
		public var isUsable: Bool {
			guard contract.hasPrefix("0x"), contract.count == 42, rpcURL.scheme?.lowercased() == "https" else { return false }
			return contract.dropFirst(2).allSatisfy { $0.isHexDigit }
		}
	}

	public enum ReadError: Error, Equatable {
		case unconfigured
		case transport(String)
		case rpc(String)
		case malformed
		/// The two endpoints do not agree (a chain id that is not the configured one, different blocks hashes, or different answers at the same block): never a basis for a write.
		case disagreement(String)
	}

	/// What the chain says about one account at one block.
	public struct Snapshot: Equatable {
		/// `exists` of `_pgpKeys(eoa)`.
		public var exists: Bool
		/// `publicKeyArmored` of `_pgpKeys(eoa)`.
		public var publicArmor: String
		/// `getEncryptedPrivateKey` for the account. Empty when there is no backup.
		public var backupBase64: String
	}

	/// The shell's one CoNET RPC for AddressPGP (the client uses one configured RPC). The shell sets it once from its
	/// native build configuration. It is never read from a PWA payload. Nil by default: nothing is configured from it, and every read fails closed.
	public static var shellEndpoint: URL?

	/// The second, independent CoNET RPC for the agreed read (the result of a first identity needs two endpoints that agree). The shell sets it once from its native build
	/// configuration, never from a page payload. Nil by default: the agreed read fails closed as `unconfigured`.
	public static var shellEndpointSecond: URL?

	/// The configured source. Nil by default (is open). The shell or the app sets it after the owner confirms.
	public static var configuration: Configuration?

	/// POSTs one JSON-RPC body to an https URL and returns the response body. Replaced in tests.
	public static var transport: (URL, Data) -> Result<Data, Error> = defaultTransport

	static let timeoutSeconds: TimeInterval = 8

	static func defaultTransport(_ url: URL, _ body: Data) -> Result<Data, Error> {
		guard url.scheme?.lowercased() == "https" else { return .failure(ReadError.transport("not https")) }
		var request = URLRequest(url: url, timeoutInterval: timeoutSeconds)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = body
		let done = DispatchSemaphore(value: 0)
		var outcome: Result<Data, Error> = .failure(ReadError.transport("no answer"))
		URLSession.shared.dataTask(with: request) { data, response, error in
			if let error {
				outcome = .failure(error)
			} else if let data, let http = response as? HTTPURLResponse, (200 ..< 300).contains(http.statusCode) {
				outcome = .success(data)
			} else {
				outcome = .failure(ReadError.transport("status"))
			}
			done.signal()
		}.resume()
		if done.wait(timeout: .now() + timeoutSeconds + 1) == .timedOut { return .failure(ReadError.transport("timeout")) }
		return outcome
	}

	// MARK: - Calls

	/// 4-byte selector: keccak256 of the canonical signature.
	static func selector(_ signature: String) -> [UInt8] {
		Array(BeamioNativeEthSigner.keccak256(Array(signature.utf8)).prefix(4))
	}

	/// An address as a 32-byte ABI word (left padded).
	static func addressWord(_ address: String) -> [UInt8] {
		let hex = Array(address.lowercased().dropFirst(2).utf8)
		var bytes: [UInt8] = []
		var i = 0
		while i + 1 < hex.count {
			bytes.append(UInt8(String(decoding: hex[i ... i + 1], as: UTF8.self), radix: 16) ?? 0)
			i += 2
		}
		return [UInt8](repeating: 0, count: 32 - bytes.count) + bytes
	}

	static func hex(_ bytes: [UInt8]) -> String {
		"0x" + bytes.map { String(format: "%02x", $0) }.joined()
	}

	static func bytes(fromHex text: String) -> [UInt8]? {
		var t = text
		if t.hasPrefix("0x") || t.hasPrefix("0X") { t = String(t.dropFirst(2)) }
		guard t.count % 2 == 0 else { return nil }
		var out: [UInt8] = []
		out.reserveCapacity(t.count / 2)
		var index = t.startIndex
		while index < t.endIndex {
			let next = t.index(index, offsetBy: 2)
			guard let b = UInt8(t[index ..< next], radix: 16) else { return nil }
			out.append(b)
			index = next
		}
		return out
	}

	/// Reads a 32-byte word at `offset`, as an unsigned integer that must fit in Int.
	static func word(_ data: [UInt8], at offset: Int) -> Int? {
		guard offset >= 0, offset + 32 <= data.count else { return nil }
		let slice = data[offset ..< offset + 32]
		guard slice.prefix(24).allSatisfy({ $0 == 0 }) else { return nil }
		var value = 0
		for b in slice.suffix(8) { value = (value << 8) | Int(b) }
		return value
	}

	/// An ABI `string` whose head word is at `headOffset` (relative to `data`).
	static func string(_ data: [UInt8], headOffset: Int) -> String? {
		guard let start = word(data, at: headOffset), let length = word(data, at: start) else { return nil }
		let from = start + 32
		guard from >= 0, length >= 0, from + length <= data.count else { return nil }
		return String(bytes: data[from ..< from + length], encoding: .utf8)
	}

	/// The result of `_pgpKeys(address)`: (string, string, string, bool).
	static func decodePGPKeys(_ data: [UInt8]) -> (publicArmor: String, exists: Bool)? {
		guard data.count >= 128 else { return nil }
		guard let stored = string(data, headOffset: 32),
		      let existsWord = word(data, at: 96),
		      let publicArmor = bareArmor(fromStored: stored)
		else { return nil }
		return (publicArmor, existsWord != 0)
	}

	/// The registered public key as bare armor. The contract holds the armor either as it is or as the base64 text of the armor (the PWA registers the base64 form, which starts with
	/// `LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBC`). Empty stays empty (no record). Text that starts with `-----BEGIN` is kept. Anything else must be strict base64 whose decoding is text that starts with
	/// the public key header; otherwise the answer is malformed (a read failure, never a missing record). The result is always bare armor.
	static func bareArmor(fromStored stored: String) -> String? {
		if stored.isEmpty { return "" }
		let header = "-----BEGIN PGP PUBLIC KEY BLOCK"
		if stored.hasPrefix(header) { return stored }
		// any other text that starts like an armor (a private key block, another block type) is not a registered public key
		if stored.hasPrefix("-----BEGIN") { return nil }
		guard let decoded = Data(base64Encoded: stored), let text = String(data: decoded, encoding: .utf8), text.hasPrefix(header) else { return nil }
		return text
	}

	static func rpc(_ method: String, _ params: [Any], using config: Configuration? = nil) -> Result<Any, Error> {
		guard let configuration = config ?? Self.configuration, configuration.isUsable else { return .failure(ReadError.unconfigured) }
		let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
		guard let payload = try? JSONSerialization.data(withJSONObject: body) else { return .failure(ReadError.malformed) }
		switch transport(configuration.rpcURL, payload) {
		case .failure(let error): return .failure(error)
		case .success(let raw):
			guard let object = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
				return .failure(ReadError.malformed)
			}
			if let error = object["error"] as? [String: Any] {
				return .failure(ReadError.rpc((error["message"] as? String) ?? "error"))
			}
			guard let result = object["result"] else { return .failure(ReadError.malformed) }
			return .success(result)
		}
	}

	/// Reads the record and the backup of `eoa` at one block. Any failure is an error; nothing is guessed.
	public static func read(eoa rawEoa: String) -> Result<Snapshot, Error> {
		guard let configuration, configuration.isUsable else { return .failure(ReadError.unconfigured) }
		// One block for both calls (step 3).
		switch latestBlock(using: configuration) {
		case .failure(let error): return .failure(error)
		case .success(let block): return read(eoa: rawEoa, at: block, using: configuration)
		}
	}

	/// The latest block of an endpoint, as a JSON-RPC quantity: 0x followed by hex digits, no leading zeros required, odd length allowed (0x1f4).
	static func latestBlock(using configuration: Configuration) -> Result<String, Error> {
		switch rpc("eth_blockNumber", [], using: configuration) {
		case .failure(let error): return .failure(error)
		case .success(let value):
			guard let text = value as? String, text.hasPrefix("0x"), text.count > 2, text.dropFirst(2).allSatisfy({ $0.isHexDigit })
			else { return .failure(ReadError.malformed) }
			return .success(text)
		}
	}

	/// Reads the record and the backup of `eoa` at the given block, on the given endpoint.
	static func read(eoa rawEoa: String, at block: String, using configuration: Configuration) -> Result<Snapshot, Error> {
		let eoa = rawEoa.lowercased()
		guard configuration.isUsable else { return .failure(ReadError.unconfigured) }
		// _pgpKeys(address)
		let keysData = selector("_pgpKeys(address)") + addressWord(eoa)
		let keys: (publicArmor: String, exists: Bool)
		switch rpc("eth_call", [["to": configuration.contract, "data": hex(keysData)], block], using: configuration) {
		case .failure(let error): return .failure(error)
		case .success(let value):
			guard let text = value as? String, let raw = bytes(fromHex: text), let decoded = decodePGPKeys(raw) else {
				return .failure(ReadError.malformed)
			}
			keys = decoded
		}
		// getEncryptedPrivateKey, read from msg.sender: `from` is the account.
		let backupData = selector("getEncryptedPrivateKey()")
		let backup: String
		switch rpc("eth_call", [["from": eoa, "to": configuration.contract, "data": hex(backupData)], block], using: configuration) {
		case .failure(let error): return .failure(error)
		case .success(let value):
			guard let text = value as? String, let raw = bytes(fromHex: text), let decoded = string(raw, headOffset: 0) else {
				return .failure(ReadError.malformed)
			}
			backup = decoded
		}
		return .success(Snapshot(exists: keys.exists, publicArmor: keys.publicArmor, backupBase64: backup))
	}

	// MARK: - The agreed read (two endpoints, one block)

	/// What two endpoints agree on at one block.
	public struct Agreed: Equatable {
		public var snapshot: Snapshot
		/// The block both endpoints read, as a JSON-RPC quantity.
		public var block: String
		/// Its hash, equal on both endpoints.
		public var blockHash: String
	}

	/// The agreed read of the PGP record and the backup of `eoa`: both configured endpoints must name the configured chain id, report the same hash for one block (the lower of their
	/// latest blocks), and answer both view calls identically at that block. Anything else is an error, and the result of a first identity (nothing registered) is taken from this read only.
	public static func readAgreed(eoa rawEoa: String) -> Result<Agreed, Error> {
		guard let configuration, configuration.isUsable, let second = shellEndpointSecond, second.scheme?.lowercased() == "https" else {
			return .failure(ReadError.unconfigured)
		}
		return readAgreed(eoa: rawEoa, configuration: configuration, second: second)
	}

	static func readAgreed(eoa rawEoa: String, configuration: Configuration, second: URL) -> Result<Agreed, Error> {
		let eoa = rawEoa.lowercased()
		let keysData = selector("_pgpKeys(address)") + addressWord(eoa)
		let backupData = selector("getEncryptedPrivateKey()")
		switch agreedCalls(
			configuration: configuration, second: second,
			calls: [(data: keysData, from: nil), (data: backupData, from: eoa)]
		) {
		case .failure(let error): return .failure(error)
		case .success(let agreed):
			guard let keys = decodePGPKeys(agreed.results[0]), let backup = string(agreed.results[1], headOffset: 0) else {
				return .failure(ReadError.malformed)
			}
			return .success(Agreed(snapshot: Snapshot(exists: keys.exists, publicArmor: keys.publicArmor, backupBase64: backup), block: agreed.block, blockHash: agreed.blockHash))
		}
	}

	/// The agreed eth_call of any contract (the PGP record, the account registry): the rules above, for a list of calls.
	static func agreedCalls(
		configuration: Configuration, second: URL, calls: [(data: [UInt8], from: String?)]
	) -> Result<(block: String, blockHash: String, results: [[UInt8]]), Error> {
		let endpoints = [configuration, Configuration(contract: configuration.contract, chainId: configuration.chainId, rpcURL: second)]
		guard endpoints.allSatisfy({ $0.isUsable }) else { return .failure(ReadError.unconfigured) }
		// the chain id of both
		for endpoint in endpoints {
			guard case .success(let id) = rpc("eth_chainId", [], using: endpoint), let text = id as? String, text.hasPrefix("0x"),
			      Int(text.dropFirst(2), radix: 16) == endpoint.chainId else { return .failure(ReadError.disagreement("chain_id")) }
		}
		// one block: the lower of the two latest blocks
		var numbers: [Int] = []
		for endpoint in endpoints {
			switch latestBlock(using: endpoint) {
			case .failure(let error): return .failure(error)
			case .success(let value):
				guard let n = Int(value.dropFirst(2), radix: 16) else { return .failure(ReadError.malformed) }
				numbers.append(n)
			}
		}
		let block = "0x" + String(numbers.min() ?? 0, radix: 16)
		// the same block hash
		var hashes: [String] = []
		for endpoint in endpoints {
			switch rpc("eth_getBlockByNumber", [block, false], using: endpoint) {
			case .failure(let error): return .failure(error)
			case .success(let value):
				guard let object = value as? [String: Any], let hash = (object["hash"] as? String)?.lowercased(), hash.hasPrefix("0x"), hash.count == 66 else {
					return .failure(ReadError.malformed)
				}
				hashes.append(hash)
			}
		}
		guard hashes[0] == hashes[1] else { return .failure(ReadError.disagreement("block_hash")) }
		// the same answers at that block
		var results: [[UInt8]] = []
		for call in calls {
			var answers: [[UInt8]] = []
			for endpoint in endpoints {
				var object: [String: Any] = ["to": endpoint.contract, "data": hex(call.data)]
				if let from = call.from { object["from"] = from }
				switch rpc("eth_call", [object, block], using: endpoint) {
				case .failure(let error): return .failure(error)
				case .success(let value):
					guard let text = value as? String, let raw = bytes(fromHex: text) else { return .failure(ReadError.malformed) }
					answers.append(raw)
				}
			}
			guard answers[0] == answers[1] else { return .failure(ReadError.disagreement("answer")) }
			results.append(answers[0])
		}
		return .success((block, hashes[0], results))
	}

	// MARK: - The account registry (the owner of a BeamioTag)

	/// The AccountRegistry contract (0x-prefixed, 40 hex digits). It comes from the init payload like the AddressPGP contract (never from a page request). Nil: the registry read fails closed.
	public static var registryContract: String?

	public enum RegistryOwner: Equatable {
		/// No account holds the name.
		case free
		/// This address holds the name.
		case owner(String)
	}

	/// `getOwnerByAccountName(string)`: the owner of a BeamioTag, read by both endpoints at one block (the same rules as the agreed PGP read). The zero address is `free`.
	public static func registryOwnerAgreed(accountName: String) -> Result<RegistryOwner, Error> {
		guard let configuration, configuration.isUsable, let second = shellEndpointSecond, second.scheme?.lowercased() == "https",
		      let registry = registryContract, registry.hasPrefix("0x"), registry.count == 42, registry.dropFirst(2).allSatisfy({ $0.isHexDigit }) else {
			return .failure(ReadError.unconfigured)
		}
		return registryOwnerAgreed(accountName: accountName, registry: registry, configuration: configuration, second: second)
	}

	static func registryOwnerAgreed(accountName: String, registry: String, configuration: Configuration, second: URL) -> Result<RegistryOwner, Error> {
		let name = Array(accountName.utf8)
		let padded = [UInt8](repeating: 0, count: (32 - name.count % 32) % 32)
		let data = selector("getOwnerByAccountName(string)") + word(32) + word(name.count) + name + padded
		let registryConfiguration = Configuration(contract: registry, chainId: configuration.chainId, rpcURL: configuration.rpcURL)
		switch agreedCalls(configuration: registryConfiguration, second: second, calls: [(data: data, from: nil)]) {
		case .failure(let error): return .failure(error)
		case .success(let agreed):
			let raw = agreed.results[0]
			guard raw.count >= 32, raw.prefix(12).allSatisfy({ $0 == 0 }) else { return .failure(ReadError.malformed) }
			let address = raw[12 ..< 32]
			if address.allSatisfy({ $0 == 0 }) { return .success(.free) }
			return .success(.owner(hex(Array(address))))
		}
	}

	/// A 32-byte big-endian word of a small number.
	static func word(_ n: Int) -> [UInt8] {
		[UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) }
	}

	// MARK: - The first-identity chain field (single RPC;, 2026-11-20)

	public enum ChainStatus: String, Equatable {
		case unregistered
		case registered
		case unknown
	}

	/// What the chain says about the account, for `pgpRestoreEvaluate.chain` and the first-identity eligibility. One RPC, the configured one: no second
	/// endpoint, no block cross-check, no fallback.
	/// - `registered`: the read shows a registration or a backup.
	/// - `unregistered`: the read succeeded and shows neither.
	/// - `unknown`: anything else: no configuration, a failed or timed-out call, a malformed answer, a chain id that is not the configured one.
	/// A stale node can answer `unregistered` for an identity that exists. The guards are in the create flow: the confirmation reads again, and a
	/// registration seen then is refused (`cas_conflict`).
	public static func chainStatus(eoa: String) -> ChainStatus {
		guard case .success(let snapshot) = read(eoa: eoa) else { return .unknown }
		return chainStatus(from: snapshot)
	}

	/// The same judgement from a snapshot that was just read from the configured endpoint (one read serves the restore evaluation and the field).
	/// The chain id is asked here; a chain id that is not the configured one is `unknown`.
	public static func chainStatus(from snapshot: Snapshot) -> ChainStatus {
		guard let configuration, configuration.isUsable else { return .unknown }
		guard case .success(let id) = rpc("eth_chainId", [], using: configuration), let text = id as? String, text.hasPrefix("0x"),
		      Int(text.dropFirst(2), radix: 16) == configuration.chainId else { return .unknown }
		return snapshot.exists || !snapshot.backupBase64.isEmpty ? .registered : .unregistered
	}

	/// A `chain` value as a page or a stored answer gives it: anything outside the enumeration is `unknown` (fail closed).
	public static func chainStatus(raw: String?) -> ChainStatus {
		raw.flatMap { ChainStatus(rawValue: $0) } ?? .unknown
	}
}
