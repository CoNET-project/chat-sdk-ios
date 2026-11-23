import Foundation

/// The pre-create binding lookup. It reads the current registry only: `getAccount(address)` for an EOA,
/// `getOwnerByAccountName(string)` for a BeamioTag. Only `eth_call` (a read). No transaction, no fallback endpoint, and no EOA is generated here.
///
/// The answers are kept apart (the RPC rule of AGENTS.md): `noBinding` only from the exact `AccountNotFound` revert of an EOA, or from the
/// zero owner of a tag, and only when this device holds no account. `alreadyBound` only from a valid non-empty answer or a local account. Every
/// other outcome is `unavailable`, which never moves the creation forward.
enum BeamioAccountBindingLookup {
	/// The account input of `nativeAccountCreateOpen`.
	enum Account: Equatable {
		case tag(String)
		case eoa(String)
	}

	/// The outcome of one lookup. `unavailable` carries a reason code for logs and tests only; a page only ever gets `lookup_unavailable`.
	enum Outcome: Equatable {
		case noBinding
		case alreadyBound
		case unavailable(String)
	}

	/// the total of one lookup, the local reads included.
	static let totalBudget: TimeInterval = 10

	/// The error data of `AccountNotFound`, exactly: the no-argument error selector and nothing after it.
	static let accountNotFoundData = "0xfaba8ebe"

	/// The current registry and its one endpoint. Both are the values the recovery reader already uses.
	static var registryAddress: String { BeamioRecoveryRegistry.registryAddress }

	/// The transport. Tests replace it. The default is an https POST with the timeout given.
	static var transport: (URL, Data, TimeInterval) -> Result<Data, Error> = defaultTransport

	/// The local sources of an account on this device: the wallet key record and the PGP account record. Tests replace it.
	static var localState: (String) -> (present: Bool, unreadable: Bool) = defaultLocalState

	/// Whether the device holds any PGP private-key record, of any account. Presence only; tests replace it.
	static var deviceK: () -> Bool = { BeamioChatPgpKeychain.deviceHasPrivateRecord() }

	/// The clock `run` starts a lookup on. Tests replace it to put the budget cases on a fake clock.
	static var clock: () -> Date = Date.init

	/// Where a lookup runs. The default is a background queue, so the main queue never waits for the network.
	static var dispatch: (@escaping () -> Void) -> Void = { work in
		DispatchQueue.global(qos: .userInitiated).async(execute: work)
	}

	/// A test seam: when set, `run` answers with it and makes no call at all.
	static var override: ((Account) -> Outcome)?

	/// A test seam: when set, `run` gives the lookup and its completion to it and returns at once. The test answers the completion later.
	static var deferred: ((Account, @escaping (Outcome) -> Void) -> Void)?

	/// The account input: a BeamioTag of 1 to 64 visible ASCII characters, not starting with `0x`; or `0x` and 40 lower-case hex
	/// digits. Nil for anything else (`bad_request`).
	static func parse(_ value: Any?) -> Account? {
		guard let text = value as? String else { return nil }
		if text.hasPrefix("0x") {
			guard text.count == 42, text.dropFirst(2).allSatisfy({ "0123456789abcdef".contains($0) }) else { return nil }
			return .eoa(text)
		}
		guard (1 ... 64).contains(text.unicodeScalars.count),
		      text.unicodeScalars.allSatisfy({ (0x21 ... 0x7E).contains($0.value) })
		else { return nil }
		return .tag(text)
	}

	/// Runs one lookup off the caller's queue and delivers the outcome on the main queue.
	static func run(_ account: Account, completion: @escaping (Outcome) -> Void) {
		// A test seam: the lookup stays in flight until the test hands its completion back.
		if let deferred {
			deferred(account, completion)
			return
		}
		if let override {
			completion(override(account))
			return
		}
		dispatch {
			let outcome = lookup(account, now: clock)
			NSLog("[BeamioBinding] outcome=%@", label(outcome))
			DispatchQueue.main.async { completion(outcome) }
		}
	}

	/// The lookup itself. Synchronous; it blocks for at most the total budget.
	static func lookup(_ account: Account, now: @escaping () -> Date = Date.init) -> Outcome {
		let started = now()
		func elapsed() -> TimeInterval { now().timeIntervalSince(started) }
		func remaining() -> TimeInterval { totalBudget - elapsed() }
		let overBudget: Outcome = .unavailable("timeout")

		switch account {
		case .eoa(let eoa):
			let read = readAccount(eoa, remaining: remaining())
			if elapsed() > totalBudget { return overBudget }
			// A valid non-empty record is positive: it wins over any failure of the local sources (step 2).
			if case .exists = read { return .alreadyBound }
			let local = localState(eoa)
			if elapsed() > totalBudget { return overBudget }
			if local.present { return .alreadyBound }
			if case .unavailable(let reason) = read { return .unavailable(reason) }
			if local.unreadable { return .unavailable("source_unreadable") }
			// Here the read is the exact AccountNotFound revert and the device holds no account of this EOA.
			return .noBinding

		case .tag(let tag):
			let read = readOwner(tag, remaining: remaining())
			if elapsed() > totalBudget { return overBudget }
			if case .owner = read { return .alreadyBound }
			if case .unavailable(let reason) = read { return .unavailable(reason) }
			// Here the read is the zero owner, a decodable answer that names no record. A device record is not positive for a tag
			// the account pointer is read only to see whether the local source can be read at all.
			let pointer = BeamioNativeAccountPointer.get()
			let local = pointer.isEmpty ? (present: false, unreadable: false) : localState(pointer)
			// F-3 (BL-50): a PGP record of any account on the device fails closed, as presence only.
			let kPresent = deviceK()
			if elapsed() > totalBudget { return overBudget }
			if local.unreadable { return .unavailable("source_unreadable") }
			if kPresent { return .unavailable("device_k_present") }
			return .noBinding
		}
	}

	static func label(_ outcome: Outcome) -> String {
		switch outcome {
		case .noBinding: return "no_binding"
		case .alreadyBound: return "already_bound"
		case .unavailable(let reason): return "unavailable:" + reason
		}
	}

	// MARK: - Reads

	/// What `getAccount` answered for an EOA. Only `exists` with a non-empty name is positive.
	enum AccountRead: Equatable {
		case exists(name: String)
		case notFound
		case unavailable(String)
	}

	/// What `getOwnerByAccountName` answered for a tag. A decodable zero address names no record.
	enum OwnerRead: Equatable {
		case owner(String)
		case zero
		case unavailable(String)
	}

	enum CallFailure: Error, Equatable {
		case revert(data: String?)
		case failed(String)
	}

	static func readAccount(_ eoa: String, remaining: TimeInterval) -> AccountRead {
		let data = AddressPGPChain.selector("getAccount(address)") + AddressPGPChain.addressWord(eoa)
		switch ethCall(data: data, remaining: remaining) {
		case .failure(.revert(let revertData)):
			// Only the exact no-argument AccountNotFound counts as no record. Any other revert data is a failure.
			return revertData == accountNotFoundData ? .notFound : .unavailable("revert")
		case .failure(.failed(let reason)):
			return .unavailable(reason)
		case .success(let bytes):
			return decodeAccount(bytes)
		}
	}

	static func readOwner(_ tag: String, remaining: TimeInterval) -> OwnerRead {
		let name = Array(tag.utf8)
		let padding = (32 - name.count % 32) % 32
		let data = AddressPGPChain.selector("getOwnerByAccountName(string)") + uintWord(32) + uintWord(name.count)
			+ name + [UInt8](repeating: 0, count: padding)
		switch ethCall(data: data, remaining: remaining) {
		case .failure(.revert):
			return .unavailable("revert")
		case .failure(.failed(let reason)):
			return .unavailable(reason)
		case .success(let bytes):
			return decodeOwner(bytes)
		}
	}

	/// `getAccount` returns one dynamic tuple: the head word is its offset, and the tuple head has 12 words. Field 9 is `exists`
	/// and field 0 is `accountName`. Anything not canonical is an invalid response.
	static func decodeAccount(_ bytes: [UInt8]) -> AccountRead {
		let invalid = AccountRead.unavailable("invalid_response")
		guard let start = AddressPGPChain.word(bytes, at: 0), start + 12 * 32 <= bytes.count else { return invalid }
		let tuple = Array(bytes[start...])
		guard let exists = AddressPGPChain.word(tuple, at: 9 * 32), exists <= 1 else { return invalid }
		guard let name = AddressPGPChain.string(tuple, headOffset: 0) else { return invalid }
		// `exists` false without the revert is not a no-record answer (only AccountNotFound is): it is unverifiable.
		guard exists == 1 else { return .unavailable("exists_false") }
		guard !name.isEmpty else { return .unavailable("semantic_mismatch") }
		return .exists(name: name)
	}

	/// `getOwnerByAccountName` returns one `address` word: the high 12 bytes are zero and the rest is the address.
	static func decodeOwner(_ bytes: [UInt8]) -> OwnerRead {
		guard bytes.count == 32, bytes[0 ..< 12].allSatisfy({ $0 == 0 }) else { return .unavailable("invalid_response") }
		let address = Array(bytes[12...])
		if address.allSatisfy({ $0 == 0 }) { return .zero }
		return .owner(AddressPGPChain.hex(address))
	}

	/// One `eth_call` at `latest` to the current registry, within the remaining budget. A JSON-RPC answer, result or error, is final:
	/// there is no failover to another endpoint.
	static func ethCall(data: [UInt8], remaining: TimeInterval) -> Result<[UInt8], CallFailure> {
		guard remaining > 0 else { return .failure(.failed("timeout")) }
		let body: [String: Any] = [
			"jsonrpc": "2.0", "id": 1, "method": "eth_call",
			"params": [["to": registryAddress, "data": AddressPGPChain.hex(data)], "latest"],
		]
		guard let payload = try? JSONSerialization.data(withJSONObject: body) else { return .failure(.failed("encode")) }
		let raw: Data
		switch transport(BeamioRecoveryRegistry.endpoint, payload, remaining) {
		case .failure(let error):
			return .failure(.failed(reason(for: error)))
		case .success(let value):
			raw = value
		}
		guard let object = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
			return .failure(.failed("malformed"))
		}
		if let error = object["error"] as? [String: Any] {
			// A revert carries its data. A JSON-RPC error without data is a failure of the call itself, not a revert.
			guard let data = error["data"] as? String else { return .failure(.failed("rpc")) }
			return .failure(.revert(data: data.lowercased()))
		}
		guard let text = object["result"] as? String, let bytes = AddressPGPChain.bytes(fromHex: text) else {
			return .failure(.failed("malformed"))
		}
		return .success(bytes)
	}

	static func reason(for error: Error) -> String {
		if let failure = error as? TransportFailure {
			switch failure {
			case .timeout: return "timeout"
			case .http: return "http"
			case .notHTTPS, .other: return "transport"
			}
		}
		if let urlError = error as? URLError, urlError.code == .timedOut { return "timeout" }
		return "transport"
	}

	/// A non-negative integer as a 32-byte ABI word.
	static func uintWord(_ value: Int) -> [UInt8] {
		[UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(value).bigEndian) { Array($0) }
	}

	// MARK: - Defaults

	static func defaultLocalState(_ eoa: String) -> (present: Bool, unreadable: Bool) {
		let wallet = BeamioNativeWallet.keyStore.keyRecordState(eoa: eoa)
		// The ACTIVE K record, or a K record of another workspace (25.52Z.3 第 7 项): both are positive for the EOA path.
		let pgp = BeamioChatPgpKeychain.bindingRecordState(eoa: eoa)
		return (present: wallet == .present || pgp == .present, unreadable: wallet == .unreadable || pgp == .unreadable)
	}

	enum TransportFailure: Error, Equatable {
		case timeout
		case http
		case notHTTPS
		case other
	}

	/// The https POST of one call. The wait is the timeout given, so a call never outlives the budget it was given.
	static func defaultTransport(_ url: URL, _ body: Data, _ timeout: TimeInterval) -> Result<Data, Error> {
		guard url.scheme?.lowercased() == "https" else { return .failure(TransportFailure.notHTTPS) }
		var request = URLRequest(url: url, timeoutInterval: timeout)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = body
		let box = ResultBox()
		let done = DispatchSemaphore(value: 0)
		URLSession.shared.dataTask(with: request) { data, response, error in
			if let error {
				box.set(.failure(error))
			} else if let data, let http = response as? HTTPURLResponse, (200 ..< 300).contains(http.statusCode) {
				box.set(.success(data))
			} else if response is HTTPURLResponse {
				box.set(.failure(TransportFailure.http))
			} else {
				box.set(.failure(TransportFailure.other))
			}
			done.signal()
		}.resume()
		if done.wait(timeout: .now() + timeout) == .timedOut {
			return .failure(TransportFailure.timeout)
		}
		return box.get()
	}

	private final class ResultBox {
		private let lock = NSLock()
		private var value: Result<Data, Error> = .failure(TransportFailure.other)

		func set(_ result: Result<Data, Error>) {
			lock.lock()
			value = result
			lock.unlock()
		}

		func get() -> Result<Data, Error> {
			lock.lock()
			defer { lock.unlock() }
			return value
		}
	}
}
