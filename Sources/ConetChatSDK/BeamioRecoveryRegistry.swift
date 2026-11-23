import Foundation

/// The read of the account registry for the native recovery. Only `eth_call` is made: no write
/// method, no transaction, and no Beamio business HTTP endpoint. The record is read from the chain, not from a server.
///
/// - Current registry `0xfFDc8d2021A41F4638Cb3eCf58B5155383EE9f6d` (CONET, chainId 224422): `getBase64ByNameHash(bytes32)` for
/// path A and `getBase64ByAccountName(string)` for path B. One endpoint, `rpc1.conet.network`, 12 seconds (the
/// client reads from one CoNET RPC; there is no second endpoint and no failover).
/// - Pre-migration registry `0x4afaca09cf8307070a83836223Ae129073eC92e5`: RETIRED. Its read-only archive endpoint is deprecated and
/// is not referenced any more. `legacyRecordByAccountName` makes no request and fails closed, so path B never reads "no record" from it.
///
/// An encoded empty string (an ABI `string` of length 0) means "no record". An empty result (`0x`), a failed call (transport, JSON-RPC error,
/// malformed answer) is an error, never a
/// missing record.
public protocol BeamioRecoveryRegistryReading {
	func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error>
	func recordByAccountName(_ name: String) -> Result<String, Error>
	func legacyRecordByAccountName(_ name: String) -> Result<String, Error>
}

/// The pre-migration registry has no usable endpoint any more, so its answer is unknown, never "no record".
public struct LegacyRegistryRetired: Error, Equatable {
	public init() {}
}

public struct BeamioRecoveryRegistry: BeamioRecoveryRegistryReading {
	public static let registryAddress = "0xfFDc8d2021A41F4638Cb3eCf58B5155383EE9f6d"
	/// The one CoNET RPC the registry is read from. The binding lookup reads from it too.
	public static let endpoint = URL(string: "https://rpc1.conet.network")!
	public static let primaryTimeout: TimeInterval = 12

	/// The transport. Tests replace it; the default is an https POST with the given timeout.
	public static var transport: (URL, Data, TimeInterval) -> Result<Data, Error> = defaultTransport

	public init() {}

	public func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
		let data = AddressPGPChain.selector("getBase64ByNameHash(bytes32)") + nameHash
		return Self.readRegistry(to: Self.registryAddress, data: data)
	}

	public func recordByAccountName(_ name: String) -> Result<String, Error> {
		Self.readRegistry(to: Self.registryAddress, data: Self.accountNameCall(name))
	}

	public func legacyRecordByAccountName(_ name: String) -> Result<String, Error> {
		.failure(LegacyRegistryRetired())
	}

	/// `getBase64ByAccountName(string)`: selector, offset word (0x20), length word, the UTF-8 bytes padded to 32.
	static func accountNameCall(_ name: String) -> [UInt8] {
		let bytes = Array(name.utf8)
		let padding = (32 - bytes.count % 32) % 32
		return AddressPGPChain.selector("getBase64ByAccountName(string)")
			+ uintWord(32) + uintWord(bytes.count) + bytes + [UInt8](repeating: 0, count: padding)
	}

	/// A non-negative integer as a 32-byte ABI word.
	static func uintWord(_ value: Int) -> [UInt8] {
		[UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(value).bigEndian) { Array($0) }
	}

	/// The recovery source: one `eth_call` at `latest` to the one CoNET RPC (`endpoint`). There is no failover to a second endpoint
	/// A failed call is an error, never "no record". The answer is an ABI `string`:
	/// an encoded empty string is "no record"; an empty result (`0x`) is unknown, an error (C-1).
	static func readRegistry(to address: String, data: [UInt8]) -> Result<String, Error> {
		let body: [String: Any] = [
			"jsonrpc": "2.0", "id": 1, "method": "eth_call",
			"params": [["to": address, "data": AddressPGPChain.hex(data)], "latest"],
		]
		guard let payload = try? JSONSerialization.data(withJSONObject: body) else {
			return .failure(AddressPGPChain.ReadError.malformed)
		}
		let raw: Data
		switch transport(endpoint, payload, primaryTimeout) {
		case .failure(let error): return .failure(error)
		case .success(let value): raw = value
		}
		guard let object = try? JSONSerialization.jsonObject(with: raw) as? [String: Any] else {
			return .failure(AddressPGPChain.ReadError.malformed)
		}
		if let error = object["error"] as? [String: Any] {
			return .failure(AddressPGPChain.ReadError.rpc((error["message"] as? String) ?? "error"))
		}
		guard let hexText = object["result"] as? String, let bytes = AddressPGPChain.bytes(fromHex: hexText) else {
			return .failure(AddressPGPChain.ReadError.malformed)
		}
		// An empty result (`0x`) is unknown, an error, never "no record" (C-1): the string decoder refuses it.
		guard let value = AddressPGPChain.string(bytes, headOffset: 0) else {
			return .failure(AddressPGPChain.ReadError.malformed)
		}
		return .success(value)
	}

	static func defaultTransport(_ url: URL, _ body: Data, _ timeout: TimeInterval) -> Result<Data, Error> {
		guard url.scheme?.lowercased() == "https" else { return .failure(AddressPGPChain.ReadError.transport("not https")) }
		var request = URLRequest(url: url, timeoutInterval: timeout)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = body
		let done = DispatchSemaphore(value: 0)
		var outcome: Result<Data, Error> = .failure(AddressPGPChain.ReadError.transport("no answer"))
		URLSession.shared.dataTask(with: request) { data, response, error in
			if let error {
				outcome = .failure(error)
			} else if let data, let http = response as? HTTPURLResponse, (200 ..< 300).contains(http.statusCode) {
				outcome = .success(data)
			} else {
				outcome = .failure(AddressPGPChain.ReadError.transport("status"))
			}
			done.signal()
		}.resume()
		if done.wait(timeout: .now() + timeout + 1) == .timedOut {
			return .failure(AddressPGPChain.ReadError.transport("timeout"))
		}
		return outcome
	}
}
