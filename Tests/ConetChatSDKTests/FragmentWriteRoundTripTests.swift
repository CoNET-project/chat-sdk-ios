import CryptoKit
import Foundation
import ObjectiveC
import XCTest
@testable import ConetChatSDK

/// A local stand-in for the three services the history store talks to (the IPFS write and read endpoints, the chain RPC and the index
/// pointer API). It keeps the uploads by content hash, exactly as the store addresses them. Test-only: `URLProtocol` is registered for the
/// test and removed afterwards. No product code is changed. Every host is `stub.invalid`; nothing leaves the process.
final class StubChatBackend: URLProtocol {
	static let host = "stub.invalid"
	private static let lock = NSLock()
	private static var uploadsByHash: [String: String] = [:]
	/// The request record for the source coverage of the log scan (SRC-8,): method and path only, never a body.
	private static var requests: [String] = []

	static func reset() {
		lock.lock()
		uploadsByHash = [:]
		requests = []
		lock.unlock()
	}

	/// The requests this stub answered, as `METHOD path`, in order. Bodies are not recorded.
	static func requestLog() -> [String] {
		lock.lock()
		defer { lock.unlock() }
		return requests
	}

	private static func recordRequest(_ entry: String) {
		lock.lock()
		requests.append(entry)
		lock.unlock()
	}

	static func upload(_ hash: String) -> String? {
		lock.lock()
		defer { lock.unlock() }
		return uploadsByHash[hash]
	}

	static func count() -> Int {
		lock.lock()
		defer { lock.unlock() }
		return uploadsByHash.count
	}

	private static func store(_ image: String) {
		lock.lock()
		uploadsByHash[Keccak256.hexUtf8(image)] = image
		lock.unlock()
	}

	override class func canInit(with request: URLRequest) -> Bool {
		request.url?.host == host
	}

	override class func canonicalRequest(for request: URLRequest) -> URLRequest {
		request
	}

	override func startLoading() {
		guard let url = request.url else {
			client?.urlProtocol(self, didFailWithError: URLError(.badURL))
			return
		}
		var status = 200
		var data = Data("{}".utf8)
		Self.recordRequest("\(request.httpMethod ?? "GET") \(url.path)")
		if (request.httpMethod ?? "GET") == "POST" {
			let json = (Self.bodyJSON(request) as? [String: Any]) ?? [:]
			switch url.path {
			case "/ipfs-write/storageFragment":
				if let image = json["image"] as? String { Self.store(image) }
			case "/api/setChatIndexPointer":
				break
			case "/rpc":
				data = Self.rpcResponse(json)
			default:
				status = 404
			}
		} else if url.path == "/ipfs/getFragment" {
			let hash = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "hash" }?.value
			if let hash, let image = Self.upload(hash) {
				data = Data(image.utf8)
			} else {
				status = 404
				data = Data()
			}
		} else {
			status = 404
			data = Data()
		}
		let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
		client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
		client?.urlProtocol(self, didLoad: data)
		client?.urlProtocolDidFinishLoading(self)
	}

	override func stopLoading() {}

	private static func bodyJSON(_ request: URLRequest) -> Any? {
		var data = request.httpBody
		if data == nil, let stream = request.httpBodyStream {
			stream.open()
			var buffer = [UInt8](repeating: 0, count: 4096)
			var collected = Data()
			while stream.hasBytesAvailable {
				let n = stream.read(&buffer, maxLength: buffer.count)
				if n <= 0 { break }
				collected.append(buffer, count: n)
			}
			stream.close()
			data = collected
		}
		guard let data else { return nil }
		return try? JSONSerialization.jsonObject(with: data)
	}

	/// `getPointer(address)` answers an empty pointer (no index yet); `nonceOf(address)` answers zero.
	private static func rpcResponse(_ json: [String: Any]) -> Data {
		let params = json["params"] as? [Any]
		let call = (params?.first as? [String: Any])?["data"] as? String ?? ""
		let result: String
		if call.hasPrefix("0x6bd15a9f") {
			result = "0x" + String(repeating: "0", count: 64 * 3)
		} else {
			result = "0x" + String(repeating: "0", count: 64)
		}
		let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "result": result]
		return (try? JSONSerialization.data(withJSONObject: body)) ?? Data()
	}
}

/// W4 on the write side. Two entries are appended
/// through the production store. The captured uploads are read back through the production read point, and the first fragment is also opened
/// with the vector key D-04 and the second with D-05. Needs DERIVATION_VECTORS; skipped without it.
final class FragmentWriteRoundTripTests: XCTestCase {
	private let peer = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	private var savedBrokerStore: BeamioChatWalletKeyStoring?
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		StubChatBackend.reset()
		URLProtocol.registerClass(StubChatBackend.self)
		EphemeralConfigurationStub.install()
		savedBrokerStore = BeamioConetChatSignBroker.keyStore
		savedNativeStore = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		EphemeralConfigurationStub.remove()
		URLProtocol.unregisterClass(StubChatBackend.self)
		// SRC-8 record: the requests the stub answered in this test, method and path only.
		print("SRC-8 stub requests (METHOD path, no bodies): \(StubChatBackend.requestLog())")
		StubChatBackend.reset()
		if let savedBrokerStore { BeamioConetChatSignBroker.keyStore = savedBrokerStore }
		if let savedNativeStore { BeamioNativeWallet.keyStore = savedNativeStore }
		super.tearDown()
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["DERIVATION_VECTORS"] else {
			throw XCTSkip("set DERIVATION_VECTORS to interface/protocol/derivation-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func expectOf(_ cases: [[String: Any]], _ id: String) throws -> [String: Any] {
		let found = try XCTUnwrap(cases.first { $0["id"] as? String == id }, "case \(id) is missing")
		return try XCTUnwrap(found["expect"] as? [String: Any], "case \(id) has no expect")
	}

	private func append(_ store: BeamioConetChatHistoryStore, sendId: String, body: String) -> Bool? {
		let done = expectation(description: "append \(sendId)")
		var result: Bool?
		store.append(entry: ["sendId": sendId, "peer": peer, "dir": "out", "body": body, "ts": NSNumber(value: 1_700_000_000_000 as Int64)]) { ok in
			result = ok
			done.fulfill()
		}
		wait(for: [done], timeout: 30)
		return result
	}

	private func rawRecord(_ dict: [String: Any]) throws -> BeamioConetChatLocalStore.RawIndexRecord {
		BeamioConetChatLocalStore.RawIndexRecord(
			seq: try XCTUnwrap(dict["seq"] as? Int),
			cid: try XCTUnwrap(dict["cid"] as? String),
			prevCid: try XCTUnwrap(dict["prevCid"] as? String),
			ts: try XCTUnwrap((dict["ts"] as? NSNumber)?.int64Value),
			peer: try XCTUnwrap(dict["peer"] as? String),
			dir: try XCTUnwrap(dict["dir"] as? String),
			sendId: try XCTUnwrap(dict["sendId"] as? String),
			revision: 0,
			deleted: false
		)
	}

	/// Two appends through the production store, read back through `fetchVerifiedBody` with the store's own fetcher and index records.
	func testWrittenFragmentsReadBackThroughTheProductionReadPoint() throws {
		let root = try vectorRoot()
		let inputs = try XCTUnwrap(root["inputs"] as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let eoa = try XCTUnwrap(inputs["eoa"] as? String)
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		let chainId = try XCTUnwrap(inputs["chainId"] as? Int)
		let privateKey = try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(inputs["P"] as? String)))
		// The native signer reads the account key from its own store; the test puts the vector key there and nowhere else.
		let keys = ChatLocalWalletBoundaryTests.MemoryWalletKeyStore()
		BeamioNativeWallet.keyStore = keys
		BeamioConetChatSignBroker.keyStore = keys
		XCTAssertTrue(keys.write(eoa: eoa, key: Data(privateKey)), "key placed for the account")

		let store = BeamioConetChatHistoryStore(
			eoa: eoa, chainId: chainId, conetRpcUrl: "https://\(StubChatBackend.host)/rpc",
			ipfsBaseUrl: "https://\(StubChatBackend.host)/ipfs", ipfsWriteBaseUrl: "https://\(StubChatBackend.host)/ipfs-write",
			apiBaseUrl: "https://\(StubChatBackend.host)/api", registryAddress: "0x1234567890123456789012345678901234567890",
			openPgp: nil, log: { _, _ in }
		)
		let prepared = expectation(description: "prepare")
		var ready: Bool?
		store.prepare { ok in
			ready = ok
			prepared.fulfill()
		}
		wait(for: [prepared], timeout: 30)
		XCTAssertEqual(ready, true, "the store is ready with the vector account")

		XCTAssertEqual(append(store, sendId: "w4-one", body: "synthetic write one"), true)
		XCTAssertEqual(append(store, sendId: "w4-two", body: "synthetic write two"), true)

		let source = try XCTUnwrap(store.localSyncSource(), "the store exposes its records and fetcher")
		let records = try source.records.map(rawRecord)
		XCTAssertEqual(records.map(\.seq), [0, 1])
		guard records.count == 2 else { return }
		let genesisCid = try XCTUnwrap(try expectOf(cases, "D-03")["genesisCid"] as? String)
		XCTAssertEqual(records[0].prevCid, genesisCid, "fragment 0 is keyed on the genesis CID")
		XCTAssertEqual(records[1].prevCid, records[0].cid, "fragment 1 is keyed on the CID of fragment 0")

		let ctx = BeamioConetChatLocalStore.SyncContext(
			master: source.master, dek: SymmetricKey(size: .bits256), idKey: SymmetricKey(size: .bits256), idxKey: SymmetricKey(size: .bits256)
		)
		XCTAssertEqual(BeamioConetChatLocalStore.fetchVerifiedBody(records[0], ctx: ctx, fetchCipher: source.fetch), "synthetic write one")
		XCTAssertEqual(BeamioConetChatLocalStore.fetchVerifiedBody(records[1], ctx: ctx, fetchCipher: source.fetch), "synthetic write two")

		// Fragment 0 is sealed with the vector key of D-04 (seq 0, prevCid = genesisCid), byte for byte.
		let d04 = try expectOf(cases, "D-04")
		let key0 = Data(try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(d04["fragKey"] as? String))))
		let image0 = try XCTUnwrap(StubChatBackend.upload(records[0].cid), "the fragment 0 upload is captured by its content hash")
		XCTAssertEqual(try BeamioConetChatHistoryStore.aesGcmDecrypt(key: key0, b64: image0), "synthetic write one")

		// Fragment 1 is keyed on the CID of fragment 0 in this chain. The D-05 vector uses a synthetic prevCid, so its key does not apply here:
		// the written fragment opens with HKDF(R_proto, "frag|1|" + records[1].prevCid), and the D-05 key does not open it.
		let image1 = try XCTUnwrap(StubChatBackend.upload(records[1].cid))
		let key1 = BeamioFragmentKeys.key(master: source.master, seq: 1, prevCid: records[1].prevCid)
		XCTAssertEqual(try BeamioConetChatHistoryStore.aesGcmDecrypt(key: key1, b64: image1), "synthetic write two")
		let d05 = try expectOf(cases, "D-05")
		let vectorKey1 = Data(try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(d05["fragKey"] as? String))))
		XCTAssertThrowsError(try BeamioConetChatHistoryStore.aesGcmDecrypt(key: vectorKey1, b64: image1))
		// The key of fragment 0 does not open fragment 1: each fragment is bound to its own (seq, prevCid).
		XCTAssertThrowsError(try BeamioConetChatHistoryStore.aesGcmDecrypt(key: key0, b64: image1))
	}
}

/// Test-only: the history store builds its session from `URLSessionConfiguration.ephemeral` and does not list protocol classes, so a
/// `URLProtocol` registered with `registerClass` alone does not see its requests (checked by a probe: DNS error). While the stub is installed,
/// the ephemeral configuration factory returns a configuration that lists the stub. The swap is removed in tearDown. No product code changes.
extension URLSessionConfiguration {
	@objc class func fragmentStubEphemeralConfiguration() -> URLSessionConfiguration {
		let config = fragmentStubEphemeralConfiguration()
		config.protocolClasses = [StubChatBackend.self] + (config.protocolClasses ?? [])
		return config
	}
}

enum EphemeralConfigurationStub {
	private static var swapped = false

	static func install() {
		guard !swapped else { return }
		guard let original = class_getClassMethod(URLSessionConfiguration.self, NSSelectorFromString("ephemeralSessionConfiguration")),
		      let replacement = class_getClassMethod(URLSessionConfiguration.self, #selector(URLSessionConfiguration.fragmentStubEphemeralConfiguration))
		else { return }
		method_exchangeImplementations(original, replacement)
		swapped = true
	}

	static func remove() {
		guard swapped else { return }
		guard let original = class_getClassMethod(URLSessionConfiguration.self, NSSelectorFromString("ephemeralSessionConfiguration")),
		      let replacement = class_getClassMethod(URLSessionConfiguration.self, #selector(URLSessionConfiguration.fragmentStubEphemeralConfiguration))
		else { return }
		method_exchangeImplementations(original, replacement)
		swapped = false
	}
}
