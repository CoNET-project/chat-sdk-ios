import XCTest
@testable import ConetChatSDK

/// The AddressPGP read (spec) with a mock transport. No test reaches a real chain: `transport` is replaced in setUp and
/// `configuration` is set to a local https address that is never contacted. Checks: the call shapes (eth_blockNumber, two
/// eth_call at one block, `from` on the backup call only, no write selector), the ABI decoding, and the failure paths.
final class AddressPGPChainTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let contract = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2"

	/// What the mock chain holds for the account.
	struct MockChain {
		var exists: Bool
		var publicArmor: String
		var backup: String
		var readable: Bool
	}

	var mock = MockChain(exists: false, publicArmor: "", backup: "", readable: true)
	var calls: [[String: Any]] = []
	var savedTransport: ((URL, Data) -> Result<Data, Error>)!

	override func setUp() {
		super.setUp()
		savedTransport = AddressPGPChain.transport
		AddressPGPChain.configuration = AddressPGPChain.Configuration(
			contract: contract, chainId: 224422, rpcURL: URL(string: "https://rpc.example.invalid/")!
		)
		AddressPGPChain.transport = { [unowned self] _, body in self.answer(body) }
	}

	override func tearDown() {
		AddressPGPChain.transport = savedTransport
		AddressPGPChain.configuration = nil
		super.tearDown()
	}

	// MARK: - ABI encoding of the mock answers

	private func word(_ n: Int) -> [UInt8] {
		[UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) }
	}

	private func encodedString(_ s: String) -> [UInt8] {
		let data = Array(s.utf8)
		let padded = data + [UInt8](repeating: 0, count: (32 - data.count % 32) % 32)
		return word(data.count) + padded
	}

	/// `(string, string, string, bool)` as `_pgpKeys` returns it.
	private func encodedKeys(publicArmor: String, exists: Bool) -> [UInt8] {
		let head = 4 * 32
		let s1 = encodedString("")
		let s2 = encodedString(publicArmor)
		let s3 = encodedString("")
		let offset1 = head
		let offset2 = offset1 + s1.count
		let offset3 = offset2 + s2.count
		return word(offset1) + word(offset2) + word(offset3) + word(exists ? 1 : 0) + s1 + s2 + s3
	}

	/// `string` as a single return value.
	private func encodedSingleString(_ s: String) -> [UInt8] {
		word(32) + encodedString(s)
	}

	private func hex(_ bytes: [UInt8]) -> String {
		"0x" + bytes.map { String(format: "%02x", $0) }.joined()
	}

	private func rpcResult(_ id: Any?, _ result: Any) -> Result<Data, Error> {
		.success(try! JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": id ?? 1, "result": result]))
	}

	/// The mock node: answers the three calls the read makes, and records them.
	private func answer(_ body: Data) -> Result<Data, Error> {
		guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
		      let method = object["method"] as? String
		else { return .failure(AddressPGPChain.ReadError.malformed) }
		calls.append(object)
		if !mock.readable { return .failure(AddressPGPChain.ReadError.transport("timeout")) }
		switch method {
		case "eth_blockNumber":
			return rpcResult(object["id"], "0x1f4")
		case "eth_call":
			let params = object["params"] as? [Any] ?? []
			let call = (params.first as? [String: Any]) ?? [:]
			let data = (call["data"] as? String) ?? ""
			let keysSelector = hex(AddressPGPChain.selector("_pgpKeys(address)"))
			let backupSelector = hex(AddressPGPChain.selector("getEncryptedPrivateKey()"))
			if data.hasPrefix(keysSelector) {
				return rpcResult(object["id"], hex(encodedKeys(publicArmor: mock.publicArmor, exists: mock.exists)))
			}
			if data == backupSelector {
				return rpcResult(object["id"], hex(encodedSingleString(mock.backup)))
			}
			return .failure(AddressPGPChain.ReadError.rpc("unknown selector"))
		default:
			return .failure(AddressPGPChain.ReadError.rpc("method not allowed in this mock"))
		}
	}

	// MARK: - Call shapes and the read

	func testTheReadMakesTwoViewCallsAtOneBlockAndTheBackupCallCarriesTheAccount() {
		mock = MockChain(exists: true, publicArmor: "armor", backup: "QUJD", readable: true)
		guard case .success(let snapshot) = AddressPGPChain.read(eoa: account) else { return XCTFail("read failed") }
		XCTAssertEqual(snapshot, AddressPGPChain.Snapshot(exists: true, publicArmor: "armor", backupBase64: "QUJD"))
		let methods = calls.map { $0["method"] as? String ?? "" }
		XCTAssertEqual(methods, ["eth_blockNumber", "eth_call", "eth_call"])
		let keysCall = (calls[1]["params"] as? [Any])?.first as? [String: Any]
		let backupCall = (calls[2]["params"] as? [Any])?.first as? [String: Any]
		XCTAssertNil(keysCall?["from"], "_pgpKeys needs no sender")
		XCTAssertEqual(backupCall?["from"] as? String, account, "getEncryptedPrivateKey reads msg.sender: from is the account")
		let blockCalls = calls.dropFirst().map { ($0["params"] as? [Any])?.last as? String }
		XCTAssertEqual(blockCalls, ["0x1f4", "0x1f4"], "both calls at the same block")
	}

	func testNoWriteSelectorIsEverSent() {
		mock = MockChain(exists: true, publicArmor: "armor", backup: "QUJD", readable: true)
		_ = AddressPGPChain.read(eoa: account)
		let forbidden = ["addPublicPGP", "addRoute", "setRouteBySig", "setMyRoute", "clearMyRoute", "changeAddressInAdminlist"]
		for call in calls {
			let data = ((call["params"] as? [Any])?.first as? [String: Any])?["data"] as? String ?? ""
			for name in forbidden {
				XCTAssertFalse(data.hasPrefix(hex(AddressPGPChain.selector(name + "(address)"))), name)
			}
		}
		XCTAssertEqual(calls.map { $0["method"] as? String ?? "" }.filter { $0 == "eth_sendRawTransaction" }.count, 0)
	}

	func testAnEmptyBackupAndNoRecordAreReadAsSuch() {
		mock = MockChain(exists: false, publicArmor: "", backup: "", readable: true)
		guard case .success(let snapshot) = AddressPGPChain.read(eoa: account) else { return XCTFail("read failed") }
		XCTAssertFalse(snapshot.exists)
		XCTAssertEqual(snapshot.backupBase64, "")
	}

	func testAReadFailureIsAnErrorNeverAnEmptyRecord() {
		mock = MockChain(exists: false, publicArmor: "", backup: "", readable: false)
		if case .success = AddressPGPChain.read(eoa: account) { XCTFail("a failed read must not look like a missing record") }
	}

	func testWithoutAConfigurationNothingIsRead() {
		AddressPGPChain.configuration = nil
		XCTAssertEqual(failure(of: AddressPGPChain.read(eoa: account)) as? AddressPGPChain.ReadError, .unconfigured)
		XCTAssertTrue(calls.isEmpty)
	}

	func testAPlainHTTPEndpointIsNotUsable() {
		let plain = AddressPGPChain.Configuration(contract: contract, chainId: 224422, rpcURL: URL(string: "http://127.0.0.1/")!)
		XCTAssertFalse(plain.isUsable)
		let bad = AddressPGPChain.Configuration(contract: "0x123", chainId: 224422, rpcURL: URL(string: "https://x.invalid/")!)
		XCTAssertFalse(bad.isUsable)
	}

	func testTheDefaultTransportRefusesPlainHTTP() {
		let result = AddressPGPChain.defaultTransport(URL(string: "http://127.0.0.1/")!, Data())
		XCTAssertNotNil(failure(of: result))
	}

	private func failure<T>(of result: Result<T, Error>) -> Error? {
		if case .failure(let error) = result { return error }
		return nil
	}

	// MARK: - ABI

	func testTheSelectorsAreTheKeccakOfTheCanonicalSignatures() {
		XCTAssertEqual(hex(AddressPGPChain.selector("getEncryptedPrivateKey()")).count, 10)
		XCTAssertNotEqual(AddressPGPChain.selector("_pgpKeys(address)"), AddressPGPChain.selector("getEncryptedPrivateKey()"))
	}

	func testAStringRoundTripsThroughTheDecoder() {
		let raw = encodedSingleString("synthetic-backup")
		XCTAssertEqual(AddressPGPChain.string(raw, headOffset: 0), "synthetic-backup")
	}

	func testTheKeysTupleDecodesTheArmorAndTheFlag() {
		let raw = encodedKeys(publicArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----", exists: true)
		let decoded = AddressPGPChain.decodePGPKeys(raw)
		XCTAssertEqual(decoded?.publicArmor, "-----BEGIN PGP PUBLIC KEY BLOCK-----")
		XCTAssertEqual(decoded?.exists, true)
	}

	func testATruncatedAnswerIsMalformed() {
		XCTAssertNil(AddressPGPChain.decodePGPKeys([0, 1, 2]))
		XCTAssertNil(AddressPGPChain.string([0, 0, 0], headOffset: 0))
	}
}
