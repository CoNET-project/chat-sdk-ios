#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The agreed read of the two chain endpoints, the registry owner read and the account registration payload. Synthetic data only; no network.
final class NewAccountChainAndPayloadTests: XCTestCase {
	private let eoaA = "0x00000000000000000000000000000000000000a1"
	private let armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nsynthetic-armor-text\n-----END PGP PUBLIC KEY BLOCK-----\n"

	// MARK: - a mock of two endpoints

	private struct Node {
		var chainId = 224422
		var latest = 0x20
		var hash = "0x" + String(repeating: "a", count: 64)
		var keysArmor = ""
		var exists = false
		var backup = ""
		var registryOwner = [UInt8](repeating: 0, count: 32)
		var down = false
	}

	private var nodes: [String: Node] = [:]
	private var savedConfiguration: AddressPGPChain.Configuration?
	private var savedSecond: URL?
	private var savedRegistry: String?
	private var savedTransport: ((URL, Data) -> Result<Data, Error>)!
	private var calls: [String: [String]] = [:]

	private func word(_ n: Int) -> [UInt8] { [UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) } }
	private func encodedString(_ s: String) -> [UInt8] {
		let data = Array(s.utf8)
		return word(data.count) + data + [UInt8](repeating: 0, count: (32 - data.count % 32) % 32)
	}
	private func hex(_ bytes: [UInt8]) -> String { "0x" + bytes.map { String(format: "%02x", $0) }.joined() }

	override func setUp() {
		super.setUp()
		savedConfiguration = AddressPGPChain.configuration
		savedSecond = AddressPGPChain.shellEndpointSecond
		savedRegistry = AddressPGPChain.registryContract
		savedTransport = AddressPGPChain.transport
		AddressPGPChain.configuration = AddressPGPChain.Configuration(contract: "0x" + String(repeating: "1", count: 40), chainId: 224422, rpcURL: URL(string: "https://rpc1.test.invalid")!)
		AddressPGPChain.shellEndpointSecond = URL(string: "https://rpc2.test.invalid")
		AddressPGPChain.registryContract = "0x" + String(repeating: "2", count: 40)
		nodes = ["rpc1.test.invalid": Node(), "rpc2.test.invalid": Node()]
		calls = [:]
		AddressPGPChain.transport = { [unowned self] url, body in self.answer(url, body) }
	}

	override func tearDown() {
		AddressPGPChain.configuration = savedConfiguration
		AddressPGPChain.shellEndpointSecond = savedSecond
		AddressPGPChain.registryContract = savedRegistry
		AddressPGPChain.transport = savedTransport
		super.tearDown()
	}

	private func answer(_ url: URL, _ body: Data) -> Result<Data, Error> {
		let host = url.host ?? ""
		guard let node = nodes[host], !node.down else { return .failure(AddressPGPChain.ReadError.transport("down")) }
		guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let method = object["method"] as? String else { return .failure(AddressPGPChain.ReadError.malformed) }
		calls[host, default: []].append(method)
		let result: Any
		switch method {
		case "eth_chainId": result = "0x" + String(node.chainId, radix: 16)
		case "eth_blockNumber": result = "0x" + String(node.latest, radix: 16)
		case "eth_getBlockByNumber": result = ["hash": node.hash, "number": (object["params"] as? [Any])?.first ?? ""]
		case "eth_call":
			let call = ((object["params"] as? [Any])?.first as? [String: Any]) ?? [:]
			let data = (call["data"] as? String) ?? ""
			if data.hasPrefix(hex(AddressPGPChain.selector("_pgpKeys(address)"))) {
				let s1 = encodedString(""), s2 = encodedString(node.keysArmor), s3 = encodedString("")
				result = hex(word(128) + word(128 + s1.count) + word(128 + s1.count + s2.count) + word(node.exists ? 1 : 0) + s1 + s2 + s3)
			} else if data.hasPrefix(hex(AddressPGPChain.selector("getOwnerByAccountName(string)"))) {
				result = hex(node.registryOwner)
			} else {
				result = hex(word(32) + encodedString(node.backup))
			}
		default: return .failure(AddressPGPChain.ReadError.rpc("unsupported"))
		}
		return .success(try! JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": result]))
	}

	private func setBoth(_ change: (inout Node) -> Void) { for key in nodes.keys { change(&nodes[key]!) } }

	// MARK: - the agreed read

	func testTwoAgreeingEndpointsGiveOneSnapshotAtTheLowerBlock() throws {
		setBoth { $0.exists = true; $0.keysArmor = armor; $0.backup = "QUJD" }
		nodes["rpc2.test.invalid"]!.latest = 0x1f
		let agreed = try AddressPGPChain.readAgreed(eoa: eoaA).get()
		XCTAssertEqual(agreed.block, "0x1f", "the lower of the two latest blocks")
		XCTAssertEqual(agreed.snapshot, AddressPGPChain.Snapshot(exists: true, publicArmor: armor, backupBase64: "QUJD"))
		XCTAssertEqual(agreed.blockHash, "0x" + String(repeating: "a", count: 64))
		for host in nodes.keys { XCTAssertEqual(calls[host]?.filter { $0 == "eth_call" }.count, 2, "both view calls on both endpoints") }
	}

	func testABase64RegistrationIsReadAsBareArmorByTheAgreedRead() throws {
		setBoth { $0.exists = true; $0.keysArmor = Data(armor.utf8).base64EncodedString() }
		XCTAssertEqual(try AddressPGPChain.readAgreed(eoa: eoaA).get().snapshot.publicArmor, armor)
	}

	func testAnEmptyChainIsAgreedEmpty() throws {
		let agreed = try AddressPGPChain.readAgreed(eoa: eoaA).get()
		XCTAssertEqual(agreed.snapshot, AddressPGPChain.Snapshot(exists: false, publicArmor: "", backupBase64: ""))
	}

	func testAChainIdThatIsNotTheConfiguredOneOnEitherEndpointIsRefused() {
		nodes["rpc2.test.invalid"]!.chainId = 1
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .disagreement("chain_id"))
		nodes["rpc2.test.invalid"]!.chainId = 224422
		nodes["rpc1.test.invalid"]!.chainId = 8453
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .disagreement("chain_id"))
	}

	func testDifferentBlockHashesAtTheSameBlockAreRefused() {
		nodes["rpc2.test.invalid"]!.hash = "0x" + String(repeating: "b", count: 64)
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .disagreement("block_hash"))
	}

	func testDifferentAnswersAtTheSameBlockAreRefused() {
		nodes["rpc1.test.invalid"]!.exists = true; nodes["rpc1.test.invalid"]!.keysArmor = armor
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .disagreement("answer"))
	}

	func testAnEndpointThatIsDownIsAFailureNotAnEmptyChain() {
		nodes["rpc2.test.invalid"]!.down = true
		guard case .failure = AddressPGPChain.readAgreed(eoa: eoaA) else { return XCTFail("a down endpoint must fail the read") }
	}

	func testWithoutTheSecondEndpointTheAgreedReadIsUnconfigured() {
		AddressPGPChain.shellEndpointSecond = nil
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .unconfigured)
		AddressPGPChain.shellEndpointSecond = URL(string: "http://rpc2.test.invalid")
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .unconfigured)
	}

	func testAMalformedRegisteredKeyFailsTheAgreedRead() {
		setBoth { $0.exists = true; $0.keysArmor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx" }
		assertFails(AddressPGPChain.readAgreed(eoa: eoaA), .malformed)
	}

	private func assertFails<T>(_ result: Result<T, Error>, _ expected: AddressPGPChain.ReadError, file: StaticString = #filePath, line: UInt = #line) {
		guard case .failure(let error) = result else { return XCTFail("expected \(expected)", file: file, line: line) }
		XCTAssertEqual(error as? AddressPGPChain.ReadError, expected, file: file, line: line)
	}

	// MARK: - the registry owner

	func testTheRegistryOwnerIsFreeOrAnAddress() throws {
		XCTAssertEqual(try AddressPGPChain.registryOwnerAgreed(accountName: "alice").get(), .free)
		let owner = [UInt8](repeating: 0, count: 12) + [UInt8](repeating: 0xab, count: 20)
		setBoth { $0.registryOwner = owner }
		XCTAssertEqual(try AddressPGPChain.registryOwnerAgreed(accountName: "alice").get(), .owner("0x" + String(repeating: "ab", count: 20)))
	}

	func testTheRegistryReadNeedsTheContractAndAgreement() {
		AddressPGPChain.registryContract = nil
		assertFails(AddressPGPChain.registryOwnerAgreed(accountName: "alice"), .unconfigured)
		AddressPGPChain.registryContract = "0x" + String(repeating: "2", count: 40)
		nodes["rpc1.test.invalid"]!.registryOwner = [UInt8](repeating: 0, count: 12) + [UInt8](repeating: 1, count: 20)
		assertFails(AddressPGPChain.registryOwnerAgreed(accountName: "alice"), .disagreement("answer"))
	}

	func testAMalformedRegistryAnswerIsAReadFailure() {
		setBoth { $0.registryOwner = [UInt8](repeating: 0xff, count: 32) }
		assertFails(AddressPGPChain.registryOwnerAgreed(accountName: "alice"), .malformed)
	}

	// MARK: - the account registration payload

	private var phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var derived: (eoa: String, key: Data) { BeamioPwaWalletSync.derivedAccount(phrase: phrase)! }

	private func store(phrase text: String?, for owner: String) -> MemoryNativeKeyStore {
		let store = MemoryNativeKeyStore()
		if let text { XCTAssertTrue(store.writeItem(.mnemonic, eoa: owner, value: Data(text.utf8))) }
		return store
	}

	private var counter: UInt8 = 0
	private func random(_ n: Int) -> [UInt8] { counter &+= 1; return (0 ..< n).map { UInt8(truncatingIfNeeded: Int($0) &* 7 &+ Int(counter)) } }

	private func makePayload(name: String = "alice", password: String = "correct horse", registry: AddressPGPChain.RegistryOwner = .free) throws -> [String: Any] {
		let saved = BeamioAccountRegisterPayload.registryOwner
		BeamioAccountRegisterPayload.registryOwner = { _ in .success(registry) }
		defer { BeamioAccountRegisterPayload.registryOwner = saved }
		return try BeamioAccountRegisterPayload.make(tag: name, password: password, eoa: derived.eoa, store: store(phrase: phrase, for: derived.eoa), random: random).get()
	}

	func testThePayloadHasTheRecordsOfCreateRecoverAndTheyOpen() throws {
		let result = try makePayload()
		XCTAssertEqual(Set(result.keys), ["accountName", "wallet", "signMessage", "recover", "recoverCodeBase58"])
		XCTAssertEqual(result["accountName"] as? String, "alice")
		let wallet = try XCTUnwrap(result["wallet"] as? String)
		XCTAssertEqual(wallet, derived.eoa, "the wallet is the lower case address")
		XCTAssertEqual(result["signMessage"] as? String, BeamioNativeEthSigner.signEip191(privateKey: [UInt8](derived.key), message: wallet), "EIP-191 over the very wallet text the page forwards (the Cluster checks the signature against it)")
		let code = try XCTUnwrap(result["recoverCodeBase58"] as? String)
		XCTAssertEqual(code.count, 22)
		XCTAssertTrue(BeamioNativeRecovery.isUUID62(code))
		let recover = try XCTUnwrap(result["recover"] as? [[String: String]])
		XCTAssertEqual(recover.count, 2)
		func keccak(_ text: String) -> String { "0x" + BeamioNativeEthSigner.keccak256(Array(text.utf8)).map { String(format: "%02x", $0) }.joined() }
		XCTAssertEqual(recover[0]["hash"], keccak(code), "the code entry is found by the hash of the code")
		XCTAssertEqual(recover[1]["hash"], keccak("alice"), "the password entry is found by the hash of the name")
		let expected = Data(phrase.utf8).base64EncodedString()
		for (index, password) in [code, "correct horse"].enumerated() {
			let record = try XCTUnwrap(BeamioNativeRecovery.Record(base64JSON: try XCTUnwrap(recover[index]["encrypto"])))
			XCTAssertEqual(record.m, 32768); XCTAssertEqual(record.t, 3); XCTAssertEqual(record.p, 1)
			guard case .success(var key) = BeamioArgon2id.derive(password: Array(password.utf8), salt: record.salt, memoryKiB: 32768, iterations: 3, parallelism: 1, outputLength: 32) else { return XCTFail("kdf") }
			defer { BeamioNativeWallet.wipe(&key) }
			let plain = try XCTUnwrap(BeamioNativeRecovery.open(record.combined, key: key), "entry \(index) opens with its own secret")
			XCTAssertEqual(String(data: plain, encoding: .utf8), expected, "the plaintext is the base64 of the phrase")
		}
		// the password entry does not open with the code, nor the code entry with the password
		let codeRecord = try XCTUnwrap(BeamioNativeRecovery.Record(base64JSON: try XCTUnwrap(recover[0]["encrypto"])))
		guard case .success(var wrong) = BeamioArgon2id.derive(password: Array("correct horse".utf8), salt: codeRecord.salt, memoryKiB: 32768, iterations: 3, parallelism: 1, outputLength: 32) else { return XCTFail("kdf") }
		defer { BeamioNativeWallet.wipe(&wrong) }
		XCTAssertNil(BeamioNativeRecovery.open(codeRecord.combined, key: wrong))
	}

	func testNeitherThePasswordNorThePhraseIsInTheResult() throws {
		let result = try makePayload(password: "unique-password-42")
		let text = "\(result)"
		XCTAssertFalse(text.contains("unique-password-42"))
		for word in phrase.split(separator: " ") where word.count > 4 { XCTAssertFalse(text.contains(word), "no phrase word in the result") }
	}

	func testTheRecoverCodeIsBase58OfTheRandomBytes() {
		let base58 = Set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
		XCTAssertEqual(BeamioAccountRegisterPayload.makeRecoverCode(random: [UInt8](repeating: 0, count: 16)), String(repeating: "1", count: 22), "zero is the first digit")
		let top = BeamioAccountRegisterPayload.makeRecoverCode(random: [UInt8](repeating: 0xff, count: 16))
		XCTAssertEqual(top.count, 22, "22 characters hold the largest 128-bit value")
		XCTAssertNotEqual(top, BeamioAccountRegisterPayload.makeRecoverCode(random: [UInt8](repeating: 0xfe, count: 16)))
		// many codes: always 22 characters, only the base58 alphabet (no 0, O, I, l), and still a valid uuid62-shaped value for the restore
		var generator = SystemRandomNumberGenerator()
		for _ in 0 ..< 500 {
			let code = BeamioAccountRegisterPayload.makeRecoverCode(random: (0 ..< 16).map { _ in UInt8.random(in: 0 ... 255, using: &generator) })
			XCTAssertEqual(code.count, 22)
			XCTAssertTrue(code.allSatisfy { base58.contains($0) }, "only base58 characters")
			XCTAssertFalse(code.contains(where: { "0OIl".contains($0) }))
			XCTAssertTrue(BeamioNativeRecovery.isUUID62(code), "the restore's 22-character check still accepts it")
		}
	}

	func testAHeldNameOrATakenNameOrAnUnreadableRegistryMakesNothing() throws {
		var got: [String] = []
		for registry in [AddressPGPChain.RegistryOwner.owner(derived.eoa), .owner("0x" + String(repeating: "cd", count: 20))] {
			let saved = BeamioAccountRegisterPayload.registryOwner
			BeamioAccountRegisterPayload.registryOwner = { _ in .success(registry) }
			defer { BeamioAccountRegisterPayload.registryOwner = saved }
			if case .failure(let f) = BeamioAccountRegisterPayload.make(tag: "alice", password: "pw", eoa: derived.eoa, store: store(phrase: phrase, for: derived.eoa), random: random) { got.append(f.code) }
		}
		XCTAssertEqual(got, ["already_registered", "tag_taken"])
		let saved = BeamioAccountRegisterPayload.registryOwner
		BeamioAccountRegisterPayload.registryOwner = { _ in .failure(AddressPGPChain.ReadError.disagreement("answer")) }
		defer { BeamioAccountRegisterPayload.registryOwner = saved }
		guard case .failure(let f) = BeamioAccountRegisterPayload.make(tag: "alice", password: "pw", eoa: derived.eoa, store: store(phrase: phrase, for: derived.eoa), random: random) else { return XCTFail("must fail") }
		XCTAssertEqual(f.code, "not_ready")
	}

	func testNoPhraseOrAPhraseOfAnotherAccountMakesNothing() {
		let saved = BeamioAccountRegisterPayload.registryOwner
		BeamioAccountRegisterPayload.registryOwner = { _ in .success(.free) }
		defer { BeamioAccountRegisterPayload.registryOwner = saved }
		func code(_ s: MemoryNativeKeyStore, eoa: String) -> String? {
			if case .failure(let f) = BeamioAccountRegisterPayload.make(tag: "alice", password: "pw", eoa: eoa, store: s, random: random) { return f.code }
			return nil
		}
		XCTAssertEqual(code(store(phrase: nil, for: derived.eoa), eoa: derived.eoa), "seal_failed", "without the phrase there is nothing to seal")
		XCTAssertEqual(code(store(phrase: phrase, for: eoaA), eoa: eoaA), "sign_failed", "the phrase derives another address")
	}

	func testABadTagOrAnEmptyPasswordMakesNothing() {
		let saved = BeamioAccountRegisterPayload.registryOwner
		BeamioAccountRegisterPayload.registryOwner = { _ in .success(.free) }
		defer { BeamioAccountRegisterPayload.registryOwner = saved }
		func code(_ name: String, _ password: String) -> String? {
			if case .failure(let f) = BeamioAccountRegisterPayload.make(tag: name, password: password, eoa: derived.eoa, store: store(phrase: phrase, for: derived.eoa), random: random) { return f.code }
			return nil
		}
		for bad in ["", "ab", String(repeating: "a", count: 27), "bad tag", "bad-tag", "@@@", "名前名前"] { XCTAssertEqual(code(bad, "pw"), "bad_tag", "tag \(bad)") }
		XCTAssertEqual(code("alice", ""), "bad_password")
		XCTAssertNil(code("@alice", "pw"), "the @ is removed")
		XCTAssertNil(code("a.l_i9", "pw"))
		XCTAssertNil(code(String(repeating: "a", count: 26), "pw"))
	}

	/// The whole call, with the standard error captured: no password, phrase word or recover code in the log.
	func testTheLogsHoldNoSecret() throws {
		let path = NSTemporaryDirectory() + "payload-log-\(UUID().uuidString).txt"
		FileManager.default.createFile(atPath: path, contents: nil)
		defer { try? FileManager.default.removeItem(atPath: path) }
		let handle = try XCTUnwrap(FileHandle(forWritingAtPath: path))
		let saved = dup(STDERR_FILENO)
		dup2(handle.fileDescriptor, STDERR_FILENO)
		let result = try makePayload(password: "log-check-password")
		fflush(stderr)
		dup2(saved, STDERR_FILENO); close(saved)
		try handle.close()
		let log = try String(contentsOfFile: path, encoding: .utf8).lowercased()
		XCTAssertFalse(log.contains("log-check-password"))
		XCTAssertFalse(log.contains((result["recoverCodeBase58"] as? String ?? "?").lowercased()))
		XCTAssertFalse(phrase.split(separator: " ").contains { $0.count > 4 && log.contains($0) })
	}

	/// At G0 (no native account) the command answers not_ready, not the gate's no_key, before anything is read.
	func testTheCommandAtG0AnswersNotReady() {
		var events: [[String: Any]] = []
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "accountCreateRegister", "reqId": 7001, "tag": "alice", "password": "pw"]) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		XCTAssertEqual(events.first?["error"] as? String, "not_ready")
		XCTAssertNil(events.first?["result"])
	}
}
#endif
