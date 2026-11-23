import CryptoKit
import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// gossip-sign-vectors.v1.json, third version: 32 cases. The 23 cases without a request run through
/// `BeamioGossipSign.sign`; the 9 request-shaped cases (R-1 to R-9) run through the `gossipSign` command, as the page sends them. A signature must match the vector byte
/// for byte; a refusal must return the vector code and no signature. Synthetic key only. Runs with
/// GOSSIP_SIGN_VECTORS=<path to the file>; skipped without it. The expectations are the vector file's.
///
/// Recovery: the vectors carry `recoveredAddress`. This test compares it with the account whose key produced the signature
/// (the key is checked against the account inside `BeamioNativeWallet`). It does not run an independent ecrecover.
final class GossipSignVectorTests: XCTestCase {
	static let expectedSHA256 = "de5e5d34284db8bc8903879a0ec633fd5d537aa89fdca1e8144cce329c9d4705"

	/// In-memory native store holding the synthetic account.
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	private let eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
	private let keyHex = "78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd"
	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		store.keys[eoa] = keyData()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.setSignerEoa(eoa)
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func cases() throws -> [[String: Any]] {
		guard let path = ProcessInfo.processInfo.environment["GOSSIP_SIGN_VECTORS"] else {
			throw XCTSkip("set GOSSIP_SIGN_VECTORS to interface/protocol/gossip-sign-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256, "vector file sha256 differs from the published value (the digest is not printed, so a failure leaves no digest in the log)")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		return try XCTUnwrap(root["cases"] as? [[String: Any]])
	}

	private func keyData() -> Data { Data(hexBytes(keyHex)) }

	private func hexBytes(_ hex: String) -> [UInt8] {
		var out: [UInt8] = []
		var i = hex.startIndex
		while i < hex.endIndex {
			let j = hex.index(i, offsetBy: 2)
			out.append(UInt8(hex[i ..< j], radix: 16) ?? 0)
			i = j
		}
		return out
	}

	func testTheDirectCasesMatchTheVectors() throws {
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		for c in try cases() where c["request"] == nil {
			let id = c["id"] as? String ?? "?"
			let kind = c["kind"] as? String ?? ""
			let bytes = hexBytes(c["messageUtf8Hex"] as? String ?? "")
			XCTAssertEqual(c["messageBytes"] as? Int, bytes.count, id)
			let message = String(decoding: bytes, as: UTF8.self)
			XCTAssertEqual(Array(message.utf8), bytes, "\(id): the vector bytes are valid UTF-8 and survive the round trip")
			let result = BeamioGossipSign.sign(kind: kind, message: message, eoa: eoa)
			if c["expect"] as? String == "ok" {
				guard case .success(let signature) = result else {
					XCTFail("\(id): expected a signature, got \(result)")
					continue
				}
				XCTAssertEqual(signature.lowercased(), (c["signature"] as? String ?? "").lowercased(), "\(id): byte-exact signature")
				XCTAssertEqual(c["recoveredAddress"] as? String, eoa, id)
			} else {
				guard case .failure(let refusal) = result else {
					XCTFail("\(id): expected a refusal, got \(result)")
					continue
				}
				XCTAssertEqual(refusal.rawValue, c["code"] as? String, id)
			}
		}
	}

	/// The bridge command `gossipSign` answers the same signature for a vector string, and nothing else.
	func testTheGossipSignCommandAnswersTheSignatureOnly() throws {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		guard let g1 = try cases().first(where: { $0["id"] as? String == "G-1" }) else {
			throw XCTSkip("set GOSSIP_SIGN_VECTORS to interface/protocol/gossip-sign-vectors.v1.json")
		}
		let message = String(decoding: hexBytes(g1["messageUtf8Hex"] as? String ?? ""), as: UTF8.self)
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(["type": "gossipSign", "reqId": 50, "kind": "gossip", "message": message],
		                                   emit: { event in
			let inner = (event["event"] as? [String: Any]) ?? event
			if inner["type"] as? String == "ack" {
				ack = inner
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		XCTAssertEqual(ack?["ok"] as? Bool, true)
		XCTAssertEqual((ack?["result"] as? [String: Any])?["signature"] as? String, g1["signature"] as? String)
		XCTAssertEqual(Set((ack?["result"] as? [String: Any] ?? [:]).keys), ["signature"])
	}

	/// R-1 to R-9: the request's top-level fields, through the module's `gossipSign` command. `pageDeferAck` is the page's init
	/// declaration (the session's `deferAck`), not a field of the request. The field `inboundGeneration` is checked against the new page rule
	/// only; an old page may omit it. No field enters the signed bytes, so the signature is the vector's.
	func testTheRequestShapeCasesThroughTheCommand() throws {
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		for c in try cases() where c["request"] != nil {
			let id = c["id"] as? String ?? "?"
			let request = c["request"] as? [String: Any] ?? [:]
			let message = String(decoding: hexBytes(c["messageUtf8Hex"] as? String ?? ""), as: UTF8.self)
			BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
			let session = try XCTUnwrap(BeamioConetChatModule.testCurrentSession())
			// pageDeferAck is the test context (the page's init declaration), not a field of the request.
			let context = c["context"] as? [String: Any] ?? [:]
			session.deferAck = (context["pageDeferAck"] as? Bool) ?? false
			var body: [String: Any] = ["type": "gossipSign", "reqId": 60, "kind": c["kind"] as? String ?? "gossip", "message": message]
			for (key, value) in request where key != "pageDeferAck" {
				body[key] = value
			}
			var answer: [String: Any]?
			let done = expectation(description: "ack \(id)")
			BeamioConetChatModule.handleCommand(body, emit: { event in
				let inner = (event["event"] as? [String: Any]) ?? event
				if inner["type"] as? String == "ack" {
					answer = inner
					done.fulfill()
				}
			})
			wait(for: [done], timeout: 5)
			if c["expect"] as? String == "ok" {
				XCTAssertEqual(answer?["ok"] as? Bool, true, "\(id): expected a signature")
				let signature = (answer?["result"] as? [String: Any])?["signature"] as? String
				XCTAssertEqual(signature?.lowercased(), (c["signature"] as? String ?? "").lowercased(), "\(id): byte-exact signature")
			} else {
				XCTAssertEqual(answer?["ok"] as? Bool, false, "\(id): expected a refusal")
				XCTAssertEqual(answer?["error"] as? String, c["code"] as? String, "\(id): the vector code, and no signature")
				XCTAssertNil((answer?["result"] as? [String: Any])?["signature"], "\(id): no signature is returned")
			}
			print("GOSSIP-SIGN \(id): compared with the request-shape rule")
		}
	}
}
#endif
