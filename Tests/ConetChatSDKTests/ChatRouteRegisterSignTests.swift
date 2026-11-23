import CryptoKit
import XCTest
@testable import ConetChatSDK

/// `chatRouteRegister` vault and signing stage, against chat-route-register-vectors.v1.json
/// (PV-1, PV-2, NR-11, NR-12), chat-route-decision-vectors.v1.json (A ack envelope, B reqId, C password) and
/// pgp-backup-compat-vectors.v1.json (the PGP private armor of PV-1 and PV-2). Synthetic data only. Runs with
/// CHAT_ROUTE_REGISTER_VECTORS, PGP_BACKUP_VECTORS and CHAT_ROUTE_DECISION_VECTORS (TEST_RUNNER_ prefix); skipped without them.
final class ChatRouteRegisterSignTests: XCTestCase {
	static let registerSHA256 = "634d98c25e7339b7dac18b0c97525700176d42b94e2ab3b784bb9b5503f3e5c5"
	static let decisionSHA256 = "a26a24cd"

	/// In-memory vault records and hardware, so that no passcode is set and the host Keychain is not read.
	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class MemoryHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { false }
		func createKey(eoa: String) -> Bool { false }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { throw BeamioPasscodeError.hardwareUnavailable }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { throw BeamioPasscodeError.hardwareUnavailable }
		func deleteKey(eoa: String) {}
	}

	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: MemoryRecords(), hardware: MemoryHardware())
		BeamioPasscodeSession.shared.lockAll()
	}

	override func tearDown() {
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// The bundled copy of each env-named file. `fallback` is the interface path, kept for reference only.
	private static let bundledResource: [String: String] = [
		"CHAT_ROUTE_REGISTER_VECTORS": "chat-route-register-vectors.v1",
		"CHAT_ROUTE_DECISION_VECTORS": "chat-route-decision-vectors.v1",
		"PGP_BACKUP_VECTORS": "pgp-backup-compat-vectors.v1",
	]

	private func load(_ env: String, _ fallback: String) throws -> [String: Any] {
		// The registered digest is checked for every file (BundledVectorFile). The env variable overrides the bundled copy when it is set.
		let resource = try XCTUnwrap(Self.bundledResource[env], "no bundled file for \(env)")
		let data = try BundledVectorFile.data(resource: resource, env: env)
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func bytes(hex: String) -> [UInt8] {
		var out: [UInt8] = []
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2)
			out.append(UInt8(hex[index..<next], radix: 16) ?? 0)
			index = next
		}
		return out
	}

	private func decodeBase64Text(_ base64: String) -> String {
		String(data: Data(base64Encoded: base64) ?? Data(), encoding: .utf8) ?? ""
	}

	/// The positive vector `index` (0 = PV-1, 1 = PV-2) as the register stage input, with its PGP record and EOA key.
	private func positive(_ index: Int) throws -> (request: BeamioChatRouteRegister.Request, secrets: BeamioChatPgpKeychain.Secrets,
	                                                 vector: [String: Any], iv: [UInt8], nonce: [UInt8], key: [UInt8]) {
		let register = try load("CHAT_ROUTE_REGISTER_VECTORS", "interface/protocol/chat-route-register-vectors.v1.json")
		let backup = try load("PGP_BACKUP_VECTORS", "interface/protocol/pgp-backup-compat-vectors.v1.json")
		let vector = try XCTUnwrap((register["positives"] as? [[String: Any]])?[index])
		let input = try XCTUnwrap(vector["input"] as? [String: Any])
		let backupPositive = try XCTUnwrap((backup["positives"] as? [[String: Any]])?[index])
		let armor = try XCTUnwrap((backupPositive["pgp"] as? [String: Any])?["privateArmor"] as? String)
		let publicBase64 = try XCTUnwrap(input["publicKeyArmoredBase64"] as? String)
		let request = BeamioChatRouteRegister.Request(
			keyID: input["keyID"] as? String ?? "", publicKeyArmored: publicBase64,
			routeKeyID: input["routeKeyID"] as? String ?? "")
		let wallet = try XCTUnwrap(input["wallet"] as? String)
		let secrets = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: armor, publicKeyArmor: decodeBase64Text(publicBase64), pgpKeyId: request.keyID,
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: wallet)
		let key = bytes(hex: String((input["eoaPrivateKeyString"] as? String ?? "").dropFirst(2)))
		let nonceHex = String((input["nonce"] as? String ?? "").dropFirst(2))
		return (request, secrets, vector, bytes(hex: input["backupIvHex"] as? String ?? ""), bytes(hex: nonceHex), key)
	}

	private func installKey(_ key: [UInt8], for wallet: String) {
		let store = BridgeRetirementAcceptanceTests.Store()
		store.keys[wallet.lowercased()] = Data(key)
		BeamioNativeWallet.keyStore = store
	}

	// MARK: -,: a G2 signing with no account key is not_ready, not no_key

	func testAG2SigningWithoutTheAccountKeyAnswersNotReadyNotNoKey() throws {
		let p = try positive(0)
		let input = try XCTUnwrap(p.vector["input"] as? [String: Any])
		let wallet = input["wallet"] as? String ?? ""
		let savedStore = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = savedStore }
		let restoreG2 = WalletG2Gate.enter(account: wallet)
		defer { restoreG2() }
		BeamioNativeWallet.keyStore = BridgeRetirementAcceptanceTests.Store()
		let outcome = BeamioChatRouteRegister.register(
			account: wallet, request: p.request, secrets: p.secrets,
			timestamp: Int64(input["timestampMs"] as? Int ?? 0), iv: p.iv, nonce: p.nonce)
		guard case .failure(let refusal) = outcome else { return XCTFail("the registration must be refused") }
		XCTAssertEqual(refusal.code, "not_ready", "G2 with no account key: not_ready, never no_key")
	}

	// MARK: - PV-1, PV-2: message, backup and signature match the vectors byte for byte

	func testPositiveVectorsReproduceTheRegistration() throws {
		for index in 0..<2 {
			let p = try positive(index)
			let input = try XCTUnwrap(p.vector["input"] as? [String: Any])
			let wallet = input["wallet"] as? String ?? ""
			let restoreG2 = WalletG2Gate.enter(account: wallet)
			defer { restoreG2() }
			installKey(p.key, for: wallet)
			let outcome = BeamioChatRouteRegister.register(
				account: wallet, request: p.request, secrets: p.secrets,
				timestamp: Int64(input["timestampMs"] as? Int ?? 0), iv: p.iv, nonce: p.nonce)
			let id = p.vector["id"] as? String ?? "PV"
			guard case .success(let result) = outcome else {
				return XCTFail("\(id): registration refused")
			}
			XCTAssertEqual(result["encrypKeyArmored"] as? String, p.vector["encrypKeyArmoredBase64"] as? String, id)
			XCTAssertEqual(result["signature"] as? String, p.vector["signature"] as? String, id)
			XCTAssertEqual(result["wallet"] as? String, p.vector["recoveredAddress"] as? String, "\(id): recovered address is the account")
			let message = BeamioChatRouteRegister.registrationMessage(
				wallet: wallet, keyID: p.request.keyID, publicKeyBase64: p.request.publicKeyArmored,
				encrypKeyBase64: result["encrypKeyArmored"] as? String ?? "", routeKeyID: p.request.routeKeyID,
				timestamp: Int64(input["timestampMs"] as? Int ?? 0), nonce: result["nonce"] as? String ?? "")
			XCTAssertEqual(message, p.vector["message"] as? String, id)
		}
	}

	// MARK: - NR-11 (sig_rejected: key differs from the vault), NR-12 (no_pgp_key: no record)

	func testAKeyThatDiffersFromTheVaultIsRejected() throws {
		let one = try positive(0)
		let two = try positive(1)
		let wallet = (try XCTUnwrap(one.vector["input"] as? [String: Any]))["wallet"] as? String ?? ""
		installKey(one.key, for: wallet)
		// The request carries PV-2's public key; the vault holds PV-1's record.
		let outcome = BeamioChatRouteRegister.register(account: wallet, request: two.request, secrets: one.secrets,
		                                               timestamp: 1, iv: one.iv, nonce: one.nonce)
		XCTAssertEqual(outcome.failure?.code, "sig_rejected")
	}

	func testAMissingVaultRecordIsNoPgpKey() throws {
		let one = try positive(0)
		let wallet = (try XCTUnwrap(one.vector["input"] as? [String: Any]))["wallet"] as? String ?? ""
		installKey(one.key, for: wallet)
		let outcome = BeamioChatRouteRegister.register(account: wallet, request: one.request, secrets: nil,
		                                               timestamp: 1, iv: one.iv, nonce: one.nonce)
		XCTAssertEqual(outcome.failure?.code, "no_pgp_key")
	}

	// MARK: - A group: the ack envelope (decision vectors)

	func testAckEnvelopeHasOnlyTheSpecFields() {
		let success = BeamioChatRouteRegister.ackEnvelope(reqId: "r-1", result: ["wallet": "0x1"], error: nil)
		XCTAssertEqual(Set(success.keys), ["type", "reqId", "ok", "result"])
		XCTAssertEqual(success["ok"] as? Bool, true)
		XCTAssertNil((success["result"] as? [String: Any])?["code"], "no code field")
		let failure = BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request")
		XCTAssertEqual(Set(failure.keys), ["type", "reqId", "ok", "error"])
		XCTAssertEqual(failure["error"] as? String, "bad_request")
	}

	// MARK: - B group: reqId rules

	/// The value of a B case. A case with a `jsonLiteral` is read as JSON text: a literal with a fraction or an exponent is not
	/// an integer literal and is refused, and 2^53−1 is legal. A structured case takes its value as it is.
	static func rawValue(_ c: [String: Any]) -> Any? {
		if c["valueAbsent"] as? Bool == true { return nil }
		guard let literal = c["jsonLiteral"] as? String else { return c["value"] }
		if literal.contains(".") || literal.contains("e") || literal.contains("E") { return nil }
		return (try? JSONSerialization.jsonObject(with: Data(literal.utf8), options: .fragmentsAllowed)) as? NSNumber
	}

	func testReqIdRulesMatchTheDecisionVector() throws {
		let decision = try load("CHAT_ROUTE_DECISION_VECTORS", "interface/protocol/chat-route-decision-vectors.v1.json")
		let cases = try XCTUnwrap((decision["B_reqId"] as? [String: Any])?["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 21, "the B group of the registered vector")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let expectOk = (c["expect"] as? [String: Any])?["ok"] as? Bool ?? false
			let raw: Any? = Self.rawValue(c)
			XCTAssertEqual(BeamioChatRouteRegister.reqIdEcho(raw) != nil, expectOk, id)
		}
	}

	// MARK: - C group: the password is the canonical form, and only that form opens the backup

	func testPasswordFormMatchesTheDecisionVector() throws {
		let decision = try load("CHAT_ROUTE_DECISION_VECTORS", "interface/protocol/chat-route-decision-vectors.v1.json")
		let cases = try XCTUnwrap((decision["C_password"] as? [String: Any])?["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 6)
		let backup = try XCTUnwrap((try load("CHAT_ROUTE_REGISTER_VECTORS", "chat-route-register-vectors.v1.json")["positives"] as? [[String: Any]])?.first)
		let blob = try XCTUnwrap(Data(base64Encoded: backup["encrypKeyArmoredBase64"] as? String ?? ""))
		let iv = blob.prefix(12)
		let tag = blob.suffix(16)
		let ciphertext = blob.dropFirst(12).dropLast(16)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let password = c["passwordString"] as? String ?? ""
			let expect = c["expect"] as? [String: Any] ?? [:]
			XCTAssertEqual(BeamioChatRouteRegister.isCanonicalPassword(password), expect["formatValid"] as? Bool, id)
			let key = SymmetricKey(data: Data(SHA256.hash(data: Data(password.utf8))))
			let opened = (try? AES.GCM.open(AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ciphertext, tag: tag), using: key))
			XCTAssertEqual(opened != nil, expect["canonicalBackupDecrypts"] as? Bool, id)
		}
	}
}

private extension Result where Failure == BeamioChatRouteRegister.RouteRegisterRefusal {
	var failure: BeamioChatRouteRegister.RouteRegisterRefusal? {
		if case .failure(let refusal) = self { return refusal }
		return nil
	}
}
