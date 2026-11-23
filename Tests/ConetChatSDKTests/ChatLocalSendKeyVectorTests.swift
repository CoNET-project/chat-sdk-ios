import CryptoKit
import XCTest
@testable import ConetChatSDK

/// T-34: recomputes the public sendKey vectors (interface/fixtures/vectors/sendkey-vectors.json, spec 23)
/// byte for byte. Runs when SENDKEY_VECTORS points at the file. Public test material only.
final class ChatLocalSendKeyVectorTests: XCTestCase {
	private func loadVectors() throws -> [String: Any] {
		guard let p = ProcessInfo.processInfo.environment["SENDKEY_VECTORS"], !p.isEmpty else {
			throw XCTSkip("set SENDKEY_VECTORS to sendkey-vectors.json")
		}
		return try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: p))) as? [String: Any] ?? [:]
	}

	private func bytes(_ hex: String) -> Data {
		var out = Data()
		var i = hex.startIndex
		while i < hex.endIndex {
			let n = hex.index(i, offsetBy: 2)
			out.append(UInt8(hex[i..<n], radix: 16) ?? 0)
			i = n
		}
		return out
	}

	private func hexOf(_ key: SymmetricKey) -> String {
		key.withUnsafeBytes { BeamioChatLocalCrypto.hex(Data($0)) }
	}

	func testRootsAndDerivations() throws {
		let v = try loadVectors()
		let roots = v["roots"] as? [String: Any] ?? [:]
		let derivations = v["derivations"] as? [String: Any] ?? [:]
		let inputs = v["inputs"] as? [String: Any] ?? [:]
		let eoa = inputs["eoa"] as? String ?? ""
		let workspace = inputs["workspace"] as? String ?? "default"
		let sig = (roots["S"] as? String ?? "")
		// R_proto = keccak256(utf8(S)), S is the EIP-191 signature string (not raw bytes).
		let rProto = Keccak256.hash(Data(sig.utf8))
		XCTAssertEqual(BeamioChatLocalCrypto.hex(rProto), roots["R_proto"] as? String)
		// R_db = HKDF(ikm = P, salt "beamio-chat-local-root|salt|v1", info "beamio-chat-local-root|v1|eoa|workspace").
		let p = bytes(inputs["P"] as? String ?? "")
		let rDb = BeamioChatLocalCrypto.localRoot(privateKey: p, eoa: eoa, workspace: workspace)
		XCTAssertEqual(BeamioChatLocalCrypto.hex(rDb), roots["R_db"] as? String)
		// K_id from the protocol root, K_idx and DEK from the local root.
		let kIdx = BeamioChatLocalCrypto.idxKey(localRoot: rDb)
		XCTAssertEqual(hexOf(BeamioChatLocalCrypto.idKey(localRoot: rDb)), (derivations["K_id"] as? [String: Any])?["hex"] as? String)
		XCTAssertEqual(hexOf(kIdx), (derivations["K_idx"] as? [String: Any])?["hex"] as? String)
		let dek = BeamioChatLocalCrypto.dek(localRoot: rDb, eoa: eoa, workspace: workspace)
		XCTAssertEqual(hexOf(dek), (derivations["DEK"] as? [String: Any])?["hex"] as? String)
		XCTAssertEqual(BeamioChatLocalCrypto.kcv(dek: dek), (derivations["kcv"] as? [String: Any])?["hex"] as? String)
		// Blind indexes.
		let blind = v["blindIndexes"] as? [String: Any] ?? [:]
		let conv = blind["conv_blind"] as? [String: Any] ?? [:]
		XCTAssertEqual(BeamioChatLocalCrypto.blind(idxKey: kIdx, conv["convKey"] as? String ?? ""), conv["value"] as? String)
		let cidB = blind["cid_blind"] as? [String: Any] ?? [:]
		XCTAssertEqual(BeamioChatLocalCrypto.blind(idxKey: kIdx, cidB["cid"] as? String ?? ""), cidB["value"] as? String)
		let layout = blind["layout_key"] as? [String: Any] ?? [:]
		XCTAssertEqual(BeamioChatLocalCrypto.blind(idxKey: kIdx, layout["params"] as? String ?? ""), layout["value"] as? String)
		// AES-256-GCM: nonce ‖ ciphertext ‖ tag, AAD = conv_blind ‖ 0x1f ‖ stable_id ‖ 0x1f ‖ revision.
		let gcm = v["aesGcm"] as? [String: Any] ?? [:]
		let sealed = Data(base64Encoded: gcm["sealedBase64"] as? String ?? "") ?? Data()
		let aad = Data((gcm["aadUtf8"] as? String ?? "").utf8)
		let plain = try BeamioChatLocalCrypto.open(sealed, key: dek, aad: aad)
		XCTAssertEqual(String(data: plain, encoding: .utf8), gcm["plaintextUtf8"] as? String)
	}

	/// sendKey for each case (spec 4.1, r1): a non-empty sendId is kept, including a UUID; only an empty sendId is derived.
	/// Every case must match the vector file byte for byte (23.4).
	func testSendKeyCasesMatchVectors() throws {
		let v = try loadVectors()
		let inputs = v["inputs"] as? [String: Any] ?? [:]
		let derivations = v["derivations"] as? [String: Any] ?? [:]
		let kId = SymmetricKey(data: bytes((derivations["K_id"] as? [String: Any])?["hex"] as? String ?? ""))
		let kIdx = SymmetricKey(data: bytes((derivations["K_idx"] as? [String: Any])?["hex"] as? String ?? ""))
		let cases = v["sendKeyCases"] as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 8)
		var mismatched: Set<String> = []
		for c in cases {
			let name = c["name"] as? String ?? ""
			let input = c["input"] as? [String: Any] ?? [:]
			let peer = input["peer"] as? String ?? ""
			let dir = input["dir"] as? String ?? ""
			let ts = Int64(input["ts"] as? String ?? "") ?? 0
			let body = input["bodyUtf8"] as? String ?? ""
			let sendId = input["sendId"] as? String ?? ""
			let sendKey: String
			if !sendId.isEmpty {
				sendKey = sendId
			} else {
				sendKey = BeamioChatLocalCrypto.sendKeyDerived(idKey: kId, peer: peer, dir: dir, ts: ts, body: body)
			}
			let stable = BeamioChatLocalCrypto.stableId(idxKey: kIdx, sendKey: sendKey)
			if sendKey != (c["sendKey"] as? String) || stable != (c["stableId"] as? String) {
				mismatched.insert(name)
			}
		}
		XCTAssertEqual(mismatched, [], "every vector case must match byte for byte (23.4)")
	}
}
