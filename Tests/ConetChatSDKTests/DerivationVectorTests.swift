import CryptoKit
import Foundation
import XCTest
@testable import ConetChatSDK

/// The derivation vectors of `derivation-vectors.v1.json`: C1 historySign and W3, W4
/// (D-01 to D-05), C5 deriveSubkeys (D-06 to D-10), and W7 ephemeralSign (W-01). The inputs are the public BIP-39 test key
/// and synthetic values. Needs DERIVATION_VECTORS=<path to the file>; skipped without it. Runs on macOS and iOS.
final class DerivationVectorTests: XCTestCase {
	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["DERIVATION_VECTORS"] else {
			throw XCTSkip("set DERIVATION_VECTORS to interface/protocol/derivation-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func hexString(_ bytes: [UInt8]) -> String {
		bytes.map { String(format: "%02x", $0) }.joined()
	}

	private func expectOf(_ cases: [[String: Any]], _ id: String) throws -> [String: Any] {
		let found = try XCTUnwrap(cases.first { $0["id"] as? String == id }, "case \(id) is missing")
		return try XCTUnwrap(found["expect"] as? [String: Any], "case \(id) has no expect")
	}

	func testHistoryRootWorkerAndDerivedKeysMatchTheVectors() throws {
		let root = try vectorRoot()
		let inputs = try XCTUnwrap(root["inputs"] as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let privateKey = try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(inputs["P"] as? String)))
		let eoa = try XCTUnwrap(inputs["eoa"] as? String)
		let chainId = try XCTUnwrap(inputs["chainId"] as? Int)
		XCTAssertEqual(eoa, eoa.lowercased(), "the vector eoa is lower case (25.43.2)")

		// D-01: S = EIP-191 over the fixed domain; R_proto = keccak256(utf8(S)).
		let d01 = try expectOf(cases, "D-01")
		let domain = "beamio.chat.history.v1|\(chainId)|" + eoa
		XCTAssertEqual(d01["domain"] as? String, domain)
		let signature = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: privateKey, message: domain))
		XCTAssertEqual(signature, d01["S"] as? String)
		XCTAssertEqual(signature.utf8.count, d01["sUtf8Bytes"] as? Int)
		XCTAssertTrue(signature.hasSuffix("1b") || signature.hasSuffix("1c"), "v is 1b or 1c")
		let rProto = BeamioNativeEthSigner.keccak256(Array(signature.utf8))
		XCTAssertEqual(hexString(rProto), d01["RPROTO"] as? String)
		let rProtoData = Data(rProto)

		// D-02: indexEncKey = HKDF(R_proto, "index-enc", 32), zero salt.
		let indexEncKey = BeamioConetChatHistoryStore.hkdf(master: rProtoData, info: "index-enc", length: 32)
		XCTAssertEqual(hexString([UInt8](indexEncKey)), try expectOf(cases, "D-02")["indexEncKey"] as? String)

		// D-03: genesisCid = "0x" + hex(HKDF(R_proto, "frag-genesis")).
		let genesisBytes = BeamioConetChatHistoryStore.hkdf(master: rProtoData, info: "frag-genesis", length: 32)
		let d03 = try expectOf(cases, "D-03")
		XCTAssertEqual(hexString([UInt8](genesisBytes)), d03["genesisBytes"] as? String)
		let genesisCid = "0x" + hexString([UInt8](genesisBytes))
		XCTAssertEqual(genesisCid, d03["genesisCid"] as? String)

		// D-04, D-05: fragKey(seq, prevCid) = HKDF(R_proto, "frag|" + seq + "|" + prevCid, 32); the CID string is used as is.
		let fragment0 = BeamioConetChatHistoryStore.hkdf(master: rProtoData, info: "frag|0|" + genesisCid, length: 32)
		let d04 = try expectOf(cases, "D-04")
		XCTAssertEqual(d04["prevCid"] as? String, genesisCid)
		XCTAssertEqual(hexString([UInt8](fragment0)), d04["fragKey"] as? String)
		let d05 = try expectOf(cases, "D-05")
		let prevCid = try XCTUnwrap(d05["prevCid"] as? String)
		let fragment1 = BeamioConetChatHistoryStore.hkdf(master: rProtoData, info: "frag|1|" + prevCid, length: 32)
		XCTAssertEqual(hexString([UInt8](fragment1)), d05["fragKey"] as? String)
	}

	func testLocalSubkeysAndBlindIndexesMatchTheVectors() throws {
		let root = try vectorRoot()
		let inputs = try XCTUnwrap(root["inputs"] as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let privateKey = Data(try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(inputs["P"] as? String))))
		let eoa = try XCTUnwrap(inputs["eoa"] as? String)
		let workspace = try XCTUnwrap(inputs["workspace"] as? String)

		// D-06: R_db = HKDF(P, "beamio-chat-local-root|v1|" + eoa + "|" + workspace, salt "beamio-chat-local-root|salt|v1").
		let localRoot = BeamioChatLocalCrypto.localRoot(privateKey: privateKey, eoa: eoa, workspace: workspace)
		XCTAssertEqual(hexString([UInt8](localRoot)), try expectOf(cases, "D-06")["RDB"] as? String)

		// D-07: K_id, K_idx (zero salt), DEK (its own salt), kcv = HMAC-SHA256(DEK, "kcv").
		let d07 = try expectOf(cases, "D-07")
		let idKey = BeamioChatLocalCrypto.idKey(localRoot: localRoot)
		let idxKey = BeamioChatLocalCrypto.idxKey(localRoot: localRoot)
		let dek = BeamioChatLocalCrypto.dek(localRoot: localRoot, eoa: eoa, workspace: workspace)
		XCTAssertEqual(symmetricHex(idKey), d07["kId"] as? String)
		XCTAssertEqual(symmetricHex(idxKey), d07["kIdx"] as? String)
		XCTAssertEqual(symmetricHex(dek), d07["dek"] as? String)
		XCTAssertEqual(BeamioChatLocalCrypto.kcv(dek: dek), d07["kcv"] as? String)

		// D-08: the DEK with a mixed-case eoa differs from the lower-case one (negative case).
		let d08 = try expectOf(cases, "D-08")
		XCTAssertEqual(symmetricHex(dek), d08["dekLowercase"] as? String)
		// The root is the one of the lower-case account (the caller's rule); only the DEK's info carries the mixed case.
		let mixed = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"  // EIP-55 checksum form, as the generator uses
		let mixedDek = BeamioChatLocalCrypto.dek(localRoot: localRoot, eoa: mixed, workspace: workspace)
		XCTAssertEqual(symmetricHex(mixedDek), d08["dekMixedCaseWouldBe"] as? String)
		XCTAssertNotEqual(symmetricHex(mixedDek), symmetricHex(dek))

		// D-09, D-10: blind indexes are base64url(HMAC-SHA256(K_idx, value)), 43 characters.
		let d09 = try expectOf(cases, "D-09")
		XCTAssertEqual(BeamioChatLocalCrypto.stableId(idxKey: idxKey, sendKey: try XCTUnwrap(d09["sendKey"] as? String)),
		               d09["stableId"] as? String)
		let d10 = try expectOf(cases, "D-10")
		XCTAssertEqual(BeamioChatLocalCrypto.blind(idxKey: idxKey, try XCTUnwrap(d10["convKey"] as? String)),
		               d10["convBlind"] as? String)
	}

	/// W-01: the voiceListen text with the upper-cased relayKeyId, and the EIP-191 signature by T (the channel key).
	func testVoiceListenSignatureMatchesTheVector() throws {
		let root = try vectorRoot()
		let inputs = try XCTUnwrap(root["inputs"] as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let w01 = try expectOf(cases, "W-01")
		let sid = try XCTUnwrap(inputs["sid"] as? String)
		let wk = try XCTUnwrap(inputs["wk"] as? String)
		let relayKeyId = try XCTUnwrap(inputs["relayKeyId"] as? String)
		let timestamp = try XCTUnwrap(inputs["timestamp"] as? Int)
		let tk = try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(inputs["tk"] as? String)))

		XCTAssertEqual(BeamioVoiceEphemeral.listenText(sid: sid, wk: wk, relayKeyId: relayKeyId, timestamp: timestamp),
		               w01["text"] as? String)
		XCTAssertTrue(BeamioVoiceEphemeral.register(sid: sid, privateKey: tk))
		defer { BeamioVoiceEphemeral.clear(sid: sid) }
		switch BeamioVoiceEphemeral.sign(sid: sid, wk: wk, relayKeyId: relayKeyId, timestamp: timestamp) {
		case .success(let out):
			XCTAssertEqual(out.temp, w01["temp"] as? String)
			XCTAssertEqual(out.tempSig, w01["tempSig"] as? String)
		case .failure(let failure):
			XCTFail("sign failed: \(failure)")
		}
	}

	private func symmetricHex(_ key: SymmetricKey) -> String {
		key.withUnsafeBytes { hexString(Array($0)) }
	}
}
