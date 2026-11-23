import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The PGP domain tags of the SDK against `protocol/domain-tags-vectors.v1.json`. Each label the SDK
/// holds is compared with the vector's bytes. The checks are booleans, so a label is never printed (LS-G1). The AAD prefixes of the vector (STAGED,
/// MARKER) are not held by the iOS SDK: the migration writes no AAD with them, so they are not applicable here. Synthetic data only.
final class DomainTagVectorTests: XCTestCase {
	/// The digest of the file as registered in (spec).
	static let expectedSHA256 = "0ad596aea11a0c67e42f7ec3d6c17b6af44a9e2a5e3ec7c09dc4da6bdbd30983"  //

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["DOMAIN_TAG_VECTORS"] else {
			throw XCTSkip("set DOMAIN_TAG_VECTORS to interface/protocol/domain-tags-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
		              "the domain-tag file differs from the registered digest (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func rows(_ root: [String: Any]) throws -> [[String: Any]] {
		try XCTUnwrap(root["labels"] as? [[String: Any]])
	}

	/// DT-01 to DT-05: the labels the SDK holds are the vector's bytes. A missing or different label fails with its name only.
	func testTheHeldLabelsAreTheVectorBytes() throws {
		let all = try rows(try vectorRoot())
		let held: [(name: String, label: String)] = [
			("chatEnvelope", BeamioPGPPurpose.candidateDomainTags["chatEnvelope"] ?? ""),
			("groupMessage", BeamioPGPPurpose.candidateDomainTags["groupMessage"] ?? ""),
			("voiceSignal", BeamioPGPPurpose.candidateDomainTags["voiceSignal"] ?? ""),
			("PRECHECK", BeamioPgpMigrationImport.precheckDomain),
			("CHALLENGE", BeamioPgpMigrationImport.challengeDomain),
		]
		for item in held {
			let row = all.first { $0["name"] as? String == item.name }
			XCTAssertTrue(row != nil, "\(item.name): the vector has the row")
			XCTAssertTrue(row?["label"] as? String == item.label, "\(item.name): the SDK label is the vector's bytes")
		}
	}

	/// DT-T1 and DT-T2, recomputed here from the vector's labels: pairwise distinct, and no label a UTF-8 prefix of another. DT-T3 is the vector's
	/// own statement (the internal labels contain "." and cannot come from a purposeId); the file's result for the three checks must read `pass`.
	func testTheLabelsDoNotOverlapAndTheVectorChecksPass() throws {
		let root = try vectorRoot()
		let all = try rows(root)
		let bytes = all.map { Array(($0["label"] as? String ?? "").utf8) }
		let names = all.map { $0["name"] as? String ?? "?" }
		for i in bytes.indices {
			for j in bytes.indices where i != j {
				XCTAssertFalse(bytes[i] == bytes[j], "DT-T1: \(names[i]) and \(names[j]) are equal")
				XCTAssertFalse(bytes[j].starts(with: bytes[i]), "DT-T2: \(names[i]) is a prefix of \(names[j])")
			}
		}
		let checks = try XCTUnwrap(root["cases"] as? [[String: Any]])
		for id in ["DT-T1", "DT-T2", "DT-T3"] {
			let check = checks.first { $0["id"] as? String == id }
			XCTAssertEqual(check?["result"] as? String, "pass", id)
		}
	}

	/// (a),: the passphrase-free probe signs the Android PRECHECK label and message, as the text canonical bytes of the label
	/// followed by the message (the LF at the end of the label is hashed as CRLF).
	func testThePrecheckProbeSignsTheAndroidBytes() throws {
		let all = try rows(try vectorRoot())
		let precheck = try XCTUnwrap(all.first { $0["name"] as? String == "PRECHECK" })
		let expected = Data(((precheck["label"] as? String ?? "") + BeamioPgpMigrationImport.precheckMessage).utf8)
		XCTAssertTrue(BeamioPgpMigrationImport.probeMessage == expected, "the probe data is the Android PRECHECK label and message, literal bytes")
		XCTAssertTrue(BeamioPgpMigrationImport.precheckMessage == "beamio pgp migrate precheck", "the Android PRECHECK message (PgpMigration.kt:29)")
	}

	/// the signed bytes are the UTF-8 label, then the message, as literal bytes. There is no text canonicalisation for sig type 0x00.
	func testTheSignedBytesAreTheLabelThenTheMessageLiterally() {
		let label = "beamio.pgp.migrate.challenge.v1\n"
		let message = Data("0xabc|0xdef|00ff".utf8)
		let signed = BeamioPgpMigrationImport.signedBytes(label: label, message: message)
		XCTAssertTrue(signed == Data("beamio.pgp.migrate.challenge.v1\n0xabc|0xdef|00ff".utf8), "the label's LF is kept as LF, then the message")
		let mixed = BeamioPgpMigrationImport.signedBytes(label: "a\r\nb", message: Data("c\nd\re".utf8))
		XCTAssertTrue(mixed == Data(Array("a\r\nb".utf8) + Array("c\nd\re".utf8)), "every byte is kept as given")
		XCTAssertTrue(BeamioPgpMigrationImport.signedBytes(label: "", message: Data()) == Data(), "empty input gives empty bytes")
	}

	/// (signing type): the migration signature is made over the canonical bytes, and it verifies with the public key. The signature type
	/// byte of the output is read and reported: X19SignDetached takes no type argument, so the type it writes is a fact to be recorded, not assumed.
	func testTheMigrationSignatureVerifiesOverTheCanonicalBytesAndItsTypeIsReported() throws {
		guard case let .success(pair) = BeamioPGPNative.generateKeyPair(name: "domain-tag-test") else {
			throw XCTSkip("the X-19 framework is not linked in this build")
		}
		let crypto = BeamioPgpMigrationImport.X19Crypto()
		let data = BeamioPgpMigrationImport.probeMessage
		let signature = try XCTUnwrap(crypto.sign(privateArmor: pair.privateArmor, data: data), "the probe signs")
		XCTAssertTrue(crypto.verify(publicArmor: pair.publicArmor, data: data, signature: signature), "the signature verifies over the canonical bytes")
		let type = try XCTUnwrap(Self.signatureType(armor: signature), "the armored signature has a v4 signature packet")
		print("X19-SIG-TYPE 0x\(String(format: "%02x", type)): the type X19SignDetached writes (, sig type 0x00)")
		XCTAssertEqual(type, 0x00, "the migration signature is sig type 0x00")
	}

	/// the CR assertion of is for sig type 0x01 and does not apply to the internal signatures, which are 0x00. A message with a CR is
	/// signed literally; the purpose is still judged first (step 2).
	func testAMessageWithACRIsSignedLiterallyAndThePurposeComesFirst() throws {
		guard case let .success(pair) = BeamioPGPNative.generateKeyPair(name: "cr-assert-test") else {
			throw XCTSkip("the X-19 framework is not linked in this build")
		}
		let crypto = BeamioPgpMigrationImport.X19Crypto()
		if case .signed = BeamioPgpMigrationImport.signInternal(crypto: crypto, privateArmor: pair.privateArmor, label: BeamioPgpMigrationImport.challengeDomain, message: Data("a\rb".utf8)) {
		} else {
			XCTFail("an internal 0x00 signature is not refused for a CR")
		}
		XCTAssertEqual(BeamioPgpMigrationImport.signInternal(crypto: crypto, privateArmor: pair.privateArmor, label: "beamio.chat.example.v1\n", message: Data("a\rb".utf8)),
		               .refused("purpose_not_registered"), "the purpose is judged first (25.27.6 step 2)")
	}

	/// The signature type of the first v4 signature packet of an ASCII-armored signature (RFC 4880 section 4.2, 5.2.1). Nil when there is none.
	static func signatureType(armor: String) -> UInt8? {
		let lines = armor.components(separatedBy: .newlines)
		guard let start = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN") }) else { return nil }
		var base64 = ""
		var inBody = false
		for line in lines[(start + 1)...] {
			if line.hasPrefix("-----END") { break }
			if !inBody {
				if line.isEmpty { inBody = true }
				continue
			}
			if line.hasPrefix("=") { break }
			base64 += line.trimmingCharacters(in: .whitespaces)
		}
		guard let data = Data(base64Encoded: base64) else { return nil }
		let bytes = [UInt8](data)
		guard let first = bytes.first else { return nil }
		let index: Int
		let tag: UInt8
		if first & 0x40 != 0 {
			// New format: the tag in the low six bits, then the length.
			tag = first & 0x3F
			guard bytes.count > 1 else { return nil }
			let length = bytes[1]
			index = length < 192 ? 2 : (length < 224 ? 3 : 6)
		} else {
			// Old format: the tag in bits 2 to 5, the length type in the low two bits.
			tag = (first >> 2) & 0x0F
			switch first & 0x03 {
			case 0: index = 2
			case 1: index = 3
			case 2: index = 5
			default: return nil
			}
		}
		guard tag == 2, bytes.count > index + 1, bytes[index] == 4 else { return nil }
		return bytes[index + 1]
	}

	/// The signing convention of the vector: PRECHECK and CHALLENGE are sig type 0x00, over the literal bytes `label ‖ message`,
	/// with no text canonicalisation and an empty signer passphrase. The vector must say so, and the SDK's bytes must be that concatenation.
	func testTheVectorSigningConventionIsTheLiteralConcatenation() throws {
		let root = try vectorRoot()
		let convention = try XCTUnwrap(root["signingConvention"] as? [String: Any])
		XCTAssertEqual(convention["applies"] as? [String], ["PRECHECK", "CHALLENGE"], "the convention applies to both internal labels")
		XCTAssertTrue((convention["sigType"] as? String ?? "").hasPrefix("0x00"), "the sig type is 0x00")
		XCTAssertTrue((convention["textCanonicalisation"] as? String ?? "").hasPrefix("无"), "there is no text canonicalisation")
		XCTAssertTrue((convention["signerPassphrase"] as? String ?? "").hasPrefix("空串"), "the signer passphrase is empty")
		let all = try rows(root)
		let challenge = try XCTUnwrap(all.first { $0["name"] as? String == "CHALLENGE" })
		let literal = Data(((challenge["label"] as? String ?? "") + "0xabc|0xdef|00ff").utf8)
		XCTAssertTrue(BeamioPgpMigrationImport.signedBytes(label: challenge["label"] as? String ?? "", message: Data("0xabc|0xdef|00ff".utf8)) == literal,
		              "the CHALLENGE bytes are the literal label and message")
	}
}
