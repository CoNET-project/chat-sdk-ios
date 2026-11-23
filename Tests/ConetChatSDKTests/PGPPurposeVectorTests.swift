import CryptoKit
import XCTest
@testable import ConetChatSDK

/// pgp-purpose-vectors.v1.json: A (domain tag bytes), B (refusal matrix, 42), C (invalid purposeId, 9).
/// REGISTERED_PURPOSES is empty, so the positive group has 0 items and is checked as empty. Synthetic data only: the vector
/// file has no keys and no signatures. Runs with PGP_PURPOSE_VECTORS=<path>; skipped without it. The file is not edited
/// to fit the code.
final class PGPPurposeVectorTests: XCTestCase {
	static let expectedSHA256 = "c55610e0b0596d79d8bb03ae88fa9ba10809f12d65f5a4e593de1acf579a4ef1"

	private func vectors() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_PURPOSE_VECTORS"] else {
			throw XCTSkip("set PGP_PURPOSE_VECTORS to interface/protocol/pgp-purpose-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
		              "vector file sha256 differs from the published value (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// A key store with no record, for the account of the refusal matrix.
	private final class EmptyKeyStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { [] }
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { false }
	}

	private func bytes(fromHex s: String) -> Data? {
		guard s.count % 2 == 0 else { return nil }
		var out = Data()
		var i = s.startIndex
		while i < s.endIndex {
			let j = s.index(i, offsetBy: 2)
			guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
			out.append(b)
			i = j
		}
		return out
	}

	private func hexString(_ d: Data) -> String {
		d.map { String(format: "%02x", $0) }.joined()
	}

	private func sigType(_ s: String) -> UInt8? {
		UInt8(s.dropFirst(2), radix: 16)
	}

	func testDomainTagBytesAndSigningObjectsMatchTheVectors() throws {
		let root = try vectors()
		let cases = try XCTUnwrap(root["domainCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 3, "A group: 3 items")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let purpose = c["purposeId"] as? String ?? ""
			// The file writes the LF of the tag as an escape (the characters backslash and n). The hex field is authoritative.
			let tagUtf8 = (c["domainTagUtf8"] as? String ?? "").replacingOccurrences(of: "\\n", with: "\n")
			XCTAssertEqual(BeamioPGPPurpose.candidateDomainTags[purpose], tagUtf8, id)
			let tag = Data(tagUtf8.utf8)
			XCTAssertEqual(c["domainTagBytes"] as? Int, tag.count, id)
			XCTAssertEqual(hexString(tag), c["domainTagHex"] as? String, id)
			XCTAssertEqual(hexString(Data(SHA256.hash(data: tag))), c["domainTagSha256"] as? String, id)
			let sample = bytes(fromHex: c["sampleMessageHex"] as? String ?? "") ?? Data()
			let signed = tag + sample
			XCTAssertEqual(hexString(signed), c["signedPayloadHex"] as? String, id)
			XCTAssertEqual(hexString(Data(SHA256.hash(data: signed))), c["signedPayloadSha256"] as? String, id)
		}
	}

	func testRefusalMatrixMatchesTheVectors() throws {
		// The account is not in the key store: an empty in-memory store, so the answer does not depend on the device Keychain.
		let saved = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = EmptyKeyStore()
		defer { BeamioNativeWallet.keyStore = saved }
		let root = try vectors()
		let cases = try XCTUnwrap(root["refusalCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 42, "B group: 3 candidates x 14 signature types")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let purpose = c["purposeId"] as? String ?? ""
			let type = sigType(c["sigType"] as? String ?? "") ?? 0xFF
			let expect = (c["expect"] as? [String: Any])?["code"] as? String ?? ""
			XCTAssertEqual(BeamioPGPPurpose.refusal(purposeId: purpose, sigType: type)?.rawValue, expect, id)
			// The C4 entry point gives the same answer and reads no key (the account is not in the key store).
			XCTAssertEqual(BeamioNativeWallet.pgpSign(eoa: "0x0000000000000000000000000000000000000001", purposeId: purpose,
			                                          sigType: type, data: Data([1])),
			               .failure(.rejected(expect)), id)
		}
	}

	func testInvalidPurposeIdsAreRefusedWithTheRegistrationCode() throws {
		let root = try vectors()
		let cases = try XCTUnwrap(root["invalidCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 9, "C group: 9 items")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let purpose = c["purposeId"] as? String ?? ""
			XCTAssertEqual(hexString(Data(purpose.utf8)), c["purposeIdBytesHex"] as? String, id)
			let expect = (c["expect"] as? [String: Any])?["code"] as? String ?? ""
			let type = sigType(c["sigType"] as? String ?? "") ?? 0xFF
			XCTAssertEqual(BeamioPGPPurpose.refusal(purposeId: purpose, sigType: type)?.rawValue, expect, id)
		}
	}

	func testPositiveGroupIsEmptyWhileNothingIsRegistered() throws {
		let root = try vectors()
		XCTAssertEqual((root["positiveSignatureCases"] as? [Any])?.count, 0, "no positive case until a purpose is registered")
		XCTAssertTrue(BeamioPGPPurpose.registered.isEmpty)
	}
}
