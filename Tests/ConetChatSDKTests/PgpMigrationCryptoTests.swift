import XCTest
@testable import ConetChatSDK
#if canImport(X19)
import X19
#endif

/// The X-19 functions of the migration path: a detached signature must not verify after
/// a one-bit change of the signature or of the challenge message, nor after a change of the data, nor with another key. The four
/// approved functions must be linked and reached in the simulator build. Synthetic keys only. The linkage test needs the iOS
/// simulator, where the framework is linked.
final class PgpMigrationCryptoTests: XCTestCase {
	private let crypto = BeamioPgpMigrationImport.X19Crypto()

	private func sample() -> Data {
		Data((0 ..< 32).map { UInt8($0) })
	}

	/// A challenge message shaped as the pipeline builds it: the domain, the EOA, the key ID and the nonce in hex.
	private func challengeMessage(keyId: String) -> Data {
		let nonceHex = (0 ..< 32).map { String(format: "%02x", UInt8($0)) }.joined()
		return Data((BeamioPgpMigrationImport.challengeDomain + PgpMigrationTestSupport.eoa + "|" + keyId + "|" + nonceHex).utf8)
	}

	/// CRC-24 of RFC 4880 (section 6.1), used to re-armor a changed signature with a valid checksum.
	private func crc24(_ bytes: [UInt8]) -> UInt32 {
		var crc: UInt32 = 0xB704CE
		for byte in bytes {
			crc ^= UInt32(byte) << 16
			for _ in 0 ..< 8 {
				crc <<= 1
				if crc & 0x1000000 != 0 {
					crc ^= 0x1864CFB
				}
			}
		}
		return crc & 0xFFFFFF
	}

	/// The body lines of an armored signature (the base64 between the blank line and the `=` checksum line).
	private func armorBody(_ armor: String) throws -> (lines: [String], blank: Int, checksum: Int) {
		let lines = armor.components(separatedBy: "\n")
		let blank = try XCTUnwrap(lines.firstIndex { $0.trimmingCharacters(in: .whitespaces).isEmpty })
		var end = blank + 1
		while end < lines.count, !lines[end].hasPrefix("=") {
			end += 1
		}
		return (lines, blank, end)
	}

	/// The length of the signature packet inside an armored signature.
	private func packetLength(_ armor: String) throws -> Int {
		let body = try armorBody(armor)
		let text = body.lines[(body.blank + 1) ..< body.checksum].joined()
		return try XCTUnwrap(Data(base64Encoded: text)).count
	}

	/// The armored signature with one bit of its packet flipped. The checksum is recomputed, so only the signature bits change and
	/// the armor stays valid: a refusal can only come from the signature check.
	private func armoredWithFlippedBit(_ armor: String, byte index: Int, bit: Int) throws -> String {
		let body = try armorBody(armor)
		let text = body.lines[(body.blank + 1) ..< body.checksum].joined()
		var bytes = [UInt8](try XCTUnwrap(Data(base64Encoded: text)))
		XCTAssertLessThan(index, bytes.count, "the bit lies in the packet")
		bytes[index] ^= UInt8(1 << bit)
		let crc = crc24(bytes)
		let checksum = Data([UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)]).base64EncodedString()
		let encoded = Data(bytes).base64EncodedString()
		var chunks: [String] = []
		var rest = Substring(encoded)
		while !rest.isEmpty {
			chunks.append(String(rest.prefix(64)))
			rest = rest.dropFirst(64)
		}
		var out = Array(body.lines[0 ... body.blank])
		out.append(contentsOf: chunks)
		out.append("=" + checksum)
		out.append(contentsOf: body.lines[(body.checksum + 1)...])
		return out.joined(separator: "\n")
	}

	// MARK: Linkage (simulator)

	func testTheFourApprovedFunctionsAreLinkedAndReachedInTheSimulator() throws {
		// Without X-19 linked this case is skipped, not a crash in the key helper.
		try PgpMigrationTestSupport.requireX19()
		#if targetEnvironment(simulator)
		XCTAssertTrue(BeamioPGPNative.linked, "X-19 is linked in the simulator build")
		XCTAssertTrue(crypto.available)
		let a = PgpMigrationTestSupport.key("A")
		// PrimaryFingerprint and FirstSubkeyKeyID, on the private and on the public armor.
		XCTAssertEqual(crypto.identity(armor: a.privateArmor)?.fingerprint, a.fingerprint)
		XCTAssertEqual(crypto.identity(armor: a.privateArmor)?.subkeyKeyID, a.keyId)
		XCTAssertEqual(crypto.identity(armor: a.publicArmor)?.fingerprint, a.fingerprint)
		// SignDetached and VerifyDetached.
		let signature = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		XCTAssertTrue(crypto.verify(publicArmor: a.publicArmor, data: sample(), signature: signature))
		#else
		throw XCTSkip("the linkage test runs on the iOS simulator")
		#endif
	}

	// MARK: Negative checks

	func testTheSignatureIsArmoredAndDoesNotCarryThePrivateKey() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let signature = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		XCTAssertTrue(signature.contains("BEGIN PGP SIGNATURE"))
		XCTAssertFalse(signature.contains("PRIVATE KEY"))
	}

	func testAValidSignatureVerifiesOverItsOwnData() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let signature = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		XCTAssertTrue(crypto.verify(publicArmor: a.publicArmor, data: sample(), signature: signature))
	}

	func testTamperedDataDoesNotVerify() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let signature = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		var tampered = sample()
		tampered[tampered.count - 1] ^= 0x01
		XCTAssertFalse(crypto.verify(publicArmor: a.publicArmor, data: tampered, signature: signature), "one bit of the data changed")
	}

	/// item 1: one bit of the signature packet changed, at the last, the middle and the first bytes, each with a valid
	/// checksum. Every change must fail the verification; the unchanged signature must pass it.
	func testAOneBitChangeOfTheSignatureDoesNotVerify() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let original = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		XCTAssertTrue(crypto.verify(publicArmor: a.publicArmor, data: sample(), signature: original), "the unchanged signature verifies")

		// The packet tag (byte 0) is not flipped: a change there would be refused by the parser, not by the signature check.
		let count = try packetLength(original)
		for (index, bit) in [(count - 1, 0), (count - 1, 7), (count - 2, 3), (count / 2, 3)] {
			let changed = try armoredWithFlippedBit(original, byte: index, bit: bit)
			XCTAssertNotEqual(changed, original, "the test changed the signature")
			XCTAssertFalse(
				crypto.verify(publicArmor: a.publicArmor, data: sample(), signature: changed),
				"bit \(bit) of byte \(index) of the signature changed: refused"
			)
		}
	}

	#if canImport(X19)
	/// The result of X19VerifyDetached before the wrapper folds it into one Bool: whether the call reported a failure, and whether
	/// the signature is valid.
	private func verifyRaw(publicArmor: String, data: Data, signature: String) -> (succeeded: Bool, failure: String?, valid: Bool) {
		var valid: ObjCBool = false
		var failure: NSError?
		let succeeded = X19VerifyDetached(publicArmor, data, signature, &valid, &failure)
		return (succeeded, failure?.localizedDescription, valid.boolValue)
	}

	/// item 1: a one-bit change of the signature must reach the signature check, not stop at the parser. The unchanged
	/// signature is valid; the changed one is reported as not valid. The raw result of both calls is printed to the test log.
	func testAFlippedSignatureReachesTheSignatureCheck() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let original = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		let changed = try armoredWithFlippedBit(original, byte: try packetLength(original) - 1, bit: 0)
		let ok = verifyRaw(publicArmor: a.publicArmor, data: sample(), signature: original)
		let bad = verifyRaw(publicArmor: a.publicArmor, data: sample(), signature: changed)
		print("X19 raw verify, unchanged signature: succeeded=\(ok.succeeded) failure=\(ok.failure ?? "none") valid=\(ok.valid)")
		print("X19 raw verify, one bit flipped: succeeded=\(bad.succeeded) failure=\(bad.failure ?? "none") valid=\(bad.valid)")
		XCTAssertTrue(ok.valid, "the unchanged signature is valid")
		XCTAssertFalse(bad.valid, "the one-bit change is not valid")
	}
	#endif

	/// item 1: one bit of the challenge message changed. The signature of the original challenge verifies; the
	/// signature does not verify a challenge with one bit changed, at the first, the middle and the last bytes.
	func testAOneBitChangeOfTheChallengeDoesNotVerify() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let message = challengeMessage(keyId: a.keyId)
		let signature = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: message))
		XCTAssertTrue(crypto.verify(publicArmor: a.publicArmor, data: message, signature: signature), "the challenge verifies")

		for (index, bit) in [(0, 0), (message.count / 2, 4), (message.count - 1, 7)] {
			var tampered = message
			tampered[index] ^= UInt8(1 << bit)
			XCTAssertNotEqual(tampered, message)
			XCTAssertFalse(
				crypto.verify(publicArmor: a.publicArmor, data: tampered, signature: signature),
				"bit \(bit) of byte \(index) of the challenge changed: refused"
			)
		}
	}

	func testASignatureOfAnotherKeyDoesNotVerify() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		let b = PgpMigrationTestSupport.key("B")
		let signature = try XCTUnwrap(crypto.sign(privateArmor: a.privateArmor, data: sample()))
		XCTAssertFalse(crypto.verify(publicArmor: b.publicArmor, data: sample(), signature: signature), "verified with the wrong key")
	}

	func testAnEmptySignatureDoesNotVerify() throws {
		try PgpMigrationTestSupport.requireX19()
		let a = PgpMigrationTestSupport.key("A")
		XCTAssertFalse(crypto.verify(publicArmor: a.publicArmor, data: sample(), signature: ""))
	}
}
