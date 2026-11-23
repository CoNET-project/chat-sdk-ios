import XCTest
@testable import ConetChatSDK

/// The vendored Argon2id (Sources/CArgon2, the official reference implementation pinned in PROVENANCE.md): the known-answer vector of RFC 9106 section 5.3 (Argon2id,
/// version 0x13, with a secret and associated data, p = 4), and the parameters of the mnemonic cipher v3. TEST ONLY.
final class Argon2idKnownAnswerTests: XCTestCase {
	private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

	/// RFC 9106 section 5.3: password 32 x 0x01, salt 16 x 0x02, secret 8 x 0x03, associated data 12 x 0x04, t = 3, m = 32 KiB, p = 4, 32-byte tag.
	/// The tag value is that of the RFC (checked here against an independent implementation too: the PWA's noble Argon2id gives the same bytes).
	func testRFC9106Argon2idKnownAnswer() throws {
		let tag = try XCTUnwrap(try? BeamioArgon2id.deriveWithContextForTests(
			password: [UInt8](repeating: 1, count: 32), salt: [UInt8](repeating: 2, count: 16), secret: [UInt8](repeating: 3, count: 8),
			associatedData: [UInt8](repeating: 4, count: 12), memoryKiB: 32, iterations: 3, parallelism: 4, outputLength: 32).get())
		XCTAssertEqual(hex(tag), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
	}

	/// the parameters of the cipher v3 (m = 32768 KiB, t = 3, p = 1, 32 bytes): deterministic, the right length, different for another salt, and a refusal for bad parameters
	func testTheV3ParametersAreDeterministicAndRefuseBadInput() throws {
		let salt = [UInt8](0..<16)
		let a = try XCTUnwrap(try? BeamioArgon2id.deriveV3Key(passcode: Array("482913".utf8), salt: salt).get())
		let b = try XCTUnwrap(try? BeamioArgon2id.deriveV3Key(passcode: Array("482913".utf8), salt: salt).get())
		XCTAssertEqual(a, b)
		XCTAssertEqual(a.count, 32)
		XCTAssertNotEqual(a, try XCTUnwrap(try? BeamioArgon2id.deriveV3Key(passcode: Array("482913".utf8), salt: [UInt8](1..<17)).get()), "another salt, another key")
		XCTAssertNotEqual(a, try XCTUnwrap(try? BeamioArgon2id.deriveV3Key(passcode: Array("482914".utf8), salt: salt).get()), "another passcode, another key")
		if case .success = BeamioArgon2id.derive(password: Array("x".utf8), salt: [1, 2, 3], memoryKiB: 32768, iterations: 3, parallelism: 1, outputLength: 32) {
			XCTFail("a 3-byte salt is refused by the reference implementation")
		}
	}
}
