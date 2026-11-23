#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The per-call channel keys (v109 section 119): prepare, forget, tempSig, decryptInner. The temporary PGP parts need X-19 and run in the iOS test
/// run (BEAMIO_REQUIRE_X19=1); on macOS they are skipped by name.
final class VoiceEphemeralPrepareTests: XCTestCase {
	private let sidA = String(repeating: "1a", count: 16)
	private let sidB = String(repeating: "2b", count: 16)

	override func setUp() {
		super.setUp()
		BeamioVoiceEphemeral.clearAll()
		BeamioVoiceEphemeral.testClock = 1_000
		BeamioVoiceEphemeral.testFailKeyGeneration = false
	}

	override func tearDown() {
		BeamioVoiceEphemeral.testClock = nil
		BeamioVoiceEphemeral.testFailKeyGeneration = false
		BeamioVoiceEphemeral.clearAll()
		_ = BeamioWipeProbe.stop()
		super.tearDown()
	}

	private func channel(_ sid: String, role: String = "caller", needPgp: Bool = false) throws -> BeamioVoiceEphemeral.Channel {
		try BeamioVoiceEphemeral.prepare(role: role, sid: sid, needPgp: needPgp).get()
	}

	func testPrepareWithoutPgpReturnsPublicFieldsOnly() throws {
		let c = try channel(sidA)
		XCTAssertEqual(c.sid, sidA)
		XCTAssertTrue(BeamioVoiceEphemeral.isWk(c.wk), "wk: canonical base64 of 32 bytes")
		XCTAssertTrue(BeamioVoiceEphemeral.isWk(c.key), "key: canonical base64 of 32 bytes")
		XCTAssertNotEqual(c.key, c.wk)
		XCTAssertTrue(c.temp.hasPrefix("0x") && c.temp.count == 42 && c.temp == c.temp.lowercased())
		XCTAssertEqual(c.tempPgpFpr, "", "no user-side PGP: an empty fingerprint")
		XCTAssertNil(c.tempPgpArmor)
		// the temporary wallet signs, and the signature recovers to the address the call published
		let text = "voice_listen text of the shell"
		let sig = try BeamioVoiceEphemeral.tempSig(sid: sidA, text: text).get()
		XCTAssertEqual(BeamioNativeEthSigner.recoverEip191AddressForTests(message: text, signature: sig), c.temp)
	}

	func testTwoPreparesDoNotShareAnyKey() throws {
		let a = try channel(sidA, role: "caller"), b = try channel(sidB, role: "callee")
		XCTAssertNotEqual(a.key, b.key)
		XCTAssertNotEqual(a.wk, b.wk)
		XCTAssertNotEqual(a.temp, b.temp)
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 2)
	}

	func testBadInputsAndASidThatAlreadyHoldsAKey() throws {
		for (role, sid) in [("caller", "short"), ("both", sidA), ("", sidA), ("caller", sidA.uppercased())] {
			XCTAssertEqual(BeamioVoiceEphemeral.prepare(role: role, sid: sid, needPgp: false), .failure(.badRequest), "\(role) \(sid)")
		}
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0)
		_ = try channel(sidA)
		XCTAssertEqual(BeamioVoiceEphemeral.prepare(role: "caller", sid: sidA, needPgp: false), .failure(.badRequest), "a held key is not replaced silently")
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1)
	}

	func testForgetIsIdempotentAndWipesTheKey() throws {
		_ = try channel(sidA)
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.forget(sid: sidA)
		let seen = BeamioWipeProbe.stop().filter { $0.count == 32 && $0.address == nil }
		XCTAssertEqual(seen.count, 1)
		XCTAssertTrue(seen.allSatisfy { $0.hadNonZero && $0.allZero })
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0)
		BeamioVoiceEphemeral.forget(sid: sidA) // again: no effect
		BeamioVoiceEphemeral.forget(sid: sidB) // never prepared
		BeamioVoiceEphemeral.forget(sid: "not-a-sid")
		XCTAssertEqual(BeamioVoiceEphemeral.tempSig(sid: sidA, text: "x"), .failure(.unknownSid), "after forget the signature is gone")
		XCTAssertEqual(BeamioVoiceEphemeral.decryptInner(sid: sidA, armor: "-----BEGIN PGP MESSAGE-----"), .failure(.unknownSid))
	}

	func testAnExpiredChannelIsWipedAndGone() throws {
		_ = try channel(sidA)
		BeamioVoiceEphemeral.testClock = 1_000 + BeamioVoiceEphemeral.maxTTLSeconds + 1
		XCTAssertEqual(BeamioVoiceEphemeral.tempSig(sid: sidA, text: "x"), .failure(.unknownSid))
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0)
	}

	func testKeygenFailureIsReportedAndStoresNothing() {
		BeamioVoiceEphemeral.testFailKeyGeneration = true
		XCTAssertEqual(BeamioVoiceEphemeral.prepare(role: "caller", sid: sidA, needPgp: false), .failure(.keygenFailed))
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0)
	}

	func testTempSigAndDecryptInnerRefuseBadInput() throws {
		_ = try channel(sidA)
		XCTAssertEqual(BeamioVoiceEphemeral.tempSig(sid: "short", text: "x"), .failure(.badRequest))
		XCTAssertEqual(BeamioVoiceEphemeral.tempSig(sid: sidA, text: ""), .failure(.badRequest))
		XCTAssertEqual(BeamioVoiceEphemeral.decryptInner(sid: sidA, armor: "not armor"), .failure(.badRequest))
		// a channel made without a temporary PGP holds no PGP key
		XCTAssertEqual(BeamioVoiceEphemeral.decryptInner(sid: sidA, armor: "-----BEGIN PGP MESSAGE-----\nx\n-----END PGP MESSAGE-----"), .failure(.unknownSid))
	}

	func testNeedPgpWithoutX19IsKeygenFailedAndNeverFallsBack() throws {
		BeamioPGPNative.linkedOverrideForTests = false
		defer { BeamioPGPNative.linkedOverrideForTests = nil }
		XCTAssertEqual(BeamioVoiceEphemeral.prepare(role: "caller", sid: sidA, needPgp: true), .failure(.keygenFailed))
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0, "nothing is kept, no page key, no long-term key")
	}

	func testPgpChannelEndToEnd() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 framework not linked in this build")
		let c = try channel(sidA, role: "callee", needPgp: true)
		XCTAssertEqual(c.tempPgpFpr.count, 40)
		XCTAssertEqual(c.tempPgpFpr, c.tempPgpFpr.lowercased())
		XCTAssertTrue(try XCTUnwrap(c.tempPgpArmor).contains("BEGIN PGP PUBLIC KEY BLOCK"))
		XCTAssertFalse(String(describing: c).contains("PRIVATE"), "no private armor in the public fields")
		XCTAssertEqual(BeamioPGPBackup.keyIdentity(armor: try XCTUnwrap(c.tempPgpArmor))?.fingerprint.lowercased(), c.tempPgpFpr)
		// a message sealed to the public key opens with decryptInner, and another sid's key does not open it
		let message = try XCTUnwrap(BeamioPGPNative.encryptArmoredForTests(publicArmor: try XCTUnwrap(c.tempPgpArmor), plaintext: Data("inner layer".utf8)))
		XCTAssertEqual(try BeamioVoiceEphemeral.decryptInner(sid: sidA, armor: message).get(), "inner layer")
		let other = try channel(sidB, role: "caller", needPgp: true)
		XCTAssertNotEqual(other.tempPgpFpr, c.tempPgpFpr, "a new key for every call")
		XCTAssertEqual(BeamioVoiceEphemeral.decryptInner(sid: sidB, armor: message), .failure(.decryptFailed))
		// forget wipes the private armor too
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.forget(sid: sidA)
		let pgpWipes = BeamioWipeProbe.stop().filter { $0.address == nil && $0.count > 100 }
		XCTAssertEqual(pgpWipes.count, 1, "the private armor was overwritten")
		XCTAssertTrue(pgpWipes.allSatisfy { $0.hadNonZero && $0.allZero })
		XCTAssertEqual(BeamioVoiceEphemeral.decryptInner(sid: sidA, armor: message), .failure(.unknownSid))
	}
}
#endif

#if BEAMIO_TEST_HOOKS
/// `BeamioVoiceEphemeral.fingerprint(armor:)`: the OpenPGP v4 fingerprint, 40 lower-case hex, the primary key. The positive sample is a synthetic public
/// key that X-19 generated for this test (the private half was thrown away), with the fingerprint X-19 reported for it.
final class PGPFingerprintTests: XCTestCase {
	func testAnX19GeneratedKeyHasTheSameFingerprintAsX19() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 framework not linked in this build")
		for n in 0 ..< 3 {
			guard case .success(let pair) = BeamioPGPNative.generateKeyPair(name: "fp-\(n)") else { return XCTFail() }
			let x19 = try XCTUnwrap(BeamioPGPBackup.keyIdentity(armor: pair.publicArmor)).fingerprint.lowercased()
			XCTAssertEqual(BeamioVoiceEphemeral.fingerprint(armor: pair.publicArmor), x19)
			XCTAssertEqual(x19.count, 40)
		}
	}

	/// A positive sample that every build can run: a synthetic curve25519 v4 public key generated by X-19 on the iOS simulator for this test (2026-11-21,
	/// the private half was discarded), with the primary fingerprint X-19 itself reported for it.
	func testAFixedSampleFromX19() {
		let armor = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEawD9YxYJKwYBBAHaRw8BAQdA0jCh8lw+t211IhodGYfgZyhUuLkXM+1dB7yo
SBVOZsDNDmJlYW1pby1maXh0dXJlwr8EExYIAHEFgmsA/WMDCwkHCRB9K4Y3vGbL
wjUUAAAAAAAcABBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3Jnns5Sju9Syv8/
hsxdO8bkGAIVCAMWAAICGQECmwMCHgEWIQQFW32Lhk9XT18zb3d9K4Y3vGbLwgAA
a5UBAMmybE6teQwSUPOE3FQ3Jh+w+efgANRDgZcr91+O0yYnAP9pM9GaY0aJYU10
d1NdG9rvJSWRuapX3aLTPA6Na2MaAM44BGsA/WMSCisGAQQBl1UBBQEBB0DDaKvF
fdBCtG33ZvD+ALsfkQ8K+mOP+ozzeVGJ9q/bNAMBCgnCrgQYFggAYAWCawD9YwkQ
fSuGN7xmy8I1FAAAAAAAHAAQc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZyUS
PTk3i4kEcI6lfgb4PuICmwwWIQQFW32Lhk9XT18zb3d9K4Y3vGbLwgAA7BcBAPJ9
DnEdL8K0nGY2B2TY4k5wQZY/5H2Q/WG0uHmgfy4aAP4hkoGctMXbgE/UUR1kVJNm
FKYM2HPt8ufiCXvrwa5/AQ==
=QZm8
-----END PGP PUBLIC KEY BLOCK-----
"""
		XCTAssertEqual(BeamioVoiceEphemeral.fingerprint(armor: armor), "055b7d8b864f574f5f336f777d2b8637bc66cbc2")
		// and with CRLF line ends, as some transports deliver it
		XCTAssertEqual(BeamioVoiceEphemeral.fingerprint(armor: armor.replacingOccurrences(of: "\n", with: "\r\n")), "055b7d8b864f574f5f336f777d2b8637bc66cbc2")
	}

	func testRefusesWhatIsNotAnArmoredV4PublicKey() {
		for bad in ["", "not armor", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----",
		            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----",
		            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!!\n-----END PGP PUBLIC KEY BLOCK-----"] {
			XCTAssertNil(BeamioVoiceEphemeral.fingerprint(armor: bad), bad)
		}
		func armor(_ bytes: [UInt8]) -> String {
			"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + Data(bytes).base64EncodedString() + "\n-----END PGP PUBLIC KEY BLOCK-----"
		}
		let body: [UInt8] = [4, 0, 0, 0, 1, 22, 9] + [UInt8](repeating: 7, count: 10)
		// new format tag 6 with a v4 body: a fingerprint
		XCTAssertNotNil(BeamioVoiceEphemeral.fingerprint(armor: armor([0xC6, UInt8(body.count)] + body)))
		// old format tag 6 (0x98, one-octet length) is the same packet: the same fingerprint
		XCTAssertEqual(BeamioVoiceEphemeral.fingerprint(armor: armor([0x98, UInt8(body.count)] + body)),
		               BeamioVoiceEphemeral.fingerprint(armor: armor([0xC6, UInt8(body.count)] + body)))
		// version 3, a user-id packet first, a truncated packet, an indeterminate length, a partial length: nil
		var v3 = body; v3[0] = 3
		XCTAssertNil(BeamioVoiceEphemeral.fingerprint(armor: armor([0xC6, UInt8(v3.count)] + v3)))
		XCTAssertNil(BeamioVoiceEphemeral.fingerprint(armor: armor([0xCD, UInt8(body.count)] + body)), "tag 13 first")
		XCTAssertNil(BeamioVoiceEphemeral.fingerprint(armor: armor([0xC6, 40] + body)), "truncated")
		XCTAssertNil(BeamioVoiceEphemeral.fingerprint(armor: armor([0x9B] + body)), "indeterminate length")
		XCTAssertNil(BeamioVoiceEphemeral.fingerprint(armor: armor([0xC6, 224] + body)), "partial length")
	}

	func testTheFingerprintIsSha1OverTheHeaderedBody() {
		// RFC 4880 section 12.2, by hand: SHA-1(0x99 || len || body); armor headers and the checksum line are skipped
		let body: [UInt8] = [4, 0, 0, 0, 1, 22, 9] + [UInt8](repeating: 7, count: 10)
		let armored = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: test\n\n" + Data([0xC6, UInt8(body.count)] + body).base64EncodedString() + "\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----"
		var hashed = Data([0x99, 0, UInt8(body.count)]); hashed.append(contentsOf: body)
		let expected = Insecure.SHA1.hash(data: hashed).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(BeamioVoiceEphemeral.fingerprint(armor: armored), expected)
		XCTAssertEqual(expected.count, 40)
	}
}
#endif
