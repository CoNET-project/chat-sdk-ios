import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Mnemonic cipher v3 (finalized section 10, 11): the interop test of this end. TEST ONLY, never product code. It opens the synthetic envelopes of
/// `mnemonic-cipher-format.v3.json` with the fixture's test-only derived key (v4), checks the EOA, and checks the closed answer set
/// (MCF3-02, 03, 06 -> unlock_failed; MCF3-04, 05 -> verify_failed). The real Argon2id derivation is checked in the iOS simulator run (X-19), where the
/// framework is linked; on macOS that one test is skipped. The synthetic phrase and passcode in the fixture are test values, not a wallet.
final class MnemonicCipherV3FixtureTests: XCTestCase {
	private struct Fixture {
		let root: [String: Any]
		let cases: [String: [String: Any]]
		let phrase: String
		let eoa: String
		let passcode: String
		let derivedKey: Data
		let aadTemplate: String
	}

	private func fixture() throws -> Fixture {
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let inputs = try XCTUnwrap(root["syntheticInputs"] as? [String: Any])
		let list = try XCTUnwrap(root["cases"] as? [[String: Any]])
		var byId: [String: [String: Any]] = [:]
		for c in list { if let id = c["id"] as? String { byId[String(id.prefix(7))] = c } }
		let derived = try XCTUnwrap(root["derivedKeyTestOnly"] as? [String: Any])
		let hex = try XCTUnwrap(derived["hexOutput"] as? String, "derivedKeyTestOnly.hexOutput")
		var bytes: [UInt8] = []
		var index = hex.startIndex
		while index < hex.endIndex {
			let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
			bytes.append(try XCTUnwrap(UInt8(hex[index..<next], radix: 16)))
			index = next
		}
		let key = Data(bytes)
		XCTAssertEqual(key.count, 32)
		return Fixture(root: root, cases: byId, phrase: inputs["phrase"] as? String ?? "", eoa: inputs["eoa"] as? String ?? "",
		               passcode: inputs["sixDigitPasscode"] as? String ?? "", derivedKey: key, aadTemplate: inputs["aadTemplate"] as? String ?? "")
	}

	private enum Outcome: Equatable { case ok(String), unlockFailed, verifyFailed }

	/// One envelope opened with `key`, in the order of the finalized section: version and shape first (verify_failed, nothing decrypted), then AES-GCM with
	/// the AAD of the envelope's own eoa (unlock_failed on any authentication failure), then the checksum and the derived address (verify_failed).
	private func open(_ envelope: [String: Any], key: Data, aadTemplate: String) -> Outcome {
		guard envelope["v"] as? Int == 3, envelope["alg"] as? String == "AES-256-GCM",
		      (envelope["kdf"] as? String) == "argon2id/m=32768/t=3/p=1/dkLen=32",
		      let eoa = (envelope["eoa"] as? String)?.lowercased(),
		      let iv = (envelope["iv"] as? String).flatMap({ Data(base64Encoded: $0) }), iv.count == 12,
		      (envelope["salt"] as? String).flatMap({ Data(base64Encoded: $0) })?.count == 16,
		      let ct = (envelope["ct"] as? String).flatMap({ Data(base64Encoded: $0) }), ct.count > 16
		else { return .verifyFailed }
		let aad = Data(aadTemplate.replacingOccurrences(of: "<eoa lowercase>", with: eoa).utf8)
		guard let nonce = try? AES.GCM.Nonce(data: iv),
		      let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ct.dropLast(16), tag: ct.suffix(16)),
		      var plain = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
		else { return .unlockFailed }
		defer { BeamioNativeWallet.wipe(&plain) }
		guard let phrase = String(data: plain, encoding: .utf8), case .key(var derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return .verifyFailed }
		defer { BeamioNativeWallet.wipe(&derived) }
		guard BeamioNativeEthSigner.address(privateKey: derived)?.lowercased() == eoa else { return .verifyFailed }
		return .ok(phrase)
	}

	private func envelope(_ f: Fixture, _ id: String) throws -> [String: Any] {
		try XCTUnwrap(f.cases[id]?["envelope"] as? [String: Any], id)
	}

	/// MCF3-01: the right key opens the envelope, the phrase is the synthetic one, and the derived EOA is 0xd49251e1…986f
	func testMCF301OpensAndTheDerivedAddressMatches() throws {
		let f = try fixture()
		XCTAssertEqual(f.eoa, "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f")
		XCTAssertEqual(open(try envelope(f, "MCF3-01"), key: f.derivedKey, aadTemplate: f.aadTemplate), .ok(f.phrase))
		guard case .key(var k) = BeamioMnemonicDerivation.derive(phrase: f.phrase) else { return XCTFail("the synthetic phrase is valid") }
		defer { BeamioNativeWallet.wipe(&k) }
		XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: k)?.lowercased(), f.eoa, "the path m/44'/60'/0'/0/0 gives the fixture's EOA")
	}

	/// the closed set of the negatives (finalized section 5): MCF3-02, 03, 06 -> unlock_failed; MCF3-04, 05 -> verify_failed
	func testTheNegativeCasesAnswerTheClosedSet() throws {
		let f = try fixture()
		var wrongKey = f.derivedKey
		wrongKey[0] ^= 0x01
		XCTAssertEqual(open(try envelope(f, "MCF3-02"), key: wrongKey, aadTemplate: f.aadTemplate), .unlockFailed, "MCF3-02 a wrong six-digit passcode")
		XCTAssertEqual(open(try envelope(f, "MCF3-03"), key: f.derivedKey, aadTemplate: f.aadTemplate), .unlockFailed, "MCF3-03 a tampered ciphertext")
		XCTAssertEqual(open(try envelope(f, "MCF3-04"), key: f.derivedKey, aadTemplate: f.aadTemplate), .verifyFailed, "MCF3-04 version not 3, nothing decrypted")
		XCTAssertEqual(open(try envelope(f, "MCF3-05"), key: f.derivedKey, aadTemplate: f.aadTemplate), .verifyFailed, "MCF3-05 the address does not match")
		XCTAssertEqual(open(try envelope(f, "MCF3-06"), key: f.derivedKey, aadTemplate: f.aadTemplate), .unlockFailed, "MCF3-06 the AAD is bound to the eoa")
	}

	/// the version check runs before any decryption: a v=2 envelope whose ciphertext would open is still verify_failed; v=1 (the withdrawn PBKDF2 format) too
	func testAnUnknownVersionIsRefusedBeforeDecrypting() throws {
		let f = try fixture()
		var e = try envelope(f, "MCF3-01")
		e["v"] = 2
		XCTAssertEqual(open(e, key: f.derivedKey, aadTemplate: f.aadTemplate), .verifyFailed)
		e["v"] = 1
		XCTAssertEqual(open(e, key: f.derivedKey, aadTemplate: f.aadTemplate), .verifyFailed, "v=1 is refused and never read")
	}

	/// the vendored Argon2id (official reference implementation) derives the fixture's test-only key from the six-digit passcode, and opens MCF3-01. Where X-19 is linked
	/// (the iOS simulator) the X-19 primitive must give the same bytes: two independent implementations agree.
	func testTheVendoredArgon2idDerivesTheTestOnlyKey() throws {
		let f = try fixture()
		let inputs = try XCTUnwrap(f.root["syntheticInputs"] as? [String: Any])
		let salt = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(inputs["saltB64"] as? String)))
		let out = try XCTUnwrap(try? BeamioArgon2id.deriveV3Key(passcode: Array(f.passcode.utf8), salt: Array(salt)).get())
		XCTAssertEqual(Data(out), f.derivedKey, "the vendored Argon2id gives the fixture's derived key")
		XCTAssertEqual(open(try envelope(f, "MCF3-01"), key: Data(out), aadTemplate: f.aadTemplate), .ok(f.phrase), "the vendored derivation opens MCF3-01")
		if BeamioPGPNative.linked, let kdf = BeamioNativeRecovery.keyDerivation, let x19 = try? kdf.argon2id(password: Array(f.passcode.utf8), salt: Array(salt), m: 32768, t: 3, p: 1).get() {
			XCTAssertEqual(x19, out, "the X-19 primitive and the vendored reference give the same bytes")
		}
	}

	/// The cross-read of the envelopes that the other ends generated (Android, PWA: random salt and IV, synthetic phrase and passcode). The directory comes	/// from the environment (BEAMIO_MCF3_FIXTURE_DIR); without it the test is skipped, and a file that is not there is skipped. The key is derived by the vendored Argon2id.
	func testEnvelopesGeneratedByTheOtherEndsOpenAndTheAddressMatches() throws {
		let env = ProcessInfo.processInfo.environment
		guard let dir = env["BEAMIO_MCF3_FIXTURE_DIR"] ?? env["MCF3_CROSS_DIR"] ?? env["TEST_RUNNER_MCF3_CROSS_DIR"] else { throw XCTSkip("no cross-read directory given (BEAMIO_MCF3_FIXTURE_DIR)") }
		let f = try fixture()
		var opened = 0
		for name in ["android-generated-v3.txt", "pwa-generated-v3.txt"] {
			guard let text = try? String(contentsOfFile: dir + "/" + name, encoding: .utf8) else { continue }
			let lines = text.split(separator: "\n").map(String.init)
			let json = try XCTUnwrap(lines.first { $0.hasPrefix("{") }, name)
			let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any], name)
			let passcode = try XCTUnwrap(lines.first { $0.hasPrefix("passcode=") }.map { String($0.dropFirst("passcode=".count)) }, name)
			let phrase = try XCTUnwrap(lines.first { $0.hasPrefix("expected_phrase=") }.map { String($0.dropFirst("expected_phrase=".count)) }, name)
			let salt = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(envelope["salt"] as? String)), name)
			let key = try XCTUnwrap(try? BeamioArgon2id.deriveV3Key(passcode: Array(passcode.utf8), salt: Array(salt)).get(), name)
			XCTAssertEqual(open(envelope, key: Data(key), aadTemplate: f.aadTemplate), .ok(phrase), "\(name) opens with the vendored Argon2id and the address matches")
			print("[MCF3-cross] \(name): opened, address matches; Argon2id: vendored reference")
			opened += 1
		}
		try XCTSkipIf(opened == 0, "no cross-read file found in \(dir)")
	}
}
