import XCTest
@testable import ConetChatSDK

/// The iOS end of the MCF v3 interop: it seals the synthetic phrase with a random salt and IV (the iOS cipher side, test only), opens it again here, and, when MCF3_GENERATE_DIR is set,
/// writes `ios-generated-v3.txt` in the same format as the Android and PWA files, so that the other ends open it. Synthetic phrase and passcode only; not a wallet.
final class MnemonicCipherIosGeneratedTests: XCTestCase {
	private let phrase = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
	private let passcode = "482913"
	private let eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"

	func testAnIosSealedEnvelopeOpensHereAndTheOtherSideOfTheFormatMatches() throws {
		let object = try XCTUnwrap(BeamioMnemonicCipherV3.sealForTests(phrase: phrase, passcode: Array(passcode.utf8), eoa: eoa))
		let envelope = try XCTUnwrap(BeamioMnemonicCipherV3.parse(object), "the iOS envelope has the finalized shape")
		XCTAssertEqual(BeamioMnemonicCipherV3.open(envelope, passcode: Array(passcode.utf8)), .ok, "iOS opens what iOS sealed")
		XCTAssertEqual(BeamioMnemonicCipherV3.open(envelope, passcode: Array("000000".utf8)), .unlockFailed)
		// random salt and IV: two seals of the same phrase differ
		let again = try XCTUnwrap(BeamioMnemonicCipherV3.sealForTests(phrase: phrase, passcode: Array(passcode.utf8), eoa: eoa))
		XCTAssertNotEqual(object["salt"] as? String, again["salt"] as? String)
		XCTAssertNotEqual(object["iv"] as? String, again["iv"] as? String)
		XCTAssertNotEqual(object["ct"] as? String, again["ct"] as? String)
		// the fixture's fixed salt and IV give exactly the fixture's ciphertext (the iOS cipher side agrees with the generator byte for byte)
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let inputs = try XCTUnwrap(root["syntheticInputs"] as? [String: Any])
		let fixedSalt = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(inputs["saltB64"] as? String)))
		let fixedIv = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(inputs["ivB64"] as? String)))
		let fixed = try XCTUnwrap(BeamioMnemonicCipherV3.sealForTests(phrase: phrase, passcode: Array(passcode.utf8), eoa: eoa, salt: fixedSalt, iv: fixedIv))
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let ok = try XCTUnwrap((cases.first { ($0["id"] as? String ?? "").hasPrefix("MCF3-01") })?["envelope"] as? [String: Any])
		XCTAssertEqual(fixed["ct"] as? String, ok["ct"] as? String, "the iOS seal reproduces the generator's ciphertext byte for byte")
	}

	/// writes ios-generated-v3.txt when asked (MCF3_GENERATE_DIR), after opening it once more from the file
	func testWriteTheIosGeneratedFileWhenAsked() throws {
		let env = ProcessInfo.processInfo.environment
		guard let dir = env["MCF3_GENERATE_DIR"] ?? env["TEST_RUNNER_MCF3_GENERATE_DIR"] else { throw XCTSkip("set MCF3_GENERATE_DIR to write ios-generated-v3.txt") }
		let object = try XCTUnwrap(BeamioMnemonicCipherV3.sealForTests(phrase: phrase, passcode: Array(passcode.utf8), eoa: eoa))
		let envelope = try XCTUnwrap(BeamioMnemonicCipherV3.parse(object))
		XCTAssertEqual(BeamioMnemonicCipherV3.open(envelope, passcode: Array(passcode.utf8)), .ok)
		let json = String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]), as: UTF8.self)
		let text = "# iOS-generated v3 envelope (random salt and IV), synthetic phrase and passcode.\n\(json)\npasscode=\(passcode)\nexpected_phrase=\(phrase)\nios_self_open=ok\n"
		try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
		try text.write(toFile: dir + "/ios-generated-v3.txt", atomically: true, encoding: .utf8)
	}
}
