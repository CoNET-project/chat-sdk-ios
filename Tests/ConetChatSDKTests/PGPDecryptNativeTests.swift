#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// C3 `pgpDecrypt` through the X-19 xcframework (gopenpgp v3.5.2), against openpgp.js 6.3.0 ciphertexts (X-19 interop,
/// 2026-11-13). Runs only where the framework is linked (iOS builds with Vendor/X19.xcframework). Synthetic keys only.
/// Runs with TEST_RUNNER_PGP_INTEROP_VECTORS=<path to pgp-native-interop-vectors.v1.json>; skipped without it.
final class PGPDecryptNativeTests: XCTestCase {
	private func vectors() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_INTEROP_VECTORS"] else {
			throw XCTSkip("set PGP_INTEROP_VECTORS to the openpgp.js interop vector file")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// The recipient key. Accepts the scratch layout (`recipient`) and the interop file layout (`keys.recipient`).
	private func recipientKey(_ root: [String: Any]) throws -> [String: Any] {
		if let recipient = root["recipient"] as? [String: Any] { return recipient }
		let keys = try XCTUnwrap(root["keys"] as? [String: Any])
		return try XCTUnwrap(keys["recipient"] as? [String: Any])
	}

	/// The openpgp.js ciphertext cases. Accepts `jsToNative` (scratch) and `openpgpjsToAndroid`.
	private func jsCases(_ root: [String: Any]) throws -> [[String: Any]] {
		if let cases = root["jsToNative"] as? [[String: Any]] { return cases }
		return try XCTUnwrap(root["openpgpjsToAndroid"] as? [[String: Any]])
	}

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = nil
		super.tearDown()
	}

	func testDecryptsOpenpgpjsCiphertextsForTheStoredAccount() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X19 xcframework not linked in this build")
		let root = try vectors()
		let recipient = try recipientKey(root)
		let privateArmor = try XCTUnwrap(recipient["privateArmored"] as? String)
		let account = "0x1111111111111111111111111111111111111111"
		let stored = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: privateArmor, publicKeyArmor: recipient["publicArmored"] as? String ?? "", pgpKeyId: "",
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: account)
		XCTAssertTrue(BeamioChatPgpKeychain.save(stored))
		for c in try jsCases(root) {
			let id = c["id"] as? String ?? "?"
			let message = Data((c["ciphertextArmored"] as? String ?? "").utf8)
			let result = BeamioNativeWallet.pgpDecrypt(eoa: account, message: message)
			XCTAssertEqual(result, .success(Data((c["plaintext"] as? String ?? "").utf8)), id)
		}
	}

	func testAnotherAccountIsRefusedWithoutDecrypting() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X19 xcframework not linked in this build")
		let root = try vectors()
		let recipient = try recipientKey(root)
		let stored = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: recipient["privateArmored"] as? String ?? "", publicKeyArmor: "", pgpKeyId: "",
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: "0x1111111111111111111111111111111111111111")
		XCTAssertTrue(BeamioChatPgpKeychain.save(stored))
		let c = try XCTUnwrap(jsCases(root).first)
		let message = Data((c["ciphertextArmored"] as? String ?? "").utf8)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: "0x2222222222222222222222222222222222222222", message: message),
		               .failure(.rejected("no_pgp_key")))
	}
}
#endif
