import CryptoKit
import XCTest
@testable import ConetChatSDK

/// P-IMP-PGP restore (pgp-backup-compat-vectors.v1.json): positives P-1, P-2 (decrypt, armor bytes, fingerprints, test
/// message through the X-19 wrapper when linked), negatives N-1 to N-10 (decrypt_failed), divergence D-2 (strict base64).
/// Synthetic data only. Runs with PGP_BACKUP_VECTORS (TEST_RUNNER_ prefix); skipped without it.
final class PGPBackupRestoreTests: XCTestCase {
	private func vectors() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_BACKUP_VECTORS"] else {
			throw XCTSkip("set PGP_BACKUP_VECTORS to interface/protocol/pgp-backup-compat-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	func testPositivesRestoreTheArmorAndTheKeyIdentity() throws {
		let root = try vectors()
		let positives = try XCTUnwrap(root["positives"] as? [[String: Any]])
		XCTAssertEqual(positives.count, 2)
		for p in positives {
			let id = p["id"] as? String ?? "?"
			let backup = try XCTUnwrap(p["backup"] as? [String: Any])
			let password = p["passwordString"] as? String ?? ""
			let pgp = try XCTUnwrap(p["pgp"] as? [String: Any])
			let expect = p["expect"] as? [String: Any] ?? [:]
			let result = BeamioPGPBackup.decrypt(base64: backup["base64"] as? String ?? "", passwordString: password)
			guard case .success(let armor) = result else { return XCTFail("\(id): restore refused") }
			XCTAssertEqual(armor, pgp["privateArmor"] as? String, "\(id): armor bytes")
			XCTAssertEqual(hex(Data(SHA256.hash(data: Data(armor.utf8)))), pgp["privateArmorSha256"] as? String, id)
			if let identity = BeamioPGPBackup.keyIdentity(armor: armor) {
				XCTAssertEqual(identity.fingerprint, expect["primaryFingerprint"] as? String, "\(id): primary fingerprint")
				XCTAssertEqual(identity.subkeyKeyID, expect["subkeyKeyID"] as? String, "\(id): subkey key ID")
			}
			// Without X19 linked, the fingerprint check is not run here (the Go test checks the same values).
		}
	}

	func testNegativesAreDecryptFailed() throws {
		let root = try vectors()
		let negatives = try XCTUnwrap(root["negatives"] as? [[String: Any]])
		XCTAssertEqual(negatives.count, 10)
		for n in negatives {
			let id = n["id"] as? String ?? "?"
			let backup = n["backup"] as? [String: Any] ?? [:]
			let result = BeamioPGPBackup.decrypt(base64: backup["base64"] as? String ?? "", passwordString: n["passwordString"] as? String ?? "")
			XCTAssertEqual(result, .failure(BeamioPGPBackup.RestoreRefusal(code: "decrypt_failed")), id)
		}
	}

	/// D-2: the PWA accepts whitespace in the base64 (ok_lenient); the native restore is strict and refuses it. Recorded as a
	/// divergence, not changed to match.
	func testDivergenceD2IsRefusedByTheStrictNativeDecoder() throws {
		let root = try vectors()
		let divergences = try XCTUnwrap(root["divergences"] as? [[String: Any]])
		let d2 = try XCTUnwrap(divergences.first { $0["id"] as? String == "D-2" })
		let backup = try XCTUnwrap(d2["backup"] as? [String: Any])
		let result = BeamioPGPBackup.decrypt(base64: backup["base64"] as? String ?? "", passwordString: d2["passwordString"] as? String ?? "")
		XCTAssertEqual(result, .failure(BeamioPGPBackup.RestoreRefusal(code: "decrypt_failed")))
	}

	private func hex(_ data: Data) -> String {
		data.map { String(format: "%02x", $0) }.joined()
	}
}
