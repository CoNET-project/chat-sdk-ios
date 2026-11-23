import CryptoKit
import Foundation
#if canImport(X19)
import X19
#endif

/// Restore of the PWA's PGP private key backup (P-IMP-PGP, pgp-backup-compat-vectors.v1.json, spec). The backup is
/// base64(iv ‖ ciphertext ‖ tag), AES-256-GCM, key = SHA-256(UTF-8(passwordString)), plaintext = the armored private key.
/// The base64 must be strict (no whitespace): the PWA accepts whitespace and iOS does not (divergence D-2, reported).
/// Any failure is `decrypt_failed`. The restored key is returned to the caller only and is not kept here.
public enum BeamioPGPBackup {
	public struct RestoreRefusal: Error, Equatable {
		public let code: String
	}

	/// Decrypts a backup with the password string (the EOA private key string, / P-IMP-PGP).
	public static func decrypt(base64 text: String, passwordString: String) -> Result<String, RestoreRefusal> {
		let refused = RestoreRefusal(code: "decrypt_failed")
		guard let blob = Data(base64Encoded: text), blob.count >= 12 + 16 else { return .failure(refused) }
		let key = SymmetricKey(data: Data(SHA256.hash(data: Data(passwordString.utf8))))
		do {
			let box = try AES.GCM.SealedBox(
				nonce: AES.GCM.Nonce(data: blob.prefix(12)),
				ciphertext: blob.dropFirst(12).dropLast(16),
				tag: blob.suffix(16)
			)
			let plain = try AES.GCM.open(box, using: key)
			guard let armor = String(data: plain, encoding: .utf8) else { return .failure(refused) }
			return .success(armor)
		} catch {
			return .failure(refused)
		}
	}

	/// The primary fingerprint (uppercase hex) and the first subkey key ID (uppercase, 16 hex digits) of an armored key, from
	/// the X-19 wrapper (gopenpgp v3.5.2). nil when the framework is not linked, or when the armor does not parse.
	public static func keyIdentity(armor: String) -> (fingerprint: String, subkeyKeyID: String)? {
		#if canImport(X19)
		var failure: NSError?
		let fingerprint = X19PrimaryFingerprint(armor, &failure) as String
		guard failure == nil else { return nil }
		var subFailure: NSError?
		let subkey = X19FirstSubkeyKeyID(armor, &subFailure) as String
		guard subFailure == nil else { return nil }
		return (fingerprint, subkey)
		#else
		_ = armor
		return nil
		#endif
	}
}
