import Foundation
#if canImport(X19)
import X19
#endif

/// Gate for the native OpenPGP layer. The library is approved (X-19, gopenpgp v3.5.2).
/// `available` is open only in the QA build: there the mailbox listen decrypts inbound
/// frames natively. Release and Store builds keep it closed. `linked` says whether the X-19 xcframework is part of this build.
public enum BeamioPGPNative {
	/// Native inbound decrypt gate. Open in every build in which the X-19 framework is linked (`linked`), Release and store builds included
	/// It does not depend on the QA flag. A build without X-19 is closed, and the listen reports
	/// `pendingCode` (`pgp_native_pending`) as its reason.
	public static var available: Bool {
		linked
	}
	/// Error code for PGP private-key operations while the native library is not linked into this build.
	public static let pendingCode = "pgp_native_pending"

	/// True when the X-19 xcframework is linked into this build. macOS test builds do not link it.
	public static var linked: Bool {
		#if BEAMIO_TEST_HOOKS
		if let forced = linkedOverrideForTests { return forced }
		#endif
		return actuallyLinked
	}

	private static var actuallyLinked: Bool {
		#if canImport(X19)
		return true
		#else
		return false
		#endif
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only (BEAMIO_TEST_HOOKS): forces `linked` (and so `available`) to a value, so the shell can test "X-19 not linked: no WebView
	/// fallback". nil restores the real value. The hook does not exist in release or store builds, so production behaviour is unchanged.
	public static var linkedOverrideForTests: Bool?
	#endif

	/// The native decrypt's outcome (steps 5 and 6). `notUTF8`: a binary literal that is not valid UTF-8.
	enum DecryptOutcome: Equatable {
		case plain(Data)
		case notUTF8
		case failed
	}

	/// A new PGP key pair for pgpIdentityCreate: v4, curve25519, no passphrase. Made in memory; the
	/// caller stores it natively and never sends the private armor to the bridge.
	static func generateKeyPair(name: String) -> Result<(privateArmor: String, publicArmor: String), Error> {
		#if canImport(X19)
		var failure: NSError?
		let priv = X19GenerateArmoredKey(name, &failure) as String
		if let failure { return .failure(failure) }
		var pubFailure: NSError?
		let pub = X19PublicArmor(priv, &pubFailure) as String
		if let pubFailure { return .failure(pubFailure) }
		return .success((priv, pub))
		#else
		_ = name
		return .failure(NSError(domain: "BeamioPGPNative", code: -1, userInfo: [NSLocalizedDescriptionKey: pendingCode]))
		#endif
	}

	/// C3 core: decrypt an ASCII-armored message with an ASCII-armored private key (gopenpgp v3.5.2, X-19 v3). A text
	/// literal comes back with CRLF turned into LF; a binary literal must be valid UTF-8. The key is passed as a
	/// string and not kept here.
	static func decryptArmoredText(privateArmor: String, armoredMessage: String) -> DecryptOutcome {
		#if canImport(X19)
		var failure: NSError?
		let plain = X19DecryptArmoredText(privateArmor, armoredMessage, &failure) as String
		guard let failure else { return .plain(Data(plain.utf8)) }
		return failure.localizedDescription.contains("not_utf8") ? .notUTF8 : .failed
		#else
		_ = (privateArmor, armoredMessage)
		return .failed
		#endif
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only: encrypts a plaintext to a public armor with the native layer, so the inbound listen tests can build real
	/// OpenPGP messages from generated keys. Nothing here reaches production code.
	static func encryptArmoredForTests(publicArmor: String, plaintext: Data) -> String? {
		#if canImport(X19)
		var failure: NSError?
		let armored = X19EncryptArmored(publicArmor, plaintext, &failure) as String
		return failure == nil ? armored : nil
		#else
		_ = (publicArmor, plaintext)
		return nil
		#endif
	}
	#endif
}
