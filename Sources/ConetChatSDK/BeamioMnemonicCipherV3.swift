import CryptoKit
import Foundation

/// The mnemonic cipher v3 (finalized section 2): Argon2id (m = 32 MiB, t = 3, p = 1, 32 bytes) of the passcode as UTF-8 bytes gives the AES-256-GCM key;
/// the AAD is `beamio-mnemonic-cipher-v3|argon2id-aes256gcm|<eoa lowercase>`; the envelope carries `v` 3, `mode` passcode, `eoa`, `kdf`, `salt` (16), `iv` (12), `alg`, `ct`
/// (ciphertext plus the 16-byte tag), all standard base64. Neither the key nor the derived output is ever stored with the envelope. The passcode is used only for this
/// call, in memory; nothing here logs a passcode, an envelope or a phrase. The SDK keeps no retry count and no cooldown.
enum BeamioMnemonicCipherV3 {
	static let version = 3
	static let kdfLabel = "argon2id/m=32768/t=3/p=1/dkLen=32"
	static let algorithm = "AES-256-GCM"
	static let aadPrefix = "beamio-mnemonic-cipher-v3|argon2id-aes256gcm|"
	private static let fields: Set<String> = ["v", "mode", "eoa", "kdf", "salt", "iv", "alg", "ct"]

	struct Envelope: Equatable {
		let eoa: String
		let salt: Data
		let iv: Data
		let ct: Data
		/// The envelope as canonical JSON (sorted keys, only the eight fields): what is stored and returned.
		let canonical: Data
	}

	/// The checks that come before any decryption: version, mode, algorithm, KDF label, the field set, the sizes and the address form. nil: `verify_failed`.
	static func parse(_ object: [String: Any]) -> Envelope? {
		guard Set(object.keys) == fields, object["v"] as? Int == version, object["mode"] as? String == "passcode",
		      object["alg"] as? String == algorithm, object["kdf"] as? String == kdfLabel,
		      let eoaRaw = object["eoa"] as? String, eoaRaw.count == 42, eoaRaw.hasPrefix("0x") || eoaRaw.hasPrefix("0X"),
		      eoaRaw.dropFirst(2).allSatisfy({ $0.isHexDigit }),
		      let salt = (object["salt"] as? String).flatMap({ Data(base64Encoded: $0) }), salt.count == 16,
		      let iv = (object["iv"] as? String).flatMap({ Data(base64Encoded: $0) }), iv.count == 12,
		      let ct = (object["ct"] as? String).flatMap({ Data(base64Encoded: $0) }), ct.count > 16,
		      let canonical = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
		else { return nil }
		return Envelope(eoa: eoaRaw.lowercased(), salt: salt, iv: iv, ct: ct, canonical: canonical)
	}

	enum Opened: Equatable { case ok, unlockFailed, verifyFailed }

	/// Decrypts in memory and checks the address. A wrong passcode, a tampered ciphertext and a wrong AAD are all `unlockFailed` (an AES-GCM authentication failure cannot
	/// tell them apart); a phrase that fails the checksum or derives another address is `verifyFailed`. The plaintext is wiped before returning.
	static func open(_ envelope: Envelope, passcode: [UInt8]) -> Opened {
		var privateKey: [UInt8]?
		let opened = open(envelope, passcode: passcode, privateKey: &privateKey)
		if privateKey != nil { BeamioNativeWallet.wipe(&privateKey!) }
		return opened
	}

	/// The same judgement, and on `ok` the private key of the account the phrase derives (in memory; the caller wipes it).
	static func open(_ envelope: Envelope, passcode: [UInt8], privateKey: inout [UInt8]?) -> Opened {
		privateKey = nil
		guard case .success(var key) = BeamioArgon2id.deriveV3Key(passcode: passcode, salt: Array(envelope.salt)) else { return .verifyFailed }
		defer { BeamioNativeWallet.wipe(&key) }
		guard let nonce = try? AES.GCM.Nonce(data: envelope.iv),
		      let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: envelope.ct.dropLast(16), tag: envelope.ct.suffix(16)),
		      var plain = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: Data((aadPrefix + envelope.eoa).utf8))
		else { return .unlockFailed }
		defer { BeamioNativeWallet.wipe(&plain) }
		guard let phrase = String(data: plain, encoding: .utf8), case .key(var derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return .verifyFailed }
		defer { BeamioNativeWallet.wipe(&derived) }
		guard BeamioNativeEthSigner.address(privateKey: derived)?.lowercased() == envelope.eoa else { return .verifyFailed }
		privateKey = derived
		return .ok
	}

	#if BEAMIO_TEST_HOOKS
	/// Test only (the iOS end of the interop): seals a phrase into a v3 envelope with a random salt and IV. The product never encrypts a mnemonic: the PWA seals it and the SDK only
	/// opens it. The result is the envelope object of the eight fields, base64 as the finalized section 2 says.
	static func sealForTests(phrase: String, passcode: [UInt8], eoa: String, salt: Data? = nil, iv: Data? = nil) -> [String: Any]? {
		let saltBytes = salt ?? Data((0..<16).map { _ in UInt8.random(in: 0...255) })
		let ivBytes = iv ?? Data((0..<12).map { _ in UInt8.random(in: 0...255) })
		let owner = eoa.lowercased()
		guard case .success(var key) = BeamioArgon2id.deriveV3Key(passcode: passcode, salt: Array(saltBytes)) else { return nil }
		defer { BeamioNativeWallet.wipe(&key) }
		guard let nonce = try? AES.GCM.Nonce(data: ivBytes),
		      let box = try? AES.GCM.seal(BeamioPwaWalletSync.normalized(phrase), using: SymmetricKey(data: key), nonce: nonce, authenticating: Data((aadPrefix + owner).utf8))
		else { return nil }
		return ["v": version, "mode": "passcode", "eoa": owner, "kdf": kdfLabel, "salt": saltBytes.base64EncodedString(), "iv": ivBytes.base64EncodedString(),
		        "alg": algorithm, "ct": (box.ciphertext + box.tag).base64EncodedString()]
	}
	#endif
}
