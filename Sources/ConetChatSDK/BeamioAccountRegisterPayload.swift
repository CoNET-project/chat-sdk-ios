import CryptoKit
import Foundation

/// `accountCreateRegister` (the new-account registration protocol, v1): the registration request of a new account (`addUser`: the BeamioTag and the recover records), made by
/// the native layer. The page gets the finished payload and only forwards it. The recover records are the ones the PWA's `createRecover` makes: two entries, one opened by the recover
/// code and one by the password, each `base64(JSON{stored, img})` with `img = base64(iv ‖ AES-256-GCM(base64(phrase)))` and the key from argon2id(password or code, the salt of `stored`).
///
/// The password and the phrase stay in memory for this call only: nothing is stored, logged or returned except the records that hide them. The recover code is returned once, for
/// the user to keep. The registry is read first (both endpoints, one block): a name that another account holds is `tag_taken`; a registry that cannot be read is `not_ready`, never
/// `tag_taken`, and nothing is made. The signature is over the exact `wallet` string that is returned (the Cluster checks the signature against the wallet text it receives).
/// Only a QA build (and the test build) enables the command; any other build answers `not_available`.
enum BeamioNewAccountFeature {
	/// The new-account registration is enabled in a QA build only, until its acceptance (the production build answers `not_available` and starts nothing).
	static var enabled: Bool {
		#if BEAMIO_QA_BUILD
		return true
		#elseif BEAMIO_TEST_HOOKS
		return enabledForTests
		#else
		return false
		#endif
	}
	#if BEAMIO_TEST_HOOKS
	static var enabledForTests = true
	#endif
}

public enum BeamioAccountRegisterPayload {
	public struct Failure: Error, Equatable {
		public let code: String
	}

	/// The agreed registry read. Replaced in tests.
	static var registryOwner: (String) -> Result<AddressPGPChain.RegistryOwner, Error> = { AddressPGPChain.registryOwnerAgreed(accountName: $0) }

	static let argonMemoryKiB = 32 * 1024
	static let argonIterations = 3
	static let argonParallelism = 1

	/// The base58 alphabet (no 0, O, I, l). It is a subset of the base62 characters of a uuid62, so the 22-character check of the restore and the PWA's parsing accept it.
	private static let base58 = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)

	/// A recover code: 22 base58 characters from 16 random bytes (58^22 is above 2^128, so 22 characters always hold them).
	static func makeRecoverCode(random: [UInt8]) -> String {
		var digits = random
		var out: [UInt8] = []
		while digits.contains(where: { $0 != 0 }) {
			var remainder = 0
			for i in digits.indices {
				let value = remainder * 256 + Int(digits[i])
				digits[i] = UInt8(value / 58)
				remainder = value % 58
			}
			out.append(base58[remainder])
		}
		while out.count < 22 { out.append(base58[0]) }
		return String(decoding: out.reversed(), as: UTF8.self)
	}

	private static func keccakHex(_ text: String) -> String {
		"0x" + BeamioNativeEthSigner.keccak256(Array(text.utf8)).map { String(format: "%02x", $0) }.joined()
	}

	/// One record: `base64(JSON{stored, img})`. `key` is the AES key of this entry; `stored` is the shared password hash block.
	private static func record(phraseBase64: [UInt8], key: [UInt8], stored: [String: Any], iv: [UInt8]) -> String? {
		guard let nonce = try? AES.GCM.Nonce(data: iv), let box = try? AES.GCM.seal(Data(phraseBase64), using: SymmetricKey(data: Data(key)), nonce: nonce) else { return nil }
		let img = (box.nonce.withUnsafeBytes { Data($0) } + box.ciphertext + box.tag).base64EncodedString()
		guard let json = try? JSONSerialization.data(withJSONObject: ["stored": stored, "img": img]) else { return nil }
		return json.base64EncodedString()
	}

	/// The payload for `accountName` and `password` of the unlocked account `eoa`. `random` supplies the bytes (the salt, the two IVs, the recover code); the product takes them from the system.
	static func make(tag raw: String, password: String, eoa rawEoa: String, store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore,
	                 random: (Int) -> [UInt8] = { BeamioChatRouteRegister.randomBytes($0) }) -> Result<[String: Any], Failure> {
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty else { return .failure(Failure(code: "bad_request")) }
		// the tag rule of the server (`/addUser`): 3 to 26 letters, digits, `_` and `.`, after the `@` is removed and the edges are trimmed
		let accountName = BeamioNativeRecovery.accountNameKey(raw)
		guard accountName.count >= 3, accountName.count <= 26, accountName.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2E })
		else { return .failure(Failure(code: "bad_tag")) }
		guard !password.isEmpty else { return .failure(Failure(code: "bad_password")) }
		// the registry first: nothing is made for a name that is taken or cannot be checked
		switch registryOwner(accountName) {
		case .failure: return .failure(Failure(code: "not_ready"))
		case .success(.owner(let holder)): return .failure(Failure(code: holder.lowercased() == eoa ? "already_registered" : "tag_taken"))
		case .success(.free): break
		}
		// the phrase of the account, and the key it derives: the phrase must be this account's
		guard let items = store as? BeamioChatMnemonicKeyStoring, var phraseBytes = items.readItem(.mnemonic, eoa: eoa), !phraseBytes.isEmpty else {
			// without the phrase there is nothing to seal
			return .failure(Failure(code: "seal_failed"))
		}
		defer { BeamioNativeWallet.wipe(&phraseBytes) }
		let phrase = String(decoding: phraseBytes, as: UTF8.self)
		guard var derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase), derived.eoa == eoa else { return .failure(Failure(code: "sign_failed")) }
		defer { BeamioNativeWallet.wipe(&derived.key) }
		let keyBytes = [UInt8](derived.key)
		// the wallet as the page forwards it: lower case. The signature is over this very text.
		guard let checksummed = BeamioNativeEthSigner.address(privateKey: keyBytes), checksummed.lowercased() == eoa,
		      let signMessage = BeamioNativeEthSigner.signEip191(privateKey: keyBytes, message: eoa) else { return .failure(Failure(code: "sign_failed")) }
		let wallet = eoa

		let salt = random(16)
		let code = makeRecoverCode(random: random(16))
		guard salt.count == 16, code.count == 22 else { return .failure(Failure(code: "seal_failed")) }
		let passwordBytes = Array(password.utf8)
		let codeBytes = Array(code.utf8)
		guard case .success(var passwordHash) = BeamioArgon2id.derive(password: passwordBytes, salt: salt, memoryKiB: UInt32(argonMemoryKiB), iterations: UInt32(argonIterations), parallelism: UInt32(argonParallelism), outputLength: 32),
		      case .success(var codeKey) = BeamioArgon2id.derive(password: codeBytes, salt: salt, memoryKiB: UInt32(argonMemoryKiB), iterations: UInt32(argonIterations), parallelism: UInt32(argonParallelism), outputLength: 32)
		else { return .failure(Failure(code: "seal_failed")) }
		defer { BeamioNativeWallet.wipe(&passwordHash); BeamioNativeWallet.wipe(&codeKey) }
		let stored: [String: Any] = [
			"algo": "argon2id", "v": 19, "m": argonMemoryKiB, "t": argonIterations, "p": argonParallelism,
			"salt": Data(salt).base64EncodedString(), "hash": Data(passwordHash).base64EncodedString(),
		]
		let phraseBase64 = Array(Data(phraseBytes).base64EncodedString().utf8)
		guard let byCode = record(phraseBase64: phraseBase64, key: codeKey, stored: stored, iv: random(12)),
		      let byPassword = record(phraseBase64: phraseBase64, key: passwordHash, stored: stored, iv: random(12))
		else { return .failure(Failure(code: "seal_failed")) }
		return .success([
			"accountName": accountName,
			"wallet": wallet,
			"signMessage": signMessage,
			"recover": [["hash": keccakHex(code), "encrypto": byCode], ["hash": keccakHex(accountName), "encrypto": byPassword]],
			"recoverCodeBase58": code,
		])
	}
}
