import CryptoKit
import Foundation
import Security

/// The walletCredential blob. The blob is the mnemonic sealed with AES-256-GCM under a
/// per-account key K. K is random, created once per account, and stored like the wallet keystore stores its items (D21):
/// - with a Secure Enclave key, K is wrapped by `SecureEnclaveWrap` (ECIES) and only the ciphertext is stored (mode "se");
/// - without one, K is stored in the Keychain item itself (mode "keychain").
/// The Keychain item is `AfterFirstUnlockThisDeviceOnly`, not synchronised, not exportable. QA and non-QA builds behave the same.
/// The blob is `hex(nonce[12] || ciphertext || tag[16])`, lowercase. The AAD is `beamio-native-wallet-v1|b|<lowercase eoa>`. The plaintext is the
/// UTF-8 mnemonic. The diagnostics record only the mode, never K, the wrapped K, the phrase, or the blob.
enum BeamioWalletCredentialBlob {
	static let aadPrefix = "beamio-native-wallet-v1|b|"
	/// The keystore's service (BeamioChatWalletKeychainStore.standard), so the blob keys sit with the wallet items.
	static let service = "com.beamio.beamio.chat-wallet"

	/// The account name of an account's K record (r2.5.19 第 59(3)(e), the PWA overwrite isolates it with the wallet items).
	static func account(_ eoa: String) -> String { "blobKey:" + eoa.lowercased() }

	private static func aad(_ eoa: String) -> Data { Data((aadPrefix + eoa.lowercased()).utf8) }

	/// The stored record of K: `{v: 2, eoa, mode, wrappedKey}`. `wrappedKey` is base64; it is separate from the keystore record, whose field is `blob`.
	private static func readRecord(eoa: String) -> [String: Any]? {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			guard let data = BeamioChatWalletTestMemory.get(service, account(eoa)) else { return nil }
			return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account(eoa),
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
		return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
	}

	private static func writeRecord(_ record: [String: Any], eoa: String) -> Bool {
		guard let payload = try? JSONSerialization.data(withJSONObject: record) else { return false }
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.put(service, account(eoa), payload)
			return true
		}
		#endif
		let base: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account(eoa),
		]
		SecItemDelete(base as CFDictionary)
		var add = base
		add[kSecValueData as String] = payload
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		add[kSecAttrSynchronizable as String] = kCFBooleanFalse
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
	}

	/// The account's key K, read from its record. nil when there is no record or it cannot be unwrapped. It never creates K.
	static func key(eoa rawEoa: String) -> Data? {
		let eoa = rawEoa.lowercased()
		guard let record = readRecord(eoa: eoa) else { return nil }
		guard record["v"] as? Int == 2, record["eoa"] as? String == eoa, let mode = record["mode"] as? String,
		      let encoded = record["wrappedKey"] as? String, let blob = Data(base64Encoded: encoded)
		else { return nil }
		switch mode {
		case "se": return SecureEnclaveWrap.unwrap(blob)
		case "keychain": return blob
		default: return nil
		}
	}

	/// Creates K for an account whose mnemonic record is present and readable (: at the mnemonic write;: the upgrade path at the first
	/// walletCredential, after the mnemonic was read in the same call). An existing K is kept, never overwritten. The new record is read back and
	/// unwrapped; a failed write or read-back removes what was written and returns false, so no K outlives a failed creation (no orphan).
	/// Keychain has no transaction; the write-read-back-rollback sequence is what makes it atomic for the caller.
	static func hasRecord(eoa rawEoa: String) -> Bool { readRecord(eoa: rawEoa.lowercased()) != nil }

	#if BEAMIO_TEST_HOOKS
	/// Test build only: makes the creation of K fail, so that the mnemonic write around it can be shown to roll back.
	static var failCreationForTests = false
	#endif

	static func createIfMissing(eoa rawEoa: String) -> Bool {
		let eoa = rawEoa.lowercased()
		#if BEAMIO_TEST_HOOKS
		if failCreationForTests { return false }
		#endif
		if readRecord(eoa: eoa) != nil { return key(eoa: eoa) != nil }
		var fresh = Data((0 ..< 32).map { _ in UInt8.random(in: 0 ... 255) })
		defer { BeamioNativeWallet.wipe(&fresh) }
		let record: [String: Any]
		if let wrapped = SecureEnclaveWrap.wrap(fresh) {
			record = ["v": 2, "eoa": eoa, "mode": "se", "wrappedKey": wrapped.base64EncodedString()]
		} else {
			record = ["v": 2, "eoa": eoa, "mode": "keychain", "wrappedKey": fresh.base64EncodedString()]
		}
		guard writeRecord(record, eoa: eoa) else { return false }
		guard let back = key(eoa: eoa), back == fresh else {
			_ = delete(eoa: eoa)
			return false
		}
		return true
	}

	/// Removes the account's K (the account's mnemonic record is removed, or the account is cleared). Returns true when no K remains.
	static func delete(eoa rawEoa: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.remove(service, account(rawEoa))
			return true
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account(rawEoa),
		]
		let status = SecItemDelete(query as CFDictionary)
		return status == errSecSuccess || status == errSecItemNotFound
	}

	/// The blob of a mnemonic for an account (lowercase hex). nil when K is unavailable or the seal fails.
	static func seal(phrase: Data, eoa rawEoa: String) -> String? {
		let eoa = rawEoa.lowercased()
		guard var keyBytes = key(eoa: eoa) else { return nil }
		defer { BeamioNativeWallet.wipe(&keyBytes) }
		guard let sealed = try? AES.GCM.seal(phrase, using: SymmetricKey(data: keyBytes), authenticating: aad(eoa)),
		      let combined = sealed.combined
		else { return nil }
		return combined.map { String(format: "%02x", $0) }.joined()
	}

	/// The mnemonic of a blob for an account. nil when the blob is not hex, K is unavailable, or the tag does not verify.
	static func open(hex: String, eoa rawEoa: String) -> Data? {
		let eoa = rawEoa.lowercased()
		guard let combined = dataFromHex(hex), combined.count >= 12 + 16 else { return nil }
		guard var keyBytes = key(eoa: eoa) else { return nil }
		defer { BeamioNativeWallet.wipe(&keyBytes) }
		guard let box = try? AES.GCM.SealedBox(combined: combined) else { return nil }
		return try? AES.GCM.open(box, using: SymmetricKey(data: keyBytes), authenticating: aad(eoa))
	}

	/// Lowercase or uppercase hex only, an even number of digits.
	static func dataFromHex(_ text: String) -> Data? {
		let chars = Array(text.utf8)
		guard chars.count % 2 == 0, !chars.isEmpty else { return nil }
		var out = Data()
		var index = 0
		while index < chars.count {
			guard let hi = hexValue(chars[index]), let lo = hexValue(chars[index + 1]) else { return nil }
			out.append(hi << 4 | lo)
			index += 2
		}
		return out
	}

	private static func hexValue(_ c: UInt8) -> UInt8? {
		switch c {
		case 48 ... 57: return c - 48
		case 97 ... 102: return c - 87
		case 65 ... 70: return c - 55
		default: return nil
		}
	}
}
#if BEAMIO_TEST_HOOKS
// Test build only: this file's Keychain calls are answered from the test store (BeamioTestKeychainStore), never the real Keychain.
fileprivate func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.copyMatching(query, result)
}
fileprivate func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.add(attributes, result)
}
fileprivate func SecItemDelete(_ query: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.delete(query)
}
#endif
