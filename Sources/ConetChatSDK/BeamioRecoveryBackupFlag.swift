import Foundation

/// The recovery-backup flag of an account. A clear or unregistration that would remove the W
/// items (the EOA key copy, the mnemonic record, K) needs it: the user has kept the recovery code, or the account was restored from a recovery
/// source. It is device-level and not secret. It is set only by the native layer (the save page after the user confirms, or a successful
/// restore). A missing, unreadable, or non-true value counts as not set. It is cleared when the W items are removed (.
enum BeamioRecoveryBackupFlag {
	/// The Keychain item of the flag: a generic password in the wallet service, `AfterFirstUnlockThisDeviceOnly`, not synchronised, not in backups
	/// (§25.52PY.10, r3qx). It is never a UserDefaults value, which travels with the device backup.
	private static let service = "com.beamio.beamio.chat-wallet"
	private static func account(_ eoa: String) -> String { "recoveryBackupConfirmed:" + eoa.lowercased() }

	/// True only when the stored item holds exactly the confirmed value. A missing, unreadable or other item counts as not set.
	static func isRecoveryBackupConfirmed(eoa eoa: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on { return BeamioChatWalletTestMemory.get(service, account(eoa)) == Data("confirmed".utf8) }
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account(eoa),
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return false }
		return data == Data("confirmed".utf8)
	}

	/// Set by the native layer only (confirmRecoveryBackup): after the user confirms the save-recovery-code page, or after a successful restore.
	/// Returns false when the item cannot be stored; the flag then stays not set.
	@discardableResult
	public static func confirmRecoveryBackup(eoa: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.put(service, account(eoa), Data("confirmed".utf8))
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
		add[kSecValueData as String] = Data("confirmed".utf8)
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		add[kSecAttrSynchronizable as String] = kCFBooleanFalse
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
	}

	/// Cleared once the W items of the account are removed. True when no item remains.
	@discardableResult
	static func clear(eoa: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.remove(service, account(eoa))
			return true
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account(eoa),
		]
		let status = SecItemDelete(query as CFDictionary)
		return status == errSecSuccess || status == errSecItemNotFound
	}

	/// Whether the account holds any W item: the EOA key copy, the mnemonic record, or K. An unreadable item counts as present.
	static func hasWalletItems(eoa rawEoa: String, store: BeamioChatWalletKeyStoring) -> Bool {
		let eoa = rawEoa.lowercased()
		if let items = store as? BeamioChatMnemonicKeyStoring {
			return items.itemState(.key, eoa: eoa) != .absent
				|| items.itemState(.mnemonic, eoa: eoa) != .absent
				|| BeamioWalletCredentialBlob.hasRecord(eoa: eoa)
		}
		return store.read(eoa: eoa) != nil || BeamioWalletCredentialBlob.hasRecord(eoa: eoa)
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
