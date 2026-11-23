#if BEAMIO_TEST_HOOKS
import Foundation
import Security

/// Test build only: the Keychain items of the SDK are answered from `BeamioChatWalletTestMemory.items`, never from the real Keychain.
///
/// A file that calls SecItemCopyMatching, SecItemAdd, SecItemUpdate, SecItemDelete or SecKeyCreateRandomKey declares, at its end and only
/// under BEAMIO_TEST_HOOKS, fileprivate functions with the same names and signatures that call the functions here. In a test-hook build the
/// calls of that file resolve to them, so the object file has no reference to the Security item functions (checked with `nm -u`). A product
/// build has no such block, and its calls are the system functions.
///
/// The model covers the query shapes the SDK uses: generic passwords with kSecAttrService and kSecAttrAccount, kSecValueData, kSecReturnData,
/// kSecReturnAttributes and kSecMatchLimit. Keys (kSecClassKey) are never held: a key query finds nothing, and no key is created. A query of any
/// other shape fails with errSecParam, so an unmodelled call is a failure, never a silent success.
enum BeamioTestKeychainStore {
	// There is no real-Keychain branch in a test build: whatever `BeamioChatWalletTestMemory.items` holds (even nil, which the memory creates on its first write), every call here is answered
	// from the in-memory items. (An earlier version passed the calls through to the system Keychain when `items` was nil, for "real-keychain regression tests".)

	private static func isGenericOrNoClass(_ q: [String: Any]) -> Bool {
		let cls = q[kSecClass as String] as? String
		return cls == nil || cls == (kSecClassGenericPassword as String)
	}

	private static func isKeyClass(_ q: [String: Any]) -> Bool {
		(q[kSecClass as String] as? String) == (kSecClassKey as String)
	}

	static func copyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
		let q = (query as NSDictionary) as? [String: Any] ?? [:]
		if isKeyClass(q) { return errSecItemNotFound }
		guard isGenericOrNoClass(q), let service = q[kSecAttrService as String] as? String else { return errSecParam }
		let wantsData = q[kSecReturnData as String] as? Bool ?? false
		let wantsAttributes = q[kSecReturnAttributes as String] as? Bool ?? false
		guard wantsData || wantsAttributes else {
			// Existence only. The result is not set.
			if let account = q[kSecAttrAccount as String] as? String {
				return BeamioChatWalletTestMemory.get(service, account) != nil ? errSecSuccess : errSecItemNotFound
			}
			return BeamioChatWalletTestMemory.accounts(service).isEmpty ? errSecItemNotFound : errSecSuccess
		}
		let matchAll = (q[kSecMatchLimit as String] as? String) == (kSecMatchLimitAll as String)
		let accounts: [String]
		if let account = q[kSecAttrAccount as String] as? String {
			guard BeamioChatWalletTestMemory.get(service, account) != nil else { return errSecItemNotFound }
			accounts = [account]
		} else {
			accounts = BeamioChatWalletTestMemory.accounts(service)
			guard !accounts.isEmpty else { return errSecItemNotFound }
		}
		let picked = matchAll ? accounts : [accounts[0]]
		let rows: [AnyObject] = picked.map { account -> AnyObject in
			let data = BeamioChatWalletTestMemory.get(service, account) ?? Data()
			if !wantsAttributes { return data as AnyObject }
			var row: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: service,
				kSecAttrAccount as String: account,
			]
			if wantsData { row[kSecValueData as String] = data }
			return row as NSDictionary
		}
		result?.pointee = (matchAll ? rows as NSArray : rows[0]) as CFTypeRef
		return errSecSuccess
	}

	static func add(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
		let a = (attributes as NSDictionary) as? [String: Any] ?? [:]
		guard isGenericOrNoClass(a), let service = a[kSecAttrService as String] as? String,
		      let account = a[kSecAttrAccount as String] as? String, let value = a[kSecValueData as String] as? Data
		else { return errSecParam }
		// Add only: an existing item is never replaced by an add.
		if BeamioChatWalletTestMemory.get(service, account) != nil { return errSecDuplicateItem }
		BeamioChatWalletTestMemory.put(service, account, value)
		return errSecSuccess
	}

	static func update(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus {
		let q = (query as NSDictionary) as? [String: Any] ?? [:]
		let a = (attributesToUpdate as NSDictionary) as? [String: Any] ?? [:]
		guard isGenericOrNoClass(q), let service = q[kSecAttrService as String] as? String,
		      let account = q[kSecAttrAccount as String] as? String, let value = a[kSecValueData as String] as? Data
		else { return errSecParam }
		guard BeamioChatWalletTestMemory.get(service, account) != nil else { return errSecItemNotFound }
		BeamioChatWalletTestMemory.put(service, account, value)
		return errSecSuccess
	}

	static func delete(_ query: CFDictionary) -> OSStatus {
		let q = (query as NSDictionary) as? [String: Any] ?? [:]
		if isKeyClass(q) { return errSecItemNotFound }
		guard isGenericOrNoClass(q), let service = q[kSecAttrService as String] as? String else { return errSecParam }
		if let account = q[kSecAttrAccount as String] as? String {
			guard BeamioChatWalletTestMemory.get(service, account) != nil else { return errSecItemNotFound }
			BeamioChatWalletTestMemory.remove(service, account)
			return errSecSuccess
		}
		let accounts = BeamioChatWalletTestMemory.accounts(service)
		guard !accounts.isEmpty else { return errSecItemNotFound }
		for account in accounts { BeamioChatWalletTestMemory.remove(service, account) }
		return errSecSuccess
	}

	/// For files that shadow `SecKeyCreateRandomKey` under BEAMIO_TEST_HOOKS: no key is created (and the real Keychain is never reached).
	static func createRandomKey(
		_ parameters: CFDictionary,
		_ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
	) -> SecKey? {
		return nil
	}
}
#endif
