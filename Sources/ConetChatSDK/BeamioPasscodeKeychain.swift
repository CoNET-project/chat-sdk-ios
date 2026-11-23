import CryptoKit
import Foundation
import Security

/// Keychain storage for the passcode vault: records and the hardware layer H are kept in the
/// Keychain, ThisDeviceOnly, not synchronised to iCloud and not in backups.
///
/// Records: a generic password per account. The record is already encrypted.
/// Hardware layer H: a Secure Enclave P-256 key (non-exportable), used to wrap with ECIES. Where there is no Secure
/// Enclave (for example the simulator), the fallback is a random 256-bit key in a Keychain generic password with
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, the same access level as the Secure Enclave path (ruling
/// 2026-11-11: background listen and voice wake must work while the device is locked). The fallback is NOT
/// hardware-bound: its key bytes are readable by code running as the app once the device has been unlocked after boot.
/// The blob says which path wrapped it.
public final class BeamioPasscodeKeychainRecords: BeamioPasscodeRecordStoring {
	public static let standard = BeamioPasscodeKeychainRecords(service: "com.beamio.beamio.passcode.record")
	/// Staging records of the shell passcode writes: an independent service (frozen protocol §8.4), so listing the owners of `standard` never sees them.
	public static let staging = BeamioPasscodeKeychainRecords(service: "com.beamio.beamio.passcode.record.staging")

	private let service: String

	public init(service: String) {
		self.service = service
	}

	public func readRecord(eoa: String) -> Data? {
		if case .present(let data) = readRecordState(eoa: eoa) { return data }
		return nil
	}

	public func readRecordState(eoa: String) -> BeamioPasscodeRecordRead {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			if let data = BeamioChatWalletTestMemory.get(service, eoa.lowercased()) { return .present(data) }
			return .absent
		}
		#endif
		var query = baseQuery(eoa: eoa)
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		if status == errSecItemNotFound { return .absent }
		guard status == errSecSuccess, let data = item as? Data else { return .unavailable }
		return .present(data)
	}

	/// Replaces the record and reads it back. Returns false unless the stored bytes are the bytes written.
	public func writeRecord(eoa: String, _ data: Data) -> Bool {
		// The one choke point of every write of a passcode record or staging copy (the main record store and the staging store are two instances of this class): the write
		// marker is set for the account while the write runs, on every path, and released by `defer`.
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.put(service, eoa.lowercased(), data)
			return true
		}
		#endif
		// An existing record is updated in place (Y.163 第 5 項: its creation time orders the silent selection). Add only when absent.
		let query = baseQuery(eoa: eoa)
		let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
		if update != errSecSuccess {
			guard update == errSecItemNotFound else { return false }
			var add = query
			add[kSecValueData as String] = data
			add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
			add[kSecAttrSynchronizable as String] = kCFBooleanFalse
			guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { return false }
		}
		return readRecord(eoa: eoa) == data
	}

	public func deleteRecord(eoa: String) {
		// as writeRecord: the one choke point of every delete of a record or staging copy
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.remove(service, eoa.lowercased())
			return
		}
		#endif
		SecItemDelete(baseQuery(eoa: eoa) as CFDictionary)
	}

	/// Any record of this service, for any account. Only the account names are read. Any failure other than "no item" answers true.
	public func hasAnyRecord() -> Bool {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on { return !BeamioChatWalletTestMemory.accounts(service).isEmpty }
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return false }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return true }
		return !rows.isEmpty
	}

	/// The account names of every record of this service. nil when the listing fails: fail closed, not "no record".
	public func enumerateRecordOwners() -> [String]? {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on { return BeamioChatWalletTestMemory.accounts(service) }
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var owners: [String] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			owners.append(account)
		}
		return owners
	}

	/// The creation time of every record of this service, from the attributes only (Y.163 第 5 項). nil when the listing fails (fail closed).
	public func enumerateRecordCreations() -> [BeamioChatKeyCreation]? {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			return BeamioChatWalletTestMemory.accounts(service).map {
				BeamioChatKeyCreation(owner: $0, created: BeamioChatWalletTestMemory.created(service, $0))
			}
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var out: [BeamioChatKeyCreation] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			out.append(BeamioChatKeyCreation(owner: account, created: row[kSecAttrCreationDate as String] as? Date))
		}
		return out
	}

	private func baseQuery(eoa: String) -> [String: Any] {
		[
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: eoa.lowercased(),
		]
	}
}

public final class BeamioPasscodeKeychainHardware: BeamioPasscodeHardwareKeyStoring {
	public static let standard = BeamioPasscodeKeychainHardware(
		seTagPrefix: "com.beamio.passcode.h.se.",
		fallbackService: "com.beamio.beamio.passcode.h-fallback"
	)

	/// The first byte of every blob says which path wrapped it.
	private enum Path: UInt8 {
		case secureEnclave = 1
		case fallback = 2
	}

	private let seTagPrefix: String
	private let fallbackService: String

	public init(seTagPrefix: String, fallbackService: String) {
		self.seTagPrefix = seTagPrefix
		self.fallbackService = fallbackService
	}

	public var isSecureEnclave: Bool { SecureEnclave.isAvailable }

	public func hasKey(eoa: String) -> Bool {
		seKey(eoa: eoa) != nil || fallbackItemExists(eoa: eoa)
	}

	/// `absent` only when both lookups answered "no item"; any other status is `unknown`.
	public func keyState(eoa: String) -> BeamioPasscodeHardwareKeyState {
		let seQuery: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrApplicationTag as String: seTag(eoa: eoa),
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecReturnRef as String: false,
		]
		let seStatus = SecItemCopyMatching(seQuery as CFDictionary, nil)
		if seStatus == errSecSuccess { return .present }
		guard seStatus == errSecItemNotFound else { return .unknown }
		var fb = fallbackQuery(eoa: eoa)
		fb[kSecReturnData as String] = false
		fb[kSecMatchLimit as String] = kSecMatchLimitOne
		let fbStatus = SecItemCopyMatching(fb as CFDictionary, nil)
		if fbStatus == errSecSuccess { return .present }
		return fbStatus == errSecItemNotFound ? .absent : .unknown
	}

	/// Creates H for the account. Secure Enclave first; the Keychain fallback where there is none. Read back before it counts.
	public func createKey(eoa: String) -> Bool {
		// H of the account is written or replaced: the same account marker as the record
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		if SecureEnclave.isAvailable, createSecureEnclaveKey(eoa: eoa), seKey(eoa: eoa) != nil {
			return true
		}
		return createFallbackKey(eoa: eoa)
	}

	public func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data {
		let payload = frame(plain, aad: aad)
		if let priv = seKey(eoa: eoa), let pub = SecKeyCopyPublicKey(priv),
		   SecKeyIsAlgorithmSupported(pub, .encrypt, Self.eciesAlgorithm) {
			var err: Unmanaged<CFError>?
			guard let sealed = SecKeyCreateEncryptedData(pub, Self.eciesAlgorithm, payload as CFData, &err) as Data? else {
				throw BeamioPasscodeError.hardwareUnavailable
			}
			return Data([Path.secureEnclave.rawValue]) + sealed
		}
		guard let key = fallbackKey(eoa: eoa) else { throw BeamioPasscodeError.hardwareUnavailable }
		return Data([Path.fallback.rawValue]) + (try BeamioPasscodeWrap.seal(payload, key: key, aad: aad))
	}

	public func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data {
		guard let tag = blob.first, let path = Path(rawValue: tag) else { throw BeamioPasscodeError.recordInvalid }
		let body = blob.dropFirst()
		let payload: Data
		switch path {
		case .secureEnclave:
			guard let priv = seKey(eoa: eoa), SecKeyIsAlgorithmSupported(priv, .decrypt, Self.eciesAlgorithm) else {
				throw BeamioPasscodeError.hardwareUnavailable
			}
			var err: Unmanaged<CFError>?
			guard let plain = SecKeyCreateDecryptedData(priv, Self.eciesAlgorithm, body as CFData, &err) as Data? else {
				throw BeamioPasscodeError.recordInvalid
			}
			payload = plain
		case .fallback:
			guard let key = fallbackKey(eoa: eoa) else { throw BeamioPasscodeError.hardwareUnavailable }
			payload = try BeamioPasscodeWrap.open(Data(body), key: key, aad: aad)
		}
		return try unframe(payload, aad: aad)
	}

	public func deleteKey(eoa: String) {
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		let q: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: seTag(eoa: eoa)]
		SecItemDelete(q as CFDictionary)
		SecItemDelete(fallbackQuery(eoa: eoa) as CFDictionary)
	}

	/// The two parts of H apart (silent cleanup, 2026-11-21 decision, item 5: the Secure Enclave key is kept in this version and only identifies the account).
	/// `absent` only when the lookup said "no item"; any other status is `unknown`.
	public func seKeyState(eoa: String) -> BeamioPasscodeHardwareKeyState {
		let q: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrApplicationTag as String: seTag(eoa: eoa),
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecReturnRef as String: false,
		]
		let status = SecItemCopyMatching(q as CFDictionary, nil)
		if status == errSecSuccess { return .present }
		return status == errSecItemNotFound ? .absent : .unknown
	}

	public func fallbackState(eoa: String) -> BeamioPasscodeHardwareKeyState {
		var q = fallbackQuery(eoa: eoa)
		q[kSecReturnData as String] = false
		q[kSecMatchLimit as String] = kSecMatchLimitOne
		let status = SecItemCopyMatching(q as CFDictionary, nil)
		if status == errSecSuccess { return .present }
		return status == errSecItemNotFound ? .absent : .unknown
	}

	/// Deletes the Keychain fallback item only; the Secure Enclave key stays.
	public func deleteFallback(eoa: String) {
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		SecItemDelete(fallbackQuery(eoa: eoa) as CFDictionary)
	}

	/// The addresses named by the Secure Enclave tags (`<seTagPrefix><address>`) and by the fallback items of H, to identify accounts. nil when either listing fails (an error other than "no item").
	public func enumerateAccounts() -> [String]? {
		var out = Set<String>()
		let keys: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var keyItems: CFTypeRef?
		let keyStatus = SecItemCopyMatching(keys as CFDictionary, &keyItems)
		if keyStatus == errSecSuccess {
			guard let rows = keyItems as? [[String: Any]] else { return nil }
			for row in rows {
				guard let tag = row[kSecAttrApplicationTag as String] as? Data, let text = String(data: tag, encoding: .utf8) else { continue }
				if text.hasPrefix(seTagPrefix) { out.insert(String(text.dropFirst(seTagPrefix.count))) }
			}
		} else if keyStatus != errSecItemNotFound { return nil }
		let fallback: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: fallbackService,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var fbItems: CFTypeRef?
		let fbStatus = SecItemCopyMatching(fallback as CFDictionary, &fbItems)
		if fbStatus == errSecSuccess {
			guard let rows = fbItems as? [[String: Any]] else { return nil }
			for row in rows { if let a = row[kSecAttrAccount as String] as? String { out.insert(a) } }
		} else if fbStatus != errSecItemNotFound { return nil }
		return out.sorted()
	}

	// MARK: - Secure Enclave

	static let eciesAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

	private func seTag(eoa: String) -> Data { Data((seTagPrefix + eoa.lowercased()).utf8) }

	private func seKey(eoa: String) -> SecKey? {
		let q: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrApplicationTag as String: seTag(eoa: eoa),
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecReturnRef as String: true,
		]
		var item: CFTypeRef?
		guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess else { return nil }
		return (item as! SecKey)
	}

	private func createSecureEnclaveKey(eoa: String) -> Bool {
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		var acError: Unmanaged<CFError>?
		guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &acError) else {
			return false
		}
		let attrs: [String: Any] = [
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeySizeInBits as String: 256,
			kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
			kSecPrivateKeyAttrs as String: [
				kSecAttrIsPermanent as String: true,
				kSecAttrApplicationTag as String: seTag(eoa: eoa),
				kSecAttrAccessControl as String: acl,
			] as [String: Any],
		]
		var err: Unmanaged<CFError>?
		return SecKeyCreateRandomKey(attrs as CFDictionary, &err) != nil
	}

	// MARK: - Keychain fallback

	private func fallbackQuery(eoa: String) -> [String: Any] {
		[
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: fallbackService,
			kSecAttrAccount as String: eoa.lowercased(),
		]
	}

	private func fallbackItemExists(eoa: String) -> Bool {
		var q = fallbackQuery(eoa: eoa)
		q[kSecReturnData as String] = false
		q[kSecMatchLimit as String] = kSecMatchLimitOne
		return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
	}

	/// The fallback key bytes are read into a SymmetricKey for one call and not kept.
	private func fallbackKey(eoa: String) -> SymmetricKey? {
		var q = fallbackQuery(eoa: eoa)
		q[kSecReturnData as String] = true
		q[kSecMatchLimit as String] = kSecMatchLimitOne
		var item: CFTypeRef?
		guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess, var bytes = item as? Data, bytes.count == 32 else {
			return nil
		}
		defer { BeamioNativeWallet.wipe(&bytes) }
		return SymmetricKey(data: bytes)
	}

	private func createFallbackKey(eoa: String) -> Bool {
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		var bytes = [UInt8](repeating: 0, count: 32)
		guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return false }
		defer { BeamioNativeWallet.wipe(&bytes) }
		SecItemDelete(fallbackQuery(eoa: eoa) as CFDictionary)
		var add = fallbackQuery(eoa: eoa)
		add[kSecValueData as String] = Data(bytes)
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		add[kSecAttrSynchronizable as String] = kCFBooleanFalse
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess && fallbackItemExists(eoa: eoa)
	}

	// MARK: - Framing (AAD bound into the wrapped data for the Secure Enclave path)

	private func frame(_ plain: Data, aad: Data) -> Data {
		var out = Data([UInt8((aad.count >> 8) & 0xff), UInt8(aad.count & 0xff)])
		out.append(aad)
		out.append(plain)
		return out
	}

	private func unframe(_ payload: Data, aad: Data) throws -> Data {
		guard payload.count >= 2 else { throw BeamioPasscodeError.recordInvalid }
		let n = Int(payload[payload.startIndex]) << 8 | Int(payload[payload.startIndex + 1])
		guard payload.count >= 2 + n, Data(payload.dropFirst(2).prefix(n)) == aad else { throw BeamioPasscodeError.recordInvalid }
		return Data(payload.dropFirst(2 + n))
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
fileprivate func SecItemUpdate(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.update(query, attributesToUpdate)
}
fileprivate func SecKeyCreateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? {
	// A test build never creates a Secure Enclave key, whatever `BeamioChatWalletTestMemory.items` holds (nil or not): this answers nil, so the creation of an SE key FAILS.
	// `BeamioPasscodeKeychainHardware.createKey` then takes its Keychain fallback (SecItemAdd, also answered from the in-memory items, which a first write creates), so `createKey`
	// still SUCCEEDS in a test build, by the fallback, with nothing written to the real Keychain.
	BeamioTestKeychainStore.createRandomKey(parameters, error)
}
#endif
