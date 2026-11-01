import Foundation
import Security

/// The wallet (EOA) private key the module signs `mailbox_listen`, ACKs and
/// sends with, so a VoIP push can open the mailbox listen before the page runs.
///
/// Keychain only: `AfterFirstUnlockThisDeviceOnly` (readable on a locked phone
/// after the first unlock, never synced, never in backups or on another
/// device), no access group. Never logged.
public enum BeamioChatWalletKeychain {
	private static let service = "com.beamio.beamio.chat-wallet"
	private static let account = "walletKey"

	public struct Stored: Equatable {
		public var eoa: String
		public var privateKeyHex: String
	}

	/// 64 lower-case hex chars without 0x; empty when not a private key.
	public static func normalizeKey(_ raw: String?) -> String {
		var t = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		if t.hasPrefix("0x") { t.removeFirst(2) }
		guard t.count == 64, t.allSatisfy({ $0.isHexDigit }) else { return "" }
		return t
	}

	@discardableResult
	public static func save(eoa: String, privateKeyHex: String) -> Bool {
		let key = normalizeKey(privateKeyHex)
		let owner = eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard !key.isEmpty, !owner.isEmpty,
		      let data = try? JSONSerialization.data(withJSONObject: ["eoa": owner, "key": key])
		else { return false }
		let base = baseQuery()
		SecItemDelete(base as CFDictionary)
		var add = base
		add[kSecValueData as String] = data
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		add[kSecAttrSynchronizable as String] = kCFBooleanFalse
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
	}

	public static func load() -> Stored? {
		var query = baseQuery()
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
		      let data = item as? Data,
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String],
		      let eoa = obj["eoa"], !eoa.isEmpty
		else { return nil }
		let key = normalizeKey(obj["key"])
		return key.isEmpty ? nil : Stored(eoa: eoa, privateKeyHex: key)
	}

	public static func clear() {
		SecItemDelete(baseQuery() as CFDictionary)
	}

	private static func baseQuery() -> [String: Any] {
		[
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
		]
	}
}
