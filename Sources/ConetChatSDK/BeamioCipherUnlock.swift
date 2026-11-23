import Foundation

/// The session key of an account whose native record is a v3 passcode envelope (method Y: the passcode protection stays in the store).
///
/// After the page unlocks the account and sends `pwaWalletSync{eoa, cipher, passcode, seq}`, the SDK verifies the envelope with the passcode in memory and keeps
/// the account's private key here, in process memory only. Nothing is written: the native record stays the envelope. A lock, a logout, an account switch and the
/// end of the process drop it, so a restart finds the envelope locked again. The passcode itself is never kept.
enum BeamioCipherUnlock {
	private static let lock = NSLock()
	private static var keys: [String: [UInt8]] = [:]

	/// Keeps a copy of the key for the account. The caller wipes its own copy.
	static func hold(eoa rawEoa: String, key: [UInt8]) {
		let eoa = rawEoa.lowercased()
		lock.lock()
		defer { lock.unlock() }
		if var old = keys[eoa] { BeamioNativeWallet.wipe(&old) }
		keys[eoa] = key
	}

	/// A copy of the held key (the caller wipes it), or nil when the account is not unlocked.
	static func key(eoa rawEoa: String) -> Data? {
		lock.lock()
		defer { lock.unlock() }
		return keys[rawEoa.lowercased()].map { Data($0) }
	}

	static func isUnlocked(eoa rawEoa: String) -> Bool {
		lock.lock()
		defer { lock.unlock() }
		return keys[rawEoa.lowercased()] != nil
	}

	/// Drops and overwrites every held key, except the one of `keeping` (the account the device pointer has just been set to: adopting the unlocked account is not
	/// leaving it).
	static func clear(keeping: String? = nil) {
		lock.lock()
		defer { lock.unlock() }
		let keep = keeping?.lowercased()
		for eoa in Array(keys.keys) where eoa != keep {
			BeamioNativeWallet.wipe(&keys[eoa]!)
			keys[eoa] = nil
		}
	}

	/// The account whose native record (`mnemonic.current`) is a v3 envelope, read through the raw store. nil for any other state, including a read that fails.
	static func cipherAccount(store: BeamioChatWalletKeyStoring) -> String? {
		guard let raw = store as? BeamioChatRawItemStoring else { return nil }
		if case .cipher(let eoa, _) = BeamioMnemonicSets.current(store: raw) { return eoa }
		return nil
	}
}
