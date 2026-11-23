import Foundation

/// The wallet state of the native store. `passcodeStatus` reports it as `walletState`: the state only, never material.
public enum BeamioNativeWalletState: String, Equatable {
	/// The store has been read completely and holds no EOA key. Only this value may be read as "no account".
	case absent
	/// One valid EOA key: the pointer's account, or the only key of the store.
	case present
	/// Not ready: the enumeration cannot be completed, more than one account's key, or a key that does not match the pointer. Retry; never "no account".
	case notReady = "not_ready"
	/// A passcode record whose passcode is locked. Judged after the unlock.
	case locked
	/// A record is listed but cannot be read now (the store cannot be read). Retry.
	case unavailable
	/// A record exists but cannot be used: not decodable, or its key is not the key of its account. Not deleted, not overwritten.
	case corrupt
}

/// Judges the wallet state from the account pointer and the enumeration of the key records. Pure: the caller reads the store and the pointer,
/// so the rules are tested without the Keychain.
public enum BeamioNativeWalletStateResolver {
	/// - Parameters:
	/// - pointer: the account pointer, lower-case; empty when no pointer is set.
	/// - entries: the enumeration of the key records; nil when the enumeration cannot be completed.
	/// - pageCopyKey: the account of a page copy that holds an EOA private key (item 3, the overlay); nil when no such copy is known.
	/// - Returns: the state, and for `present` and `locked` the account of the one key.
	public static func resolve(pointer: String, entries: [BeamioChatKeyEntryCheck]?, markerWithoutRecord: Bool = false,
		pageCopyKey: String? = nil, pageCopyEnumerationFailed: Bool = false) -> (state: BeamioNativeWalletState, account: String?) {
		// An enumeration that cannot be completed is not_ready: the read is not done and can be retried (; walletstate-vectors AD-06, AD-14).
		guard let entries = entries else { return (.notReady, nil) }
		// A record that is listed but cannot be read now is unavailable (the store cannot be read). It is never absent.
		if entries.contains(.unavailable) { return (.unavailable, nil) }
		var valid = Set<String>()
		var locked = Set<String>()
		var corrupt = false
		for entry in entries {
			switch entry {
			case .valid(let eoa): valid.insert(eoa.lowercased())
			case .locked(let eoa): locked.insert(eoa.lowercased())
			case .corrupt: corrupt = true
			case .unavailable: break
			}
		}
		// A corrupt record is not a key: it neither counts as a key nor makes an account present.
		let keys = valid.union(locked)
		// item 3: with no native key, a page copy that holds an EOA private key is present (the upgrade overlay). It holds
		// until migrateLegacy succeeds; a pending or failed migration keeps it, and it is never absent. The migration state is not an input: once the key is
		// written natively, the key itself decides. A pointer that is set must name the copy's account.
		// AD-35: with no native key, a page-copy enumeration that failed cannot tell the overlay apart: unavailable, not present or absent.
		if keys.isEmpty, pageCopyEnumerationFailed { return (.unavailable, nil) }
		if keys.isEmpty, let copy = pageCopyKey?.lowercased(), !copy.isEmpty, pointer.isEmpty || pointer == copy {
			return (.present, copy)
		}
		// (AD-29): a native marker with no record is not_ready: never absent, never corrupt. The marker is kept on the native side (Android MARK).
		if markerWithoutRecord && keys.isEmpty { return (.notReady, nil) }
		if !pointer.isEmpty {
			// item 6(a), (b): the pointer decides. Its own key present: that account, whatever other keys exist (AD-26, AD-28).
			// Its key missing: not_ready, with no fallback to the enumeration and no automatic choice (AD-27). A corrupt record cannot be attributed to
			// an account, so it does not decide the pointer either: not_ready.
			if locked.contains(pointer) { return (.locked, pointer) }
			if valid.contains(pointer) { return (.present, pointer) }
			return (.notReady, nil)
		}
		// without a pointer: exactly one valid key is present; more than one is not_ready and is never chosen automatically.
		if keys.count == 1, let only = keys.first {
			return locked.contains(only) ? (.locked, only) : (.present, only)
		}
		if keys.count > 1 { return (.notReady, nil) }
		return corrupt ? (.corrupt, nil) : (.absent, nil)
	}

	/// The state the shell reads now: the native key store, the account pointer, and the store's own passcode locks.
	public static func current() -> (state: BeamioNativeWalletState, account: String?) {
		// The overlay (item 3) reads the page copies that hold an EOA key. The production store has no copy index yet ((a) gap), so this is nil
		// in production until that index exists; the rule itself is tested through `pageCopyKey`.
		// Y.163 第 31、32、34 項: the entries are the mnemonic accounts; only a pointer with a mnemonic item decides the account.
			let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
			return resolve(pointer: inventory.usablePointer(BeamioNativeAccountPointer.get()), entries: inventory.entries,
			pageCopyKey: BeamioShellRecord.accountOfCopyWithKey(store: BeamioShellRecord.EncryptedShellRecordStore.production))
	}
}
