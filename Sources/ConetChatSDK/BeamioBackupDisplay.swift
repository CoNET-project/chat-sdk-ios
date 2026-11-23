import Foundation

/// The read of the recovery phrase for the native save page (§25.52PY.16). Internal: it never crosses the bridge and never logs.
/// The caller owns the returned bytes and must wipe them when the view closes. The flag is not set here: the page calls
/// `BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa:)` only after the user confirms "saved".
public enum BeamioBackupDisplay {
	public enum Output {
		case mnemonic(Data)
		case unavailable
	}

	public static let purpose = "backup_display"

	/// The phrase of an account for the save page. `unavailable` when the purpose is not `backup_display`, the store cannot
	/// read the phrase, or the account has no phrase (a private-key-only account fails closed; no key is shown).
	public static func readMnemonicForBackupDisplay(eoa rawEoa: String, purpose requested: String) -> Output {
		guard requested == purpose else { return .unavailable }
		let eoa = rawEoa.lowercased()
		guard let items = BeamioNativeWallet.keyStore as? BeamioChatMnemonicKeyStoring,
		      let phrase = items.readItem(.mnemonic, eoa: eoa), !phrase.isEmpty
		else { return .unavailable }
		return .mnemonic(phrase)
	}
}

extension BeamioBackupDisplay {
	/// A private-key-only account: the EOA key is present and the phrase is absent (PY.14 (c)). Such an account has no phrase to back up, so a
	/// clear or an unregistration fails closed for it: nothing is removed and the answer is `unregister_refused`.
	public static func isKeyOnlyAccount(eoa rawEoa: String) -> Bool {
		let eoa = rawEoa.lowercased()
		guard let items = BeamioNativeWallet.keyStore as? BeamioChatMnemonicKeyStoring else { return false }
		return items.itemState(.key, eoa: eoa) != .absent && items.itemState(.mnemonic, eoa: eoa) == .absent
	}
}
