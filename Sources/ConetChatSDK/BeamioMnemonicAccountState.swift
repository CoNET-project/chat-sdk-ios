import Foundation

/// The judgement of one account's recovery mnemonic (25.52Y.163 r8/r9 第 31 項, 1423): the mnemonic is the only saved wallet credential.
/// `valid`: the phrase is readable, passes the BIP-39 check, and the address it derives is the owner's. `invalid`: the phrase is readable but
/// fails the check, or derives another address. `unreadable`: the item cannot be read now (fail closed, never absent). `absent`: no phrase item.
public enum BeamioMnemonicAccountState: Equatable {
	case valid
	case invalid
	case unreadable
	case absent
}

extension BeamioChatMnemonicKeyStoring {
	/// Reads the account's mnemonic item and checks it against the owner. Reads the phrase only; the key and phrase are wiped at the end.
	/// Nothing is written or deleted. The store's `mnemonicAccountState(owner:)` answers this for every store.
	public func itemsAccountState(owner rawOwner: String) -> BeamioMnemonicAccountState {
		let owner = rawOwner.lowercased()
		switch itemState(.mnemonic, eoa: owner) {
		case .absent: return .absent
		case .unreadable: return .unreadable
		case .present: break
		}
		// A locked passcode account with its header and record: valid, locked (frozen protocol §7.3); the phrase is judged after the unlock.
		if (self as? BeamioLockedMnemonicHeaderJudging)?.lockedMnemonicHeaderIsValid(owner: owner) == true { return .valid }
		// method Y: the account of a v3 envelope is valid; its passcode is checked by the page's sync, never here
		if BeamioCipherUnlock.cipherAccount(store: self) == owner { return .valid }
		guard var phraseBytes = readItem(.mnemonic, eoa: owner) else { return .unreadable }
		defer { BeamioNativeWallet.wipe(&phraseBytes) }
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phraseBytes, as: UTF8.self)) else { return .invalid }
		defer { BeamioNativeWallet.wipe(&key) }
		guard let derived = BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), derived == owner else { return .invalid }
		return .valid
	}
}
