#if BEAMIO_TEST_HOOKS
import Foundation
@testable import ConetChatSDK

/// Valid mnemonic accounts for fixtures. Since the mnemonic ownership rule (Y.163 items 31 and 32, 2026-11-16/17) an account is a valid mnemonic record: a key alone is no account
/// (G0, no_key). Fixtures that need an account on the device install one with `install`: the key and the mnemonic item of the account the phrase derives.
/// Public BIP-39 test phrases only; synthetic.
enum ValidTestAccounts {
	static let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	static let phraseC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
	static let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"

	static func derived(_ phrase: String) -> (eoa: String, key: Data) {
		guard let account = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { preconditionFailure("the test phrase derives an account") }
		return account
	}

	static var accountA: (eoa: String, key: Data) { derived(phraseA) }
	static var accountB: (eoa: String, key: Data) { derived(phraseB) }
	static var accountC: (eoa: String, key: Data) { derived(phraseC) }

	/// Writes the key and the mnemonic item of the account the phrase derives; returns the account.
	@discardableResult
	static func install(_ store: MemoryNativeKeyStore, phrase: String = phraseA) -> (eoa: String, key: Data) {
		let account = derived(phrase)
		_ = store.writeItem(.key, eoa: account.eoa, value: account.key)
		_ = store.writeItem(.mnemonic, eoa: account.eoa, value: BeamioPwaWalletSync.normalized(phrase))
		return account
	}
}
#endif
