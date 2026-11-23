import XCTest
@testable import ConetChatSDK

/// §25.52PY.14 / PY.16: the save-page read and the recovery-backup flag. Synthetic data only.
/// The flag is a Keychain item; a host that cannot write the Keychain skips the flag cases.
final class BackupDisplayTests: XCTestCase {
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let account = "0x00000000000000000000000000000000000000a1"
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUpWithError() throws {
		try super.setUpWithError()
		let probe = "0x00000000000000000000000000000000000000f1"
		let writable = BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: probe)
		BeamioRecoveryBackupFlag.clear(eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018)")
		BeamioRecoveryBackupFlag.clear(eoa: account)
		savedStore = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		BeamioRecoveryBackupFlag.clear(eoa: account)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	/// Read success: an account with a phrase returns it to the native view.
	func testReadSucceedsWithThePhrase() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		BeamioNativeWallet.keyStore = items
		guard case .mnemonic(let got) = BeamioBackupDisplay.readMnemonicForBackupDisplay(eoa: account.uppercased(), purpose: "backup_display") else {
			return XCTFail("expected the phrase")
		}
		XCTAssertEqual(String(decoding: got, as: UTF8.self), phrase)
	}

	/// Read failure: an unreadable phrase is unavailable, and the flag is not set.
	func testReadFailureIsUnavailableAndSetsNoFlag() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		items.failRead = [.mnemonic]
		BeamioNativeWallet.keyStore = items
		guard case .unavailable = BeamioBackupDisplay.readMnemonicForBackupDisplay(eoa: account, purpose: "backup_display") else {
			return XCTFail("an unreadable phrase must be unavailable")
		}
		XCTAssertFalse(BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: account))
	}

	/// Private-key-only account (no phrase): fails closed, no key is returned.
	func testPrivateKeyOnlyAccountFailsClosed() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.key, eoa: account, value: Data(repeating: 7, count: 32))
		BeamioNativeWallet.keyStore = items
		guard case .unavailable = BeamioBackupDisplay.readMnemonicForBackupDisplay(eoa: account, purpose: "backup_display") else {
			return XCTFail("a private-key-only account must not show a key")
		}
	}

	/// A read with any other purpose is refused.
	func testWrongPurposeIsRefused() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		BeamioNativeWallet.keyStore = items
		guard case .unavailable = BeamioBackupDisplay.readMnemonicForBackupDisplay(eoa: account, purpose: "export") else {
			return XCTFail("only backup_display may read the phrase")
		}
	}

	/// Confirm sets the flag, per account.
	func testConfirmSetsTheFlagForTheAccount() {
		XCTAssertFalse(BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: account))
		XCTAssertTrue(BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: account))
		XCTAssertTrue(BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: account))
		XCTAssertFalse(BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: "0x00000000000000000000000000000000000000a2"))
	}

	/// Skip or close without confirming: nothing calls confirm, so the flag stays unset after a read.
	func testSkipLeavesTheFlagUnset() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		BeamioNativeWallet.keyStore = items
		_ = BeamioBackupDisplay.readMnemonicForBackupDisplay(eoa: account, purpose: "backup_display")
		XCTAssertFalse(BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: account))
	}
}
