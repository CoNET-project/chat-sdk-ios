#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// 25.52Y.96 第 1 条 (a) to (e): the production passcode store keeps the phrase as `mnemonic:<lower-case eoa>` in the chat-wallet service, beside
/// the key record. A locked account's phrase is neither read nor returned. A rollback removes the key record only. Synthetic phrase and key only.
/// The records, the hardware key and the chat-wallet items are test doubles or the test memory (never the Keychain).
final class PasscodeStoreMnemonicTests: XCTestCase {
	private let service = "com.beamio.beamio.chat-wallet"
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var key = Data()
	private var eoa = ""
	private var records: BeamioPasscodeRecordStoring = BeamioPasscodeKeychainRecords.standard
	private var hardware = TestPasscodeHardware()
	private var session = BeamioPasscodeSession()
	private var store: BeamioPasscodeWalletStore!
	private var savedMemory: [String: Data]?
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		// This class tests the withdrawn device and passcode record formats (never published). The production `write` and `delete` of the store are off
		//; the test seam turns the old behaviour on here only, so that the formats stay covered.
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = true
		savedMemory = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		NativeAccountPointerIsolation.begin()
		AdmittedCreationDevice.install()
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else {
			XCTFail("the test phrase must derive a key")
			return
		}
		key = Data(derived)
		eoa = BeamioNativeEthSigner.address(privateKey: [UInt8](key))?.lowercased() ?? ""
		hardware = TestPasscodeHardware()
		session = BeamioPasscodeSession()
		session.vault = BeamioPasscodeVault(records: records, hardware: hardware)
		store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: BeamioChatWalletKeychainStore.standard, session: session)
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
	}

	override func tearDown() {
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = false
		BeamioConetChatModule.closeAccountCreatePage()
		// A closed page sends its answer on the main queue: deliver it here, not to the next test.
		let drainUntil = Date().addingTimeInterval(0.3)
		while Date() < drainUntil { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioAccountBindingLookup.override = nil
		BeamioNativeAccountCreate.onCreateRequired = nil
		BeamioNativeWallet.keyStore = savedStore
		AdmittedCreationDevice.remove()
		NativeAccountPointerIsolation.end()
		BeamioChatWalletTestMemory.items = savedMemory
		super.tearDown()
	}

	/// Opens the creation page through the bridge at G0 (the zero account, no binding), as the page does.
	private func openCreatePage() {
		BeamioAccountBindingLookup.override = { _ in .noBinding }
		BeamioNativeAccountCreate.onCreateRequired = { true }
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatModule.handleCommand(["type": "nativeAccountCreateOpen", "reqId": 9100, "account": "0x0000000000000000000000000000000000000000"], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while !BeamioConetChatModule.accountCreatePageOpen() && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
	}

	/// The import path (creation and import share it): key, phrase and commit, through the production store.
	private func importAccount() {
		var keyBytes = [UInt8](key)
		let outcome = BeamioNativeKeyImport.storeDerivedKey(&keyBytes, expectedEoa: eoa, store: store, mnemonic: Array(phrase.utf8))
		if case .imported = outcome {} else { XCTFail("the import of the production store is imported, got \(outcome)") }
	}

	func testTheImportKeepsThePhraseAsTheMnemonicItemBesideTheKey() {
		importAccount()
		// an import with a mnemonic is a no-passcode set; no key record, no intent and no commit item; the key is derived in memory
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .present, "the key is available from the set")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: eoa), .present, "the mnemonic of the account exists (the set)")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8), "the phrase reads back")
		XCTAssertNotNil(BeamioChatWalletTestMemory.get(service, BeamioMnemonicSets.setName(eoa)), "the set is in the chat-wallet service")
		XCTAssertNil(BeamioChatWalletTestMemory.get(service, "mnemonic:" + eoa), "no mnemonic:<eoa> item of the withdrawn layout is written")
		XCTAssertNil(BeamioChatWalletTestMemory.get(service, "intent:" + eoa), "no intent")
		XCTAssertNil(BeamioChatWalletTestMemory.get(service, "commit:" + eoa), "no commit item")
		XCTAssertEqual(records.readRecordState(eoa: eoa), .absent, "no key record in the passcode records")
	}

	func testALockedAccountNeitherReadsNorReturnsItsPhrase() {
		importAccount()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		let encoded = (try? JSONEncoder().encode(passcodeRecord)) ?? Data()
		XCTAssertTrue(records.writeRecord(eoa: eoa, encoded), "the passcode record is written")
		XCTAssertTrue(session.isLocked(eoa: eoa), "the account is locked: a passcode is set and no bundle is unlocked")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: eoa), .unreadable, "a locked phrase is unknown, not absent")
		XCTAssertNil(store.readItem(.mnemonic, eoa: eoa), "a locked phrase is not returned")
		XCTAssertFalse(store.writeItem(.mnemonic, eoa: eoa, value: Data(phrase.utf8)), "a locked phrase is not written")
		session.install(eoa: eoa, bundle: [UInt8](key))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8), "unlocked, the phrase reads back")
	}

	func testTheBackupDisplayReadsThePhraseFromTheProductionShapedStore() {
		importAccount()
		let shown = BeamioBackupDisplay.readMnemonicForBackupDisplay(eoa: eoa, purpose: BeamioBackupDisplay.purpose)
		if case .mnemonic(let text) = shown {
			XCTAssertEqual(text, Data(phrase.utf8), "the backup display shows the phrase")
		} else {
			XCTFail("the backup display is available on the production store, got \(shown)")
		}
		XCTAssertFalse(BeamioBackupDisplay.isKeyOnlyAccount(eoa: eoa), "an account with a phrase is not key-only")
	}

	/// (a) The creation path (12 words generated from 16 bytes, then the same write as the import) keeps the phrase in the production layout.
	func testTheCreationPathSavesThePhraseOfTheNewAccount() {
		let entropy: [UInt8] = Array(repeating: 0x42, count: 16)
		guard let words = BeamioNativeAccountCreate.phrase(entropy: entropy) else {
			XCTFail("16 bytes give a phrase")
			return
		}
		openCreatePage()
		XCTAssertTrue(BeamioConetChatModule.accountCreatePageOpen(), "the creation page is open at G0")
		let outcome = BeamioNativeAccountCreate.createAccount(store: store, entropy: entropy)
		guard case .ok(let created) = outcome else {
			XCTFail("the creation is ok, got \(outcome)")
			return
		}
		XCTAssertEqual(store.itemState(.key, eoa: created), .present, "the key is available (derived from the set)")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: created), .present, "the set is written by the creation")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: created), Data(words.utf8), "the phrase of the creation reads back")
		XCTAssertNotNil(BeamioChatWalletTestMemory.get(service, BeamioMnemonicSets.setName(created)), "the set is in the chat-wallet service")
		// The saved phrase derives the account address: the phrase is the account's own.
		if let saved = store.readItem(.mnemonic, eoa: created),
		   case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: String(decoding: saved, as: UTF8.self)) {
			XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: derived)?.lowercased(), created, "the saved phrase derives the account address")
		} else {
			XCTFail("the saved phrase derives a key")
		}
	}

	/// (b) walletCredentialOutcome answers the phrase of the record account when the account is unlocked.
	func testWalletCredentialOutcomeReturnsThePhraseOfTheRecordAccountWhenUnlocked() {
		importAccount()
		BeamioNativeAccountPointer.set(eoa)
		let out = BeamioConetChatModule.walletCredentialOutcome()
		XCTAssertTrue(out.ok, "the outcome is ok, error \(String(describing: out.error))")
		XCTAssertEqual(out.result?["mnemonic"] as? String, phrase, "the phrase is returned")
		XCTAssertEqual(out.result?["credentialKind"] as? String, "mnemonic")
		XCTAssertEqual(out.result?["eoa"] as? String, eoa)
	}

	/// (b) walletCredentialOutcome while the passcode is locked: unavailable, and no phrase is returned.
	func testWalletCredentialOutcomeIsUnavailableWhileLockedAndReturnsNoPhrase() {
		importAccount()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		XCTAssertTrue(records.writeRecord(eoa: eoa, (try? JSONEncoder().encode(passcodeRecord)) ?? Data()))
		BeamioNativeAccountPointer.set(eoa)
		let out = BeamioConetChatModule.walletCredentialOutcome()
		XCTAssertFalse(out.ok)
		XCTAssertNil(out.result, "no phrase is returned while locked")
		XCTAssertEqual(out.error, "unavailable")
	}

	func testARollbackOfTheKeyRemovesTheRecordOnlyAndKeepsTheHardwareKey() {
		// the withdrawn device-record format, covered through its test seam (never compiled into a release)
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = true
		defer { BeamioPasscodeWalletStore.deviceRecordWritesForTests = false }
		XCTAssertTrue(store.write(eoa: eoa, key: key))
		XCTAssertTrue(store.deleteItem(.key, eoa: eoa), "the key record is removed")
		XCTAssertEqual(store.itemState(.key, eoa: eoa), .absent)
		XCTAssertTrue(hardware.hasKey(eoa: eoa), "the hardware key is kept (25.52Y.80 第 3 项 (a))")
	}
}

/// An in-memory hardware key for the tests only. The wrap is a reversal, so no real key protection is claimed.
final class TestPasscodeHardware: BeamioPasscodeHardwareKeyStoring {
	var isSecureEnclave: Bool { false }
	var keys: Set<String> = []
	func hasKey(eoa: String) -> Bool { keys.contains(eoa.lowercased()) }
	func createKey(eoa: String) -> Bool { keys.insert(eoa.lowercased()); return true }
	func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { Data(plain.reversed()) }
	func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { Data(blob.reversed()) }
	func deleteKey(eoa: String) { keys.remove(eoa.lowercased()) }
}
#endif
