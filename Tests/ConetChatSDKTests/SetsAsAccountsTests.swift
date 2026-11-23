import XCTest
@testable import ConetChatSDK

/// Item (a): a no-passcode set (`mnemonic.set.<eoa>`) is an account of the device. The inventory lists it, the account judgement reads it, the key store
/// derives its key in memory (never stored) and only for the owner's own address; a published `walletKey` is still preferred and untouched.
/// Synthetic phrases only, in the keychain test memory (no real keychain).
final class SetsAsAccountsTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var raw: BeamioChatWalletKeychainStore!
	private var savedMemory: [String: Data]?

	override func setUp() {
		super.setUp()
		savedMemory = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		raw = BeamioChatWalletKeychainStore(service: "sets-as-accounts-test")
	}

	override func tearDown() {
		BeamioChatWalletTestMemory.items = savedMemory
		super.tearDown()
	}

	private func eoa(_ phrase: String) -> String { BeamioPwaWalletSync.derivedAccount(phrase: phrase)!.eoa }

	private func composite() -> BeamioPasscodeWalletStore {
		BeamioPasscodeWalletStore(records: ShellPasscodeCoreTests.MemRecords(), hardware: ShellPasscodeCoreTests.MemHardware(), legacy: raw, session: BeamioPasscodeSession())
	}

	func testASetIsListedAsAValidAccountAndItsKeyIsDerivedInMemory() throws {
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z"), .updated)
		let store = composite()
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		XCTAssertTrue(inventory.enumerated)
		XCTAssertEqual(inventory.valid.map(\.eoa), [eoa(phraseA)], "the set is a valid account")
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa(phraseA)), .valid)
		XCTAssertEqual(store.keyRecordState(eoa: eoa(phraseA)), .present)
		let key = try XCTUnwrap(store.read(eoa: eoa(phraseA)), "the key comes from the set")
		XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: [UInt8](key))?.lowercased(), eoa(phraseA))
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		defer { BeamioNativeWallet.keyStore = savedStore }
		let signed = BeamioNativeWallet.withAccountKeyUnchecked(eoa: eoa(phraseA)) { BeamioNativeEthSigner.signEip191(privateKey: $0, message: "m") }
		if case .failure = signed { XCTFail("the account key signs from a set") }
	}

	func testNothingIsWrittenAndNoKeyRecordAppears() {
		_ = BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z")
		let before = BeamioChatWalletTestMemory.items
		let store = composite()
		_ = BeamioNativeMnemonicInventory.read(store: store)
		_ = store.read(eoa: eoa(phraseA))
		_ = store.keyRecordState(eoa: eoa(phraseA))
		XCTAssertEqual(BeamioChatWalletTestMemory.items, before, "reads write nothing; the key is never stored")
	}

	func testTwoSetsAreTwoAccountsAndACipherVersionIsNotAnAccount() throws {
		_ = BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z")
		_ = BeamioMnemonicSets.save(phrase: phraseB, store: raw, utc: "2026-11-22T00:00:01Z")
		// a cipher version item of the same naming family must not be listed
		XCTAssertTrue(raw.rawWrite(account: BeamioMnemonicSets.setName(eoa(phraseA)) + ".c.0123456789abcdef", bytes: Data("{}".utf8)))
		let inventory = BeamioNativeMnemonicInventory.read(store: composite())
		XCTAssertEqual(Set(inventory.valid.map(\.eoa)), [eoa(phraseA), eoa(phraseB)])
		XCTAssertEqual(inventory.accounts.count, 2)
	}

	func testADamagedSetIsNeverAValidAccountAndGivesNoKey() {
		let owner = eoa(phraseA)
		XCTAssertTrue(raw.rawWrite(account: BeamioMnemonicSets.setName(owner), bytes: Data("{\"v\":1}".utf8)))
		let store = composite()
		XCTAssertNotEqual(store.mnemonicAccountState(owner: owner), .valid)
		XCTAssertNil(store.read(eoa: owner), "no key from a damaged set")
		XCTAssertEqual(store.keyRecordState(eoa: owner), .unreadable, "damaged is unknown, never absent")
	}

	func testASetWhosePhraseDerivesAnotherAddressGivesNoKey() throws {
		// the record is filed under A's address but holds B's phrase
		let owner = eoa(phraseA)
		let record: [String: Any] = ["v": 1, "mode": "keychain", "eoa": owner, "phrase": phraseB, "utc": "x"]
		XCTAssertTrue(raw.rawWrite(account: BeamioMnemonicSets.setName(owner), bytes: try JSONSerialization.data(withJSONObject: record)))
		let store = composite()
		XCTAssertNil(store.read(eoa: owner))
		XCTAssertEqual(store.mnemonicAccountState(owner: owner), .invalid)
	}

	func testAnAbsentSetStaysAbsent() {
		let store = composite()
		XCTAssertEqual(store.keyRecordState(eoa: eoa(phraseA)), .absent)
		XCTAssertNil(store.read(eoa: eoa(phraseA)))
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa(phraseA)), .absent)
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: store).accounts.isEmpty)
	}

	// MARK: - native create and import with a mnemonic

	private func importPhrase(_ phrase: String, store: BeamioPasscodeWalletStore, expected: String = "", setPointer: Bool = true) -> BeamioNativeKeyImport.Outcome {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { XCTFail("synthetic phrase"); return .invalidKey }
		return BeamioNativeKeyImport.storeDerivedKey(&key, expectedEoa: expected, store: store, mnemonic: [UInt8](phrase.utf8), setPointer: setPointer)
	}

	func testNativeImportWithAMnemonicStoresASetAndTheAccountIsUsable() throws {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		let store = composite()
		XCTAssertEqual(importPhrase(phraseA, store: store), .imported)
		XCTAssertEqual(BeamioNativeMnemonicInventory.read(store: store).valid.map(\.eoa), [eoa(phraseA)])
		XCTAssertEqual(BeamioMnemonicSets.current(store: raw), .ok(eoa: eoa(phraseA), phrase: phraseA), "current points at the new set")
		XCTAssertNotNil(store.read(eoa: eoa(phraseA)), "the key is derived from the set")
		XCTAssertEqual(importPhrase(phraseA, store: store), .alreadyPresent, "the same account again is already_exists")
		// no key, intent or commit record is left behind
		for kind in [BeamioChatWalletItemKind.key, .intent, .commit] { XCTAssertEqual(raw.itemState(kind, eoa: eoa(phraseA)), .absent, "\(kind)") }
	}

	func testNativeImportRefusesAnExpectedAddressThatIsNotTheMnemonics() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		let store = composite()
		XCTAssertEqual(importPhrase(phraseA, store: store, expected: eoa(phraseB)), .addressMismatch)
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: store).accounts.isEmpty, "nothing is written")
	}

	func testAPrivateKeyWithoutAMnemonicIsStillNotWritten() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		let store = composite()
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		let outcome = BeamioNativeKeyImport.storeDerivedKey(&key, expectedEoa: "", store: store)
		XCTAssertNotEqual(outcome, .imported, "a key-only import is not an account and stays unwritable")
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: store).accounts.isEmpty)
	}

	func testAPublishedWalletKeyOnlyUserStillReadsItsKeyAndIsNotAnAccountOfTheInventory() throws {
		// the published build left only a walletKey record (synthetic): the key is read as before; the inventory (mnemonic items only) does not list it
		let owner = eoa(phraseA)
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		XCTAssertTrue(raw.write(eoa: owner, key: Data(key)))
		let store = composite()
		XCTAssertEqual(store.read(eoa: owner), Data(key))
		XCTAssertEqual(store.keyRecordState(eoa: owner), .present)
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: store).accounts.isEmpty, "key-only is not an account (confirmed_missing for the preread)")
		let before = BeamioChatWalletTestMemory.items
		_ = BeamioMnemonicSets.current(store: raw)
		XCTAssertEqual(BeamioChatWalletTestMemory.items, before, "reads change nothing")
	}
}
