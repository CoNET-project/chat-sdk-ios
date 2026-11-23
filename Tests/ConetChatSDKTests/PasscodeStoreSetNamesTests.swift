#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The product key store (`BeamioPasscodeWalletStore`) as the PWA wallet sync writes through it: the mnemonic set items `mnemonic.set.<eoa>`,
/// their cipher versions `mnemonic.set.<eoa>.c.<digest>` and the device pointer `mnemonic.current` belong to their owner, like the older item names.
/// Names that only look like them stay refused, a locked owner is refused, and the sets are never deleted through this store.
final class PasscodeStoreSetNamesTests: XCTestCase {
	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	/// A synthetic hardware layer for the test only: wrap and unwrap are the identity. It is not a security control.
	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeAccountPointer.clear()
		savedStore = BeamioNativeWallet.keyStore
		BeamioChatWalletTestMemory.items = [:]
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
		BeamioNativeKeySnapshot.invalidate()
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioChatWalletTestMemory.items = [:]
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private var store: BeamioPasscodeWalletStore { BeamioPasscodeWalletStore.standard }

	private func syncState(_ answer: [String: Any]) -> String? { (answer["result"] as? [String: Any])?["sync"] as? String }

	/// The signature of `message` by the account, checked against its address.
	private func assertSignsAs(_ account: (eoa: String, key: Data), _ label: String) {
		BeamioConetChatModule.setNativeGateForTests(account: account.eoa, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2, "\(label): the session is G2")
		switch BeamioNativeWallet.signEip191(eoa: account.eoa, message: "set names") {
		case .success(let signature):
			XCTAssertEqual(BeamioNativeEthSigner.recoverEip191AddressForTests(message: "set names", signature: signature), account.eoa.lowercased(), "\(label): the signature recovers the account")
		case .failure(let failure):
			XCTFail("\(label): the signature failed \(failure)")
		}
	}

	// MARK: - The sync writes through the product store

	/// New: the first phrase of the device, and the key it signs with.
	func testPwaWalletSyncWritesThroughTheProductStoreAndTheAccountSigns() {
		let a = ValidTestAccounts.accountA
		let first = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 910_001, seq: 1, eoa: a.eoa, phrase: ValidTestAccounts.phraseA)
		XCTAssertEqual(syncState(first), "updated", "the set is written and read back through the product store")
		XCTAssertEqual(store.read(eoa: a.eoa), a.key, "the key is derived from the set")
		XCTAssertEqual(syncState(BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 910_002, seq: 2, eoa: a.eoa, phrase: ValidTestAccounts.phraseA)), "idempotent")
		assertSignsAs(a, "new")
	}

	/// Overwrite upgrade: a different phrase moves `mnemonic.current` to the new set, and the new account signs.
	func testAnOverwriteUpgradeThroughTheProductStoreMovesTheAccount() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		XCTAssertEqual(syncState(BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 910_011, seq: 1, eoa: a.eoa, phrase: ValidTestAccounts.phraseA)), "updated")
		XCTAssertEqual(syncState(BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 910_012, seq: 2, eoa: b.eoa, phrase: ValidTestAccounts.phraseB)), "updated", "the second account is written")
		XCTAssertEqual(store.read(eoa: b.eoa), b.key)
		XCTAssertEqual(store.read(eoa: a.eoa), a.key, "the old set stays: nothing is deleted")
		assertSignsAs(b, "overwrite")
	}

	/// Restore: the explicit import writes the set through the product store; the key reads back and signs.
	func testARestoreThroughTheProductStoreWritesTheSetAndTheAccountSigns() {
		let a = ValidTestAccounts.accountA
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: ValidTestAccounts.phraseA, expectedEoa: "", store: store), .imported)
		XCTAssertEqual(store.read(eoa: a.eoa), a.key)
		BeamioNativeKeySnapshot.invalidate()
		assertSignsAs(a, "restore")
	}

	// MARK: - The names

	func testTheSetNamesAndTheCipherNamesAreWrittenAndReadThroughTheProductStore() {
		let a = ValidTestAccounts.accountA
		let digest = "0123456789abcdef"
		for name in [BeamioMnemonicSets.setName(a.eoa), BeamioMnemonicSets.setName(a.eoa) + ".c." + digest] {
			XCTAssertTrue(store.rawWrite(account: name, bytes: Data("x".utf8)), "\(name) is written")
			XCTAssertEqual(store.rawRead(account: name), .present(Data("x".utf8)), "\(name) reads back")
		}
		let pointer = try! JSONSerialization.data(withJSONObject: ["v": 1, "eoa": a.eoa], options: [.sortedKeys])
		XCTAssertTrue(store.rawWrite(account: BeamioMnemonicSets.currentName, bytes: pointer), "the device pointer names its owner and is written")
		XCTAssertEqual(store.rawRead(account: BeamioMnemonicSets.currentName), .present(pointer))
	}

	/// Names that only look like a set item have no owner and stay refused, and so does a pointer that names none.
	func testNamesOutsideTheSetFormatAreStillRefused() {
		let eoa = ValidTestAccounts.accountA.eoa
		let prefix = BeamioMnemonicSets.setPrefix
		let outside = [
			prefix, prefix + ".c.0123456789abcdef", prefix + eoa + ".x", prefix + eoa + ".c.", prefix + eoa + ".c.zz", prefix + eoa + ".c.0123.45",
			prefix + eoa + ".c", "mnemonic.setx" + eoa, "mnemonic." + eoa, "mnemonics:" + eoa, "other.set." + eoa, "walletkey" + eoa, "",
		]
		for name in outside {
			XCTAssertFalse(store.rawWrite(account: name, bytes: Data("x".utf8)), "'\(name)' is refused")
		}
		XCTAssertFalse(store.rawWrite(account: BeamioMnemonicSets.currentName, bytes: Data("{}".utf8)), "a pointer that names no owner is refused")
		XCTAssertFalse(store.rawWrite(account: BeamioMnemonicSets.currentName, bytes: Data()), "an empty pointer is refused")
		XCTAssertFalse(store.rawWrite(account: BeamioMnemonicSets.setName(eoa), bytes: Data()), "an empty set is refused")
	}

	/// The sets are never deleted through the product store: the delete path stays disabled.
	func testTheSetsAreNotDeletedThroughTheProductStore() {
		let a = ValidTestAccounts.accountA
		let names = [BeamioMnemonicSets.setName(a.eoa), BeamioMnemonicSets.setName(a.eoa) + ".c.0123456789abcdef"]
		for name in names { XCTAssertTrue(store.rawWrite(account: name, bytes: Data("x".utf8))) }
		let pointer = try! JSONSerialization.data(withJSONObject: ["v": 1, "eoa": a.eoa], options: [.sortedKeys])
		XCTAssertTrue(store.rawWrite(account: BeamioMnemonicSets.currentName, bytes: pointer))
		for name in names + [BeamioMnemonicSets.currentName] {
			XCTAssertFalse(store.rawDelete(account: name), "\(name) is not deleted")
			XCTAssertNotEqual(store.rawRead(account: name), .absent, "\(name) is still there")
		}
	}

	/// The older names keep their rule: an owner-less or unknown name is refused, and the published items are written and deleted as before.
	func testTheOlderNamesKeepTheirRule() {
		let a = ValidTestAccounts.accountA
		XCTAssertTrue(store.rawWrite(account: "mnemonic:" + a.eoa, bytes: Data("x".utf8)))
		XCTAssertTrue(store.rawDelete(account: "mnemonic:" + a.eoa), "the withdrawn-format item is still deletable by its owner rule")
		XCTAssertFalse(store.rawWrite(account: "unknown:" + a.eoa, bytes: Data("x".utf8)))
	}

	// MARK: - A locked owner

	/// A passcode account that is not unlocked: its set items are unreadable and unwritable, the cipher version does not give the private key,
	/// and nothing is derived. After unlock the same names work.
	func testALockedOwnerSetItemsAreRefusedAndNoKeyIsDerived() {
		let a = ValidTestAccounts.accountA
		let records = MemoryRecords()
		let vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		let session = BeamioPasscodeSession()
		session.vault = vault
		let locked = BeamioPasscodeWalletStore(records: records, hardware: IdentityHardware(), legacy: BeamioChatWalletKeychainStore.standard, session: session)
		// a set and its cipher version exist before the account is locked
		XCTAssertTrue(BeamioChatWalletKeychainStore.standard.rawWrite(account: BeamioMnemonicSets.setName(a.eoa), bytes: Data("{}".utf8)))
		let cipherName = BeamioMnemonicSets.setName(a.eoa) + ".c.0123456789abcdef"
		XCTAssertTrue(BeamioChatWalletKeychainStore.standard.rawWrite(account: cipherName, bytes: Data("{}".utf8)))
		records.data[a.eoa.lowercased()] = try! JSONEncoder().encode(BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 8)))
		XCTAssertEqual(session.appState(eoa: a.eoa), .locked, "a passcode record and no bundle: locked")
		for name in [BeamioMnemonicSets.setName(a.eoa), cipherName] {
			XCTAssertEqual(locked.rawRead(account: name), .unreadable, "\(name) is unreadable while locked")
			XCTAssertFalse(locked.rawWrite(account: name, bytes: Data("x".utf8)), "\(name) is not written while locked")
		}
		let pointer = try! JSONSerialization.data(withJSONObject: ["v": 1, "eoa": a.eoa], options: [.sortedKeys])
		XCTAssertFalse(locked.rawWrite(account: BeamioMnemonicSets.currentName, bytes: pointer), "the pointer of a locked owner is not written")
		XCTAssertNil(locked.read(eoa: a.eoa), "no key is derived for a locked account")
		// the native signature with this store: refused (a record that gives no key now is never "no key"), and the failure carries no key bytes
		let savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = locked
		defer { BeamioNativeWallet.keyStore = savedKeyStore }
		BeamioConetChatModule.setNativeGateForTests(account: a.eoa, sessionReady: true)
		switch BeamioNativeWallet.signEip191(eoa: a.eoa, message: "locked") {
		case .success(let signature): XCTFail("a locked account must not sign: \(signature)")
		case .failure(let failure):
			XCTAssertTrue([.locked, .storageUnreadable].contains(failure), "locked or unknown, never a missing key: \(failure)")
			XCTAssertFalse("\(failure)".contains(a.key.map { String(format: "%02x", $0) }.joined()), "the failure does not carry the key")
		}
		// unlocked (no passcode record): the same names work
		records.data[a.eoa.lowercased()] = nil
		XCTAssertEqual(session.appState(eoa: a.eoa), .noPasscode)
		XCTAssertTrue(locked.rawWrite(account: cipherName, bytes: Data("{}".utf8)))
	}
}
#endif
