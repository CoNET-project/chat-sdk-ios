import XCTest
@testable import ConetChatSDK

/// S-1 acceptance, native re-import group: fresh install; upgrade with a native key; upgrade without one
/// (locked, import requested, nothing read from the WebView); import success; import failure. The bridge retirement is a
/// separate group (ChatLocalWalletBoundaryTests, testRetiredWalletTransferTakesNoKeyFromTheBridge). Synthetic key 0x11…11
/// only; never a user key.
final class WalletUpgradeAcceptanceTests: XCTestCase {
	final class Store: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var writes = 0
		var failWrite = false
		var corruptReadBack = false
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			if failWrite { return false }
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? {
			guard let k = keys[eoa.lowercased()] else { return nil }
			return corruptReadBack ? Data(repeating: 0xEE, count: k.count) : k
		}
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	private let keyHex = String(repeating: "11", count: 32)
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// True only when the native wallet signs for the account.
	private func canSign() -> Bool {
		if case .success(let sig) = BeamioNativeWallet.signEip191(eoa: eoa, message: "acceptance") {
			return sig.hasPrefix("0x")
		}
		return false
	}

	// MARK: - Group: fresh install

	func testFreshInstallIsLockedAndAsksForTheNativeImport() {
		XCTAssertFalse(BeamioNativeWallet.hasKey(eoa: eoa))
		XCTAssertFalse(canSign(), "nothing is signed while locked")
		RemovedImportHostHooks.assertAbsent()
		XCTAssertEqual(store.writes, 0, "the app never creates a key by itself")
	}

	// MARK: - Group: upgrade

	func testUpgradeWithANativeKeyKeepsTheWalletAndWritesNothing() {
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		store.keys[eoa] = Data(repeating: 0x11, count: 32)
		let writes = store.writes
		XCTAssertTrue(BeamioNativeWallet.hasKey(eoa: eoa))
		XCTAssertTrue(canSign(), "the wallet works as before the upgrade")
		RemovedImportHostHooks.assertAbsent()
		XCTAssertEqual(store.writes, writes, "an upgrade with a native key writes nothing to the key store")
	}

	func testUpgradeWithoutANativeKeyStaysLockedAndAsksForTheImport() {
		// The WebView may still hold an old copy. The native side never reads it, so nothing is moved.
		XCTAssertFalse(BeamioNativeWallet.hasKey(eoa: eoa))
		XCTAssertFalse(canSign())
		RemovedImportHostHooks.assertAbsent()
		XCTAssertEqual(store.writes, 0, "nothing is written from the old copy")
		XCTAssertNil(store.keys[eoa])
	}

	// MARK: - Group: native import

	func testImportSuccessUnlocksTheWalletAndNoImportIsAskedAfterwards() {
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		let outcome = BeamioNativeKeyImport.importPrivateKey(text: "0x" + keyHex, expectedEoa: eoa, store: store)
		XCTAssertEqual(outcome, .imported)
		XCTAssertEqual(BeamioNativeKeyImport.userMessage(for: outcome), "已导入")
		XCTAssertTrue(BeamioNativeWallet.hasKey(eoa: eoa))
		XCTAssertTrue(canSign(), "signing works after the import")
		RemovedImportHostHooks.assertAbsent()
	}

	func testMalformedTextIsRefusedWithItsMessageAndStaysLocked() {
		let outcome = BeamioNativeKeyImport.importPrivateKey(text: "not-a-key", expectedEoa: eoa, store: store)
		XCTAssertEqual(outcome, .invalidFormat)
		XCTAssertEqual(BeamioNativeKeyImport.userMessage(for: outcome), "格式不正确")
		XCTAssertNil(store.keys[eoa])
		XCTAssertFalse(canSign())
	}

	func testAKeyForAnotherAccountIsRefusedWithItsMessageAndStaysLocked() {
		let outcome = BeamioNativeKeyImport.importPrivateKey(text: String(repeating: "22", count: 32),
		                                                     expectedEoa: eoa, store: store)
		XCTAssertEqual(outcome, .addressMismatch)
		XCTAssertEqual(BeamioNativeKeyImport.userMessage(for: outcome), "该密钥与当前账号不符")
		XCTAssertNil(store.keys[eoa])
		XCTAssertFalse(canSign())
	}

	func testAnExistingKeyIsNeverOverwrittenByAnImport() {
		store.keys[eoa] = Data(repeating: 0x11, count: 32)
		let outcome = BeamioNativeKeyImport.importPrivateKey(text: "0x" + keyHex, expectedEoa: eoa, store: store)
		XCTAssertEqual(outcome, .alreadyPresent)
		XCTAssertEqual(BeamioNativeKeyImport.userMessage(for: outcome), "该账号已有密钥，未做更改")
		XCTAssertEqual(store.keys[eoa], Data(repeating: 0x11, count: 32))
	}

	func testAWriteFailureIsShownAsASaveErrorAndStaysLocked() {
		store.failWrite = true
		let outcome = BeamioNativeKeyImport.importPrivateKey(text: "0x" + keyHex, expectedEoa: eoa, store: store)
		XCTAssertEqual(outcome, .writeFailed)
		XCTAssertEqual(BeamioNativeKeyImport.userMessage(for: outcome), "保存失败，请重试")
		XCTAssertNil(store.keys[eoa])
		XCTAssertFalse(canSign())
	}

	func testAFailedReadBackIsShownAsASaveErrorAndTheWriteIsDeleted() {
		store.corruptReadBack = true
		let outcome = BeamioNativeKeyImport.importPrivateKey(text: "0x" + keyHex, expectedEoa: eoa, store: store)
		XCTAssertEqual(outcome, .readBackFailed)
		XCTAssertEqual(BeamioNativeKeyImport.userMessage(for: outcome), "保存失败，请重试")
		XCTAssertNil(store.keys[eoa], "a failed read-back deletes the write")
		XCTAssertFalse(canSign())
	}
}
