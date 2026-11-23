import CryptoKit
import XCTest
@testable import ConetChatSDK

/// (identity clear keeps every stored account; `identity_cleared` marker): after a clear, the kept walletKey, mnemonic items and mnemonic sets are not
/// adopted again (list, snapshot judgement, silent selection, existing-key account) and no pointer is written; the user's explicit restore, import, creation or sync of an
/// account ends the ignore of that account only; nothing is deleted at any step; an unreadable marker is unknown. Synthetic phrases, the keychain test memory only.
final class IdentityClearedTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var raw: BeamioChatWalletKeychainStore!
	private var savedMemory: [String: Data]?
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		savedMemory = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		raw = BeamioChatWalletKeychainStore(service: "identity-cleared-test")
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = composite()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		BeamioChatWalletTestMemory.items = savedMemory
		super.tearDown()
	}

	private func eoa(_ phrase: String) -> String { BeamioPwaWalletSync.derivedAccount(phrase: phrase)!.eoa }

	private func composite() -> BeamioPasscodeWalletStore {
		BeamioPasscodeWalletStore(records: ShellPasscodeCoreTests.MemRecords(), hardware: ShellPasscodeCoreTests.MemHardware(), legacy: raw, session: BeamioPasscodeSession())
	}

	private func digestOfEverything() -> String {
		let items = BeamioChatWalletTestMemory.items ?? [:]
		var hash = SHA256()
		for key in items.keys.sorted() where key != "\u{1}x" {
			// the marker is the one item a clear may add; everything else must stay byte for byte
			if key.hasSuffix(BeamioIdentityCleared.itemName) { continue }
			hash.update(data: Data(key.utf8)); hash.update(data: items[key] ?? Data())
		}
		return hash.finalize().map { String(format: "%02x", $0) }.joined()
	}

	/// the end of a clear as clearSteps runs it: the marker of the accounts on the device and the owner, then the pointer goes
	private func clearIdentity(owner: String) {
		XCTAssertTrue(BeamioIdentityCleared.record(accounts: BeamioIdentityCleared.accountsOnDevice(store: BeamioNativeWallet.keyStore, owners: [owner]), store: BeamioNativeWallet.keyStore))
		BeamioNativeAccountPointer.clear()
	}

	func testAfterAClearTheKeptAccountsAreNotAdoptedAndNoPointerIsWritten() throws {
		let a = eoa(phraseA)
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z"), .updated)
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		XCTAssertTrue(raw.write(eoa: a, key: Data(key)))   // the published walletKey of the same account
		BeamioNativeAccountPointer.set(a)
		XCTAssertEqual(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).valid.map(\.eoa), [a])
		let before = digestOfEverything()
		clearIdentity(owner: a)
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty, "the start after the clear: the pointer is empty")
		let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
		XCTAssertTrue(inventory.accounts.isEmpty, "the kept account is not listed")
		XCTAssertEqual(BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore), .none, "no silent selection")
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty, "no pointer is written")
		XCTAssertNil(BeamioNativeRecovery.existingKeyAccount(store: BeamioNativeWallet.keyStore), "the existing key is not adopted")
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.account ?? nil, nil, "the snapshot names no current account")
		XCTAssertEqual(digestOfEverything(), before, "nothing is deleted or changed: the walletKey, the mnemonic set and the pointer item stay byte for byte")
		XCTAssertNotNil(raw.read(eoa: a), "the walletKey still reads")
		XCTAssertEqual(BeamioMnemonicSets.current(store: raw), .ok(eoa: a, phrase: phraseA), "the set still reads")
	}

	func testExplicitReImportEndsTheIgnoreOfThatAccountOnly() throws {
		let a = eoa(phraseA), b = eoa(phraseB)
		_ = BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z")
		_ = BeamioMnemonicSets.save(phrase: phraseB, store: raw, utc: "2026-11-22T00:00:01Z")
		clearIdentity(owner: a)
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).accounts.isEmpty)
		// the user imports account A again (the page's explicit import: the same account that is kept)
		guard case .key(var keyA) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		_ = BeamioNativeKeyImport.storeDerivedKey(&keyA, expectedEoa: a, store: BeamioNativeWallet.keyStore, mnemonic: [UInt8](phraseA.utf8))
		let listed = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).valid.map(\.eoa)
		XCTAssertEqual(listed, [a], "account A is back; account B stays ignored")
		XCTAssertFalse(listed.contains(b))
		guard case .ok(let ignored) = BeamioIdentityCleared.read(store: BeamioNativeWallet.keyStore) else { return XCTFail() }
		XCTAssertEqual(ignored, [b])
		// a phrase sync of B through the trusted bridge lifts B too
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: phraseB, store: raw, utc: "2026-11-22T00:00:02Z"), .idempotent)
		XCTAssertEqual(Set(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).valid.map(\.eoa)), [a, b])
	}

	func testAnUnreadableMarkerIsUnknownNeverNothingIgnored() {
		_ = BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z")
		let marker = Data("not json".utf8)
		XCTAssertTrue(raw.rawWrite(account: BeamioIdentityCleared.itemName, bytes: marker))
		XCTAssertFalse(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).enumerated, "an unreadable marker: the list is not enumerated (fail closed)")
		XCTAssertEqual(BeamioIdentityCleared.read(store: BeamioNativeWallet.keyStore), .unreadable)
	}

	func testTheRedoOfAnInterruptedClearIsNotBlockedByKeptItems() {
		let before = BeamioPgpMigrationImport.walletItemsToClearMayExist()
		_ = BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z")
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		XCTAssertTrue(raw.write(eoa: eoa(phraseA), key: Data(key)))
		XCTAssertEqual(BeamioPgpMigrationImport.walletItemsToClearMayExist(), before, "kept walletKey, mnemonic and set items do not count")
	}

	func testClearWalletItemsNeverDeletesTheWalletKey() throws {
		let a = eoa(phraseA)
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		XCTAssertTrue(raw.write(eoa: a, key: Data(key)))
		let before = raw.read(eoa: a)
		_ = raw.clearWalletItems(eoa: a)
		XCTAssertEqual(raw.read(eoa: a), before, "the published walletKey stays byte for byte")
	}

	// MARK: - MS-R1: a read fault deletes and writes nothing

	func testMSR1AReadFaultOnTheCurrentPointerWritesNothingInASave() {
		// a healthy store with set A as current; then the read of the current pointer fails and a save of phrase B is attempted
		let store = MemoryNativeKeyStore()
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: phraseA, store: store, utc: "2026-11-22T00:00:00Z"), .updated)
		let rawBefore = store.rawAccounts
		let keysBefore = store.keys
		store.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		guard case .failed = BeamioMnemonicSets.save(phrase: phraseB, store: store, utc: "x") else { return XCTFail("a read fault is reported, never success") }
		XCTAssertEqual(store.rawAccounts, rawBefore, "MS-R1: before and after are byte for byte the same: nothing is written, nothing is deleted")
		XCTAssertEqual(store.keys, keysBefore)
	}

	// MARK: -: a clear is the user's reset of the shell identity; the page re-provisions

	/// After the clear and before the page provisions: nothing is adopted. A successful pwaWalletSync commit (here: the page sends another account's phrase, and later the
	/// same account's phrase) ends the ignore of that account; the other kept account stays ignored; the legacy walletKey is never adopted as the current identity.
	func testTheFlowClearThenProvisionSameOrAnotherAccount() throws {
		let a = eoa(phraseA), b = eoa(phraseB)
		_ = BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:00Z")
		guard case .key(let keyB) = BeamioMnemonicDerivation.derive(phrase: phraseB) else { return XCTFail() }
		XCTAssertTrue(raw.write(eoa: b, key: Data(keyB)))   // a published walletKey of account B only (no mnemonic)
		BeamioNativeAccountPointer.set(a)
		clearIdentity(owner: a)
		// before the page provisions
		XCTAssertEqual(BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore), .none)
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty)
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).accounts.isEmpty)
		// a failed commit does not end the ignore
		let failing = MemoryNativeKeyStore()
		_ = BeamioIdentityCleared.record(accounts: [b], store: failing)
		failing.failWriteAccounts.insert(BeamioMnemonicSets.setName(b))
		guard case .failed = BeamioMnemonicSets.save(phrase: phraseB, store: failing, utc: "x") else { return XCTFail("the write fault is reported") }
		guard case .ok(let stillIgnored) = BeamioIdentityCleared.read(store: failing) else { return XCTFail() }
		XCTAssertEqual(stillIgnored, [b], "a failed commit leaves the account ignored")
		// the page provisions another account (B): B's ignore ends, A stays ignored
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: phraseB, store: raw, utc: "2026-11-22T00:00:03Z"), .updated)
		XCTAssertEqual(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).valid.map(\.eoa), [b], "B is a normal account; A is still ignored")
		// later the page provisions the same account (A) again
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: phraseA, store: raw, utc: "2026-11-22T00:00:04Z"), .updated, "the set exists; current moves back to it")
		XCTAssertEqual(Set(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).valid.map(\.eoa)), [a, b])
		guard case .ok(let ignored) = BeamioIdentityCleared.read(store: BeamioNativeWallet.keyStore) else { return XCTFail() }
		XCTAssertTrue(ignored.isEmpty, "the marker no longer ignores anything")
	}

	func testALegacyWalletKeyIsNeverAdoptedAsTheCurrentIdentityByAClear() throws {
		let a = eoa(phraseA)
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phraseA) else { return XCTFail() }
		XCTAssertTrue(raw.write(eoa: a, key: Data(key)))
		BeamioNativeAccountPointer.set(a)
		clearIdentity(owner: a)
		XCTAssertEqual(BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore), .none)
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty)
		XCTAssertNil(BeamioNativeRecovery.existingKeyAccount(store: BeamioNativeWallet.keyStore))
		XCTAssertNotNil(raw.read(eoa: a), "the walletKey is kept")
	}
}
