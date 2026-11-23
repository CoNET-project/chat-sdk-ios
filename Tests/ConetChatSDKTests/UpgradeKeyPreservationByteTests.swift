#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// (U-A1, U-A2, U-A14, U-A15, U-A17) and (d),: the upgrade keeps every key byte for byte.
/// A record with no intent is never deleted, by the start-up reconciliation or by a rollback of another account. The old wallet file and
/// its address are unchanged. Synthetic data only. The production Keychain path is in `testProductionStoreKeepsALegacyKeyByteForByte`,
/// which skips in a SwiftPM test host (no keychain entitlement); it is listed in the receipt for the real-device run.
final class UpgradeKeyPreservationByteTests: XCTestCase {
	typealias MemStore = MnemonicIntentStorageTests.MemStore

	/// BIP-39 test vectors (12 words), the same as the intent tests. `legacyKey` is a 32-byte key that no phrase derives: a key-only account.
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private let legacyKey = [UInt8](repeating: 0x42, count: 32)

	private func derived(_ phrase: String) -> (eoa: String, key: [UInt8]) {
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let eoa = BeamioNativeEthSigner.address(privateKey: key)
		else { fatalError("the test vector does not derive") }
		return (eoa.lowercased(), key)
	}

	private func addressOf(_ key: [UInt8]) -> String? {
		BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
	}

	private func intentJSON(eoa: String, planned: Bool) -> Data {
		Data("{\"v\":1,\"eoa\":\"\(eoa)\",\"mnemonicPlanned\":\(planned),\"startedAt\":\"2026-11-15T06:00:00Z\",\"phase\":\"begun\"}".utf8)
	}

	/// The items of the accounts `owners`, taken from the whole store (the byte snapshot compared before and after).
	private func snapshot(_ store: MemStore, owners: [String]) -> [String: Data] {
		store.items.filter { entry in owners.contains { entry.key.hasSuffix(":" + $0) } }
	}

	override func setUp() {
		super.setUp()
		BeamioNativeKeyImport.clearIntentMarksForTests()
		BeamioNativeKeyImport.resetStartupForTests()
	}

	/// U-A1, U-A17: a key-only account from before the upgrade (no mnemonic, no intent, no commit) keeps its key bytes and its address through
	/// a start-up reconciliation that finds an uncommitted intent of another account, and through the retry of that account's rollback.
	func testALegacyKeyOnlyAccountKeepsItsBytesThroughAFailedRollbackAndItsRetry() {
		let store = MemStore()
		let legacy = (eoa: addressOf(legacyKey) ?? "", key: legacyKey)
		XCTAssertFalse(legacy.eoa.isEmpty)
		store.items["key:" + legacy.eoa] = Data(legacy.key)
		let other = derived(phraseB)
		store.items["key:" + other.eoa] = Data(other.key)
		store.items["intent:" + other.eoa] = intentJSON(eoa: other.eoa, planned: false)
		let before = snapshot(store, owners: [legacy.eoa])

		// The rollback of the other account cannot delete its key: the intent stays and the other account is marked ((e)).
		store.failDelete = [.key]
		let marked = BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertEqual(marked, [other.eoa])
		XCTAssertEqual(snapshot(store, owners: [legacy.eoa]), before, "the legacy key-only account is byte-identical after the failed rollback")
		XCTAssertEqual(addressOf(store.read(eoa: legacy.eoa).map { [UInt8]($0) } ?? []), legacy.eoa, "the legacy address is unchanged")
		XCTAssertFalse(BeamioNativeKeyImport.isIntentUnavailable(eoa: legacy.eoa), "the legacy account is not marked")

		// The retry after the deletion works again: only the other account's intent and key go; the legacy account is still byte-identical.
		store.failDelete = []
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertEqual(snapshot(store, owners: [legacy.eoa]), before, "the retry does not touch the legacy account")
		XCTAssertNil(store.items["intent:" + other.eoa], "the other account's intent is removed by the retry")
		XCTAssertNil(store.items["key:" + other.eoa], "the other account's key, which the intent registered, is removed by the retry")
	}

	/// U-A14, U-A17: an account with a mnemonic and a commit but no intent, and a corrupt account with a mnemonic but neither commit nor intent,
	/// are never deleted and their bytes do not change (第 4 項 (c), (d), (k)(4)).
	func testRecordsWithoutAnIntentAreNeverDeletedAndKeepTheirBytes() {
		let store = MemStore()
		let committed = derived(phraseA)
		store.items["key:" + committed.eoa] = Data(committed.key)
		store.items["mnemonic:" + committed.eoa] = Data(phraseA.utf8)
		store.items["commit:" + committed.eoa] = Data("{\"v\":1,\"eoa\":\"\(committed.eoa)\",\"committedAt\":\"2026-11-15T06:00:00Z\"}".utf8)
		let corrupt = derived(phraseB)
		store.items["key:" + corrupt.eoa] = Data(corrupt.key)
		// The corrupt mnemonic does not read as a valid phrase for its account (WK26 item 2: a valid mnemonic without a commit is Ready).
		store.items["mnemonic:" + corrupt.eoa] = Data("not a valid phrase for this account".utf8)
		let owners = [committed.eoa, corrupt.eoa]
		let before = snapshot(store, owners: owners)

		XCTAssertEqual(BeamioNativeKeyImport.reconcileIntents(store: store), [], "no intent, nothing marked")
		XCTAssertEqual(snapshot(store, owners: owners), before, "no byte of a record without an intent changes")
		XCTAssertTrue(BeamioNativeKeyImport.walletMarkersUnreadable(eoa: corrupt.eoa, store: store), "the corrupt mnemonic is not_ready, not deleted")
		XCTAssertFalse(BeamioNativeKeyImport.walletMarkersUnreadable(eoa: committed.eoa, store: store), "the committed account stays usable")
	}

	/// U-A17 for the whole store: with no intent at all, the reconciliation returns nothing and the store is byte-identical.
	func testAStoreWithNoIntentIsByteIdenticalAfterTheReconciliation() {
		let store = MemStore()
		let a = derived(phraseA)
		store.items["key:" + a.eoa] = Data(a.key)
		store.items["mnemonic:" + a.eoa] = Data(phraseA.utf8)
		store.items["commit:" + a.eoa] = Data("{\"v\":1,\"eoa\":\"\(a.eoa)\",\"committedAt\":\"2026-11-15T06:00:00Z\"}".utf8)
		let legacy = addressOf(legacyKey) ?? ""
		store.items["key:" + legacy] = Data(legacyKey)
		let before = store.items
		XCTAssertEqual(BeamioNativeKeyImport.reconcileIntents(store: store), [])
		XCTAssertEqual(store.items, before, "every item, the legacy key-only account included, is byte-identical")
		XCTAssertEqual(addressOf(legacyKey), legacy, "the legacy address is derived from the same bytes")
	}

	/// (e): an import of another account whose mnemonic write fails rolls back only what it registered. The legacy key-only account and
	/// the committed account are byte-identical afterwards.
	func testAFailedImportOfAnotherAccountLeavesTheExistingAccountsUntouched() {
		let store = MemStore()
		let legacy = addressOf(legacyKey) ?? ""
		store.items["key:" + legacy] = Data(legacyKey)
		let committed = derived(phraseA)
		store.items["key:" + committed.eoa] = Data(committed.key)
		store.items["mnemonic:" + committed.eoa] = Data(phraseA.utf8)
		store.items["commit:" + committed.eoa] = Data("{\"v\":1,\"eoa\":\"\(committed.eoa)\",\"committedAt\":\"2026-11-15T06:00:00Z\"}".utf8)
		let owners = [legacy, committed.eoa]
		let before = snapshot(store, owners: owners)

		store.failWrite = [.mnemonic]
		let outcome = BeamioNativeKeyImport.importRecoveryPhrase(text: phraseB, expectedEoa: derived(phraseB).eoa, store: store)
		// §25.25.3: a mnemonic write the store refuses is write_failed (the read-back is not reached).
		XCTAssertEqual(outcome, .writeFailed)
		XCTAssertNil(store.items["key:" + derived(phraseB).eoa], "the failed import removes only its own key")
		XCTAssertNil(store.items["intent:" + derived(phraseB).eoa], "and its intent")
		XCTAssertEqual(snapshot(store, owners: owners), before, "the existing accounts are byte-identical")
	}

	/// The production Keychain store keeps a legacy key byte for byte through the reconciliation. The SwiftPM test host has no keychain
	/// entitlement (SecItemAdd returns errSecMissingEntitlement, -34018), so this skips there; it runs on a host with the entitlement or a device.
	func testProductionStoreKeepsALegacyKeyByteForByte() throws {
		let service = "com.beamio.test.upgrade.\(UUID().uuidString)"
		let store = BeamioChatWalletKeychainStore(service: service)
		let probe = "0x00000000000000000000000000000000000000ff"
		let writable = store.writeItem(.intent, eoa: probe, value: Data("{}".utf8))
		_ = store.deleteItem(.intent, eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this SwiftPM test host: SecItemAdd returns errSecMissingEntitlement (-34018); needs a keychain-entitled host or a device")
		let eoa = addressOf(legacyKey) ?? ""
		defer { for kind in BeamioChatWalletItemKind.allCases { _ = store.deleteItem(kind, eoa: eoa) } }
		XCTAssertTrue(store.writeItem(.key, eoa: eoa, value: Data(legacyKey)))
		let before = store.readItem(.key, eoa: eoa)
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertEqual(store.readItem(.key, eoa: eoa), before, "the production key is byte-identical after the reconciliation")
		XCTAssertEqual(addressOf(before.map { [UInt8]($0) } ?? []), eoa)
	}
}
#endif
