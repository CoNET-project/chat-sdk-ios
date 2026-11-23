#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// 第 2 至 4 项、第 12 至 13 项: the mnemonic, intent and commit items of an import, the rollback, and the
/// start-up reconciliation. Synthetic data only: the phrases are the BIP-39 test vectors, the keys derive from them.
final class MnemonicIntentStorageTests: XCTestCase {
	/// In-memory store with the four items of an account. `failWrite` and `failDelete` inject the faults of (e).
	final class MemStore: BeamioChatMnemonicKeyStoring {
		var items: [String: Data] = [:]
		var failWrite: Set<BeamioChatWalletItemKind> = []
		var failDelete: Set<BeamioChatWalletItemKind> = []
		/// Present items whose value cannot be read (itemState stays present, readItem returns nil).
		var failRead: Set<BeamioChatWalletItemKind> = []
		private func name(_ kind: BeamioChatWalletItemKind, _ eoa: String) -> String { kind.rawValue + ":" + eoa.lowercased() }

		func write(eoa: String, key: Data) -> Bool { writeItem(.key, eoa: eoa, value: key) }
		func read(eoa: String) -> Data? { readItem(.key, eoa: eoa) }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? {
			(enumerateKeyOwners() ?? []).map { .valid(eoa: $0) }
		}
		func enumerateKeyOwners() -> [String]? {
			let prefix = BeamioChatWalletItemKind.key.rawValue + ":"
			return items.keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }
		}
		/// The mnemonic ownership rule (Y.163 items 31 and 32): the store lists its mnemonic accounts.
		func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? {
			let prefix = BeamioChatWalletItemKind.mnemonic.rawValue + ":"
			return items.keys.filter { $0.hasPrefix(prefix) }.map { BeamioChatKeyCreation(owner: String($0.dropFirst(prefix.count)), created: nil) }
		}
		func delete(eoa: String) { _ = deleteItem(.key, eoa: eoa) }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool { true }

		func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
			items[name(kind, eoa)] == nil ? .absent : .present
		}
		func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
			if failWrite.contains(kind) { return false }
			items[name(kind, eoa)] = value
			return true
		}
		func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? { failRead.contains(kind) ? nil : items[name(kind, eoa)] }
		func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
			if failDelete.contains(kind) { return false }
			items[name(kind, eoa)] = nil
			return true
		}
		func intentOwners() -> [String]? {
			items.keys.filter { $0.hasPrefix("intent:") }.map { String($0.dropFirst("intent:".count)) }
		}
	}

	/// BIP-39 test vector (12 words): the phrase and the account it derives.
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"

	private func account(_ phrase: String) -> (eoa: String, key: [UInt8]) {
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let eoa = BeamioNativeEthSigner.address(privateKey: key)
		else { fatalError("the test vector does not derive") }
		return (eoa.lowercased(), key)
	}

	override func setUp() {
		super.setUp()
		BeamioNativeKeyImport.clearIntentMarksForTests()
	}

	/// The import keeps the key, the mnemonic and the commit, and removes the intent ((a), (b)).
	func testImportWithAPhraseKeepsTheKeyMnemonicAndCommitAndRemovesTheIntent() {
		let store = MemStore()
		let (eoa, _) = account(phraseA)
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: phraseA, expectedEoa: eoa, store: store), .imported)
		XCTAssertEqual(store.itemState(.key, eoa: eoa), .present)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phraseA.utf8), "the mnemonic is kept")
		XCTAssertEqual(store.itemState(.commit, eoa: eoa), .present, "the commit marker is written")
		XCTAssertEqual(store.itemState(.intent, eoa: eoa), .absent, "the intent is removed after the commit")
	}

	/// An account with any of the four items already present is refused and nothing is written ((i)).
	func testAnExistingCommitRefusesTheImportAndWritesNothing() {
		let store = MemStore()
		let (eoa, _) = account(phraseA)
		store.items["commit:" + eoa] = Data("{}".utf8)
		let before = store.items
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: phraseA, expectedEoa: eoa, store: store), .alreadyPresent)
		XCTAssertEqual(store.items, before)
	}

	/// A failed commit rolls back what this import registered, and the intent: nothing of the import is left ((e)).
	func testAFailedCommitRollsBackOnlyWhatTheImportRegistered() {
		let store = MemStore()
		let (eoa, _) = account(phraseA)
		store.failWrite = [.commit]
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: phraseA, expectedEoa: eoa, store: store), .writeFailed)
		XCTAssertTrue(store.items.isEmpty, "no key, mnemonic, intent or commit is left: \(store.items.keys.sorted())")
	}

	/// A rollback that cannot delete keeps the intent and reports rollback_pending ((e);). The account is marked unavailable
	/// only through the reconciliation, which is tested below.
	func testAFailedRollbackDeletionKeepsTheIntentAndReportsRollbackPending() {
		let store = MemStore()
		let (eoa, _) = account(phraseA)
		store.failWrite = [.commit]
		store.failDelete = [.key]
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: phraseA, expectedEoa: eoa, store: store), .rollbackPending)
		XCTAssertEqual(store.itemState(.intent, eoa: eoa), .present, "the intent is kept for the next start-up")
	}

	/// (b): a creation makes the 12-word phrase, derives the account, and keeps the phrase with the key (intent, mnemonic, key, commit).
	func testACreationKeepsThePhraseWithTheKeyAndTheCommit() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		defer { BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false) }
		let store = MemStore()
		let entropy = [UInt8](repeating: 0, count: 16)
		guard case .made(let material) = BeamioNativeAccountCreate.makeAccount(store: store, entropy: entropy, userExplicit: true) else {
			return XCTFail("the creation is made")
		}
		let eoa = material.eoa
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(material.mnemonicPhrase.utf8), "the phrase is kept")
		XCTAssertEqual(store.itemState(.commit, eoa: eoa), .present)
		XCTAssertEqual(store.itemState(.intent, eoa: eoa), .absent)
		XCTAssertEqual(material.mnemonicPhrase, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	}

	/// T-IU1: an unreadable intent marks only its own account. The legacy key of another account is still readable, and its address is unchanged.
	func testT_IU1_AnUnreadableIntentMarksOnlyItsAccountAndTheLegacyAccountStaysUsable() {
		let store = MemStore()
		let legacy = account(phraseB)
		store.items["key:" + legacy.eoa] = Data(legacy.key)
		let broken = account(phraseA)
		store.items["key:" + broken.eoa] = Data(broken.key)
		store.items["mnemonic:" + broken.eoa] = Data(phraseA.utf8)
		store.items["intent:" + broken.eoa] = Data("not json".utf8)
		let marked = BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertEqual(marked, [broken.eoa], "only the account with the unreadable intent is marked")
		XCTAssertTrue(BeamioNativeKeyImport.isIntentUnavailable(eoa: broken.eoa))
		XCTAssertFalse(BeamioNativeKeyImport.isIntentUnavailable(eoa: legacy.eoa), "the legacy account is not affected")
		XCTAssertEqual(store.read(eoa: legacy.eoa), Data(legacy.key), "the legacy key is unchanged and readable")
		XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: legacy.key)?.lowercased(), legacy.eoa, "the legacy address is unchanged")
	}

	/// T-IU2: the reconciliation does not change one byte of the broken account's key, mnemonic or intent (nothing is deleted).
	func testT_IU2_TheReconciliationKeepsTheBrokenAccountItemsByteForByte() {
		let store = MemStore()
		let broken = account(phraseA)
		store.items["key:" + broken.eoa] = Data(broken.key)
		store.items["mnemonic:" + broken.eoa] = Data(phraseA.utf8)
		store.items["intent:" + broken.eoa] = Data("not json".utf8)
		let before = store.items
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertEqual(store.items, before)
	}

	/// (c): a committed intent is only removed; a missing commit removes the registered records of that intent only.
	func testAnIntentWithACommitRemovesOnlyTheIntent() {
		let store = MemStore()
		let (eoa, key) = account(phraseA)
		store.items["key:" + eoa] = Data(key)
		store.items["mnemonic:" + eoa] = Data(phraseA.utf8)
		store.items["commit:" + eoa] = Data("{}".utf8)
		store.items["intent:" + eoa] = Data("{\"v\":1,\"eoa\":\"\(eoa)\",\"mnemonicPlanned\":true,\"startedAt\":\"x\",\"phase\":\"begun\"}".utf8)
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertNil(store.items["intent:" + eoa])
		XCTAssertEqual(store.items["key:" + eoa], Data(key))
		XCTAssertEqual(store.items["mnemonic:" + eoa], Data(phraseA.utf8))
		XCTAssertNotNil(store.items["commit:" + eoa])
	}

	/// 第 4 項 (c): an intent without a commit removes what it registered (the key and the mnemonic when planned), then the intent.
	func testAnIntentWithoutACommitRemovesWhatItRegistered() {
		let store = MemStore()
		let (eoa, key) = account(phraseA)
		store.items["key:" + eoa] = Data(key)
		store.items["mnemonic:" + eoa] = Data(phraseA.utf8)
		store.items["intent:" + eoa] = Data("{\"v\":1,\"eoa\":\"\(eoa)\",\"mnemonicPlanned\":true,\"startedAt\":\"x\",\"phase\":\"begun\"}".utf8)
		BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertTrue(store.items.isEmpty, "an uncommitted import is rolled back: \(store.items.keys.sorted())")
	}

	/// Probe: the production store can write one item in this test host. False: the production-store tests are skipped, with the reason.
	private func keychainWritable(_ store: BeamioChatWalletKeychainStore) -> Bool {
		let probe = "0x00000000000000000000000000000000000000ff"
		let written = store.writeItem(.intent, eoa: probe, value: Data("{}".utf8))
		_ = store.deleteItem(.intent, eoa: probe)
		return written
	}

	/// (c), 接线: the start-up reconciliation runs before the first command reads a record. A command (walletStatus) finds the
	/// intents already settled: the committed intent is removed, the uncommitted intent removes what it registered, and the legacy key and the
	/// committed mnemonic are unchanged.
	func testTheStartupReconciliationRunsBeforeAnyCommandReadsARecord() {
		let saved = BeamioNativeWallet.keyStore
		defer {
			BeamioNativeWallet.keyStore = saved
			BeamioNativeKeyImport.resetStartupForTests()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
		let store = MemStore()
		BeamioNativeWallet.keyStore = store
		let legacy = account(phraseB)
		store.items["key:" + legacy.eoa] = Data(legacy.key)
		let committed = account(phraseA)
		store.items["key:" + committed.eoa] = Data(committed.key)
		store.items["mnemonic:" + committed.eoa] = Data(phraseA.utf8)
		store.items["commit:" + committed.eoa] = Data("{}".utf8)
		store.items["intent:" + committed.eoa] = Data("{\"v\":1,\"eoa\":\"\(committed.eoa)\",\"mnemonicPlanned\":true,\"startedAt\":\"x\",\"phase\":\"begun\"}".utf8)
		let before = store.items.filter { !$0.key.hasPrefix("intent:") }
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioConetChatModule.setNativeGateForTests(account: legacy.eoa, sessionReady: false)
		var answers: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 4001], emit: { answers.append($0) })
		XCTAssertNil(store.items["intent:" + committed.eoa], "the committed intent is removed before the read")
		XCTAssertEqual(store.items.filter { !$0.key.hasPrefix("intent:") }, before, "no key, mnemonic or commit changed")
		XCTAssertFalse(BeamioNativeKeyImport.isIntentUnavailable(eoa: legacy.eoa))
	}

	/// (k): walletStatus answers `not_ready` with `notReadyReason: "unreadable"` for an unreadable mark, and `not_ready` without the
	/// reason for an account with no mark problem. Nothing is deleted.
	func testWalletStatusAnswersUnreadableForABrokenMarkAndPlainNotReadyOtherwise() {
		let saved = BeamioNativeWallet.keyStore
		defer {
			BeamioNativeWallet.keyStore = saved
			BeamioNativeKeyImport.resetStartupForTests()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
		let store = MemStore()
		BeamioNativeWallet.keyStore = store
		// A damaged record: the mnemonic item of the account holds another account's phrase, so it does not derive the account (invalid, not absent: the device holds a record that
		// cannot be read). A mnemonic that is valid and has no commit is Ready since 15c9471, so a missing mark no longer makes a damaged record.
		let broken = account(phraseA)
		store.items["key:" + broken.eoa] = Data(broken.key)
		store.items["mnemonic:" + broken.eoa] = Data(phraseB.utf8)
		// A valid mnemonic account with a key and no marks: the plain G1 account. (A key alone is no account since Y.163 items 31 and 32: it answers no_key.)
		let plain = account(phraseB)
		store.items["key:" + plain.eoa] = Data(plain.key)
		store.items["mnemonic:" + plain.eoa] = Data(phraseB.utf8)
		BeamioNativeKeyImport.resetStartupForTests()
		func status(_ eoa: String, _ reqId: Int) -> [String: Any] {
			// Each answer starts from a cleared gate and no unavailable marks left by other tests in this process.
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			BeamioNativeKeyImport.resetStartupForTests()
			BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
			var answers: [[String: Any]] = []
			BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": reqId], emit: { answers.append($0) })
			// The answers are delivered on the main queue. Wait for the ack of THIS reqId; acks of other commands are not this answer.
			let deadline = Date().addingTimeInterval(5)
			func ownAck() -> [String: Any]? {
				answers.compactMap { ($0["event"] as? [String: Any]) ?? $0 }
					.first { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
			}
			while ownAck() == nil, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
			return (ownAck()?["result"] as? [String: Any]) ?? [:]
		}
		let brokenAnswer = status(broken.eoa, 4002)
		XCTAssertEqual(brokenAnswer["status"] as? String, "not_ready")
		XCTAssertEqual(brokenAnswer["notReadyReason"] as? String, "unreadable")
		XCTAssertEqual(store.items["key:" + broken.eoa], Data(broken.key), "nothing is deleted")
		let plainAnswer = status(plain.eoa, 4003)
		XCTAssertEqual(plainAnswer["status"] as? String, "not_ready")
		XCTAssertEqual(plainAnswer["notReadyReason"] as? String, "g1_uninitialized", "a legacy key without marks is not unreadable (第 4 項 (j)); its G1 reason is g1_uninitialized (25.52Y.117, Y.118)")
	}

	/// T-IU5: the bridge names and the SDK command table contain no command that deletes a record or an intent.
	func testT_IU5_NoCommandDeletesARecordOrAnIntent() {
		let names = BeamioConetChatModule.commandNamesForAudit
		// accountCleanupOld (owner requirement, silent cleanup in the next version) is the one named exception; its deletion set is exact names of the old account.
		let forbidden = names.subtracting(["accountCleanupOld"]).filter { name in
			let lower = name.lowercased()
			return lower.contains("intent") || lower.contains("rollback") || lower.contains("cleanup") || lower.contains("purge")
				|| lower.contains("reconcile") || lower.contains("deleteaccount") || lower.contains("removekey")
		}
		XCTAssertEqual(forbidden, [], "no command deletes an intent, a rollback, or a cleanup record")
	}

	/// (5): the same import, rollback and reconciliation on the production store `BeamioChatWalletKeychainStore`, in the Keychain of
	/// the simulator under a test-only service name. Every item is removed afterwards.
	func testProductionStoreImportKeepsMnemonicAndCommitAndRemovesIntent() throws {
		let service = "com.beamio.test.intent.\(UUID().uuidString)"
		let store = BeamioChatWalletKeychainStore(service: service)
		try XCTSkipUnless(keychainWritable(store), "the Keychain cannot be written in this SwiftPM test host: SecItemAdd returns errSecMissingEntitlement (-34018); the production-store path needs a host with a keychain entitlement or a real device")
		defer { for kind in BeamioChatWalletItemKind.allCases { _ = store.deleteItem(kind, eoa: account(phraseA).eoa) } }
		let (eoa, _) = account(phraseA)
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: phraseA, expectedEoa: eoa, store: store), .imported)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phraseA.utf8), "the production store keeps the mnemonic")
		// the keychain store itself takes the key-and-mnemonic import path (four items); only the passcode store writes a set
		if BeamioNativeKeyImport.setStore(of: store) != nil {
			XCTAssertEqual(store.itemState(.commit, eoa: eoa), .absent, "a set import writes no commit item")
		} else {
			XCTAssertEqual(store.itemState(.commit, eoa: eoa), .present)
		}
		XCTAssertEqual(store.itemState(.intent, eoa: eoa), .absent)
	}

	func testProductionStoreReconciliationRemovesAnUncommittedImportAndKeepsAnUnreadableIntent() throws {
		let service = "com.beamio.test.intent.\(UUID().uuidString)"
		let store = BeamioChatWalletKeychainStore(service: service)
		try XCTSkipUnless(keychainWritable(store), "the Keychain cannot be written in this SwiftPM test host: SecItemAdd returns errSecMissingEntitlement (-34018); the production-store path needs a host with a keychain entitlement or a real device")
		let (eoa, key) = account(phraseA)
		let other = account(phraseB)
		defer {
			for kind in BeamioChatWalletItemKind.allCases {
				_ = store.deleteItem(kind, eoa: eoa)
				_ = store.deleteItem(kind, eoa: other.eoa)
			}
			BeamioNativeKeyImport.clearIntentMarksForTests()
		}
		// An uncommitted import of EOA: its intent, key and mnemonic are removed by the reconciliation.
		XCTAssertTrue(store.writeItem(.intent, eoa: eoa, value: Data("{\"v\":1,\"eoa\":\"\(eoa)\",\"mnemonicPlanned\":true,\"startedAt\":\"x\",\"phase\":\"begun\"}".utf8)))
		XCTAssertTrue(store.writeItem(.key, eoa: eoa, value: Data(key)))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: eoa, value: Data(phraseA.utf8)))
		// An intent of another EOA that cannot be read: nothing is deleted, only that account is marked.
		XCTAssertTrue(store.writeItem(.intent, eoa: other.eoa, value: Data("not json".utf8)))
		XCTAssertTrue(store.writeItem(.key, eoa: other.eoa, value: Data(other.key)))
		let otherKeyBefore = store.readItem(.key, eoa: other.eoa)
		let marked = BeamioNativeKeyImport.reconcileIntents(store: store)
		XCTAssertEqual(marked, [other.eoa])
		XCTAssertEqual(store.itemState(.key, eoa: eoa), .absent, "the uncommitted key is removed")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: eoa), .absent, "the uncommitted mnemonic is removed")
		XCTAssertEqual(store.itemState(.intent, eoa: eoa), .absent)
		XCTAssertEqual(store.readItem(.key, eoa: other.eoa), otherKeyBefore, "the other account's key is byte-for-byte unchanged")
		XCTAssertTrue(BeamioNativeKeyImport.isIntentUnavailable(eoa: other.eoa))
	}

	/// Runs one walletCredential for the account (the gate G1) and returns its ack (the answer with this reqId).
	private func credentialAnswer(_ store: MemStore, eoa: String, reqId: Int) -> [String: Any] {
		let saved = BeamioNativeWallet.keyStore
		defer {
			BeamioNativeWallet.keyStore = saved
			BeamioNativeKeyImport.resetStartupForTests()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		var answers: [[String: Any]] = []
		BeamioConetChatModule.nativeObserver = { answers.append($0) }
		defer { BeamioConetChatModule.nativeObserver = nil }
		BeamioConetChatModule.walletCredentialForTests(["type": "walletCredential", "reqId": reqId])
		let deadline = Date().addingTimeInterval(5)
		func ownAck() -> [String: Any]? {
			answers.compactMap { ($0["event"] as? [String: Any]) ?? $0 }
				.first { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
		}
		while ownAck() == nil, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
		return ownAck() ?? [:]
	}

	/// walletCredential is not registered in the bridge command table until the ruling. Through the bridge it answers unknown_command.
	func testWalletCredentialIsNotRegisteredOnTheBridge() {
		XCTAssertFalse(BeamioConetChatModule.dispatchedCommands.contains("walletCredential"))
	}

	/// W-L5 ((a)): walletCredential for an `eoa_key` account (a key and no mnemonic record) answers `unavailable`. It returns
	/// no private key and no `{eoa}`.
	func testWL5_WalletCredentialForAnEoaKeyAccountAnswersUnavailable() {
		let store = MemStore()
		let legacy = account(phraseB)
		store.items["key:" + legacy.eoa] = Data(legacy.key)
		let ack = credentialAnswer(store, eoa: legacy.eoa, reqId: 5001)
		XCTAssertEqual(ack["ok"] as? Bool, false, "W-L5: the answer is a refusal")
		XCTAssertEqual(ack["error"] as? String, "unavailable", "W-L5: the eoa_key account answers unavailable")
		XCTAssertNil(ack["result"], "W-L5: no result (no eoaPrivateKey, no {eoa})")
		let text = String(describing: ack)
		XCTAssertFalse(text.contains(legacy.key.map { String(format: "%02x", $0) }.joined()), "W-L5: the private key does not appear")
	}

	/// W-L6: walletCredential for an account with a committed mnemonic returns the mnemonic (credentialKind "mnemonic"), and no private key.
	func testWL6_WalletCredentialForAMnemonicAccountReturnsTheMnemonic() {
		let store = MemStore()
		let (eoa, key) = account(phraseA)
		store.items["key:" + eoa] = Data(key)
		store.items["mnemonic:" + eoa] = Data(phraseA.utf8)
		store.items["commit:" + eoa] = Data("{}".utf8)
		let ack = credentialAnswer(store, eoa: eoa, reqId: 6001)
		XCTAssertEqual(ack["ok"] as? Bool, true)
		let result = ack["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["credentialKind"] as? String, "mnemonic")
		XCTAssertEqual(result["mnemonic"] as? String, phraseA)
		XCTAssertNil(result["eoaPrivateKey"], "a mnemonic account returns no private key")
	}

	/// the window entries. walletEoaAddress returns only the public address; an untrusted call is `origin_refused` (an envelope
	/// error: ok false and error, no result); an invalid reqId is `bad_request`; walletCredential for an eoa_key account is `unavailable`.
	func testWindowEntriesAnswerTheEnvelopeAndTheAddressOnly() {
		let saved = BeamioNativeWallet.keyStore
		defer {
			BeamioNativeWallet.keyStore = saved
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
		let store = MemStore()
		BeamioNativeWallet.keyStore = store
		let legacy = account(phraseB)
		store.items["key:" + legacy.eoa] = Data(legacy.key)
		// a valid account for the address call (a key alone is no account since Y.163 items 31 and 32); the mnemonic is removed again before the eoa_key case at the end
		store.items["mnemonic:" + legacy.eoa] = Data(phraseB.utf8)
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatModule.setNativeGateForTests(account: legacy.eoa, sessionReady: false)

		var address: [String: Any] = [:]
		BeamioWindowWallet.walletEoaAddress(reqId: 7001, trust: .trusted) { address = $0 }
		XCTAssertEqual(address["ok"] as? Bool, true)
		XCTAssertEqual((address["result"] as? [String: Any])?["eoa"] as? String, legacy.eoa)
		XCTAssertNil((address["result"] as? [String: Any])?["eoaPrivateKey"], "the address call returns no key")

		var refused: [String: Any] = [:]
		BeamioWindowWallet.walletEoaAddress(reqId: 7002, trust: .originRefused) { refused = $0 }
		XCTAssertEqual(refused["error"] as? String, "origin_refused")
		XCTAssertEqual(refused["ok"] as? Bool, false)
		XCTAssertNil(refused["result"], "an envelope error carries no result")

		var bad: [String: Any] = [:]
		BeamioWindowWallet.walletEoaAddress(reqId: nil, trust: .trusted) { bad = $0 }
		XCTAssertEqual(bad["error"] as? String, "bad_request")

		// no build declares wallet.credential.v1 yet, so walletCredential answers not_trusted before the account is read.
		XCTAssertFalse(BeamioWindowWallet.walletCredentialDeclared(), "no build declares the capability yet")
		var credential: [String: Any] = [:]
		BeamioWindowWallet.walletCredential(["type": "walletCredential", "reqId": 7003], trust: .trusted) { credential = $0 }
		XCTAssertEqual(credential["error"] as? String, "not_trusted", "walletCredential without the capability is not_trusted")
		XCTAssertNil(credential["result"])
		// The mnemonic path itself (W-L5 for an eoa_key account) is judged by walletCredentialOutcome, which the tests call directly: the key is left with no mnemonic.
		store.items["mnemonic:" + legacy.eoa] = nil
		XCTAssertEqual(BeamioConetChatModule.walletCredentialOutcome().error, "unavailable", "W-L5: an eoa_key account answers unavailable")
	}

	/// the window entries of the record commands. An untrusted call is the envelope `origin_refused` (ok false, error);
	/// a call without a reqId is the envelope `bad_request`. No store is read here (the envelope cases only).
	func testShellRecordWindowEntriesAnswerTheEnvelopeCases() {
		var refused: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": 8001], trust: .originRefused) { refused = $0 }
		XCTAssertEqual(refused["ok"] as? Bool, false)
		XCTAssertEqual(refused["error"] as? String, "origin_refused", "an untrusted call is the envelope origin_refused")
		XCTAssertNil(refused["result"])
		var bad: [String: Any] = [:]
		BeamioWindowWallet.shellRecordWrite([:], trust: .trusted) { bad = $0 }
		XCTAssertEqual(bad["ok"] as? Bool, false)
		XCTAssertEqual(bad["error"] as? String, "bad_request", "a call without a reqId is the envelope bad_request")
	}
}
#endif
