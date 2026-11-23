import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Native wallet boundary: the local root comes from the native key store, unlock and logout behave as
/// specified, a missing key keeps the library locked, the one-time migration is gated, signing is native, and the bridge
/// refuses keys. Synthetic keys only (0x11…11); never a user key.
final class ChatLocalWalletBoundaryTests: XCTestCase {
	/// In-memory store with failure injection for the migration rollback paths.
	final class MemoryWalletKeyStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var markers = Set<String>()
		var failWrite = false
		var failMarker = false
		var corruptReadBack = false
		var failRunning = false
		var writes = 0
		var phases: [String: BeamioChatMigrationPhase] = [:]

		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			if failWrite { return false }
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? {
			guard let k = keys[eoa.lowercased()] else { return nil }
			if corruptReadBack { return Data(repeating: 0xEE, count: 32) }
			return k
		}
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { markers.contains(eoa.lowercased()) }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase {
			let k = eoa.lowercased()
			if let p = phases[k] { return p }
			return markers.contains(k) ? .complete : .none
		}
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			let k = eoa.lowercased()
			switch phase {
			case .complete:
				if failMarker { return false }
				markers.insert(k)
				phases[k] = .complete
			case .running:
				if failRunning { return false }
				phases[k] = .running
			case .switched:
				phases[k] = .switched
			case .none:
				phases[k] = nil
				markers.remove(k)
			}
			return true
		}
	}

	private let keyHex = String(repeating: "11", count: 32)
	private lazy var eoa: String = hexKeyAddress(keyHex)!.lowercased()
	private var roots: [URL] = []
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioConetChatSignBroker.keyStore
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.keyStore = savedStore
		BeamioConetChatSignBroker.clearSigner()
		for r in roots { try? FileManager.default.removeItem(at: r) }
		roots = []
		super.tearDown()
	}

	private func tempRoot() -> URL {
		let u = FileManager.default.temporaryDirectory.appendingPathComponent("chat-wallet-\(UUID().uuidString)", isDirectory: true)
		roots.append(u)
		return u
	}

	private func keyBytes() -> Data { BeamioChatLocalCrypto.bytes(fromHex: keyHex)! }

	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait)

	// MARK: - Unlock, logout, missing key

	func testUnlockWithNativeKeyDerivesTheLocalRoot() throws {
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = keyBytes()
		let root = try XCTUnwrap(BeamioChatWalletBoundary.localRoot(eoa: eoa, store: store))
		XCTAssertEqual(root, BeamioChatLocalCrypto.localRoot(privateKey: keyBytes(), eoa: eoa, workspace: "default"),
		               "R_db = HKDF(P, salt, info) with the account eoa and workspace default")
		let library = BeamioConetChatLocalStore(rootDirectory: tempRoot())
		try library.unlock(accountKey: eoa + ":default", localRoot: root)
		XCTAssertTrue(library.isUnlocked)
		XCTAssertEqual(library.openConversation(convKey: "0x2222222222222222222222222222222222222222", viewport: viewport).source, .local)
	}

	func testLogoutLocksAndKeepsTheKeyForTheNextUnlock() throws {
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = keyBytes()
		let root = try XCTUnwrap(BeamioChatWalletBoundary.localRoot(eoa: eoa, store: store))
		let library = BeamioConetChatLocalStore(rootDirectory: tempRoot())
		try library.unlock(accountKey: eoa + ":default", localRoot: root)
		library.lock()
		XCTAssertFalse(library.isUnlocked, "logout locks the library")
		XCTAssertEqual(library.openConversation(convKey: "0x2222222222222222222222222222222222222222", viewport: viewport).source, .locked)
		XCTAssertTrue(BeamioChatWalletKeychain.hasKey(eoa: eoa, store: store), "the device wallet key stays (D2: lock, not erase)")
		let again = try XCTUnwrap(BeamioChatWalletBoundary.localRoot(eoa: eoa, store: store))
		try library.unlock(accountKey: eoa + ":default", localRoot: again)
		XCTAssertTrue(library.isUnlocked, "unlock after logout works with the same key")
	}

	func testMissingNativeKeyKeepsTheLibraryLocked() throws {
		let store = MemoryWalletKeyStore()
		XCTAssertNil(BeamioChatWalletBoundary.localRoot(eoa: eoa, store: store), "no key → no root")
		XCTAssertFalse(BeamioChatWalletKeychain.hasKey(eoa: eoa, store: store))
		let library = BeamioConetChatLocalStore(rootDirectory: tempRoot())
		XCTAssertFalse(library.isUnlocked)
		XCTAssertEqual(library.openConversation(convKey: "0x2222222222222222222222222222222222222222", viewport: viewport).source, .locked,
		               "no key: locked, nothing is transferred over the bridge")
	}

	// MARK: - Keychain round trip (an item of the in-memory test Keychain under a test service; the real Keychain is never reached in a test build)

	func testKeychainStoreRoundTripAndDelete() {
		let store = BeamioChatWalletKeychainStore(service: "com.beamio.test.chat-wallet.\(UUID().uuidString)")
		addTeardownBlock { store.delete(eoa: self.eoa) }
		XCTAssertNil(store.read(eoa: eoa))
		XCTAssertTrue(store.write(eoa: eoa, key: keyBytes()), "Keychain write")
		XCTAssertEqual(store.read(eoa: eoa), keyBytes(), "Keychain read-back equals the input")
		// Diagnostic only: which storage mode this host used ("se" when a Secure Enclave wrap worked, else "keychain").
		print("WALLET_STORAGE_MODE=\(store.storageMode(eoa: eoa) ?? "nil")")
		store.delete(eoa: eoa)
		XCTAssertNil(store.read(eoa: eoa))
	}

	// MARK: - One-time migration

	func testMigrationStoresOnceAndThenRefuses() {
		let store = MemoryWalletKeyStore()
		let derive: (String) -> String? = { hexKeyAddress($0) }
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .migrated)
		XCTAssertEqual(store.keys[eoa], keyBytes())
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .alreadyPresent)
		store.delete(eoa: eoa)
		let writes = store.writes
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .alreadyMigrated,
		               "one migration per account per device")
		XCTAssertEqual(store.writes, writes, "no write after the marker")
	}

	func testMigrationRefusesAnAddressThatDoesNotMatch() {
		let store = MemoryWalletKeyStore()
		let other = "0x" + String(repeating: "9", count: 40)
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: other, privateKeyHex: keyHex, store: store,
		                                                    addressOf: { hexKeyAddress($0) }),
		               .addressMismatch)
		XCTAssertEqual(store.writes, 0, "nothing is written when the address does not match")
		XCTAssertNil(store.keys[other])
	}

	func testMigrationRefusesAnInvalidKey() {
		let store = MemoryWalletKeyStore()
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: "not-a-key", store: store,
		                                                    addressOf: { hexKeyAddress($0) }),
		               .invalidKey)
		XCTAssertEqual(store.writes, 0)
	}

	func testMigrationRollsBackWhenTheWriteFails() {
		let store = MemoryWalletKeyStore()
		store.failWrite = true
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store,
		                                                    addressOf: { hexKeyAddress($0) }),
		               .writeFailed)
		XCTAssertNil(store.keys[eoa], "a failed write leaves nothing behind; the caller keeps its copy")
		XCTAssertFalse(store.migrationMarkerExists(eoa: eoa))
	}

	func testMigrationRollsBackWhenTheReadBackDoesNotMatch() {
		let store = MemoryWalletKeyStore()
		store.corruptReadBack = true
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store,
		                                                    addressOf: { hexKeyAddress($0) }),
		               .readBackFailed)
		XCTAssertNil(store.keys[eoa], "the write is removed when the read-back fails")
		XCTAssertFalse(store.migrationMarkerExists(eoa: eoa))
	}

	func testMigrationRollsBackWhenTheMarkerFails() {
		let store = MemoryWalletKeyStore()
		store.failMarker = true
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store,
		                                                    addressOf: { hexKeyAddress($0) }),
		               .writeFailed)
		XCTAssertNil(store.keys[eoa], "no key without its marker")
	}

	// MARK: - Signing is native

	func testEip191SigningUsesTheNativeKey() {
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = keyBytes()
		BeamioConetChatSignBroker.keyStore = store
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		let expected = hexKeySignEip191(keyHex, message: "hello r3")
		var got: Result<String, Error>?
		BeamioConetChatSignBroker.requestEip191(message: "hello r3") { got = $0 }
		XCTAssertEqual(try? got?.get(), expected)
	}

	func testSigningWithoutANativeKeyFailsAndNeverAsksThePage() {
		BeamioConetChatSignBroker.keyStore = MemoryWalletKeyStore()
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		var got: Result<String, Error>?
		BeamioConetChatSignBroker.requestEip191(message: "x") { got = $0 }
		if case .failure(let e)? = got { XCTAssertEqual(e as? BeamioConetChatSignBroker.SignError, .walletKeyMissing) } else { XCTFail() }
	}

	// MARK: - Bridge refuses keys; the one-time command is the only key path

	private func runBridge(_ body: [String: Any]) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(body, emit: { event in
			if (event["event"] as? [String: Any])?["type"] as? String == "ack" {
				ack = event["event"] as? [String: Any]
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		return ack
	}

	/// The account has a native key, so the refusal is the answer (: without a record the answer is `no_key`, see
	/// NoKeyRejectVectorTests).
	func testProvisionIdentityRefusesAnyPrivateKeyField() {
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = keyBytes()
		BeamioConetChatSignBroker.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		for field in ["privateKeyHex", "walletPrivateKey", "pgpPrivateKeyArmored"] {
			let ack = runBridge(["type": "provisionIdentity", "reqId": 7, "payload": ["eoa": eoa, field: "secret"]])
			XCTAssertEqual(ack?["error"] as? String, "key_over_bridge_refused", field)
			XCTAssertEqual(ack?["ok"] as? Bool, false)
		}
		XCTAssertEqual(store.keys.count, 1, "nothing stored from the bridge")
		XCTAssertEqual(store.keys[eoa], keyBytes(), "the stored key is unchanged")
	}

	func testProvisionIdentityOnlyReportsAStoredKey() {
		let store = MemoryWalletKeyStore()
		BeamioConetChatSignBroker.keyStore = store
		XCTAssertEqual(runBridge(["type": "provisionIdentity", "reqId": 8, "payload": ["eoa": eoa]])?["error"] as? String, "no_key")
		store.keys[eoa] = keyBytes()
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		let ack = runBridge(["type": "provisionIdentity", "reqId": 9, "payload": ["eoa": eoa]])
		XCTAssertEqual(ack?["ok"] as? Bool, true)
	}

	func testProvisionIdentityRefusesPgpPassphrase() {
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = keyBytes()
		BeamioConetChatSignBroker.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		let ack = runBridge(["type": "provisionIdentity", "reqId": 10, "payload": ["eoa": eoa, "pgpPassphrase": "x"]])
		XCTAssertEqual(ack?["error"] as? String, "key_over_bridge_refused")
	}

	/// T-104: `ready` needs a stored key that derives the account (read-back), never a key stored for another account.
	func testIdentityReadyNeedsAKeyThatDerivesTheAccount() {
		let store = MemoryWalletKeyStore()
		BeamioConetChatSignBroker.keyStore = store
		XCTAssertFalse(BeamioConetChatModule.identityKeyReady(eoa: eoa))
		store.keys[eoa] = keyBytes()
		XCTAssertTrue(BeamioConetChatModule.identityKeyReady(eoa: eoa))
		let other = "0x0000000000000000000000000000000000000001"
		store.keys[other] = keyBytes()
		XCTAssertFalse(BeamioConetChatModule.identityKeyReady(eoa: other))
	}

	/// The identity.native-keys.v1 answer stays off until the interface vectors declare the capability.
#if BEAMIO_QA_BUILD
	/// The QA build declares the capability (item 6): the production list is the one without it.
	func testIdentityNativeKeysCapabilityIsDeclaredOnlyByTheQABuild() {
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains(BeamioConetChatModule.identityNativeKeysCapability))
	}
#else
	/// 25.52Y.121: the pair is in the shipped list (flipped from "not declared yet" with the project requirement).
	func testIdentityNativeKeysCapabilityIsDeclaredInTheShippedList() {
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains(BeamioConetChatModule.identityNativeKeysCapability))
	}
#endif

	/// S-1: the X-21 one-time transfer is retired. A key offered over the bridge is refused without being
	/// read: nothing is stored, the phase does not move, and the ack says `not_supported`. A missing key is imported natively.
	func testRetiredWalletTransferTakesNoKeyFromTheBridge() {
		let store = MemoryWalletKeyStore()
		BeamioConetChatSignBroker.keyStore = store
		let ack = runBridge(["type": "walletTransferOnce", "reqId": 10, "requestId": "any", "kind": "eoaKey",
		                     "bytes": [Int](repeating: 0x11, count: 32)])
		XCTAssertEqual(ack?["ok"] as? Bool, false)
		XCTAssertEqual(ack?["error"] as? String, "not_supported")
		XCTAssertNil(store.keys[eoa], "no key is stored from the bridge")
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .none)
	}

	// MARK: - X-21 migration phases (none, running, complete, switched)

	func testPhasesRunFromNoneToCompleteToSwitched() throws {
		let store = MemoryWalletKeyStore()
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .none)
		XCTAssertEqual(BeamioChatWalletBoundary.markSwitched(eoa: eoa, store: store), false, "switched needs complete first")
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .migrated)
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .complete, "complete only after the read-back")
		XCTAssertTrue(BeamioChatWalletBoundary.markSwitched(eoa: eoa, store: store))
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .switched)
		XCTAssertEqual(BeamioChatWalletBoundary.markSwitched(eoa: eoa, store: store), true, "switched again is harmless")
	}

	func testAFailedWriteRollsBackToNoneAndNothingIsLeft() {
		let store = MemoryWalletKeyStore()
		store.failWrite = true
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .writeFailed)
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .none, "a failed attempt is retried, not reported as done")
		XCTAssertNil(store.keys[eoa])
	}

	func testRunningIsRecordedBeforeAnyKeyIsWritten() {
		let store = MemoryWalletKeyStore()
		store.failRunning = true
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .writeFailed)
		XCTAssertEqual(store.writes, 0, "no key is written when running cannot be recorded")
	}

	func testCrashAfterTheWriteIsCompletedOnTheNextAttempt() {
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = keyBytes()
		store.phases[eoa] = .running  // the process stopped after the write and before `complete`
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store, addressOf: { hexKeyAddress($0) }), .alreadyPresent)
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .complete, "verified on the next attempt, then recorded")
	}

	/// S-1 group A (spec, T-141): the three X-21 commands answer `not_supported` for any argument, with no result
	/// and no state change.
	func testTheThreeX21CommandsAreRetiredWithNoStateChange() {
		let store = MemoryWalletKeyStore()
		BeamioConetChatSignBroker.keyStore = store
		for (reqId, type) in [(30, "walletTransferSwitched"), (31, "walletTransferStatus"), (32, "walletTransferOnce")] {
			let ack = runBridge(["type": type, "reqId": reqId, "payload": ["eoa": eoa], "requestId": "any",
			                     "kind": "eoaKey", "bytes": [Int](repeating: 0x11, count: 32)])
			XCTAssertEqual(ack?["ok"] as? Bool, false, type)
			XCTAssertEqual(ack?["error"] as? String, "not_supported", type)
			XCTAssertNil(ack?["result"], type)
		}
		XCTAssertNil(store.keys[eoa])
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .none)
	}

	// MARK: - record_mismatch (6.6, 25.6)

	func testAStoredKeyForAnotherAccountIsRefusedAndKept() {
		let store = MemoryWalletKeyStore()
		let other = Data(repeating: 0x22, count: 32)
		store.keys[eoa] = other
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store,
		                                                    addressOf: { hexKeyAddress($0) }), .recordMismatch)
		XCTAssertEqual(store.keys[eoa], other, "nothing is deleted or replaced")
		XCTAssertNil(BeamioChatWalletBoundary.localRoot(eoa: eoa, store: store), "a key that does not derive the account is never used")
	}

	func testRecordMismatchWhileRunningStaysRunning() {
		let store = MemoryWalletKeyStore()
		store.keys[eoa] = Data(repeating: 0x22, count: 32)
		store.phases[eoa] = .running
		XCTAssertEqual(BeamioChatWalletBoundary.migrateOnce(eoa: eoa, privateKeyHex: keyHex, store: store,
		                                                    addressOf: { hexKeyAddress($0) }), .recordMismatch)
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .running, "not recorded as complete")
	}

	func testPGPSideIsGatedWhileTheNativeLibraryIsPending() {
		// the native inbound gate is open in every build with X-19 linked (owner requirement), and closed without it.
		XCTAssertEqual(BeamioPGPNative.available, BeamioPGPNative.linked)
		XCTAssertEqual(BeamioPGPNative.pendingCode, "pgp_native_pending")
	}

	// MARK: - D10 sendKey from R_db (spec 4.1, rule 2)

	func testEmptySendKeyIsDerivedFromLocalRootNotFromTheProtocolMaster() throws {
		let store = MemoryWalletKeyStore()
		let peer = "0x2222222222222222222222222222222222222222"
		XCTAssertNil(BeamioConetChatHistoryStore.emptySendKey(eoa: eoa, peer: peer, dir: "out", ts: 1767225603500,
		                                                      body: "hi", store: store),
		             "no native key: no sendKey is derived and the append fails")
		store.keys[eoa] = keyBytes()
		let got = try XCTUnwrap(BeamioConetChatHistoryStore.emptySendKey(eoa: eoa, peer: peer, dir: "out",
		                                                                 ts: 1767225603500, body: "hi", store: store))
		let root = BeamioChatLocalCrypto.localRoot(privateKey: keyBytes(), eoa: eoa, workspace: "default")
		let want = BeamioChatLocalCrypto.sendKeyDerived(idKey: BeamioChatLocalCrypto.idKey(localRoot: root),
		                                                peer: peer, dir: "out", ts: 1767225603500, body: "hi")
		XCTAssertEqual(got, want, "K_id comes from R_db")
		XCTAssertTrue(got.hasPrefix("x"))
	}
}
