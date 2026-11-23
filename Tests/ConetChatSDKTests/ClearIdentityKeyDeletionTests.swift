#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// A,,: clearIdentity checks the recovery source of every owner before anything else. Only
/// when every owner is ok are the copies removed, the session destroyed, the wallet key deleted, the account pointer cleared, and the inbox wiped.
/// A refusal, a busy account and a bad request answer their own code and change nothing: the wallet key, the account pointer, the copies M and N,
/// the scoped record L, the last code, the inbox and the call signals all stay. Synthetic data only.
final class ClearIdentityKeyDeletionTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let other = "0x2222222222222222222222222222222222222222"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
	private let frameHash = "0x" + String(repeating: "7", count: 64)
	private var savedMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var savedWalletMemory: [String: Data]?
	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: NativeCombinationTests.Store!
	private var events: [[String: Any]] = []

	private var callKey: String { BeamioConetChatCallLedger.key(callId: "call-r", sessionId: "sess-r") }

	override func setUpWithError() throws {
		try super.setUpWithError()
		// The recovery-backup flag, the K records and the store items are Keychain items. The test host has no Keychain entitlement (-34018),
		// so the test build keeps them in BeamioChatWalletTestMemory (test build only). No real Keychain or macOS login Keychain is written.
		savedWalletMemory = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		// The backup flag is set for the existing cases; the gate has its own case below.
		BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: account)
		BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: other)
		savedMemory = BeamioChatPgpKeychain.memory
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		savedStore = BeamioNativeWallet.keyStore
		store = NativeCombinationTests.Store()
		store.keys[account] = keyData
		BeamioNativeWallet.keyStore = store
		// The device holds the key of `account`, the signer is that account and the session is ready (G2), as `init` leaves it. The account
		// pointer is the same account.
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
		BeamioConetChatInboxStore.clear()
		BeamioConetChatCallLedger.clear()
	}

	override func tearDown() {
		BeamioRecoveryBackupFlag.clear(eoa: account)
		BeamioConetChatModule.testUnregisterCheck = nil
		BeamioInboxFile.failRemovals = false
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		// setUp may have skipped before saving the stores (no Keychain on this host): then there is nothing to restore.
		if let savedStore { BeamioNativeWallet.keyStore = savedStore }
		if let savedMemory { BeamioChatPgpKeychain.memory = savedMemory }
		BeamioChatWalletTestMemory.items = savedWalletMemory
		BeamioConetChatInboxStore.clear()
		BeamioConetChatCallLedger.clear()
		super.tearDown()
	}

	private func waitUntil(_ timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
		let deadline = Date().addingTimeInterval(timeout)
		while !condition() && Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		return condition()
	}

	/// Sends clearIdentity and returns its answer once it has come.
	private func clearIdentity(_ reqId: Int) -> [String: Any]? {
		BeamioConetChatModule.handleCommand(["type": "clearIdentity", "reqId": reqId], emit: { _ in })
		let answered = waitUntil(20) {
			self.events.contains { ($0["event"] as? [String: Any])?["reqId"] as? Int == reqId }
		}
		XCTAssertTrue(answered, "clearIdentity answers")
		return events.compactMap { $0["event"] as? [String: Any] }.first { $0["reqId"] as? Int == reqId }
	}

	/// clearIdentity without the command gate, for the two-owner cases: the account pointer and the signer may differ there.
	private func clearIdentityWithoutGate(_ reqId: Int) -> [String: Any]? {
		BeamioConetChatModule.testClearIdentity(reqId: reqId)
		let answered = waitUntil(20) {
			self.events.contains { ($0["event"] as? [String: Any])?["reqId"] as? Int == reqId }
		}
		XCTAssertTrue(answered, "clearIdentity answers")
		return events.compactMap { $0["event"] as? [String: Any] }.first { $0["reqId"] as? Int == reqId }
	}

	/// The inbound state a refused clear must keep: one inbox row and one delivered call signal.
	private func seedInboundState() {
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(callKey))
	}

	/// The record of one account: the scoped record L (the recovery source), the copies M and N of it, and the last code of the migration.
	private func seedCopies(of eoa: String, tag: String) {
		XCTAssertTrue(BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-\(tag)\n-----END PGP PRIVATE KEY BLOCK-----",
			publicKeyArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-\(tag)\n-----END PGP PUBLIC KEY BLOCK-----",
			pgpKeyId: "key-\(tag)", routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)))
		let migration = BeamioPgpMigrationImport.KeychainStore()
		let key = BeamioChatPgpKeychain.accountKey(eoa: eoa)
		XCTAssertTrue(migration.writeMarker(account: key, BeamioPgpMigrationImport.Marker(
			fp16: "0123456789abcdef", source: "L", verifiedAt: "2026-11-14T00:00:00Z")))
		XCTAssertTrue(migration.writeStaged(account: key, BeamioPgpMigrationImport.StagedRecord(
			eoa: eoa, privateArmor: [], publicArmor: "synthetic", keyId: "key-\(tag)",
			fingerprint: "00", fp16: "0123456789abcdef", source: "L")))
		XCTAssertTrue(migration.writeLastCode(account: key, "ok"))
	}

	/// Whether the copies M and N of one account are still there.
	private func copiesPresent(_ eoa: String) -> Bool {
		let migration = BeamioPgpMigrationImport.KeychainStore()
		let key = BeamioChatPgpKeychain.accountKey(eoa: eoa)
		return migration.marker(account: key) != nil && migration.staged(account: key) != nil
	}

	/// Whether the scoped record L of one account is still the record it was (its key id names the seeded tag).
	private func legacyRecordKept(_ eoa: String, tag: String) -> Bool {
		BeamioChatPgpKeychain.readOnlyRecord(eoa: eoa)?.pgpKeyId == "key-\(tag)"
	}

	/// The last code of the migration of one account, as it was seeded.
	private func lastCodeKept(_ eoa: String) -> Bool {
		BeamioPgpMigrationImport.KeychainStore().lastCode(account: BeamioChatPgpKeychain.accountKey(eoa: eoa)) == "ok"
	}

	/// Everything a refused, busy or bad-request clear keeps as it was.
	private func assertNothingChanged(_ answer: [String: Any]?, code: String, _ label: String) {
		XCTAssertEqual(answer?["ok"] as? Bool, false, "\(label): not ok")
		XCTAssertEqual(answer?["error"] as? String, code, "\(label): the answer code")
		XCTAssertEqual(store.keys[account], keyData, "\(label): the wallet key stays")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "\(label): the account pointer stays")
		XCTAssertEqual(BeamioConetChatSignBroker.currentSignerEoa(), account, "\(label): the signer stays")
		XCTAssertNotNil(BeamioConetChatModule.testCurrentSession(), "\(label): the session is not destroyed")
		XCTAssertTrue(copiesPresent(account), "\(label): the copies M and N stay")
		XCTAssertTrue(legacyRecordKept(account, tag: "signer"), "\(label): the scoped record L stays")
		XCTAssertTrue(lastCodeKept(account), "\(label): the last code stays")
		XCTAssertEqual(BeamioConetChatInboxStore.list().map { $0.armorHash }, [frameHash], "\(label): the inbox stays")
		XCTAssertEqual(BeamioConetChatCallLedger.state(callKey), .delivered, "\(label): the call signal state stays")
	}

	func testClearIdentityDeletesTheWalletKeyAndClearsThePointerOnlyAfterAnOkUnregistration() {
		let answer = clearIdentity(1300)
		XCTAssertEqual(answer?["ok"] as? Bool, true, "clearIdentity is ok: \(String(describing: answer?["error"]))")
		XCTAssertNil(store.keys[account], "the wallet key of the signer's account is deleted")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the account pointer is cleared after an ok unregistration")
		XCTAssertEqual(BeamioConetChatSignBroker.currentSignerEoa(), "", "the signer is cleared")
		XCTAssertNil(BeamioConetChatModule.testCurrentSession(), "the session is destroyed after an ok unregistration")
	}

	func testARefusedUnregistrationDeletesNothingAndAnswersUnregisterRefused() {
		seedCopies(of: account, tag: "signer")
		seedInboundState()
		BeamioConetChatModule.testUnregisterCheck = { _ in
			BeamioPgpMigrationImport.Outcome(code: "unregister_refused", fp: nil, interrupted: false)
		}
		assertNothingChanged(clearIdentity(1301), code: "unregister_refused", "refused")
	}

	func testABusyAccountDeletesNothingAndAnswersBusy() {
		seedCopies(of: account, tag: "signer")
		seedInboundState()
		BeamioConetChatModule.testUnregisterCheck = { _ in
			BeamioPgpMigrationImport.Outcome(code: "busy", fp: nil, interrupted: false)
		}
		assertNothingChanged(clearIdentity(1302), code: "busy", "busy")
	}

	func testABadRequestDeletesNothingAndAnswersBadRequest() {
		seedCopies(of: account, tag: "signer")
		seedInboundState()
		BeamioConetChatModule.testUnregisterCheck = { _ in
			BeamioPgpMigrationImport.Outcome(code: "bad_request", fp: nil, interrupted: false)
		}
		assertNothingChanged(clearIdentity(1303), code: "bad_request", "bad_request")
	}

	/// two (the signer and the account pointer). The first is ok and the second is refused: nothing is removed, so both
	/// accounts keep their copies M and N, their legacy records L and their last codes.
	func testWithTwoOwnersTheSecondRefusalLeavesBothAccountsCopies() {
		seedCopies(of: account, tag: "signer")
		seedCopies(of: other, tag: "pointer")
		BeamioNativeAccountPointer.set(other)
		seedInboundState()
		BeamioConetChatModule.testUnregisterCheck = { owner in
			owner == self.account
				? BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false)
				: BeamioPgpMigrationImport.Outcome(code: "unregister_refused", fp: nil, interrupted: false)
		}
		let answer = clearIdentityWithoutGate(1304)
		XCTAssertEqual(answer?["error"] as? String, "unregister_refused")
		XCTAssertEqual(answer?["ok"] as? Bool, false)
		XCTAssertTrue(copiesPresent(account), "the signer's copies stay when another owner is refused")
		XCTAssertTrue(copiesPresent(other), "the pointer's copies stay")
		XCTAssertTrue(legacyRecordKept(account, tag: "signer"), "the signer's scoped record L stays")
		XCTAssertTrue(legacyRecordKept(other, tag: "pointer"), "the pointer's scoped record L stays")
		XCTAssertTrue(lastCodeKept(account), "the signer's last code stays")
		XCTAssertTrue(lastCodeKept(other), "the pointer's last code stays")
		XCTAssertEqual(store.keys[account], keyData, "the wallet key stays")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), other, "the account pointer stays")
		XCTAssertNotNil(BeamioConetChatModule.testCurrentSession(), "the session is not destroyed")
		XCTAssertEqual(BeamioConetChatInboxStore.list().map { $0.armorHash }, [frameHash], "the inbox stays")
	}

	/// both are ok. The copies M and N of both go; the scoped record L of both stays.
	func testWithTwoOwnersBothOkRemovesTheCopiesOfBothAndKeepsTheLegacyRecords() {
		seedCopies(of: account, tag: "signer")
		seedCopies(of: other, tag: "pointer")
		BeamioNativeAccountPointer.set(other)
		store.keys[other] = keyData
		let answer = clearIdentityWithoutGate(1305)
		XCTAssertEqual(answer?["ok"] as? Bool, true, "clearIdentity is ok: \(String(describing: answer?["error"]))")
		XCTAssertFalse(copiesPresent(account), "the signer's copies are removed")
		XCTAssertFalse(copiesPresent(other), "the pointer's copies are removed")
		XCTAssertNotNil(BeamioChatPgpKeychain.readOnlyRecord(eoa: account), "the signer's scoped record L stays")
		XCTAssertNotNil(BeamioChatPgpKeychain.readOnlyRecord(eoa: other), "the pointer's scoped record L stays")
		XCTAssertNil(store.keys[account], "the wallet key of the signer is deleted")
		XCTAssertNil(store.keys[other], "the wallet key of the pointer's account is deleted too (item 2)")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the account pointer is cleared")
	}

	/// item 2 ((a)): the account pointer is the last step. The wallet key and the copies go first, the pointer goes after
	/// the inbox wipe, and the reply goes after the pointer.
	func testTheAccountPointerIsTheLastStepOfAClear() {
		seedCopies(of: account, tag: "signer")
		seedInboundState()
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.testClearTrace = []
		defer { BeamioConetChatModule.testClearTrace = nil }
		let answer = clearIdentity(1306)
		XCTAssertEqual(answer?["ok"] as? Bool, true, "clearIdentity is ok: \(String(describing: answer?["error"]))")
		XCTAssertEqual(BeamioConetChatModule.testClearTrace, ["pending", "copies", "keys", "wipe", "marker", "pointer"], "the steps run in this order (the identity_cleared marker goes before the pointer)")
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "the clear_pending marker is cleared with the pointer (item 1)")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the pointer is cleared")
		XCTAssertNil(store.keys[account], "the wallet key is deleted before the pointer")
		XCTAssertFalse(copiesPresent(account), "the copies are removed before the pointer")
	}

	/// item 3 ((a)): an interrupted clear leaves the window: the pointer is set, and the key and the copies are gone. That
	/// state is fail-closed (walletState not_ready). A clear run again completes it: the pointer goes, and the state is clean (walletState absent).
	/// The redo runs through the test entry, which skips the command gate. A G0 state refuses clearIdentity at the gate (see the report).
	func testAnInterruptedClearIsFailClosedAndAClearRunAgainCompletesIt() {
		BeamioNativeAccountPointer.set(account)
		store.keys[account] = nil
		XCTAssertEqual(BeamioNativeWalletStateResolver.resolve(pointer: account, entries: [], markerWithoutRecord: false).state, .notReady,
			"the window (pointer set, no key, no copy) is not_ready")
		BeamioConetChatSignBroker.clearSigner()
		let answer = clearIdentityWithoutGate(1307)
		XCTAssertEqual(answer?["ok"] as? Bool, true, "the redo is ok: \(String(describing: answer?["error"]))")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the redo clears the pointer")
		XCTAssertEqual(BeamioNativeWalletStateResolver.resolve(pointer: "", entries: [], markerWithoutRecord: false).state, .absent,
			"after the redo the state is clean (walletState absent)")
	}

	/// item 1: a refused clear sets no marker: nothing has started, and nothing is removed.
	func testARefusedClearSetsNoClearPendingMarker() {
		BeamioNativeClearPending.clear()
		seedCopies(of: account, tag: "signer")
		seedInboundState()
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.testUnregisterCheck = { _ in
			BeamioPgpMigrationImport.Outcome(code: "unregister_refused", fp: nil, interrupted: false)
		}
		_ = clearIdentity(1308)
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "a refusal sets no marker")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer stays")
	}

	/// item 4: with the device marker set, pgpIdentityCreate ends before any key is generated: one result event,
	/// `not_ready` with state `undetermined`. Nothing is generated, prepared or written.
	func testPgpIdentityCreateWithTheMarkerEndsNotReadyBeforeAnyKey() {
		let device = MarkerOnlyDevice()
		device.state.legacyUnreadable = true
		BeamioShellRecord.testDeviceOverride = device
		defer { BeamioShellRecord.testDeviceOverride = nil }
		var generated = 0
		let savedGenerate = BeamioPGPIdentityCreate.generateKeyPair
		BeamioPGPIdentityCreate.generateKeyPair = { _ in
			generated += 1
			return .failure(NSError(domain: "test", code: 1))
		}
		defer { BeamioPGPIdentityCreate.generateKeyPair = savedGenerate }
		// The answer comes on the command's own emit (not the native observer), so the test collects it there.
		var emitted: [[String: Any]] = []
		// The command names its account as the restore family does (`accountKey` = account:default); without it the command is account_mismatch first.
		BeamioConetChatModule.handleCommand(["type": "pgpIdentityCreate", "reqId": 1309, "idempotencyKey": "marker-key", "accountKey": account + ":default"], emit: { emitted.append($0) })
		// The answers are posted on the main queue: drain it before the check (the same as the chat channel tests).
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		let unwrapped = (emitted + events).map { ($0["event"] as? [String: Any]) ?? $0 }
		let result = unwrapped.first { $0["type"] as? String == "pgpIdentityCreateResult" }
		XCTAssertNotNil(result, "the creation answers one result event")
		XCTAssertEqual(result?["code"] as? String, "not_ready")
		XCTAssertEqual(result?["state"] as? String, "undetermined")
		XCTAssertEqual(generated, 0, "no key is generated while the marker is set")
	}
}

extension ClearIdentityKeyDeletionTests {
	/// item 3: a failed inbox wipe is fail-closed. The pointer and the marker clear_pending stay, and the reply is
	/// clear_incomplete. The redo of the clear completes it later.
	func testAFailedWipeKeepsThePointerAndTheClearPendingMarker() {
		BeamioNativeClearPending.clear()
		seedInboundState()
		BeamioNativeAccountPointer.set(account)
		BeamioInboxFile.failRemovals = true
		let answer = clearIdentity(1310)
		BeamioInboxFile.failRemovals = false
		XCTAssertEqual(answer?["error"] as? String, "clear_incomplete", "the wipe failure is answered as clear_incomplete")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer stays (fail-closed)")
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "clear_pending stays (fail-closed)")
		BeamioNativeClearPending.clear()
		BeamioNativeAccountPointer.set("")
	}
}

/// A device state store in memory, for the device-marker tests (item 4).
private final class MarkerOnlyDevice: BeamioShellRecord.DeviceStateStore {
	var state = BeamioShellRecord.DeviceState()
	func load() -> BeamioShellRecord.DeviceState { state }
	@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
}

extension ClearIdentityKeyDeletionTests {
	/// a failed wallet step of the clear (here the blob key K) answers clear_incomplete at the command, keeps the pointer and clear_pending, and a
	/// redo after the failure completes the clear with ok. Runs on the production keystore, so the wallet steps are the real ones.
	func testAFailedWalletStepAnswersClearIncompleteAndTheRedoCompletes() throws {
		let production = BeamioChatWalletKeychainStore.standard
		// The wallet steps need a Keychain that accepts writes.
		let probe = "0x00000000000000000000000000000000000000ff"
		let writable = production.writeItem(.key, eoa: probe, value: Data(repeating: 1, count: 32))
		production.delete(eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018)")
		BeamioNativeClearPending.clear()
		BeamioNativeWallet.keyStore = production
		defer {
			#if BEAMIO_TEST_HOOKS
			BeamioChatWalletKeychainStore.clearFailStepForTests = nil
			#endif
			_ = production.clearWalletItems(eoa: account)
			BeamioNativeWallet.keyStore = store
			BeamioNativeClearPending.clear()
		}
		_ = production.clearWalletItems(eoa: account)
		_ = production.writeItem(.key, eoa: account, value: keyData)
		_ = production.writeItem(.mnemonic, eoa: account, value: Data("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".utf8))
		BeamioNativeAccountPointer.set(account)
		#if BEAMIO_TEST_HOOKS
		BeamioChatWalletKeychainStore.clearFailStepForTests = "blobKey"
		#endif
		let failed = clearIdentity(1330)
		XCTAssertEqual(failed?["ok"] as? Bool, false)
		XCTAssertEqual(failed?["error"] as? String, "clear_incomplete", "a failed wallet step is clear_incomplete")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer stays")
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "clear_pending stays")
		#if BEAMIO_TEST_HOOKS
		BeamioChatWalletKeychainStore.clearFailStepForTests = nil
		#endif
		let redone = clearIdentity(1331)
		XCTAssertEqual(redone?["ok"] as? Bool, true, "the redo completes the clear")
		XCTAssertEqual(production.itemState(.mnemonic, eoa: account), .absent, "the mnemonic record is removed")
		XCTAssertEqual(production.itemState(.key, eoa: account), .present, "the published walletKey item is kept (the clear deletes no walletKey)")
	}
}

extension ClearIdentityKeyDeletionTests {
	/// (1b),: with W items present and no recovery-backup flag, the clear is refused as unregister_refused before any
	/// removal: the W items, the pointer, and clear_pending stay. With the flag set, the clear completes and the flag is cleared with the items.
	func testWalletItemsWithoutTheBackupFlagAreNotRemoved() throws {
		let production = BeamioChatWalletKeychainStore.standard
		let probe = "0x00000000000000000000000000000000000000ff"
		let writable = production.writeItem(.key, eoa: probe, value: Data(repeating: 1, count: 32))
		production.delete(eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018)")
		BeamioNativeClearPending.clear()
		BeamioNativeWallet.keyStore = production
		defer { BeamioNativeWallet.keyStore = store; _ = production.clearWalletItems(eoa: account); BeamioNativeClearPending.clear() }
		_ = production.clearWalletItems(eoa: account)
		_ = production.writeItem(.key, eoa: account, value: keyData)
		// PY.14 (c): a key-only account fails closed; this case needs a phrase, so the account is not key-only.
		_ = production.writeItem(.mnemonic, eoa: account, value: Data("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".utf8))
		BeamioRecoveryBackupFlag.clear(eoa: account)
		BeamioNativeAccountPointer.set(account)
		let refused = clearIdentity(1340)
		XCTAssertEqual(refused?["error"] as? String, "unregister_refused", "no backup flag: refused")
		XCTAssertEqual(refused?["reason"] as? String, "backup_unconfirmed", "the additional field names the cause; the error code is unchanged")
		XCTAssertEqual(production.itemState(.key, eoa: account), .present, "the W item is not removed")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer stays")
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "no clear_pending is set")
		BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: account)
		let done = clearIdentity(1341)
		XCTAssertEqual(done?["ok"] as? Bool, true, "with the flag the clear completes")
		XCTAssertEqual(production.itemState(.key, eoa: account), .present, "the walletKey is kept by the clear")
		XCTAssertFalse(BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: account), "the flag goes with the W items")
	}
}

extension ClearIdentityKeyDeletionTests {
	/// (§25.52PY.8 第 1 项 (6)): with no account known (no signer, no pointer) and a residual PGP copy present, the clear is refused as
	/// unregister_refused and nothing is removed.
	func testNoAccountWithAResidualCopyIsRefused() {
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeAccountPointer.clear()
		seedCopies(of: other, tag: "residual")
		XCTAssertTrue(copiesPresent(other))
		let answer = clearIdentityWithoutGate(1350)
		XCTAssertEqual(answer?["error"] as? String, "unregister_refused")
		XCTAssertNil(answer?["reason"], "a residual-copy refusal carries no reason (the closed set is key_only, backup_unconfirmed)")
		XCTAssertTrue(copiesPresent(other), "the residual copy is kept")
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "no clear_pending is set")
	}
}

extension ClearIdentityKeyDeletionTests {
	/// §25.52PY.8 第 7 項: the startup redo with no active account clears an account whose C.3 check passes (L present) and keeps one with a W item.
	func testStartupRedoClearsResidualCopiesOfAnAccountWithoutWallet() {
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeAccountPointer.clear()
		seedCopies(of: other, tag: "startup")
		XCTAssertTrue(copiesPresent(other))
		// The sweep is skipped as a whole while any wallet item is on the device (991bd29). setUp leaves two recovery-backup flags (wallet-service items) and a key:
		// first the whole-sweep gate (nothing is cleared), then the device without a wallet item (the account with a passing check is cleared).
		XCTAssertEqual(BeamioPgpMigrationImport.redoResidualCopiesAtStart(activeAccount: "") { _ in false }, [], "a wallet item on the device skips the whole sweep")
		XCTAssertTrue(copiesPresent(other), "the residual copy is kept while the sweep is skipped")
		BeamioRecoveryBackupFlag.clear(eoa: account)
		BeamioRecoveryBackupFlag.clear(eoa: other)
		store.keys[account] = nil
		let cleared = BeamioPgpMigrationImport.redoResidualCopiesAtStart(activeAccount: "") { _ in false }
		XCTAssertTrue(cleared.contains(other.lowercased()), "the account with a passing check is cleared")
		XCTAssertFalse(copiesPresent(other), "M and N are removed")
		XCTAssertTrue(legacyRecordKept(other, tag: "startup"), "L is kept")
	}
}

extension ClearIdentityKeyDeletionTests {
	/// / PY.8 第 5 項: with clear_pending set and a W item present, the startup redo does not run and a wallet command answers not_ready;
	/// when the marker is cleared, the command is no longer blocked.
	func testClearPendingBlocksWalletCommandsUntilItIsCleared() throws {
		let production = BeamioChatWalletKeychainStore.standard
		let probe = "0x00000000000000000000000000000000000000ff"
		let writable = production.writeItem(.key, eoa: probe, value: Data(repeating: 1, count: 32))
		production.delete(eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018)")
		BeamioNativeWallet.keyStore = production
		defer { BeamioNativeWallet.keyStore = store; _ = production.clearWalletItems(eoa: account); BeamioNativeClearPending.clear() }
		_ = production.clearWalletItems(eoa: account)
		_ = production.writeItem(.key, eoa: account, value: keyData)
		BeamioNativeClearPending.set()
		BeamioConetChatModule.resetStartupRedoForTests()
		func command() -> String? {
			var events: [[String: Any]] = []
			BeamioConetChatModule.handleCommand(["type": "walletSignMessage", "reqId": 1360], emit: { events.append(($0["event"] as? [String: Any]) ?? $0) })
			let deadline = Date().addingTimeInterval(3)
			while events.isEmpty && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
			return events.first?["error"] as? String
		}
		XCTAssertEqual(command(), "not_ready", "clear_pending with a W item: the wallet command is not_ready")
		XCTAssertEqual(production.itemState(.key, eoa: account), .present, "the automatic redo did not run")
		_ = production.clearWalletItems(eoa: account)
		BeamioNativeClearPending.clear()
		XCTAssertNotEqual(command(), "not_ready", "after clear_pending is cleared, the command is not blocked")
	}

	/// The closed-set field `reason` of unregister_refused, driven over the harness store: a key-only account is refused with reason key_only and
	/// A key-only account is recognised BEFORE the gate (and before clear_pending): clearIdentity answers {ok:false, error:unregister_refused, reason:key_only}, not the gate's
	/// no_key (project owner's requirement, spec 25.52PY.14 item 4 (c),; Android does the same). Nothing is deleted.
	func testKeyOnlyAccountClearIdentityIsUnregisterRefusedWithReasonKeyOnlyBeforeTheGate() throws {
		let keyOnly = MemoryNativeKeyStore()
		keyOnly.keys[account] = keyData
		BeamioNativeWallet.keyStore = keyOnly
		defer { BeamioNativeWallet.keyStore = store }
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		XCTAssertTrue(BeamioBackupDisplay.isKeyOnlyAccount(eoa: account))
		let before = keyOnly.keys
		for gate in [BeamioConetChatModule.NativeGate.g0, .g1, .g2] {
			BeamioConetChatModule.setNativeGateForTests(account: gate == .g0 ? nil : account, sessionReady: gate == .g2)
			BeamioNativeAccountPointer.set(account)
			let refused = clearIdentity(1343)
			XCTAssertEqual(refused?["ok"] as? Bool, false, "\(gate)")
			XCTAssertEqual(refused?["error"] as? String, "unregister_refused", "\(gate): not the gate's no_key")
			XCTAssertEqual(refused?["reason"] as? String, "key_only", "\(gate)")
		}
		XCTAssertEqual(keyOnly.keys, before, "nothing is removed")
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "no clear_pending is set")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer stays")
	}

	/// the key-only precheck follows a STRICT reading of clear_pending. Unset: a new clear of a key-only account is refused (covered above). Set: the precheck
	/// is skipped and the redo of the clear that began goes on. Cannot be read: refused, nothing is deleted.
	func testKeyOnlyPrecheckWithClearPendingSetSkipsAndWithAnUnreadableMarkerRefuses() throws {
		let keyOnly = MemoryNativeKeyStore()
		keyOnly.keys[account] = keyData
		BeamioNativeWallet.keyStore = keyOnly
		defer { BeamioNativeWallet.keyStore = store; BeamioNativeClearPending.clear() }
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		XCTAssertTrue(BeamioBackupDisplay.isKeyOnlyAccount(eoa: account))
		BeamioNativeAccountPointer.set(account)
		let before = keyOnly.keys
		// unreadable: the marker holds a value that is not a Boolean
		let savedDefaults = BeamioNativeClearPending.defaults
		let memory = BeamioMemoryDefaults()
		memory.set("garbage", forKey: "beamio.native.clear_pending.v1")
		BeamioNativeClearPending.defaults = memory
		XCTAssertEqual(BeamioNativeClearPending.read(), .unreadable)
		let refused = clearIdentity(1350)
		BeamioNativeClearPending.defaults = savedDefaults
		XCTAssertEqual(refused?["ok"] as? Bool, false)
		XCTAssertEqual(refused?["error"] as? String, "unregister_refused", "an unreadable clear_pending refuses")
		XCTAssertEqual(keyOnly.keys, before, "nothing is deleted")
		// set for THIS account: the precheck is skipped and the existing redo path continues the clear that began
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))
		XCTAssertEqual(BeamioNativeClearPending.read(), .set)
		let redone = clearIdentity(1351)
		XCTAssertNotEqual(redone?["reason"] as? String, "key_only", "clear_pending set for this account: the key-only precheck does not refuse the redo")
		XCTAssertNotEqual(redone?["error"] as? String, "unregister_refused", "the redo continues")
		XCTAssertEqual(redone?["ok"] as? Bool, true, "the redo of the recorded account completes the clear")
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "the marker is cleared with the pointer")
		XCTAssertEqual(BeamioNativeClearPending.owners(), .missing, "the owner record goes with the marker")
	}

	// MARK: -: clear_pending is bound to the account(s) of the clear that began

	/// clear_pending recorded for X, then the pointer is switched to Y: a clearIdentity for Y is NOT a redo. Y's checks run as usual (here: Y is key-only, refused with reason
	/// key_only), Y's data is byte for byte unchanged, and the pending clear of X is not consumed by Y.
	func testAPointerSwitchedToAnotherAccountIsNotRedoneAndKeepsItsChecks() throws {
		let y = other
		let keyOnly = MemoryNativeKeyStore()
		keyOnly.keys[y] = keyData
		BeamioNativeWallet.keyStore = keyOnly
		defer { BeamioNativeWallet.keyStore = store; BeamioNativeClearPending.clear() }
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))   // the clear of X began
		BeamioNativeAccountPointer.set(y)                                  // then the pointer was switched to Y (a page provisioning)
		BeamioConetChatSignBroker.setSignerEoa(y)
		XCTAssertTrue(BeamioBackupDisplay.isKeyOnlyAccount(eoa: y))
		let before = keyOnly.keys
		let refused = clearIdentity(1352)
		XCTAssertEqual(refused?["ok"] as? Bool, false)
		XCTAssertEqual(refused?["error"] as? String, "unregister_refused", "Y is judged as a new clear: its checks apply")
		XCTAssertEqual(refused?["reason"] as? String, "key_only")
		XCTAssertEqual(keyOnly.keys, before, "Y's data is unchanged")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), y, "Y's pointer stays")
		XCTAssertEqual(BeamioNativeClearPending.owners(), .list([account]), "the pending clear of X is untouched")
	}

	/// the marker belongs to X and the current account is Y; Y passes all of its own checks. The answer is only clear_incomplete: nothing is deleted or written,
	/// the data of X and Y, the pointer and the marker (with its owner record) are all byte for byte unchanged.
	func testWhenTheMarkerBelongsToAnotherAccountAndTheCurrentOnePassesTheAnswerIsClearIncompleteAndNothingChanges() throws {
		let x = other, y = account   // Y is the current account of the harness and passes its checks (the backup flag is set for both)
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		store.keys[x] = keyData
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [x]))
		BeamioNativeAccountPointer.set(y)
		let keysBefore = store.keys
		let ownersBefore = BeamioNativeClearPending.owners()
		let answer = clearIdentity(1354)
		XCTAssertEqual(answer?["ok"] as? Bool, false)
		XCTAssertEqual(answer?["error"] as? String, "clear_incomplete", "Y passes, but X's clear must end before Y's begins")
		XCTAssertEqual(store.keys, keysBefore, "X's and Y's data are unchanged")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), y, "the pointer is unchanged")
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "the marker stays")
		XCTAssertEqual(BeamioNativeClearPending.owners(), ownersBefore, "the owner record is unchanged")
		BeamioNativeClearPending.clear()
	}

	// MARK: - (owner, G0 plan B): six positive and negative cases (item 6)

	/// Case 1. G0 (no current account: no signer, no pointer) and the marker belongs to X: a manual clearIdentity does not continue X's clear. It answers clear_incomplete, and nothing is
	/// deleted or written: X's key, copies, last code, the marker and its owner record all stay.
	func testG0ManualClearWithAnOwnedMarkerAnswersClearIncompleteAndDeletesNothing() throws {
		defer { BeamioNativeClearPending.clear() }
		seedCopies(of: account, tag: "signer")
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeAccountPointer.clear()
		let keysBefore = store.keys
		let answer = clearIdentityWithoutGate(1401)
		XCTAssertEqual(answer?["ok"] as? Bool, false)
		XCTAssertEqual(answer?["error"] as? String, "clear_incomplete")
		XCTAssertEqual(store.keys, keysBefore, "no key is deleted")
		XCTAssertTrue(copiesPresent(account), "the copies stay")
		XCTAssertTrue(legacyRecordKept(account, tag: "signer"), "the scoped record stays")
		XCTAssertTrue(lastCodeKept(account), "the last code stays")
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "the marker stays")
		XCTAssertEqual(BeamioNativeClearPending.owners(), .list([account]), "the owner record stays")
	}

	/// Case 2. Cold start, the marker belongs to X, X is the only account on the device and every read succeeds: the redo finishes X's clear and removes the marker.
	func testColdStartWithAnOwnedMarkerAndNoOtherAccountsFinishesTheClear() throws {
		defer { BeamioNativeClearPending.clear() }
		seedCopies(of: account, tag: "signer")
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.resetStartupRedoForTests()
		BeamioConetChatModule.runStartupClearRedoOnce()
		XCTAssertTrue(waitUntil(10) { !BeamioNativeClearPending.isSet() }, "the redo finished and removed the marker")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the pointer of X went with the finish")
		// (this key store double removes a key on `delete`; the production store keeps walletKey in clearWalletItems, which the identity-cleared tests assert)
		XCTAssertFalse(copiesPresent(account), "X's copies M and N were removed")
	}

	/// Case 3. Cold start, the marker belongs to X, and another account Y has an entry (a wallet key, a PGP copy, or the pointer): nothing is deleted or written and the marker stays.
	func testColdStartWithAnOwnedMarkerAndAnotherAccountsEntryDeletesNothing() throws {
		let y = other
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		for variant in ["key", "copies", "pointer"] {
			seedCopies(of: account, tag: "signer")
			store.keys[y] = nil
			BeamioNativeAccountPointer.set(account)
			switch variant {
			case "key": store.keys[y] = keyData
			case "copies": seedCopies(of: y, tag: "other")
			default: BeamioNativeAccountPointer.set(y)
			}
			XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))
			let keysBefore = store.keys
			let pointerBefore = BeamioNativeAccountPointer.get()
			BeamioConetChatModule.resetStartupRedoForTests()
			BeamioConetChatModule.runStartupClearRedoOnce()
			RunLoop.current.run(until: Date().addingTimeInterval(0.3))
			XCTAssertTrue(BeamioNativeClearPending.isSet(), "\(variant): the marker stays")
			XCTAssertEqual(BeamioNativeClearPending.owners(), .list([account]), "\(variant): the owner record stays")
			XCTAssertEqual(store.keys, keysBefore, "\(variant): no key is deleted")
			XCTAssertEqual(BeamioNativeAccountPointer.get(), pointerBefore, "\(variant): the pointer is unchanged")
			XCTAssertTrue(copiesPresent(account), "\(variant): X's copies stay")
			if variant == "copies" { XCTAssertTrue(copiesPresent(y), "Y's copies stay") }
			BeamioNativeClearPending.clear()
		}
	}

	/// Case 4. Cold start, the marker belongs to X, and a read fails (the key owners cannot be enumerated): nothing is deleted or written, the marker stays.
	func testColdStartWithAnOwnedMarkerAndAFailedReadDeletesNothing() throws {
		defer { BeamioNativeClearPending.clear(); BeamioNativeWallet.keyStore = store }
		seedCopies(of: account, tag: "signer")
		let failing = AccountSelectVectorStore()
		failing.enumOk = false
		BeamioNativeWallet.keyStore = failing
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.resetStartupRedoForTests()
		BeamioConetChatModule.runStartupClearRedoOnce()
		RunLoop.current.run(until: Date().addingTimeInterval(0.3))
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "the marker stays")
		XCTAssertEqual(failing.deleteCalls, 0, "nothing is deleted")
		XCTAssertEqual(failing.writeCalls, 0, "nothing is written")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer is unchanged")
		XCTAssertTrue(copiesPresent(account), "the copies stay")
	}

	/// Case 5. An Unknown marker (no owner record, or one that cannot be read): the startup redo and a manual clearIdentity delete nothing and write nothing; the marker stays.
	func testAnUnknownMarkerDeletesNothingAtColdStartOrByAManualClear() throws {
		defer { BeamioNativeClearPending.clear() }
		seedCopies(of: account, tag: "signer")
		BeamioNativeClearPending.set()   // no owner record
		BeamioNativeAccountPointer.set(account)
		let keysBefore = store.keys
		BeamioConetChatModule.resetStartupRedoForTests()
		BeamioConetChatModule.runStartupClearRedoOnce()
		RunLoop.current.run(until: Date().addingTimeInterval(0.3))
		XCTAssertTrue(BeamioNativeClearPending.isSet())
		XCTAssertEqual(store.keys, keysBefore)
		XCTAssertTrue(copiesPresent(account))
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeAccountPointer.clear()
		let manual = clearIdentityWithoutGate(1405)
		XCTAssertEqual(manual?["error"] as? String, "clear_incomplete")
		XCTAssertEqual(store.keys, keysBefore)
		XCTAssertTrue(copiesPresent(account))
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "the marker stays")
	}

	/// Case 6. The current account is X (signer and pointer name X): a clearIdentity continues X's clear by the existing path and finishes it.
	func testWhenTheCurrentAccountIsTheMarkedOneAClearIdentityContinuesTheClear() throws {
		defer { BeamioNativeClearPending.clear() }
		BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [account]))
		BeamioNativeAccountPointer.set(account)
		let answer = clearIdentityWithoutGate(1406)
		XCTAssertEqual(answer?["ok"] as? Bool, true, "the redo is ok: \(String(describing: answer?["error"]))")
		XCTAssertFalse(BeamioNativeClearPending.isSet(), "the marker is cleared")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the pointer is cleared")
		// (this key store double removes a key on `delete`; the production store keeps walletKey in clearWalletItems, which the identity-cleared tests assert)
	}

	/// A marker with no owner record (an older marker) is never a redo and deletes nothing: clearIdentity answers clear_incomplete, the startup redo does not run.
	func testAMarkerWithoutAnOwnerRecordDeletesNothing() throws {
		BeamioNativeClearPending.set()   // no owner record
		XCTAssertEqual(BeamioNativeClearPending.owners(), .missing)
		BeamioNativeAccountPointer.set(account)
		let keysBefore = store.keys
		let refused = clearIdentity(1353)
		XCTAssertEqual(refused?["ok"] as? Bool, false)
		XCTAssertEqual(refused?["error"] as? String, "clear_incomplete")
		XCTAssertEqual(store.keys, keysBefore, "nothing is deleted")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account)
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "the marker stays")
		BeamioConetChatModule.resetStartupRedoForTests()
		BeamioConetChatModule.runStartupClearRedoOnce()
		XCTAssertEqual(store.keys, keysBefore, "the startup redo does not run without an owner record")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account)
		BeamioNativeClearPending.clear()
	}

	// MARK: - identity-clear-g0-plan-b-vectors.v1.json (14 cases), one verdict line per case

	// MARK: - P3: key-only refusal and the identity_cleared marker

	/// GB-P3b and its counterparts: a published key-only record stays on the device. With no current account and no clear_pending marker, the answer is the gate's no_key
	/// only when identity_cleared is strictly read as set; unset, unreadable and malformed are refused as key_only (unregister_refused, reason key_only). A current account (GB-P3a)
	/// is always refused. Nothing is deleted or written in any of them.
	func testKeyOnlyClearAtG0IsNoKeyOnlyWhenTheIdentityClearedMarkerIsStrictlySet() throws {
		defer { BeamioNativeWallet.keyStore = store; BeamioNativeClearPending.clear() }
		func run(_ label: String, current: Bool, setup: (MemoryNativeKeyStore) -> Void, expectError: String, expectReason: String?, _ reqId: Int) {
			let k = MemoryNativeKeyStore()
			k.keys[account] = keyData
			setup(k)
			BeamioNativeWallet.keyStore = k
			BeamioNativeClearPending.clear()
			BeamioNativeAccountPointer.clear()
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			if current {
				BeamioNativeAccountPointer.set(account)
				BeamioConetChatSignBroker.setSignerEoa(account)
				BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
			}
			let keysBefore = k.keys, rawBefore = k.rawAccounts
			let answer = clearIdentity(reqId)
			XCTAssertEqual(answer?["ok"] as? Bool, false, "\(label)")
			XCTAssertEqual(answer?["error"] as? String, expectError, "\(label): the answer")
			XCTAssertEqual(answer?["reason"] as? String, expectReason, "\(label): the reason")
			XCTAssertEqual(k.keys, keysBefore, "\(label): nothing is deleted")
			XCTAssertEqual(k.rawAccounts, rawBefore, "\(label): nothing is written")
		}
		// strictly set -> no_key (the gate)
		run("set", current: false, setup: { XCTAssertTrue(BeamioIdentityCleared.record(accounts: [self.account], store: $0)) }, expectError: "no_key", expectReason: nil, 1601)
		// never cleared (unset) -> refused
		run("unset", current: false, setup: { _ in }, expectError: "unregister_refused", expectReason: "key_only", 1602)
		// unreadable or malformed marker: never an exemption (not strictly set). Here the same unreadable marker also makes the account listing fail closed, so the key-only judgement itself is
		// unknown and the command is not_ready (retryable) at the gate instead of unregister_refused. It is still never no_key, and nothing is deleted or written.
		run("unreadable", current: false, setup: { k in
			XCTAssertTrue(BeamioIdentityCleared.record(accounts: [self.account], store: k))
			k.failRawReadAccounts = [BeamioIdentityCleared.itemName]
		}, expectError: "not_ready", expectReason: nil, 1603)
		run("malformed", current: false, setup: { $0.rawAccounts[BeamioIdentityCleared.itemName] = Data("not json".utf8) }, expectError: "not_ready", expectReason: nil, 1604)
		// the marker item stays present after a restore lifts the account, so "set" alone proves nothing. A key-only account restored after the clear is refused as key_only.
		run("restored after the clear", current: false, setup: { k in
			XCTAssertTrue(BeamioIdentityCleared.record(accounts: [self.account], store: k))
			BeamioIdentityCleared.lift(self.account, store: k)
			XCTAssertTrue(BeamioIdentityCleared.isSetStrict(store: k), "the marker item is still present")
		}, expectError: "unregister_refused", expectReason: "key_only", 1606)
		// another key record the marker does not ignore (a second account on the device): not the clear's published copy, refused
		run("another key record", current: false, setup: { k in
			XCTAssertTrue(BeamioIdentityCleared.record(accounts: [self.account], store: k))
			k.keys[self.other] = self.keyData
		}, expectError: "unregister_refused", expectReason: "key_only", 1607)
		// counterexamples that must never answer no_key (the device holds more than the published copy): a mnemonic account (also what a locked wallet looks like), a published copy
		// that cannot be read. They are refused or not_ready, and nothing is deleted or written.
		for (label, id) in [("mnemonic account present", 1608), ("published copy unreadable", 1609)] {
			let k = MemoryNativeKeyStore()
			let acct = ValidTestAccounts.accountA
			if label.hasPrefix("mnemonic") { ValidTestAccounts.install(k) } else { k.keys[acct.eoa] = acct.key; k.failKeyReadOwners = [acct.eoa] }
			XCTAssertTrue(BeamioIdentityCleared.record(accounts: [acct.eoa], store: k))
			BeamioNativeWallet.keyStore = k
			BeamioNativeClearPending.clear(); BeamioNativeAccountPointer.clear(); BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			let keysBefore = k.keys
			let answer = clearIdentity(id)
			XCTAssertEqual(answer?["ok"] as? Bool, false, label)
			XCTAssertNotEqual(answer?["error"] as? String, "no_key", "\(label): never no_key")
			XCTAssertTrue(["unregister_refused", "not_ready"].contains(answer?["error"] as? String ?? ""), "\(label): refused or not_ready, got \(String(describing: answer?["error"]))")
			XCTAssertEqual(k.keys, keysBefore, "\(label): nothing is deleted")
		}
		// a current account is refused even when the marker is set (GB-P3a)
		run("current account, set", current: true, setup: { XCTAssertTrue(BeamioIdentityCleared.record(accounts: [self.account], store: $0)) }, expectError: "unregister_refused", expectReason: "key_only", 1605)
	}

	/// Drives the 14 cases of the G0-B vector file (identity-clear-g0-plan-b-vectors.v1.json), set IDENTITY_CLEAR_G0B_VECTORS=<path>. X is the harness account, Y `other`, Z a third account.
	/// Prints `[GB-CASE] <id> PASS|FAIL|N/A <note>`. N/A (GB-07a only) is a state iOS cannot produce, never counted as PASS.
	func testTheG0PlanBVectorCases() throws {
		guard let path = ProcessInfo.processInfo.environment["IDENTITY_CLEAR_G0B_VECTORS"] else {
			throw XCTSkip("set IDENTITY_CLEAR_G0B_VECTORS to interface/protocol/identity-clear-g0-plan-b-vectors.v1.json")
		}
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 20)
		let x = account, y = other, z = "0x3333333333333333333333333333333333333333"
		var reqId = 1500
		// The manual cases model a running process: the once-per-process cold-start redo has already run (the first command through the entry point would otherwise run it, and with a
		// marker set for X and nothing else on the device it would legitimately finish X's clear before the manual command is judged; that is the coldStart phase, not these cases).
		BeamioNativeClearPending.clear()
		BeamioConetChatModule.resetStartupRedoForTests()
		BeamioConetChatModule.runStartupClearRedoOnce()
		RunLoop.current.run(until: Date().addingTimeInterval(0.5))
		for c in cases {
			reqId += 1
			let id = c["id"] as? String ?? "?"
			let st = c["state"] as? [String: Any] ?? [:]
			let expect = c["expect"] as? [String: Any] ?? [:]
			let marker = st["marker"] as? [String: Any] ?? [:]
			let kind = marker["kind"] as? String ?? "absent"
			let current = st["currentAccount"] as? String
			let phase = c["phase"] as? String ?? ""
			let readFailure = st["readFailure"] as? String ?? "none"
			let failuresBefore = testRun?.failureCount ?? 0
			var note = ""
			// fresh world
			BeamioNativeClearPending.clear()
			BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
			BeamioPgpMigrationImport.KeychainStore.enumerationFailsForTests = false
			BeamioNativeWallet.keyStore = store
			store.keys = [x: keyData]
			BeamioNativeAccountPointer.clear()
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.testUnregisterCheck = { _ in BeamioPgpMigrationImport.Outcome(code: "ok", fp: nil, interrupted: false) }
			seedCopies(of: x, tag: "signer")
			var keyOnlyStore: MemoryNativeKeyStore?
			var failing: AccountSelectVectorStore?
			if st["keyOnly"] as? Bool == true || st["publishedCopiesKept"] as? Bool == true {
				let k = MemoryNativeKeyStore()
				k.keys[x] = keyData   // a published key-only record: a key and no mnemonic
				// GB-P3b: the clear completed, so the identity_cleared marker is set; GB-P3a has a current account and is refused whatever the marker says
				// v2 `identityCleared`: set = the marker is written; unreadable = written and then its read fails; unset = never cleared
				switch st["identityCleared"] as? String ?? "unset" {
				case "set": XCTAssertTrue(BeamioIdentityCleared.record(accounts: [x], store: k))
				case "unreadable": XCTAssertTrue(BeamioIdentityCleared.record(accounts: [x], store: k)); k.failRawReadAccounts = [BeamioIdentityCleared.itemName]
				case "invalid": k.rawAccounts[BeamioIdentityCleared.itemName] = Data("not json".utf8)   // content invalid: treated as unreadable
				default: break
				}
				// v3 walletEntities keyOnlyAccountRestored (GB-P3e): the key-only account was restored after the clear, so the marker no longer ignores it (lifted); the marker item stays present
				if st["walletEntities"] as? String == "keyOnlyAccountRestored" { BeamioIdentityCleared.lift(x, store: k) }
				// v3 publishedCopiesReadable false (GB-P3f): the published copy cannot be read
				if st["publishedCopiesReadable"] as? Bool == false { k.failKeyReadOwners = [x] }
				keyOnlyStore = k
				BeamioNativeWallet.keyStore = k
			}
			switch current {
			case "X": BeamioNativeAccountPointer.set(x); BeamioConetChatSignBroker.setSignerEoa(x)
			case "Y": store.keys[y] = keyData; BeamioNativeAccountPointer.set(y); BeamioConetChatSignBroker.setSignerEoa(y)
			default: break
			}
			if st["otherAccountEntries"] as? Bool == true { store.keys[z] = keyData; seedCopies(of: z, tag: "other") }
			switch readFailure {
			case "walletEnumeration": let f = AccountSelectVectorStore(); f.enumOk = false; failing = f; BeamioNativeWallet.keyStore = f
			case "otherAccountProbe": let f = AccountSelectVectorStore(); f.mnemonicEnumFails = true; f.rows = [AccountSelectVectorStore.Row(eoa: x, created: nil, valid: true, kind: "key", legacy: false)]; failing = f; BeamioNativeWallet.keyStore = f
			case "chatEnumeration": BeamioPgpMigrationImport.KeychainStore.enumerationFailsForTests = true
			default: break
			}
			switch kind {
			case "owned": XCTAssertTrue(BeamioNativeClearPending.set(owners: [x]))
			case "unknown", "noAccount": BeamioNativeClearPending.set()   // iOS keeps no separate NoAccount marker: a marker with no owner record
			case "flagUnreadable": BeamioNativeClearPending.defaults.set("garbage", forKey: "beamio.native.clear_pending.v1")   // v4 GB-05c: the marker itself is not a Boolean (the .unreadable reading)
			default: break
			}
			let keysBefore = store.keys, pointerBefore = BeamioNativeAccountPointer.get()
			let ownersBefore = BeamioNativeClearPending.owners()
			var verdict = ""
			BeamioConetChatModule.testClearTrace = []
			defer { BeamioConetChatModule.testClearTrace = nil }
			if phase == "coldStart" {
				BeamioConetChatModule.resetStartupRedoForTests()
				BeamioConetChatModule.runStartupClearRedoOnce()
				RunLoop.current.run(until: Date().addingTimeInterval(0.4))
				let finished = !BeamioNativeClearPending.isSet() && !copiesPresent(x)
				let untouched = BeamioNativeClearPending.isSet() && BeamioNativeClearPending.owners() == ownersBefore && copiesPresent(x) && store.keys == keysBefore
					&& BeamioNativeAccountPointer.get() == pointerBefore && (failing.map { $0.deleteCalls == 0 && $0.writeCalls == 0 } ?? true)
				switch expect["outcome"] as? String {
				case "finished":
					if kind == "noAccount" {
						// item 1: N/A on iOS. A clear that starts with no account cannot write its marker (an empty owner record fails the read-back and the marker is removed), so
						// a NoAccount marker is unreachable here; a marker with no owner record is Unknown and is left untouched (conservative). No marker form is added. Android follows the vector.
						verdict = untouched ? "N/A" : "FAIL"
						note = "unreachable on iOS (no NoAccount marker is ever written; an unowned marker is Unknown): untouched, accepted"
					} else if finished { verdict = "PASS" } else { verdict = "FAIL" }
				default: verdict = untouched ? "PASS" : "FAIL"
				}
				if expect["otherAccountsUntouched"] as? Bool == true { XCTAssertEqual(store.keys[z], keysBefore[z], "\(id): other accounts untouched"); XCTAssertEqual(copiesPresent(z), st["otherAccountEntries"] as? Bool == true) }
				if st["otherAccountEntries"] as? Bool == true { XCTAssertTrue(copiesPresent(z), "\(id): Z's copies stay") }
			} else {
				let answer: [String: Any]?
				if id.hasPrefix("GB-P3") || id == "GB-01b" || id == "GB-05c" { answer = clearIdentity(reqId) } else { answer = clearIdentityWithoutGate(reqId) }
				let want = expect["answer"] as? String ?? ""
				let got = (answer?["ok"] as? Bool == true) ? "ok" : (answer?["error"] as? String ?? "?")
				// v3 answerAnyOf / answerNotIn: the answer must be one of the allowed (code, optional reason) pairs and none of the forbidden codes
				if let anyOf = expect["answerAnyOf"] as? [[String: Any]] {
					let notIn = expect["answerNotIn"] as? [String] ?? []
					let allowed = anyOf.contains { item in
						(item["answer"] as? String) == got && ((item["reason"] as? String).map { $0 == answer?["reason"] as? String } ?? true)
					}
					// v4: reasonAllowed ("absent" = no reason) and reasonNotIn bound the top-level reason of unregister_refused; marker "unknown" = the flag is left byte for byte as it was
					let reasonGot = answer?["reason"] as? String
					let reasonNotIn = expect["reasonNotIn"] as? [String] ?? []
					let reasonOk = !(reasonGot.map { reasonNotIn.contains($0) } ?? false) && anyOf.contains { item in
						guard (item["answer"] as? String) == got, let allowedReasons = item["reasonAllowed"] as? [String] else { return true }
						return allowedReasons.contains(reasonGot ?? "absent")
					}
					let flagKept = kind == "flagUnreadable" ? (BeamioNativeClearPending.defaults.object(forKey: "beamio.native.clear_pending.v1") as? String) == "garbage" : !BeamioNativeClearPending.isSet()
					let unchangedSet = (keyOnlyStore?.keys ?? store.keys) == (keyOnlyStore?.keys ?? keysBefore) && BeamioNativeAccountPointer.get() == pointerBefore && flagKept
					verdict = allowed && reasonOk && !notIn.contains(got) && unchangedSet ? "PASS" : "FAIL"
					note = verdict == "PASS" ? "answered \(got)\(answer?["reason"].map { "/" + String(describing: $0) } ?? "") (in the allowed set)" : "answered \(got) reason=\(String(describing: answer?["reason"])), outside the allowed set or state changed"
					BeamioNativeClearPending.clear()
					BeamioPgpMigrationImport.KeychainStore.enumerationFailsForTests = false
					BeamioNativeWallet.keyStore = store
					if verdict == "FAIL" { XCTFail("\(id): \(note)") }
					print("[GB-CASE] \(id) \(verdict) \(note)")
					continue
				}
				// GB-P3c (item 3): an identity_cleared that cannot be read allows unregister_refused/key_only or not_ready; both delete and write nothing and neither exempts.
				let p3cAllowedNotReady = id == "GB-P3c" && got == "not_ready"
				if let wantReason = expect["reason"] as? String, !p3cAllowedNotReady { XCTAssertEqual(answer?["reason"] as? String, wantReason, "\(id): reason") }
				let deletedNothing = BeamioNativeClearPending.isSet() == (expect["marker"] as? String == "kept") || expect["marker"] as? String == "cleared"
				let unchanged = (keyOnlyStore?.keys ?? store.keys) == (keyOnlyStore?.keys ?? keysBefore) && copiesPresent(x) && BeamioNativeAccountPointer.get() == pointerBefore
				if got == want || p3cAllowedNotReady {
					if p3cAllowedNotReady { note = "not_ready (allowed with unregister_refused/key_only by item 3)" }
					if want == "ok" { verdict = (!BeamioNativeClearPending.isSet() && !copiesPresent(x)) ? "PASS" : "FAIL" }
					else {
						verdict = (deletedNothing && unchanged && BeamioNativeClearPending.isSet() == (expect["marker"] as? String == "kept")) ? "PASS" : "FAIL"
						if verdict == "FAIL" { note = "answered \(got) as expected but state check failed: deletedNothing=\(deletedNothing) unchanged=\(unchanged) markerSet=\(BeamioNativeClearPending.isSet()) copiesX=\(copiesPresent(x)) pointerSame=\(BeamioNativeAccountPointer.get() == pointerBefore)" }
					}
					if id.hasPrefix("GB-P3"), id != "GB-P3b" { XCTAssertNotEqual(got, "no_key", "\(id): only GB-P3b is exempt") }
				} else {
					verdict = "FAIL"; note = "answered \(got), expected \(want) \(String(describing: answer)) owners=\(String(describing: BeamioNativeClearPending.owners())) read=\(BeamioNativeClearPending.read()) trace=\(BeamioConetChatModule.testClearTrace ?? [])"
				}
			}
			BeamioNativeClearPending.clear()
			BeamioPgpMigrationImport.KeychainStore.enumerationFailsForTests = false
			BeamioNativeWallet.keyStore = store
			if verdict == "FAIL" { XCTFail("\(id): \(note)") }
			_ = failuresBefore
			print("[GB-CASE] \(id) \(verdict) \(note)")
		}
	}
}
#endif


extension ClearIdentityKeyDeletionTests {
	/// PY.14 (c): a private-key-only account (no phrase) fails closed, even with the backup flag set: nothing is removed and the clear answers
	/// `unregister_refused`.
	func testKeyOnlyAccountIsRefusedEvenWithTheFlag() throws {
		let production = BeamioChatWalletKeychainStore.standard
		let probe = "0x00000000000000000000000000000000000000ff"
		let writable = production.writeItem(.key, eoa: probe, value: Data(repeating: 1, count: 32))
		production.delete(eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018)")
		BeamioNativeClearPending.clear()
		BeamioNativeWallet.keyStore = production
		defer { BeamioNativeWallet.keyStore = store; _ = production.clearWalletItems(eoa: account); BeamioRecoveryBackupFlag.clear(eoa: account); BeamioNativeClearPending.clear() }
		_ = production.clearWalletItems(eoa: account)
		_ = production.writeItem(.key, eoa: account, value: keyData)
		BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: account)
		BeamioNativeAccountPointer.set(account)
		XCTAssertTrue(BeamioBackupDisplay.isKeyOnlyAccount(eoa: account))
		let refused = clearIdentity(1342)
		// A key-only account is no account since Y.163 items 31 and 32 (G0): the gate refuses with no_key before the unregister check (PY.14(c)) is reached. Fail closed either way.
		// a key-only account is recognised before the gate: unregister_refused with reason key_only (spec 25.52PY.14 item 4 (c)), not the gate's no_key
		XCTAssertEqual(refused?["error"] as? String, "unregister_refused")
		XCTAssertEqual(refused?["reason"] as? String, "key_only")
		XCTAssertEqual(production.itemState(.key, eoa: account), .present, "the key-only W item is not removed")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account, "the pointer stays")
		XCTAssertFalse(BeamioNativeClearPending.isSet())
	}
}
