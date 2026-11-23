#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The silent cleanup core (v193 section 213.5, eight cases; v196 ack shape; vector accountCleanupOld v3). The command is registered (AccountCleanupCommandTests drive it through the bridge).
/// Synthetic accounts only.
final class AccountCleanupTests: XCTestCase {
	private let new = "0x1111111111111111111111111111111111111111"
	private let old = "0x2222222222222222222222222222222222222222"
	private var store: Set<String> = []   // "owner|name"
	private var deleteCalls = 0
	private var failDelete: Set<String> = []

	private func env(gate: Bool = true, pointer: String? = nil, derived: String?? = nil, newState: BeamioMnemonicAccountState = .valid,
	                 newRecord: BeamioChatWalletKeyRecordState = .present, accounts: [String]?? = nil, oldItemsListed: Bool = true) -> BeamioAccountCleanup.Environment {
		BeamioAccountCleanup.Environment(
			gatePassed: { gate },
			activeSnapshot: { (pointer ?? self.new, derived ?? self.new) },
			mnemonicState: { $0 == self.new ? newState : .valid },
			keyRecordState: { $0 == self.new ? newRecord : .present },
			accounts: { accounts ?? [self.new, self.old] },
			itemsOfOldAccount: { owner in
				oldItemsListed ? self.store.filter { $0.hasPrefix(owner + "|") }.map { BeamioAccountCleanup.Item(owner: owner, name: String($0.split(separator: "|")[1])) }.sorted { $0.name < $1.name } : nil
			},
			delete: { item in
				self.deleteCalls += 1
				if self.failDelete.contains(item.name) { return false }
				self.store.remove("\(item.owner)|\(item.name)")
				return true
			}
		)
	}

	private func run(_ e: BeamioAccountCleanup.Environment, key: String? = nil, idem: String = "idem-1") -> BeamioAccountCleanup.Answer {
		BeamioAccountCleanup.run(accountKey: key ?? new, idempotencyKey: idem, env: e)
	}

	override func setUp() { super.setUp(); store = ["\(old)|a", "\(old)|b", "\(new)|keep"]; deleteCalls = 0; failDelete = [] }

	// 1 success: a silent cleanup of the old account's own items, the new account's kept
	func testCase1SuccessCleansTheOldAndKeepsTheNew() {
		let a = run(env())
		XCTAssertEqual(a, BeamioAccountCleanup.Answer(ok: true, error: nil, cleanupPending: false, keptUnattributed: 0, deleted: 2))
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// 2 a failed or incomplete recovery sends no confirmation command: there is no run, so nothing is deleted (the core is only reached by the command)
	func testCase2NoCommandNoDeletion() {
		XCTAssertEqual(deleteCalls, 0)
		XCTAssertEqual(store.count, 3)
	}

	// 3 a read-back that cannot be read: not_ready, nothing deleted
	func testCase3ReadBackFailuresAreNotReadyAndKeepEverything() {
		for e in [env(derived: .some(nil)), env(newState: .unreadable), env(newRecord: .unreadable), env(accounts: .some(nil))] {
			let a = run(e)
			XCTAssertEqual(a.ok, false)
			XCTAssertEqual(a.error, "not_ready")
			XCTAssertEqual(a.cleanupPending, false)
		}
		XCTAssertEqual(deleteCalls, 0)
		XCTAssertEqual(store.count, 3)
	}

	// 4 the page's address is not the native one: account_mismatch, nothing deleted
	func testCase4AnAddressThatDoesNotMatchIsAccountMismatch() {
		XCTAssertEqual(run(env(derived: .some(old))).error, "account_mismatch")
		XCTAssertEqual(run(env(pointer: old)).error, "account_mismatch")
		XCTAssertEqual(run(env(newState: .invalid)).error, "account_mismatch")
		XCTAssertEqual(run(env(newRecord: .absent)).error, "account_mismatch")
		XCTAssertEqual(run(env(), key: old).error, "account_mismatch", "a page address that is another account")
		XCTAssertEqual(deleteCalls, 0)
		XCTAssertEqual(store.count, 3)
	}

	// 5 a repeated callback: the same idempotencyKey gives the same result and the second run deletes nothing more
	func testCase5ARepeatedRunDeletesNothingMore() {
		XCTAssertEqual(run(env()).deleted, 2)
		let calls = deleteCalls
		let again = run(env())
		XCTAssertEqual(again, BeamioAccountCleanup.Answer(ok: true, error: nil, cleanupPending: false, keptUnattributed: 0, deleted: 0))
		XCTAssertEqual(deleteCalls, calls)
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// 6 an item that belongs to nobody is kept and counted, never deleted
	func testCase6UnattributedItemsAreKeptAndCounted() {
		var e = env()
		let listed = e.itemsOfOldAccount
		e.itemsOfOldAccount = { owner in (listed(owner) ?? []) + [BeamioAccountCleanup.Item(owner: "someone-else", name: "stray")] }
		let a = run(e)
		XCTAssertEqual(a.ok, true)
		XCTAssertEqual(a.keptUnattributed, 1)
		XCTAssertEqual(a.deleted, 2)
	}

	// 7 the new account's wallet, chat and page records are never deleted, even when mislisted under an old account
	func testCase7TheNewAccountIsNeverDeleted() {
		var e = env()
		let listed = e.itemsOfOldAccount
		e.itemsOfOldAccount = { owner in (listed(owner) ?? []) + [BeamioAccountCleanup.Item(owner: self.new, name: "wallet"), BeamioAccountCleanup.Item(owner: self.new, name: "chat")] }
		let a = run(e)
		XCTAssertEqual(a.keptUnattributed, 2)
		XCTAssertTrue(store.contains("\(new)|keep"))
		XCTAssertEqual(store, ["\(new)|keep"], "only the old account's items went")
	}

	// 8 CU-06: locked or not ready: not_ready, nothing read for deletion, nothing deleted
	func testCase8TheGateNotPassedIsNotReadyAndDeletesNothing() {
		let a = run(env(gate: false))
		XCTAssertEqual(a, BeamioAccountCleanup.Answer.refused("not_ready"))
		XCTAssertEqual(deleteCalls, 0)
		XCTAssertEqual(store.count, 3)
	}

	/// A delete that fails after the gate passed: clear_incomplete with cleanupPending, the rest kept, a retry finishes it.
	func testAFailedItemIsClearIncompleteAndPending() {
		failDelete = ["a"]
		let a = run(env())
		XCTAssertEqual(a.ok, false)
		XCTAssertEqual(a.error, "clear_incomplete")
		XCTAssertEqual(a.cleanupPending, true)
		XCTAssertTrue(store.contains("\(old)|a") && store.contains("\(new)|keep"), "the failed item stays")
		XCTAssertFalse(store.contains("\(old)|b"), "the other item of the same account went: a failure keeps only itself")
		failDelete = []
		XCTAssertEqual(run(env()).ok, true)
		XCTAssertEqual(store, ["\(new)|keep"])
		// an old account whose items cannot be listed: clear_incomplete and pending, nothing deleted
		let unlisted = run(env(oldItemsListed: false))
		XCTAssertEqual(unlisted.error, "clear_incomplete")
		XCTAssertEqual(unlisted.cleanupPending, true)
	}

	func testABadRequestAndTheProductionDeletionSet() {
		XCTAssertEqual(run(env(), key: "0xABC").error, "bad_request")
		XCTAssertEqual(run(env(), idem: "").error, "bad_request")
		// the command is registered (owner requirement); the bridge cases are in AccountCleanupCommandTests
		XCTAssertTrue(BeamioConetChatModule.knownBridgeCommand("accountCleanupOld"))
	}

	/// The ack shape of the v3 vector: BR3-05 (gate), BR3-06 (clear_incomplete), BR3-07 (success). Read from the file; compared with the ack the core builds.
	func testTheV3VectorShape() throws {
		let data = try BundledVectorFile.data(resource: "accountCleanupOld.v3")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 3)
		func canonical(_ v: Any) -> String { String(decoding: (try? JSONSerialization.data(withJSONObject: v, options: [.sortedKeys])) ?? Data(), as: UTF8.self) }
		for c in cases {
			let id = c["id"] as? String ?? "?"
			var expect = c["expect"] as? [String: Any] ?? [:]
			var answer: BeamioAccountCleanup.Answer
			store = ["\(old)|a", "\(new)|keep"]; failDelete = []
			switch id {
			case "BR3-05-gate-not_ready": answer = run(env(gate: false))
			case "BR3-06-item-clear_incomplete": failDelete = ["a"]; answer = run(env())
			case "BR3-07-success": answer = run(env())
			default: XCTFail("\(id): no setup"); continue
			}
			var actual = answer.ack(reqId: "r")
			actual.removeValue(forKey: "reqId")
			// "<integer>" in the vector stands for any integer
			if var result = expect["result"] as? [String: Any], result["keptUnattributed"] as? String == "<integer>" {
				result["keptUnattributed"] = (actual["result"] as? [String: Any])?["keptUnattributed"] as? Int ?? -1
				expect["result"] = result
			}
			XCTAssertEqual(canonical(actual), canonical(expect), id)
		}
	}

	/// Exact names only (v201 section 221 as narrowed by the owner): rebuilt in full from the old address and compared whole. Isolation copies, the device-level items, the
	/// new account's names, another account's intent, a fake isolation copy and look-alikes that only end with, or hold in the middle, an old item name are never in.
	func testTheExactItemNamesOfTheOldAccount() {
		let o = old, n = new
		let mine = [
			"mnemonic:\(o)", "intent:\(o)", "commit:\(o)", "phase:\(o)", "migrated:\(o)", "recoveryBackupConfirmed:\(o)", "wallet.restore.unconfirmed.\(o)",
		]
		let never = [
			// the new account's, another account's intent
			"walletKey:\(n)", "mnemonic:\(n)", "intent:\(n)", "phase:\(n)", "recoveryBackupConfirmed:\(n)", "wallet.restore.unconfirmed.\(n)",
			// isolation copies, genuine-looking or fake: the tag cannot be recomputed, so none is proved the old account's
			"wallet.discard.iso.t1.mnemonic:\(o)", "wallet.iso.t2.part.walletKey:\(o)", "wallet.iso.t3.new.commit:\(o)", "wallet.iso.x.mnemonic:\(o)",
			"fake.wallet.iso.t.mnemonic:\(o)", "wallet.iso.mnemonic:\(o)",
			// device-level
			"wallet.discard.intent", "wallet.discard.audit", "wallet.sync.audit",
			// only the suffix or the middle is the old account's
			"walletKey:\(o)", "other.walletKey:\(o)", "x.mnemonic:\(o)", "prefix-intent:\(o)", "walletKey:\(o)x", "mnemonic:\(o).tail", "a.phase:\(o).b", "walletKey", "walletKey:", "siNodesJson",
		]
		let got = BeamioAccountCleanup.attributableWalletItemNames(oldEoa: o, listed: mine + never)
		XCTAssertEqual(Set(got), Set(mine), "exactly the old account's seven names (the walletKey is not one of them)")
		XCTAssertTrue(BeamioAccountCleanup.attributableWalletItemNames(oldEoa: o, listed: []).isEmpty)
		XCTAssertFalse(BeamioAccountCleanup.attributableWalletItemNames(oldEoa: n, listed: mine + never).contains("walletKey:\(o)"))
		XCTAssertEqual(Set(BeamioAccountCleanup.attributableWalletItemNames(oldEoa: o.uppercased(), listed: mine)), Set(mine), "the address is compared in lower case")
	}

	// MARK: passcode items (v204 section 224, v205 section 225)

	private var records: Set<String> = []     // accounts with a passcode record
	private var hardware: Set<String> = []    // accounts with the Keychain fallback part of H (deletable)
	private var seKeys: Set<String> = []      // accounts with a Secure Enclave key (kept: requirement, item 5)
	private var seUnknown = false
	private var staging: [String: Date] = [:] // accounts with a staging copy and its modification time
	private var inProgress: Set<String> = []
	private var hardwareUnknown = false
	private var stagingUnavailable = false
	private var stagingAgeUnknown = false
	private var failHardwareDelete = false
	private let processStart = Date(timeIntervalSince1970: 1_000_000)

	private func passcodeItems() -> BeamioAccountCleanup.PasscodeItems {
		BeamioAccountCleanup.PasscodeItems(
			recordState: { self.records.contains($0) ? .present(Data([1])) : .absent },
			deleteRecord: { self.records.remove($0) },
			hardwareState: { self.hardwareUnknown ? .unknown : (self.hardware.contains($0) ? .present : .absent) },
			deleteHardware: { if !self.failHardwareDelete { self.hardware.remove($0) } },
			stagingState: { self.stagingUnavailable ? .unavailable : (self.staging[$0] != nil ? .present(Data([2])) : .absent) },
			stagingModified: { self.stagingAgeUnknown ? nil : self.staging[$0] },
			deleteStaging: { self.staging[$0] = nil },
			writeInProgress: { self.inProgress.contains($0) },
			processStart: processStart,
			seKeyState: { self.seUnknown ? .unknown : (self.seKeys.contains($0) ? .present : .absent) }
		)
	}

	private func withPasscode() -> BeamioAccountCleanup.Environment {
		var e = env()
		e.passcode = passcodeItems()
		return e
	}

	private func seedPasscode() {
		records = [old, new]; hardware = [old, new]; staging = [:]; inProgress = []
		hardwareUnknown = false; stagingUnavailable = false; failHardwareDelete = false
	}

	/// The old account's record and H go as a pair; the new account's are never touched.
	func testThePasscodePairOfTheOldAccountGoesAndTheNewStays() {
		seedPasscode()
		let a = run(withPasscode())
		XCTAssertEqual(a.ok, true)
		XCTAssertEqual(records, [new])
		XCTAssertEqual(hardware, [new])
	}

	/// The Secure Enclave key of an old account is kept and not counted (v4 EA-11): the record and the fallback go, the key stays; a lookup that failed is unknown (clear_incomplete).
	func testTheSecureEnclaveKeyIsKeptAndCounted() {
		seedPasscode(); seKeys = [old, new]
		let a = run(withPasscode())
		XCTAssertEqual(a.ok, true)
		XCTAssertEqual(a.keptUnattributed, 0, "a Secure Enclave key is not counted")
		XCTAssertEqual(records, [new]); XCTAssertEqual(hardware, [new])
		XCTAssertEqual(seKeys, [old, new], "no Secure Enclave key is deleted")
		seUnknown = true
		XCTAssertEqual(run(withPasscode()).error, "clear_incomplete")
	}

	/// H that cannot be deleted: clear_incomplete and pending; success only when all three are confirmed absent; a retry finishes.
	func testAnIncompletePairIsClearIncompleteAndAZeroSuccessIsNeverReported() {
		seedPasscode(); failHardwareDelete = true
		let a = run(withPasscode())
		XCTAssertEqual(a.ok, false)
		XCTAssertEqual(a.error, "clear_incomplete")
		XCTAssertEqual(a.cleanupPending, true)
		XCTAssertTrue(hardware.contains(old), "H stays; nothing says done")
		failHardwareDelete = false
		XCTAssertEqual(run(withPasscode()).ok, true)
		XCTAssertEqual(hardware, [new])
		XCTAssertEqual(records, [new])
	}

	/// An H lookup that failed is unknown: the record is not left half-deleted as a success, and the state is incomplete.
	func testAnUnknownHardwareStateIsIncompleteAndKeepsTheRest() {
		seedPasscode(); hardwareUnknown = true
		let a = run(withPasscode())
		XCTAssertEqual(a.error, "clear_incomplete")
		XCTAssertEqual(records.contains(new) && hardware.contains(new), true)
	}

	/// Staging (v208 section 228, v209 section 229): older than this process AND no write of the account running; otherwise the copy stays and the cleanup is
	/// clear_incomplete with cleanupPending (confirmed the old account's, only the timing defers it): never a success, never unattributed.
	func testTheStagingCopyIsDeletedOnlyWhenOlderThanTheProcessAndNoWriteIsRunning() {
		seedPasscode()
		staging[old] = processStart.addingTimeInterval(-10); inProgress = []   // old and no write: deleted
		XCTAssertEqual(run(withPasscode()).ok, true)
		XCTAssertNil(staging[old])

		for (label, modified, running, ageUnknown) in [
			("old but a write is running", -10.0, true, false),
			("written by this process", 10.0, false, false),
			("an age that cannot be read", -10.0, false, true),
		] {
			seedPasscode()
			staging[old] = processStart.addingTimeInterval(modified); inProgress = running ? [old] : []; stagingAgeUnknown = ageUnknown
			let a = run(withPasscode())
			XCTAssertEqual(a.ok, false, label)
			XCTAssertEqual(a.error, "clear_incomplete", label)
			XCTAssertEqual(a.cleanupPending, true, label)
			XCTAssertEqual(a.keptUnattributed, 0, "\(label): confirmed the old account's, so not unattributed")
			XCTAssertNotNil(staging[old], label)
			XCTAssertNil(records.contains(old) ? "x" : nil, "\(label): the pair before it was deleted")
			stagingAgeUnknown = false
		}

		seedPasscode()
		staging[old] = processStart.addingTimeInterval(-10); stagingUnavailable = true
		XCTAssertEqual(run(withPasscode()).error, "clear_incomplete", "a staging state that cannot be read is unknown")
		XCTAssertNil(run(env()).error, "without passcode items nothing of them is touched")
	}

	/// Judged again at the removal: a write that begins between the first judgement and the removal keeps the copy.
	func testAWriteThatBeginsBeforeTheRemovalKeepsTheStagingCopy() {
		seedPasscode()
		staging[old] = processStart.addingTimeInterval(-10)
		var items = passcodeItems()
		var asked = 0
		items.writeInProgress = { _ in asked += 1; return asked >= 2 }   // free at the first judgement, running at the second (the removal)
		var e = env(); e.passcode = items
		let a = run(e)
		XCTAssertEqual(a.ok, false)
		XCTAssertEqual(a.error, "clear_incomplete")
		XCTAssertEqual(a.cleanupPending, true)
		XCTAssertNotNil(staging[old], "kept")
		XCTAssertGreaterThanOrEqual(asked, 2)
	}

	/// The new account's staging copy is never touched (the cleanup only walks the old accounts).
	func testTheNewAccountsStagingCopyIsNeverTouched() {
		seedPasscode()
		staging[new] = processStart.addingTimeInterval(-10)
		_ = run(withPasscode())
		XCTAssertNotNil(staging[new])
	}

	/// The write marker is a counter, released on each end; nested writes of one account all have to end.
	func testTheWriteMarkerIsACounter() {
		let eoa = "0x3333333333333333333333333333333333333333"
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa))
		BeamioPasscodeWriteMarker.begin(eoa); BeamioPasscodeWriteMarker.begin(eoa.uppercased())
		XCTAssertTrue(BeamioPasscodeWriteMarker.isInProgress(eoa))
		BeamioPasscodeWriteMarker.end(eoa)
		XCTAssertTrue(BeamioPasscodeWriteMarker.isInProgress(eoa), "one write is still running")
		BeamioPasscodeWriteMarker.end(eoa)
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa))
		BeamioPasscodeWriteMarker.end(eoa)
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa), "an extra end never goes negative")
	}

	/// Every write or delete of a passcode record or staging copy goes through the record store's choke point and sets the marker for the account (all callers listed in
	/// the receipt: BeamioPasscodeVault, BeamioPasscodeSession, BeamioShellPasscode). The test proves the choke point does.
	func testTheRecordStoreSetsTheMarkerOnEveryWriteAndDelete() {
		let saved = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		defer { BeamioChatWalletTestMemory.items = saved; BeamioPasscodeWriteMarker.testOnBegin = nil }
		var begun: [String] = []
		BeamioPasscodeWriteMarker.testOnBegin = { begun.append($0) }
		for store in [BeamioPasscodeKeychainRecords.standard, BeamioPasscodeKeychainRecords.staging] {
			begun = []
			XCTAssertTrue(store.writeRecord(eoa: old.uppercased(), Data([1])))
			store.deleteRecord(eoa: old)
			XCTAssertEqual(begun, [old, old], "a write and a delete each set the marker")
			XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(old), "and release it")
		}
	}

	/// The marker is a re-entrant counter released on every exit (v211 ruling): nested scopes of one account, a throw and an early return.
	func testTheScopedMarkerIsReentrantAndReleasedOnEveryExit() {
		let eoa = "0x4444444444444444444444444444444444444444"
		struct Boom: Error {}
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa))
		BeamioPasscodeWriteMarker.scoped(eoa) {
			BeamioPasscodeWriteMarker.scoped(eoa.uppercased()) {
				XCTAssertTrue(BeamioPasscodeWriteMarker.isInProgress(eoa))
			}
			XCTAssertTrue(BeamioPasscodeWriteMarker.isInProgress(eoa), "the inner scope did not release the outer one")
		}
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa))
		// a throw inside, even nested
		XCTAssertThrowsError(try BeamioPasscodeWriteMarker.scoped(eoa) { try BeamioPasscodeWriteMarker.scoped(eoa) { throw Boom() } })
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa), "released after a throw")
		// an early return
		func early(_ fail: Bool) -> Int {
			BeamioPasscodeWriteMarker.begin(eoa)
			defer { BeamioPasscodeWriteMarker.end(eoa) }
			if fail { return -1 }
			return 1
		}
		XCTAssertEqual(early(true), -1); XCTAssertEqual(early(false), 1)
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa), "released after an early return")
	}

	/// H of an account: createKey and deleteKey (and the two creators inside createKey) set the account's marker and release it, nested, whatever the keychain answers.
	func testTheHardwareLayerSetsTheSameAccountMarker() {
		let eoa = "0x5555555555555555555555555555555555555555"
		var begun: [String] = []
		BeamioPasscodeWriteMarker.testOnBegin = { begun.append($0) }
		defer { BeamioPasscodeWriteMarker.testOnBegin = nil }
		let hardware = BeamioPasscodeKeychainHardware(seTagPrefix: "com.beamio.test.h.se.", fallbackService: "com.beamio.test.h-fallback")
		_ = hardware.createKey(eoa: eoa)
		XCTAssertGreaterThanOrEqual(begun.count, 2, "createKey and the creator it calls each begin (nested)")
		XCTAssertTrue(begun.allSatisfy { $0 == eoa })
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa), "released after createKey, whatever it answered")
		begun = []
		hardware.deleteKey(eoa: eoa)
		XCTAssertEqual(begun, [eoa])
		XCTAssertFalse(BeamioPasscodeWriteMarker.isInProgress(eoa))
	}

	/// There is no real-Keychain branch in a test build: with the in-memory items switched off (nil), a write through the test store creates them and the real Keychain gets nothing.
	func testTheTestKeychainStoreNeverFallsThroughToTheRealKeychain() {
		let saved = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = nil
		defer { BeamioChatWalletTestMemory.items = saved }
		let service = "com.beamio.beamio.test-never-real.\(UUID().uuidString)"
		let before = BeamioProductPathGuard.productKeychainFacts()
		let status = BeamioTestKeychainStore.add([
			kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
			kSecAttrAccount as String: "a", kSecValueData as String: Data([1]),
		] as CFDictionary, nil)
		XCTAssertEqual(status, errSecSuccess)
		XCTAssertNotNil(BeamioChatWalletTestMemory.items, "the memory was created, not bypassed")
		XCTAssertNotNil(BeamioChatWalletTestMemory.get(service, "a"))
		let after = BeamioProductPathGuard.productKeychainFacts()
		XCTAssertEqual(before, after, "the real Keychain's product services did not change")
		XCTAssertFalse(after.contains { $0.path.contains(service) }, "nothing of the test item is in the real Keychain")
	}

	/// The guard's facts name keys and services, never a value or an account: no fact path of the real defaults or Keychain carries a value or a raw account name.
	func testTheGuardFactsCarryNoValueAndNoAccountName() {
		for fact in BeamioProductPathGuard.productDefaultsFacts() {
			XCTAssertTrue(fact.path.hasPrefix("defaults:"))
			XCTAssertFalse(fact.path.contains("="), "a defaults fact is the key name only: \(fact.path.prefix(20))")
		}
		for fact in BeamioProductPathGuard.productKeychainFacts() where fact.path.hasPrefix("keychain:com.beamio.beamio.") {
			let account = fact.path.split(separator: "|", maxSplits: 1).last.map(String.init) ?? ""
			XCTAssertEqual(account.count, 8, "the account is a short digest, not its name")
			XCTAssertFalse(account.hasPrefix("0x") && account.count > 8)
		}
	}

	// a failed item keeps only itself: the other old accounts are still cleaned, and the run ends clear_incomplete with cleanupPending (requirement, item 2)
	func testAFailureDoesNotStopTheOtherOldAccounts() {
		let third = "0x3333333333333333333333333333333333333333"
		store = ["\(old)|a", "\(old)|b", "\(third)|a", "\(third)|b", "\(new)|keep"]
		failDelete = ["a"]   // the item named `a` of both old accounts cannot be deleted
		let a = run(env(accounts: [new, old, third]))
		XCTAssertEqual(a.ok, false); XCTAssertEqual(a.error, "clear_incomplete"); XCTAssertEqual(a.cleanupPending, true)
		XCTAssertEqual(store, ["\(old)|a", "\(third)|a", "\(new)|keep"], "only the failed items stay; both accounts' other items went")
		failDelete = []
		XCTAssertEqual(run(env(accounts: [new, old, third])).ok, true, "a repeat finishes")
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// an old account whose items cannot be listed is kept and the others go on; the answer is clear_incomplete with cleanupPending
	func testAnUnlistableAccountDoesNotStopTheOthers() {
		let third = "0x3333333333333333333333333333333333333333"
		store = ["\(old)|a", "\(third)|a", "\(new)|keep"]
		var e = env(accounts: [new, old, third])
		let list = e.itemsOfOldAccount
		e.itemsOfOldAccount = { $0 == self.old ? nil : list($0) }
		let a = run(e)
		XCTAssertEqual(a.error, "clear_incomplete"); XCTAssertEqual(a.cleanupPending, true)
		XCTAssertEqual(store, ["\(old)|a", "\(new)|keep"])
	}

	// the Secure Enclave key that cannot be looked up keeps that account's mark, the other accounts' passcode items still go
	func testASecureEnclaveLookupFailureDoesNotStopTheOtherAccounts() {
		let third = "0x3333333333333333333333333333333333333333"
		seedPasscode(); records.insert(third); hardware.insert(third)
		var e = withPasscode(); e.accounts = { [self.new, self.old, third] }
		var pc = e.passcode!
		pc.seKeyState = { $0 == self.old ? .unknown : .absent }
		e.passcode = pc
		let a = run(e)
		XCTAssertEqual(a.error, "clear_incomplete"); XCTAssertEqual(a.cleanupPending, true)
		XCTAssertFalse(records.contains(third), "the other account's record went although the first account's key lookup failed")
	}
}
#endif
