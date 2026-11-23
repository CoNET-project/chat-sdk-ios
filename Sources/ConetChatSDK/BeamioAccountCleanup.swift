import Foundation

/// The silent cleanup of the old account's data after a recovery: when the recovery succeeded and
/// both sides read back the same address, the page sends `accountCleanupOld {accountKey, idempotencyKey}`; the SDK compares the page-derived address with the native
/// derived one and cleans the old account's attributable local data. There is no user confirmation. This is the judgement core. The command is not registered and the
/// production deletion set is empty until the item list is settled, so nothing is ever deleted. Nothing here is reached by a bridge command yet.
///
/// Rules (v180 section 200.2 a to d, as changed by v193): the new account and its data are never deleted; items are judged by their owner and an item whose owner is
/// not an old account is `keptUnattributed` (counted, never deleted); a read failure, a lock or a state that is not ready is unknown (data stays, no success,
/// retry possible); the cleanup is idempotent (a repeated run finds nothing).
enum BeamioAccountCleanup {
	/// One item the cleanup may delete, with the account it belongs to.
	struct Item: Equatable {
		let owner: String
		let name: String
	}

	/// The answer in the shape of v196 section 216 (accountCleanupAck): `ok`, `error` (closed set) when not ok, and `cleanupPending` and `keptUnattributed` always.
	struct Answer: Equatable {
		let ok: Bool
		let error: String?
		let cleanupPending: Bool
		let keptUnattributed: Int
		/// True when something was deleted by this run.
		let deleted: Int

		static func refused(_ error: String) -> Answer { Answer(ok: false, error: error, cleanupPending: false, keptUnattributed: 0, deleted: 0) }

		/// The ack of the command: no `error` when ok; `result` always present with booleans and an integer only.
		func ack(reqId: Any) -> [String: Any] {
			var out: [String: Any] = ["type": "ack", "reqId": reqId, "ok": ok,
			                          "result": ["cleanupPending": cleanupPending, "keptUnattributed": keptUnattributed]]
			if let error { out["error"] = error }
			return out
		}
	}

	struct Environment {
		/// False when the gate is locked or not ready (nothing is read for deletion then).
		var gatePassed: () -> Bool
		/// One reading of the active account: the device's account pointer and the address the native side derives from that same pointer (nil when the key record or the key cannot be read).
		/// Required and without a default, and the only way the cleanup reads either value: two separate reads could be split by an account switch, so there is no two-closure form.
		var activeSnapshot: () -> (pointer: String, derived: String?)
		var mnemonicState: (String) -> BeamioMnemonicAccountState
		var keyRecordState: (String) -> BeamioChatWalletKeyRecordState
		/// The accounts the device lists, or nil when it cannot list them.
		var accounts: () -> [String]?
		/// The items that belong to the old account `owner`; nil when they cannot be listed.
		var itemsOfOldAccount: (String) -> [Item]?
		/// True when the item is gone.
		var delete: (Item) -> Bool
		/// The passcode items of an account (v205 section 225): the record, the hardware layer H (Secure Enclave key and Keychain fallback) and the staging copy.
		/// Absent defaults mean no passcode items are known: nothing of them is touched.
		var passcode: PasscodeItems? = nil
		/// Called with the verified active account (`accountKey`): no other read of the pointer is needed.
		/// Items on the device that belong to no known account and cannot be attributed by name (a chat library whose file-name tag matches no account the device knows). They are
		/// kept and counted in keptUnattributed, never deleted. nil when they cannot be listed. Default: none.
		var unattributedKept: (_ accountKey: String) -> [String]? = { _ in [] }
	}

	/// The passcode storage seen by the cleanup, per account. All reads say present, absent or unknown (never absent for a failed read).
	struct PasscodeItems {
		var recordState: (String) -> BeamioPasscodeRecordRead
		var deleteRecord: (String) -> Void
		/// H, the deletable part: present when the Keychain fallback item exists; unknown when a lookup failed. (The Secure Enclave key is `seKeyState`, kept.)
		var hardwareState: (String) -> BeamioPasscodeHardwareKeyState
		/// Deletes the Keychain fallback item of the account. The Secure Enclave key stays.
		var deleteHardware: (String) -> Void
		var stagingState: (String) -> BeamioPasscodeRecordRead
		var stagingModified: (String) -> Date?
		var deleteStaging: (String) -> Void
		var writeInProgress: (String) -> Bool
		var processStart: Date
		/// The Secure Enclave key of H (requirement, item 5; v4 EA-11): kept, never deleted in this version, not counted. It identifies the account.
		var seKeyState: (String) -> BeamioPasscodeHardwareKeyState = { _ in .absent }
	}

	/// The passcode items of the product: the record store, the staging store and the H layer, each by the old account's exact lower-case address (v204 section 224).
	/// The staging copy's age is its creation time (it is written once and replaced in place, which keeps the creation time). The passcode attempt and cooldown counters
	/// of an account are fields of its own record (`BeamioPasscodeRecord.failures` and `lastFailureAt`, BeamioPasscodeVault.swift:151–152), so they are deleted with the old account's record
	/// as one; the device-level or global counters that are not keyed by an address (the native-recovery PIN counter in UserDefaults, the retry and
	/// backoff counters of the listen, gossip and guardian paths) are not touched here and must never be added. Reached by nothing while the command is not registered.
	static func productionPasscodeItems(
		records: BeamioPasscodeKeychainRecords = .standard,
		staging: BeamioPasscodeKeychainRecords = .staging,
		hardware: BeamioPasscodeKeychainHardware = .standard
	) -> PasscodeItems {
		PasscodeItems(
			recordState: { records.readRecordState(eoa: $0) },
			deleteRecord: { records.deleteRecord(eoa: $0) },
			hardwareState: { hardware.fallbackState(eoa: $0) },
			deleteHardware: { hardware.deleteFallback(eoa: $0) },
			stagingState: { staging.readRecordState(eoa: $0) },
			stagingModified: { eoa in staging.enumerateRecordCreations()?.first { $0.owner == eoa.lowercased() }?.created },
			deleteStaging: { staging.deleteRecord(eoa: $0) },
			writeInProgress: { BeamioPasscodeWriteMarker.isInProgress($0) },
			processStart: BeamioPasscodeWriteMarker.processStart,
			seKeyState: { hardware.seKeyState(eoa: $0) }
		)
	}

	/// The production environment (the deletion set of v198 to v201, v210 and the passcode items) is `BeamioAccountCleanupProduction.environment()`. The command is still not
	/// registered: nothing calls it until it is explicitly enabled.

	/// The raw account names of the chat-wallet service that belong to the old account `oldEoa` exactly, from the names the store lists (v201 section 221 as narrowed by the
	/// owner's answer). Pure. Every name is rebuilt in full from the old address and compared whole: walletKey, mnemonic, intent and commit of that address, its phase and
	/// migrated markers, its recovery-backup flag, its unconfirmed-restore mark and its credential K record (blobKey). Isolation copies are NOT returned: their tag cannot be recomputed from the address, so a
	/// copy cannot be proved the old account's alone and it stays; a name that only ends with, or holds in its middle, an item name of the old account is never a match. The device-level
	/// items (discard intent and audit, sync audit) belong to no account and are never returned.
	static func attributableWalletItemNames(oldEoa: String, listed: [String]) -> [String] {
		let o = oldEoa.lowercased()
		// and the reconcile decision: `walletKey:<account>` (the published wallet key) and `blobKey:<account>` (purpose not verified: protected) are never in
		// the deletable set. The sets (`mnemonic.set.*`, `mnemonic.current`) are not names of this list at all. Nothing else changes here.
		let exact: Set<String> = [
			"mnemonic:" + o, "intent:" + o, "commit:" + o,
			"phase:" + o, "migrated:" + o, "recoveryBackupConfirmed:" + o, "wallet.restore.unconfirmed." + o,
		]
		return listed.filter { exact.contains($0) }
	}

	private static func isAddress(_ s: String) -> Bool {
		s.count == 42 && s.hasPrefix("0x") && s.dropFirst(2).allSatisfy { $0.isHexDigit && !$0.isUppercase }
	}

	/// `accountKey` is the new account's address as the page derived it (lower-case 0x and 40 hex digits). `idempotencyKey` only names the request: a repeated run is
	/// idempotent by what it finds, not by a record that could be lost.
	static func run(accountKey: String, idempotencyKey: String, env: Environment) -> Answer {
		guard isAddress(accountKey), !idempotencyKey.isEmpty else { return .refused("bad_request") }
		// the gate first: locked or not ready, nothing else is read and nothing is deleted
		guard env.gatePassed() else { return .refused("not_ready") }
		// read-back: the page's address must be the native derived one and the pointer, the mnemonic valid and the key record present
		let first = active(env)
		guard let derived = first.derived else { return .refused("not_ready") }
		guard derived.lowercased() == accountKey, first.pointer.lowercased() == accountKey else { return .refused("account_mismatch") }
		switch env.mnemonicState(accountKey) {
		case .valid: break
		case .unreadable: return .refused("not_ready")
		case .invalid, .absent: return .refused("account_mismatch")
		}
		switch env.keyRecordState(accountKey) {
		case .present: break
		case .unreadable: return .refused("not_ready")
		case .absent: return .refused("account_mismatch")
		}
		guard let listed = env.accounts() else { return .refused("not_ready") }
		let olds = Set(listed.map { $0.lowercased() }).subtracting([accountKey]).sorted()
		// nothing has been deleted yet: a listing of the kept-on-purpose items that cannot be read is not_ready
		guard let orphans = env.unattributedKept(accountKey) else { return .refused("not_ready") }
		var deleted = 0, unattributed = 0
		// an item that is kept on purpose is counted once per device, not once per old account (the device-level files are listed under every old account, a mislisted item of
		// the new account too): the count is of distinct items, keyed by owner and name
		var counted: Set<String> = []
		func countKept(_ item: Item) { if counted.insert(item.owner + "|" + item.name).inserted { unattributed += 1 } }
		for name in orphans { countKept(Item(owner: "<device-level>", name: name)) }
		// An item that is kept because it cannot be listed, read or deleted does not stop the others (requirement, item 2): the run goes on with every other confirmed old account and
		// ends with clear_incomplete and cleanupPending. Only the enumeration (before any deletion) and a change of the active account stop the run.
		var incomplete = false
		for old in olds {
			// defensive: an account that is the active one is kept whole and counted, never deleted. Unreachable in the normal flow (the read-back made the
			// active account equal to `accountKey`, which is not in `olds`), so it is a guard, not a path.
			if active(env).pointer.lowercased() == old {
				if let kept = env.itemsOfOldAccount(old) { for item in kept { countKept(item) } } else { incomplete = true }
				continue
			}
			// the active account is judged again before each old account is touched: a switch in the middle stops the cleanup (what was deleted stays deleted, nothing more goes)
			if let changed = readBackChanged(accountKey: accountKey, env: env) { return .refused(changed) }
			guard let items = env.itemsOfOldAccount(old) else { incomplete = true; continue }
			for item in items {
				// an item that is not the old account's own (the new account's, or anyone else's) is never deleted
				guard item.owner.lowercased() == old else { countKept(item); continue }
				if env.delete(item) { deleted += 1 } else { incomplete = true }
			}
		}
		// the passcode items of each old account (v205 section 225): the record with the fallback part of H as a pair, then the staging copy
		if let passcode = env.passcode {
			for old in olds {
				if active(env).pointer.lowercased() == old { continue }   // the defensive guard above kept it whole
				if let changed = readBackChanged(accountKey: accountKey, env: env) { return .refused(changed) }
				// the Secure Enclave key stays (requirement, item 5; v4 EA-11): it identifies the account and is not counted; one that cannot be looked up is kept as unknown
				if passcode.seKeyState(old) == .unknown { incomplete = true }
				let pair = deletePasscodePair(old, passcode)
				deleted += pair.deleted
				if !pair.complete { incomplete = true }
				switch stagingVerdict(old, passcode) {
				case .none: break
				case .delete:
					// judged again at the removal: a write that began since the first judgement keeps the copy, and the cleanup stays pending (v209 section 229)
					if stagingStillDeletable(old, passcode) {
						passcode.deleteStaging(old)
						if case .absent = passcode.stagingState(old) { deleted += 1 } else { incomplete = true }
					} else { incomplete = true }
				case .keep, .unknown:
					// the copy is confirmed the old account's but cannot be deleted yet (written by this process, a write running, or an age that cannot be read), or its state is unknown:
					// kept, clear_incomplete with cleanupPending so that the next start retries, never a success (v209 section 229)
					incomplete = true
				}
			}
		}
		if incomplete { return Answer(ok: false, error: "clear_incomplete", cleanupPending: true, keptUnattributed: unattributed, deleted: deleted) }
		return Answer(ok: true, error: nil, cleanupPending: false, keptUnattributed: unattributed, deleted: deleted)
	}

	/// The active account judged again in the middle of a run: nil while the pointer and the derived address are still `accountKey`. A derived address that cannot be read is not_ready, a
	/// different one account_mismatch.
	private static func readBackChanged(accountKey: String, env: Environment) -> String? {
		let now = active(env)
		guard let derived = now.derived else { return "not_ready" }
		return derived.lowercased() == accountKey && now.pointer.lowercased() == accountKey ? nil : "account_mismatch"
	}

	/// One reading of the active account: the snapshot of the environment.
	private static func active(_ env: Environment) -> (pointer: String, derived: String?) {
		env.activeSnapshot()
	}

	/// The record and the fallback part of H, one pair, deleted item by item; complete only when both are confirmed absent (the Secure Enclave key is kept, see `run`). A state that
	/// cannot be read is unknown and incomplete: nothing is reported done.
	private static func deletePasscodePair(_ old: String, _ p: PasscodeItems) -> (complete: Bool, deleted: Int) {
		var deleted = 0
		switch p.recordState(old) {
		case .absent: break
		case .unavailable: return (false, 0)
		case .present: p.deleteRecord(old); deleted += 1
		}
		switch p.hardwareState(old) {
		case .absent: break
		case .unknown: return (false, deleted)
		case .present: p.deleteHardware(old); deleted += 1
		}
		// confirm: all absent
		guard case .absent = p.recordState(old), p.hardwareState(old) == .absent else { return (false, deleted) }
		return (true, deleted)
	}

	private enum StagingVerdict { case none, delete, keep, unknown }

	/// v208 section 228 (replacing v205 section 225.2): the staging copy of the old account goes only when all three hold: its account is the old account's exactly
	/// (the caller walks old accounts only), it was created or modified before this process started, and no write of the account is running in this process. A staging
	/// copy whose age cannot be read is kept. Judged again at the removal itself (`confirmStagingStillDeletable`). A copy written by this process is always kept and counted;
	/// the next process start handles it.
	private static func stagingVerdict(_ old: String, _ p: PasscodeItems) -> StagingVerdict {
		switch p.stagingState(old) {
		case .absent: return .none
		case .unavailable: return .unknown
		case .present: break
		}
		return stagingStillDeletable(old, p) ? .delete : .keep
	}

	private static func stagingStillDeletable(_ old: String, _ p: PasscodeItems) -> Bool {
		guard !p.writeInProgress(old), let modified = p.stagingModified(old), modified < p.processStart else { return false }
		return true
	}
}
