import Foundation

/// The P-IMP-PGP commands.
///
/// - `pgpRestoreEvaluate` (steps 1 to 5): read only. Reads the record and the backup from AddressPGP at one
/// block, decrypts the backup with the account key (SHA-256 of the EOA key string, AES-256-GCM), and compares the
/// restored key with the on-chain record. Writes nothing.
/// - `pgpRestore` (steps 1 to 6): the same evaluation. On `ok` it judges the local record first, then writes the
/// local record and reads it back; a failed write or read-back is rolled back, and a rollback that does not complete is `not_ready`.
/// - `pgpIdentityCreate`: not built. The chain write, the signing and the native confirmation panel are drafted first
///. It answers only the refusals that need none of them.
///
/// Nothing here returns key material, armor, a passphrase or a backup. Only states, codes and UI keys.
enum BeamioPGPRestoreCommands {
	static let names: Set<String> = ["pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate"]

	/// The refusal for `pgpIdentityCreate` (and for any of the three with a forbidden or an observed-version field).
	static func refusal(type: String, body: [String: Any]) -> String {
		if body.keys.contains(where: { BeamioPGPInbound.forbiddenFields.contains($0) }) { return "key_over_bridge_refused" }
		if body["observedVersion"] != nil { return "bad_request" }
		if type == "pgpIdentityCreate", body["confirm"] != nil { return "confirmation_not_native" }
		return "not_supported"
	}

	/// The outcome of the evaluation (`result`). `armor` and `chainPublicArmor` stay native: they are read by the
	/// restore step and never leave this file.
	struct Evaluation: Equatable {
		var state: String
		var failureClass: String?
		var code: String?
		var offerEntry: Bool
		var uiKey: String?
		var armor: String?
		var chainPublicArmor: String?
		var chainSubkeyKeyID: String?
		var restoredSubkeyKeyID: String?
	}

	static func retry() -> Evaluation {
		Evaluation(state: "undetermined", failureClass: nil, code: "pgp_source_unavailable", offerEntry: false,
		           uiKey: "chat.restore_retry.body", armor: nil, chainPublicArmor: nil, chainSubkeyKeyID: nil, restoredSubkeyKeyID: nil)
	}

	static func failed(_ failureClass: String, code: String) -> Evaluation {
		Evaluation(state: "failed", failureClass: failureClass, code: code, offerEntry: true,
		           uiKey: "chat.restore_failed.body", armor: nil, chainPublicArmor: nil, chainSubkeyKeyID: nil, restoredSubkeyKeyID: nil)
	}

	/// steps 1 to 5. The order of the checks is the spec's: a read failure is never a missing record or backup.
	static func evaluate(eoa: String, snapshot: AddressPGPChain.Snapshot? = nil) -> Evaluation {
		let chain: AddressPGPChain.Snapshot
		if let snapshot {
			chain = snapshot
		} else {
			guard case .success(let read) = AddressPGPChain.read(eoa: eoa) else { return retry() }
			chain = read
		}
		let hasBackup = !chain.backupBase64.isEmpty
		// No record and no backup: the first identity. Not a failure class, no failure prompt.
		if !chain.exists && !hasBackup {
			return Evaluation(state: "first_identity", failureClass: nil, code: nil, offerEntry: true,
			                  uiKey: "chat.first_identity.body", armor: nil, chainPublicArmor: nil, chainSubkeyKeyID: nil, restoredSubkeyKeyID: nil)
		}
		// A record with no backup: backup missing (class 1).
		if chain.exists && !hasBackup {
			return failed("backup_missing", code: "pgp_backup_missing")
		}
		// A backup with no registered public key: registered-missing.
		if hasBackup && (!chain.exists || chain.publicArmor.isEmpty) {
			return failed("registration_missing", code: "pgp_registration_missing")
		}
		// Step 4: decrypt with the account key (native). A missing key is not a backup failure.
		let password: String
		switch BeamioNativeWallet.withAccountKey(eoa: eoa, { BeamioChatRouteRegister.passwordString(privateKey: $0) }) {
		case .success(let value): password = value
		case .failure: return retry()
		}
		let armor: String
		switch BeamioPGPBackup.decrypt(base64: chain.backupBase64, passwordString: password) {
		case .success(let value): armor = value
		case .failure: return failed("decrypt_failed", code: "pgp_backup_undecryptable")
		}
		// The identity checks need the X-19 framework. Without it, nothing can be called verified: a retry, not a failure.
		guard let restored = BeamioPGPBackup.keyIdentity(armor: armor) else {
			return BeamioPGPNative.linked ? failed("decrypt_failed", code: "pgp_backup_invalid") : retry()
		}
		guard let onChain = BeamioPGPBackup.keyIdentity(armor: chain.publicArmor) else { return retry() }
		// Step 5: primary fingerprint and subkey key ID must both match the on-chain record.
		guard restored.fingerprint == onChain.fingerprint, restored.subkeyKeyID == onChain.subkeyKeyID else {
			return failed("fingerprint_mismatch", code: "pgp_fingerprint_mismatch")
		}
		return Evaluation(state: "ok", failureClass: nil, code: nil, offerEntry: false, uiKey: nil, armor: armor,
		                  chainPublicArmor: chain.publicArmor, chainSubkeyKeyID: onChain.subkeyKeyID,
		                  restoredSubkeyKeyID: restored.subkeyKeyID)
	}

	/// The `result` of `pgpRestoreEvaluate`: no key material.
	static func evaluationResult(_ e: Evaluation) -> [String: Any] {
		[
			"state": e.state,
			"failureClass": e.failureClass as Any? ?? NSNull(),
			"code": e.code as Any? ?? NSNull(),
			"offerEntry": e.offerEntry,
			"uiKey": e.uiKey as Any? ?? NSNull(),
		]
	}

	/// Steps 6: judge the local record, then write it and read it back. Returns the code of the event.
	/// `stillUnlocked` is judged once more right before the save: a lock then writes nothing and returns `cancelled`.
	/// Before any write:
	/// - a marked incomplete restore is `not_ready`;
	/// - a pending migration of the account is `not_ready`, and its copy is not overwritten;
	/// - an unreadable PGP record is `not_ready`, and nothing is written;
	/// - a present record of the same identity is `already_exists`; another identity is `not_ready`;
	/// - an absent record is written and read back, and a failed write is rolled back.
	static func writeLocal(eoa: String, evaluation e: Evaluation, stillUnlocked: () -> Bool = { true }) -> (code: String, state: String) {
		guard let armor = e.armor, let publicArmor = e.chainPublicArmor, let subkey = e.chainSubkeyKeyID else {
			return ("write_failed", "undetermined")
		}
		guard stillUnlocked() else { return ("cancelled", "") }
		guard !BeamioChatPgpKeychain.restoreIncomplete(eoa: eoa), !migrationPending(eoa: eoa) else {
			return ("not_ready", "undetermined")
		}
		guard BeamioChatPgpKeychain.recordState(eoa: eoa) != .unreadable else {
			return ("not_ready", "undetermined")
		}
		// M1: a plain legacy record of this account is copied to its own account first (a copy only, nothing is deleted), so the comparison
		// below sees it, with its route and entries.
		_ = BeamioChatPgpKeychain.load(eoa: eoa)
		switch BeamioChatPgpKeychain.recordState(eoa: eoa) {
		case .unreadable:
			return ("not_ready", "undetermined")
		case .present:
			let same = BeamioChatPgpKeychain.scopedRecordSameKey(eoa: eoa, privateArmor: armor, publicArmor: publicArmor, keyId: subkey) ?? false
			return same ? ("already_exists", "ok") : ("not_ready", "undetermined")
		case .absent:
			break
		}
		// A write keeps the route and the entry domains the account already has: it never blanks them.
		let kept = BeamioChatPgpKeychain.keptRouteAndEntries(eoa: eoa)
		let record = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: armor, publicKeyArmor: publicArmor, pgpKeyId: subkey,
			routePublicKeyArmor: kept.route, entryDomains: kept.entryDomains, siNodes: [], mailboxIp: "", eoa: eoa
		)
		// The scoped record this account had before the write. A failed save or read-back puts it back exactly.
		let previous = BeamioChatPgpKeychain.scopedSnapshot(eoa: eoa)
		guard BeamioChatPgpKeychain.save(record) else {
			// N1: the rollback result is checked. A rollback that does not complete is not_ready, never a clean failure.
			return rolledBack(eoa: eoa, restored: BeamioChatPgpKeychain.restoreScoped(eoa: eoa, snapshot: previous), code: "write_failed")
		}
		switch verifyReadBack(eoa: eoa, armor: armor, publicArmor: publicArmor, previous: previous,
		                      readBack: { readBackRecord(eoa: eoa) }) {
		case .matched:
			return ("ok", "ok")
		case .mismatchRestored:
			return ("readback_failed", "undetermined")
		case .mismatchRestoreFailed:
			return incompleteRestore(eoa: eoa)
		}
	}

	/// The answer of a save that failed. A clean rollback is an ordinary failure, and the record is as it was (`code`, undetermined). A rollback that
	/// did not complete is the terminal `not_ready`.
	private static func rolledBack(eoa: String, restored: Bool, code: String) -> (code: String, state: String) {
		if restored { return (code, "undetermined") }
		return incompleteRestore(eoa: eoa)
	}

	/// The terminal answer of a restore whose rollback did not complete (spec (ii),). The record may be mixed, so it is
	/// marked incomplete: no reader returns it and no restore writes over it until the record is cleared. The answer is `not_ready`, never a clean failure.
	static func incompleteRestore(eoa: String) -> (code: String, state: String) {
		if !BeamioChatPgpKeychain.markRestoreIncomplete(eoa: eoa) {
			NSLog("[BeamioPGPRestore] rollback incomplete and the mark was not written (%@)", String(eoa.prefix(10)))
		}
		return ("not_ready", "undetermined")
	}

	/// The local state that is class 4 of the explicit replacement (spec,,): a restore that was marked
	/// incomplete, a PGP record that does not open, or a pending migration. iOS does not implement the explicit replacement yet: a replacement
	/// request in this state answers `not_supported`, and nothing is written or deleted. The identity-mismatch case of class 4 needs the chain read and is
	/// not judged here.
	static func isClass4LocalState(eoa: String) -> Bool {
		BeamioChatPgpKeychain.restoreIncomplete(eoa: eoa)
			|| BeamioChatPgpKeychain.recordState(eoa: eoa) == .unreadable
			|| migrationPending(eoa: eoa)
	}

	/// The migration of the account is pending (spec): a write must not overwrite its copy. Test builds may set it (`testMigrationPending`).
	static func migrationPending(eoa: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if let forced = testMigrationPending { return forced }
		#endif
		return BeamioPgpMigrationImport.isPending(eoa: eoa)
	}

	/// The record as the read-back sees it. A test build may change the result, or the store, during the read-back.
	private static func readBackRecord(eoa: String) -> BeamioChatPgpKeychain.Secrets? {
		let back = BeamioChatPgpKeychain.load(eoa: eoa)
		#if BEAMIO_TEST_HOOKS
		if let override = testReadBackOverride { return override(back) }
		#endif
		return back
	}

	#if BEAMIO_TEST_HOOKS
	/// Test seam: the read-back result, as the test sets it. The closure may also change the store, to simulate a failure during the read-back.
	static var testReadBackOverride: ((BeamioChatPgpKeychain.Secrets?) -> BeamioChatPgpKeychain.Secrets?)?
	/// Test seam: the migration pending state that the write judges, when set.
	static var testMigrationPending: Bool?
	#endif

	/// The read-back of the record just written. A mismatch puts back the scoped record the account had
	/// before the write (`previous`, from `scopedSnapshot`; empty when it had none), so the record of the account is exactly what it was. The
	/// scoped record L and the plain legacy items are never removed on this path.
	static func verifyReadBack(eoa: String, armor: String, publicArmor: String, previous: [String: String],
	                           readBack: () -> BeamioChatPgpKeychain.Secrets?) -> ReadBackOutcome {
		guard let back = readBack(), back.privateKeyArmor == armor,
		      back.publicKeyArmor == publicArmor, back.eoa.lowercased() == eoa.lowercased()
		else {
			// N1: the rollback result is returned, so a rollback that does not complete is never reported as a clean one.
			return BeamioChatPgpKeychain.restoreScoped(eoa: eoa, snapshot: previous) ? .mismatchRestored : .mismatchRestoreFailed
		}
		return .matched
	}

	/// The result of the read-back. `mismatchRestored`: the read-back differed and the record was put back. `mismatchRestoreFailed`: the read-back
	/// differed and the rollback did not complete.
	enum ReadBackOutcome: Equatable {
		case matched
		case mismatchRestored
		case mismatchRestoreFailed
	}
}
