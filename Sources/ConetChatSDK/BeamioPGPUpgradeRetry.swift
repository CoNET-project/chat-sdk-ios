import Foundation

/// `pgpUpgradeRetry {type, reqId, accountKey}` (25.52Y.63 第 2 条, 25.52Y.62, 25.52Y.96 第 3 条): the user-click retry of the K_pgp upgrade.
///
/// The ack is `{type, reqId, ok: true, accepted: true}`, or `{ok: false, error}` with a refusal code. The outcome follows as the event
/// `pgpUpgradeState {type, code}`, which carries no reqId and no key material (25.52Y.62 第 1 条).
///
/// Implemented: the refusals, `keep_existing` (a K_pgp already exists and is not overwritten), `upgraded_from_L` (the legacy record L, read
/// only, whose private key and public key share one primary fingerprint and key ID, is written to K_pgp and read back; L is kept), and
/// `pgp_migration_retry` for every other case.
///
/// Not implemented, answered `pgp_migration_retry` (fail closed: nothing is generated, replaced or deleted):
/// `upgraded_from_chain` (25.52Y.59 第 3 项 (b): the chain-backup source is not wired), and `generated_on_user_click`
/// (25.52Y.59 第 5 项: needs the PGP identity creation, the native confirmation record and the P-IMP-REPLACE chain replacement).
enum BeamioPGPUpgradeRetry {
	/// The only fields a retry carries.
	static let allowedFields: Set<String> = ["type", "reqId", "accountKey"]

	/// The codes of `pgpUpgradeState` that this implementation sends (25.52Y.62 第 2 条).
	enum Code: String {
		case upgradedFromL = "upgraded_from_L"
		case keepExisting = "keep_existing"
		case migrationRetry = "pgp_migration_retry"
	}

	/// The refusal of the ack, judged before anything is read for the decision. nil when the retry may run.
	/// The order is the order of the checks: key material first (25.35.5), then the shape, the account, the passcode lock, and the storage-derived lock.
	static func refusal(_ body: [String: Any], account: String) -> String? {
		if !BeamioChatPgpKeychain.refusedPrivateFields(in: body).isEmpty { return "key_over_bridge_refused" }
		if body.keys.contains(where: { !allowedFields.contains($0) }) { return "bad_request" }
		guard let accountKey = body["accountKey"] as? String else { return "bad_request" }
		guard !account.isEmpty else { return "not_ready" }
		guard accountKey.lowercased() == BeamioChatPgpKeychain.accountKey(eoa: account) else { return "account_mismatch" }
		if BeamioNativeWallet.storageDerivedLocked(eoa: account) { return "not_ready" }
		return nil
	}

	/// The decision for `eoa` once the refusals have passed. Any read that cannot be judged gives `pgp_migration_retry`.
	static func decide(eoa: String) -> Code {
		switch BeamioChatPgpKeychain.readK(eoa: eoa) {
		case .unreadable: return .migrationRetry
		case .record: return .keepExisting
		case .absent: break
		}
		guard let legacy = BeamioChatPgpKeychain.readOnlyRecord(eoa: eoa), legacy.hasUserPrivate,
		      let own = BeamioPGPBackup.keyIdentity(armor: legacy.privateKeyArmor),
		      let published = BeamioPGPBackup.keyIdentity(armor: legacy.publicKeyArmor),
		      own.fingerprint == published.fingerprint,
		      own.subkeyKeyID.uppercased() == published.subkeyKeyID.uppercased(),
		      legacy.pgpKeyId.uppercased() == own.subkeyKeyID.uppercased()
		else {
			return .migrationRetry
		}
		let written = BeamioChatPgpKeychain.upgradeKFromLegacy(
			eoa: eoa, privateArmor: legacy.privateKeyArmor, publicArmor: legacy.publicKeyArmor, keyId: own.subkeyKeyID.uppercased()
		)
		return written ? .upgradedFromL : .migrationRetry
	}
}
