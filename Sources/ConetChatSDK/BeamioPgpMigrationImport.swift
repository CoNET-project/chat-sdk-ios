import Foundation
import Security
#if canImport(X19)
import X19
#endif

/// The PGP migration import of an account. The source is the SDK's own
/// account record L, read in place and never written by the migration, or the record P that the shell hands over. The migrated
/// copy N and the success marker M are kept per account in the SDK secure store.
///
/// The pipeline (with and): read the marker; preflight L (parse both armors, empty-passphrase
/// probe); compare the local fingerprint with L's public key; check the account; check the on-chain registration; write N
/// only when N is absent (a N with the same fingerprint is kept and not rewritten, another fingerprint is
/// `fingerprint_mismatch` and nothing is overwritten or deleted); reread N from the store; prove the key pair with a challenge;
/// write M last. A failure after this run wrote N deletes that N, and nothing else.
///
/// Unregistration removes M and then N, after a recovery source is confirmed. L is never removed by the migration.
///
/// No path generates a key. The bridge sees only codes, the 16-character fingerprint prefix and the request's reqId.
/// A run that stops at a checkpoint sends no event. The next run continues from the stored state. Checkpoints exist in
/// test builds only: a Release build has no checkpoint parameter.
///
/// The type is `BeamioPgpMigrationImport`: the older `BeamioPGPMigration` (P-IMP-PGP restore) differs only by case.
public enum BeamioPgpMigrationImport {
	/// The derived state of an account: verified (M agrees with N, and L agrees when L is present); failed (the last
	/// finished run failed); pending (N exists); none.
	public enum State: String, Equatable {
		case none
		case pending
		case failed
		case verified
	}

	/// One answer. `interrupted` means the run stopped at a checkpoint before it answered: no event.
	public struct Outcome: Equatable {
		public let code: String
		public let fp: String?
		public let interrupted: Bool
	}

	/// X-19 approval for this path. The project approved the native use of SignDetached,
	/// VerifyDetached, PrimaryFingerprint and FirstSubkeyKeyID, limited to verifying the migration of an old PGP private key.
	/// The approval covers the call sites in this file only. The same functions used by P-IMP-PGP restore, identity create and
	/// the inbound path are not covered and are not changed here. Without the approval every run answers `verify_unavailable`.
	static let x19Approved = true

	static let challengeDomain = "beamio.pgp.migrate.challenge.v1\n"
	static let challengeNonceBytes = 32
	static let fingerprintPrefixLength = 16
	/// PRECHECK: the Android bytes, `PgpMigration.kt:28–29`. The passphrase-free probe signs the label followed by the message,
	/// the same way the challenge signs its label (`challengeDomain`). The earlier iOS probe (`beamio.pgp.migrate.probe.v1`, no label) is withdrawn.
	static let precheckDomain = "beamio.pgp.migrate.precheck.v1\n"
	static let precheckMessage = "beamio pgp migrate precheck"
	static let probeMessage = signedBytes(label: precheckDomain, message: Data(precheckMessage.utf8))

	/// The internal migration purposes: the only labels the SDK signs with. They are not in the purpose registry.
	static let internalLabels: Set<String> = [precheckDomain, challengeDomain]

	/// The outcome of an internal migration signature. A refusal carries its code.
	enum InternalSignOutcome: Equatable {
		case signed(String)
		case refused(String)
	}

	/// Signs `message` under an internal label with sig type 0x00: the purpose is judged first (step 2), then the signature (step 3).
	/// The CR assertion of is for sig type 0x01 only, and it does not apply to the internal signatures.
	static func signInternal(crypto: Crypto, privateArmor: String, label: String, message: Data) -> InternalSignOutcome {
		guard internalLabels.contains(label) else { return .refused("purpose_not_registered") }
		guard let signature = crypto.sign(privateArmor: privateArmor, data: signedBytes(label: label, message: message)) else {
			return .refused("sign_failed")
		}
		return .signed(signature)
	}

	/// The bytes that a migration signature covers: the UTF-8 label, then the message, as literal bytes (第 7 条). The signature type
	/// is 0x00, so there is no text canonicalisation: the LF at the end of the label is hashed as LF.
	static func signedBytes(label: String, message: Data) -> Data {
		var out = Data(label.utf8)
		out.append(message)
		return out
	}

	/// Fields that must never reach the bridge (`forbiddenKeys` of the vectors).
	static let forbiddenRequestFields: Set<String> = [
		"privateKeyArmor", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "privateKeyHex", "walletPrivateKey",
		"mnemonic", "recoveryCode",
	]
	/// The only fields a `pgpMigrate` request may carry.
	static let allowedRequestFields: Set<String> = ["type", "reqId"]

	/// Source names kept in N and M.
	enum Source {
		static let legacyPwa = "legacyPwa"
		static let chainBackup = "chainBackup"
	}

	/// The record L (or P) as the run reads it. The private armor is bytes, so that the SDK can clear it after use. A
	/// class, so that the copy the run holds is the one that is cleared. The store returns a copy on every read.
	final class LegacyRecord {
		let eoa: String
		var privateArmor: [UInt8]
		let publicArmor: String
		let keyId: String

		init(eoa: String, privateArmor: [UInt8], publicArmor: String, keyId: String) {
			self.eoa = eoa
			self.privateArmor = privateArmor
			self.publicArmor = publicArmor
			self.keyId = keyId
		}

		/// Clears the private bytes.
		func zeroize() {
			for index in privateArmor.indices {
				privateArmor[index] = 0
			}
		}
	}

	/// The migrated copy N (one item per account, written in a single update). The private armor is bytes.
	struct StagedRecord: Codable, Equatable {
		var eoa: String
		var privateArmor: [UInt8]
		var publicArmor: String
		var keyId: String
		var fingerprint: String
		var fp16: String
		var source: String
	}

	/// The success marker M. It holds no key material.
	struct Marker: Codable, Equatable {
		var fp16: String
		var source: String
		var verifiedAt: String
	}

	/// The stages where a checkpoint may stop a run or an unregistration. `afterRecordInit` belongs to the
	/// page-record feature and is not reached by this file.
	enum Checkpoint: Equatable {
		case afterStagedWrite
		case afterReread
		case afterChallenge
		case beforeMarkerWrite
		case afterMarkerWrite
		case afterMarkerDeleted
	}

	/// Thrown by a checkpoint to stop without an answer. Any other error thrown by a checkpoint is the failure
	/// of its stage.
	struct CheckpointInterrupt: Error {}

	/// What a checkpoint says at a stage: continue, stop without an answer, or fail the stage.
	enum CheckpointAnswer: Equatable {
		case proceed
		case interrupted
		case failed
	}

	/// The secure store of one account's copy and marker, and the read-only view of L. `legacy` returns a copy on every call.
	protocol Store {
		func legacy(eoa: String) -> LegacyRecord?
		func staged(account: String) -> StagedRecord?
		@discardableResult func writeStaged(account: String, _ record: StagedRecord) -> Bool
		func deleteStaged(account: String)
		func marker(account: String) -> Marker?
		@discardableResult func writeMarker(account: String, _ marker: Marker) -> Bool
		func deleteMarker(account: String)
		/// The result code of the last finished run. A non-secret value, one per account.
		func lastCode(account: String) -> String?
		@discardableResult func writeLastCode(account: String, _ code: String) -> Bool
		func deleteLastCode(account: String)
	}

	/// The OpenPGP functions the run needs. The production implementation is `X19Crypto`. The armor is text at this boundary: the
	/// X-19 functions take text, so a copy made here cannot be cleared (see the limits of the receipt).
	protocol Crypto {
		var available: Bool { get }
		func identity(armor: String) -> (fingerprint: String, subkeyKeyID: String)?
		func passphraseFree(privateArmor: String) -> Bool
		func sign(privateArmor: String, data: Data) -> String?
		func verify(publicArmor: String, data: Data, signature: String) -> Bool
	}

	/// Everything a run touches from outside. Tests replace parts of it; the bridge uses `production`.
	struct Environment {
		var store: Store
		var crypto: Crypto
		/// The public armor registered on chain for the account (AddressPGP). nil when nothing is registered (case 2).
		/// A failed read is `.failure` (case 3).
		var chainPublicArmor: (String) -> Result<String?, Error>
		/// Recovery source 3 of: a backup is registered on chain for the account.
		var chainBackupRegistered: (String) -> Bool
		/// Recovery source 2 of: the source P is readable natively. Closed until the entry point is frozen.
		var sourcePReadable: (String) -> Bool
		/// The page record of the account holds W-class fields, or cannot be read. Unregister removes them.
		var shellWalletPresent: (String) -> Bool
		/// Removes the W-class fields of the page record of the account. False when they cannot be removed.
		var shellWalletRemove: (String) -> Bool
		var x19Approved: () -> Bool
		var randomBytes: (Int) -> [UInt8]?
		#if DEBUG
		/// The checkpoint of a stage. Test builds only: a Release build has no checkpoint parameter.
		var checkpoint: (Checkpoint) throws -> Void = { _ in }
		#endif
		var now: () -> String
	}

	static var production: Environment {
		Environment(
			store: KeychainStore(),
			crypto: X19Crypto(),
			chainPublicArmor: { eoa in
				switch AddressPGPChain.read(eoa: eoa) {
				case .failure(let error):
					return .failure(error)
				case .success(let snapshot):
					guard snapshot.exists, !isZeroValue(snapshot.publicArmor) else { return .success(nil) }
					return .success(snapshot.publicArmor)
				}
			},
			chainBackupRegistered: { eoa in
				// Local log codes only (no account value): an unavailable or offline chain is `chain_unavailable`; a readable chain without a backup is `not_met`.
				// The answer itself is the same for both (false), so the caller's behaviour does not change.
				guard case .success(let snapshot) = AddressPGPChain.read(eoa: eoa) else {
					NSLog("[BeamioPgp] chain backup check: code=chain_unavailable")
					return false
				}
				let registered = snapshot.exists && !isZeroValue(snapshot.backupBase64)
				if !registered { NSLog("[BeamioPgp] chain backup check: code=not_met") }
				return registered
			},
			sourcePReadable: { _ in false },
			shellWalletPresent: { BeamioShellRecord.walletFieldsPresent(eoa: $0) },
			shellWalletRemove: { BeamioShellRecord.removeWalletFields(eoa: $0) },
			x19Approved: { x19Approved && BeamioPGPNative.linked },
			randomBytes: { count in
				var bytes = [UInt8](repeating: 0, count: count)
				return SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess ? bytes : nil
			},
			now: { ISO8601DateFormatter().string(from: Date()) }
		)
	}

	// MARK: Public entry points

	/// Whether a migration of the account is pending: its copy N exists and either has no success marker M, or N and M
	/// carry different fingerprints (fp16). Only this state blocks a restore write. `failed`, `verified` and `none` do not block.
	static func isPending(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		let account = BeamioChatPgpKeychain.accountKey(eoa: eoa)
		let store = KeychainStore()
		guard let staged = store.staged(account: account) else { return false }
		guard let marker = store.marker(account: account) else { return true }
		return marker.fp16 != staged.fp16
	}

	/// The derived state of the account of `eoa`. It reads the stored copy, the marker, the last code and L.
	public static func state(eoa rawEoa: String, workspace: String = BeamioChatPgpKeychain.defaultWorkspace) -> State {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, workspace == BeamioChatPgpKeychain.defaultWorkspace else { return .none }
		let account = BeamioChatPgpKeychain.accountKey(eoa: eoa, workspace: workspace)
		return derivedState(store: KeychainStore(), eoa: eoa, account: account, crypto: X19Crypto())
	}

	/// The failure codes that make a state `failed` (rule 2).
	static let failureCodes: Set<String> = [
		"fingerprint_mismatch", "legacy_unreadable", "account_mismatch", "chain_unavailable", "write_failed", "reread_failed",
		"challenge_failed", "verify_unavailable", "store_missing",
	]

	/// The derived state of an account, judged in order: verified (M agrees with N, and L agrees with them when L is
	/// present); failed (the last finished run failed); pending (N exists); none.
	static func derivedState(store: Store, eoa: String, account: String, crypto: Crypto) -> State {
		let staged = store.staged(account: account)
		if let marker = store.marker(account: account), let staged, marker.fp16 == staged.fp16 {
			// A marker that agrees with the copy is verified only while L, when present, agrees too (SS-07): otherwise failed.
			return legacyAgrees(store: store, eoa: eoa, staged: staged, crypto: crypto) ? .verified : .failed
		}
		if let code = store.lastCode(account: account), failureCodes.contains(code) {
			return .failed
		}
		return staged == nil ? .none : .pending
	}

	/// verified also needs L, when L is present, to agree with the copy. An L that cannot be read does not agree.
	private static func legacyAgrees(store: Store, eoa: String, staged: StagedRecord, crypto: Crypto) -> Bool {
		guard let legacy = store.legacy(eoa: eoa) else { return true }
		defer { legacy.zeroize() }
		guard let identity = crypto.identity(armor: legacy.publicArmor) else { return false }
		return identity.fingerprint == staged.fingerprint
	}

	/// The source of a migration, judged from the reading of the source P and the fingerprint of L. `use` is the
	/// source the migration reads (`P` or `L`); `code` is the answer when no source is used.
	struct SourceChoice: Equatable {
		var use: String?
		var code: String?
	}

	/// What the native reader found in the PWA store for the account: nothing, a layout that has not been measured,
	/// or a measured record with the account match and its fingerprint.
	enum PSourceReading: Equatable {
		case absent
		case unmeasured
		case measured(matched: Bool, fingerprint: String?)
	}

	/// The source selection (SR-01 to SR-07) from a reading of P and the fingerprint of L (nil: L absent). Unmeasured
	/// layouts are never read. An L that exists but cannot be read is decided by the caller, never reported as absent.
	static func selectSource(p: PSourceReading, lFingerprint: String?) -> SourceChoice {
		switch p {
		case .absent:
			return lFingerprint == nil ? SourceChoice(use: nil, code: "none") : SourceChoice(use: "L", code: nil)
		case .unmeasured:
			return SourceChoice(use: nil, code: "legacy_unreadable")
		case .measured(let matched, let fingerprint):
			guard matched else { return SourceChoice(use: nil, code: "account_mismatch") }
			guard let lFingerprint else { return SourceChoice(use: "P", code: nil) }
			return lFingerprint == fingerprint
				? SourceChoice(use: "P", code: nil)
				: SourceChoice(use: nil, code: "fingerprint_mismatch")
		}
	}

	/// The result of the first-run import: the wallet copy, and the PGP migration when it ran (nil otherwise).
	public struct FirstRunOutcome {
		public let wallet: BeamioShellRecord.FirstRunImportCode
		public let pgp: Outcome?
	}

	/// The first-run import: the SDK entry that the shell's reader calls. It imports the page wallet copy from
	/// `walletRecord` (rev 0 to 1, W fields encrypted), and runs the PGP migration of `pgpSource` once the wallet copy is in place.
	/// The account is `migrating` for the whole call, whether or not the shell set the mark before.
	public static func importFirstRun(
		eoa rawEoa: String,
		walletRecord: BeamioShellRecord.LegacyWalletRead,
		pgpSource: LegacyPgpSource?
	) -> FirstRunOutcome {
		importFirstRun(
			eoa: rawEoa,
			walletRecord: walletRecord,
			pgpSource: pgpSource,
			store: BeamioShellRecord.EncryptedShellRecordStore.production,
			device: BeamioShellRecord.productionDevice,
				addressOf: BeamioShellRecord.productionAddress,
			env: production
		)
	}

	/// The first-run import with the store, the address check and the environment injected (the production entry and the tests).
	static func importFirstRun(
		eoa rawEoa: String,
		walletRecord: BeamioShellRecord.LegacyWalletRead,
		pgpSource: LegacyPgpSource?,
		store: BeamioShellRecord.ShellRecordStore,
		device: BeamioShellRecord.DeviceStateStore,
		addressOf: (String) -> String?,
		env: Environment
	) -> FirstRunOutcome {
		let eoa = rawEoa.lowercased()
		let wasMigrating = BeamioShellRecord.isMigrating(eoa)
		if !wasMigrating { BeamioShellRecord.beginPreWebViewMigration(eoa: eoa) }
		defer {
			if !wasMigrating { BeamioShellRecord.finishPreWebViewMigration(eoa: eoa) }
		}
		let wallet = BeamioShellRecord.importFirstRun(
			eoa: eoa,
			legacy: walletRecord,
			store: store,
			device: device,
				addressOf: addressOf,
			setState: BeamioShellRecord.setFirstRunState
		)
		// The PGP part runs only in the import branch, once the copy is written. Absent and exists skip it.
		guard wallet == .importOk else {
			return FirstRunOutcome(wallet: wallet, pgp: nil)
		}
		let pgp = runInternal(eoa: eoa, workspace: BeamioChatPgpKeychain.defaultWorkspace, env: env, source: pgpSource)
		return FirstRunOutcome(wallet: wallet, pgp: pgp)
	}

	/// One run with the production environment. `source` is the record P that the shell read from the PWA store; nil
	/// reads L. The SDK clears the source bytes on every exit. The bridge calls `runInternal`.
	public static func run(
		eoa rawEoa: String,
		workspace: String = BeamioChatPgpKeychain.defaultWorkspace,
		source: LegacyPgpSource? = nil
	) -> Outcome {
		runInternal(eoa: rawEoa, workspace: workspace, env: production, source: source)
	}

	/// The record P as the shell read it natively. The key material is kept as bytes so that the SDK can clear it after
	/// use; the caller clears its own copies. Strings made from the bytes inside the SDK cannot be cleared.
	public final class LegacyPgpSource {
		/// The limit of each armor, in bytes.
		public static let maxBytes = 64 * 1024

		public var privateArmor: [UInt8]
		public var publicArmor: [UInt8]
		public var keyId: String
		/// The account matches a record of P (rule 4). The shell sets it.
		public var matchedAccount: Bool
		/// The layout of P is measured. The shell sets it.
		public var measuredLayout: Bool

		public init(
			privateArmor: [UInt8],
			publicArmor: [UInt8],
			keyId: String,
			matchedAccount: Bool = true,
			measuredLayout: Bool = true
		) {
			self.privateArmor = privateArmor
			self.publicArmor = publicArmor
			self.keyId = keyId
			self.matchedAccount = matchedAccount
			self.measuredLayout = measuredLayout
		}

		/// Clears the key bytes.
		public func zeroFill() {
			for index in privateArmor.indices {
				privateArmor[index] = 0
			}
			for index in publicArmor.indices {
				publicArmor[index] = 0
			}
		}
	}

	/// The source of a run. Without P, L is used when it exists, and "none" only when L is absent. With P, the checks of
	/// apply, and the fingerprint of L decides between P and a mismatch; an L that cannot be read is `legacy_unreadable`
	///. Used by the run and by the source vectors (SR).
	static func sourceChoice(eoa: String, source: LegacyPgpSource?, env: Environment) -> SourceChoice {
		guard let source else {
			return env.store.legacy(eoa: eoa) != nil ? SourceChoice(use: "L", code: nil) : SourceChoice(use: nil, code: "none")
		}
		guard source.measuredLayout else { return SourceChoice(use: nil, code: "legacy_unreadable") }
		guard source.matchedAccount else { return SourceChoice(use: nil, code: "account_mismatch") }
		guard env.x19Approved(), env.crypto.available else { return SourceChoice(use: nil, code: "verify_unavailable") }
		let publicArmor = String(decoding: source.publicArmor, as: UTF8.self)
		guard let identity = env.crypto.identity(armor: publicArmor) else {
			return SourceChoice(use: nil, code: "legacy_unreadable")
		}
		guard let legacy = env.store.legacy(eoa: eoa) else {
			return selectSource(p: .measured(matched: true, fingerprint: identity.fingerprint), lFingerprint: nil)
		}
		defer { legacy.zeroize() }
		guard let lIdentity = env.crypto.identity(armor: legacy.publicArmor) else {
			return SourceChoice(use: nil, code: "legacy_unreadable")
		}
		return selectSource(p: .measured(matched: true, fingerprint: identity.fingerprint), lFingerprint: lIdentity.fingerprint)
	}

	/// Unregistration: removes the marker M and then the copy N of one account. L is never removed here. Before any
	/// removal one recovery source must hold: L exists, the source P is readable, or a backup is registered on chain. Otherwise
	/// the answer is `unregister_refused` and nothing is removed.
	public static func unregister(eoa rawEoa: String, workspace: String = BeamioChatPgpKeychain.defaultWorkspace) -> Outcome {
		unregisterInternal(eoa: rawEoa, workspace: workspace, env: production)
	}

	/// The check of one unregistration without any removal: the same answers as `unregister` for the same state. Nothing is
	/// written, deleted or marked. A clear checks every owner with this before it removes anything.
	public static func unregisterCheck(eoa rawEoa: String, workspace: String = BeamioChatPgpKeychain.defaultWorkspace) -> Outcome {
		unregisterCheckInternal(eoa: rawEoa, workspace: workspace, env: production)
	}

	/// The check of one unregistration with the given environment. The guards are those of `unregisterInternal`; no removal.
	static func unregisterCheckInternal(eoa rawEoa: String, workspace: String, env: Environment) -> Outcome {
		let eoa = normalized(rawEoa)
		guard isEOA(eoa), workspace == BeamioChatPgpKeychain.defaultWorkspace else { return answer("bad_request") }
		let account = BeamioChatPgpKeychain.accountKey(eoa: eoa, workspace: workspace)
		guard begin(account: account) else { return answer("busy") }
		defer { end(account: account) }
		let store = env.store
		let marker = store.marker(account: account)
		let staged = store.staged(account: account)
		// (§25.52J.3, M2): the recovery-source check is triggered by M and N only. W is gated by the backup flag (PY.10), not here.
		guard marker != nil || staged != nil else { return answer("ok") }
		guard hasLegacy(store: store, eoa: eoa) || env.sourcePReadable(eoa) || env.chainBackupRegistered(eoa) else {
			return answer("unregister_refused")
		}
		return answer("ok")
	}

	// MARK: Runs

	private static let runLock = NSLock()
	private static var running: Set<String> = []

	/// Marks an account as running. False while a run of the same account is in progress (`busy`).
	static func begin(account: String) -> Bool {
		runLock.lock()
		defer { runLock.unlock() }
		guard !running.contains(account) else { return false }
		running.insert(account)
		return true
	}

	static func end(account: String) {
		runLock.lock()
		defer { runLock.unlock() }
		running.remove(account)
	}

	/// One run with the given environment. A run of the same account already in progress answers `busy`. A source P is cleared on
	/// every exit.
	static func runInternal(eoa rawEoa: String, workspace: String, env: Environment, source: LegacyPgpSource? = nil) -> Outcome {
		defer { source?.zeroFill() }
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, workspace == BeamioChatPgpKeychain.defaultWorkspace else {
			return Outcome(code: "none", fp: nil, interrupted: false)
		}
		let account = BeamioChatPgpKeychain.accountKey(eoa: eoa, workspace: workspace)
		guard begin(account: account) else { return Outcome(code: "busy", fp: nil, interrupted: false) }
		defer { end(account: account) }
		let outcome: Outcome
		if let source {
			outcome = executeFromSource(eoa: eoa, account: account, source: source, env: env)
		} else {
			outcome = execute(eoa: eoa, account: account, env: env, legacyOverride: nil)
		}
		// The last code is written only when a run finishes, never on an interruption.
		if !outcome.interrupted {
			_ = env.store.writeLastCode(account: account, outcome.code)
		}
		NSLog(
			"[BeamioPgpMigration] code=%@ fp8=%@ interrupted=%@",
			outcome.code,
			String((outcome.fp ?? "-").prefix(8)),
			outcome.interrupted ? "yes" : "no"
		)
		return outcome
	}

	/// One unregistration with the given environment.
	/// Whether any W item may exist on this device: an EOA key copy, a mnemonic record, K, or a page copy of the record. An unreadable store counts as
	/// present (fail closed). Enumeration and presence only; no value is read.
	/// The startup redo of an interrupted clear (, item 2): only what a clear is meant to remove counts. The published and stored accounts that a clear keeps
	/// (walletKey, mnemonic items, mnemonic sets) do not, so the automatic redo is not blocked by them; the `clear_pending` marker decides. A page copy still counts.
	static func walletItemsToClearMayExist() -> Bool {
		BeamioShellRecord.EncryptedShellRecordStore.production.hasAnyRecord()
	}

	static func walletItemsMayExist() -> Bool {
		BeamioNativeWallet.hasAnyRecord()
			|| BeamioShellRecord.EncryptedShellRecordStore.production.hasAnyRecord()
			|| BeamioChatWalletKeychainStore.standard.hasAnyWalletItemOrUnreadable()
	}

	/// The startup redo when no account is known. For each account with a copy (N, M, lastCode) that is not the active account and has no W item,
	/// the recovery-source check runs (L present, P readable, or a chain backup registered); a passing account has its copies removed in the order
	/// M, N, lastCode. A failing account keeps its copies. Returns the EOAs that were cleared (no value is returned or logged). For each account with a copy (N, M, lastCode) that is not the active
	/// account and has no W item, the C.3 check runs (L present, P readable, or a chain backup registered); a passing account has its copies removed in
	/// the order M, N, lastCode. A failing account keeps its copies. Returns the EOAs that were cleared (no value is returned or logged).
	@discardableResult
	public static func redoResidualCopiesAtStart(activeAccount: String, hasWallet: (String) -> Bool) -> [String] {
		let residual = KeychainStore.accountsWithCopies()
		if residual.isEmpty { return [] }
		// with no account known, the sweep is gated as a whole. Any W item on the device, or any W item that cannot be read, skips the
		// whole sweep. Per-account exclusion needs a proof that every W item belongs to an account, which is not given here.
		// Gated as a whole whether or not an active account is known: per-account exclusion needs the W-attribution proof, not given.
		if walletItemsMayExist() {
			// Diagnostic: the code and the count only, never an account value.
			NSLog("[BeamioPgp] startup residual sweep skipped: code=wallet_present residual=%d", residual.count)
			return []
		}
		var cleared: [String] = []
		for eoa in residual {
			let owner = eoa.lowercased()
			if owner == activeAccount.lowercased() || hasWallet(owner) { continue }
			let code = unregister(eoa: owner).code
			if code == "ok" { cleared.append(owner) } else {
				// A failed or unavailable check skips the account this round: the code only, no account value.
				NSLog("[BeamioPgp] startup residual sweep: an account was skipped this round, code=%@", code)
			}
		}
		return cleared
	}

	static func unregisterInternal(eoa rawEoa: String, workspace: String, env: Environment) -> Outcome {
		let eoa = normalized(rawEoa)
		// UG-07: an EOA that is not `0x` and 40 hexadecimal digits, or another workspace, is refused and nothing changes.
		guard isEOA(eoa), workspace == BeamioChatPgpKeychain.defaultWorkspace else { return answer("bad_request") }
		let account = BeamioChatPgpKeychain.accountKey(eoa: eoa, workspace: workspace)
		guard begin(account: account) else { return answer("busy") }
		defer { end(account: account) }
		let store = env.store
		let marker = store.marker(account: account)
		let staged = store.staged(account: account)
		// The W-class fields of the page record count as copies to remove: they need the same recovery source.
		let walletPresent = env.shellWalletPresent(eoa)
		// PY.14 (c): a private-key-only account fails closed: no phrase to back up, so nothing is removed.
		if walletPresent, BeamioBackupDisplay.isKeyOnlyAccount(eoa: eoa) { return answer("unregister_refused") }
		// the recovery-source check runs only when M or N is present; without them the copies go nothing here.
		guard marker != nil || staged != nil else {
			// D9 (UG-12): the W-class fields need a recovery source too. With no source they are kept and the answer is unregister_refused.
			if walletPresent {
				guard hasLegacy(store: store, eoa: eoa) || env.sourcePReadable(eoa) || env.chainBackupRegistered(eoa) else {
					return answer("unregister_refused")
				}
				if !env.shellWalletRemove(eoa) { return answer("unregister_refused") }
			}
			store.deleteLastCode(account: account)
			return answer("ok")
		}
		// The recovery source is checked before any removal. The sources are read in the order of the rule.
		guard hasLegacy(store: store, eoa: eoa) || env.sourcePReadable(eoa) || env.chainBackupRegistered(eoa) else {
			return answer("unregister_refused")
		}
		if marker != nil {
			store.deleteMarker(account: account)
			switch checkpoint(.afterMarkerDeleted, env) {
			case .proceed:
				break
			case .interrupted, .failed:
				return interrupted()
			}
		}
		if staged != nil {
			store.deleteStaged(account: account)
		}
		// The last code goes with the copy and the marker.
		store.deleteLastCode(account: account)
		// The W-class fields go last (M, N, lastCode, then W). An interruption before this point keeps them.
		if walletPresent, !env.shellWalletRemove(eoa) {
			return answer("unregister_refused")
		}
		return answer("ok")
	}

	private static func hasLegacy(store: Store, eoa: String) -> Bool {
		guard let legacy = store.legacy(eoa: eoa) else { return false }
		legacy.zeroize()
		return true
	}

	private static func execute(eoa: String, account: String, env: Environment, legacyOverride: LegacyRecord?) -> Outcome {
		let store = env.store
		// The source P, when the shell gave one, takes the place of L; L itself is never written here.
		let legacy = legacyOverride ?? store.legacy(eoa: eoa)
		defer { legacy?.zeroize() }
		let staged = store.staged(account: account)

		if let marker = store.marker(account: account) {
			if let staged {
				return checkMarked(eoa: eoa, staged: staged, marker: marker, legacy: legacy, env: env)
			}
			guard legacy != nil else { return answer("store_missing") }
			// The copy is gone while L is present: the marker is stale. Clear it and migrate again (step 1).
			store.deleteMarker(account: account)
		}

		guard let legacy else {
			guard let staged else { return answer("none") }
			// A copy without L (step 2): verify the copy only.
			guard env.x19Approved(), env.crypto.available else { return answer("verify_unavailable") }
			if let code = chainCode(eoa: eoa, expectedFingerprint: staged.fingerprint, env: env) {
				return answer(code)
			}
			return reread(expected: staged, fingerprint: staged.fingerprint, wrote: false, eoa: eoa, account: account, env: env)
		}

		// L is present (step 3).
		guard env.x19Approved(), env.crypto.available else { return answer("verify_unavailable") }
		let privateArmor = text(legacy.privateArmor)
		guard let priv = env.crypto.identity(armor: privateArmor),
		      let pub = env.crypto.identity(armor: legacy.publicArmor)
		else { return answer("legacy_unreadable") }
		guard env.crypto.passphraseFree(privateArmor: privateArmor) else { return answer("legacy_unreadable") }
		guard priv.fingerprint == pub.fingerprint else { return answer("fingerprint_mismatch") }
		guard normalized(legacy.eoa) == eoa else { return answer("account_mismatch") }
		if let code = chainCode(eoa: eoa, expectedFingerprint: pub.fingerprint, env: env) {
			return answer(code)
		}
		if let staged {
			// a copy with the same fingerprint is kept and verified again; any other copy is never overwritten.
			guard staged.fingerprint == pub.fingerprint else { return answer("fingerprint_mismatch") }
			return reread(expected: staged, fingerprint: pub.fingerprint, wrote: false, eoa: eoa, account: account, env: env)
		}
		let record = StagedRecord(
			eoa: eoa,
			privateArmor: legacy.privateArmor,
			publicArmor: legacy.publicArmor,
			keyId: pub.subkeyKeyID,
			fingerprint: pub.fingerprint,
			fp16: prefix(pub.fingerprint),
			source: Source.legacyPwa
		)
		guard store.writeStaged(account: account, record) else { return answer("write_failed") }
		switch checkpoint(.afterStagedWrite, env) {
		case .proceed:
			break
		case .interrupted:
			return interrupted()
		case .failed:
			store.deleteStaged(account: account)
			return answer("write_failed")
		}
		return reread(expected: record, fingerprint: pub.fingerprint, wrote: true, eoa: eoa, account: account, env: env)
	}

	/// A run from the source P: the bytes are checked for the limit, the source is chosen against L, and the
	/// migration pipeline then runs on P. The copy made for the run is cleared after it.
	private static func executeFromSource(eoa: String, account: String, source: LegacyPgpSource, env: Environment) -> Outcome {
		guard source.privateArmor.count <= LegacyPgpSource.maxBytes, source.publicArmor.count <= LegacyPgpSource.maxBytes else {
			return answer("legacy_unreadable")
		}
		let choice = sourceChoice(eoa: eoa, source: source, env: env)
		if let code = choice.code {
			return answer(code)
		}
		let record = LegacyRecord(
			eoa: eoa,
			privateArmor: source.privateArmor,
			publicArmor: String(decoding: source.publicArmor, as: UTF8.self),
			keyId: source.keyId
		)
		defer { record.zeroize() }
		return execute(eoa: eoa, account: account, env: env, legacyOverride: record)
	}

	/// A copy and a marker exist (step 1): the copy must agree with the marker, and with L when L is present.
	private static func checkMarked(
		eoa: String,
		staged: StagedRecord,
		marker: Marker,
		legacy: LegacyRecord?,
		env: Environment
	) -> Outcome {
		guard env.x19Approved(), env.crypto.available else { return answer("verify_unavailable") }
		guard staged.fp16 == marker.fp16 else { return answer("fingerprint_mismatch") }
		guard let legacy else { return answer("already_verified", fp: marker.fp16) }
		guard normalized(legacy.eoa) == eoa else { return answer("account_mismatch") }
		guard let identity = env.crypto.identity(armor: legacy.publicArmor) else { return answer("legacy_unreadable") }
		guard identity.fingerprint == staged.fingerprint else { return answer("fingerprint_mismatch") }
		return answer("already_verified", fp: marker.fp16)
	}

	/// Steps 4 to 7: reread the copy from the store, check the fingerprint, prove the key pair, write M.
	/// `wrote` is true when this run wrote the copy: a failure then deletes that copy, and nothing else.
	private static func reread(
		expected: StagedRecord,
		fingerprint: String,
		wrote: Bool,
		eoa: String,
		account: String,
		env: Environment
	) -> Outcome {
		func refuse(_ code: String) -> Outcome {
			if wrote { env.store.deleteStaged(account: account) }
			return answer(code)
		}
		guard let back = env.store.staged(account: account), back == expected else { return refuse("reread_failed") }
		guard let priv = env.crypto.identity(armor: text(back.privateArmor)),
		      let pub = env.crypto.identity(armor: back.publicArmor)
		else { return refuse("reread_failed") }
		guard priv.fingerprint == fingerprint, pub.fingerprint == fingerprint else { return refuse("fingerprint_mismatch") }
		switch checkpoint(.afterReread, env) {
		case .proceed:
			break
		case .interrupted:
			return interrupted()
		case .failed:
			return refuse("reread_failed")
		}
		guard challenge(eoa: eoa, back, env: env) else { return refuse("challenge_failed") }
		switch checkpoint(.afterChallenge, env) {
		case .proceed:
			break
		case .interrupted:
			return interrupted()
		case .failed:
			return refuse("challenge_failed")
		}
		let marker = Marker(fp16: prefix(fingerprint), source: back.source, verifiedAt: env.now())
		switch checkpoint(.beforeMarkerWrite, env) {
		case .proceed:
			break
		case .interrupted:
			return interrupted()
		case .failed:
			// The copy stays: the marker is what failed.
			return answer("write_failed")
		}
		guard env.store.writeMarker(account: account, marker) else { return answer("write_failed") }
		switch checkpoint(.afterMarkerWrite, env) {
		case .proceed:
			break
		case .interrupted, .failed:
			return interrupted()
		}
		return answer("ok", fp: marker.fp16)
	}

	/// The on-chain check (step 3). Returns the code of a failure, or nil when the registration matches.
	private static func chainCode(eoa: String, expectedFingerprint: String, env: Environment) -> String? {
		switch env.chainPublicArmor(eoa) {
		case .failure:
			return "chain_unavailable"
		case .success(nil):
			return "fingerprint_mismatch"
		case .success(let armor?):
			guard let identity = env.crypto.identity(armor: armor), identity.fingerprint == expectedFingerprint else {
				return "fingerprint_mismatch"
			}
			return nil
		}
	}

	/// The challenge: a fresh nonce, a detached signature with the copy's private key, a verification with its public
	/// key, and a negative check that a one-bit change of the message fails.
	private static func challenge(eoa: String, _ record: StagedRecord, env: Environment) -> Bool {
		guard let nonce = env.randomBytes(challengeNonceBytes) else { return false }
		let nonceHex = nonce.map { String(format: "%02x", $0) }.joined()
		let message = Data((eoa + "|" + record.keyId + "|" + nonceHex).utf8)
		guard case let .signed(signature) = signInternal(crypto: env.crypto, privateArmor: text(record.privateArmor), label: challengeDomain, message: message)
		else { return false }
		// The signed bytes are the literal `label ‖ message`; the verification and the tamper check use the same bytes.
		let signed = signedBytes(label: challengeDomain, message: message)
		guard env.crypto.verify(publicArmor: record.publicArmor, data: signed, signature: signature) else { return false }
		var tampered = signed
		tampered[tampered.count - 1] ^= 0x01
		return !env.crypto.verify(publicArmor: record.publicArmor, data: tampered, signature: signature)
	}

	/// Calls the checkpoint of a stage. In a Release build there is no checkpoint, so every stage proceeds.
	private static func checkpoint(_ point: Checkpoint, _ env: Environment) -> CheckpointAnswer {
		#if DEBUG
		do {
			try env.checkpoint(point)
			return .proceed
		} catch is CheckpointInterrupt {
			return .interrupted
		} catch {
			return .failed
		}
		#else
		_ = (point, env)
		return .proceed
		#endif
	}

	private static func answer(_ code: String, fp: String? = nil) -> Outcome {
		Outcome(code: code, fp: fp, interrupted: false)
	}

	private static func interrupted() -> Outcome {
		Outcome(code: "interrupted", fp: nil, interrupted: true)
	}

	private static func prefix(_ fingerprint: String) -> String {
		String(fingerprint.prefix(fingerprintPrefixLength))
	}

	private static func normalized(_ eoa: String) -> String {
		eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
	}

	/// An EOA: `0x` and 40 hexadecimal digits (after normalization).
	static func isEOA(_ rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		return eoa.count == 42 && eoa.hasPrefix("0x") && eoa.dropFirst(2).allSatisfy { $0.isHexDigit }
	}

	/// The armor as text, for the X-19 boundary.
	private static func text(_ bytes: [UInt8]) -> String {
		String(decoding: bytes, as: UTF8.self)
	}

	/// A registered value that is empty or zero: "", "0x", or hexadecimal zeros only.
	static func isZeroValue(_ value: String) -> Bool {
		let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		return trimmed.allSatisfy { $0 == "0" || $0 == "x" }
	}

	// MARK: Production crypto and store

	/// The X-19 functions (gopenpgp v3.5.2). Linked only in iOS builds that carry the framework.
	struct X19Crypto: Crypto {
		var available: Bool { BeamioPGPNative.linked }

		/// The primary fingerprint and the first subkey key ID, called here directly. The shared
		/// `BeamioPGPBackup.keyIdentity` is used by other paths and is left as it is.
		func identity(armor: String) -> (fingerprint: String, subkeyKeyID: String)? {
			#if canImport(X19)
			var fingerprintFailure: NSError?
			let fingerprint = X19PrimaryFingerprint(armor, &fingerprintFailure) as String
			guard fingerprintFailure == nil, !fingerprint.isEmpty else { return nil }
			var subkeyFailure: NSError?
			let subkey = X19FirstSubkeyKeyID(armor, &subkeyFailure) as String
			guard subkeyFailure == nil, !subkey.isEmpty else { return nil }
			return (fingerprint, subkey)
			#else
			_ = armor
			return nil
			#endif
		}

		/// Empty passphrase: the key signs a fixed probe. A passphrase-protected key cannot sign without it (step 2).
		func passphraseFree(privateArmor: String) -> Bool {
			if case .signed = BeamioPgpMigrationImport.signInternal(crypto: self, privateArmor: privateArmor, label: precheckDomain,
			                                                       message: Data(precheckMessage.utf8)) {
				return true
			}
			return false
		}

		func sign(privateArmor: String, data: Data) -> String? {
			#if canImport(X19)
			var failure: NSError?
			let signature = X19SignDetached(privateArmor, data, &failure) as String
			guard failure == nil, !signature.isEmpty else { return nil }
			return signature
			#else
			_ = (privateArmor, data)
			return nil
			#endif
		}

		func verify(publicArmor: String, data: Data, signature: String) -> Bool {
			#if canImport(X19)
			var valid: ObjCBool = false
			var failure: NSError?
			let succeeded = X19VerifyDetached(publicArmor, data, signature, &valid, &failure)
			return succeeded && failure == nil && valid.boolValue
			#else
			_ = (publicArmor, data, signature)
			return false
			#endif
		}
	}

	/// The Keychain items of the copy and the marker: one item each per account, written with a single update.
	/// The memory seam of `BeamioChatPgpKeychain` replaces the Keychain in tests.
	final class KeychainStore: Store {
		private static let service = "com.beamio.beamio.chat-pgp"
		private static let stagedField = "migrationStaged"
		private static let markerField = "migrationMarker"
		private static let lastCodeField = "migrationLastCode"

		func legacy(eoa: String) -> LegacyRecord? {
			guard let record = BeamioChatPgpKeychain.readOnlyRecord(eoa: eoa) else { return nil }
			return LegacyRecord(
				eoa: record.eoa,
				privateArmor: Array(record.privateKeyArmor.utf8),
				publicArmor: record.publicKeyArmor,
				keyId: record.pgpKeyId
			)
		}

		func staged(account: String) -> StagedRecord? {
			readJSON(StagedRecord.self, account: account + "|" + Self.stagedField)
		}

		@discardableResult
		func writeStaged(account: String, _ record: StagedRecord) -> Bool {
			writeJSON(record, account: account + "|" + Self.stagedField)
		}

		func deleteStaged(account: String) {
			deleteRaw(account + "|" + Self.stagedField)
		}

		func marker(account: String) -> Marker? {
			readJSON(Marker.self, account: account + "|" + Self.markerField)
		}

		@discardableResult
		func writeMarker(account: String, _ marker: Marker) -> Bool {
			writeJSON(marker, account: account + "|" + Self.markerField)
		}

		func deleteMarker(account: String) {
			deleteRaw(account + "|" + Self.markerField)
		}

		func lastCode(account: String) -> String? {
			readRaw(account + "|" + Self.lastCodeField)
		}

		@discardableResult
		func writeLastCode(account: String, _ code: String) -> Bool {
			writeRaw(code, account: account + "|" + Self.lastCodeField)
		}

		func deleteLastCode(account: String) {
			deleteRaw(account + "|" + Self.lastCodeField)
		}

		private func readJSON<T: Decodable>(_ type: T.Type, account: String) -> T? {
			guard let text = readRaw(account), let data = text.data(using: .utf8) else { return nil }
			return try? JSONDecoder().decode(type, from: data)
		}

		private func writeJSON<T: Encodable>(_ value: T, account: String) -> Bool {
			guard let data = try? JSONEncoder().encode(value), let text = String(data: data, encoding: .utf8) else { return false }
			return writeRaw(text, account: account)
		}

		/// The EOAs that have a copy item (N, M, or lastCode) on this device, from the item names only (§25.52PY.8 第 7 項). No value is read.
		static func accountsWithCopies() -> [String] { accountsWithCopiesChecked() ?? [] }

		#if BEAMIO_TEST_HOOKS
		/// Test seam: the enumeration of the copies fails (a Keychain query error), so `accountsWithCopiesChecked` answers nil.
		static var enumerationFailsForTests = false
		#endif

		/// Same as `accountsWithCopies`, but a query that fails (any status other than success or item not found) answers nil: a failed read, never "no copies" (/// the startup redo reads it fail closed).
		static func accountsWithCopiesChecked() -> [String]? {
			#if BEAMIO_TEST_HOOKS
			if enumerationFailsForTests { return nil }
			if let memory = BeamioChatPgpKeychain.memory {
				return Array(Set(memory.values.keys.compactMap { key -> String? in
					guard key.hasSuffix("|" + stagedField) || key.hasSuffix("|" + markerField) || key.hasSuffix("|" + lastCodeField) else { return nil }
					return String(key.split(separator: "|", maxSplits: 1).first ?? "").split(separator: ":").first.map { String($0) }
				})).sorted()
			}
			#endif
			let query: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: service,
				kSecReturnAttributes as String: true,
				kSecMatchLimit as String: kSecMatchLimitAll,
			]
			var items: CFTypeRef?
			let status = SecItemCopyMatching(query as CFDictionary, &items)
			if status == errSecItemNotFound { return [] }
			guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
			var out = Set<String>()
			for row in rows {
				guard let account = row[kSecAttrAccount as String] as? String else { continue }
				guard account.hasSuffix("|" + stagedField) || account.hasSuffix("|" + markerField) || account.hasSuffix("|" + lastCodeField) else { continue }
				let key = account.split(separator: "|", maxSplits: 1).first.map(String.init) ?? ""
				if let eoa = key.split(separator: ":").first { out.insert(String(eoa)) }
			}
			return out.sorted()
		}

		/// Whether any PGP copy (N, the staged record, or the marker M) is present for any account (the no-account residual check).
		/// Enumeration only: no value is read. An item that cannot be enumerated counts as present (fail closed).
		static func residualCopiesPresent() -> Bool {
			#if BEAMIO_TEST_HOOKS
			if let memory = BeamioChatPgpKeychain.memory {
				return memory.values.keys.contains { $0.hasSuffix("|" + stagedField) || $0.hasSuffix("|" + markerField) }
			}
			#endif
			let query: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: service,
				kSecReturnAttributes as String: true,
				kSecMatchLimit as String: kSecMatchLimitAll,
			]
			var items: CFTypeRef?
			let status = SecItemCopyMatching(query as CFDictionary, &items)
			if status == errSecItemNotFound { return false }
			guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return true }
			return rows.contains { row in
				guard let account = row[kSecAttrAccount as String] as? String else { return true }
				return account.hasSuffix("|" + stagedField) || account.hasSuffix("|" + markerField)
			}
		}

		private func readRaw(_ account: String) -> String? {
			#if BEAMIO_TEST_HOOKS
			if let memory = BeamioChatPgpKeychain.memory { return memory.values[account] }
			#endif
			let query: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: Self.service,
				kSecAttrAccount as String: account,
				kSecReturnData as String: true,
				kSecMatchLimit as String: kSecMatchLimitOne,
			]
			var item: CFTypeRef?
			guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let data = item as? Data else { return nil }
			return String(data: data, encoding: .utf8)
		}

		/// A single item update. The old value stays when the update fails; an item is added only when none exists.
		private func writeRaw(_ value: String, account: String) -> Bool {
			#if BEAMIO_TEST_HOOKS
			if let memory = BeamioChatPgpKeychain.memory {
				memory.values[account] = value
				return true
			}
			#endif
			guard let data = value.data(using: .utf8) else { return false }
			let query: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: Self.service,
				kSecAttrAccount as String: account,
			]
			let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
			if status == errSecSuccess { return true }
			guard status == errSecItemNotFound else { return false }
			var add = query
			add[kSecValueData as String] = data
			add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
			return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
		}

		private func deleteRaw(_ account: String) {
			#if BEAMIO_TEST_HOOKS
			if let memory = BeamioChatPgpKeychain.memory {
				memory.values[account] = nil
				return
			}
			#endif
			let query: [String: Any] = [
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: Self.service,
				kSecAttrAccount as String: account,
			]
			SecItemDelete(query as CFDictionary)
		}
	}
}
#if BEAMIO_TEST_HOOKS
// Test build only: this file's Keychain calls are answered from the test store (BeamioTestKeychainStore), never the real Keychain.
fileprivate func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.copyMatching(query, result)
}
fileprivate func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.add(attributes, result)
}
fileprivate func SecItemUpdate(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.update(query, attributesToUpdate)
}
fileprivate func SecItemDelete(_ query: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.delete(query)
}
#endif
