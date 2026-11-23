import CryptoKit
import Foundation

/// `pgpIdentityCreate`: a new Chat identity, up to the local pending key.
///
/// 1. `prepare` (the command, G2 and unlocked): one chain read. Decides the mode (`replace` after a failure class, `first`
/// for a first identity, and `replace` when the account is restored: the write path is not approved, so the confirmation answers
/// `waiting_registration`,; `pgp_source_unavailable` when the read fails).
/// The state the user will see is kept natively as S_seen, with no key ("prepared"). Ack: `{accepted, mode}`.
/// 2. `userConfirmed` (called by the shell after the native confirmation panel): reads the chain again (CAS). A change is
/// `cas_conflict`: the prepared state is dropped. Otherwise a new key is generated (X-19 v4), kept as the pending
/// identity, and read again before the registration (CAS 2). Then the registration is asked. It is injected: without one
/// the pending key waits (`waitingRegistration`). With a successful registration the record is written, read back, and
/// the pending identity cleared. A failed registration keeps the pending key (`retry_write`).
/// 3. `userCancelled`: drops a prepared identity that has no key yet. A pending key is kept.
///
/// Nothing is returned over the bridge but codes and the mode. The private armor never leaves this file except into the
/// keychain and the registration call.
public enum BeamioPGPIdentityCreate {
	public enum Mode: String, Equatable {
		case replace, first
	}

	/// The registration of the new public key and backup on chain. Injected: the decision on
	/// the transaction form and the gas payer is open.
	public protocol Registering {
		func register(eoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error>
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: the injection point for the registration call. Not declared in the product build, and not
	/// public. The test invocation sets BEAMIO_TEST_HOOKS; a product build never does. Nil: a generated key waits for it.
	static var registration: Registering?
#endif

	/// The registration in force. The product build has no injection point: it is always nil, so a generated key waits and the
	/// command answers `waiting_registration`.
	static var activeRegistration: Registering? {
#if BEAMIO_TEST_HOOKS
		registration
#else
		nil
#endif
	}

	/// Key generation. The default is the X-19 v4 wrapper; tests inject a fixed pair.
	public static var generateKeyPair: ((String) -> Result<(privateArmor: String, publicArmor: String), Error>) = { name in
		BeamioPGPNative.generateKeyPair(name: name)
	}

	/// The result of the command.
	public enum PrepareOutcome: Equatable {
		case ready(Mode)
		/// The same key again while the first confirmation is still waiting on the native panel: the repeat is accepted with the
		/// first mode and gets one `idempotent` result, under its own reqId. Nothing is prepared, and no panel is shown for the repeat.
		case inFlightDuplicate(Mode)
		case failed(String)
	}

	/// The result of the native confirmation.
	public enum ConfirmOutcome: Equatable {
		case ok
		case waitingRegistration
		case retryWrite
		case casConflict
		/// A passcode lock found before the chain write: nothing is written to the chain.
		case cancelledLocked
		/// The same idempotency key again after a completed write: nothing is generated or written.
		case idempotent
		case failed(String)
	}

	/// The last identity this process completed for an account: its idempotency key and its mode. In memory only. After a restart
	/// the chain state answers the command, so no second write can happen.
	struct CompletedIdentity: Equatable {
		let idempotencyKey: String
		let mode: Mode
	}

	private static let completedLock = NSLock()
	private static var completedIdentities: [String: CompletedIdentity] = [:]

	/// The in-flight window of an account: the prepared identity whose native confirmation has not yet ended and whose chain write
	/// has not started. It opens when a prepare is ready, and closes on every result, on a cancel, on a waiting registration, and right before the write.
	struct InFlight: Equatable {
		let idempotencyKey: String
		let mode: Mode
	}

	private static var inFlightIdentities: [String: InFlight] = [:]

	static func inFlightIdentity(eoa: String) -> InFlight? {
		completedLock.lock()
		defer { completedLock.unlock() }
		return inFlightIdentities[eoa]
	}

	static func setInFlightIdentity(eoa: String, _ value: InFlight?) {
		completedLock.lock()
		defer { completedLock.unlock() }
		inFlightIdentities[eoa] = value
	}

	/// The accounts whose chain write is running in this process. A second confirmation during that write does not write again (one write at a time).
	private static var writingAccounts: Set<String> = []

	/// Marks the chain write of `eoa` as running. False when a write is already running for the account.
	static func beginWrite(eoa: String) -> Bool {
		completedLock.lock()
		defer { completedLock.unlock() }
		return writingAccounts.insert(eoa).inserted
	}

	static func endWrite(eoa: String) {
		completedLock.lock()
		defer { completedLock.unlock() }
		writingAccounts.remove(eoa)
	}

	/// The answer of the window for a repeat of its key, or nil when no window matches. Nothing is read or written.
	static func inFlightAnswer(eoa rawEoa: String, idempotencyKey: String) -> PrepareOutcome? {
		let eoa = rawEoa.lowercased()
		guard let open = inFlightIdentity(eoa: eoa), open.idempotencyKey == idempotencyKey else { return nil }
		return .inFlightDuplicate(open.mode)
	}

	/// Clears the in-flight windows of every account. For the tests.
	static func resetInFlightIdentities() {
		completedLock.lock()
		defer { completedLock.unlock() }
		inFlightIdentities = [:]
	}

	static func completedIdentity(eoa: String) -> CompletedIdentity? {
		completedLock.lock()
		defer { completedLock.unlock() }
		return completedIdentities[eoa]
	}

	static func setCompletedIdentity(eoa: String, _ value: CompletedIdentity?) {
		completedLock.lock()
		defer { completedLock.unlock() }
		completedIdentities[eoa] = value
	}

	/// Clears the completed identities of every account. For the tests.
	static func resetCompletedIdentities() {
		completedLock.lock()
		defer { completedLock.unlock() }
		completedIdentities = [:]
	}

	/// S_seen: a token of the on-chain state, from the record, the public key and the backup (hashes, not the values).
	static func seenToken(_ chain: AddressPGPChain.Snapshot) -> String {
		func digest(_ text: String) -> String {
			SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
		}
		return "exists=\(chain.exists)|pub=\(digest(chain.publicArmor))|backup=\(digest(chain.backupBase64))"
	}

	static func readChain(_ eoa: String) -> AddressPGPChain.Snapshot? {
		if case .success(let chain) = AddressPGPChain.read(eoa: eoa) { return chain }
		return nil
	}

	/// The first moment of a start (hello, init): an erase that was left behind is tried again for the account of the pointer (r2x s3). While it fails
	/// the marker stays and the temporary key stays blocked (`retry_write` at the next prepare or confirm). Nothing is read for any other purpose.
	@discardableResult
	public static func retryCleanupAtStart() -> Bool {
		guard case .value(let eoa) = BeamioNativeAccountPointer.read(), !eoa.isEmpty else { return true }
		return BeamioChatPgpKeychain.retryCleanup(eoa: eoa)
	}

	/// The command (`pgpIdentityCreate`). The caller has checked the gate, the account and the lock.
	public static func prepare(eoa rawEoa: String, idempotencyKey: String) -> PrepareOutcome {
		let eoa = rawEoa.lowercased()
		guard !idempotencyKey.isEmpty else { return .failed("bad_request") }
		// an erase that was left behind (a flag) is tried again before anything new starts; while it is still owed, nothing starts (r2x s3: retry_write)
		guard BeamioChatPgpKeychain.retryCleanup(eoa: eoa) else { return .failed("retry_write") }
		// the write path is not approved (no registration). The whole command answers waiting_registration, and it does not
		// read the chain first: no mode, no panel, no pending key, nothing written.
		guard activeRegistration != nil else { return .failed("waiting_registration") }
		// the same key while the first confirmation is still in its window: one idempotent answer, nothing prepared.
		if let answer = inFlightAnswer(eoa: eoa, idempotencyKey: idempotencyKey) { return answer }
		if let pending = BeamioChatPgpKeychain.loadPending(eoa: eoa) {
			// Another identity is already pending (C-16). The same key again keeps what is pending.
			if pending.idempotencyKey != idempotencyKey { return .failed("pending_exists") }
			if !pending.privateArmor.isEmpty { return .ready(modeOf(eoa: eoa, chain: readChain(eoa))) }
		}
		// (C-15): the same key after a completed write is accepted again, with the mode of that write. Nothing is prepared.
		// another key after a completed write is not answered from memory: it reads the chain like any prepare.
		if let done = completedIdentity(eoa: eoa), done.idempotencyKey == idempotencyKey { return .ready(done.mode) }
		guard let chain = readChain(eoa) else { return .failed("pgp_source_unavailable") }
		let evaluation = BeamioPGPRestoreCommands.evaluate(eoa: eoa, snapshot: chain)
		let mode: Mode
		switch evaluation.state {
		// the account is restored. Before the chain-identity check is approved, the answer is not `already_exists`;
		// the prepare is accepted, and the confirmation answers `waiting_registration` without a write.
		case "ok": mode = .replace
		case "undetermined": return .failed("pgp_source_unavailable")
		case "first_identity": mode = .first
		default: mode = .replace
		}
		// A first identity needs the native judgement: no old chat key on this device and no registration on the chain. Judged here, not taken from the page.
		if mode == .first, let refusal = BeamioFirstIdentity.firstIdentityRefusal(eoa: eoa) { return .failed(refusal) }
		let prepared = BeamioChatPgpKeychain.PendingIdentity(
			privateArmor: "", publicArmor: "", idempotencyKey: idempotencyKey, seen: seenToken(chain), mode: mode.rawValue
		)
		guard BeamioChatPgpKeychain.savePending(eoa: eoa, prepared) else { return .failed("write_failed") }
		setInFlightIdentity(eoa: eoa, InFlight(idempotencyKey: idempotencyKey, mode: mode))
		return .ready(mode)
	}

	/// The mode of a prepared identity, for a repeated command with the same key.
	private static func modeOf(eoa: String, chain: AddressPGPChain.Snapshot?) -> Mode {
		guard let chain else { return .replace }
		return BeamioPGPRestoreCommands.evaluate(eoa: eoa, snapshot: chain).state == "first_identity" ? .first : .replace
	}

	/// The native confirmation. Synchronous; the shell calls it off the main queue.
	public static func confirm(eoa rawEoa: String, idempotencyKey: String) -> ConfirmOutcome {
		let eoa = rawEoa.lowercased()
		// the temporary key of an erase that is owed is used for nothing; the erase is tried at once, and while it fails the answer is retry_write (r2x s2, s3)
		guard BeamioChatPgpKeychain.retryCleanup(eoa: eoa) else { return .retryWrite }
		guard let start = BeamioChatPgpKeychain.loadPending(eoa: eoa), start.idempotencyKey == idempotencyKey else {
			// (C-15): the key of a completed write, again: `idempotent`, and no chain write.
			// (C-15): the key of a completed write, again: `idempotent`, and no chain write.
			if let done = completedIdentity(eoa: eoa), done.idempotencyKey == idempotencyKey { return .idempotent }
			// Internal to the native confirmation: no bridge code and no event (eventCode is nil for it).
			return .failed("not_prepared")
		}
		var pending = start
		if pending.privateArmor.isEmpty {
			// CAS 1: the state the user saw is still the state on chain.
			guard let now = readChain(eoa), seenToken(now) == pending.seen else {
				// an erase that fails is not ignored: the prepared state stays and the confirmation can be repeated (retry_write)
				guard BeamioChatPgpKeychain.clearPending(eoa: eoa) else { setInFlightIdentity(eoa: eoa, nil); return .retryWrite }
				setInFlightIdentity(eoa: eoa, nil)
				return .casConflict
			}
			// the same judgement once more, right before the key is made: the device or the chain may have changed since the prepare.
			if pending.mode == Mode.first.rawValue, let refusal = BeamioFirstIdentity.firstIdentityRefusal(eoa: eoa) {
				guard BeamioChatPgpKeychain.clearPending(eoa: eoa) else { setInFlightIdentity(eoa: eoa, nil); return .retryWrite }
				setInFlightIdentity(eoa: eoa, nil)
				// a registration seen now is the same conflict as a change after the prepare: nothing generated, nothing written
				return refusal == "cas_conflict" ? .casConflict : .failed(refusal)
			}
			guard case .success(let pair) = generateKeyPair(eoa) else {
				setInFlightIdentity(eoa: eoa, nil)
				return .failed("generation_failed")
			}
			pending.privateArmor = pair.privateArmor
			pending.publicArmor = pair.publicArmor
			guard BeamioChatPgpKeychain.savePending(eoa: eoa, pending) else {
				setInFlightIdentity(eoa: eoa, nil)
				return .failed("write_failed")
			}
			// CAS 2: before anything is written, the state is read again.
			// The chain already holds this very identity (a write that went through before the record was kept): no write, nothing is changed, and the
			// answer says so (a no-op, not a second registration).
			if let same = readChain(eoa), same.exists, !same.publicArmor.isEmpty, same.publicArmor == pending.publicArmor {
				setInFlightIdentity(eoa: eoa, nil)
				return .failed("already_registered_same_key")
			}
			guard let again = readChain(eoa), seenToken(again) == pending.seen else {
				guard BeamioChatPgpKeychain.clearPending(eoa: eoa) else { setInFlightIdentity(eoa: eoa, nil); return .retryWrite }
				setInFlightIdentity(eoa: eoa, nil)
				return .casConflict
			}
		}
		// Without a registration the key waits: the window closes, and a later confirmation retries.
		guard let registration = activeRegistration else {
			setInFlightIdentity(eoa: eoa, nil)
			return .waitingRegistration
		}
		// The window closes before the chain write starts: a repeat after this point is a retry, not an in-flight repeat.
		setInFlightIdentity(eoa: eoa, nil)
		// One chain write at a time: a confirmation that arrives during a running write does not write again.
		guard beginWrite(eoa: eoa) else { return .idempotent }
		defer { endWrite(eoa: eoa) }
		switch registration.register(eoa: eoa, publicArmor: pending.publicArmor, idempotencyKey: idempotencyKey, seen: pending.seen) {
		case .failure:
			return .retryWrite
		case .success:
			guard let keyId = BeamioPGPBackup.keyIdentity(armor: pending.publicArmor)?.subkeyKeyID else {
				return .failed("write_failed")
			}
			let record = BeamioChatPgpKeychain.Secrets(
				privateKeyArmor: pending.privateArmor, publicKeyArmor: pending.publicArmor, pgpKeyId: keyId,
				routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa
			)
			guard BeamioChatPgpKeychain.save(record) else {
				BeamioChatPgpKeychain.removeRecord(eoa: eoa)
				return .failed("write_reverted")
			}
			guard let back = BeamioChatPgpKeychain.load(eoa: eoa),
			      back.privateKeyArmor == pending.privateArmor, back.publicKeyArmor == pending.publicArmor
			else {
				BeamioChatPgpKeychain.removeRecord(eoa: eoa)
				return .failed("readback_failed")
			}
			// The identity is registered and kept. An erase of the pending key that fails does not undo that: a flag is left, and the next start erases again.
			if !BeamioChatPgpKeychain.clearPending(eoa: eoa) { BeamioChatPgpKeychain.markCleanupPending(eoa: eoa) }
			setCompletedIdentity(eoa: eoa, CompletedIdentity(idempotencyKey: idempotencyKey, mode: Mode(rawValue: pending.mode) ?? .replace))
			return .ok
		}
	}

	/// Where a confirmation came from. Only the native panel may confirm a new identity (spec: native only, native confirmed).
	public enum ConfirmSource: Equatable {
		case native
		case webView
		case other
	}

	/// A confirmation with its provenance. A confirmation from anywhere but the native layer is `confirmation_not_native`; a native source that has not
	/// been confirmed by the user is `native_confirmation_missing`. In both cases nothing is generated and nothing is written.
	public static func confirm(eoa: String, idempotencyKey: String, source: ConfirmSource, nativeConfirmed: Bool) -> ConfirmOutcome {
		guard source == .native else { return .failed("confirmation_not_native") }
		guard nativeConfirmed else { return .failed("native_confirmation_missing") }
		return confirm(eoa: eoa, idempotencyKey: idempotencyKey)
	}

	/// The user cancelled, or the confirmation timed out. Only a prepared identity is dropped:
	/// a key that is already pending stays for the registration. Returns true when something was dropped.
	@discardableResult
	public static func cancel(eoa rawEoa: String) -> Bool {
		setInFlightIdentity(eoa: rawEoa.lowercased(), nil)
		let eoa = rawEoa.lowercased()
		guard let pending = BeamioChatPgpKeychain.loadPending(eoa: eoa), pending.privateArmor.isEmpty else { return false }
		// outside the create flow: a failed erase leaves a flag (nothing secret), and the next start erases again
		if !BeamioChatPgpKeychain.clearPending(eoa: eoa) { BeamioChatPgpKeychain.markCleanupPending(eoa: eoa) }
		return true
	}

	/// The shell calls this when the user confirms on the native panel. Runs off the main queue and emits the one
	/// `pgpIdentityCreateResult` of the prepared command, with its code (`waiting_registration` included,).
	public static func userConfirmed(eoa: String, idempotencyKey: String) {
		DispatchQueue.global(qos: .userInitiated).async {
			let code = eventCode(confirm(eoa: eoa, idempotencyKey: idempotencyKey))
			DispatchQueue.main.async { BeamioConetChatModule.emitIdentityCreateResult(code: code) }
		}
	}

	/// The shell calls this when the user cancels, or when the 120-second confirmation times out (`timedOut`).
	public static func userCancelled(eoa: String, timedOut: Bool = false) {
		DispatchQueue.global(qos: .userInitiated).async {
			let dropped = cancel(eoa: eoa)
			DispatchQueue.main.async {
				BeamioConetChatModule.emitIdentityCreateResult(code: dropped ? (timedOut ? "confirm_timeout" : "cancelled") : nil)
			}
		}
	}

	/// The code of a confirmation result for the event. Nil: no event.
	static func eventCode(_ outcome: ConfirmOutcome) -> String? {
		switch outcome {
		case .ok: return "ok"
		// 第 2 条,: the write path is not approved yet; nothing is written and the result says so.
		case .waitingRegistration: return "waiting_registration"
		case .retryWrite: return "retry_write"
		case .casConflict: return "cas_conflict"
		case .cancelledLocked: return "cancelled"
		case .idempotent: return "idempotent"
		case .failed(let code):
			switch code {
			case "readback_failed": return "readback_failed"
			case "not_prepared": return nil
			// the codes of the spec that this flow can reach, passed through unchanged
			case "already_exists", "pgp_source_unavailable", "not_eligible", "already_registered_same_key",
			     "native_confirmation_missing", "confirmation_not_native", "pending_exists", "write_reverted":
				return code
			// anything else is not a rollback and has no code of its own: unknown, retryable (write_reverted is only the rollback of a failed save)
			default: return "retry_write"
			}
		}
	}
}
