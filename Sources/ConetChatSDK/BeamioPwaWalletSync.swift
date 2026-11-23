import Foundation

/// The PWA-to-native sync commands (25.52Y.163 r2.4 to r2.5.19): `pwaWalletSync`, `pwaEmptySignal` and `nativeMnemonicPreread`.
///
/// Implemented: the trusted-origin gate (第 46(5)(6) 项, 第 46(7) 项, 第 59(1)(d) 项), the credential refusal for every field but `phrase`
/// (第 59(1)(c) 项), the closed answer sets (第 49 项, 第 60 项), the shared transaction sequence (第 56 项, an in-process ledger that restarts at
/// zero), the preread with its phrase and its seq rule (第 59(2) 项, 第 60 项), and the write of `pwaWalletSync` (第 59(3) 项): an absent
/// record is created, the same phrase is idempotent, and a different record is overwritten with isolation (`BeamioPwaPhraseOverwrite`).
///
/// The preread answers the published reading of the current epoch (`BeamioPwaPreread`): the start-up read of the shell, and a re-read after each
/// write (第 42(2) 项, 第 49(2) 项, 第 59(3)(f) 项).
///
/// `pwaEmptySignal`: the accepted signal, its `(seq, pwaState)`, is held in process memory with the same ledger as `pwaWalletSync` (第 58(4)(a) 项).
/// It is not durable, and it is recorded whatever its state. What is durable is the narrow discard's intent and audit (`BeamioNarrowDiscardStore`).
/// The discard runs only when the two sides are explicitly empty and the signal is the latest accepted seq (第 46(6) 项, 第 53(7) 项). A discard that
/// stays pending answers `write_failed` with `reason: "internal_state"` (第 58(4)(c) 项). A signal with `valid` or `unknown` discards nothing.
enum BeamioPwaWalletSync {
	static let syncCommand = "pwaWalletSync"
	static let emptySignalCommand = "pwaEmptySignal"
	static let prereadCommand = "nativeMnemonicPreread"
	static let commands: Set<String> = [syncCommand, emptySignalCommand, prereadCommand]

	/// The closed states of `nativeMnemonicPreread` (第 31(3) 项, 第 59(2)(a) 项).
	enum Preread: String, CaseIterable {
		case valid, absent, unknown
	}

	/// The native reading for the preread. `eoa` and `phrase` are set only for `valid`; the phrase is returned by the preread and by no other answer.
	/// Known limit: `phrase` is a Swift String, which cannot be zeroed. The Data copies this file makes (the item payloads and the MnemonicCopy
	/// buffers) are wiped when the reading is done; the String is not, and it is never logged or stored by the SDK.
	struct Reading: Equatable {
		let state: Preread
		let eoa: String?
		let phrase: String?
		/// The current record of the passcode state, the stored v3 envelope (canonical JSON), returned as it is; nil in the no-passcode state.
		var cipher: Data? = nil

		static let unknown = Reading(state: .unknown, eoa: nil, phrase: nil)
	}

	private static let lock = NSLock()
	/// The most recent accepted seq of `pwaWalletSync` and `pwaEmptySignal` (第 56(1) 项). Process memory only: it restarts at zero (第 56(2) 项).
	private static var lastAcceptedSeq: Int64?

	/// True when `seq` is current: not older than the last accepted seq. Equal is current (第 56(1) 项). Records nothing.
	static func isCurrent(_ seq: Int64) -> Bool {
		lock.lock(); defer { lock.unlock() }
		guard let last = lastAcceptedSeq else { return true }
		return seq >= last
	}

	/// Test seam: a process restart clears the ledger (第 56(2) 项).
	static func restartForTests() {
		lock.lock()
		lastAcceptedSeq = nil
		lock.unlock()
		BeamioPwaPreread.restartForTests()
	}

	/// The most recent accepted `pwaEmptySignal` and its state (第 46(6) 项, 第 59(4)(a) 项). Process memory only, like the seq ledger.
	private static var emptySignal: (seq: Int64, state: String)?

	static func recordEmptySignal(seq: Int64, state: String) {
		lock.lock(); defer { lock.unlock() }
		emptySignal = (seq, state)
	}

	/// The most recent accepted seq of `pwaWalletSync` and `pwaEmptySignal` (第 56(1) 项), or nil before any.
	static func latestAcceptedSeq() -> Int64? {
		lock.lock(); defer { lock.unlock() }
		return lastAcceptedSeq
	}

	/// Records `seq` as the last accepted seq. Called only after a successful write or record.
	static func recordAccepted(_ seq: Int64) {
		lock.lock(); defer { lock.unlock() }
		lastAcceptedSeq = seq
	}

	/// The native read seq of a `pwaEmptySignal` (iOS review 2026-11-17, condition 1): the native reading is taken at the signal, and it carries the signal's
	/// seq when it can be taken (第 46(7) 项). A reading that cannot be taken (snapshot unknown, storage locked, or a read failure) carries no seq, so the
	/// discard is refused. Production passes this to `answer`; the value is nil for any other command.
	static func snapshotReadSeq(body: [String: Any], snapshotKnown: Bool, storageLocked: Bool, store: BeamioChatWalletKeyStoring) -> Int64? {
		guard let seq = BeamioPwaSeq.parse(body["seq"]) else { return nil }
		guard reading(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: store).state != .unknown else { return nil }
		return seq
	}

	/// The answer envelope of one command. `snapshotKnown` false or `storageLocked` true: the native state is not judged, so nothing is read.
	/// `reading` is the native reading of the preread; nil reads the store (the production path).
	static func answer(_ body: [String: Any], snapshotKnown: Bool, storageLocked: Bool, reading: Reading? = nil,
	                   nativeReadSeq: Int64? = nil) -> [String: Any] {
		let type = body["type"] as? String ?? ""
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request")
		}
		if type == prereadCommand {
			return prereadAnswer(body, reqId: echo, snapshotKnown: snapshotKnown, storageLocked: storageLocked, reading: reading)
		}
		// 第 46(5)(6) 项, 第 59(1)(d) 项. CONTRACT: `trustedOrigin` is filled in by the SHELL only, after its own main-frame and source check
		// (the iOS messageHandlers channel). A value that the page puts in its own message proves nothing: the shell must overwrite or drop it, and the SDK takes only the
		// Boolean `true` (a missing value, `false`, the text "true" and any other type are all refused). The SDK cannot tell who set the field, so the contract is the shell's to keep.
		// A refused command reads nothing and writes nothing (tested in MnemonicCipherSyncTests).
		guard body["trustedOrigin"] as? Bool == true else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "untrusted_source")
		}
		// 第 59(1)(c) 项: the only credential field these commands carry is `phrase`. Any other credential field is refused; its value is not echoed.
		// `cipher` (the locked record) and `passcode` (this call's optional passcode) are the fields of the passcode state (finalized section 6).
		if body.keys.contains(where: { !["phrase", "cipher", "passcode"].contains($0) && BeamioConetChatModule.credentialFieldNames.contains($0) }) {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "key_over_bridge_refused")
		}
		guard let seq = BeamioPwaSeq.parse(body["seq"]) else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		}
		if type == emptySignalCommand {
			// 第 53(2) 项: `pwaState` is a closed set; any other value is `unknown` (第 53(3) 项).
			let text = body["pwaState"] as? String ?? ""
			let pwaState = ["valid", "explicit_empty", "unknown"].contains(text) ? text : "unknown"
			// 第 49(1) 项: an internal state that is not ready is write_failed, with its reason; nothing is recorded.
			guard snapshotKnown, !storageLocked else { return writeFailed(reqId: echo, reason: "internal_state") }
			// 第 56(1) 项: an older seq is stale, and it is neither recorded nor used.
			guard isCurrent(seq) else {
				return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["code": "stale_seq"], error: nil)
			}
			// 第 56(1) 项, 第 59(4)(a) 项: the accepted signal is recorded in process memory with its state. It is not durable.
			recordAccepted(seq)
			recordEmptySignal(seq: seq, state: pwaState)
			let accepted = BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["code": "ok"], error: nil)
			// 第 46(6) 项, 第 59(4)(b) 项: the narrow discard needs the accepted signal `explicit_empty` and the native side explicitly empty (no valid
			// mnemonic). Its durable part (intent and audit) is written by `BeamioNarrowDiscardStore`. Unknown is never a basis for a deletion.
			guard pwaState == "explicit_empty" else { return accepted }
			// 第 46(7) 项 (iOS review 2026-11-17): the native reading must carry this signal's own seq. nil (no reading seq, for example a reading that
			// could not be taken) never discards. Production passes `snapshotReadSeq`, computed at the signal; a test passes the seq it models.
			guard nativeReadSeq == seq else { return accepted }
			// The reading is taken (as before) and not held: it is not used below. Its `phrase` is a String and cannot be zeroed; the Data copies
			// behind it are wiped inside `reading`.
			_ = Self.reading(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: BeamioNativeWallet.keyStore)
			// 第 46(6) 项, 第 53(7) 项 (project ruling): the signal must still be the latest accepted seq; a later accepted sync or signal voids it.
			guard latestAcceptedSeq() == seq else { return accepted }
			// 2026-11-17 (project constant): a signal never removes a record. The narrow discard (33(5)) is not run here: no intent, no copy,
			// no removal. The signal is accepted and the store is left as it is.
			return accepted
		}
		if body["cipher"] != nil {
			return cipherSync(body, echo: echo, seq: seq, snapshotKnown: snapshotKnown, storageLocked: storageLocked)
		}
		// 第 59(1)(a) 项, 第 59(3)(a) 项: the phrase must be a valid mnemonic; the optional `eoa` must be the account it derives.
		guard let phrase = body["phrase"] as? String, var derived = derivedAccount(phrase: phrase) else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		}
		defer { BeamioNativeWallet.wipe(&derived.key) }
		if let claimed = body["eoa"], (claimed as? String)?.lowercased() != derived.eoa {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		}
		// 第 49(1) 项: the internal state is not ready, so nothing is read or written.
		guard snapshotKnown, !storageLocked else { return syncFailure(reqId: echo, reason: "internal_state") }
		// 第 56(1) 项: an older seq is stale and is neither written nor recorded.
		guard isCurrent(seq) else {
			return ["type": "ack", "reqId": echo, "ok": false, "error": "stale_seq"]
		}
		// method Y: a plaintext phrase never replaces a v3 envelope of the same account, current or not (that would downgrade the protection). Passcode protection changes
		// only through the passcode commands. A store that cannot list its items is an unknown state: nothing is written.
		if let raw = BeamioNativeWallet.keyStore as? BeamioChatRawItemStoring {
			guard let names = raw.rawAccountNames() else { return syncFailure(reqId: echo, reason: "internal_state") }
			let cipherPrefix = BeamioMnemonicSets.setName(derived.eoa) + ".c."
			if names.contains(where: { $0.hasPrefix(cipherPrefix) }) {
				recordAccepted(seq)
				return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["eoa": derived.eoa, "sync": "unchanged"], error: nil)
			}
		}
		// 第 49(2) 项, 第 59(3)(f) 项: a preread still in flight from before the write is dropped, and after the write the store is read again and published.
		BeamioPwaPreread.beforeWrite()
		let outcome = Self.phraseWrite(phrase: phrase, derived: derived, store: BeamioNativeWallet.keyStore)
		BeamioPwaPreread.afterWrite(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: BeamioNativeWallet.keyStore)
		switch outcome {
		case .updated:
			recordAccepted(seq)
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["eoa": derived.eoa, "sync": "updated"], error: nil)
		case .idempotent:
			recordAccepted(seq)
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["eoa": derived.eoa, "sync": "idempotent"], error: nil)
		case .badRequest:
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		case .failed(let reason):
			return syncFailure(reqId: echo, reason: reason)
		}
	}

	/// The passcode state of `pwaWalletSync` (finalized section 6): `{cipher: <v3 envelope>, passcode?: <six digits>}`. The shape and version are judged before anything is decrypted
	/// (`verify_failed`). With a passcode the envelope is opened in memory only (the vendored Argon2id): a wrong passcode or a failed authentication is `unlock_failed`, a phrase that
	/// derives another address is `verify_failed`; neither writes anything. Without a passcode nothing can be decrypted: the new version is written, read back, and only then does `current`
	/// move (`stored: true`, `readback: "match"` (the string, the only meaning: the bytes read back equal the bytes written), `decrypted: false`). After a passcode is set or changed, the first sync carries the passcode, and `decrypted: true` completes the conversion. The SDK counts no failure and sets no cooldown; the passcode and the envelope are never logged.
	private static func cipherSync(_ body: [String: Any], echo: Any, seq: Int64, snapshotKnown: Bool, storageLocked: Bool) -> [String: Any] {
		guard body["phrase"] == nil, let object = body["cipher"] as? [String: Any] else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		}
		var passcode: [UInt8]?
		if let raw = body["passcode"], !(raw is NSNull) {
			guard let text = raw as? String else { return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request") }
			if !text.isEmpty { passcode = Array(text.utf8) }
		}
		defer { if passcode != nil { BeamioNativeWallet.wipe(&passcode!) } }
		// the order of the checks (M6 v3.2): 1 the shape, 2 the request eoa against the envelope eoa (both before any decryption), 3 the decryption, 4 the derived address
		guard let envelope = BeamioMnemonicCipherV3.parse(object) else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		}
		// the account the request names must be the account of the envelope (an identity mismatch writes nothing and unlocks nothing)
		if let claimed = body["eoa"], (claimed as? String)?.lowercased() != envelope.eoa {
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["code": "verify_failed"], error: nil)
		}
		guard snapshotKnown, !storageLocked else { return syncFailure(reqId: echo, reason: "internal_state") }
		guard isCurrent(seq) else { return ["type": "ack", "reqId": echo, "ok": false, "error": "stale_seq"] }
		var decrypted = false
		var sessionKey: [UInt8]?
		defer { if sessionKey != nil { BeamioNativeWallet.wipe(&sessionKey!) } }
		if let passcode {
			switch BeamioMnemonicCipherV3.open(envelope, passcode: passcode, privateKey: &sessionKey) {
			case .ok: decrypted = true
			case .unlockFailed: return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["code": "unlock_failed"], error: nil)
			case .verifyFailed: return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["code": "verify_failed"], error: nil)
			}
		}
		guard let raw = BeamioNativeWallet.keyStore as? BeamioChatRawItemStoring else { return syncFailure(reqId: echo, reason: "internal_state") }
		// the account the device named before this sync (for the answer of a legal switch)
		var previousAccount: String?
		switch BeamioMnemonicSets.current(store: raw) {
		case .ok(let eoa, _), .cipher(let eoa, _): previousAccount = eoa
		default: break
		}
		// M6 v3.3: without a passcode nothing can be verified. When the account already has a v3 version, an envelope of other bytes is refused (nothing is written, no version is added,
		// current does not move); the same bytes are idempotent (below). An account with no version at all is stored as before.
		if !decrypted {
			guard let names = raw.rawAccountNames() else { return syncFailure(reqId: echo, reason: "internal_state") }
			let prefix = BeamioMnemonicSets.setName(envelope.eoa) + ".c."
			let versions = names.filter { $0.hasPrefix(prefix) }
			if !versions.isEmpty && !versions.contains(BeamioMnemonicSets.cipherItemName(envelope)) {
				return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
			}
		}
		BeamioPwaPreread.beforeWrite()
		let saved = BeamioMnemonicSets.saveCipher(envelope: envelope, store: raw, utc: BeamioNativeKeyImport.utcSeconds(Date()))
		BeamioPwaPreread.afterWrite(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: BeamioNativeWallet.keyStore)
		switch saved {
		case .updated, .idempotent:
			recordAccepted(seq)
			// method Y: the record stays the envelope; a correct passcode only readies the session, with the key in process memory (never stored)
			if decrypted, let key = sessionKey {
				BeamioCipherUnlock.hold(eoa: envelope.eoa, key: key)
				BeamioNativeKeySnapshot.invalidate()   // the gate judges the account again, now that its session is ready
				// a legal account switch (the device named another account before): the answer says the account was saved and made current; the session is ready for it
				if let previous = previousAccount, previous != envelope.eoa {
					return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["eoa": envelope.eoa, "sync": "updated"], error: nil)
				}
			}
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["code": "ok", "stored": true, "readback": "match", "decrypted": decrypted], error: nil)
		case .badRequest:
			return BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request")
		case .failed(let reason):
			return syncFailure(reqId: echo, reason: reason)
		}
	}

	/// The pwaWalletSync failure answer (v3.2 section eleven): flat `error` and `reason`, the reason from the fixed words only.
	static func syncFailure(reqId: Any, reason: String) -> [String: Any] {
		["type": "ack", "reqId": reqId, "ok": false, "error": "write_failed", "reason": reason]
	}

	private static func writeFailed(reqId: Any, reason: String) -> [String: Any] {
		BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: ["code": "write_failed", "reason": reason], error: nil)
	}

	// MARK: - Preread (第 31(3) 项, 第 59(2) 项, 第 60 项)

	/// The native reading of the store (第 31(3) 项, r2.5.17; 第 59(2) 项, r2.5.18). A readable store with no mnemonic is `absent`. A single valid
	/// mnemonic is `valid`, with its account and its phrase. An unreadable store, or any mnemonic that is not a single valid one, is `unknown`.
	/// Nothing is written, renamed or deleted.
	///
	/// Source order (-59E-mnemonic-source-priority, E9.2, 2026-11-17): (1) the current record (`mnemonic:<eoa>`); a valid one is the answer and
	/// no sealed copy is read (E9.2-1, E9.2-2); a read failure of the current record is `unknown`, never a jump to a copy (E9.2-3). (2) Only with no valid
	/// current record, the sealed copies named by the registers (`copiedMnemonics`). One valid copy account is the answer. Several copy accounts, all
	/// valid, take the one sealed most recently by the audit timestamp; a tie or a missing timestamp is `unknown` (E92-06). Several valid current
	/// records keep the multi-account rule (`unknown`, E71-05). No valid phrase anywhere, all read: `absent`, onboarding.
	/// The shell-side encrypted copy of an account (E9.3.1): the record the shell keeps, read through this seam. Production reads the encrypted shell
	/// record store; a test replaces it.
	static var shellCopyReader: (String) -> BeamioShellRecord.ShellRecordRead = { account in
		BeamioShellRecord.EncryptedShellRecordStore.production.read(account: account)
	}

	/// Whether a failed read of the shell copy of `account` is deterministic (E9.3.1-2). Production asks the record store; a test replaces it.
	static var shellCopyDeterministic: (String) -> Bool = { account in
		BeamioShellRecord.EncryptedShellRecordStore.production.readFailureIsDeterministic(account: account)
	}

	/// The judgement of one shell copy (E9.3.1-2): `valid` with its phrase; `none` (absent, empty, or a readable phrase that does not derive the owner,
	/// which is not a credential, E7); `unknown` (unreadable and not the pending write of the marker).
	enum ShellCopy: Equatable {
		case valid(String)
		case none
		case unknown
	}

	static func shellCopy(owner: String, pendingOwners: Set<String>) -> ShellCopy {
		switch shellCopyReader(owner) {
		case .absent:
			return .none
		case .unreadable:
			// E9.3.1-2: an unreadable copy is ignored only when the marker (phase pending) names it as this write's unfinished record AND the failure is
			// deterministic. A transient failure (the key is not loadable, a locked keychain) is unknown.
			return pendingOwners.contains(owner) && shellCopyDeterministic(owner) ? .none : .unknown
		case .record(let object):
			guard let text = object["mnemonicPhrase"] as? String, !text.isEmpty else { return .none }
			guard let derived = derivedAccount(phrase: text), derived.eoa.lowercased() == owner.lowercased() else { return .none }
			return .valid(text)
		}
	}

	/// The owners whose unfinished write the marker (phase pending) names. nil when the marker exists but cannot be read or parsed (unknown).
	static func pendingOwners(store: BeamioChatRawItemStoring) -> Set<String>? {
		switch store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount) {
		case .absent: return []
		case .unreadable: return nil
		case .present(let bytes):
			guard let marker = BeamioPwaPhraseOverwrite.parseMarker(bytes) else { return nil }
			guard marker.phase == .pending else { return [] }
			return Set(marker.owners.map { $0.lowercased() } + [marker.eoa.lowercased()])
		}
	}

	/// The native reading of the store (第 31(3) 项, r2.5.17; 第 59(2) 项, r2.5.18). A readable store with no mnemonic is `absent`. A single valid
	/// mnemonic is `valid`, with its account and its phrase. An unreadable store, or any mnemonic that is not a single valid one, is `unknown`.
	/// Nothing is written, renamed or deleted.
	///
	/// Source order (-59E-mnemonic-source-priority; E9.2, E9.2.1, E9.3.1, 2026-11-17):
	/// 1. The current records at the same position: the native `mnemonic:<eoa>` item and the shell-side encrypted copy (E9.3.1-1). One valid account
	/// among them is the answer (E9.2-1, E9.3.1-3); two valid accounts that differ are unknown (E93-05); a read failure of either is unknown, and
	/// there is no jump to a sealed copy (E9.2-3, E9.3.1-2). With no valid current record, the sealed copies are not read for a valid current answer.
	/// 2. Only when both current records are confirmed to hold no valid phrase: the sealed copies named by the registers (`copiedMnemonics`). One
	/// valid copy account is the answer. Several copy accounts, all valid: the copy sealed most recently by the audit timestamp; a tie, a missing
	/// timestamp or a read failure is `unknown` (E9.2.1, E92-06 to 06c).
	/// 3. No valid phrase anywhere, all read: `absent`, onboarding.
	static func reading(snapshotKnown: Bool, storageLocked: Bool, store: BeamioChatWalletKeyStoring) -> Reading {
		guard snapshotKnown, !storageLocked else { return .unknown }
		// The current set of the no-passcode state comes first. A confirmed absence goes on to the other sources; any other failure is unknown, never absent.
		if let raw = store as? BeamioChatRawItemStoring {
			switch BeamioMnemonicSets.current(store: raw) {
			case .ok(let eoa, let phrase): return Reading(state: .valid, eoa: eoa, phrase: phrase)
			case .cipher(let eoa, let envelope): return Reading(state: .valid, eoa: eoa, phrase: nil, cipher: envelope)
			case .confirmedMissing:
				// No pointer. A v3 cipher version item without a pointer is a record the pointer failed to name (the version is written before the pointer):
				// the answer is a read failure, never "missing". Retrying the same envelope writes the pointer. A version of an identity that was cleared is ignored
				// with it. A store that cannot list its items, or an unreadable marker, is unknown too.
				guard BeamioMnemonicSets.orphanVersionsBlock(store: store) == false else { return .unknown }
			case .readError, .unknown, .verifyFailed: return .unknown
			}
		}
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		if !inventory.enumerated { return .unknown }
		let live = Set(inventory.valid.map { $0.eoa.lowercased() })
		if live.count > 1 { return .unknown }
		// Position 1 (E9.3.1-1): the native mnemonic items and the shell copy, of every account the native store lists, and of the account a marker names.
		let raw = store as? BeamioChatRawItemStoring
		let pending: Set<String>
		if let raw {
			guard let names = pendingOwners(store: raw) else { return .unknown }
			pending = names
		} else {
			pending = []
		}
		// E9.1-1 (-59E-halfwrite, 2026-11-17): a mnemonic item that cannot be read is a failure, unless a pending marker names it as this write's
		// unfinished record. Such an item is ignored (counted as no phrase); any other unreadable item is unknown.
		let unreadable = Set(inventory.accounts.filter { $0.state == .unreadable }.map { $0.eoa.lowercased() })
		guard unreadable.isSubset(of: pending) else { return .unknown }
		// Only a deterministic failure (absent, or an item that does not decode) may be ignored. A transient one (a locked keychain, before the first
		// unlock) is a read failure: unknown, data kept, retry (requirement).
		let items = store as? BeamioChatMnemonicKeyStoring
		guard !unreadable.contains(where: { items?.mnemonicReadFailureIsTransient(owner: $0) ?? true }) else { return .unknown }
		// E9.1.2-1 (b): a key missing while its record exists is a temporary failure: unknown, never ignored.
		// Only a present key record allows ignoring the marked item; absent, unreadable, or any other state is unknown (review 2026-11-17).
		guard !unreadable.contains(where: { store.keyRecordState(eoa: $0) != .present }) else { return .unknown }
		let listed = inventory.accounts.filter { !unreadable.contains($0.eoa.lowercased()) }
		// A shell copy exists only where a native key exists (replicaAnswer needs the key), so the key owners are checked as well. An unlisted key
		// store is unknown.
		guard let keyOwners = store.enumerateKeyOwners() else { return .unknown }
		var owners = Set(listed.map { $0.eoa.lowercased() })
		owners.formUnion(keyOwners.map { $0.lowercased() })
		owners.formUnion(pending)
		var shellValid: [String: String] = [:]
		for owner in owners.sorted() {
			switch shellCopy(owner: owner, pendingOwners: pending) {
			case .valid(let text): shellValid[owner] = text
			case .none: break
			case .unknown: return .unknown
			}
		}
		let current = live.union(shellValid.keys)
		if current.count > 1 { return .unknown }
		if let eoa = current.first {
			if live.contains(eoa) { return phraseReading(eoa: eoa, store: store, source: .current) }
			guard let text = shellValid[eoa] else { return .unknown }
			let shell = MnemonicCopy(name: "shell", owner: eoa, state: .valid, phrase: Data(text.utf8), sealedAt: nil)
			defer { shell.wipe() }
			return phraseReading(eoa: eoa, store: store, source: .copy(shell))
		}
		// Position 2: no valid current record. The sealed copies (E9.2-2). A read failure of a named copy is unknown (copiedMnemonics).
		guard let copies = copiedMnemonics(store: store) else { return .unknown }
		defer { copies.forEach { $0.wipe() } }
		let valid = copies.filter { $0.state == .valid }
		if valid.isEmpty {
			if listed.isEmpty { return Reading(state: .absent, eoa: nil, phrase: nil) }
			// E7 (ruling of the project lead, 2026-11-17): a mnemonic record that is readable but not a valid phrase (a deterministic check failure, corrupt) is not
			// an account credential: absent, so the start goes to onboarding. The record is kept, not deleted. Read failures stay unknown (readFailed above).
			// E7-7 N5 (determinism): the same readable-but-invalid result on a second read; any difference or read failure is unknown.
			let again = BeamioNativeMnemonicInventory.read(store: store)
			let againUnreadable = Set(again.accounts.filter { $0.state == .unreadable }.map { $0.eoa.lowercased() })
			let againListed = again.accounts.filter { !againUnreadable.contains($0.eoa.lowercased()) }
			guard again.enumerated, againUnreadable.isSubset(of: pending), again.valid.isEmpty,
			      againListed.map({ $0.eoa }) == listed.map({ $0.eoa }),
			      againListed.map({ $0.state }) == listed.map({ $0.state }),
			      againUnreadable == unreadable
			else { return Reading(state: .unknown, eoa: nil, phrase: nil) }
			return Reading(state: .absent, eoa: nil, phrase: nil)
		}
		let owners2 = Set(valid.map { $0.owner })
		let chosen: MnemonicCopy
		if owners2.count == 1 {
			chosen = valid[0]
		} else {
			// E9.2.1 (E92-06 to 06c): the copy sealed most recently by the audit timestamp. A missing or equal timestamp is unknown; nothing is chosen silently.
			guard let latest = latestSealed(valid) else { return .unknown }
			chosen = latest
		}
		return phraseReading(eoa: chosen.owner, store: store, source: .copy(chosen))
	}

	private enum PhraseSource {
		case current
		case copy(MnemonicCopy)
	}

	/// The reading of one account whose mnemonic is the answer: the pointer rule (E7.1) and the phrase from the chosen source.
	private static func phraseReading(eoa: String, store: BeamioChatWalletKeyStoring, source: PhraseSource) -> Reading {
		let pointer = BeamioNativeAccountPointer.get().lowercased()
		if !pointer.isEmpty, pointer != eoa { return .unknown }
		switch source {
		case .current:
			guard let items = store as? BeamioChatMnemonicKeyStoring, var raw = items.readItem(.mnemonic, eoa: eoa) else { return .unknown }
			defer { BeamioNativeWallet.wipe(&raw) }
			guard let phrase = String(data: raw, encoding: .utf8) else { return .unknown }
			return Reading(state: .valid, eoa: eoa, phrase: phrase)
		case .copy(let copy):
			guard let bytes = copy.phrase, let phrase = String(data: bytes, encoding: .utf8) else { return .unknown }
			return Reading(state: .valid, eoa: eoa, phrase: phrase)
		}
	}

	/// The valid copy sealed most recently, by the audit timestamps of its own sealing rows. nil when any valid copy has no readable timestamp, or when the
	/// latest timestamp is shared by two copies (E92-06: unknown).
	private static func latestSealed(_ valid: [MnemonicCopy]) -> MnemonicCopy? {
		let formatter = ISO8601DateFormatter()
		var dated: [(copy: MnemonicCopy, at: Date)] = []
		for copy in valid {
			guard let text = copy.sealedAt, let at = formatter.date(from: text) else { return nil }
			dated.append((copy, at))
		}
		guard let newest = dated.map({ $0.at }).max() else { return nil }
		let winners = dated.filter { $0.at == newest }
		return winners.count == 1 ? winners[0].copy : nil
	}

	/// The buffer of a copied phrase. A class, so that every copy of the `MnemonicCopy` value shares one buffer and one wipe zeroes it in place
	/// (a value-type Data that several holders share would be copied by the wipe, and the shared bytes would stay).
	final class PhraseBuffer {
		fileprivate var bytes: Data
		init(_ bytes: Data) { self.bytes = bytes }
		fileprivate func wipe() { BeamioNativeWallet.wipe(&bytes) }
	}

	/// One copy of a mnemonic item that the registers name, judged from its own payload. `phrase` is set only for `valid`. `sealedAt` is the UTC
	/// timestamp of the latest audit row that names this copy (nil when there is none). `wipe()` zeroes the phrase bytes; the reader calls it once
	/// the reading is done.
	struct MnemonicCopy {
		let name: String
		let owner: String
		let state: BeamioMnemonicAccountState
		let sealedAt: String?
		private let buffer: PhraseBuffer?
		var phrase: Data? { buffer?.bytes }

		init(name: String, owner: String, state: BeamioMnemonicAccountState, phrase: Data?, sealedAt: String?) {
			self.name = name
			self.owner = owner
			self.state = state
			self.sealedAt = sealedAt
			self.buffer = phrase.map { PhraseBuffer($0) }
		}

		func wipe() { buffer?.wipe() }
	}

	/// The mnemonic-item name prefix (the account name of a mnemonic item in every store, `mnemonic:<owner>`).
	private static let mnemonicNamePrefix = "mnemonic:"

	/// The copies of mnemonic items named by the overwrite marker (moves and partials), by the overwrite audit rows, and by a discard intent. A
	/// register that is absent names nothing; a register that cannot be read or parsed, or a named copy that cannot be read, gives nil (unknown). The
	/// copies are judged in place: nothing is written, renamed or deleted. A store that keeps no raw payloads has no copies.
	static func copiedMnemonics(store: BeamioChatWalletKeyStoring) -> [MnemonicCopy]? {
		guard let raw = store as? BeamioChatRawItemStoring else { return [] }
		var named: [(name: String, owner: String)] = []
		var auditTimes: [String: String] = [:]
		func collect(from: String, to: String) {
			guard from.hasPrefix(mnemonicNamePrefix) else { return }
			let owner = String(from.dropFirst(mnemonicNamePrefix.count)).lowercased()
			guard !owner.isEmpty, !named.contains(where: { $0.name == to }) else { return }
			named.append((to, owner))
		}
		// The overwrite marker (any phase). Present but unparseable: its names are unknown, so the reading is unknown.
		switch raw.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount) {
		case .absent: break
		case .unreadable: return nil
		case .present(let bytes):
			guard let marker = BeamioPwaPhraseOverwrite.parseMarker(bytes) else { return nil }
			for move in marker.moves + marker.partials { collect(from: move.from, to: move.to) }
		}
		// The overwrite audit: one row per renamed record, with its `from`, `to` and UTC time (the sealing timestamp, E92-06).
		switch raw.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount) {
		case .absent: break
		case .unreadable: return nil
		case .present(let bytes):
			guard let rows = try? JSONSerialization.jsonObject(with: bytes) as? [Any] else { return nil }
			for case let row as [String: String] in rows {
				guard let from = row["from"], let to = row["to"] else { continue }
				collect(from: from, to: to)
				if let utc = row["utc"], from.hasPrefix(mnemonicNamePrefix) { auditTimes[to] = utc }
			}
		}
		// A discard intent (its moves are the private-key records only, so nothing is collected from it unless a mnemonic name is listed).
		switch raw.rawRead(account: BeamioNarrowDiscardStore.intentAccount) {
		case .absent: break
		case .unreadable: return nil
		case .present(let bytes):
			guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
			      let list = object["moves"] as? [[String: String]]
			else { return nil }
			for row in list { if let from = row["from"], let to = row["to"] { collect(from: from, to: to) } }
		}
		var copies: [MnemonicCopy] = []
		for entry in named {
			switch raw.rawRead(account: entry.name) {
			case .absent: continue
			case .unreadable: return nil
			case .present(var bytes):
				defer { BeamioNativeWallet.wipe(&bytes) }
				let judged = raw.judgeMnemonicPayload(bytes, owner: entry.owner)
				if judged.state == .unreadable { return nil }
				copies.append(MnemonicCopy(name: entry.name, owner: entry.owner, state: judged.state, phrase: judged.phrase,
				                           sealedAt: auditTimes[entry.name]))
			}
		}
		return copies
	}

	/// The three-value state only (第 31(3) 项): the reading without its phrase.
	static func preread(snapshotKnown: Bool, storageLocked: Bool, store: BeamioChatWalletKeyStoring) -> Preread {
		reading(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: store).state
	}

	/// 第 59(2)(c) 项, 第 60(3) 项: the order is trusted origin, then seq format, then stale seq, then the native state. A preread never records a seq.
	private static func prereadAnswer(_ body: [String: Any], reqId: Any, snapshotKnown: Bool, storageLocked: Bool, reading: Reading?) -> [String: Any] {
		guard body["trustedOrigin"] as? Bool == true else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: nil, error: "untrusted_source")
		}
		// E1 (v3.3.1): the preread request carries no credential field, `phrase` included (the phrase exception is for pwaWalletSync only).
		if body.keys.contains(where: { $0 == "phrase" || BeamioConetChatModule.credentialFieldNames.contains($0) }) {
			return BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: nil, error: "key_over_bridge_refused")
		}
		guard let seq = BeamioPwaSeq.parse(body["seq"]) else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: nil, error: "bad_request")
		}
		guard isCurrent(seq) else {
			return BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: nil, error: "stale_seq")
		}
		let current = reading ?? BeamioPwaPreread.current(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: BeamioNativeWallet.keyStore)
		// and the finalized section 5 and 6: the answer is `result.code`. The current record is returned as it is: a plaintext mnemonic with its
		// address (the no-passcode state), or a confirmed absence; a read that fails or cannot be confirmed is `read_error`, never a confirmed absence. No passcode
		// is asked, nothing is unlocked, and the SDK need not be initialized: no passcode state and no lock gates this answer. The mnemonic goes only through
		// the trusted bridge and never to a log. (The ciphertext of the passcode state is returned the same way once the cipher storage exists.)
		var result: [String: Any]
		switch current.state {
		case .valid:
			if let envelope = current.cipher {
				// the passcode state: the saved ciphertext as it is, never decrypted, no passcode asked
				if let object = try? JSONSerialization.jsonObject(with: envelope) as? [String: Any] {
					result = ["code": "ok", "cipher": object]
				} else {
					result = ["code": "read_error"]
				}
			} else if let phrase = current.phrase {
				result = ["code": "ok", "mnemonic": phrase]
				// the address is returned when the reading knows it (the set storage names it); an older source may not
				if let eoa = current.eoa { result["eoa"] = eoa }
			} else {
				result = ["code": "read_error"]
			}
		case .absent:
			result = ["code": "confirmed_missing"]
		case .unknown:
			result = ["code": "read_error"]
		}
		return BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: result, error: nil)
	}

	// MARK: - Write (第 59(3) 项)

	enum SyncWrite: Equatable {
		case updated
		case idempotent
		case badRequest
		/// `reason` is one of the closed words `internal_state` and `storage_write` (第 49(1a) 项), or the proposed words `sealing_failed` and
		/// `readback_mismatch` (r2.5.21, 拟定; not yet in the closed set, to be confirmed).
		case failed(String)
	}

	/// The phrase as the store keeps it: words separated by one space, lower case, UTF-8.
	static func normalized(_ phrase: String) -> Data {
		Data(phrase.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ").lowercased().utf8)
	}

	/// The derived account and key of a phrase, or nil when the phrase is not a valid mnemonic.
	static func derivedAccount(phrase: String) -> (eoa: String, key: Data)? {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return nil }
		defer { BeamioNativeWallet.wipe(&key) }
		guard BeamioNativeEthSigner.isValidKey(key),
		      let address = BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
		else { return nil }
		return (address, Data(key))
	}

	/// 第 59(3) 项: (a) the account derives from the phrase (checked by the caller); (b) no record: the import (第 28 项); (c) the same account and the
	/// same phrase: idempotent; (d) the record is unreadable: write_failed; (e) a different record: the overwrite with isolation.
	/// E5.1 PHRASE_ONLY (§25.52Y.117, §56(3)): the pointer account has a readable phrase and no key record. Read only; nil otherwise.
	static func phraseOnlyResidueEOA(store: BeamioChatWalletKeyStoring) -> String? {
		let pointer = BeamioNativeAccountPointer.get().lowercased()
		guard !pointer.isEmpty, let items = store as? BeamioChatMnemonicKeyStoring else { return nil }
		guard items.itemState(.key, eoa: pointer) == .absent else { return nil }
		guard items.itemState(.mnemonic, eoa: pointer) == .present, let raw = items.readItem(.mnemonic, eoa: pointer),
		      let text = String(data: raw, encoding: .utf8), let derived = derivedAccount(phrase: text), derived.eoa == pointer
		else { return nil }
		return pointer
	}

#if BEAMIO_TEST_HOOKS
	/// Test seam only: the tests of the withdrawn overwrite and sealing format (never published) switch it on. The default is off,
	/// which is the production behaviour: a phrase goes into the no-passcode set storage.
	static var legacyPhraseWriteForTests = false
#endif

	/// The write of a validated phrase from the trusted bridge (the no-passcode state, finalized section 1): into the set storage, never as a device record.
	private static func phraseWrite(phrase: String, derived: (eoa: String, key: Data), store: BeamioChatWalletKeyStoring) -> SyncWrite {
		#if BEAMIO_TEST_HOOKS
		if legacyPhraseWriteForTests { return syncWrite(phrase: phrase, derived: derived, store: store) }
		#endif
		guard let raw = store as? BeamioChatRawItemStoring else { return .failed("internal_state") }
		switch BeamioMnemonicSets.save(phrase: phrase, store: raw, utc: BeamioNativeKeyImport.utcSeconds(Date())) {
		case .updated: return .updated
		case .idempotent: return .idempotent
		case .badRequest: return .badRequest
		case .failed(let reason): return .failed(reason)
		}
	}

	private static func syncWrite(phrase: String, derived: (eoa: String, key: Data), store: BeamioChatWalletKeyStoring) -> SyncWrite {
		// A valid phrase-only residue at the current pointer is repaired in place: derive the same account key, write it
		// through the wallet store's normal passcode/device wrapping path, and verify read-back. Do not move, replace, or
		// delete the existing phrase or any other wallet item.
		if let residue = phraseOnlyResidueEOA(store: store) {
			guard residue == derived.eoa, let items = store as? BeamioChatMnemonicKeyStoring else { return .failed("internal_state") }
			var stored = items.readItem(.mnemonic, eoa: residue)
			defer { if stored != nil { BeamioNativeWallet.wipe(&stored!) } }
			var want = normalized(phrase)
			defer { BeamioNativeWallet.wipe(&want) }
			var storedNormalized = stored.map { normalized(String(decoding: $0, as: UTF8.self)) }
			defer { if storedNormalized != nil { BeamioNativeWallet.wipe(&storedNormalized!) } }
			guard stored != nil, want == storedNormalized,
			      var storedDerived = derivedAccount(phrase: String(decoding: stored!, as: UTF8.self))
			else { return .failed("internal_state") }
			defer { BeamioNativeWallet.wipe(&storedDerived.key) }
			guard storedDerived.eoa == residue,
			      items.itemState(.key, eoa: residue) == .absent,
			      store.write(eoa: residue, key: storedDerived.key),
			      store.read(eoa: residue) == storedDerived.key,
			      items.readItem(.mnemonic, eoa: residue) == stored
			else { return .failed("internal_state") }
			return .updated
		}
		guard let items = store as? BeamioChatRawItemStoring else { return .failed("internal_state") }
		// The start-up settling of an overwrite left behind comes first (第 59(3)(e)(7)).
		guard BeamioPwaPhraseOverwrite.recoverAtStart(store: items) else { return .failed("internal_state") }
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		if inventory.readFailed { return .failed("internal_state") }
		var want = normalized(phrase)
		defer { BeamioNativeWallet.wipe(&want) }
		if let own = inventory.accounts.first(where: { $0.eoa == derived.eoa }) {
			guard own.state == .valid, var stored = items.readItem(.mnemonic, eoa: derived.eoa) else { return .failed("internal_state") }
			defer { BeamioNativeWallet.wipe(&stored) }
			if stored == want { return .idempotent }
		}
		if inventory.accounts.isEmpty {
			// (b) 第 28 项: the import of a new account. An existing key record of the account is `already_exists`, which this answer does not give (第 59(3)(g) 项).
			switch BeamioNativeKeyImport.importRecoveryPhraseReport(text: phrase, expectedEoa: derived.eoa, store: store).outcome {
			case .imported: return .updated
			case .invalidFormat, .invalidMnemonic, .invalidKey, .addressMismatch: return .badRequest
			case .writeFailed: return .failed("storage_write")
			case .alreadyPresent, .readBackFailed, .rollbackPending, .unavailable, .cancelled: return .failed("internal_state")
			}
		}
		// (e) a different record: the overwrite. Its owners are every account that holds a mnemonic on this device.
		let result = BeamioPwaPhraseOverwrite.run(eoa: derived.eoa, phrase: want, key: derived.key, owners: inventory.accounts.map { $0.eoa },
		                                          store: items, utc: BeamioNativeKeyImport.utcSeconds(Date()), tag: UUID().uuidString)
		if let reason = wireReason(result) { return .failed(reason) }
		return .updated
	}

	/// The reason on the wire for a failed overwrite (v3.2 section eleven, section six): only the fixed words `storage_write` and `internal_state`.
	/// The internal labels (sealing_failed, readback_mismatch, rollback_pending, unknown_loss) are not sent. nil for `updated`.
	static func wireReason(_ result: BeamioPwaPhraseOverwrite.Result) -> String? {
		switch result {
		case .updated: return nil
		case .writeFailed: return "storage_write"
		case .sealingFailed, .readbackMismatch, .internalState: return "internal_state"
		}
	}
}
