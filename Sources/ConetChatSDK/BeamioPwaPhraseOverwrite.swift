import CryptoKit
import Foundation

/// The overwrite of the native mnemonic record by the phrase the PWA sends (25.52Y.163 r2.5.19 第 59(3)(e); revised by r2.5.21, project decision
/// 2026-11-17: the sealed copies of the old wallet are kept after success, and nothing on the write path deletes them).
///
/// The decided order (spec-59e-revision-text-v2-decided.md, section two), on the raw payloads of `BeamioChatRawItemStoring`:
/// 1. the intent marker `prepared` is written; it lists the old owners, the new account and every record to isolate, with its SHA-256 digest;
/// 2. seal: each record is copied byte for byte to its isolation name, the copy is read back (same digest), the audit row is appended, and only then
/// the live name is removed. A failure here is `sealing_failed`;
/// 3. sealing check: each old account that held a mnemonic must still derive that account from its isolated copy; otherwise `sealing_failed`;
/// 4. the marker becomes `pending`; the three records of the new account are written (key, mnemonic, commit); a failed write is `storage_write`;
/// 5. the new records are read back independently; a mismatch is `readback_mismatch`;
/// 6. success: the marker becomes `committed`, the entry of `isolation.retained` is written and read back (once per tag), and then the intent marker is
/// removed. The isolated copies and the audit are kept.
///
/// A failure in steps 2 to 5 restores the old records byte for byte when no new name holds data (the answer is retryable). When a new name holds data,
/// both sides are kept and the state is unknown (`internal_state`, marker stays). Nothing is deleted by a failure path.
/// The start-up recovery (第 59(3)(e)(7), spec v2 section four) finishes a committed or consistent marker, keeps the state unknown while a new name holds
/// data without a consistent set, and otherwise restores the copies.
///
/// The marker, the audit and the retained entries hold account names, phases, UTC times and digests. They never hold key or phrase material.
enum BeamioPwaPhraseOverwrite {
	static let markerAccount = "wallet.sync.marker"
	static let auditAccount = "wallet.sync.audit"
	/// The isolation retained record (r2.5.21): an array of entries, one per completed overwrite. Appended, never removed by the write path.
	static let retainedAccount = "wallet.isolation.retained"
	static let isolationPrefix = "wallet.iso."

	/// `window` (v3.3): the recovery of a half-written overwrite has begun; the partial new records are already moved aside.
	enum Phase: String { case prepared, pending, committed, window }

	/// One record moved aside: the live account, its isolation account, and the SHA-256 digest of the stored payload.
	struct Move: Equatable {
		let from: String
		let to: String
		let digest: String
	}

	/// The intent marker. `owners` are the old accounts (the new account is not one of them).
	struct Marker: Equatable {
		let phase: Phase
		let eoa: String
		let tag: String
		let utc: String
		let owners: [String]
		let moves: [Move]
		/// The renames of the window (v3.3.1 addendum): each partial name, its isolation name and digest, recorded before any rename.
		var partials: [Move] = []
	}

	enum Result: Equatable {
		/// The new record is written, read back and is the account's record.
		case updated
		/// The write failed and every record is as it was before (`storage_write`).
		case writeFailed
		/// The sealing of the old records failed and they are as they were before (`sealing_failed`, proposed reason; retryable).
		case sealingFailed
		/// The read-back of the new records did not match (`readback_mismatch`, proposed reason).
		case readbackMismatch
		/// The state is not known. The marker stays; the start-up recovery settles it (`internal_state`, rollback_pending).
		case internalState
	}

	static func digest(_ bytes: Data) -> String {
		SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
	}

	/// The accounts of one owner's records that an overwrite isolates or writes: the key, mnemonic and commit items, and the K record (blobKey).
	/// The K record is isolated as the other records are (第 59(3)(e) 项, project ruling): a K left in place would pair the old account's K with the new pointer.
	static func ownerAccounts(_ owner: String, store: BeamioChatRawItemStoring) -> [String] {
		[BeamioChatWalletItemKind.key, .mnemonic, .commit].map { store.accountName($0, eoa: owner) } + [BeamioWalletCredentialBlob.account(owner)]
	}

	/// The accounts an overwrite writes for the new account (its three items and its K record).
	static func fixedAccounts(_ eoa: String, store: BeamioChatRawItemStoring) -> [String] {
		ownerAccounts(eoa, store: store)
	}

	/// Runs the overwrite. `owners` are the accounts that hold records on the device; the new account is always included in the collection.
	/// The caller has settled any earlier marker and has checked that `phrase` derives `key` and `eoa`.
	static func run(eoa rawEoa: String, phrase: Data, key: Data, owners: [String], store: BeamioChatRawItemStoring,
	                utc: String, tag: String) -> Result {
		let eoa = rawEoa.lowercased()
		guard case .absent = store.rawRead(account: markerAccount) else { return .internalState }
		let oldOwners = Set(owners.map { $0.lowercased() }).subtracting([eoa]).sorted()
		let collected = Set(owners.map { $0.lowercased() } + [eoa]).sorted()
		// Collect what is isolated. An intent that is still present is not settled here, so nothing is written.
		var moves: [Move] = []
		var payloads: [String: Data] = [:]
		for owner in collected {
			switch store.rawRead(account: store.accountName(.intent, eoa: owner)) {
			case .absent: break
			case .present, .unreadable: return .internalState
			}
			for from in ownerAccounts(owner, store: store) {
				switch store.rawRead(account: from) {
				case .absent: continue
				case .unreadable: return .internalState
				case .present(let bytes):
					moves.append(Move(from: from, to: isolationPrefix + tag + "." + from, digest: digest(bytes)))
					payloads[from] = bytes
				}
			}
		}
		// Classification before any write (v3.2 section two step 5, section four, I-7, I-8): each old account is openable, confirmed lost (all three
		// section-four conditions hold), or unknown. An unknown one stops the overwrite here: nothing is sealed, renamed or written.
		var lostOwners: Set<String> = []
		var corruptOwners: Set<String> = []
		for owner in oldOwners {
			// E7-7 (P-08): a mnemonic record that is readable, deterministically not a valid phrase (corrupt), is kept and sealed like the others: the new
			// account is written only after it is isolated, never over it. Read the same twice.
			let mnemonicName = store.accountName(.mnemonic, eoa: owner)
			// Not a corrupt record when a keystore error or an enumeration failure is in play (section four), or when it is the confirmed-lost shape.
			let probe = wrapAliasProbe(owner)
			let keyAbsent = store.rawRead(account: store.accountName(.key, eoa: owner)) == .absent
			let lostShape = probe == .itemNotFound && keyAbsent
			if let bytes = payloads[mnemonicName], invalidPhrase(bytes), store.rawRead(account: mnemonicName) == .present(bytes),
			   enumerationSucceeds(store), probe != .otherError, !lostShape {
				corruptOwners.insert(owner)
				continue
			}
			switch classify(owner: owner, mnemonic: payloads[store.accountName(.mnemonic, eoa: owner)], store: store) {
			case .openable: continue
			case .confirmedLost: lostOwners.insert(owner)
			case .unknown: return .internalState
			}
		}
		let lostNames = Set(lostOwners.flatMap { ownerAccounts($0, store: store) })
		let corruptNames = Set(corruptOwners.flatMap { ownerAccounts($0, store: store) })
		let fixed = fixedAccounts(eoa, store: store)
		func marker(_ phase: Phase) -> Data {
			markerBytes(Marker(phase: phase, eoa: eoa, tag: tag, utc: utc, owners: oldOwners, moves: moves))
		}
		guard store.rawWrite(account: markerAccount, bytes: marker(.prepared)) else {
			return .writeFailed
		}
		// Step 2: seal. The live bytes are checked against the digest before the copy; the copy is read back; the audit row comes before the rename.
		// v3.2 section two step 4: the audit row is written right after each rename; a failed rename leaves no audit row.
		for move in moves {
			guard let bytes = payloads[move.from], digest(bytes) == move.digest,
			      store.rawRead(account: move.from) == .present(bytes),
			      store.rawWrite(account: move.to, bytes: bytes),
			      store.rawRead(account: move.to) == .present(bytes),
			      store.rawDelete(account: move.from),
			      store.rawRead(account: move.from) == .absent,
			      appendAudit(["from": move.from, "to": move.to, "utc": utc,
			                   "reason": lostNames.contains(move.from) ? "pwa_sync_confirmed_lost" : (corruptNames.contains(move.from) ? "pwa_sync_corrupt_kept" : "pwa_sync")], store: store)
			else {
				return restoreOrKeep(moves, fixed: fixed, store: store, utc: utc, restored: .sealingFailed, kept: .internalState)
			}
		}
		// Step 3: sealing check. The old accounts must stay recoverable from their isolated copies before anything new is written.
		guard sealingHolds(moves, oldOwners: oldOwners.filter { !lostOwners.contains($0) && !corruptOwners.contains($0) }, store: store) else {
			return restoreOrKeep(moves, fixed: fixed, store: store, utc: utc, restored: .sealingFailed, kept: .internalState)
		}
		guard store.rawWrite(account: markerAccount, bytes: marker(.pending)) else {
			return restoreOrKeep(moves, fixed: fixed, store: store, utc: utc, restored: .writeFailed, kept: .internalState)
		}
		// Step 4: the new records.
		let writes: [(BeamioChatWalletItemKind, Data)] = [(.key, key), (.mnemonic, phrase),
		                                                  (.commit, commitBytes(eoa: eoa, utc: utc))]
		for (kind, value) in writes {
			guard store.writeItem(kind, eoa: eoa, value: value) else {
				return restoreOrKeep(moves, fixed: fixed, store: store, utc: utc, restored: .writeFailed, kept: .internalState)
			}
		}
		// Step 5: the independent read-back, from the store, against the values of this request.
		guard var back = readBack(eoa: eoa, store: store) else {
			return restoreOrKeep(moves, fixed: fixed, store: store, utc: utc, restored: .readbackMismatch, kept: .readbackMismatch)
		}
		defer { BeamioNativeWallet.wipe(&back.key); BeamioNativeWallet.wipe(&back.phrase) }
		guard back.key == key, back.phrase == phrase else {
			return restoreOrKeep(moves, fixed: fixed, store: store, utc: utc, restored: .readbackMismatch, kept: .readbackMismatch)
		}
		// Step 6: commit. A committed-marker write that fails is an unknown state: nothing is cleaned up, the recovery finishes it.
		let committed = Marker(phase: .committed, eoa: eoa, tag: tag, utc: utc, owners: oldOwners, moves: moves)
		guard store.rawWrite(account: markerAccount, bytes: markerBytes(committed)) else {
			return .internalState
		}
		guard finishCommit(marker: committed, store: store) else {
			return .internalState
		}
		BeamioNativeAccountPointer.set(eoa)
		return .updated
	}

	/// The start-up settling of a marker left behind (第 59(3)(e)(7)). True when no marker is left.
	static func recoverAtStart(store: BeamioChatRawItemStoring) -> Bool {
		switch store.rawRead(account: markerAccount) {
		case .absent: return true
		case .unreadable: return false
		case .present(let bytes):
			guard let marker = parseMarker(bytes) else { return false }
			// Roll-forward (requirement, (a)(b)(c)): when the marker's account holds a valid mnemonic under its fixed name (confirmed by the read), the
			// interrupted overwrite is finished forward: the account's records stay, nothing is moved or restored, and the marker is isolated (audited). The
			// other accounts' sealed copies stay isolated (kept, counted, bytes unchanged). Rollback applies only when there is no valid current record.
			if marker.phase != .committed,
			   let items = store as? BeamioChatMnemonicKeyStoring, items.itemsAccountState(owner: marker.eoa) == .valid {
				// The retained record of the completed overwrite is written first; then the marker is isolated (audited), not deleted.
				guard recordRetained(marker: marker, store: store) else { return false }
				BeamioNativeAccountPointer.set(marker.eoa)
				return isolateMarker(store: store, utc: marker.utc)
			}
			if marker.phase == .window {
				// A window that has begun is finished by the window rule; the partial new records are no longer under the fixed names.
				return recoverWindow(marker, store: store)
			}
			let consistent = readBack(eoa: marker.eoa, store: store) != nil
			if marker.phase == .committed || consistent {
				guard finishCommit(marker: marker, store: store) else { return false }
				BeamioNativeAccountPointer.set(marker.eoa)
				return true
			}
			let fixed = fixedAccounts(marker.eoa, store: store)
			let partial = fixed.filter { store.rawRead(account: $0) != .absent }
			let dirtyLive = marker.moves.contains { move in
				if case .present(let live) = store.rawRead(account: move.from) { return digest(live) != move.digest }
				return false
			}
			if partial.isEmpty, !dirtyLive {
				// The new names are empty: the sealed records go back to their names (SO-08, WK-43).
				guard rollback(marker.moves, fixed: fixed, store: store, utc: marker.utc, reason: "recovery_restore") else { return false }
				return isolateMarker(store: store, utc: marker.utc)
			}
			// The window (v3.2 section four, SO-25): a new name holds part of the new account without a consistent set.
			return recoverWindow(marker, store: store)
		}
	}

	/// The shell's start-up settling of a marker left behind (第 59(3)(e)(7)), once per process, before the first command reads a record.
	private static let startLock = NSLock()
	private static var settledAtStart = false

	/// The code of the last failed start-up attempt (v3.3.1): recorded, never retried in a loop. nil when the last attempt succeeded or none ran.
	private(set) static var lastRecoveryErrorCode: String?

	/// Settles the leftovers of the PWA write and of the narrow discard, once per process (project ruling): a leftover overwrite marker and a leftover
	/// discard intent are both finished or rolled back at start-up, not at the next signal.
	/// E4 (rollback_pending): an unsettled overwrite marker (a half-written overwrite, `rollback_pending`) is a lock on the family commands and
	/// walletStatus, until the recovery settles it. Reads only.
	static func settlementPending(store: BeamioChatRawItemStoring) -> Bool {
		store.rawRead(account: markerAccount) != .absent
	}

	/// The settlement lock of E4: an overwrite marker or a discard intent is left behind (read only).
	static func settlementLockPending(store: BeamioChatRawItemStoring) -> Bool {
		settlementPending(store: store) || BeamioNarrowDiscardStore.intentPending(store: store)
	}

	static func settleOnceAtStart(store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) {
		startLock.lock()
		let first = !settledAtStart
		settledAtStart = true
		startLock.unlock()
		guard first, let items = store as? BeamioChatRawItemStoring else { return }
		// v3.3.1: one automatic attempt per launch. A failure records its code only; it is not retried in a loop. The user's retry entry (a pwaWalletSync
		// write) runs the recovery again and does not count as an automatic attempt.
		if !recoverAtStart(store: items) { lastRecoveryErrorCode = "rollback_pending" }
		_ = BeamioNarrowDiscardStore.recoverAtStart(store: items)
	}

	/// Test seam: forgets that the start-up settling ran in this process.
	static func resetStartupForTests() {
		startLock.lock()
		settledAtStart = false
		startLock.unlock()
	}

	// MARK: - Steps

	/// A failure before any new name holds data: the old records are restored, the marker is removed, and `restored` is the answer. When a new name
	/// holds data, nothing is changed and `kept` is the answer (the marker stays; the state is unknown).
	private static func restoreOrKeep(_ moves: [Move], fixed: [String], store: BeamioChatRawItemStoring, utc: String,
	                                  restored: Result, kept: Result) -> Result {
		if fixed.contains(where: { store.rawRead(account: $0) != .absent }) { return kept }
		guard rollback(moves, fixed: fixed, store: store, utc: utc, reason: "rollback_restore") else { return .internalState }
		// Rollback and failure paths isolate the marker, never delete it (requirement, Android parity): the bytes move to an isolation name with an audit row.
		guard isolateMarker(store: store, utc: utc) else { return .internalState }
		return restored
	}

	/// Sealing check (step 3): each old account that held a mnemonic must still derive that account from its isolated copy, and the copy must match
	/// its digest. Nothing is written.
	private static func sealingHolds(_ moves: [Move], oldOwners: [String], store: BeamioChatRawItemStoring) -> Bool {
		for owner in oldOwners {
			let from = store.accountName(.mnemonic, eoa: owner)
			guard let move = moves.first(where: { $0.from == from }) else { continue }
			guard case .present(let copy) = store.rawRead(account: move.to), digest(copy) == move.digest,
			      let text = String(data: copy, encoding: .utf8),
			      let derived = BeamioPwaWalletSync.derivedAccount(phrase: text),
			      derived.eoa == owner
			else { return false }
		}
		return true
	}

	/// Finishes a committed overwrite (step 6, and the recovery of a committed or consistent marker). The `isolation.retained` entry of the tag is
	/// appended once and read back; then the intent marker is removed. The isolated copies are never touched. False when a step cannot be verified;
	/// the marker stays and the next start finishes it.
	/// The retained record of a completed overwrite (one entry per old account with records), written and read back. Shared by the commit and by the roll-forward.
	static func recordRetained(marker: Marker, store: BeamioChatRawItemStoring) -> Bool {
		var entries: [[String: Any]] = []
		switch store.rawRead(account: retainedAccount) {
		case .absent: break
		case .unreadable: return false
		case .present(let bytes):
			guard let parsed = try? JSONSerialization.jsonObject(with: bytes) as? [[String: Any]] else { return false }
			entries = parsed
		}
		var appended = false
		for entry in retainedEntries(marker, store: store) where !entries.contains(where: { sameRetained($0, entry) }) {
			entries.append(entry)
			appended = true
		}
		if appended {
			guard let bytes = try? JSONSerialization.data(withJSONObject: entries, options: [.sortedKeys]),
			      store.rawWrite(account: retainedAccount, bytes: bytes),
			      store.rawRead(account: retainedAccount) == .present(bytes)
			else { return false }
		}
		return true
	}

	static func finishCommit(marker: Marker, store: BeamioChatRawItemStoring) -> Bool {
		guard recordRetained(marker: marker, store: store) else { return false }
		guard store.rawDelete(account: markerAccount), store.rawRead(account: markerAccount) == .absent else { return false }
		return true
	}

	/// Puts every record back byte for byte. What the overwrite wrote under the new account's names is removed first (only when `fixed` is empty,
	/// which the callers check). A moved record is restored from its copy when the live name is absent, or the copy is removed when the live name already
	/// holds the original. Anything else is refused without a change. Each restore appends an audit row. True only when every step is verified.
	static func rollback(_ moves: [Move], fixed: [String], store: BeamioChatRawItemStoring, utc: String = "", reason: String? = nil) -> Bool {
		let movedFrom = Set(moves.map { $0.from })
		for account in fixed where !movedFrom.contains(account) {
			guard store.rawDelete(account: account) else { return false }
		}
		for move in moves.reversed() {
			switch store.rawRead(account: move.to) {
			case .present(let copy):
				switch store.rawRead(account: move.from) {
				case .present(let live) where digest(live) == move.digest:
					break // the live name holds the original: only the copy is removed
				case .absent:
					guard digest(copy) == move.digest else { return false }
					guard store.rawWrite(account: move.from, bytes: copy), store.rawRead(account: move.from) == .present(copy) else { return false }
				default:
					return false
				}
				guard reason.map({ appendAudit(["from": move.from, "to": move.to, "utc": utc, "reason": $0], store: store) }) ?? true,
				      store.rawDelete(account: move.to), store.rawRead(account: move.to) == .absent
				else { return false }
			case .absent:
				// The copy was never made, so the live name still holds the original.
				guard case .present(let live) = store.rawRead(account: move.from), digest(live) == move.digest else { return false }
			case .unreadable:
				return false
			}
		}
		return true
	}

	/// The new account's three records, read back from the store. nil when any of them is missing or does not derive the account.
	static func readBack(eoa: String, store: BeamioChatRawItemStoring) -> (key: Data, phrase: Data)? {
		guard let key = store.readItem(.key, eoa: eoa), let phrase = store.readItem(.mnemonic, eoa: eoa),
		      store.readItem(.commit, eoa: eoa) != nil,
		      let text = String(data: phrase, encoding: .utf8),
		      case .key(var derived) = BeamioMnemonicDerivation.derive(phrase: text)
		else { return nil }
		defer { BeamioNativeWallet.wipe(&derived) }
		guard Data(derived) == key else { return nil }
		return (key, phrase)
	}

	// MARK: - Marker, retained, audit and commit records

	private static func markerBytes(_ marker: Marker) -> Data {
		let object: [String: Any] = [
			"v": 1, "phase": marker.phase.rawValue, "eoa": marker.eoa, "tag": marker.tag, "source": "pwaWalletSync",
			"utc": marker.utc, "owners": marker.owners,
			"moves": marker.moves.map { ["from": $0.from, "to": $0.to, "digest": $0.digest] },
			"partials": marker.partials.map { ["from": $0.from, "to": $0.to, "digest": $0.digest] },
		]
		return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
	}

	static func parseMarker(_ bytes: Data) -> Marker? {
		guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
		      object["v"] as? Int == 1,
		      let phase = (object["phase"] as? String).flatMap({ Phase(rawValue: $0) }),
		      let eoa = object["eoa"] as? String,
		      let tag = object["tag"] as? String,
		      let utc = object["utc"] as? String,
		      let owners = object["owners"] as? [String],
		      let list = object["moves"] as? [[String: String]]
		else { return nil }
		let moves = list.compactMap { row -> Move? in
			guard let from = row["from"], let to = row["to"], let digest = row["digest"] else { return nil }
			return Move(from: from, to: to, digest: digest)
		}
		guard moves.count == list.count else { return nil }
		let partialRows = (object["partials"] as? [[String: String]]) ?? []
		let partials = partialRows.compactMap { row -> Move? in
			guard let from = row["from"], let to = row["to"], let digest = row["digest"] else { return nil }
			return Move(from: from, to: to, digest: digest)
		}
		guard partials.count == partialRows.count else { return nil }
		return Marker(phase: phase, eoa: eoa, tag: tag, utc: utc, owners: owners, moves: moves, partials: partials)
	}

	/// One `isolation.retained` entry per old account that had records (v3.3 section five): exactly five non-secret fields. The keyID is the EOA, so
	/// it is not stored twice. No key, phrase, password, PIN, PGP key or ciphertext is stored here.
	static func retainedEntries(_ marker: Marker, store: BeamioChatRawItemStoring) -> [[String: Any]] {
		marker.owners.compactMap { owner -> [String: Any]? in
			let names = Set(ownerAccounts(owner, store: store))
			let mine = marker.moves.filter { names.contains($0.from) }
			guard !mine.isEmpty else { return nil }
			return [
				"oldEoa": owner,
				"time": marker.utc,
				"auditRef": marker.tag,
				"isolatedNames": mine.map { $0.to },
				"oldSha": mine.map { $0.digest },
			]
		}
	}

	/// The same retained record: the same audit reference for the same old account.
	private static func sameRetained(_ a: [String: Any], _ b: [String: Any]) -> Bool {
		(a["auditRef"] as? String) == (b["auditRef"] as? String) && (a["oldEoa"] as? String) == (b["oldEoa"] as? String)
	}

	/// A stored phrase that is not a valid BIP-39 phrase for any account (the check failed deterministically). Read only.
	static func invalidPhrase(_ bytes: Data) -> Bool {
		guard let text = String(data: bytes, encoding: .utf8) else { return true }
		return BeamioPwaWalletSync.derivedAccount(phrase: text) == nil
	}

	/// The mnemonic record derives the owner account (the existing unwrap rule). No key is returned.
	static func openable(_ bytes: Data, owner: String) -> Bool {
		guard let text = String(data: bytes, encoding: .utf8), let derived = BeamioPwaWalletSync.derivedAccount(phrase: text) else { return false }
		return derived.eoa == owner.lowercased()
	}

	/// The old-record state of section four (v3.2): `openable`, `confirmedLost` (all three conditions hold), or `unknown`.
	enum OldRecordState: Equatable { case openable, confirmedLost, unknown }

	/// Condition 2 of section four (v3.3, SO-22F): the result of probing the iOS SE wrapping item (alias `beamio.wallet.wrap.v1`). Only `itemNotFound`
	/// counts as missing; any other error code is unknown. This code does not probe the keychain yet, so the default is `present` and no account is
	/// classified lost in production (conservative). Tests set this seam.
	enum AliasProbe: Equatable { case present, itemNotFound, otherError }
	static var wrapAliasProbe: (String) -> AliasProbe = { _ in .present }

	/// Condition 1 of section four: the keystore enumeration succeeds. Production: the store's own enumeration (nil is a failure).
	static var enumerationSucceeds: (BeamioChatRawItemStoring) -> Bool = { $0.enumerateKeyOwners() != nil }

	/// Classifies one old account (section four). Lost needs all three conditions: enumeration succeeds, the wrap alias is missing, and the native side
	/// has no readable phrase and no readable key. Anything else that is not openable is unknown: a read error, a failed enumeration, a present key.
	static func classify(owner: String, mnemonic: Data?, store: BeamioChatRawItemStoring) -> OldRecordState {
		if let mnemonic, openable(mnemonic, owner: owner) { return .openable }
		guard enumerationSucceeds(store), wrapAliasProbe(owner) == .itemNotFound else { return .unknown }
		let phraseReadable: Bool
		switch store.rawRead(account: store.accountName(.mnemonic, eoa: owner)) {
		case .absent: phraseReadable = false
		case .present(let bytes):
			phraseReadable = String(data: bytes, encoding: .utf8).map { BeamioPwaWalletSync.derivedAccount(phrase: $0) != nil } ?? false
		case .unreadable: return .unknown
		}
		switch store.rawRead(account: store.accountName(.key, eoa: owner)) {
		case .absent: break
		case .present, .unreadable: return .unknown
		}
		return phraseReadable ? .unknown : .confirmedLost
	}

	/// The window recovery (v3.2 section four, SO-25; v3.3 per entry, SO-25b; E2 addendum, SO-25d/e/f).
	/// 1. Validation before any change: each entry has its sealed copy with the right digest, or its live name already holds the original, and a
	/// mnemonic copy opens to its owner.
	/// 2. The partial names (new-account names that hold data, and old live names that hold other content) are recorded in the marker, with their
	/// digests, before anything is renamed. The marker moves to the `window` phase.
	/// 3. Each partial is renamed to an isolation name (never deleted). The rename is audited after it succeeds; a rename that cannot be completed is
	/// undone only for its own copy, and nothing is audited. A rename whose audit row is missing gets it written on the next start (matched by name).
	/// 4. Each entry is restored from its sealed copy and read back by digest (an entry already restored is left as it is); each restored mnemonic opens
	/// to its owner; then the marker goes. Any step that cannot be verified returns false: the marker stays and the next start retries
	/// (rollback_pending, never a permanent unknown).
	private static func recoverWindow(_ marker: Marker, store: BeamioChatRawItemStoring) -> Bool {
		for move in marker.moves {
			if case .present(let live) = store.rawRead(account: move.from), digest(live) == move.digest { continue }
			guard case .present(let copy) = store.rawRead(account: move.to), digest(copy) == move.digest else { return false }
			if let owner = marker.owners.first(where: { store.accountName(.mnemonic, eoa: $0) == move.from }), !openable(copy, owner: owner) {
				return false
			}
		}
		var current = marker
		if marker.phase != .window {
			var parts: [Move] = []
			for name in fixedAccounts(marker.eoa, store: store) {
				if case .present(let bytes) = store.rawRead(account: name) {
					parts.append(Move(from: name, to: isolationPrefix + marker.tag + ".new." + name, digest: digest(bytes)))
				}
			}
			for move in marker.moves {
				if case .present(let live) = store.rawRead(account: move.from), digest(live) != move.digest {
					parts.append(Move(from: move.from, to: isolationPrefix + marker.tag + ".part." + move.from, digest: digest(live)))
				}
			}
			current = Marker(phase: .window, eoa: marker.eoa, tag: marker.tag, utc: marker.utc, owners: marker.owners, moves: marker.moves, partials: parts)
			guard store.rawWrite(account: markerAccount, bytes: markerBytes(current)) else { return false }
		}
		for part in current.partials {
			let toState = store.rawRead(account: part.to)
			switch store.rawRead(account: part.from) {
			case .present(let live) where digest(live) == part.digest:
				if case .present(let copy) = toState, digest(copy) == part.digest {
					// the copy is already there from an earlier attempt
				} else {
					guard toState == .absent, store.rawWrite(account: part.to, bytes: live), store.rawRead(account: part.to) == .present(live) else {
						return false
					}
				}
				guard store.rawDelete(account: part.from), store.rawRead(account: part.from) == .absent else {
					// Undo only the copy this rename made; the original stays under its name and nothing is audited.
					if case .present(let copy) = store.rawRead(account: part.to), digest(copy) == part.digest { _ = store.rawDelete(account: part.to) }
					return false
				}
			case .absent:
				guard case .present(let copy) = toState, digest(copy) == part.digest else { return false }
			default:
				return false
			}
			// The rename is complete: its audit row is written now if it is missing (SO-25f: backfilled by name, idempotent).
			guard let audited = auditRowExists(to: part.to, store: store) else { return false }
			if !audited {
				guard appendAudit(["from": part.from, "to": part.to, "utc": marker.utc, "reason": "window_isolated", "sha": part.digest], store: store)
				else { return false }
			}
		}
		for move in marker.moves.reversed() {
			switch store.rawRead(account: move.from) {
			case .absent:
				guard case .present(let copy) = store.rawRead(account: move.to), digest(copy) == move.digest,
				      store.rawWrite(account: move.from, bytes: copy), store.rawRead(account: move.from) == .present(copy),
				      appendAudit(["from": move.to, "to": move.from, "utc": marker.utc, "reason": "recovery_restore_copy"], store: store)
				else { return false }
			case .present(let live) where digest(live) == move.digest:
				break
			default:
				return false
			}
		}
		for owner in marker.owners {
			let name = store.accountName(.mnemonic, eoa: owner)
			guard let move = marker.moves.first(where: { $0.from == name }) else { continue }
			guard case .present(let live) = store.rawRead(account: name), digest(live) == move.digest, openable(live, owner: owner) else { return false }
		}
		return store.rawDelete(account: markerAccount) && store.rawRead(account: markerAccount) == .absent
	}

	/// Whether the audit file holds a row for this isolation name. nil when the audit cannot be read.
	private static func auditRowExists(to name: String, store: BeamioChatRawItemStoring) -> Bool? {
		switch store.rawRead(account: auditAccount) {
		case .absent: return false
		case .unreadable: return nil
		case .present(let bytes):
			guard let rows = try? JSONSerialization.jsonObject(with: bytes) as? [Any] else { return nil }
			return rows.contains { ($0 as? [String: String])?["to"] == name }
		}
	}

	private static func commitBytes(eoa: String, utc: String) -> Data {
		(try? JSONSerialization.data(withJSONObject: ["v": 1, "eoa": eoa, "committedAt": utc], options: [.sortedKeys])) ?? Data()
	}

	/// Moves the live marker to an isolation name (the bytes unchanged, an audit row for the move), then removes the live marker. A failure leaves the marker
	/// where it was. Used by the rollback and failure paths only; the committed success path erases its bookkeeping marker after its own audit (E4, 2026-11-17).
	static func isolateMarker(store: BeamioChatRawItemStoring, utc: String) -> Bool {
		guard case .present(let bytes) = store.rawRead(account: markerAccount) else { return store.rawRead(account: markerAccount) == .absent }
		let to = "wallet.sync.marker.iso." + UUID().uuidString
		guard store.rawWrite(account: to, bytes: bytes), store.rawRead(account: to) == .present(bytes),
		      appendAudit(["from": markerAccount, "to": to, "utc": utc, "reason": "marker_isolated"], store: store),
		      store.rawDelete(account: markerAccount), store.rawRead(account: markerAccount) == .absent
		else { return false }
		return true
	}

	/// Appends one audit row (names, times and the reason only). False when the audit cannot be written; the rename then does not happen.
	private static func appendAudit(_ row: [String: String], store: BeamioChatRawItemStoring) -> Bool {
		var rows: [Any] = []
		switch store.rawRead(account: auditAccount) {
		case .absent: break
		case .unreadable: return false
		case .present(let bytes):
			guard let parsed = try? JSONSerialization.jsonObject(with: bytes) as? [Any] else { return false }
			rows = parsed
		}
		rows.append(row)
		guard let bytes = try? JSONSerialization.data(withJSONObject: rows, options: [.sortedKeys]) else { return false }
		return store.rawWrite(account: auditAccount, bytes: bytes)
	}
}
