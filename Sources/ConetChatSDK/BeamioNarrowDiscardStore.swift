import Foundation

/// The durable part of the narrow discard of private-key records (25.52Y.163 r2.5.19, 第 46(3)(5)(8) 项, 第 53(6)、59(4)(b) 项).
///
/// The discard writes its intent `wallet.discard.intent` first (phase `prepared`), then one audit row `{entryType, count, utc}` before any record
/// is moved, and then moves each private-key record aside byte for byte (`wallet.discard.iso.<tag>.<name>`), checking the copy before the original
/// is removed. The phase becomes `committed` before the copies are removed, and the intent is removed last. A failure before the commit restores
/// every record from its copy and writes an audit row with count 0 (the discard is aborted, 第 46(5) 项). A restart finishes a `committed` intent and
/// rolls back a `prepared` or `pending` one from its copies.
///
/// The records are only the private-key records (the wallet items `walletKey:<eoa>`). Nothing else is named here: a record of another kind, such as the
/// pending PGP record of chat-pgp-pending, is not in the plan and is never touched.
enum BeamioNarrowDiscardStore {
	static let intentAccount = "wallet.discard.intent"

	/// E4 (DISCARD_PENDING): an unsettled discard intent is a lock on the family commands and walletStatus.
	static func intentPending(store: BeamioChatRawItemStoring) -> Bool {
		store.rawRead(account: intentAccount) != .absent
	}
	static let auditAccount = "wallet.discard.audit"
	static let isolationPrefix = "wallet.discard.iso."

	enum Outcome: Equatable {
		/// No private-key record is named: nothing is written.
		case nothingToDiscard
		/// The records are removed; the count is the number of records.
		case discarded(count: Int)
		/// The discard is not durable, or it was aborted: `write_failed` with reason `internal_state` (第 59(4)(c) 项).
		case pending
	}

	/// The discard of the private-key records of `owners` (第 46 项). The caller has checked both sides for explicit emptiness.
	static func run(store: BeamioChatRawItemStoring, owners: [String], utc: String, tag: String) -> Outcome {
		// 2026-11-17 (project constant): the discard never removes a record. Nothing is intended, copied or removed here.
		return .nothingToDiscard
		guard recoverAtStart(store: store) else { return .pending }
		var moves: [BeamioPwaPhraseOverwrite.Move] = []
		var payloads: [String: Data] = [:]
		for owner in Set(owners.map { $0.lowercased() }).sorted() {
			let from = store.accountName(.key, eoa: owner)
			switch store.rawRead(account: from) {
			case .absent: continue
			case .unreadable: return .pending
			case .present(let bytes):
				moves.append(.init(from: from, to: isolationPrefix + tag + "." + from, digest: BeamioPwaPhraseOverwrite.digest(bytes)))
				payloads[from] = bytes
			}
		}
		if moves.isEmpty { return .nothingToDiscard }
		// The intent first, then the audit row, both before any record moves (第 46(3) 项).
		guard store.rawWrite(account: intentAccount, bytes: intentBytes(phase: "prepared", utc: utc, moves: moves)) else { return .pending }
		guard appendAudit(["entryType": "privatekey", "count": moves.count, "utc": utc], store: store) else {
			_ = store.rawDelete(account: intentAccount)
			return .pending
		}
		// Each record is copied, the copy is read back, and only then the original is removed.
		for move in moves {
			guard let bytes = payloads[move.from],
			      store.rawRead(account: move.from) == .present(bytes),
			      store.rawWrite(account: move.to, bytes: bytes),
			      store.rawRead(account: move.to) == .present(bytes),
			      store.rawDelete(account: move.from),
			      store.rawRead(account: move.from) == .absent
			else {
				return abort(moves, utc: utc, store: store)
			}
		}
		// The commit: the phase is written before the copies go, so a restart finishes the removal instead of restoring the records.
		guard store.rawWrite(account: intentAccount, bytes: intentBytes(phase: "committed", utc: utc, moves: moves)) else {
			return abort(moves, utc: utc, store: store)
		}
		for move in moves { _ = store.rawDelete(account: move.to) }
		_ = store.rawDelete(account: intentAccount)
		return .discarded(count: moves.count)
	}

	/// Restores every record from its copy, writes the abort audit row (count 0), and removes the intent. `pending` when the restore cannot be verified:
	/// the intent stays, and the next start rolls back from the copies.
	private static func abort(_ moves: [BeamioPwaPhraseOverwrite.Move], utc: String, store: BeamioChatRawItemStoring) -> Outcome {
		guard BeamioPwaPhraseOverwrite.rollback(moves, fixed: [], store: store) else { return .pending }
		_ = appendAudit(["entryType": "privatekey", "count": 0, "utc": utc], store: store)
		_ = store.rawDelete(account: intentAccount)
		return .pending
	}

	/// The start-up settling of a leftover intent. True when no intent is left. A `committed` intent is finished; a `prepared` or `pending` one is rolled
	/// back from its copies. An intent that cannot be read or verified stays, and the answer is false.
	static func recoverAtStart(store: BeamioChatRawItemStoring) -> Bool {
		switch store.rawRead(account: intentAccount) {
		case .absent: return true
		case .unreadable: return false
		case .present(let bytes):
			guard let parsed = parseIntent(bytes) else { return false }
			// A leftover intent is only ever restored from its copies (never deleted), whatever its phase.
			guard BeamioPwaPhraseOverwrite.rollback(parsed.moves, fixed: [], store: store) else { return false }
			return store.rawDelete(account: intentAccount)
		}
	}

	// MARK: - Intent and audit

	/// The intent: phase, UTC time, and each record with its copy and digest. It holds account names and digests, never key material.
	static func intentBytes(phase: String, utc: String, moves: [BeamioPwaPhraseOverwrite.Move]) -> Data {
		let object: [String: Any] = [
			"v": 1, "phase": phase, "utc": utc,
			"moves": moves.map { ["from": $0.from, "to": $0.to, "digest": $0.digest] },
		]
		return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
	}

	private static func parseIntent(_ bytes: Data) -> (phase: String, moves: [BeamioPwaPhraseOverwrite.Move])? {
		guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
		      object["v"] as? Int == 1,
		      let phase = object["phase"] as? String,
		      ["prepared", "pending", "committed"].contains(phase),
		      let list = object["moves"] as? [[String: String]]
		else { return nil }
		let moves = list.compactMap { row -> BeamioPwaPhraseOverwrite.Move? in
			guard let from = row["from"], let to = row["to"], let digest = row["digest"] else { return nil }
			return .init(from: from, to: to, digest: digest)
		}
		guard moves.count == list.count else { return nil }
		return (phase, moves)
	}

	/// Appends one audit row `{entryType, count, utc}`. False when the audit cannot be written, and then nothing is removed.
	static func appendAudit(_ row: [String: Any], store: BeamioChatRawItemStoring) -> Bool {
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
