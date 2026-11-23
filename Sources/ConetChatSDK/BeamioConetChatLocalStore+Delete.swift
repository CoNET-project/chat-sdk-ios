import CryptoKit
import Foundation

/// Native deletion of one message and of one conversation. A delete is a tombstone, the same change that sync makes: the row
/// keeps its key, its body and media metadata are cleared, and its layout rows go. Every tombstone goes through
/// `applyIngest`, so the `deleted` events are the ones of sync. Nothing is written to the page record.
extension BeamioConetChatLocalStore {
	/// `historyDeleteMessage`. The message is found by (convKey, sendKey). A folded sendKey is resolved through the alias table.
	/// `true` when a live row became a tombstone. An absent or already tombstoned message gives `false`, and nothing changes. nil when the store
	/// cannot answer (busy).
	func deleteMessage(convKey rawConv: String, sendKey: String) -> Bool? {
		queue.sync { () -> Bool? in
			guard let db, let dek, let idxKey else { return nil }
			let conv = rawConv.lowercased()
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
			do {
				guard let sid = try resolveDeleteStableId(db: db, dek: dek, idxKey: idxKey, connBlind: connBlind, sendKey: sendKey),
				      let existing = try loadExisting(db: db, connBlind: connBlind, stableId: sid, dek: dek), !existing.deleted
				else { return false }
				let events = try db.transaction { () -> [BeamioChatEvent] in
					try tombstones(db: db, dek: dek, rows: [(conv, sid, existing)])
				}
				emit(events)
				return true
			} catch {
				return nil
			}
		}
	}

	/// `historyDeleteConversation`. Every live message of the conversation becomes a tombstone (one `deleted` event each), the layout rows
	/// go, and the conversation's index row (`conv`) is removed. Other conversations and their messages stay. A conversation that does not exist gives
	/// `false`. nil when the store cannot answer (busy).
	func deleteConversation(convKey rawConv: String) -> Bool? {
		queue.sync { () -> Bool? in
			guard let db, let dek, let idxKey else { return nil }
			let conv = rawConv.lowercased()
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
			do {
				guard try db.scalarInt("SELECT COUNT(*) FROM conv WHERE conv_blind = ?", [.text(connBlind)]) > 0 else { return false }
				var stableIds: [String] = []
				let st = try db.prepare("SELECT stable_id FROM msg WHERE conv_blind = ? AND state = 0")
				try st.bind([.text(connBlind)])
				while try st.step() {
					if let sid = st.text(0) { stableIds.append(sid) }
				}
				var rows: [(String, String, ExistingRow)] = []
				for sid in stableIds {
					if let existing = try loadExisting(db: db, connBlind: connBlind, stableId: sid, dek: dek), !existing.deleted {
						rows.append((conv, sid, existing))
					}
				}
				let events = try db.transaction { () -> [BeamioChatEvent] in
					let events = try rows.isEmpty ? [] : tombstones(db: db, dek: dek, rows: rows)
					try db.run("DELETE FROM conv WHERE conv_blind = ?", [.text(connBlind)])
					return events
				}
				emit(events)
				return true
			} catch {
				return nil
			}
		}
	}

	/// The stable_id of the row a sendKey names: the direct id when that row exists, else the survivor of a folded sendKey.
	private func resolveDeleteStableId(db: ChatLocalSQLite, dek: SymmetricKey, idxKey: SymmetricKey, connBlind: String,
	                                   sendKey: String) throws -> String? {
		let direct = BeamioChatLocalCrypto.stableId(idxKey: idxKey, sendKey: sendKey)
		if try db.scalarInt("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND stable_id = ?", [.text(connBlind), .text(direct)]) > 0 {
			return direct
		}
		let aliasBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, sendKey)
		let st = try db.prepare("SELECT target_enc FROM alias WHERE alias_blind = ?")
		try st.bind([.text(aliasBlind)])
		guard try st.step(), let enc = st.blob(0) else { return nil }
		guard let plain = try? BeamioChatLocalCrypto.open(enc, key: dek, aad: Data(aliasBlind.utf8)) else { return nil }
		return String(data: plain, encoding: .utf8)
	}

	/// Applies the tombstones through `applyIngest`, the path of sync. The revision and sort key are the stored ones, so the row is judged as the same row.
	private func tombstones(db: ChatLocalSQLite, dek: SymmetricKey, rows: [(String, String, ExistingRow)]) throws -> [BeamioChatEvent] {
		var report = BeamioChatSyncReport()
		let ingest = rows.map { conv, sid, existing in
			IngestRow(convKey: conv, stableId: sid, sendKey: nil, sortTs: existing.sortTs, dir: "", kind: .text, cid: nil,
			          revision: existing.revision, deleted: true, body: nil, media: nil, pending: false)
		}
		let (events, _) = try applyIngest(db: db, rows: ingest, dek: dek, report: &report)
		return events
	}
}
