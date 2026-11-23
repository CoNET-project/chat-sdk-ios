import CryptoKit
import Foundation

/// Native import for the D8 migration (spec 11.1 M2–M3, 11.2): `historyImportBatch` and `historyVerifyImport`.
/// Idempotent by sendKey / stable_id. Bodies are stored encrypted, like any other row.
extension BeamioConetChatLocalStore {
	public static let importBatchLimit = 200

	/// Imports up to 200 rows. Native code derives the sendKey and stable_id, de-duplicates, and encrypts (11.2).
	public func importBatch(accountKey rawAccount: String, rows: [BeamioChatImportRow]) throws -> BeamioChatImportResult {
		try queue.sync {
			guard let db, let dek, let idKey, let idxKey else { throw BeamioChatLocalError.locked }
			guard rawAccount.lowercased() == accountKey else { throw BeamioChatLocalError.accountMismatch }
			guard rows.count <= Self.importBatchLimit else { throw BeamioChatLocalError.batchTooLarge }
			var ingest: [IngestRow] = []
			for r in rows {
				let conv = r.convKey.lowercased()
				guard !conv.isEmpty, r.dir == "in" || r.dir == "out", let ts = r.ts, ts >= 0 else {
					throw BeamioChatLocalError.badRow
				}
				let sendKey = (r.sendId?.isEmpty == false)
					? r.sendId!
					: BeamioChatLocalCrypto.sendKeyDerived(idKey: idKey, peer: conv, dir: r.dir, ts: ts, body: r.body)
				let parsed = mediaManifestParser?(r.body)
				ingest.append(IngestRow(
					convKey: conv, stableId: BeamioChatLocalCrypto.stableId(idxKey: idxKey, sendKey: sendKey),
					sendKey: sendKey, sortTs: ts, dir: r.dir, kind: parsed?.kind ?? .text, cid: nil, revision: 0,
					deleted: false, body: r.body, media: parsed?.media, pending: r.pending, tsProv: 2
				))
			}
			var report = BeamioChatSyncReport()
			let events = try db.transaction { () -> [BeamioChatEvent] in
				try applyIngest(db: db, rows: ingest, dek: dek, report: &report).0
			}
			emit(events)
			return BeamioChatImportResult(imported: report.inserted, duplicates: rows.count - report.inserted - report.updated,
			                              sendKeyConflict: report.sendKeyConflict)
		}
	}

	/// Row count and digest for the M3 comparison. Live rows only (deleted = 0). The computation is
	/// `BeamioChatImportDigest`, shared with the vectors in interface/protocol/import-digest-vectors.v1.json.
	public func verifyImport(accountKey rawAccount: String) throws -> (rows: Int, digest: String) {
		try queue.sync {
			guard let db, let dek, let idxKey else { throw BeamioChatLocalError.locked }
			guard rawAccount.lowercased() == accountKey else { throw BeamioChatLocalError.accountMismatch }
			let st = try db.prepare("SELECT conv_blind, stable_id, sort_ts, dir, revision, body_enc, meta_enc FROM msg WHERE state = 0")
			var rows: [BeamioChatImportDigest.Row] = []
			while try st.step() {
				let conv = st.text(0) ?? ""
				let sid = st.text(1) ?? ""
				let sortTs = st.int(2)
				let dir = st.text(3) ?? ""
				let revision = st.int(4)
				guard let bodyEnc = st.blob(5), let metaEnc = st.blob(6) else { throw BeamioChatLocalError.crypto }
				let meta = decodeMeta(connBlind: conv, stableId: sid, enc: metaEnc, dek: dek)
				guard let sendKey = meta.sendKey,
				      let body = decryptBody(connBlind: conv, stableId: sid, revision: revision, enc: bodyEnc, dek: dek)
				else { throw BeamioChatLocalError.crypto }
				rows.append(BeamioChatImportDigest.Row(convBlind: conv, stableId: sid, sendKey: sendKey,
				                                       sortTs: sortTs, dir: dir, body: Data(body.utf8)))
			}
			let digest = BeamioChatImportDigest.compute(kIdx: idxKey, rows: rows)
			return (digest.rows, digest.global)
		}
	}
}
