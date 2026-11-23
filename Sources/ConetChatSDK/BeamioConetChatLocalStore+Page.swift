import CryptoKit
import Foundation

/// Paging, row materialization, layout values and ingest (spec v1.1: 5, 6.2–6.4, 7.2, 8, 10).
/// Every function here runs on the store queue.
extension BeamioConetChatLocalStore {
	struct ScanRow {
		var key: BeamioChatLocalKey
		var stableId: String
		var sortTs: Int64
		var dir: String
		var kind: BeamioChatKind
		var revision: Int64
		var body: String?
		var media: BeamioChatMedia?
		var layout: BeamioChatLayout
	}

	struct ScanResult {
		/// Visible rows, ascending.
		var rows: [ScanRow]
		/// Oldest and newest raw rows examined, tombstones included (the window of the loaded range, O-6).
		var oldest: BeamioChatLocalKey?
		var newest: BeamioChatLocalKey?
		var olderState: BeamioChatOlderState
		var capped: Bool
		var short: Bool
		var scanExhausted: Bool
		var visibleSum: Double
	}

	/// One page, the same rules for the first screen and `loadOlder` (chat-layout-oracle.mjs openPage, normative).
	/// Walks raw rows (tombstones included) from the newest row, or from the cursor, toward older rows. A visible
	/// row adds its height; the walk stops when the visible sum reaches `heightPt`, so the row that crosses the
	/// boundary is included. Tombstones add no height and do not count toward the visible cap. At most
	/// `pageCap` (200) visible rows and `scanBudget` (2000) raw rows per call. When the budget ends the call,
	/// the state is `more` with `scanExhausted`, so the UI asks again rather than treating the page as the end.
	func scanPage(db: ChatLocalSQLite, conv: String, connBlind: String, before: BeamioChatLocalKey?,
	              viewport vp: BeamioChatViewport, syncComplete: Bool) throws -> ScanResult {
		guard let dek else { throw BeamioChatLocalError.locked }
		let select = "SELECT stable_id, sort_ts, dir, revision, state, body_enc, meta_enc FROM msg WHERE conv_blind = ?"
		let st: ChatLocalStatement
		if let b = before {
			st = try db.prepare(select + " AND (sort_ts < ? OR (sort_ts = ? AND stable_id < ?)) ORDER BY sort_ts DESC, stable_id DESC")
			try st.bind([.text(connBlind), .int(b.sortTs), .int(b.sortTs), .text(b.stableId)])
		} else {
			st = try db.prepare(select + " ORDER BY sort_ts DESC, stable_id DESC")
			try st.bind([.text(connBlind)])
		}
		var visible: [ScanRow] = []
		var scanned = 0
		var sum = 0.0
		var newest: BeamioChatLocalKey?
		var oldest: BeamioChatLocalKey?
		var capped = false
		var exhausted = false
		var stopped = false
		while try st.step() {
			let sid = st.text(0) ?? ""
			let key = BeamioChatLocalKey(sortTs: st.int(1), stableId: sid)
			if newest == nil { newest = key }
			oldest = key
			scanned += 1
			// The kind is inside meta_enc, so the meta is read first.: `reply` rows are never shown and take no height.
			let visibleMeta: MetaValue? = st.int(4) == 0
				? decodeMeta(connBlind: connBlind, stableId: sid, enc: st.blob(6), dek: dek) : nil
			if let vm = visibleMeta, vm.kind != .reply {
				let kind = vm.kind
				let revision = st.int(3)
				var meta = vm
				if var m = meta.media, let check = blobAvailable, !check(m.blob) {
					m.blobMissing = true
					m.state = "failed"
					meta.media = m
				}
				let body: String? = (kind == .text || kind == .system)
					? st.blob(5).flatMap { decryptBody(connBlind: connBlind, stableId: sid, revision: revision, enc: $0, dek: dek) }.map(BeamioChatMediaBody.displayText)
					: nil
				let layout = try layoutFor(db: db, connBlind: connBlind, stableId: sid, viewport: vp, kind: kind,
				                           body: body, media: meta.media, dek: dek)
				visible.append(ScanRow(key: key, stableId: sid, sortTs: key.sortTs, dir: st.text(2) ?? "in", kind: kind,
				                       revision: revision, body: body, media: meta.media, layout: layout))
				sum += layout.hPt
				if sum >= vp.heightPt {
					stopped = true
				} else if visible.count >= Self.pageCap {
					capped = true
					stopped = true
				}
			}
			if stopped { break }
			if scanned >= Self.scanBudget {
				exhausted = true
				break
			}
		}
		var rawRemain = false
		if let o = oldest {
			rawRemain = try db.scalarInt(
				"SELECT EXISTS(SELECT 1 FROM msg WHERE conv_blind = ? AND (sort_ts < ? OR (sort_ts = ? AND stable_id < ?)))",
				[.text(connBlind), .int(o.sortTs), .int(o.sortTs), .text(o.stableId)]
			) == 1
		}
		let olderState: BeamioChatOlderState = (rawRemain || exhausted) ? .more : (syncComplete ? .end : .pending)
		let short = olderState == .end && sum < vp.heightPt
		return ScanResult(rows: visible.reversed(), oldest: oldest, newest: newest, olderState: olderState,
		                  capped: capped, short: short, scanExhausted: exhausted, visibleSum: sum)
	}

	/// Measured size when stored (decrypted from val_enc), otherwise the estimate (8.3).
	func layoutFor(db: ChatLocalSQLite, connBlind: String, stableId: String, viewport vp: BeamioChatViewport,
	               kind: BeamioChatKind, body: String?, media: BeamioChatMedia?, dek: SymmetricKey) throws -> BeamioChatLayout {
		let st = try db.prepare("""
			SELECT val_enc FROM layout WHERE conv_blind = ? AND stable_id = ? AND width_bucket = ?
			AND orientation = ? AND font_bucket = ? AND layout_version = ?
			""")
		try st.bind([
			.text(connBlind), .text(stableId), .int(Int64(BeamioChatLocalLayoutModel.widthBucket(vp.widthPt))),
			.text(vp.orientation.rawValue), .int(Int64(BeamioChatLocalLayoutModel.fontBucket(vp.fontScale))),
			.int(Int64(vp.layoutVersion)),
		])
		if try st.step(), let enc = st.blob(0),
		   let v = decodeLayoutValue(enc, connBlind: connBlind, stableId: stableId, layoutKey: BeamioChatLocalLayoutModel.layoutKey(vp), dek: dek) {
			return BeamioChatLayout(wPt: v.wPt, hPt: v.hPt, measured: true)
		}
		let est = BeamioChatLocalLayoutModel.estimate(kind: kind, body: body, media: media, viewport: vp)
		return BeamioChatLayout(wPt: est.wPt, hPt: est.hPt, measured: false)
	}

	func buildItems(connBlind: String, rows: [ScanRow], dek: SymmetricKey) -> [BeamioChatItem] {
		rows.map { r in
			BeamioChatItem(stableId: r.stableId, sortTs: r.sortTs, dir: r.dir, kind: r.kind, body: r.body,
			               media: r.media, revision: r.revision, layout: r.layout)
		}
	}

	func decryptBody(connBlind: String, stableId: String, revision: Int64, enc: Data, dek: SymmetricKey) -> String? {
		do {
			let plain = try BeamioChatLocalCrypto.open(enc, key: dek,
			                                           aad: BeamioChatLocalCrypto.bodyAAD(connBlind: connBlind, stableId: stableId, revision: revision))
			return String(data: plain, encoding: .utf8)
		} catch {
			decryptFailures += 1
			return nil
		}
	}

	// MARK: - meta_enc (sendKey and media metadata, 7.1)

	struct MetaValue {
		var sendKey: String?
		var media: BeamioChatMedia?
		var tsProv: Int = 2
		/// Kind. `.unknown` when absent.
		var kind: BeamioChatKind = .unknown
	}

	func encodeMeta(sendKey: String?, media: BeamioChatMedia?, connBlind: String, stableId: String, dek: SymmetricKey,
		              tsProv: Int? = nil, kind: BeamioChatKind? = nil) throws -> Data {
		var obj: [String: Any] = [:]
		if let sendKey { obj["sk"] = sendKey }
		if let tsProv { obj["tp"] = tsProv }
		if let kind { obj["k"] = kind.rawValue }
		if let m = media {
			var mo: [String: Any] = ["mime": m.mime, "blob": m.blob, "bm": m.blobMissing]
			if let w = m.widthPx { mo["w"] = w }
			if let h = m.heightPx { mo["h"] = h }
			obj["m"] = mo
		}
		let plain = try JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])
		return try BeamioChatLocalCrypto.seal(plain, key: dek, aad: BeamioChatLocalCrypto.metaAAD(connBlind: connBlind, stableId: stableId))
	}

	func decodeMeta(connBlind: String, stableId: String, enc: Data?, dek: SymmetricKey) -> MetaValue {
		guard let enc else { return MetaValue(sendKey: nil, media: nil) }
		do {
			let plain = try BeamioChatLocalCrypto.open(enc, key: dek, aad: BeamioChatLocalCrypto.metaAAD(connBlind: connBlind, stableId: stableId))
			guard let obj = try JSONSerialization.jsonObject(with: plain) as? [String: Any] else { return MetaValue(sendKey: nil, media: nil) }
			var media: BeamioChatMedia?
			if let mo = obj["m"] as? [String: Any] {
				media = BeamioChatMedia(mime: mo["mime"] as? String ?? "",
				                        widthPx: (mo["w"] as? NSNumber)?.intValue,
				                        heightPx: (mo["h"] as? NSNumber)?.intValue,
				                        blob: mo["blob"] as? String ?? "",
				                        blobMissing: (mo["bm"] as? Bool) ?? false)
			}
			return MetaValue(sendKey: obj["sk"] as? String, media: media, tsProv: (obj["tp"] as? NSNumber)?.intValue ?? 2,
			                 kind: (obj["k"] as? String).flatMap { BeamioChatKind(rawValue: $0) } ?? .unknown)
		} catch {
			decryptFailures += 1
			return MetaValue(sendKey: nil, media: nil)
		}
	}

	// MARK: - val_enc (layout values, 7.2)

	func encodeLayoutValue(wPt: Double, hPt: Double, connBlind: String, stableId: String, layoutKey: String, dek: SymmetricKey) throws -> Data {
		let plain = try JSONSerialization.data(withJSONObject: ["w": wPt, "h": hPt], options: [.sortedKeys])
		return try BeamioChatLocalCrypto.seal(plain, key: dek,
		                                      aad: BeamioChatLocalCrypto.layoutAAD(connBlind: connBlind, stableId: stableId, layoutKey: layoutKey))
	}

	func decodeLayoutValue(_ enc: Data, connBlind: String, stableId: String, layoutKey: String, dek: SymmetricKey) -> (wPt: Double, hPt: Double)? {
		do {
			let plain = try BeamioChatLocalCrypto.open(enc, key: dek,
			                                           aad: BeamioChatLocalCrypto.layoutAAD(connBlind: connBlind, stableId: stableId, layoutKey: layoutKey))
			guard let o = try JSONSerialization.jsonObject(with: plain) as? [String: Any],
			      let w = (o["w"] as? NSNumber)?.doubleValue, let h = (o["h"] as? NSNumber)?.doubleValue
			else { return nil }
			return (w, h)
		} catch {
			decryptFailures += 1
			return nil
		}
	}

	// MARK: - Ingest (called inside a transaction)

	struct IngestRow {
		var convKey: String
		/// stable_id (4.3). Known before the body for a non-UUID sendId, and from the cid lookup for legacy rows.
		var stableId: String
		/// sendKey (4.1), when known. Stored only encrypted (meta_enc).
		var sendKey: String?
		var sortTs: Int64
		var dir: String
		var kind: BeamioChatKind
		var cid: String?
		var revision: Int64
		var deleted: Bool
		var body: String?
		var media: BeamioChatMedia?
		var pending: Bool
		/// ts_prov for a new row (5.1, D16). 2 = unknown_inbound.
		var tsProv: Int = 2
	}

	struct ExistingRow {
		var sortTs: Int64
		var revision: Int64
		var deleted: Bool
		var hasBody: Bool
		var cidBlind: String?
		var tsProv: Int = 2
	}

	func loadExisting(db: ChatLocalSQLite, connBlind: String, stableId: String, dek: SymmetricKey) throws -> ExistingRow? {
		let st = try db.prepare("SELECT sort_ts, revision, state, body_enc IS NOT NULL, cid_blind, meta_enc FROM msg WHERE conv_blind = ? AND stable_id = ?")
		try st.bind([.text(connBlind), .text(stableId)])
		guard try st.step() else { return nil }
		let tsProv = decodeMeta(connBlind: connBlind, stableId: stableId, enc: st.blob(5), dek: dek).tsProv
		return ExistingRow(sortTs: st.int(0), revision: st.int(1), deleted: st.int(2) != 0, hasBody: st.int(3) != 0, cidBlind: st.text(4), tsProv: tsProv)
	}

	/// Applies rows with the rules of spec 5 and 4.4. Returns events for open windows, and the conversations
	/// that received older rows while their window was waiting for sync (6.4).
	func applyIngest(db: ChatLocalSQLite, rows: [IngestRow], dek: SymmetricKey, report: inout BeamioChatSyncReport) throws -> ([BeamioChatEvent], Set<String>) {
		guard let idxKey else { throw BeamioChatLocalError.locked }
		var events: [BeamioChatEvent] = []
		var olderConvs = Set<String>()
		for r in rows {
			let conv = r.convKey
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
			let sid = r.stableId
			// D16: a stored provenance for this row (a local write not yet ingested) is consumed here, once.
			let stored = try takeTsProv(db: db, connBlind: connBlind, stableId: sid, dek: dek)
			let key = BeamioChatLocalKey(sortTs: r.sortTs, stableId: sid)
			let cidBlind = r.cid.map { BeamioChatLocalCrypto.blind(idxKey: idxKey, $0) }
			var found = try loadExisting(db: db, connBlind: connBlind, stableId: sid, dek: dek)
			if let old = found, !old.deleted, !r.deleted, old.tsProv == 1, r.tsProv == 0, old.sortTs != r.sortTs {
				// D16 correction: the old row is superseded FIRST, so the unique (conv_blind, stable_id)
				// index is free for the new row. Only receive-time rows with a sendId are corrected (R-4).
				let superseded = BeamioChatLocalCrypto.blind(idxKey: idxKey, "superseded|\(sid)|\(old.sortTs)")
				try db.run("UPDATE msg SET state = 2, stable_id = ?, body_enc = NULL, meta_enc = NULL WHERE conv_blind = ? AND stable_id = ?",
				           [.text(superseded), .text(connBlind), .text(sid)])
				try db.run("DELETE FROM layout WHERE conv_blind = ? AND stable_id = ?", [.text(connBlind), .text(sid)])
				if placement(conv: conv, key: BeamioChatLocalKey(sortTs: old.sortTs, stableId: sid)) == "middle" {
					events.append(.deleted(convKey: conv, stableId: sid))
				}
				report.tsCorrected += 1
				found = nil
			}
			guard let ex = found else {
				if r.deleted {
					try db.run("""
						INSERT INTO msg (conv_blind, stable_id, sort_ts, dir, revision, state, pending_publish, cid_blind, body_enc, meta_enc)
						VALUES (?, ?, ?, ?, ?, 1, 0, ?, NULL, NULL)
						""", [.text(connBlind), .text(sid), .int(r.sortTs), .text(r.dir), .int(r.revision), optText(cidBlind)])
					report.tombstones += 1
					continue
				}
				let bodyEnc = try r.body.map { try BeamioChatLocalCrypto.seal(Data($0.utf8), key: dek,
				                                                             aad: BeamioChatLocalCrypto.bodyAAD(connBlind: connBlind, stableId: sid, revision: r.revision)) }
				let metaEnc = try encodeMeta(sendKey: r.sendKey, media: r.media, connBlind: connBlind, stableId: sid, dek: dek, tsProv: stored ?? r.tsProv, kind: r.kind)
				try db.run("""
					INSERT INTO msg (conv_blind, stable_id, sort_ts, dir, revision, state, pending_publish, cid_blind, body_enc, meta_enc)
					VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
					""", [.text(connBlind), .text(sid), .int(r.sortTs), .text(r.dir), .int(r.revision),
					      .int(r.pending ? 1 : 0), optText(cidBlind), optBlob(bodyEnc), .blob(metaEnc)])
				let convMeta = try Self.encodeConvMeta(conv: conv, connBlind: connBlind, pendingCount: 0, dek: dek)
				try db.run("""
					INSERT INTO conv (conv_blind, last_sort_ts, meta_enc) VALUES (?, ?, ?)
					ON CONFLICT(conv_blind) DO UPDATE SET last_sort_ts = MAX(COALESCE(conv.last_sort_ts, 0), excluded.last_sort_ts),
						meta_enc = COALESCE(conv.meta_enc, excluded.meta_enc)
					""", [.text(connBlind), .int(r.sortTs), .blob(convMeta)])
				report.inserted += 1
				if let w = windows[conv], w.pending, let lo = w.lo, key < lo { olderConvs.insert(conv) }
				if r.kind != .reply, let pos = placement(conv: conv, key: key) {  // replies are not shown
					let est = windows[conv]?.viewport.map { BeamioChatLocalLayoutModel.estimate(kind: r.kind, body: r.kind == .text ? r.body.map(BeamioChatMediaBody.displayText) : nil, media: r.media, viewport: $0) }
					let item = BeamioChatItem(
						stableId: sid, sortTs: r.sortTs, dir: r.dir, kind: r.kind,
						body: r.kind == .text || r.kind == .system ? r.body.map(BeamioChatMediaBody.displayText) : nil, media: r.media, revision: r.revision,
						layout: BeamioChatLayout(wPt: est?.wPt ?? 0, hPt: est?.hPt ?? 0, measured: false)
					)
					events.append(.inserted(convKey: conv, items: [item], position: pos))
					if pos == "tail" { windows[conv]?.hi = key }
				}
				continue
			}

			if r.sortTs != ex.sortTs {
				report.tsMismatch += 1
				tsMismatchTotal += 1
			}
			if r.deleted {
				guard !ex.deleted, r.revision >= ex.revision else { continue }
				try db.run("UPDATE msg SET state = 1, body_enc = NULL, meta_enc = NULL, revision = ?, cid_blind = COALESCE(?, cid_blind) WHERE conv_blind = ? AND stable_id = ?",
				           [.int(r.revision), optText(cidBlind), .text(connBlind), .text(sid)])
				// N7: a tombstone removes every layout row of the message.
				try db.run("DELETE FROM layout WHERE conv_blind = ? AND stable_id = ?", [.text(connBlind), .text(sid)])
				report.tombstones += 1
				if placement(conv: conv, key: key) == "middle" { events.append(.deleted(convKey: conv, stableId: sid)) }
				continue
			}
			if r.revision > ex.revision {
				// A new revision changes the body, so the stored size is no longer valid (8.6).
				let bodyEnc = try r.body.map { try BeamioChatLocalCrypto.seal(Data($0.utf8), key: dek,
				                                                             aad: BeamioChatLocalCrypto.bodyAAD(connBlind: connBlind, stableId: sid, revision: r.revision)) }
				let metaEnc = try encodeMeta(sendKey: r.sendKey, media: r.media, connBlind: connBlind, stableId: sid, dek: dek, tsProv: ex.tsProv, kind: r.kind)
				try db.run("""
					UPDATE msg SET body_enc = ?, meta_enc = ?, cid_blind = COALESCE(?, cid_blind), revision = ?, state = 0
					WHERE conv_blind = ? AND stable_id = ?
					""", [optBlob(bodyEnc), .blob(metaEnc), optText(cidBlind), .int(r.revision), .text(connBlind), .text(sid)])
				try db.run("DELETE FROM layout WHERE conv_blind = ? AND stable_id = ?", [.text(connBlind), .text(sid)])
				report.updated += 1
				if !ex.deleted, placement(conv: conv, key: key) == "middle" {
					events.append(.updated(convKey: conv, stableId: sid, revision: r.revision))
				}
				continue
			}
			if r.revision == ex.revision, !ex.deleted {
				if ex.hasBody, let body = r.body {
					// Same sendKey, same revision, different body: keep the first, count it (4.4).
					if let existing = try existingBody(db: db, connBlind: connBlind, stableId: sid, revision: ex.revision, dek: dek), existing != body {
						report.sendKeyConflict += 1
					}
				}
				if !ex.hasBody, let body = r.body {
					let bodyEnc = try BeamioChatLocalCrypto.seal(Data(body.utf8), key: dek,
					                                             aad: BeamioChatLocalCrypto.bodyAAD(connBlind: connBlind, stableId: sid, revision: r.revision))
					try db.run("UPDATE msg SET body_enc = ? WHERE conv_blind = ? AND stable_id = ?", [.blob(bodyEnc), .text(connBlind), .text(sid)])
				}
				if let cb = cidBlind, cb != ex.cidBlind {
					try db.run("UPDATE msg SET cid_blind = ? WHERE conv_blind = ? AND stable_id = ?", [.text(cb), .text(connBlind), .text(sid)])
					report.cidUpdated += 1
				}
			}
			// A lower revision is stale: skip it, and do not move cid_blind back (4.5, 9.2).
		}
		return (events, olderConvs)
	}

	func existingBody(db: ChatLocalSQLite, connBlind: String, stableId: String, revision: Int64, dek: SymmetricKey) throws -> String? {
		let st = try db.prepare("SELECT body_enc FROM msg WHERE conv_blind = ? AND stable_id = ?")
		try st.bind([.text(connBlind), .text(stableId)])
		guard try st.step(), let enc = st.blob(0) else { return nil }
		return decryptBody(connBlind: connBlind, stableId: stableId, revision: revision, enc: enc, dek: dek)
	}

	/// "middle" when the row is inside what the UI has loaded, "tail" when it is above it, nil when below.
	func placement(conv: String, key: BeamioChatLocalKey) -> String? {
		guard let w = windows[conv] else { return nil }
		if let hi = w.hi, !(hi < key) {
			if w.reachedOldest { return "middle" }
			if let lo = w.lo, !(key < lo) { return "middle" }
			return nil
		}
		return "tail"
	}

	private func optText(_ s: String?) -> ChatLocalValue {
		guard let s else { return .null }
		return .text(s)
	}

	private func optBlob(_ d: Data?) -> ChatLocalValue {
		guard let d else { return .null }
		return .blob(d)
	}
}
