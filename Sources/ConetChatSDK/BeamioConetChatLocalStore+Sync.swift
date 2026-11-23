import CryptoKit
import Foundation

/// Full-history sync into the local library (spec v1.1: 9). The sync is the only writer besides the
/// send path, and it runs on the caller's thread:
/// - network fetches happen with no store lock held;
/// - each database batch is one short transaction (at most `syncBatchSize` rows);
/// - tail (newest) records go first; `syncComplete` is set only after every record is processed (9.4).
extension BeamioConetChatLocalStore {
	static let syncBatchSize = 200
	static let syncFetchParallelism = 6

	struct RawIndexRecord {
		var seq: Int
		var cid: String
		var prevCid: String
		var ts: Int64
		var peer: String
		var dir: String
		var sendId: String
		var revision: Int64
		var deleted: Bool
		/// Set when the sendKey was folded into an earlier record (4.5): the surviving stable_id.
		var sidOverride: String? = nil
	}

	struct SyncContext {
		var master: Data
		var dek: SymmetricKey
		var idKey: SymmetricKey
		var idxKey: SymmetricKey
	}

	enum SyncPlanItem {
		case skip(conv: String, stableId: String, newCid: String?)
		case tombstone(IngestRow)
		case fetch(RawIndexRecord, legacy: Bool)
	}

	/// Index records come from the chain index (same shape as the existing history store).
	/// `revision` and `deleted` are optional (5).
	static func parseIndex(_ raw: [[String: Any]]) -> [RawIndexRecord] {
		raw.compactMap { o in
			let cid = String(o["cid"] as? String ?? "")
			guard !cid.isEmpty else { return nil }
			return RawIndexRecord(
				seq: BeamioConetChatHistoryStore.intValue(o["seq"]) ?? 0,
				cid: cid,
				prevCid: String(o["prevCid"] as? String ?? ""),
				ts: BeamioConetChatHistoryStore.int64Value(o["ts"]) ?? 0,
				peer: String(o["peer"] as? String ?? "").lowercased(),
				dir: String(o["dir"] as? String ?? "out"),
				sendId: String(o["sendId"] as? String ?? ""),
				revision: Int64(BeamioConetChatHistoryStore.intValue(o["revision"]) ?? 0),
				deleted: (o["deleted"] as? Bool) ?? false
			)
		}
	}

	/// Syncs the index into the library (9.2). Stored bodies are not fetched again. A changed cid for the
	/// same revision only updates `cid_blind`.
	@discardableResult
	public func syncIndex(records raw: [[String: Any]], indexHash: String? = nil, historyMaster: Data,
	                      fetchCipher: @escaping (String) -> String?) -> BeamioChatSyncReport {
		var report = BeamioChatSyncReport()
		let recs = Self.parseIndex(raw)
		report.records = recs.count
		let started: SyncContext? = queue.sync { () -> SyncContext? in
			guard db != nil, let k = dek, let i = idKey, let x = idxKey else { return nil }
			syncStateValue = .running
			syncCancelled = false
			return SyncContext(master: historyMaster, dek: k, idKey: i, idxKey: x)
		}
		guard let ctx = started else {
			report.locked = true
			return report
		}
		defer {
			queue.sync { if syncStateValue == .running { syncStateValue = .idle } }
		}

		// r1 4.5: fold records with the same (peer, dir, ts, body digest) into the earliest one. Bodies are fetched
		// only for groups that have more than one record (9.2). Folded sendKeys become aliases.
		let folding = foldDuplicates(recs, ctx: ctx, fetchCipher: fetchCipher)
		report.folded = folding.dropped
		queue.sync {
			guard let db else { return }
			try? db.transaction {
				for (alias, target) in folding.aliases {
					let aliasBlind = BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, alias)
					let targetStable = BeamioChatLocalCrypto.stableId(idxKey: ctx.idxKey, sendKey: target)
					let enc = try BeamioChatLocalCrypto.seal(Data(targetStable.utf8), key: ctx.dek, aad: Data(aliasBlind.utf8))
					try db.run("INSERT OR REPLACE INTO alias (alias_blind, target_enc) VALUES (?, ?)", [.text(aliasBlind), .blob(enc)])
				}
			}
		}
		let ordered = folding.records.sorted { $0.seq > $1.seq }
		var done = 0
		var start = 0
		while start < ordered.count {
			if queue.sync(execute: { syncCancelled }) {
				report.stopped = true
				break
			}
			let chunk = Array(ordered[start..<min(start + Self.syncBatchSize, ordered.count)])
			start += chunk.count

			guard let plan = queue.sync(execute: { () -> [SyncPlanItem]? in
				guard db != nil else { return nil }
				return planBatch(chunk, ctx: ctx, report: &report)
			}) else {
				report.locked = true
				break
			}

			let fetched = fetchBodies(plan, ctx: ctx, fetchCipher: fetchCipher, prefetched: folding.bodies)
			report.fetched += fetched.count
			report.failed += fetched.failed
			for item in plan {
				if case .fetch(_, let legacy) = item, legacy { report.legacyRefetch += 1 }
			}

			let applied: Bool = queue.sync { () -> Bool in
				guard let db else { return false }
				var rows: [IngestRow] = []
				var cidMoves: [(String, String, String)] = []
				for item in plan {
					switch item {
					case .skip(let conv, let sid, let newCid):
						report.skippedHave += 1
						if let newCid { cidMoves.append((conv, sid, newCid)) }
					case .tombstone(let row):
						rows.append(row)
					case .fetch(let rec, _):
						guard let res = fetched.byCid[rec.cid], let body = res else { continue }
						rows.append(makeIngestRow(rec: rec, body: body, ctx: ctx))
					}
				}
				do {
					let (events, olderConvs) = try db.transaction { () -> ([BeamioChatEvent], Set<String>) in
						for (conv, sid, newCid) in cidMoves {
							let connBlind = BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, conv)
							try db.run("UPDATE msg SET cid_blind = ? WHERE conv_blind = ? AND stable_id = ?",
							           [.text(BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, newCid)), .text(connBlind), .text(sid)])
							report.cidUpdated += 1
						}
						return try applyIngest(db: db, rows: rows, dek: ctx.dek, report: &report)
					}
					var out = events
					for conv in olderConvs { out.append(.olderAvailable(convKey: conv)) }
					emit(out)
					return true
				} catch {
					NSLog("[BeamioChatLocal] sync batch failed: %@", String(describing: error))
					report.failed += rows.count
					return false
				}
			}
			if !applied { break }
			done += chunk.count
			queue.sync {
				emit([.syncProgress(accountKey: accountKey, doneRows: done, totalRows: ordered.count, state: "running")])
			}
		}

		queue.sync {
			guard let db else { return }
			try? db.transaction {
				try writeMeta(db, "migrationState", "complete")
				try writeMeta(db, "syncedAtMs", String(Int64(Date().timeIntervalSince1970 * 1000)))
				if let indexHash { try writeMeta(db, "headIndexHash", indexHash) }
				// 9.4: set only when every record was processed.
				if !report.stopped && !report.locked && report.failed == 0 {
					try writeMeta(db, "syncComplete", "1")
				}
			}
			if !report.stopped && !report.locked && report.failed == 0 {
				// Windows waiting on sync can now decide where the end is (6.4).
				var out: [BeamioChatEvent] = []
				for (conv, w) in windows where w.pending { out.append(.olderAvailable(convKey: conv)) }
				emit(out)
			}
		}
		return report
	}

	/// Per record: already stored (no fetch), tombstone, or fetch (9.2). Runs on the store queue.
	private func planBatch(_ chunk: [RawIndexRecord], ctx: SyncContext, report: inout BeamioChatSyncReport) -> [SyncPlanItem]? {
		guard let db else { return nil }
		var plan: [SyncPlanItem] = []
		plan.reserveCapacity(chunk.count)
		for rec in chunk {
			let conv = rec.peer
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, conv)
			// r1 (4.1): a non-empty sendId is the sendKey, UUID included. Only an empty sendId is derived from the body.
			if !rec.sendId.isEmpty {
				// The index sendId is the sendKey (4.1 rule 1): stable_id needs no body.
				var sid = rec.sidOverride ?? BeamioChatLocalCrypto.stableId(idxKey: ctx.idxKey, sendKey: rec.sendId)
				var ex = try? loadExisting(db: db, connBlind: connBlind, stableId: sid, dek: ctx.dek)
				// A sendKey folded in an earlier sync: resolve through the alias table (4.5).
				if ex == nil, rec.sidOverride == nil, let target = aliasTarget(db: db, ctx: ctx, connBlind: connBlind, sendKey: rec.sendId) {
					sid = target
					ex = try? loadExisting(db: db, connBlind: connBlind, stableId: sid, dek: ctx.dek)
				}
				if rec.deleted {
					plan.append(.tombstone(IngestRow(convKey: conv, stableId: sid, sendKey: rec.sendId, sortTs: rec.ts,
					                                 dir: rec.dir, kind: .text, cid: rec.cid, revision: rec.revision,
					                                 deleted: true, body: nil, media: nil, pending: false)))
				} else if let ex, ex.hasBody, !ex.deleted, ex.revision >= rec.revision {
					let cidMoves = rec.revision == ex.revision && ex.cidBlind != BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, rec.cid)
					plan.append(.skip(conv: conv, stableId: sid, newCid: cidMoves ? rec.cid : nil))
				} else if let ex, ex.deleted, rec.revision <= ex.revision {
					plan.append(.skip(conv: conv, stableId: sid, newCid: nil))
				} else {
					plan.append(.fetch(rec, legacy: false))
				}
				continue
			}
			// No sendId, or a legacy random UUID: the sendKey needs the body, so match by cid first (9.2 step 2).
			var found: (sid: String, hasBody: Bool, deleted: Bool, revision: Int64)?
			let st = try? db.prepare("SELECT stable_id, body_enc IS NOT NULL, state, revision FROM msg WHERE conv_blind = ? AND cid_blind = ? LIMIT 1")
			if let st {
				try? st.bind([.text(connBlind), .text(BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, rec.cid))])
				if (try? st.step()) == true, let s = st.text(0) {
					found = (s, st.int(1) != 0, st.int(2) != 0, st.int(3))
				}
			}
			if let f = found, f.hasBody, !f.deleted, f.revision >= rec.revision, !rec.deleted {
				plan.append(.skip(conv: conv, stableId: f.sid, newCid: nil))
			} else if let f = found, rec.deleted {
				plan.append(.tombstone(IngestRow(convKey: conv, stableId: f.sid, sendKey: nil, sortTs: rec.ts,
				                                 dir: rec.dir, kind: .text, cid: rec.cid, revision: rec.revision,
				                                 deleted: true, body: nil, media: nil, pending: false)))
			} else if rec.deleted {
				// A tombstone without a sendKey and without a stored row: nothing to mark.
				report.skippedHave += 1
			} else {
				plan.append(.fetch(rec, legacy: false))
			}
		}
		return plan
	}

	/// True when every member of a group is already in the library: its cid is stored, or its sendKey is stored or aliased.
	private func allStored(_ members: [RawIndexRecord], ctx: SyncContext) -> Bool {
		queue.sync {
			guard let db else { return false }
			for m in members {
				let connBlind = BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, m.peer)
				let cidHit = (try? db.scalarInt("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND cid_blind = ?",
				                                [.text(connBlind), .text(BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, m.cid))])) ?? 0
				if cidHit > 0 { continue }
				guard !m.sendId.isEmpty else { return false }
				let sid = BeamioChatLocalCrypto.stableId(idxKey: ctx.idxKey, sendKey: m.sendId)
				let rowHit = (try? db.scalarInt("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND stable_id = ?", [.text(connBlind), .text(sid)])) ?? 0
				let aliasHit = (try? db.scalarInt("SELECT COUNT(*) FROM alias WHERE alias_blind = ?", [.text(BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, m.sendId))])) ?? 0
				if rowHit == 0 && aliasHit == 0 { return false }
			}
			return true
		}
	}

	/// Surviving stable_id for a folded sendKey, from the alias table (decrypted with the alias AAD).
	private func aliasTarget(db: ChatLocalSQLite, ctx: SyncContext, connBlind: String, sendKey: String) -> String? {
		let aliasBlind = BeamioChatLocalCrypto.blind(idxKey: ctx.idxKey, sendKey)
		guard let st = try? db.prepare("SELECT target_enc FROM alias WHERE alias_blind = ?") else { return nil }
		guard (try? st.bind([.text(aliasBlind)])) != nil, (try? st.step()) == true, let enc = st.blob(0) else { return nil }
		guard let plain = try? BeamioChatLocalCrypto.open(enc, key: ctx.dek, aad: Data(aliasBlind.utf8)) else { return nil }
		return String(data: plain, encoding: .utf8)
	}

	struct FetchOutcome {
		var byCid: [String: String?]
		var count: Int
		var failed: Int
	}

	/// Downloads and decrypts the bodies needed by `plan` (bounded to `syncFetchParallelism`). No store lock is
	/// held here. Ciphertext must hash to its cid (9.2 step 3).
	private func fetchBodies(_ plan: [SyncPlanItem], ctx: SyncContext, fetchCipher: @escaping (String) -> String?,
	                         prefetched: [String: String] = [:]) -> FetchOutcome {
		var recs: [RawIndexRecord] = []
		for item in plan {
			if case .fetch(let rec, _) = item { recs.append(rec) }
		}
		let lock = NSLock()
		var out: [String: String?] = [:]
		var failed = 0
		let slots = DispatchSemaphore(value: Self.syncFetchParallelism)
		let group = DispatchGroup()
		for rec in recs {
			if let cached = prefetched[rec.cid] {
				lock.lock()
				out[rec.cid] = cached
				lock.unlock()
				continue
			}
			slots.wait()
			group.enter()
			DispatchQueue.global(qos: .utility).async {
				defer {
					slots.signal()
					group.leave()
				}
				let body = Self.fetchVerifiedBody(rec, ctx: ctx, fetchCipher: fetchCipher)
				lock.lock()
				if let body {
					out[rec.cid] = body
				} else {
					failed += 1
					out[rec.cid] = .some(nil)
				}
				lock.unlock()
			}
		}
		group.wait()
		return FetchOutcome(byCid: out, count: recs.count, failed: failed)
	}

	/// Fetches one fragment, checks it hashes to its cid, and decrypts it with the record's (seq, prevCid) key (9.2).
	static func fetchVerifiedBody(_ rec: RawIndexRecord, ctx: SyncContext, fetchCipher: (String) -> String?) -> String? {
		guard let cipher = fetchCipher(rec.cid), Keccak256.hexUtf8(cipher).lowercased() == rec.cid.lowercased() else { return nil }
		let key = BeamioFragmentKeys.key(master: ctx.master, seq: rec.seq, prevCid: rec.prevCid)
		return try? BeamioConetChatHistoryStore.aesGcmDecrypt(key: key, b64: cipher)
	}

	struct FoldResult {
		var records: [RawIndexRecord]
		/// folded sendKey -> surviving sendKey
		var aliases: [(alias: String, target: String)]
		/// Bodies already fetched while deciding folds (cid -> body).
		var bodies: [String: String]
		var dropped: Int
	}

	/// r1 4.5. Base records (revision 0, not deleted) that share (peer, dir, ts) are compared by body digest
	/// SHA-256(body). Equal digests fold into the earliest record (lowest seq). A folded sendKey becomes an alias,
	/// and later revisions or tombstones that name it are rewritten to the survivor's sendKey.
	func foldDuplicates(_ recs: [RawIndexRecord], ctx: SyncContext, fetchCipher: @escaping (String) -> String?) -> FoldResult {
		var groups: [String: [RawIndexRecord]] = [:]
		for r in recs where r.revision == 0 && !r.deleted {
			groups["\(r.peer)|\(r.dir)|\(r.ts)", default: []].append(r)
		}
		var bodies: [String: String] = [:]
		var dropSeqs = Set<Int>()
		var folded: [String: String] = [:]
		var aliases: [(alias: String, target: String)] = []
		var dropped = 0
		for (_, members) in groups where members.count > 1 {
			// A group whose members are all stored already (by cid, or by sendKey / alias) was folded before: no fetch (9.2).
			if allStored(members, ctx: ctx) { continue }
			var survivorByDigest: [String: (rec: RawIndexRecord, sendKey: String)] = [:]
			for m in members.sorted(by: { $0.seq < $1.seq }) {
				guard let body = Self.fetchVerifiedBody(m, ctx: ctx, fetchCipher: fetchCipher) else { continue }
				bodies[m.cid] = body
				let digest = BeamioChatLocalCrypto.hex(Data(SHA256.hash(data: Data(body.utf8))))
				let sendKey = m.sendId.isEmpty
					? BeamioChatLocalCrypto.sendKeyDerived(idKey: ctx.idKey, peer: m.peer, dir: m.dir, ts: m.ts, body: body)
					: m.sendId
				if let survivor = survivorByDigest[digest] {
					if survivor.sendKey != sendKey {
						folded[sendKey] = survivor.sendKey
						aliases.append((sendKey, survivor.sendKey))
					}
					dropSeqs.insert(m.seq)
					dropped += 1
				} else {
					survivorByDigest[digest] = (m, sendKey)
				}
			}
		}
		let effective = recs.filter { !dropSeqs.contains($0.seq) }.map { r -> RawIndexRecord in
			var x = r
			if let target = folded[r.sendId] { x.sendId = target }
			return x
		}
		_ = ctx
		return FoldResult(records: effective, aliases: aliases, bodies: bodies, dropped: dropped)
	}

	/// Builds the row for a fetched record. The sendKey is the index sendId when it is deterministic, and is
	/// derived from the body otherwise (4.1, 4.2).
	private func makeIngestRow(rec: RawIndexRecord, body: String, ctx: SyncContext) -> IngestRow {
		let sendKey = !rec.sendId.isEmpty
			? rec.sendId
			: BeamioChatLocalCrypto.sendKeyDerived(idKey: ctx.idKey, peer: rec.peer, dir: rec.dir, ts: rec.ts, body: body)
		let parsed = mediaManifestParser?(body)
		return IngestRow(
			convKey: rec.peer, stableId: rec.sidOverride ?? BeamioChatLocalCrypto.stableId(idxKey: ctx.idxKey, sendKey: sendKey), sendKey: sendKey,
			sortTs: rec.ts, dir: rec.dir, kind: parsed?.kind ?? .text, cid: rec.cid, revision: rec.revision,
			deleted: false, body: body, media: parsed?.media, pending: false
		)
	}
}
