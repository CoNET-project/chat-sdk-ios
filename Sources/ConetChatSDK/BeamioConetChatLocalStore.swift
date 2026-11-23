import CryptoKit
import Foundation

/// Global local chat library: one encrypted SQLite file per account (interface spec v1.1).
///
/// - Read path (`openConversation`, `loadOlder`): local database only. No network, no waiting for sync (9.1).
/// - Write path: `syncIndex` and the send path, both through the store queue (9.1, N8).
/// - Only ciphertext for bodies, metadata and layout values is on disk. The DEK is in memory while
/// unlocked; `lock` clears it and tells the UI first (6.5).
/// - Sort key K = (sortTs, stableId). `seq`, `cid` and `revision` never take part in order or cursors.
///
/// All state is guarded by `queue`. Event handlers run on a separate queue, so they may call the store.
public final class BeamioConetChatLocalStore {
	public typealias Handler = (BeamioChatEvent) -> Void
	/// Maps a decrypted message body to its kind and media metadata. nil = plain text.
	public typealias MediaManifestParser = (String) -> (kind: BeamioChatKind, media: BeamioChatMedia?)?

	public static let schemaVersion: Int64 = 1
	/// Safety cap on rows examined by the first screen (6.2).
	static let pageCap = 200
	/// Rows examined by one `loadOlder` before it gives up with `scanExhausted` (6.3).
	static let scanBudget = 2000

	public var mediaManifestParser: MediaManifestParser? = BeamioChatMediaBody.parse
	/// Host reports whether the local copy of a media blob exists. The library stores no media bytes. A missing
	/// blob is a local failure: the 88·fs placeholder and state `failed` (8.3, T-6). nil = treat as available.
	public var blobAvailable: ((String) -> Bool)?

	private let rootDirectory: URL
	internal let queue = DispatchQueue(label: "beamio.chat.local.store", qos: .utility)
	/// Event delivery lane. Internal so tests can wait for delivered events.
	let notifyQueue = DispatchQueue(label: "beamio.chat.local.notify", qos: .utility)

	// Everything below is touched only on `queue`.
	internal var db: ChatLocalSQLite?
	internal var accountKey = ""
	internal var localRoot: Data?
	internal var dek: SymmetricKey?
	internal var idKey: SymmetricKey?
	internal var idxKey: SymmetricKey?
	internal var dbEpoch = ""
	internal var generation = 0
	internal var syncStateValue: BeamioChatSyncState = .idle
	internal var windows: [String: BeamioChatLocalWindow] = [:]
	internal var handlers: [UUID: (conv: String?, handler: Handler)] = [:]
	internal var syncCancelled = false
	internal var decryptFailures = 0
	internal var tsMismatchTotal = 0

	public init(rootDirectory: URL) {
		self.rootDirectory = rootDirectory
	}

	/// Default location: Application Support/ConetChat/local-v1 (excluded from backup).
	public static func defaultRootDirectory() -> URL? {
		#if BEAMIO_TEST_HOOKS
		// A test build never uses the product's directory: its local library is in the process's temporary directory.
		_ = BeamioProductPathGuard.baseline
		let tmp = FileManager.default.temporaryDirectory
			.appendingPathComponent("beamio-conetchat-test-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
			.appendingPathComponent("local-v1", isDirectory: true)
		try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
		return tmp
		#else
		guard let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
		return base.appendingPathComponent("ConetChat", isDirectory: true).appendingPathComponent("local-v1", isDirectory: true)
		#endif
	}

	// MARK: - Lock / unlock

	public var isUnlocked: Bool {
		queue.sync { db != nil }
	}

	/// Opens the account library (`accountKey` = eoa + ":" + workspace, D5). `master` is never written anywhere.
	/// Throws `kcvMismatch` when the master changed and unsent local rows exist (7.3), and `schemaNewer`
	/// when the file came from a newer library (T-14).
	public func unlock(accountKey rawAccount: String, localRoot newRoot: Data) throws {
		try queue.sync {
			lockLocked()
			let acct = rawAccount.lowercased()
			// accountKey = eoa + ":" + workspace (D5). The DEK and K_idx come from the local root (22.2).
			let parts = acct.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
			let eoa = parts.first ?? acct
			let workspace = parts.count > 1 ? parts[1] : "default"
			let key = BeamioChatLocalCrypto.dek(localRoot: newRoot, eoa: eoa, workspace: workspace)
			try FileManager.default.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
			let handle = try ChatLocalSQLite(path: databasePath(for: acct))
			try handle.exec("PRAGMA journal_mode=WAL;")
			try handle.transaction { try handle.exec(ChatLocalSchema.ddl) }

			let version = try handle.scalarText("SELECT v FROM meta WHERE k = 'schemaVersion'").flatMap { Int64($0) }
			if let version, version > Self.schemaVersion {
				handle.close()
				throw BeamioChatLocalError.schemaNewer
			}
			let kcv = BeamioChatLocalCrypto.kcv(dek: key)
			let storedKcv = try handle.scalarText("SELECT v FROM meta WHERE k = 'kcv'")
			if storedKcv == nil {
				try handle.transaction {
					try writeMeta(handle, "schemaVersion", String(Self.schemaVersion))
					try writeMeta(handle, "layoutVersion", String(1))
					try writeMeta(handle, "migrationState", "none")
					try writeMeta(handle, "syncComplete", "0")
					try writeMeta(handle, "headIndexHash", "")
					try writeMeta(handle, "kcv", kcv)
					try writeMeta(handle, "dbEpoch", BeamioChatLocalCrypto.newEpoch())
				}
			} else if storedKcv != kcv {
				// 7.3 and T-38: a mismatch never writes, clears or rebuilds. No data is returned.
				handle.close()
				throw BeamioChatLocalError.kcvMismatch
			}
			let idx = BeamioChatLocalCrypto.idxKey(localRoot: newRoot)
			db = handle
			accountKey = acct
			localRoot = newRoot
			dek = key
			idKey = BeamioChatLocalCrypto.idKey(localRoot: newRoot)
			idxKey = idx
			dbEpoch = try handle.scalarText("SELECT v FROM meta WHERE k = 'dbEpoch'") ?? ""
		}
	}

	/// Logout (D2, 6.5): the UI is told first, then the keys are cleared and the file is kept.
	public func lock() {
		queue.sync {
			guard db != nil else { return }
			emit([.locked])
			lockLocked()
		}
	}

	/// Must run on `queue`. Bumps the generation so results still in flight are discarded (6.5).
	internal func lockLocked() {
		generation += 1
		db?.close()
		db = nil
		if localRoot != nil { BeamioNativeWallet.wipe(&localRoot!) }
		localRoot = nil
		dek = nil
		idKey = nil
		idxKey = nil
		dbEpoch = ""
		accountKey = ""
		windows = [:]
		syncCancelled = false
		syncStateValue = .idle
	}

	// MARK: - Read path (no network)

	/// First screen (6.2): from the newest row toward older rows until the visible heights reach `heightPt`.
	/// The row that crosses the boundary is included.
	public func openConversation(convKey rawConv: String, viewport: BeamioChatViewport) -> BeamioChatPage {
		queue.sync {
			guard let db, let dek, let idxKey else { return lockedPage() }
			let conv = rawConv.lowercased()
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
			do {
				try db.run("DELETE FROM layout WHERE conv_blind = ? AND layout_version <> ?",
				           [.text(connBlind), .int(Int64(viewport.layoutVersion))])
				let syncComplete = try isSyncComplete(db)
				let scan = try scanPage(db: db, conv: conv, connBlind: connBlind, before: nil, viewport: viewport, syncComplete: syncComplete)
				let items = buildItems(connBlind: connBlind, rows: scan.rows, dek: dek)
				let state = scan.olderState
				windows[conv] = BeamioChatLocalWindow(
					lo: state == .end ? nil : scan.oldest,
					reachedOldest: state == .end,
					hi: scan.newest,
					viewport: viewport,
					pending: state == .pending,
					convKey: conv
				)
				return BeamioChatPage(
					items: items,
					olderCursor: state == .end ? nil : scan.oldest.map { encodeCursor($0, conv: conv) },
					olderState: state,
					scanExhausted: scan.scanExhausted,
					syncState: syncStateValue,
					source: .local,
					short: scan.short,
					capped: scan.capped
				)
			} catch {
				NSLog("[BeamioChatLocal] openConversation failed: %@", String(describing: error))
				return BeamioChatPage(items: [], olderCursor: nil, olderState: .end, syncState: syncStateValue, source: .local)
			}
		}
	}

	/// The page strictly older than `cursor` (6.3), with the same rules as the first screen.
	public func loadOlder(convKey rawConv: String, cursor: String, viewport: BeamioChatViewport) throws -> BeamioChatPage {
		try queue.sync {
			guard let db, let dek, let idxKey else { return lockedPage() }
			let conv = rawConv.lowercased()
			let before = try decodeCursor(cursor, conv: conv)
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
			let syncComplete = try isSyncComplete(db)
			let scan = try scanPage(db: db, conv: conv, connBlind: connBlind, before: before, viewport: viewport, syncComplete: syncComplete)
			let items = buildItems(connBlind: connBlind, rows: scan.rows, dek: dek)
			let state = scan.olderState
			if var w = windows[conv] {
				w.lo = state == .end ? nil : scan.oldest
				w.reachedOldest = state == .end
				w.pending = state == .pending
				windows[conv] = w
			}
			return BeamioChatPage(
				items: items,
				olderCursor: state == .end ? nil : scan.oldest.map { encodeCursor($0, conv: conv) },
				olderState: state,
				scanExhausted: scan.scanExhausted,
				syncState: syncStateValue,
				source: .local,
				short: scan.short,
				capped: scan.capped
			)
		}
	}

	// MARK: - Layout sizes

	/// Stores a real measured size (8.2). Estimates are never written. Returns true when a row was written.
	@discardableResult
	public func reportLayout(convKey rawConv: String, stableId: String, viewport vp: BeamioChatViewport, wPt: Double, hPt: Double) -> Bool {
		queue.sync {
			guard let db, let dek, let idxKey else { return false }
			let conv = rawConv.lowercased()
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
			do {
				// Only rows that exist can be measured.
				let msgSt = try db.prepare("SELECT 1 FROM msg WHERE conv_blind = ? AND stable_id = ? AND state = 0")
				try msgSt.bind([.text(connBlind), .text(stableId)])
				guard try msgSt.step() else { return false }

				let key = BeamioChatLocalLayoutModel.layoutKey(vp)
				let wb = Int64(BeamioChatLocalLayoutModel.widthBucket(vp.widthPt))
				let fb = Int64(BeamioChatLocalLayoutModel.fontBucket(vp.fontScale))
				let existing = try db.prepare("""
					SELECT val_enc FROM layout WHERE conv_blind = ? AND stable_id = ? AND width_bucket = ?
					AND orientation = ? AND font_bucket = ? AND layout_version = ?
					""")
				try existing.bind([.text(connBlind), .text(stableId), .int(wb), .text(vp.orientation.rawValue), .int(fb), .int(Int64(vp.layoutVersion))])
				if try existing.step(), let enc = existing.blob(0), let old = decodeLayoutValue(enc, connBlind: connBlind, stableId: stableId, layoutKey: key, dek: dek) {
					if abs(old.wPt - wPt) <= 2, abs(old.hPt - hPt) <= 2 { return false }
				}
				let enc = try encodeLayoutValue(wPt: wPt, hPt: hPt, connBlind: connBlind, stableId: stableId, layoutKey: key, dek: dek)
				try db.run("""
					INSERT OR REPLACE INTO layout (conv_blind, stable_id, width_bucket, orientation, font_bucket, layout_version, val_enc, updated_ms)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					""", [.text(connBlind), .text(stableId), .int(wb), .text(vp.orientation.rawValue), .int(fb),
					      .int(Int64(vp.layoutVersion)), .blob(enc), .int(Int64(Date().timeIntervalSince1970 * 1000))])
				return true
			} catch {
				NSLog("[BeamioChatLocal] reportLayout failed: %@", String(describing: error))
				return false
			}
		}
	}

	// MARK: - Invalidation and deletion

	/// Clears one conversation, or the whole account when `convKey` is nil (10). Rows with
	/// `pending_publish = 1` are kept and counted (T-12). Any scope changes `dbEpoch`, so older cursors
	/// become `cursor_invalid` (7.4).
	@discardableResult
	public func clearLocalCache(convKey rawConv: String? = nil) throws -> BeamioChatClearResult {
		try queue.sync {
			guard let db, let idxKey else { throw BeamioChatLocalError.locked }
			let conv = rawConv?.lowercased()
			let kept: Int
			if let conv {
				let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, conv)
				try db.transaction {
					try db.run("DELETE FROM msg WHERE conv_blind = ? AND pending_publish = 0", [.text(connBlind)])
					try db.run("DELETE FROM layout WHERE conv_blind = ? AND NOT EXISTS (SELECT 1 FROM msg m WHERE m.conv_blind = layout.conv_blind AND m.stable_id = layout.stable_id)", [.text(connBlind)])
					try db.run("DELETE FROM conv WHERE conv_blind = ? AND NOT EXISTS (SELECT 1 FROM msg m WHERE m.conv_blind = conv.conv_blind)", [.text(connBlind)])
					try writeMeta(db, "dbEpoch", BeamioChatLocalCrypto.newEpoch())
				}
				kept = Int(try db.scalarInt("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND pending_publish = 1", [.text(connBlind)]))
				windows.removeValue(forKey: conv)
			} else {
				try db.transaction {
					try db.run("DELETE FROM msg WHERE pending_publish = 0")
					try db.run("DELETE FROM layout WHERE NOT EXISTS (SELECT 1 FROM msg m WHERE m.conv_blind = layout.conv_blind AND m.stable_id = layout.stable_id)")
					try db.run("DELETE FROM conv WHERE NOT EXISTS (SELECT 1 FROM msg m WHERE m.conv_blind = conv.conv_blind)")
					try writeMeta(db, "headIndexHash", "")
					try writeMeta(db, "syncComplete", "0")
					try writeMeta(db, "dbEpoch", BeamioChatLocalCrypto.newEpoch())
				}
				kept = Int(try db.scalarInt("SELECT COUNT(*) FROM msg WHERE pending_publish = 1"))
				windows.removeAll()
			}
			dbEpoch = try db.scalarText("SELECT v FROM meta WHERE k = 'dbEpoch'") ?? dbEpoch
			emit([.cleared(scope: conv == nil ? "account" : "conversation", convKey: conv, pendingKept: kept)])
			return BeamioChatClearResult(pendingKept: kept)
		}
	}

	/// The number of messages of the account's library that are not yet published (`pending_publish = 1`); 0 when there is no main file. Read only. Throws `io` when the file cannot be probed
	/// and the database error when it cannot be opened or read: an unknown state, never "none". The silent cleanup keeps a library with unsent messages.
	internal func unsentMessageCount(accountKey rawAccount: String) throws -> Int {
		try queue.sync {
			let path = databasePath(for: rawAccount.lowercased())
			guard let present = BeamioShellRecord.fileExistence(at: path) else { throw BeamioChatLocalError.io }
			guard present else { return 0 }
			let probe = try ChatLocalSQLite(path: path)
			defer { probe.close() }
			return Int(try probe.scalarInt("SELECT COUNT(*) FROM msg WHERE pending_publish = 1"))
		}
	}

	/// Deletes an account library file (10). A pending-publish count blocks the delete unless `force` is set.
	public func deleteLocalData(accountKey rawAccount: String, force: Bool = false) throws {
		try queue.sync {
			let acct = rawAccount.lowercased()
			if acct == accountKey { lockLocked() }
			let path = databasePath(for: acct)
			// the existence probe can fail: "no such file" means there is nothing to delete; a permission or I/O error is not "nothing" and is thrown (`io`), never returned silently
			guard let present = BeamioShellRecord.fileExistence(at: path) else { throw BeamioChatLocalError.io }
			if present, !force {
				let probe = try ChatLocalSQLite(path: path)
				let pending = try probe.scalarInt("SELECT COUNT(*) FROM msg WHERE pending_publish = 1")
				probe.close()
				if pending > 0 { throw BeamioChatLocalError.pendingPresent(Int(pending)) }
			}
			// the main file and its side files (-wal, -shm, -journal) are all derived from the same path, so all are this account's: each is probed and removed even when the main
			// file is already gone (a side file can outlive it). Absent is done; a failed probe or a failed removal is thrown.
			for suffix in ["", "-wal", "-shm", "-journal"] {
				let target = path + suffix
				guard let exists = BeamioShellRecord.fileExistence(at: target) else { throw BeamioChatLocalError.io }
				if exists {
					do { try FileManager.default.removeItem(atPath: target) } catch { throw BeamioChatLocalError.io }
				}
			}
		}
	}

	/// Subscribes to events. With `convKey`, only that conversation's events are delivered (events without a
	/// conversation, such as `syncProgress` and `locked`, are always delivered).
	public func subscribe(convKey: String? = nil, _ handler: @escaping Handler) -> UUID {
		let id = UUID()
		let filter = convKey?.lowercased()
		queue.sync { handlers[id] = (conv: filter, handler: handler) }
		return id
	}

	public func unsubscribe(_ id: UUID) {
		queue.sync { handlers.removeValue(forKey: id) }
	}

	/// Asks a running `syncIndex` to stop after the current batch (6.3 `stopFullSync`).
	public func stopFullSync() {
		queue.sync { syncCancelled = true }
	}

	/// Local outgoing message not yet published (`pending_publish = 1`). Internal: used by the send path and tests.
	func addPendingLocal(convKey rawConv: String, sendId: String?, sortTs: Int64, dir: String, body: String,
	                     tsProvided: Bool = true) throws {
		try queue.sync {
			guard let db, let dek, let idKey else { throw BeamioChatLocalError.locked }
			let conv = rawConv.lowercased()
			let sendKey = (sendId?.isEmpty == false)
				? sendId!
				: BeamioChatLocalCrypto.sendKeyDerived(idKey: idKey, peer: conv, dir: dir, ts: sortTs, body: body)
			var report = BeamioChatSyncReport()
			let row = IngestRow(convKey: conv, stableId: BeamioChatLocalCrypto.stableId(idxKey: idxKey!, sendKey: sendKey),
			                    sendKey: sendKey, sortTs: sortTs, dir: dir, kind: .text, cid: nil, revision: 0,
			                    deleted: false, body: body, media: nil, pending: true,
			                    tsProv: tsProvided ? 0 : ((sendId?.isEmpty == false) ? 1 : 3))
			let (events, _) = try db.transaction { () -> ([BeamioChatEvent], Set<String>) in
				try applyIngest(db: db, rows: [row], dek: dek, report: &report)
			}
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey!, conv)
			let pending = Int(try db.scalarInt("SELECT COUNT(*) FROM msg WHERE conv_blind = ? AND pending_publish = 1", [.text(connBlind)]))
			let convMeta = try Self.encodeConvMeta(conv: conv, connBlind: connBlind, pendingCount: pending, dek: dek)
			try db.run("UPDATE conv SET meta_enc = ? WHERE conv_blind = ?", [.blob(convMeta), .text(connBlind)])
			emit(events)
		}
	}

	// MARK: - Helpers (queue only)

	internal func databasePath(for acct: String) -> String {
		rootDirectory.appendingPathComponent("chat-local-v1-\(libraryTag(for: acct)).sqlite").path
	}

	/// The tag in a library's file name: the first eight bytes of the SHA-256 of the account key. One way: a file name does not give the account back.
	internal func libraryTag(for acct: String) -> String {
		SHA256.hash(data: Data(acct.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
	}

	/// The tags of the main library files in the root (`chat-local-v1-<tag>.sqlite`). nil when the folder cannot be listed (anything but "it does not exist").
	internal func libraryTagsOnDisk() -> [String]? {
		var isDir: ObjCBool = false
		guard FileManager.default.fileExists(atPath: rootDirectory.path, isDirectory: &isDir) else {
			return BeamioShellRecord.fileExistence(at: rootDirectory.path) == false ? [] : nil
		}
		guard isDir.boolValue, let names = try? FileManager.default.contentsOfDirectory(atPath: rootDirectory.path) else { return nil }
		let prefix = "chat-local-v1-", suffix = ".sqlite"
		return names.filter { $0.hasPrefix(prefix) && $0.hasSuffix(suffix) }.map { String($0.dropFirst(prefix.count).dropLast(suffix.count)) }.sorted()
	}

	internal func lockedPage() -> BeamioChatPage {
		BeamioChatPage(items: [], olderCursor: nil, olderState: .end, syncState: syncStateValue, source: .locked)
	}

	internal func isSyncComplete(_ db: ChatLocalSQLite) throws -> Bool {
		try db.scalarText("SELECT v FROM meta WHERE k = 'syncComplete'") == "1"
	}

	internal func emit(_ events: [BeamioChatEvent]) {
		guard !events.isEmpty else { return }
		let current = Array(handlers.values)
		notifyQueue.async {
			for event in events {
				let conv = Self.eventConvKey(event)
				for entry in current where entry.conv == nil || conv == nil || entry.conv == conv {
					entry.handler(event)
				}
			}
		}
	}

	static func eventConvKey(_ event: BeamioChatEvent) -> String? {
		switch event {
		case .inserted(let conv, _, _), .updated(let conv, _, _), .deleted(let conv, _), .olderAvailable(let conv):
			return conv
		case .cleared(_, let conv, _):
			return conv
		case .syncProgress, .locked:
			return nil
		}
	}

	/// Cursor (7.4): base64url(JSON{v:1, e: first 8 of dbEpoch, c: convKey, t: sortTs, i: stableId}).
	internal func encodeCursor(_ key: BeamioChatLocalKey, conv: String) -> String {
		let obj: [String: Any] = ["v": 1, "e": String(dbEpoch.prefix(8)), "c": conv,
		                          "t": NSNumber(value: key.sortTs), "i": key.stableId]
		let data = (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
		return BeamioChatLocalCrypto.base64Url(data)
	}

	/// A cursor from another epoch or conversation is `cursor_invalid` (6.6).
	internal func decodeCursor(_ cursor: String, conv: String) throws -> BeamioChatLocalKey {
		var b64 = cursor.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		while b64.count % 4 != 0 { b64 += "=" }
		guard let data = Data(base64Encoded: b64),
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
		      (obj["v"] as? NSNumber)?.intValue == 1,
		      let epoch = obj["e"] as? String, let c = obj["c"] as? String,
		      let stableId = obj["i"] as? String,
		      let sortTs = (obj["t"] as? NSNumber)?.int64Value
		else { throw BeamioChatLocalError.cursorInvalid }
		guard epoch == String(dbEpoch.prefix(8)), c == conv else { throw BeamioChatLocalError.cursorInvalid }
		return BeamioChatLocalKey(sortTs: sortTs, stableId: stableId)
	}

	internal func writeMeta(_ handle: ChatLocalSQLite, _ k: String, _ v: String) throws {
		try handle.run("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", [.text(k), .text(v)])
	}
}

/// Sort key K = (sortTs, stableId). Byte order on stableId (5).
struct BeamioChatLocalKey: Equatable, Comparable {
	var sortTs: Int64
	var stableId: String

	static func < (a: BeamioChatLocalKey, b: BeamioChatLocalKey) -> Bool {
		if a.sortTs != b.sortTs { return a.sortTs < b.sortTs }
		return a.stableId.utf8.lexicographicallyPrecedes(b.stableId.utf8)
	}
}

/// What a conversation has loaded in memory, used to decide `inserted{tail|middle}` (5, 7.4).
struct BeamioChatLocalWindow {
	var lo: BeamioChatLocalKey?
	var reachedOldest: Bool
	var hi: BeamioChatLocalKey?
	var viewport: BeamioChatViewport?
	var pending: Bool
	var convKey: String
}

enum ChatLocalSchema {
	static let ddl = """
	CREATE TABLE IF NOT EXISTS meta (
	  k TEXT PRIMARY KEY,
	  v TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS conv (
	  conv_blind TEXT PRIMARY KEY,
	  last_sort_ts INTEGER,
	  meta_enc BLOB
	);
	CREATE TABLE IF NOT EXISTS tsprov (
	  conv_blind TEXT NOT NULL,
	  stable_id TEXT NOT NULL,
	  val_enc BLOB NOT NULL,
	  PRIMARY KEY (conv_blind, stable_id)
	);
	CREATE TABLE IF NOT EXISTS msg (
	  conv_blind TEXT NOT NULL,
	  stable_id TEXT NOT NULL,
	  sort_ts INTEGER NOT NULL,
	  dir TEXT NOT NULL,
	  revision INTEGER NOT NULL DEFAULT 0,
	  state INTEGER NOT NULL DEFAULT 0,
	  pending_publish INTEGER NOT NULL DEFAULT 0,
	  cid_blind TEXT,
	  body_enc BLOB,
	  meta_enc BLOB,
	  PRIMARY KEY (conv_blind, sort_ts, stable_id)
	);
	CREATE UNIQUE INDEX IF NOT EXISTS msg_id_uq ON msg (conv_blind, stable_id);
	CREATE INDEX IF NOT EXISTS msg_cid ON msg (conv_blind, cid_blind);
	CREATE TABLE IF NOT EXISTS alias (
	  alias_blind TEXT PRIMARY KEY,
	  target_enc BLOB NOT NULL
	);
	CREATE TABLE IF NOT EXISTS layout (
	  conv_blind TEXT NOT NULL,
	  stable_id TEXT NOT NULL,
	  width_bucket INTEGER NOT NULL,
	  orientation TEXT NOT NULL,
	  font_bucket INTEGER NOT NULL,
	  layout_version INTEGER NOT NULL,
	  val_enc BLOB NOT NULL,
	  updated_ms INTEGER NOT NULL,
	  PRIMARY KEY (conv_blind, stable_id, width_bucket, orientation, font_bucket, layout_version)
	);
	"""
}
