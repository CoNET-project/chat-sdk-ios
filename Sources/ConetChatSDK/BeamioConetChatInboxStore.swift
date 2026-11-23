import Foundation

/// Inbound mailbox frames, kept on disk.
///
/// Each decrypted and stored frame has a record: its armorHash (keccak256 of the armor; the dedupe key,), its arrival time, whether
/// the page confirmed it (`c`), and whether the mailbox acknowledged it (`s`: the `gossip_delivery_ack` got a successful server answer).
/// Records do not expire by time: the mailbox keeps a chat frame until it is acked, so a redelivery can come at any time. Above
/// `maxRecords` only acknowledged records are dropped, oldest first; an unacknowledged record is never dropped.
///
/// The OpenPGP armor (still encrypted to the user key) stays until the page's ackInbound confirms the message, with no time expiry
///. It is the copy the replay on attach hands to the page. Dedupe does not read it: a record outlives its armor.
///
/// A file that cannot be read, or does not parse, is never overwritten: the write returns false, and the frame is neither shown nor
/// acked. Every call reads the file: nothing is cached.
enum BeamioConetChatInboxStore {
	struct Entry {
		var armorHash: String
		var armor: String
		var viaDomain: String
		var at: TimeInterval
		var confirmed: Bool
		var serverAcked: Bool
	}

	/// What a read found. `unreadable` is not an empty inbox.
	private enum Load {
		case rows([Entry], quarantined: [Any])
		case unreadable
	}

	private static let lock = NSLock()
	static let maxRecords = 50000

#if BEAMIO_TEST_HOOKS
	/// Test build only: every write fails.
	static var failWrites = false
	/// Test build only: every read is unreadable.
	static var failReads = false
#endif

	private static var fileURL: URL? { BeamioInboxFile.folder?.appendingPathComponent("inbox_v1.json") }

	private static func load() -> Load {
		guard let url = fileURL else { return .unreadable }
#if BEAMIO_TEST_HOOKS
		if failReads { return .unreadable }
#endif
		let data: Data
		switch BeamioInboxFile.read(url) {
		case .missing: return .rows([], quarantined: [])
		case .unreadable: return .unreadable
		case .data(let d): data = d
		}
		// The file must be an array, or it is unreadable and nothing is written over it.
		guard let rows = try? JSONSerialization.jsonObject(with: data) as? [Any] else { return .unreadable }
		// (6): a row without a usable hash is isolated. It cannot be linked to any frame, so nothing is shown or acked from it; it is kept
		// verbatim on every write, and its error code is reported by `quarantineCodes`. The rest of the inbox keeps running.
		var entries: [Entry] = []
		var quarantined: [Any] = []
		for item in rows {
			guard let r = item as? [String: Any], let h = r["h"] as? String, !h.isEmpty else {
				quarantined.append(item)
				continue
			}
			let t = (r["t"] as? Double) ?? 0
			let confirmed = (r["c"] as? Bool) ?? false
			let stored = (r["a"] as? String) ?? ""
			// The armor stays until the page confirms the message: no time expiry. Dedupe does not read it.
			let armor = (!confirmed && stored.contains("BEGIN PGP MESSAGE")) ? stored : ""
			entries.append(Entry(
				armorHash: h,
				armor: armor,
				viaDomain: (r["v"] as? String) ?? "",
				at: t,
				confirmed: confirmed,
				serverAcked: (r["s"] as? Bool) ?? false
			))
		}
		return .rows(entries, quarantined: quarantined)
	}

	/// (review B3, superseded by the spec): above the limit, the oldest records the mailbox acked go first, with their armor. A
	/// record the mailbox has not acked is never dropped. The page's ackInbound is not a condition (; vector IB-06 keeps armor only
	/// until the eviction).
	static func trimmed(_ entries: [Entry], limit: Int) -> [Entry] {
		var excess = entries.count - limit
		guard excess > 0 else { return entries }
		return entries.filter { e in
			if excess > 0 && e.serverAcked {
				excess -= 1
				return false
			}
			return true
		}
	}

	private static func save(_ entries: [Entry], quarantined: [Any]) -> Bool {
		guard let url = fileURL else { return false }
#if BEAMIO_TEST_HOOKS
		if failWrites { return false }
#endif
		var rows: [Any] = entries.map { e -> [String: Any] in
			["h": e.armorHash, "a": e.confirmed ? "" : e.armor, "v": e.viaDomain, "t": e.at, "c": e.confirmed, "s": e.serverAcked]
		}
		rows.append(contentsOf: quarantined)
		guard let data = try? JSONSerialization.data(withJSONObject: rows) else { return false }
		return BeamioInboxFile.replace(url, with: data)
	}

	/// What one arrival found and did: the read, whether its record was there before, and whether this call stored it.
	struct Admission: Equatable {
		var readable: Bool
		var known: Bool
		var stored: Bool
		/// The record was there and the mailbox has already answered its ack ((3)).
		var serverAcked = false
	}

	/// One read, then at most one write. The dedupe answer and the store are decided together. An unreadable inbox is not
	/// written. Runs on the inbox IO queue (`BeamioInboxIO.perform`).
	static func admit(armorHash: String, armor: String, viaDomain: String) -> Admission {
		lock.lock(); defer { lock.unlock() }
		guard case .rows(var all, let quarantined) = load() else { return Admission(readable: false, known: false, stored: false) }
		if let existing = all.first(where: { $0.armorHash == armorHash }) {
			return Admission(readable: true, known: true, stored: false, serverAcked: existing.serverAcked)
		}
		guard !armorHash.isEmpty, armor.contains("BEGIN PGP MESSAGE") else { return Admission(readable: true, known: false, stored: false) }
		all.append(Entry(
			armorHash: armorHash, armor: armor, viaDomain: viaDomain,
			at: Date().timeIntervalSince1970, confirmed: false, serverAcked: false
		))
		all = trimmed(all, limit: maxRecords)
		guard save(all, quarantined: quarantined) else { return Admission(readable: true, known: false, stored: false) }
		return Admission(readable: true, known: false, stored: true)
	}

	/// the record of a dropped frame, the armorHash only. Nothing is shown and no armor is kept, so
	/// `list` never hands it to the page. One read, then at most one write, as `admit`.
	static func admitMarker(armorHash: String) -> Admission {
		lock.lock(); defer { lock.unlock() }
		guard case .rows(var all, let quarantined) = load() else { return Admission(readable: false, known: false, stored: false) }
		if let existing = all.first(where: { $0.armorHash == armorHash }) {
			return Admission(readable: true, known: true, stored: false, serverAcked: existing.serverAcked)
		}
		guard !armorHash.isEmpty else { return Admission(readable: true, known: false, stored: false) }
		all.append(Entry(
			armorHash: armorHash, armor: "", viaDomain: "",
			at: Date().timeIntervalSince1970, confirmed: false, serverAcked: false
		))
		all = trimmed(all, limit: maxRecords)
		guard save(all, quarantined: quarantined) else { return Admission(readable: true, known: false, stored: false) }
		return Admission(readable: true, known: false, stored: true)
	}

	/// Stores a new frame and its record. True when the record is there (before, or just written). An unreadable inbox answers false.
	static func put(armorHash: String, armor: String, viaDomain: String) -> Bool {
		let a = admit(armorHash: armorHash, armor: armor, viaDomain: viaDomain)
		return a.readable && (a.known || a.stored)
	}

	/// The page has stored these messages: their armor goes; their record stays (dedupe). False when the inbox cannot be read or written.
	@discardableResult
	static func confirm(_ hashes: [String]) -> Bool {
		guard !hashes.isEmpty else { return true }
		lock.lock(); defer { lock.unlock() }
		guard case .rows(var all, let quarantined) = load() else { return false }
		var changed = false
		for i in all.indices where hashes.contains(all[i].armorHash) && !all[i].confirmed {
			all[i].confirmed = true
			all[i].armor = ""
			changed = true
		}
		return changed ? save(all, quarantined: quarantined) : true
	}

	/// The mailbox answered the `gossip_delivery_ack` of these frames successfully. False when the inbox cannot be read or written.
	@discardableResult
	static func markServerAcked(_ hashes: [String]) -> Bool {
		guard !hashes.isEmpty else { return true }
		lock.lock(); defer { lock.unlock() }
		guard case .rows(var all, let quarantined) = load() else { return false }
		var changed = false
		for i in all.indices where hashes.contains(all[i].armorHash) && !all[i].serverAcked {
			all[i].serverAcked = true
			changed = true
		}
		return changed ? save(all, quarantined: quarantined) : true
	}

	/// True when this frame was stored before, in any state. An unreadable inbox answers false, and the frame is then not stored either.
	static func hasRecord(armorHash: String) -> Bool {
		lock.lock(); defer { lock.unlock() }
		guard case .rows(let all, _) = load() else { return false }
		return all.contains { $0.armorHash == armorHash }
	}

	/// The messages the page has not confirmed yet, with their armor (handed over again on attach).
	static func list() -> [Entry] {
		lock.lock(); defer { lock.unlock() }
		guard case .rows(let all, _) = load() else { return [] }
		return all.filter { !$0.confirmed && !$0.armor.isEmpty }
	}

	/// The codes of the rows the inbox isolated ((6)): `row_without_hash` (an object with no usable `h`) or `row_not_an_object`.
	static func quarantineCodes() -> [String] {
		lock.lock(); defer { lock.unlock() }
		guard case .rows(_, let quarantined) = load() else { return [] }
		return quarantined.map { ($0 is [String: Any]) ? "row_without_hash" : "row_not_an_object" }
	}

	/// True when the inbox holds any row (isolated rows included), or cannot be read: data of unknown content is data ((2)).
	static func holdsAnyRow() -> Bool {
		lock.lock(); defer { lock.unlock() }
		switch load() {
		case .rows(let all, let quarantined):
			return !(all.isEmpty && quarantined.isEmpty)
		case .unreadable:
			return true
		}
	}

	@discardableResult
	static func clear() -> Bool {
		lock.lock(); defer { lock.unlock() }
		guard let url = fileURL else { return true }
		return BeamioInboxFile.remove(url)
	}
}
