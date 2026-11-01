import Foundation

/// Inbound messages the app has not confirmed yet (no `ackInbound`), kept on
/// disk so a message received while the page is not running (VoIP push, page
/// suspended or killed) reaches the page when it starts.
///
/// Holds only the OpenPGP armor as received (still encrypted to the user PGP
/// key) plus its hash; it is decrypted again when handed over. The file is
/// excluded from backup and protected until the first unlock. Entries leave on
/// ACK, after a week, or past 500 (oldest first); the mailbox keeps its own copy
/// until the ACK either way.
enum BeamioConetChatInboxStore {
	struct Entry {
		var armorHash: String
		var armor: String
		var viaDomain: String
		var at: TimeInterval
	}

	private static let lock = NSLock()
	private static let maxEntries = 500
	private static let ttl: TimeInterval = 7 * 24 * 3600

	private static var fileURL: URL? {
		guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
		let folder = dir.appendingPathComponent("ConetChat", isDirectory: true)
		if !FileManager.default.fileExists(atPath: folder.path) {
			try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
			var values = URLResourceValues()
			values.isExcludedFromBackup = true
			var f = folder
			try? f.setResourceValues(values)
		}
		return folder.appendingPathComponent("inbox_v1.json")
	}

	private static func readAll() -> [Entry] {
		guard let url = fileURL, let data = try? Data(contentsOf: url),
		      let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
		else { return [] }
		let now = Date().timeIntervalSince1970
		return rows.compactMap { r in
			guard let h = r["h"] as? String, !h.isEmpty,
			      let a = r["a"] as? String, a.contains("BEGIN PGP MESSAGE")
			else { return nil }
			let t = (r["t"] as? Double) ?? 0
			guard now - t < ttl else { return nil }
			return Entry(armorHash: h, armor: a, viaDomain: (r["v"] as? String) ?? "", at: t)
		}
	}

	private static func writeAll(_ entries: [Entry]) {
		guard let url = fileURL else { return }
		let rows = entries.suffix(maxEntries).map { ["h": $0.armorHash, "a": $0.armor, "v": $0.viaDomain, "t": $0.at] as [String: Any] }
		guard let data = try? JSONSerialization.data(withJSONObject: rows) else { return }
		try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
		var values = URLResourceValues()
		values.isExcludedFromBackup = true
		var u = url
		try? u.setResourceValues(values)
	}

	static func put(armorHash: String, armor: String, viaDomain: String) {
		guard !armorHash.isEmpty, armor.contains("BEGIN PGP MESSAGE") else { return }
		lock.lock(); defer { lock.unlock() }
		var all = readAll()
		if all.contains(where: { $0.armorHash == armorHash }) { return }
		all.append(Entry(armorHash: armorHash, armor: armor, viaDomain: viaDomain, at: Date().timeIntervalSince1970))
		writeAll(all)
	}

	static func remove(_ hashes: [String]) {
		guard !hashes.isEmpty else { return }
		lock.lock(); defer { lock.unlock() }
		let all = readAll()
		let kept = all.filter { !hashes.contains($0.armorHash) }
		if kept.count != all.count { writeAll(kept) }
	}

	static func list() -> [Entry] {
		lock.lock(); defer { lock.unlock() }
		return readAll()
	}

	static func clear() {
		lock.lock(); defer { lock.unlock() }
		if let url = fileURL { try? FileManager.default.removeItem(at: url) }
	}
}
