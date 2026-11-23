import CryptoKit
import Foundation

/// M3 import digest (spec M3 (a)–(d)). Pure functions, so the store and the shared vectors
/// (interface/protocol/import-digest-vectors.v1.json) use the same code.
///
/// - row: HMAC-SHA256(K_idx, sendKey ‖ 0x1f ‖ decimal(sort_ts) ‖ 0x1f ‖ dir ‖ 0x1f ‖ body bytes), raw 32 bytes.
/// - conversation: HMAC-SHA256(K_idx, "import-digest-v1" ‖ 0x1f ‖ decimal(n) ‖ 0x1f ‖ row_1 … row_n), rows ordered by
/// (sort_ts ascending, stable_id in ASCII byte order).
/// - global: HMAC-SHA256(K_idx, "import-digest-v1|global" ‖ 0x1f ‖ entries), entries for every conversation with n ≥ 1,
/// ordered by conv_blind in ASCII byte order; each entry is conv_blind ‖ 0x1f ‖ conv_digest (raw).
enum BeamioChatImportDigest {
	struct Row {
		var convBlind: String
		var stableId: String
		var sendKey: String
		var sortTs: Int64
		var dir: String
		var body: Data
	}

	static func rowHMAC(kIdx: SymmetricKey, row: Row) -> Data {
		var msg = Data(row.sendKey.utf8)
		msg.append(BeamioChatLocalCrypto.separator)
		msg.append(contentsOf: String(row.sortTs).utf8)
		msg.append(BeamioChatLocalCrypto.separator)
		msg.append(contentsOf: row.dir.utf8)
		msg.append(BeamioChatLocalCrypto.separator)
		msg.append(row.body)
		return Data(HMAC<SHA256>.authenticationCode(for: msg, using: kIdx))
	}

	/// Returns the global digest (hex) and the per-conversation digests keyed by conv_blind (hex), plus the row count.
	static func compute(kIdx: SymmetricKey, rows: [Row]) -> (global: String, conversations: [String: String], rows: Int) {
		var byConv: [String: [Row]] = [:]
		for r in rows { byConv[r.convBlind, default: []].append(r) }
		var convDigests: [String: Data] = [:]
		for (conv, list) in byConv where !list.isEmpty {
			let ordered = list.sorted { a, b in
				if a.sortTs != b.sortTs { return a.sortTs < b.sortTs }
				return a.stableId.utf8.lexicographicallyPrecedes(b.stableId.utf8)
			}
			var msg = Data("import-digest-v1".utf8)
			msg.append(BeamioChatLocalCrypto.separator)
			msg.append(contentsOf: String(ordered.count).utf8)
			msg.append(BeamioChatLocalCrypto.separator)
			for r in ordered { msg.append(rowHMAC(kIdx: kIdx, row: r)) }
			convDigests[conv] = Data(HMAC<SHA256>.authenticationCode(for: msg, using: kIdx))
		}
		var global = Data("import-digest-v1|global".utf8)
		global.append(BeamioChatLocalCrypto.separator)
		for conv in convDigests.keys.sorted(by: { $0.utf8.lexicographicallyPrecedes($1.utf8) }) {
			global.append(contentsOf: conv.utf8)
			global.append(BeamioChatLocalCrypto.separator)
			global.append(convDigests[conv]!)
		}
		let g = Data(HMAC<SHA256>.authenticationCode(for: global, using: kIdx))
		return (
			BeamioChatLocalCrypto.hex(g),
			convDigests.mapValues { BeamioChatLocalCrypto.hex($0) },
			rows.count
		)
	}
}
