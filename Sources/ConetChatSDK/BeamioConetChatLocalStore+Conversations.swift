import CryptoKit
import Foundation

/// One row of the session list (spec 6.7).
public struct BeamioChatConversationRow: Equatable {
	public var convKey: String
	/// sort_ts of the newest visible item (`reply` and tombstones are not visible, 6.8).
	public var lastSortTs: Int64
	public var lastStableId: String
	/// Text of the newest visible item when it is text. Empty for other kinds.
	public var lastPreview: String
	public var pendingCount: Int

	public init(convKey: String, lastSortTs: Int64, lastStableId: String, lastPreview: String, pendingCount: Int) {
		self.convKey = convKey
		self.lastSortTs = lastSortTs
		self.lastStableId = lastStableId
		self.lastPreview = lastPreview
		self.pendingCount = pendingCount
	}
}

public struct BeamioChatConversationPage: Equatable {
	public var rows: [BeamioChatConversationRow]
	/// nil when the list is complete.
	public var nextCursor: String?

	public init(rows: [BeamioChatConversationRow], nextCursor: String?) {
		self.rows = rows
		self.nextCursor = nextCursor
	}
}

extension BeamioChatLocalCrypto {
	/// AAD of the encrypted convKey kept in `conv.meta_enc`, bound to the blinded conversation.
	static func convAAD(connBlind: String) -> Data {
		Data("beamio-chat-local|conv|v1|\(connBlind)".utf8)
	}
}

extension BeamioConetChatLocalStore {
	/// `listConversations({limit ≤ 100, cursor})` (spec 6.7).
	///
	/// Order: `lastSortTs` descending, then `conv_blind` ASCII ascending. The cursor is `base64url(JSON{t, b})` of the last
	/// row of the previous page. While locked the list is empty (6.5, the list is cleared on lock). The kind and the
	/// pending count are inside the encrypted meta, so each conversation is read through its own rows.
	///
	/// Simplification: the last visible row is found per call, not kept as `meta_enc.lastSortTs`. The result is the same
	/// order. The cost is one indexed read per conversation, which the review asked to measure at 50k rows.
	public func listConversations(limit: Int, cursor: String?) throws -> BeamioChatConversationPage {
		try queue.sync { () throws -> BeamioChatConversationPage in
			guard let db, let dek else { return BeamioChatConversationPage(rows: [], nextCursor: nil) }
			let size = min(100, max(1, limit))
			let after = try cursor.map { try Self.decodeConversationCursor($0) }
			var convs: [(blind: String, enc: Data?)] = []
			let st = try db.prepare("SELECT conv_blind, meta_enc FROM conv")
			while try st.step() {
				convs.append((st.text(0) ?? "", st.blob(1)))
			}
			var rows: [(blind: String, row: BeamioChatConversationRow)] = []
			for c in convs {
				guard let enc = c.enc, let meta = Self.decodeConvMeta(connBlind: c.blind, enc: enc, dek: dek),
				      let last = try lastVisible(db: db, connBlind: c.blind, dek: dek)
				else { continue }
				rows.append((c.blind, BeamioChatConversationRow(
					convKey: meta.convKey, lastSortTs: last.sortTs, lastStableId: last.stableId,
					lastPreview: last.preview, pendingCount: meta.pendingCount
				)))
			}
			rows.sort { a, b in
				a.row.lastSortTs != b.row.lastSortTs ? a.row.lastSortTs > b.row.lastSortTs : a.blind < b.blind
			}
			if let (t, b) = after {
				rows = rows.filter { $0.row.lastSortTs < t || ($0.row.lastSortTs == t && $0.blind > b) }
			}
			let page = Array(rows.prefix(size))
			var next: String?
			if rows.count > size, let last = page.last {
				next = try Self.encodeConversationCursor(ts: last.row.lastSortTs, blind: last.blind)
			}
			return BeamioChatConversationPage(rows: page.map { $0.row }, nextCursor: next)
		}
	}

	/// The newest visible row that is not a `reply` (6.7, 6.8), newest first. Stops at the first match.
	private func lastVisible(db: ChatLocalSQLite, connBlind: String, dek: SymmetricKey)
		throws -> (sortTs: Int64, stableId: String, preview: String)? {
		let st = try db.prepare("SELECT sort_ts, stable_id, revision, body_enc, meta_enc FROM msg WHERE conv_blind = ? AND state = 0 ORDER BY sort_ts DESC, stable_id DESC")
		try st.bind([.text(connBlind)])
		while try st.step() {
			let stableId = st.text(1) ?? ""
			let meta = decodeMeta(connBlind: connBlind, stableId: stableId, enc: st.blob(4), dek: dek)
			if meta.kind == .reply { continue }
			var preview = ""
			if meta.kind == .text, let enc = st.blob(3),
			   let raw = decryptBody(connBlind: connBlind, stableId: stableId, revision: st.int(2), enc: enc, dek: dek) {
				preview = BeamioChatMediaBody.displayText(raw)
			}
			return (st.int(0), stableId, preview)
		}
		return nil
	}

	/// Encrypted conversation meta: the convKey and the pending count.
	static func encodeConvMeta(conv: String, connBlind: String, pendingCount: Int, dek: SymmetricKey) throws -> Data {
		let plain = try JSONSerialization.data(withJSONObject: ["convKey": conv, "pc": pendingCount], options: [.sortedKeys])
		return try BeamioChatLocalCrypto.seal(plain, key: dek, aad: BeamioChatLocalCrypto.convAAD(connBlind: connBlind))
	}

	static func decodeConvMeta(connBlind: String, enc: Data, dek: SymmetricKey) -> (convKey: String, pendingCount: Int)? {
		guard let plain = try? BeamioChatLocalCrypto.open(enc, key: dek, aad: BeamioChatLocalCrypto.convAAD(connBlind: connBlind)),
		      let obj = (try? JSONSerialization.jsonObject(with: plain)) as? [String: Any],
		      let conv = obj["convKey"] as? String
		else { return nil }
		return (conv, (obj["pc"] as? NSNumber)?.intValue ?? 0)
	}

	static func encodeConversationCursor(ts: Int64, blind: String) throws -> String {
		let json = try JSONSerialization.data(withJSONObject: ["t": ts, "b": blind], options: [.sortedKeys])
		return BeamioChatLocalCrypto.base64Url(json)
	}

	static func decodeConversationCursor(_ s: String) throws -> (Int64, String) {
		var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		while b64.count % 4 != 0 { b64 += "=" }
		guard let data = Data(base64Encoded: b64),
		      let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
		      let t = obj["t"] as? NSNumber, let b = obj["b"] as? String
		else { throw BeamioChatLocalError.cursorInvalid }
		return (t.int64Value, b)
	}
}
