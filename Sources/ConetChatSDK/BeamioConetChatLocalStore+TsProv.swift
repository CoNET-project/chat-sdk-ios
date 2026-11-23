import CryptoKit
import Foundation

/// D16 provenance of this device's own writes, kept until the record is ingested.
///
/// Written when the write is made, before the record is published, so that a kill between the write and the ingest
/// keeps the provenance. Stored only in the account's encrypted database: the value is sealed with DEK, the key is the
/// blinded conversation and the stable_id (K_idx). No sendKey, no plaintext, no UserDefaults, no log. Nothing is written
/// while the library is locked. The row is deleted by the ingest that consumes it. Each account has its own file, so
/// accounts cannot see each other's provenance.
extension BeamioChatLocalCrypto {
	static func tsProvAAD(connBlind: String, stableId: String) -> Data {
		Data("beamio-chat-local|tsprov|v1|\(connBlind)|\(stableId)".utf8)
	}
}

extension BeamioConetChatLocalStore {
	/// Records the ts_prov of one of this device's own writes (0 sender time, 1 receive-time fallback, 3 fallback with a
	/// derived sendKey). Called by the history store before the record is published. Locked: nothing is written.
	public func recordLocalTsProv(convKey: String, sendKey: String, tsProv: Int) {
		queue.sync {
			guard let db, let dek, let idxKey else { return }
			let connBlind = BeamioChatLocalCrypto.blind(idxKey: idxKey, convKey.lowercased())
			let sid = BeamioChatLocalCrypto.stableId(idxKey: idxKey, sendKey: sendKey)
			guard let plain = try? JSONSerialization.data(withJSONObject: ["tp": tsProv], options: [.sortedKeys]),
			      let enc = try? BeamioChatLocalCrypto.seal(plain, key: dek,
			                                                aad: BeamioChatLocalCrypto.tsProvAAD(connBlind: connBlind, stableId: sid))
			else { return }
			try? db.run("INSERT OR REPLACE INTO tsprov (conv_blind, stable_id, val_enc) VALUES (?, ?, ?)",
			            [.text(connBlind), .text(sid), .blob(enc)])
		}
	}

	/// The stored provenance of a row, if any. The entry is deleted in all cases: the ingest consumes it once.
	func takeTsProv(db: ChatLocalSQLite, connBlind: String, stableId: String, dek: SymmetricKey) throws -> Int? {
		let enc: Data? = try {
			let st = try db.prepare("SELECT val_enc FROM tsprov WHERE conv_blind = ? AND stable_id = ?")
			try st.bind([.text(connBlind), .text(stableId)])
			guard try st.step() else { return nil }
			return st.blob(0)
		}()
		guard let enc else { return nil }
		try db.run("DELETE FROM tsprov WHERE conv_blind = ? AND stable_id = ?", [.text(connBlind), .text(stableId)])
		guard let plain = try? BeamioChatLocalCrypto.open(enc, key: dek,
		                                                  aad: BeamioChatLocalCrypto.tsProvAAD(connBlind: connBlind, stableId: stableId)),
		      let obj = (try? JSONSerialization.jsonObject(with: plain)) as? [String: Any],
		      let tp = (obj["tp"] as? NSNumber)?.intValue
		else { return nil }
		return tp
	}
}
