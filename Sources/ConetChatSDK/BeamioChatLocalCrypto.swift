import CryptoKit
import Foundation

/// Keys, blind indexes and AEAD for the local chat library (interface spec v1.1: 3, 4, 7.2, 7.3).
///
/// Everything derives from the account master. The master exists only in memory while unlocked;
/// nothing here writes a key to disk or to the Keychain.
enum BeamioChatLocalCrypto {
	static let separator: UInt8 = 0x1f

	/// DEK = HKDF-SHA256(ikm = R_db, salt = "beamio-chat-local-db|salt|v1",
	/// info = "beamio-chat-local-db|v1|" + eoa + "|" + workspace, 32). Never persisted (22.2, 23.2).
	static func dek(localRoot: Data, eoa: String, workspace: String) -> SymmetricKey {
		hkdfSalted(ikm: localRoot, salt: "beamio-chat-local-db|salt|v1",
		           info: "beamio-chat-local-db|v1|" + eoa + "|" + workspace)
	}

	/// R_db = HKDF-SHA256(ikm = P (the 32-byte wallet private key), salt = "beamio-chat-local-root|salt|v1",
	/// info = "beamio-chat-local-root|v1|" + eoa + "|" + workspace). Local root only (22.2, vectors).
	static func localRoot(privateKey: Data, eoa: String, workspace: String) -> Data {
		hkdfSalted(ikm: privateKey, salt: "beamio-chat-local-root|salt|v1",
		           info: "beamio-chat-local-root|v1|" + eoa + "|" + workspace).withUnsafeBytes { Data($0) }
	}

	static func hkdfSalted(ikm: Data, salt: String, info: String) -> SymmetricKey {
		HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data(salt.utf8),
		                       info: Data(info.utf8), outputByteCount: 32)
	}

	/// K_id = HKDF-SHA256(ikm = R_db, salt = "", info = "chat-local-id-v1", 32). Keys the derived sendKey (4.2).
	/// Derived from the local root (r1, 7.2): the protocol root is not used by the local library.
	static func idKey(localRoot: Data) -> SymmetricKey {
		SymmetricKey(data: BeamioConetChatHistoryStore.hkdf(master: localRoot, info: "chat-local-id-v1", length: 32))
	}

	/// K_idx = HKDF-SHA256(ikm = R_db, salt = "", info = "chat-local-idx-v1", 32). Keys stable_id and the blind
	/// indexes (4.3, 7.1). Derived from the local root, not from the protocol master (23.1).
	static func idxKey(localRoot: Data) -> SymmetricKey {
		SymmetricKey(data: BeamioConetChatHistoryStore.hkdf(master: localRoot, info: "chat-local-idx-v1", length: 32))
	}

	/// Key-check value stored in `meta`, used to detect a DEK change when the database is opened.
	static func kcv(dek: SymmetricKey) -> String {
		hex(Data(HMAC<SHA256>.authenticationCode(for: Data("kcv".utf8), using: dek)))
	}

	/// Random 16-byte database epoch, hex (7.1 meta.dbEpoch).
	static func newEpoch() -> String {
		hex(SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) })
	}

	/// The RFC 4122 UUID shape. Legacy random sendIds have it; the PWA `ms-random` form does not (4.1).
	static func isRandomUUID(_ s: String) -> Bool {
		s.range(of: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
		        options: [.regularExpression, .caseInsensitive]) != nil
	}

	/// sendKey (4.1): a non-empty, non-UUID sendId is the sendKey itself. Otherwise
	/// "x" + base64url(HMAC(K_id, peer ‖ 0x1f ‖ dir ‖ 0x1f ‖ decimal(ts) ‖ 0x1f ‖ SHA256(body))).
	static func sendKeyDerived(idKey: SymmetricKey, peer: String, dir: String, ts: Int64, body: String) -> String {
		var msg = Data(peer.utf8)
		msg.append(separator)
		msg.append(contentsOf: dir.utf8)
		msg.append(separator)
		msg.append(contentsOf: String(ts).utf8)
		msg.append(separator)
		msg.append(contentsOf: Data(SHA256.hash(data: Data(body.utf8))))
		return "x" + base64Url(Data(HMAC<SHA256>.authenticationCode(for: msg, using: idKey)))
	}

	/// stable_id (4.3) = base64url(HMAC-SHA256(K_idx, sendKey)), 43 ASCII characters.
	static func stableId(idxKey: SymmetricKey, sendKey: String) -> String {
		base64Url(Data(HMAC<SHA256>.authenticationCode(for: Data(sendKey.utf8), using: idxKey)))
	}

	/// Blind index (7.1): base64url(HMAC-SHA256(K_idx, value)) for convKey and cid.
	static func blind(idxKey: SymmetricKey, _ value: String) -> String {
		base64Url(Data(HMAC<SHA256>.authenticationCode(for: Data(value.utf8), using: idxKey)))
	}

	/// AAD for body_enc: conv_blind ‖ 0x1f ‖ stable_id ‖ 0x1f ‖ revision (7.2).
	static func bodyAAD(connBlind: String, stableId: String, revision: Int64) -> Data {
		join([connBlind, stableId, String(revision)])
	}

	/// AAD for meta_enc: conv_blind ‖ 0x1f ‖ stable_id (7.2).
	static func metaAAD(connBlind: String, stableId: String) -> Data {
		join([connBlind, stableId])
	}

	/// AAD for val_enc: conv_blind ‖ 0x1f ‖ stable_id ‖ 0x1f ‖ layout key (7.2).
	static func layoutAAD(connBlind: String, stableId: String, layoutKey: String) -> Data {
		join([connBlind, stableId, layoutKey])
	}

	private static func join(_ parts: [String]) -> Data {
		var d = Data()
		for (i, p) in parts.enumerated() {
			if i > 0 { d.append(separator) }
			d.append(contentsOf: p.utf8)
		}
		return d
	}

	/// Returns nonce(12) ‖ ciphertext ‖ tag (AES-GCM `combined`, 7.2).
	static func seal(_ plain: Data, key: SymmetricKey, aad: Data) throws -> Data {
		let box = try AES.GCM.seal(plain, using: key, authenticating: aad)
		guard let combined = box.combined else { throw BeamioChatLocalError.crypto }
		return combined
	}

	static func open(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
		let box = try AES.GCM.SealedBox(combined: combined)
		return try AES.GCM.open(box, using: key, authenticating: aad)
	}

	static func base64Url(_ data: Data) -> String {
		data.base64EncodedString()
			.replacingOccurrences(of: "+", with: "-")
			.replacingOccurrences(of: "/", with: "_")
			.replacingOccurrences(of: "=", with: "")
	}

	/// 32-byte hex (optionally 0x-prefixed) to bytes; nil when malformed.
	static func bytes(fromHex raw: String) -> Data? {
		var h = raw.lowercased()
		if h.hasPrefix("0x") { h.removeFirst(2) }
		guard h.count == 64 else { return nil }
		var out = Data()
		var idx = h.startIndex
		while idx < h.endIndex {
			let next = h.index(idx, offsetBy: 2)
			guard let b = UInt8(h[idx..<next], radix: 16) else { return nil }
			out.append(b)
			idx = next
		}
		return out
	}

	static func hex(_ data: Data) -> String {
		data.map { String(format: "%02x", $0) }.joined()
	}
}
