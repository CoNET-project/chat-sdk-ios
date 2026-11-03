import Foundation
import Security
import libsecp256k1

/// Native Ethereum signing for the voice v3 channel texts: EIP-191 personal_sign
/// and wallet addresses, byte-for-byte what ethers.js `Wallet.signMessage` /
/// `Wallet.address` give (RFC 6979 nonce, low-s, `v` = 27/28, EIP-55 address).
/// secp256k1 is bitcoin-core libsecp256k1 (swift-secp256k1 0.24.0, C product only);
/// Keccak-256 is the SDK's existing native one. Keys stay where they are: callers pass the hex they hold.
public enum BeamioNativeEthSigner {
	private static let context: OpaquePointer? = {
		// SECP256K1_CONTEXT_NONE = 1 (the macro does not import into Swift).
		guard let ctx = secp256k1_context_create(UInt32(1)) else { return nil }
		var seed = [UInt8](repeating: 0, count: 32)
		if SecRandomCopyBytes(kSecRandomDefault, 32, &seed) == errSecSuccess {
			_ = secp256k1_context_randomize(ctx, seed)  // side-channel blinding only
		}
		return ctx
	}()

	/// EIP-55 checksummed address of a 32-byte private key (hex, optional 0x).
	public static func address(privateKeyHex: String) -> String? {
		guard let ctx = context, let key = parseKey(privateKeyHex) else { return nil }
		var pubkey = secp256k1_pubkey()
		guard secp256k1_ec_pubkey_create(ctx, &pubkey, key) == 1 else { return nil }
		var out = [UInt8](repeating: 0, count: 65)
		var len = 65
		// SECP256K1_EC_UNCOMPRESSED = 2.
		guard secp256k1_ec_pubkey_serialize(ctx, &out, &len, &pubkey, UInt32(2)) == 1, len == 65 else { return nil }
		let raw = Array(keccak256(Array(out[1...]))[12...])
		return checksum(raw)
	}

	/// `0x` + r ‖ s ‖ v (65 bytes, v = 27/28) over EIP-191 of `message` (UTF-8).
	public static func signEip191(privateKeyHex: String, message: String) -> String? {
		guard let ctx = context, let key = parseKey(privateKeyHex) else { return nil }
		let bytes = Array(message.utf8)
		let prefix = Array("\u{19}Ethereum Signed Message:\n\(bytes.count)".utf8)
		let hash = keccak256(prefix + bytes)
		var sig = secp256k1_ecdsa_recoverable_signature()
		// nil nonce function = RFC 6979 (as ethers / noble-secp256k1).
		guard secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, key, nil, nil) == 1 else { return nil }
		var compact = [UInt8](repeating: 0, count: 64)
		var recId: Int32 = 0
		guard secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &compact, &recId, &sig) == 1,
		      (0 ... 1).contains(recId)
		else { return nil }
		return "0x" + hex(compact + [UInt8(27 + recId)])
	}

	/// Keccak-256 via the SDK's native implementation (BeamioConetChatHistoryStore.swift).
	public static func keccak256(_ data: [UInt8]) -> [UInt8] { Array(Keccak256.hash(Data(data))) }

	private static func parseKey(_ hexKey: String) -> [UInt8]? {
		var h = hexKey
		if h.hasPrefix("0x") || h.hasPrefix("0X") { h.removeFirst(2) }
		guard h.count == 64 else { return nil }
		var out = [UInt8]()
		out.reserveCapacity(32)
		var i = h.startIndex
		while i < h.endIndex {
			let j = h.index(i, offsetBy: 2)
			guard let b = UInt8(h[i ..< j], radix: 16) else { return nil }
			out.append(b)
			i = j
		}
		guard let ctx = context, secp256k1_ec_seckey_verify(ctx, out) == 1 else { return nil }
		return out
	}

	private static func checksum(_ raw: [UInt8]) -> String {
		let lower = hex(raw)
		let h = hex(keccak256(Array(lower.utf8)))
		var s = "0x"
		for (c, d) in zip(lower, h) {
			if c.isLetter, let v = Int(String(d), radix: 16), v >= 8 { s.append(Character(c.uppercased())) } else { s.append(c) }
		}
		return s
	}

	private static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
}
