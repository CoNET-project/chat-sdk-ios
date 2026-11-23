import Foundation
import Security
import libsecp256k1

/// Native Ethereum signing: EIP-191 personal_sign, digest signing for EIP-712, and wallet addresses.
/// Byte-for-byte what ethers.js `Wallet.signMessage` / `Wallet.signTypedData` / `Wallet.address` give
/// (RFC 6979 nonce, low-s, `v` = 27/28, EIP-55 address).
/// secp256k1 is bitcoin-core libsecp256k1 (swift-secp256k1 0.24.0, C product only);
/// Keccak-256 is the SDK's existing native one.
///
/// Keys: byte arrays only. There is no hex-key overload; a caller that
/// holds hex must parse it to bytes itself and wipe the bytes after use.
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

	// MARK: - Byte-array keys (preferred)

	/// EIP-55 checksummed address of a 32-byte private key.
	public static func address(privateKey: [UInt8]) -> String? {
		guard let ctx = context, isValidKey(privateKey) else { return nil }
		var pubkey = secp256k1_pubkey()
		guard secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey) == 1 else { return nil }
		var out = [UInt8](repeating: 0, count: 65)
		var len = 65
		// SECP256K1_EC_UNCOMPRESSED = 2.
		guard secp256k1_ec_pubkey_serialize(ctx, &out, &len, &pubkey, UInt32(2)) == 1, len == 65 else { return nil }
		let raw = Array(keccak256(Array(out[1...]))[12...])
		return checksum(raw)
	}

	/// `0x` + r ‖ s ‖ v (65 bytes, v = 27/28) over EIP-191 of `message` (UTF-8).
	public static func signEip191(privateKey: [UInt8], message: String) -> String? {
		let bytes = Array(message.utf8)
		let prefix = Array("\u{19}Ethereum Signed Message:\n\(bytes.count)".utf8)
		return signDigest(privateKey: privateKey, digest: keccak256(prefix + bytes))
	}

	/// Compatibility with the 0.1.8 signature (2026-11-17, B'): the key given as 0x-hex text. It decodes to the same 32 bytes and calls the byte API,
	/// so the algorithm is the same (EIP-191 prefix, keccak-256, RFC 6979 recoverable signature, v = 27 + recId). nil when the text is not a valid key.
	public static func signEip191(privateKeyHex: String, message: String) -> String? {
		guard let key = keyBytes(fromHex: privateKeyHex) else { return nil }
		return signEip191(privateKey: key, message: message)
	}

	/// The 32 key bytes of a 0x-prefixed or bare 64-digit hex key. nil when the length or a digit is wrong or the key is not valid.
	public static func keyBytes(fromHex hexKey: String) -> [UInt8]? {
		var h = hexKey
		if h.hasPrefix("0x") || h.hasPrefix("0X") { h.removeFirst(2) }
		guard h.count == 64, h.allSatisfy({ $0.isHexDigit }) else { return nil }
		var out = [UInt8]()
		out.reserveCapacity(32)
		var i = h.startIndex
		while i < h.endIndex {
			let j = h.index(i, offsetBy: 2)
			guard let b = UInt8(h[i..<j], radix: 16) else { return nil }
			out.append(b)
			i = j
		}
		return isValidKey(out) ? out : nil
	}

	/// `0x` + r ‖ s ‖ v over a 32-byte digest (RFC 6979, low-s, v = 27/28). Used for EIP-191 and EIP-712.
	public static func signDigest(privateKey: [UInt8], digest: [UInt8]) -> String? {
		guard let ctx = context, digest.count == 32, isValidKey(privateKey) else { return nil }
		var sig = secp256k1_ecdsa_recoverable_signature()
		// nil nonce function = RFC 6979 (as ethers / noble-secp256k1).
		guard secp256k1_ecdsa_sign_recoverable(ctx, &sig, digest, privateKey, nil, nil) == 1 else { return nil }
		var compact = [UInt8](repeating: 0, count: 64)
		var recId: Int32 = 0
		guard secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, &compact, &recId, &sig) == 1,
		      (0 ... 1).contains(recId)
		else { return nil }
		return "0x" + hex(compact + [UInt8(27 + recId)])
	}

	/// Keccak-256 via the SDK's native implementation (BeamioConetChatHistoryStore.swift).
	public static func keccak256(_ data: [UInt8]) -> [UInt8] { Array(Keccak256.hash(Data(data))) }

	/// Overwrites the bytes with zeros (memset_s, not optimised away).
	public static func wipe(_ bytes: inout [UInt8]) {
		#if BEAMIO_TEST_HOOKS
		let before = bytes.contains { $0 != 0 }
		#endif
		bytes.withUnsafeMutableBytes { buf in
			guard let base = buf.baseAddress, buf.count > 0 else { return }
			_ = memset_s(base, buf.count, 0, buf.count)
		}
		#if BEAMIO_TEST_HOOKS
		BeamioWipeProbe.record(count: bytes.count, hadNonZero: before, allZero: !bytes.contains { $0 != 0 },
		                       address: bytes.withUnsafeBufferPointer { $0.baseAddress.map { UInt(bitPattern: $0) } })
		#endif
	}

	/// True for a 32-byte secp256k1 private key in range.
	public static func isValidKey(_ key: [UInt8]) -> Bool {
		guard key.count == 32, let ctx = context else { return false }
		return secp256k1_ec_seckey_verify(ctx, key) == 1
	}

	/// The 33-byte compressed public key of a private key. nil for an invalid key.
	static func compressedPublicKey(privateKey: [UInt8]) -> [UInt8]? {
		guard let ctx = context, isValidKey(privateKey) else { return nil }
		var pubkey = secp256k1_pubkey()
		guard secp256k1_ec_pubkey_create(ctx, &pubkey, privateKey) == 1 else { return nil }
		var out = [UInt8](repeating: 0, count: 33)
		var len = 33
		// SECP256K1_EC_COMPRESSED = (1 << 1) | (1 << 8) = 258.
		guard secp256k1_ec_pubkey_serialize(ctx, &out, &len, &pubkey, UInt32(258)) == 1, len == 33 else { return nil }
		return out
	}

	/// In-place `key = key + tweak mod n` (BIP-32 child key). False when the result is invalid (tweak ≥ n, or a zero sum).
	static func tweakAddPrivateKey(_ key: inout [UInt8], tweak: [UInt8]) -> Bool {
		guard let ctx = context, key.count == 32, tweak.count == 32 else { return false }
		return secp256k1_ec_seckey_tweak_add(ctx, &key, tweak) == 1
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

#if BEAMIO_TEST_HOOKS
extension BeamioNativeEthSigner {
	/// Test hook only: the lowercase address that an EIP-191 signature (`0x` + r + s + v, v = 27 or 28) of `message` recovers to, or nil.
	/// Used to check the W7 signature of `ephemeralSign` against its `temp`. Public material only.
	static func recoverEip191AddressForTests(message: String, signature: String) -> String? {
		guard let ctx = context, signature.hasPrefix("0x"), signature.count == 132 else { return nil }
		var bytes: [UInt8] = []
		var index = signature.index(signature.startIndex, offsetBy: 2)
		while index < signature.endIndex {
			let next = signature.index(index, offsetBy: 2)
			guard let byte = UInt8(signature[index..<next], radix: 16) else { return nil }
			bytes.append(byte)
			index = next
		}
		guard bytes.count == 65, bytes[64] == 27 || bytes[64] == 28 else { return nil }
		let body = Array(message.utf8)
		let digest = keccak256(Array("\u{19}Ethereum Signed Message:\n\(body.count)".utf8) + body)
		var recoverable = secp256k1_ecdsa_recoverable_signature()
		guard secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recoverable, Array(bytes[0..<64]), Int32(bytes[64]) - 27) == 1 else {
			return nil
		}
		var pubkey = secp256k1_pubkey()
		guard secp256k1_ecdsa_recover(ctx, &pubkey, &recoverable, digest) == 1 else { return nil }
		var out = [UInt8](repeating: 0, count: 65)
		var len = 65
		guard secp256k1_ec_pubkey_serialize(ctx, &out, &len, &pubkey, UInt32(2)) == 1, len == 65 else { return nil }
		return "0x" + hex(Array(keccak256(Array(out[1...]))[12...]))
	}
}
#endif
