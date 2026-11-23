import Foundation

/// EIP-712 digest for the one whitelisted typed struct, SetPointer.
/// Nothing else is encodable: the type strings, the domain name and version are constants here, and the caller
/// supplies only values. Byte-for-byte with ethers.js `TypedDataEncoder.hash` (vectors in BeamioNativeWalletTests).
enum BeamioNativeEip712 {
	static let domainName = "ChatIndexRegistry"
	static let domainVersion = "1"
	static let domainTypeString = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
	static let setPointerTypeString = "SetPointer(address owner,bytes32 indexHash,uint64 ts,uint64 seq,uint256 nonce)"

	/// keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct(SetPointer)).
	static func setPointerDigest(chainId: Int, verifyingContract: [UInt8], owner: [UInt8], indexHash: [UInt8],
	                             ts: UInt64, seq: UInt64, nonce: [UInt8]) -> [UInt8] {
		let domainSeparator = keccak(
			keccak(domainTypeString) + keccak(domainName) + keccak(domainVersion)
				+ word(UInt64(chainId)) + addressWord(verifyingContract)
		)
		let structHash = keccak(
			keccak(setPointerTypeString) + addressWord(owner) + indexHash + word(ts) + word(seq) + nonce
		)
		return keccak([0x19, 0x01] + domainSeparator + structHash)
	}

	/// 32-byte big-endian encoding of a decimal integer in [0, 2^256). nil when malformed or too large.
	static func uint256(decimal s: String) -> [UInt8]? {
		guard !s.isEmpty, s.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
		var out = [UInt8](repeating: 0, count: 32)
		for digit in s.utf8 {
			var carry = UInt16(digit - 48)
			for i in stride(from: 31, through: 0, by: -1) {
				let v = UInt16(out[i]) * 10 + carry
				out[i] = UInt8(v & 0xff)
				carry = v >> 8
			}
			if carry != 0 { return nil }
		}
		return out
	}

	/// Exactly `count` bytes from a hex string with an optional 0x prefix.
	static func bytes(hex raw: String, count: Int) -> [UInt8]? {
		var h = raw
		if h.hasPrefix("0x") || h.hasPrefix("0X") { h.removeFirst(2) }
		guard h.utf8.count == count * 2 else { return nil }
		var out = [UInt8]()
		out.reserveCapacity(count)
		var i = h.startIndex
		while i < h.endIndex {
			let j = h.index(i, offsetBy: 2)
			guard let b = UInt8(h[i ..< j], radix: 16) else { return nil }
			out.append(b)
			i = j
		}
		return out
	}

	private static func keccak(_ s: String) -> [UInt8] { BeamioNativeEthSigner.keccak256(Array(s.utf8)) }
	private static func keccak(_ b: [UInt8]) -> [UInt8] { BeamioNativeEthSigner.keccak256(b) }

	private static func word(_ v: UInt64) -> [UInt8] {
		var out = [UInt8](repeating: 0, count: 24)
		for shift in stride(from: 56, through: 0, by: -8) { out.append(UInt8((v >> UInt64(shift)) & 0xff)) }
		return out
	}

	private static func addressWord(_ a: [UInt8]) -> [UInt8] { [UInt8](repeating: 0, count: 12) + a }
}
