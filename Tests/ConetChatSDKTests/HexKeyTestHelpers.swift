import Foundation
@testable import ConetChatSDK

// Test-only helpers. Production code takes private keys as byte arrays only (no hex-key overload exists);
// the test vectors stay hex, so they are parsed here and the bytes are wiped after each use.

/// 32 key bytes from a 64-digit hex string (optional 0x); nil when malformed or out of range.
func parseHexTestKey(_ hex: String) -> [UInt8]? {
	var h = hex
	if h.hasPrefix("0x") || h.hasPrefix("0X") { h.removeFirst(2) }
	guard h.count == 64 else { return nil }
	var out = [UInt8]()
	var i = h.startIndex
	while i < h.endIndex {
		let j = h.index(i, offsetBy: 2)
		guard let b = UInt8(h[i ..< j], radix: 16) else {
			BeamioNativeEthSigner.wipe(&out)
			return nil
		}
		out.append(b)
		i = j
	}
	guard BeamioNativeEthSigner.isValidKey(out) else {
		BeamioNativeEthSigner.wipe(&out)
		return nil
	}
	return out
}

/// EIP-55 address of a hex test key.
func hexKeyAddress(_ hex: String) -> String? {
	guard var key = parseHexTestKey(hex) else { return nil }
	defer { BeamioNativeEthSigner.wipe(&key) }
	return BeamioNativeEthSigner.address(privateKey: key)
}

/// EIP-191 signature of `message` with a hex test key.
func hexKeySignEip191(_ hex: String, message: String) -> String? {
	guard var key = parseHexTestKey(hex) else { return nil }
	defer { BeamioNativeEthSigner.wipe(&key) }
	return BeamioNativeEthSigner.signEip191(privateKey: key, message: message)
}
