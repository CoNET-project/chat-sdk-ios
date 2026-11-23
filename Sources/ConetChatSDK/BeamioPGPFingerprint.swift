import CryptoKit
import Foundation

/// The OpenPGP v4 fingerprint of an armored public key, computed here and not by X-19, so a build without the native library can still check what a peer
/// sent (v109 section 119, section 108.7). RFC 4880 section 12.2: SHA-1 over `0x99 || 2-byte big-endian length || the body of the primary public-key
/// packet`; the primary key, not a subkey. Output: 40 lower-case hex characters. A value that is not an armored public key block, whose first packet is not a
/// public-key packet (a private key block is not accepted), that is not version 4, or whose packet is malformed or has an indeterminate length: nil.
enum BeamioPGPFingerprint {
	static func fingerprint(armor: String) -> String? {
		guard let packets = binary(fromArmor: armor), let body = firstPublicKeyBody(packets), body.first == 4, body.count <= 0xFFFF else { return nil }
		var hashed = Data([0x99, UInt8(body.count >> 8), UInt8(body.count & 0xFF)])
		hashed.append(body)
		return Insecure.SHA1.hash(data: hashed).map { String(format: "%02x", $0) }.joined()
	}

	/// The packet bytes of a `-----BEGIN PGP PUBLIC KEY BLOCK-----` armor (headers and the `=` checksum line are skipped).
	private static func binary(fromArmor armor: String) -> Data? {
		let lines = armor.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
		guard let begin = lines.firstIndex(of: "-----BEGIN PGP PUBLIC KEY BLOCK-----"),
		      let end = lines[(begin + 1)...].firstIndex(of: "-----END PGP PUBLIC KEY BLOCK-----")
		else { return nil }
		var index = begin + 1
		// armor headers (`Key: value`) run until the first empty line
		if index < end, lines[index].contains(":") {
			while index < end, !lines[index].isEmpty { index += 1 }
		}
		var text = ""
		for line in lines[index ..< end] where !line.isEmpty && !line.hasPrefix("=") { text += line }
		guard !text.isEmpty, let data = Data(base64Encoded: text) else { return nil }
		return data
	}

	/// The body of the first packet when it is a public-key packet (tag 6), with its old or new format header; nil for any other first packet.
	private static func firstPublicKeyBody(_ data: Data) -> Data? {
		let bytes = [UInt8](data)
		guard bytes.count >= 2, bytes[0] & 0x80 != 0 else { return nil }
		let tag: Int, length: Int, headerSize: Int
		if bytes[0] & 0x40 != 0 { // new format
			tag = Int(bytes[0] & 0x3F)
			let first = Int(bytes[1])
			if first < 192 { length = first; headerSize = 2 }
			else if first < 224 {
				guard bytes.count >= 3 else { return nil }
				length = ((first - 192) << 8) + Int(bytes[2]) + 192; headerSize = 3
			} else if first == 255 {
				guard bytes.count >= 6 else { return nil }
				length = Int(bytes[2]) << 24 | Int(bytes[3]) << 16 | Int(bytes[4]) << 8 | Int(bytes[5]); headerSize = 6
			} else { return nil } // a partial length: not for a key packet
		} else { // old format
			tag = Int((bytes[0] >> 2) & 0x0F)
			switch bytes[0] & 0x03 {
			case 0: length = Int(bytes[1]); headerSize = 2
			case 1:
				guard bytes.count >= 3 else { return nil }
				length = Int(bytes[1]) << 8 | Int(bytes[2]); headerSize = 3
			case 2:
				guard bytes.count >= 5 else { return nil }
				length = Int(bytes[1]) << 24 | Int(bytes[2]) << 16 | Int(bytes[3]) << 8 | Int(bytes[4]); headerSize = 5
			default: return nil // indeterminate length
			}
		}
		guard tag == 6, length > 0, bytes.count >= headerSize + length else { return nil }
		return Data(bytes[headerSize ..< headerSize + length])
	}
}
