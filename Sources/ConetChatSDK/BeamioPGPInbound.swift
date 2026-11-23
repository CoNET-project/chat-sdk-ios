import Foundation

/// `pgpDecryptInbound`. The native decrypt of a call offer or any inbound Chat line,
/// with the account's PGP key. The gate (G0, G1) runs before this, in the module. Here: the order of steps 1 to 8,
/// and the answer. Nothing is cached, stored or logged; only the command name and the result code leave this file.
enum BeamioPGPInbound {
	/// The largest armored message.
	static let maxArmorBytes = 65_536

	/// Fields that may never reach the bridge. A hit answers `key_over_bridge_refused`; only the name is logged.
	static let forbiddenFields: Set<String> = [
		"privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
	]
	static let allowedFields: Set<String> = ["type", "reqId", "accountKey", "armoredMessage"]

	/// Inputs the command needs from the native side. Injected so the order of checks can be tested without a key.
	struct Context {
		/// The account the device record names, with `:default` (D5), or nil when there is no record.
		var unlockedAccountKey: String?
		/// The account is passcode-locked.
		var locked: Bool
		/// The account's PGP subkey key ID (uppercase hex), when the account has a PGP record.
		var subkeyKeyID: String?
		/// The X-19 framework is linked into this build (`BeamioPGPNative.linked`).
		var nativeAvailable: Bool
		/// Native decrypt: the message (UTF-8 armor) to the plaintext bytes, or a failure.
		var decrypt: (Data) -> Result<Data, BeamioNativeWallet.Failure>
	}

	/// The ack answer: a result dictionary, or an error code. Never both, never key material.
	enum Answer: Equatable {
		case ok(plaintext: String, signal: [String: String]?, rejectReason: String?)
		case error(String)
	}

	static func run(_ body: [String: Any], context: Context) -> Answer {
		// (forbidden fields first, then unknown fields). Refused before the armor is read.
		for key in body.keys.sorted() where forbiddenFields.contains(key) {
			NSLog("[BeamioPGPInbound] key_over_bridge_refused field=%@", key)
			return .error("key_over_bridge_refused")
		}
		for key in body.keys where !allowedFields.contains(key) {
			return .error("bad_request")
		}
		guard body["type"] as? String == "pgpDecryptInbound",
		      let accountKey = body["accountKey"] as? String,
		      let armored = body["armoredMessage"] as? String
		else { return .error("bad_request") }
		// G2 and locked: answered before the payload is read.
		// Test seam only: production passes `locked: false`. The branch is not compiled into a release or store build.
		#if BEAMIO_TEST_HOOKS
		if context.locked { return .error("locked") }
		#endif
		// Step 1: length, before any armor parse.
		if armored.utf8.count > maxArmorBytes { return .error("payload_too_large") }
		// Step 2: the account (T-54).
		guard let unlocked = context.unlockedAccountKey, accountKey.lowercased() == unlocked.lowercased() else {
			return .error("account_mismatch")
		}
		// Step 3: an OpenPGP encrypted message, not a signature, a literal, or a key block.
		guard let scan = scan(armor: armored) else { return .error("not_openpgp_message") }
		// The native OpenPGP library is needed from here on (key identity and decrypt). Without it: not_supported.
		guard context.nativeAvailable else { return .error("not_supported") }
		// Step 4: a recipient key ID equal to the account's PGP subkey (anonymous recipients do not count).
		guard let subkey = context.subkeyKeyID?.uppercased(), !subkey.isEmpty, scan.recipientKeyIDs.contains(subkey) else {
			return .error("recipient_mismatch")
		}
		// Step 5: decrypt with the account key (native).
		let plain: Data
		switch context.decrypt(Data(armored.utf8)) {
		case .success(let data): plain = data
		case .failure(let failure): return .error(code(for: failure))
		}
		// Step 6: the literal rules are applied natively (X-19 v3, DecryptArmoredText): CRLF to LF for text literals, and
		// valid UTF-8 for binary ones. A check here is kept as a second line of defence.
		guard let text = String(data: plain, encoding: .utf8) else { return .error("plaintext_not_utf8") }
		// Step 7: classify, with the shared vectors' rules (BeamioConetChatCallSignal).
		guard let hit = BeamioConetChatCallSignal.classify(text) else {
			return .ok(plaintext: text, signal: nil, rejectReason: nil)
		}
		var signal: [String: String] = ["kind": hit.kind, "type": hit.type, "callId": hit.callId, "sessionId": hit.sessionId]
		if let reason = hit.rejectReason { signal["rejectReason"] = reason }
		return .ok(plaintext: text, signal: signal, rejectReason: hit.rejectReason)
	}

	/// The native failure as a code. Anything unknown is a decrypt failure, never a plaintext.
	static func code(for failure: BeamioNativeWallet.Failure) -> String {
		switch failure {
		case .locked: return "locked"
		case .walletKeyMissing: return "no_key"
		case .pending: return "not_supported"
		case .storageUnreadable: return "not_ready"
		case .rejected(let reason):
			switch reason {
			case "no_pgp_key": return "pgp_source_unavailable"
			case "plaintext_not_utf8": return "plaintext_not_utf8"
			default: return "decrypt_failed"
			}
		case .signFailed: return "decrypt_failed"
		}
	}

	// MARK: - Packet scan (step 3 and step 4)

	struct Scan: Equatable {
		/// Key IDs of the public-key-encrypted session keys (uppercase hex, 16 digits). Anonymous ones are not listed.
		var recipientKeyIDs: [String]
	}

	/// Parses the armor and the packet headers. Returns nil unless the message holds an encrypted-data packet (SEIPD, AEAD
	/// or SED) and a session-key packet (PKESK or SKESK), and carries no signature-only or key packets.
	static func scan(armor: String) -> Scan? {
		guard let bytes = dearmor(armor), let packets = packets(in: bytes) else { return nil }
		let tags = Set(packets.map { $0.tag })
		if tags.contains(5) || tags.contains(7) { return nil }
		let hasSession = tags.contains(1) || tags.contains(3)
		let hasData = tags.contains(18) || tags.contains(20) || tags.contains(9)
		guard hasSession, hasData else { return nil }
		var ids: [String] = []
		for p in packets where p.tag == 1 {
			// PKESK v3: version (1), key ID (8), algorithm (1), session key. The zero key ID is anonymous.
			guard p.body.count >= 10, p.body[p.body.startIndex] == 3 else { continue }
			let id = p.body[(p.body.startIndex + 1) ..< (p.body.startIndex + 9)].map { String(format: "%02X", $0) }.joined()
			if id != "0000000000000000" { ids.append(id) }
		}
		return Scan(recipientKeyIDs: ids)
	}

	/// The base64 body between the BEGIN and END lines, with armor headers and the CRC line removed. Nil if malformed.
	static func dearmor(_ armor: String) -> Data? {
		let lines = armor.replacingOccurrences(of: "\r\n", with: "\n").components(separatedBy: "\n")
		guard let begin = lines.firstIndex(of: "-----BEGIN PGP MESSAGE-----"),
		      let end = lines.firstIndex(of: "-----END PGP MESSAGE-----"), end > begin + 1
		else { return nil }
		var i = begin + 1
		// Armor headers (Key: value) end at the first blank line. A message without headers has no blank line.
		if lines[i].trimmingCharacters(in: .whitespaces).isEmpty {
			i += 1
		} else if lines[i].contains(":") {
			while i < end, !lines[i].trimmingCharacters(in: .whitespaces).isEmpty { i += 1 }
			i += 1
		}
		var b64 = ""
		while i < end, !lines[i].hasPrefix("=") {
			b64 += lines[i].trimmingCharacters(in: .whitespaces)
			i += 1
		}
		guard !b64.isEmpty, let data = Data(base64Encoded: b64) else { return nil }
		return data
	}

	struct Packet {
		var tag: Int
		var body: Data
	}

	/// OpenPGP packet headers (RFC 4880 and RFC 9580): new and old formats, partial body lengths. Nil on any bound error.
	static func packets(in data: Data) -> [Packet]? {
		let bytes = [UInt8](data)
		var out: [Packet] = []
		var pos = 0
		func byte() -> UInt8? {
			guard pos < bytes.count else { return nil }
			defer { pos += 1 }
			return bytes[pos]
		}
		func be(_ n: Int) -> Int? {
			var v = 0
			for _ in 0 ..< n { guard let b = byte() else { return nil }; v = (v << 8) | Int(b) }
			return v
		}
		while pos < bytes.count {
			guard let head = byte(), head & 0x80 != 0 else { return nil }
			var tag: Int
			var body = Data()
			if head & 0x40 != 0 {
				tag = Int(head & 0x3F)
				guard let l1 = byte() else { return nil }
				switch l1 {
				case 0 ..< 192:
					guard let chunk = take(Int(l1), bytes: bytes, pos: &pos) else { return nil }
					body.append(chunk)
				case 192 ..< 224:
					guard let second = byte() else { return nil }
					let len = ((Int(l1) - 192) << 8) + Int(second) + 192
					guard let chunk = take(len, bytes: bytes, pos: &pos) else { return nil }
					body.append(chunk)
				case 255:
					guard let len = be(4), let chunk = take(len, bytes: bytes, pos: &pos) else { return nil }
					body.append(chunk)
				default:
					// Partial body length: 2^k octets, then another length header, until a final one.
					var partial = 1 << Int(l1 & 0x1F)
					while true {
						guard let chunk = take(partial, bytes: bytes, pos: &pos) else { return nil }
						body.append(chunk)
						guard let next = byte() else { return nil }
						if next < 224 || next == 255 {
							// Final chunk: `next` is the first octet of the final length.
							let len: Int
							if next < 192 {
								len = Int(next)
							} else if next < 224 {
								guard let second = byte() else { return nil }
								len = ((Int(next) - 192) << 8) + Int(second) + 192
							} else {
								guard let four = be(4) else { return nil }
								len = four
							}
							guard let chunk2 = take(len, bytes: bytes, pos: &pos) else { return nil }
							body.append(chunk2)
							break
						}
						partial = 1 << Int(next & 0x1F)
					}
				}
			} else {
				tag = Int((head >> 2) & 0x0F)
				switch head & 0x03 {
				case 0:
					guard let len = be(1), let chunk = take(len, bytes: bytes, pos: &pos) else { return nil }
					body.append(chunk)
				case 1:
					guard let len = be(2), let chunk = take(len, bytes: bytes, pos: &pos) else { return nil }
					body.append(chunk)
				case 2:
					guard let len = be(4), let chunk = take(len, bytes: bytes, pos: &pos) else { return nil }
					body.append(chunk)
				default:
					// Indeterminate length: the rest of the stream.
					body.append(contentsOf: bytes[pos...])
					pos = bytes.count
				}
			}
			out.append(Packet(tag: tag, body: body))
		}
		return out.isEmpty ? nil : out
	}

	private static func take(_ n: Int, bytes: [UInt8], pos: inout Int) -> Data? {
		guard n >= 0, pos + n <= bytes.count else { return nil }
		defer { pos += n }
		return Data(bytes[pos ..< pos + n])
	}
}
