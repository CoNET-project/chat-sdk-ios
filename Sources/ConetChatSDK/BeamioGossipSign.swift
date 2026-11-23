import Foundation

/// C2 `gossipSign`: the native EIP-191 signature for a caller's string, with the gossip shape
/// checks of and the cross-purpose refusal of
///
/// The signed bytes are the caller's UTF-8 exactly: no domain prefix, no re-serialisation, no trim, no normalisation.
/// A refusal carries only its vector code (`gossip-sign-vectors.v1.json`), never the text.
public enum BeamioGossipSign {
	static let maxBytes = 2048
	static let ackCommand = "gossip_delivery_ack"
	static let allowedTopKeys: Set<String> = ["command", "walletAddress", "armorHash", "timestamp", "sendId"]
	/// The kinds this function signs. The other W5 kinds (selfAuth, pointerEip712, chatRouteRegister, voice) are not
	/// implemented here (T-53) and are refused as `kind`.
	static let signableKinds: Set<String> = ["gossip", "envelope", "group"]

	/// The refusals of `gossipSign`. The raw value is the vector code, returned to the page as the ack error.
	public enum GossipRefusal: String, Error, Equatable {
		case kind, noKey = "no_key", tooLong = "too_long", notJSON = "not_json", duplicateKey = "duplicate_key"
		case unknownKey = "unknown_key", command, walletMismatch = "wallet_mismatch", armorHash = "armor_hash"
		case timestamp, sendId = "send_id", crossPurpose = "cross_purpose", signFailed = "sign_failed"
	}

	/// Signs `message` for `eoa` (the open account). Returns the `0x` signature, or the refusal.
	public static func sign(kind: String, message: String, eoa: String) -> Result<String, GossipRefusal> {
		switch signCode(kind: kind, message: message, eoa: eoa) {
		case .signed(let sig): return .success(sig)
		case .refused(let code): return .failure(GossipRefusal(rawValue: code) ?? .signFailed)
		}
	}

	enum SignOutcome {
		case signed(String)
		case refused(String)
	}

	static func signCode(kind: String, message: String, eoa rawEoa: String) -> SignOutcome {
		guard signableKinds.contains(kind) else { return .refused("kind") }
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty, BeamioNativeWallet.hasKey(eoa: eoa) else { return .refused("no_key") }
		if kind == "gossip" {
			if let refusal = gossipShapeRefusal(message, eoa: eoa) { return .refused(refusal) }
		} else if isAckShape(message) {
			// An envelope or group must not sign the shape of a mailbox ack: the signature would replay as one.
			return .refused("cross_purpose")
		}
		switch BeamioNativeWallet.signEip191(eoa: eoa, message: message) {
		case .success(let sig): return .signed(sig)
		case .failure: return .refused("sign_failed")
		}
	}

	/// The first refusal of the gossip shape, in the order of the vectors. nil when the shape is accepted.
	static func gossipShapeRefusal(_ message: String, eoa: String) -> String? {
		guard message.utf8.count <= maxBytes else { return "too_long" }
		let root: BeamioStrictJSON.Value
		switch BeamioStrictJSON.parse(message) {
		case .success(let v): root = v
		case .failure(.duplicateKey): return "duplicate_key"
		case .failure(.invalid): return "not_json"
		}
		guard case .object(let fields) = root else { return "not_json" }
		if fields.contains(where: { !allowedTopKeys.contains($0.key) }) { return "unknown_key" }
		var dict: [String: BeamioStrictJSON.Value] = [:]
		for field in fields { dict[field.key] = field.value }

		guard case .string(let command)? = dict["command"], command == ackCommand else { return "command" }
		guard case .string(let wallet)? = dict["walletAddress"], wallet.lowercased() == eoa else { return "wallet_mismatch" }
		guard case .string(let armor)? = dict["armorHash"], isLowerHex32Bytes(armor) else { return "armor_hash" }
		guard case .number(let raw)? = dict["timestamp"], let t = Int(raw), (1_000_000_000 ... 9_999_999_999).contains(t)
		else { return "timestamp" }
		if let sendId = dict["sendId"] {
			guard case .string(let id) = sendId, !id.isEmpty else { return "send_id" }
		}
		return nil
	}

	/// True when `message` is a JSON object whose `command` is the mailbox ack command (any other shape is not an ack).
	static func isAckShape(_ message: String) -> Bool {
		guard case .success(.object(let fields)) = BeamioStrictJSON.parse(message) else { return false }
		for field in fields where field.key == "command" {
			if case .string(let c) = field.value { return c == ackCommand }
			return false
		}
		return false
	}

	/// `0x` followed by exactly 64 lowercase hex digits.
	static func isLowerHex32Bytes(_ text: String) -> Bool {
		let scalars = Array(text.unicodeScalars).map { $0.value }
		guard scalars.count == 66, scalars[0] == 0x30, scalars[1] == 0x78 else { return false }
		return scalars[2...].allSatisfy { (0x30 ... 0x39).contains($0) || (0x61 ... 0x66).contains($0) }
	}
}

/// A strict JSON reader for the gossip shape: the whole text must be one value, objects must not repeat a key (compared
/// by Unicode scalar, not by canonical equivalence), numbers keep their literal text so an integer can be told apart.
enum BeamioStrictJSON {
	indirect enum Value {
		case object([(key: String, value: Value)])
		case array([Value])
		case string(String)
		case number(String)
		case bool(Bool)
		case null
	}

	enum Failure: Error, Equatable {
		case invalid
		case duplicateKey
	}

	static func parse(_ text: String) -> Result<Value, Failure> {
		var parser = Parser(text)
		do {
			return .success(try parser.document())
		} catch let failure as Failure {
			return .failure(failure)
		} catch {
			return .failure(.invalid)
		}
	}

	private struct Parser {
		let s: [UInt32]
		var i = 0

		init(_ text: String) { s = text.unicodeScalars.map { $0.value } }

		mutating func document() throws -> Value {
			skipSpace()
			let v = try value(depth: 0)
			skipSpace()
			guard i == s.count else { throw Failure.invalid }
			return v
		}

		mutating func skipSpace() {
			while i < s.count, s[i] == 0x20 || s[i] == 0x09 || s[i] == 0x0A || s[i] == 0x0D { i += 1 }
		}

		mutating func value(depth: Int) throws -> Value {
			guard depth <= 64, i < s.count else { throw Failure.invalid }
			switch s[i] {
			case 0x7B: return try object(depth: depth + 1)
			case 0x5B: return try array(depth: depth + 1)
			case 0x22: return .string(try string())
			case 0x74: try literal("true"); return .bool(true)
			case 0x66: try literal("false"); return .bool(false)
			case 0x6E: try literal("null"); return .null
			case 0x2D, 0x30 ... 0x39: return .number(try number())
			default: throw Failure.invalid
			}
		}

		mutating func literal(_ word: String) throws {
			for u in word.unicodeScalars {
				guard i < s.count, s[i] == u.value else { throw Failure.invalid }
				i += 1
			}
		}

		mutating func object(depth: Int) throws -> Value {
			i += 1
			skipSpace()
			var fields: [(key: String, value: Value)] = []
			var seen = Set<[UInt32]>()
			if i < s.count, s[i] == 0x7D {
				i += 1
				return .object(fields)
			}
			while true {
				guard i < s.count, s[i] == 0x22 else { throw Failure.invalid }
				let keyScalars = try rawString()
				guard seen.insert(keyScalars).inserted else { throw Failure.duplicateKey }
				skipSpace()
				guard i < s.count, s[i] == 0x3A else { throw Failure.invalid }
				i += 1
				skipSpace()
				let v = try value(depth: depth)
				fields.append((key: Self.text(keyScalars), value: v))
				skipSpace()
				guard i < s.count else { throw Failure.invalid }
				if s[i] == 0x2C {
					i += 1
					skipSpace()
					continue
				}
				if s[i] == 0x7D {
					i += 1
					return .object(fields)
				}
				throw Failure.invalid
			}
		}

		mutating func array(depth: Int) throws -> Value {
			i += 1
			skipSpace()
			var items: [Value] = []
			if i < s.count, s[i] == 0x5D {
				i += 1
				return .array(items)
			}
			while true {
				items.append(try value(depth: depth))
				skipSpace()
				guard i < s.count else { throw Failure.invalid }
				if s[i] == 0x2C {
					i += 1
					skipSpace()
					continue
				}
				if s[i] == 0x5D {
					i += 1
					return .array(items)
				}
				throw Failure.invalid
			}
		}

		mutating func string() throws -> String {
			Self.text(try rawString())
		}

		/// The scalars of a JSON string, without the quotes, escapes resolved.
		mutating func rawString() throws -> [UInt32] {
			i += 1
			var out: [UInt32] = []
			while true {
				guard i < s.count else { throw Failure.invalid }
				let c = s[i]
				i += 1
				if c == 0x22 { return out }
				if c < 0x20 { throw Failure.invalid }
				guard c == 0x5C else {
					out.append(c)
					continue
				}
				guard i < s.count else { throw Failure.invalid }
				let e = s[i]
				i += 1
				switch e {
				case 0x22, 0x5C, 0x2F: out.append(e)
				case 0x62: out.append(0x08)
				case 0x66: out.append(0x0C)
				case 0x6E: out.append(0x0A)
				case 0x72: out.append(0x0D)
				case 0x74: out.append(0x09)
				case 0x75:
					let hi = try hex4()
					if (0xD800 ... 0xDBFF).contains(hi) {
						guard i + 1 < s.count, s[i] == 0x5C, s[i + 1] == 0x75 else { throw Failure.invalid }
						i += 2
						let lo = try hex4()
						guard (0xDC00 ... 0xDFFF).contains(lo) else { throw Failure.invalid }
						out.append(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
					} else {
						guard !(0xDC00 ... 0xDFFF).contains(hi) else { throw Failure.invalid }
						out.append(hi)
					}
				default: throw Failure.invalid
				}
			}
		}

		mutating func hex4() throws -> UInt32 {
			guard i + 4 <= s.count else { throw Failure.invalid }
			var v: UInt32 = 0
			for _ in 0 ..< 4 {
				let d = s[i]
				i += 1
				switch d {
				case 0x30 ... 0x39: v = v << 4 | (d - 0x30)
				case 0x41 ... 0x46: v = v << 4 | (d - 0x41 + 10)
				case 0x61 ... 0x66: v = v << 4 | (d - 0x61 + 10)
				default: throw Failure.invalid
				}
			}
			return v
		}

		mutating func number() throws -> String {
			let start = i
			func isDigit(_ c: UInt32) -> Bool { (0x30 ... 0x39).contains(c) }
			if s[i] == 0x2D { i += 1 }
			guard i < s.count, isDigit(s[i]) else { throw Failure.invalid }
			if s[i] == 0x30 {
				i += 1
			} else {
				while i < s.count, isDigit(s[i]) { i += 1 }
			}
			if i < s.count, s[i] == 0x2E {
				i += 1
				guard i < s.count, isDigit(s[i]) else { throw Failure.invalid }
				while i < s.count, isDigit(s[i]) { i += 1 }
			}
			if i < s.count, s[i] == 0x65 || s[i] == 0x45 {
				i += 1
				if i < s.count, s[i] == 0x2B || s[i] == 0x2D { i += 1 }
				guard i < s.count, isDigit(s[i]) else { throw Failure.invalid }
				while i < s.count, isDigit(s[i]) { i += 1 }
			}
			return Self.text(Array(s[start ..< i]))
		}

		static func text(_ scalars: [UInt32]) -> String {
			var view = String.UnicodeScalarView()
			for v in scalars {
				if let u = Unicode.Scalar(v) { view.append(u) }
			}
			return String(view)
		}
	}
}
