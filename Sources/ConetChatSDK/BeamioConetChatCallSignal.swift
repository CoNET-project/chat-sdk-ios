import Foundation

/// Call-signal classification per the spec's `src/call-signal.ts` (shared
/// vectors `callSignal`), for protocol v1 `event:callSignal` (P3). Kept apart
/// from `BeamioConetChatCallControl`, which the module still uses for the shell's
/// call layer; aligning the two is left to whoever owns call control.
public enum BeamioConetChatCallSignal {
	public struct Signal: Equatable {
		/// `offer` | `accept` | `reject` | `end` | `timeout` | `ringing`.
		public var kind: String
		public var type: String
		public var callId: String
		public var sessionId: String
		/// `voice_call_reject_v1` only: `busy` when `reason == "busy"`, else `declined`.
		public var rejectReason: String? = nil
	}

	public static let kinds: [String: String] = [
		"voice_call_offer_v1": "offer",
		"voice_call_accept_v1": "accept",
		"voice_call_reject_v1": "reject",
		"voice_end_v1": "end",
		"voice_call_timeout_v1": "timeout",
		// Wake receipt: the callee's device is ringing (callee → caller mailbox, NoPush).
		"voice_call_ringing_v1": "ringing",
	]

	private static let maxDepth = 8

	/// The call signal inside a decrypted Chat line, or nil.
	public static func classify(_ line: String) -> Signal? {
		walk(line, depth: 0)
	}

	private static func parseJson(_ text: String) -> Any? {
		let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
		guard t.hasPrefix("{") || t.hasPrefix("["), let data = t.data(using: .utf8) else { return nil }
		return try? JSONSerialization.jsonObject(with: data)
	}

	/// Padded standard base64 only (whitespace removed), decoding to UTF-8.
	private static func decodeBase64Utf8(_ text: String) -> String? {
		let compact = text.components(separatedBy: .whitespacesAndNewlines).joined()
		guard !compact.isEmpty, compact.count % 4 == 0,
		      compact.range(of: "^[A-Za-z0-9+/]+={0,2}$", options: .regularExpression) != nil,
		      let data = Data(base64Encoded: compact)
		else { return nil }
		return String(data: data, encoding: .utf8)
	}

	private static func parseString(_ raw: String) -> Any? {
		let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
		if t.hasPrefix("{") || t.hasPrefix("[") { return parseJson(t) }
		guard let decoded = decodeBase64Utf8(t) else { return nil }
		return parseJson(decoded)
	}

	private static func trimmed(_ v: Any?) -> String {
		(v as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
	}

	private static func walk(_ value: Any, depth: Int) -> Signal? {
		guard depth < maxDepth else { return nil }
		if let text = value as? String {
			guard let parsed = parseString(text) else { return nil }
			return walk(parsed, depth: depth + 1)
		}
		if let arr = value as? [Any] {
			for v in arr { if let hit = walk(v, depth: depth + 1) { return hit } }
			return nil
		}
		guard let obj = value as? [String: Any] else { return nil }
		if let type = obj["type"] as? String, let kind = kinds[type] {
			let callId = trimmed(obj["callId"])
			let sessionId = trimmed(obj["sessionId"])
			if callId.isEmpty && sessionId.isEmpty { return nil }
			let rejectReason: String? = type == "voice_call_reject_v1"
				? ((obj["reason"] as? String) == "busy" ? "busy" : "declined")
				: nil
			return Signal(kind: kind, type: type, callId: callId, sessionId: sessionId, rejectReason: rejectReason)
		}
		if let inner = obj["text"] as? String, let hit = walk(inner, depth: depth + 1) { return hit }
		for (k, v) in obj where k != "text" {
			if v is [String: Any] || v is [Any], let hit = walk(v, depth: depth + 1) { return hit }
		}
		return nil
	}
}
