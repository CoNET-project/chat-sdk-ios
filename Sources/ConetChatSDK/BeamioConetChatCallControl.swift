import Foundation

/// Call control carried as an ordinary Chat message (the peer's mailbox copy of
/// `voice_end_v1` / `voice_call_timeout_v1`). The module recognises it and hands
/// it to the shell's call layer (`BeamioConetChatModule.callControlObserver`);
/// Android uses the same rules.
public enum BeamioConetChatCallControl {
	public struct Signal {
		public var type: String
		public var callId: String
		public var sessionId: String
	}

	private static let types: Set<String> = ["voice_end_v1", "voice_call_timeout_v1"]

	/// The call-control signal inside a decrypted Chat line, or nil.
	public static func parse(_ line: String) -> Signal? {
		walk(line, depth: 0)
	}

	private static func walk(_ value: Any, depth: Int) -> Signal? {
		guard depth < 8 else { return nil }
		if let text = value as? String {
			let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
			if let data = trimmed.data(using: .utf8),
			   let parsed = try? JSONSerialization.jsonObject(with: data) {
				return walk(parsed, depth: depth + 1)
			}
			// Chat envelopes are often base64(UTF-8 JSON).
			if let data = Data(base64Encoded: trimmed, options: [.ignoreUnknownCharacters]),
			   let parsed = try? JSONSerialization.jsonObject(with: data) {
				return walk(parsed, depth: depth + 1)
			}
			return nil
		}
		if let arr = value as? [Any] {
			for v in arr { if let hit = walk(v, depth: depth + 1) { return hit } }
			return nil
		}
		guard let obj = value as? [String: Any] else { return nil }
		if let type = obj["type"] as? String, types.contains(type) {
			let callId = (obj["callId"] as? String) ?? ""
			let sessionId = (obj["sessionId"] as? String) ?? ""
			if callId.isEmpty && sessionId.isEmpty { return nil }
			return Signal(type: type, callId: callId, sessionId: sessionId)
		}
		if let inner = obj["text"] as? String, let hit = walk(inner, depth: depth + 1) { return hit }
		for (k, v) in obj where k != "text" {
			if v is [String: Any] || v is [Any], let hit = walk(v, depth: depth + 1) { return hit }
		}
		return nil
	}
}
