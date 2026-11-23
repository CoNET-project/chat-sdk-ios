import Foundation

/// Call control carried as an ordinary Chat message (the peer's mailbox copy of
/// `voice_end_v1` / `voice_call_timeout_v1`). The module recognises it and hands
/// it to the shell's call layer (`BeamioConetChatModule.callControlObserver`);
/// Android uses the same rules.
///
/// A signal reaches the shell only through `admit` (2026): the message is an envelope, the signer of
/// its outer EIP-191 signature (recovered by the module) equals the envelope `from`, the inner signal carries a `from` and it equals the envelope
/// `from`, and the signal is a call-control kind. Anything else is dropped: no hand-over and no state change (the message is still an ordinary line).
public enum BeamioConetChatCallControl {
	public struct Signal {
		public var type: String
		public var callId: String
		public var sessionId: String
		/// The inner `from`, lower case, as the signal carries it (empty when it carries none).
		public var from: String = ""
	}

	public enum Verdict: Equatable {
		/// `from` is the verified envelope sender (lower case).
		case deliver(type: String, callId: String, sessionId: String, from: String)
		case drop(String)
	}

	private static let addressForm = try! NSRegularExpression(pattern: "^0x[0-9a-f]{40}$")

	private static func isAddress(_ text: String) -> Bool {
		addressForm.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
	}

	/// The gate. `plaintext` is the decrypted line, `signer` the address recovered from the outer signature over `text` (nil when it did not verify).
	public static func admit(plaintext: String, signer: String?) -> Verdict {
		guard let data = plaintext.data(using: .utf8), let outer = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
		      outer["signMessage"] != nil, let text = outer["text"] as? String
		else { return .drop("not_envelope") }
		let outerFrom = ((outer["from"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard isAddress(outerFrom) else { return .drop("no_envelope_from") }
		let who = (signer ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard !who.isEmpty else { return .drop("unverified") }
		guard who == outerFrom else { return .drop("signer_mismatch") }
		guard let sig = walk(text, depth: 0) else { return .drop("not_control") }
		guard !sig.from.isEmpty else { return .drop("no_inner_from") }
		guard sig.from == outerFrom else { return .drop("inner_from_mismatch") }
		return .deliver(type: sig.type, callId: sig.callId, sessionId: sig.sessionId, from: outerFrom)
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
			let from = ((obj["from"] as? String) ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
			return Signal(type: type, callId: callId, sessionId: sessionId, from: from)
		}
		if let inner = obj["text"] as? String, let hit = walk(inner, depth: depth + 1) { return hit }
		for (k, v) in obj where k != "text" {
			if v is [String: Any] || v is [Any], let hit = walk(v, depth: depth + 1) { return hit }
		}
		return nil
	}
}
