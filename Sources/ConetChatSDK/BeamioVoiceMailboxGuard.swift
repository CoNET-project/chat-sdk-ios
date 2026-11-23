import Foundation

/// The voice guard of the signed chat mailbox (v109 section 122, project owner's requirement): audio, video, the channel controls and the
/// relay commands never go through the chat mailbox. A mailbox entry (`send`, `sendGroup`, `mailboxCommand`, `ownMailboxCommand`, and the shared
/// `postSignedMailboxCommand`) is refused with `not_supported` when
///  - a `command` or a `type` of the message starts with `voice`, in any letter case, and is not one of the pre-connection control messages of the exact
///    table `allowedChatTypes` (those travel by the chat route, as `send`); or
///  - an object of the message carries a media field (`frame`, `frameId`, `blob`, `chunk`, `chunkIndex`, `chunkCount`, `mediaKind`), whatever its name, or an
///    allowed control message carries a `payload` or a `sid` next to it.
/// `mailboxCommand` and `ownMailboxCommand` have no allowed name: the pre-connection control messages are chat lines, not router commands.
enum BeamioVoiceMailboxGuard {
	/// The exact (case-sensitive) `type`s of the pre-connection control messages that a chat line may carry (v113 section 131.1, v118 section 137). The page
	/// names the offer of both protocol lines `voice_call_offer_v1` and the accept of both `voice_call_accept_v1`; the line is told apart by `proto` (3 or 4),
	/// not by the type, and both lines run side by side. Until the per-signal key schemas are registered the guard is this table, the voice prefix and the
	/// media fields.
	static let allowedChatTypes: Set<String> = [
		"voice_call_offer_v1", "voice_call_accept_v1", "voice_call_ringing_v1", "voice_call_reject_v1", "voice_call_timeout_v1", "voice_end_v1",
	]

	/// The chat voice message (v137 section 157.3): a reference to stored audio, not call media, so it is not under the call-media guard. A chat line may carry
	/// it, checked against its manifest: exactly these keys, with these types. No router command may.
	static let voiceMessageType = "voice_message_v1"
	private static let manifestStrings: Set<String> = ["type", "key", "iv", "mime", "fragmentHash"]
	private static let manifestIntegers: Set<String> = ["durationMs", "sizeBytes"]

	/// The media fields of section 122.3 and 157.3 (`payload` and `sid` count only beside a voice name).
	static let mediaFields: Set<String> = ["frame", "frameId", "blob", "chunk", "chunkIndex", "chunkCount", "mediaKind", "dataUrl"]

	private static let maxDepth = 8

	static func isVoiceName(_ text: String) -> Bool { text.lowercased().hasPrefix("voice") }

	/// A router command of `mailboxCommand` / `ownMailboxCommand` / `postSignedMailboxCommand`: no voice name at all.
	static func refusesCommand(_ command: [String: Any]) -> Bool {
		refuses(object: command, allowChatTypes: false, depth: 0)
	}

	/// A chat line of `send` or `sendGroup` (its payload or body text): voice names only from the table, and no media field.
	static func refusesChatText(_ text: String) -> Bool {
		refuses(value: text, allowChatTypes: true, depth: 0)
	}

	private static func refuses(value: Any, allowChatTypes: Bool, depth: Int) -> Bool {
		guard depth < maxDepth else { return false }
		if let text = value as? String {
			let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
			if let data = trimmed.data(using: .utf8), let parsed = try? JSONSerialization.jsonObject(with: data) {
				return refuses(value: parsed, allowChatTypes: allowChatTypes, depth: depth + 1)
			}
			if let data = Data(base64Encoded: trimmed, options: [.ignoreUnknownCharacters]), !trimmed.isEmpty,
			   let parsed = try? JSONSerialization.jsonObject(with: data) {
				return refuses(value: parsed, allowChatTypes: allowChatTypes, depth: depth + 1)
			}
			return false
		}
		if let array = value as? [Any] {
			return array.contains { refuses(value: $0, allowChatTypes: allowChatTypes, depth: depth + 1) }
		}
		guard let object = value as? [String: Any] else { return false }
		return refuses(object: object, allowChatTypes: allowChatTypes, depth: depth)
	}

	/// The manifest of a `voice_message_v1` (v137 section 157.3; the PWA's generator, voiceMessage.ts, sends exactly these seven keys, all of them): the seven
	/// keys and no other; strings for type, key, iv, mime and fragmentHash (key and iv standard base64, fragmentHash `0x` and 64 hex); whole non-negative
	/// numbers for durationMs and sizeBytes. It judges what this device sends. What arrives and is already stored is shown as it is (no check here).
	private static func isManifest(_ object: [String: Any]) -> Bool {
		guard Set(object.keys) == manifestStrings.union(manifestIntegers) else { return false }
		for key in manifestStrings { guard let text = object[key] as? String, !text.isEmpty else { return false } }
		// key and iv: standard base64 with padding; fragmentHash: `0x` and 64 hex characters (a keccak-256 digest, 66 characters in all)
		for key in ["key", "iv"] {
			guard let text = object[key] as? String, let data = Data(base64Encoded: text), !data.isEmpty, data.base64EncodedString() == text else { return false }
		}
		guard let hash = object["fragmentHash"] as? String, hash.utf8.count == 66, hash.hasPrefix("0x"),
		      hash.dropFirst(2).allSatisfy({ $0.isASCII && $0.isHexDigit }) else { return false }
		for key in manifestIntegers {
			guard let number = object[key] as? NSNumber, CFGetTypeID(number as CFTypeRef) != CFBooleanGetTypeID(),
			      number.doubleValue >= 0, number.doubleValue == number.doubleValue.rounded() else { return false }
		}
		return true
	}

	private static func refuses(object: [String: Any], allowChatTypes: Bool, depth: Int) -> Bool {
		if object.keys.contains(where: { mediaFields.contains($0) }) { return true }
		var voiceNamed = false
		for key in ["command", "type"] {
			guard let name = object[key] as? String, isVoiceName(name) else { continue }
			// the chat voice message: only as a chat line, and only with its manifest
			if allowChatTypes, key == "type", name == voiceMessageType {
				if !isManifest(object) { return true }
				continue
			}
			voiceNamed = true
			if !(allowChatTypes && allowedChatTypes.contains(name)) { return true }
		}
		// an allowed control message carries no media: nothing named payload or sid beside it
		if voiceNamed, object["payload"] != nil || object["sid"] != nil { return true }
		for (_, nested) in object where nested is [String: Any] || nested is [Any] || nested is String {
			if refuses(value: nested, allowChatTypes: allowChatTypes, depth: depth + 1) { return true }
		}
		return false
	}
}
