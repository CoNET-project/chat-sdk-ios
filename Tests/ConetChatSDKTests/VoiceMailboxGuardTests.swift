#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The voice guard of the signed chat mailbox (v109 section 122): every entry refuses a voice name that is not a pre-connection control message, and every
/// media field. Synthetic data only.
final class VoiceMailboxGuardTests: XCTestCase {
	private typealias Guard = BeamioVoiceMailboxGuard

	private func line(_ inner: [String: Any]) -> String {
		let text = String(data: try! JSONSerialization.data(withJSONObject: inner, options: [.sortedKeys]), encoding: .utf8)!
		return String(data: try! JSONSerialization.data(withJSONObject: ["timestamp": 1, "text": text, "from": "0x01", "signMessage": "0x00"], options: [.sortedKeys]), encoding: .utf8)!
	}

	func testTheControlMessagesOfTheTableAreLetThroughAsChatLines() {
		for type in Guard.allowedChatTypes.sorted() {
			XCTAssertFalse(Guard.refusesChatText(line(["type": type, "callId": "c1", "sessionId": "s1", "from": "0x01"])), type)
		}
		XCTAssertFalse(Guard.refusesChatText("hello"), "an ordinary text")
		XCTAssertFalse(Guard.refusesChatText(line(["type": "chat", "text": "voice mail is nice"])), "the word in a text is not a name")
		XCTAssertFalse(Guard.refusesChatText(""))
	}

	/// Both protocol lines use the same type names (the line is told apart by `proto`), so both pass the table.
	func testTheAcceptAndOfferOfBothProtocolLinesPass() {
		for proto in [3, 4] {
			XCTAssertFalse(Guard.refusesChatText(line(["type": "voice_call_accept_v1", "proto": proto, "callId": "c1", "sessionId": "s1", "from": "0x01"])), "accept proto \(proto)")
			XCTAssertFalse(Guard.refusesChatText(line(["type": "voice_call_offer_v1", "proto": proto, "callId": "c1", "sessionId": "s1", "from": "0x01"])), "offer proto \(proto)")
		}
		// the same names still refuse any media field
		XCTAssertTrue(Guard.refusesChatText(line(["type": "voice_call_accept_v1", "proto": 4, "blob": "x"])))
	}

	private let manifest: [String: Any] = ["type": "voice_message_v1", "key": "AAECAwQFBgcICQoLDA0ODw==", "iv": "AAECAwQFBgcICQoL", "mime": "audio/mp4", "durationMs": 4200, "sizeBytes": 31337,
	                                         "fragmentHash": "0x" + String(repeating: "ab", count: 32)]

	/// v137 section 157.3: the chat voice message passes as a chat line, by its manifest, and never as a router command.
	func testTheChatVoiceMessagePassesByItsManifest() {
		XCTAssertFalse(Guard.refusesChatText(line(manifest)))
		XCTAssertFalse(Guard.refusesChatText(String(data: try! JSONSerialization.data(withJSONObject: manifest), encoding: .utf8)!), "bare")
		XCTAssertTrue(Guard.refusesCommand(manifest), "no router command may carry it")
		XCTAssertTrue(Guard.refusesCommand(["command": "voice_message_v1"]))
		// a manifest with an extra key, a missing key, a wrong type, or a media field is refused
		var extra = manifest; extra["waveform"] = "x"
		XCTAssertTrue(Guard.refusesChatText(line(extra)), "extra key")
		var missing = manifest; missing.removeValue(forKey: "iv")
		XCTAssertTrue(Guard.refusesChatText(line(missing)), "missing key")
		var emptyKey = manifest; emptyKey["key"] = ""
		XCTAssertTrue(Guard.refusesChatText(line(emptyKey)), "empty string")
		// the shapes of key, iv and fragmentHash
		for (key, value) in [("key", "not base64!"), ("key", "AAECAwQFBgcICQoLDA0ODw"), ("iv", "AAECAwQFBgcICQp="), ("fragmentHash", "abcd"),
		                     ("fragmentHash", "0x" + String(repeating: "ab", count: 31)), ("fragmentHash", "0x" + String(repeating: "zz", count: 32)),
		                     ("fragmentHash", String(repeating: "ab", count: 33))] as [(String, Any)] {
			var bad = manifest; bad[key] = value
			XCTAssertTrue(Guard.refusesChatText(line(bad)), "\(key)=\(value)")
		}
		var upper = manifest; upper["fragmentHash"] = "0x" + String(repeating: "AB", count: 32)
		XCTAssertFalse(Guard.refusesChatText(line(upper)), "hex digits in either case")
		for (key, value) in [("durationMs", "4200"), ("sizeBytes", -1), ("sizeBytes", 1.5), ("durationMs", true), ("key", 5), ("fragmentHash", [1])] as [(String, Any)] {
			var bad = manifest; bad[key] = value
			XCTAssertTrue(Guard.refusesChatText(line(bad)), "\(key)=\(value)")
		}
		for field in ["dataUrl", "frame", "blob", "chunk", "chunkIndex", "chunkCount", "mediaKind", "frameId"] {
			var media = manifest; media[field] = "x"
			XCTAssertTrue(Guard.refusesChatText(line(media)), "media field \(field)")
		}
		// the name is matched exactly
		var other = manifest; other["type"] = "Voice_Message_V1"
		XCTAssertTrue(Guard.refusesChatText(line(other)))
		other["type"] = "voice_message_v2"
		XCTAssertTrue(Guard.refusesChatText(line(other)))
	}

	/// v137 section 157.4: the in-channel controls are refused on the mailbox path by the voice prefix.
	func testTheInChannelControlsAreRefusedOnTheMailbox() {
		for name in ["voice_media_caps_v1", "voice_video_enable_v1", "voice_video_disable_v1", "voice_offer_store"] {
			XCTAssertTrue(Guard.refusesChatText(line(["type": name, "callId": "c"])), "chat \(name)")
			XCTAssertTrue(Guard.refusesCommand(["command": name]), "router \(name)")
		}
	}

	func testEveryOtherVoiceNameIsRefusedInAnyLetterCase() {
		for name in ["voice_uplink", "voice_frame_v1", "voice_frame_v2", "voice_listen", "voice_channel_ready_v3", "voice_offer_store", "voice_offer_fetch",
		             "Voice_Uplink", "VOICE_FRAME_V1", "voice_call_accept_v4", "voice_call_offer_v2", "voice_call_offer_v4", "voice", "voiceX"] {
			XCTAssertTrue(Guard.refusesChatText(line(["type": name, "callId": "c1"])), "type \(name)")
			XCTAssertTrue(Guard.refusesChatText(line(["command": name])), "command \(name)")
			XCTAssertTrue(Guard.refusesCommand(["command": name]), "router command \(name)")
			XCTAssertTrue(Guard.refusesCommand(["type": name]), "router type \(name)")
		}
		// a near miss of the allowed name is a different name, so it is refused
		XCTAssertTrue(Guard.refusesChatText(line(["type": "VOICE_END_V1"])), "an allowed name is matched exactly")
		XCTAssertTrue(Guard.refusesChatText(line(["type": "voice_end_v1 "])))
	}

	func testARouterCommandHasNoAllowedVoiceName() {
		for type in Guard.allowedChatTypes { XCTAssertTrue(Guard.refusesCommand(["command": type]), "command \(type)") }
		XCTAssertFalse(Guard.refusesCommand(["command": "gossip_delivery_ack", "armorHash": "ab"]))
		XCTAssertFalse(Guard.refusesCommand(["command": "presence_query", "walletAddress": "0x01"]))
	}

	func testAMediaFieldRefusesTheObjectWhateverItsName() {
		for field in Guard.mediaFields.sorted() {
			XCTAssertTrue(Guard.refusesCommand(["command": "something", field: "x"]), "router command with \(field)")
			XCTAssertTrue(Guard.refusesChatText(line(["type": "chat", field: "x"])), "chat line with \(field)")
			XCTAssertTrue(Guard.refusesChatText(line(["type": "voice_call_offer_v1", field: 1])), "an allowed control message with \(field)")
			XCTAssertTrue(Guard.refusesCommand(["command": "something", "inner": [field: "x"]]), "nested \(field)")
		}
		// payload or sid beside an allowed control message is media, beside nothing voice it is an ordinary field
		XCTAssertTrue(Guard.refusesChatText(line(["type": "voice_call_offer_v1", "payload": "AAAA"])))
		XCTAssertTrue(Guard.refusesChatText(line(["type": "voice_call_offer_v1", "sid": "ab"])))
		XCTAssertFalse(Guard.refusesChatText(line(["type": "chat", "payload": "AAAA", "sid": "ab"])))
		XCTAssertFalse(Guard.refusesCommand(["command": "something", "payload": "AAAA"]))
	}

	func testANestedOrEncodedVoiceMessageIsFound() {
		let inner = ["type": "voice_frame_v1", "frame": "x"] as [String: Any]
		let innerText = String(data: try! JSONSerialization.data(withJSONObject: inner), encoding: .utf8)!
		XCTAssertTrue(Guard.refusesChatText(innerText), "bare")
		XCTAssertTrue(Guard.refusesChatText(Data(innerText.utf8).base64EncodedString()), "base64")
		XCTAssertTrue(Guard.refusesChatText(line(["text": innerText])), "inside the text of an envelope")
		XCTAssertTrue(Guard.refusesChatText(String(data: try! JSONSerialization.data(withJSONObject: [[inner]]), encoding: .utf8)!), "in an array")
	}

	// MARK: - the entries

	private final class KeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private func answer(_ body: [String: Any]) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(body) { out in
			let event = (out["event"] as? [String: Any]) ?? out
			if event["type"] as? String == "ack", ack == nil { ack = event; done.fulfill() }
		}
		wait(for: [done], timeout: 10)
		return ack
	}

	func testEveryMailboxEntryAnswersNotSupported() {
		NativeAccountPointerIsolation.begin()
		let saved = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = saved; NativeAccountPointerIsolation.end() }
		let key = [UInt8](repeating: 0x11, count: 32)
		let account = BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
		let store = KeyStore()
		_ = store.write(eoa: account, key: Data(key))
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		let router = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----"
		var n = 900
		func send(_ fields: [String: Any]) -> [String: Any]? { n += 1; var b = fields; b["reqId"] = n; return answer(b) }
		let media = ["type": "voice_frame_v1", "callId": "c", "frame": "x"] as [String: Any]
		let mediaText = String(data: try! JSONSerialization.data(withJSONObject: media), encoding: .utf8)!
		let cases: [(String, [String: Any])] = [
			("send", ["type": "send", "to": ["routerArmoredPublicKey": router], "payload": line(media)]),
			("send bare", ["type": "send", "to": ["routerArmoredPublicKey": router], "payload": mediaText]),
			("sendGroup", ["type": "sendGroup", "request": ["roster": ["members": []], "body": line(media)]]),
			("mailboxCommand voice_", ["type": "mailboxCommand", "routerArmoredPublicKey": router, "command": ["command": "voice_uplink", "payload": "AAAA"]]),
			("mailboxCommand case", ["type": "mailboxCommand", "routerArmoredPublicKey": router, "command": ["command": "VOICE_OFFER_FETCH"]]),
			("mailboxCommand media", ["type": "mailboxCommand", "routerArmoredPublicKey": router, "command": ["command": "x", "blob": "A"]]),
			("ownMailboxCommand", ["type": "ownMailboxCommand", "command": ["command": "voice_offer_store"]]),
		]
		for (label, body) in cases {
			let ack = send(body)
			XCTAssertEqual(ack?["ok"] as? Bool, false, label)
			XCTAssertEqual(ack?["error"] as? String, "not_supported", label)
		}
	}

	/// Source guard: no voice command is built or posted by an unsigned route any more, and the shared signed entry carries the guard.
	func testTheSourceHasNoUnsignedVoicePostAndTheSharedEntryIsGuarded() throws {
		let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
			.appendingPathComponent("Sources/ConetChatSDK/BeamioConetChatModule.swift")
		guard let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) else { throw XCTSkip("SDK sources not readable in this run") }
		XCTAssertFalse(text.contains("postOpaqueVoiceCommand"), "the unsigned voice POST is gone")
		XCTAssertFalse(text.contains("hasPrefix(\"voice_\")"), "no case-sensitive prefix route")
		let start = try XCTUnwrap(text.range(of: "static func postSignedMailboxCommand("))
		XCTAssertTrue(text[start.lowerBound...].prefix(2500).contains("BeamioVoiceMailboxGuard.refusesCommand(command)"), "the shared signed entry is guarded")
	}
}
#endif
