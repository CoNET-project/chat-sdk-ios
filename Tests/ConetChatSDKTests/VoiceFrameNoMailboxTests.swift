#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The chat mailbox carries no audio or video (v99 section 106): `voiceFrame` is refused with `not_supported` and posts nothing.
final class VoiceFrameNoMailboxTests: XCTestCase {
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

	private func sourceText(_ name: String) throws -> String {
		let here = URL(fileURLWithPath: #filePath)
		let url = here.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
			.appendingPathComponent("Sources/ConetChatSDK/\(name)")
		guard let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) else {
			throw XCTSkip("the SDK sources are not readable from this test run (\(name))")
		}
		return text
	}

	func testTheShippedCommandAnswersNotSupportedWhateverTheFrame() {
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
		let frames: [[String: Any]] = [
			["routerArmoredPublicKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----",
			 "frame": ["callId": "c", "sessionId": "s", "targetSessionId": "t", "payload": "AAAA", "seq": 1]],
			[:], ["frame": "not an object"],
		]
		for (n, extra) in frames.enumerated() {
			var body: [String: Any] = ["type": "voiceFrame", "reqId": 700 + n]
			for (k, v) in extra { body[k] = v }
			var ack: [String: Any]?
			let done = expectation(description: "ack \(n)")
			BeamioConetChatModule.handleCommand(body) { out in
				let event = (out["event"] as? [String: Any]) ?? out
				if event["type"] as? String == "ack" { ack = event; done.fulfill() }
			}
			wait(for: [done], timeout: 10)
			XCTAssertEqual(ack?["ok"] as? Bool, false, "frame \(n)")
			XCTAssertEqual(ack?["error"] as? String, "not_supported", "frame \(n)")
			XCTAssertNil(ack?["result"], "nothing was sent")
		}
	}

	/// Source guard: the handler neither builds nor posts a voice command, and it answers not_supported; no `voice_uplink` command is built anywhere.
	func testTheHandlerSourceDoesNotPostToTheMailbox() throws {
		let text = try sourceText("BeamioConetChatModule.swift")
		let start = try XCTUnwrap(text.range(of: "private static func handleVoiceFrame("))
		let tail = text[start.lowerBound...]
		let end = try XCTUnwrap(tail.range(of: "\n\t}\n"))
		let body = String(tail[..<end.upperBound])
		for forbidden in ["postOpaqueVoiceCommand", "postToEntries", "encrypt(", "voice_uplink", "voice_frame_v1", "currentSession"] {
			XCTAssertFalse(body.contains(forbidden), "handleVoiceFrame must not contain \(forbidden)")
		}
		XCTAssertTrue(body.contains("not_supported"))
		var built: [String] = []
		for name in ["BeamioConetChatModule.swift", "BeamioSiCipherPost.swift", "BeamioNativeVoiceBridge.swift"] {
			guard let t = try? sourceText(name) else { continue }
			if t.contains("\"command\": \"voice_uplink\"") || t.contains("\"voice_frame_v1\"") { built.append(name) }
		}
		XCTAssertTrue(built.isEmpty, "no voice_uplink command is built in \(built)")
	}
}
#endif
