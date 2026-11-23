import XCTest
@testable import ConetChatSDK

/// ChatDaemon protocol v1 conformance (iOS). Reads the shared vectors
/// `Resources/chat-daemon-vectors.v1.json` — a copy of the spec's file in
/// `@conet.project/chat-sdk` (`scripts/sync-protocol-vectors.sh`), the same
/// vectors the TS Worker and chat-sdk-android test against.
///
/// Run on a simulator (crypto runs in WKWebView):
/// xcodebuild test -scheme ConetChatSDK -destination 'platform=iOS Simulator,name=iPhone 17'
@MainActor
final class ChatDaemonConformanceTests: XCTestCase {
	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
	}

	private static var cached: [String: Any]?

	private var vectors: [String: Any] {
		get throws {
			if let v = Self.cached { return v }
			let url = try XCTUnwrap(Bundle.module.url(forResource: "chat-daemon-vectors.v1", withExtension: "json"))
			let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
			Self.cached = obj
			return obj
		}
	}

	private var host: BeamioOpenPgpHost { BeamioOpenPgpHost.shared }

	private func keys() throws -> [String: [String: String]] {
		try XCTUnwrap(try vectors["keys"] as? [String: [String: String]])
	}

	private func call<T>(_ body: (@escaping (Result<T, Error>) -> Void) -> Void) async throws -> T {
		try await withCheckedThrowingContinuation { cont in
			body { cont.resume(with: $0) }
		}
	}

	private func json(_ text: String) throws -> Any {
		try JSONSerialization.jsonObject(with: Data(text.utf8))
	}

	private func assertJsonEqual(_ a: Any?, _ b: Any?, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
		let lhs = a.map { NSArray(object: $0) }
		let rhs = b.map { NSArray(object: $0) }
		XCTAssertEqual(lhs, rhs, message, file: file, line: line)
	}

	// MARK: - hello

	func testHelloMatchesVectors() throws {
		let hello = try XCTUnwrap(try vectors["hello"] as? [String: Any])
		let all = try XCTUnwrap(hello["capabilities"] as? [String])
		let ios = try XCTUnwrap((hello["implementations"] as? [String: Any])?["ios"] as? [String: Any])
		let result = BeamioConetChatProtocol.helloResult()
		XCTAssertEqual(try vectors["protocolVersion"] as? Int, BeamioConetChatProtocol.protocolVersion)
		XCTAssertEqual(result["protocolVersion"] as? Int, ios["protocolVersion"] as? Int)
		XCTAssertEqual(result["minProtocolVersion"] as? Int, ios["minProtocolVersion"] as? Int)
		XCTAssertEqual(result["implementation"] as? String, "ios")
		// (QA only): the QA candidate declares exactly the approved QA capabilities on top of the spec list (BEAMIO_QA_BUILD, for
			// identity.route-register.native.v1). Outside QA the extra list is empty, so the comparison is the spec list as before.
			let qaExtra = BeamioConetChatProtocol.qaCapabilities
			XCTAssertEqual(result["capabilities"] as? [String], (ios["capabilities"] as? [String] ?? []) + qaExtra)
		for cap in BeamioConetChatProtocol.capabilities where !qaExtra.contains(cap) {
			XCTAssertTrue(all.contains(cap), "\(cap) is not a spec capability")
		}
		let version = try XCTUnwrap(result["sdkVersion"] as? String)
		XCTAssertNotNil(version.range(of: #"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$"#, options: .regularExpression), "X.Y.Z with an optional release suffix")
	}

	func testModuleAnswersHelloAndUnknownCommands() async throws {
		var events: [[String: Any]] = []
		// Three requests, three answers, one each. reqId -1 is not valid: it is answered bad_request with reqId null.
		let done = expectation(description: "three acks")
		done.expectedFulfillmentCount = 3
		let emit: BeamioConetChatModule.WebEmit = { payload in
			guard let event = payload["event"] as? [String: Any], event["type"] as? String == "ack" else { return }
			events.append(event)
			done.fulfill()
		}
		BeamioConetChatModule.handleCommand(["type": "hello", "reqId": 41, "protocolVersion": 1], emit: emit)
		BeamioConetChatModule.handleCommand(["type": "notACommand", "reqId": 42], emit: emit)
		BeamioConetChatModule.handleCommand(["type": "notACommand", "reqId": -1], emit: emit)
		await fulfillment(of: [done], timeout: 5)
		let hello = try XCTUnwrap(events.first { $0["reqId"] as? Int == 41 })
		XCTAssertEqual(hello["ok"] as? Bool, true)
		assertJsonEqual(hello["result"], BeamioConetChatProtocol.helloResult(), "hello result")
		let unknown = try XCTUnwrap(events.first { $0["reqId"] as? Int == 42 })
		XCTAssertEqual(unknown["ok"] as? Bool, false)
		// The name is not in the command table: unknown_command, judged before the gate in every state.
		XCTAssertEqual(unknown["error"] as? String, "unknown_command")
		let invalid = try XCTUnwrap(events.first { $0["reqId"] is NSNull })
		XCTAssertEqual(invalid["error"] as? String, "bad_request")
		XCTAssertEqual(events.count, 3, "one answer per request")
	}

	// MARK: - call signals

	func testCallSignalClassification() throws {
		let cases = try XCTUnwrap(try vectors["callSignal"] as? [[String: Any]])
		XCTAssertFalse(cases.isEmpty)
		for c in cases {
			let name = c["name"] as? String ?? "?"
			let line = try XCTUnwrap(c["line"] as? String)
			let got = BeamioConetChatCallSignal.classify(line)
			if let expect = c["expect"] as? [String: String] {
				let hit = try XCTUnwrap(got, name)
				XCTAssertEqual(hit.kind, expect["kind"], name)
				XCTAssertEqual(hit.type, expect["type"], name)
				XCTAssertEqual(hit.callId, expect["callId"], name)
				XCTAssertEqual(hit.sessionId, expect["sessionId"], name)
				XCTAssertEqual(hit.rejectReason, expect["rejectReason"], name)
			} else {
				XCTAssertNil(got, name)
			}
		}
	}

	// MARK: - builders

	func testWireBuilders() throws {
		let cases = try XCTUnwrap(try vectors["builders"] as? [[String: Any]])
		for c in cases {
			let name = try XCTUnwrap(c["name"] as? String)
			let i = try XCTUnwrap(c["input"] as? [String: Any])
			let s = { (k: String) in i[k] as? String ?? "" }
			let n = { (k: String) in (i[k] as? NSNumber)?.intValue ?? 0 }
			let built: [String: Any]
			switch name {
			case "deliveryAckCommand":
				built = BeamioConetChatWire.deliveryAckCommand(eoa: s("eoa"), armorHash: s("armorHash"), timestamp: n("timestamp"))
			case "deliveryReceipt":
				built = BeamioConetChatWire.deliveryReceipt(sendId: s("sendId"), armorHash: s("armorHash"), deliveredAt: n("deliveredAt"), eoa: s("eoa"))
			case "pendingRow":
				built = BeamioConetChatWire.pendingRow(sendId: s("sendId"), text: s("text"), createdAt: n("createdAt"))
			case "chatEnvelope":
				built = BeamioConetChatWire.chatEnvelope(timestamp: n("timestamp"), text: s("text"), from: s("from"), signMessage: s("signMessage"))
			case "mailboxWork", "mailboxWorkPush":
				built = BeamioConetChatWire.mailboxWork(data: s("data"), noPush: i["noPush"] as? Bool ?? false)
			default:
				XCTFail("no iOS builder for \(name)")
				continue
			}
			assertJsonEqual(built, c["expect"], name)
		}
	}

	// MARK: - crypto (bundled openpgp / ethers in WKWebView)

	func testAckHashes() async throws {
		let cases = try XCTUnwrap(try vectors["ackHash"] as? [[String: String]])
		// The first call starts the host's page. On a cold simulator the first boot can outlast the 3 s boot timeout (the host then resets and the
		// second boot is ready). Warm the host up first, so the vectors judge the hash and not the cold start.
		for _ in 0..<3 {
			if (try? await call { done in host.keccakUtf8("warm-up", completion: done) }) != nil { break }
		}
		for c in cases {
			let armor = try XCTUnwrap(c["armor"])
			let hash: String = try await call { done in host.keccakUtf8(armor, completion: done) }
			XCTAssertEqual(hash, c["armorHash"], c["name"] ?? "?")
		}
	}

	func testEip191SignAndRecover() async throws {
		let wallet = try XCTUnwrap(try keys()["wallet"])
		let key = try XCTUnwrap(wallet["privateKey"]).replacingOccurrences(of: "0x", with: "")
		// r3: signing and the address come from the native signer, not from the WebView.
		let address = try XCTUnwrap(hexKeyAddress(key))
		XCTAssertEqual(address.lowercased(), wallet["address"]?.lowercased())
		let cases = try XCTUnwrap(try vectors["eip191"] as? [[String: String]])
		for c in cases {
			let message = try XCTUnwrap(c["message"])
			let sig = try XCTUnwrap(hexKeySignEip191(key, message: message))
			XCTAssertEqual(sig, c["signature"], message)
			let signer: String = try await call { done in host.verifyMessage(text: message, signature: sig, completion: done) }
			XCTAssertEqual(signer.lowercased(), c["signer"]?.lowercased(), message)
		}
	}

	/// Decrypts an envelope with the native OpenPGP layer (X-19, gopenpgp v3.5.2): the production decrypt of this branch (25.52 r3). The
	/// private armor is the vector's own test key, read from the vector file, never from storage and never from a WebView. Nothing is logged.
	/// macOS test builds do not link X-19: the case is skipped there; the iOS simulator runs it.
	private func decrypt(_ armor: String, with which: String) async throws -> (text: String, armorHash: String) {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build (macOS test build); the iOS simulator runs this case")
		let privateArmor = try XCTUnwrap(try keys()[which]?["privateArmored"], "the vector key \(which)")
		switch BeamioPGPNative.decryptArmoredText(privateArmor: privateArmor, armoredMessage: armor) {
		case .plain(let plain):
			return (String(decoding: plain, as: UTF8.self), BeamioConetChatListenSession.armorHash(armor))
		case .notUTF8, .failed:
			XCTFail("the native decrypt of \(which) failed")
			throw NSError(domain: "ChatDaemonConformanceTests", code: 1, userInfo: [NSLocalizedDescriptionKey: "native decrypt failed"])
		}
	}

	private func decodeLiteral(_ text: String, _ encoding: String) throws -> Any {
		if encoding == "base64-json" {
			let data = try XCTUnwrap(Data(base64Encoded: text))
			return try JSONSerialization.jsonObject(with: data)
		}
		return try json(text)
	}

	func testEnvelopes() async throws {
		let cases = try XCTUnwrap(try vectors["envelopes"] as? [[String: Any]])
		for c in cases {
			let name = try XCTUnwrap(c["name"] as? String)
			let out = try await decrypt(try XCTUnwrap(c["armor"] as? String), with: try XCTUnwrap(c["decryptWith"] as? String))
			XCTAssertEqual(out.armorHash, c["armorHash"] as? String, "\(name) armorHash")
			let obj = try XCTUnwrap(try decodeLiteral(out.text, try XCTUnwrap(c["literal"] as? String)) as? [String: Any], name)
			assertJsonEqual(obj, c["expect"], name)
			if let signed = c["signed"] as? [String: String] {
				let text = try XCTUnwrap(obj[try XCTUnwrap(signed["textField"])] as? String)
				let sig = try XCTUnwrap(obj[try XCTUnwrap(signed["signatureField"])] as? String)
				let signer: String = try await call { done in host.verifyMessage(text: text, signature: sig, completion: done) }
				XCTAssertEqual(signer.lowercased(), signed["signer"]?.lowercased(), "\(name) signer")
			}
			if let messageJson = c["messageJson"] {
				assertJsonEqual(try json(try XCTUnwrap(obj["message"] as? String)), messageJson, "\(name) message")
			}
		}
	}

	func testEncodersRoundTrip() async throws {
		let cases = try XCTUnwrap(try vectors["envelopes"] as? [[String: Any]])
		let route = try XCTUnwrap(cases.first { $0["name"] as? String == "routeCommand" }?["expect"] as? [String: String])
		let work = try XCTUnwrap(cases.first { $0["name"] as? String == "mailboxWork" }?["expect"] as? [String: Any])
		let routePub = try XCTUnwrap(try keys()["routePgp"]?["publicArmored"])

		let routeArmor: String = try await call { done in
			host.encryptSignedRouteCommand(message: route["message"] ?? "", signMessage: route["signMessage"] ?? "", routePublicArmor: routePub, completion: done)
		}
		let routeOut = try await decrypt(routeArmor, with: "routePgp")
		assertJsonEqual(try decodeLiteral(routeOut.text, "base64-json"), route, "encryptSignedRouteCommand")

		let workArmor: String = try await call { done in
			host.wrapArmorToMailboxWork(innerArmor: work["data"] as? String ?? "", mailboxRoutePublicArmor: routePub, noPush: true, completion: done)
		}
		let workOut = try await decrypt(workArmor, with: "routePgp")
		assertJsonEqual(try json(workOut.text), work, "wrapArmorToMailboxWork")
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

}
