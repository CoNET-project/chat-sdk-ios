import XCTest
@testable import ConetChatSDK

/// ChatDaemon protocol v1 conformance (iOS). Reads the shared vectors
/// `Resources/chat-daemon-vectors.v1.json` — a copy of the spec's file in
/// `@conet.project/chat-sdk` (`scripts/sync-protocol-vectors.sh`), the same
/// vectors the TS Worker and chat-sdk-android test against.
///
/// Run on a simulator (crypto runs in WKWebView):
///   xcodebuild test -scheme ConetChatSDK -destination 'platform=iOS Simulator,name=iPhone 17'
@MainActor
final class ChatDaemonConformanceTests: XCTestCase {
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
		XCTAssertEqual(result["capabilities"] as? [String], ios["capabilities"] as? [String])
		for cap in BeamioConetChatProtocol.capabilities {
			XCTAssertTrue(all.contains(cap), "\(cap) is not a spec capability")
		}
		let version = try XCTUnwrap(result["sdkVersion"] as? String)
		XCTAssertNotNil(version.range(of: #"^\d+\.\d+\.\d+$"#, options: .regularExpression))
	}

	func testModuleAnswersHelloAndUnknownCommands() async throws {
		var events: [[String: Any]] = []
		let done = expectation(description: "two acks")
		done.expectedFulfillmentCount = 2
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
		XCTAssertEqual(unknown["error"] as? String, "unknown_command")
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
		for c in cases {
			let armor = try XCTUnwrap(c["armor"])
			let hash: String = try await call { done in host.keccakUtf8(armor, completion: done) }
			XCTAssertEqual(hash, c["armorHash"], c["name"] ?? "?")
		}
	}

	func testEip191SignAndRecover() async throws {
		let wallet = try XCTUnwrap(try keys()["wallet"])
		let key = try XCTUnwrap(wallet["privateKey"]).replacingOccurrences(of: "0x", with: "")
		let address: String = try await call { done in host.walletAddress(privateKeyHex: key, completion: done) }
		XCTAssertEqual(address, wallet["address"]?.lowercased())
		let cases = try XCTUnwrap(try vectors["eip191"] as? [[String: String]])
		for c in cases {
			let message = try XCTUnwrap(c["message"])
			let sig: String = try await call { done in host.signEip191(privateKeyHex: key, message: message, completion: done) }
			XCTAssertEqual(sig, c["signature"], message)
			let signer: String = try await call { done in host.verifyMessage(text: message, signature: sig, completion: done) }
			XCTAssertEqual(signer.lowercased(), c["signer"]?.lowercased(), message)
		}
	}

	private func decrypt(_ armor: String, with which: String) async throws -> (text: String, armorHash: String) {
		let priv = try XCTUnwrap(try keys()[which]?["privateArmored"])
		return try await call { done in host.decryptInboundArmor(privateKeyArmor: priv, armor: armor, completion: done) }
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
}
