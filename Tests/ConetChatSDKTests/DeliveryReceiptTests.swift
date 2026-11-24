#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// DR-01..DR-14 (the delivery-receipt vectors): the native "delivered" receipt, driven through the bridge
/// commands `setRoutes` and `ackInbound`. The vectors are synthetic. The mailbox ack that precedes a receipt is not part of these cases.
final class DeliveryReceiptTests: XCTestCase {
	let eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
	private let keyHex = "78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd"
	private var store: GossipSignVectorTests.Store!
	private var savedStore: BeamioChatWalletKeyStoring!
	let peer = "0x00000000000000000000000000000000000000b2"
	let armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----"

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = GossipSignVectorTests.Store()
		var key = Data()
		var i = keyHex.startIndex
		while i < keyHex.endIndex { let j = keyHex.index(i, offsetBy: 2); key.append(UInt8(keyHex[i..<j], radix: 16)!); i = j }
		store.keys[eoa] = key
		BeamioNativeWallet.keyStore = store
		restoreG2 = WalletG2Gate.enter(account: eoa)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		BeamioConetChatModule.testCurrentSession()?.clearReceiptState()
		sent = []
		releases = []
		autoRelease = true
		BeamioConetChatModule.receiptSendHook = { [unowned self] body, release in
			self.sent.append(body)
			self.inFlightPeak = max(self.inFlightPeak, self.sent.count - self.releasedCount)
			if self.autoRelease { self.releasedCount += 1; release() } else { self.releases.append(release) }
		}
		releasedCount = 0
		inFlightPeak = 0
	}

	override func tearDown() {
		BeamioConetChatModule.receiptSendHook = nil
		restoreG2?()
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	var sent: [[String: Any]] = []
	var restoreG2: (() -> Void)?
	var releases: [() -> Void] = []
	var autoRelease = true
	var releasedCount = 0
	var inFlightPeak = 0

	private func entry(_ who: String, user: String? = nil) -> [String: Any] {
		["eoaAddress": who, "userPublicKeyArmored": user ?? armor, "routerArmoredPublicKey": armor]
	}

	@discardableResult
	private func setRoutes(eoa account: String?, routes: Any, reqId: Int = 901) -> [String: Any]? {
		var body: [String: Any] = ["type": "setRoutes", "reqId": reqId, "routes": routes]
		if let account { body["eoa"] = account }
		var answer: [String: Any]?
		let done = expectation(description: "setRoutes ack")
		BeamioConetChatModule.handleCommand(body, emit: { event in
			let inner = (event["event"] as? [String: Any]) ?? event
			if inner["type"] as? String == "ack", inner["reqId"] as? Int == reqId {
				answer = inner
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		return answer
	}

	func message(sendId: String?, text: String = "hello", extra: [String: Any] = [:]) -> String {
		var payload: [String: Any] = ["from": "me", "text": text, "createdAt": 1]
		if let sendId { payload["sendId"] = sendId }
		for (k, v) in extra { payload[k] = v }
		let payloadJson = String(data: try! JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
		let outer: [String: Any] = ["timestamp": 1, "text": payloadJson, "from": peer, "signMessage": "0xsig"]
		return String(data: try! JSONSerialization.data(withJSONObject: outer), encoding: .utf8)!
	}

	private func ackInbound(_ hash: String, _ plaintext: String) {
		BeamioConetChatModule.testStagePending(armorHash: hash, plaintext: plaintext, from: peer)
		BeamioConetChatModule.handleCommand(["type": "ackInbound", "reqId": 902, "armorHashes": [hash]], emit: { _ in })
	}

	func testDR01_ackAfterSetRoutesSendsOneReceipt() throws {
		let a = setRoutes(eoa: eoa, routes: [entry(peer)]); XCTAssertEqual(a?["ok"] as? Bool, true, "\(String(describing: a))")
		ackInbound("h1", message(sendId: "S1"))
		XCTAssertEqual(sent.count, 1)
		let outer = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data((try XCTUnwrap(sent.first)["payload"] as! String).utf8)) as? [String: Any])
		let inner = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data((outer["text"] as! String).utf8)) as? [String: Any])
		XCTAssertEqual(inner["sendId"] as? String, "S1")
		XCTAssertEqual(inner["armorHash"] as? String, "h1")
	}

	func testDR02_aReceiptIsNotReceipted() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let receipt = "{\"type\":\"beamio_chat_delivery_receipt_v1\",\"sendId\":\"S1\",\"armorHash\":\"x\",\"deliveredAt\":1,\"from\":\"\(peer)\"}"
		ackInbound("h2", message(sendId: UUID().uuidString, text: receipt))
		XCTAssertEqual(sent.count, 0)
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 0)
	}

	func testDR03_callControlIsNotReceipted() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let call = "{\"type\":\"voice_end_v1\",\"callId\":\"c1\",\"sessionId\":\"s1\",\"from\":\"\(peer)\"}"
		ackInbound("h3", message(sendId: "S3", text: call))
		XCTAssertEqual(sent.count, 0)
	}

	func testDR04_voiceFrameAndOtherControlsAreNotReceipted() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("h4a", message(sendId: "S4", text: "{\"type\":\"voice_frame\"}"))
		ackInbound("h4b", message(sendId: "S4b", text: "{\"type\":\"reaction\",\"emoji\":\"x\"}"))
		ackInbound("h4c", message(sendId: "S4c", text: "{\"type\":\"recall\",\"sendId\":\"old\"}"))
		ackInbound("h4d", message(sendId: "S4d", text: "{\"type\":\"file_control\"}"))
		ackInbound("h4e", message(sendId: "S4e", extra: ["groupId": "g1"]))
		XCTAssertEqual(sent.count, 0)
	}

	func testDR05_theSameArmorHashIsReceiptedOnce() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let m = message(sendId: "S5")
		ackInbound("h5", m)
		ackInbound("h5", m)
		XCTAssertEqual(sent.count, 1)
	}

	func testDR06_aMissingRouteQueuesTheReceipt() {
		ackInbound("h6", message(sendId: "S6"))
		XCTAssertEqual(sent.count, 0)
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 1)
	}

	func testDR07_aLaterSetRoutesFlushesTheQueue() {
		ackInbound("h7", message(sendId: "S7"))
		setRoutes(eoa: eoa, routes: [entry(peer)])
		XCTAssertEqual(sent.count, 1)
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 0)
	}

	func testDR08_anExpiredQueueEntryIsNotSent() {
		ackInbound("h8", message(sendId: "S8"))
		BeamioConetChatModule.testAgeReceiptQueue(by: 601)
		setRoutes(eoa: eoa, routes: [entry(peer)])
		XCTAssertEqual(sent.count, 0)
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 0)
	}

	func testDR09_theQueueKeeps128AndDropsTheOldest() {
		for i in 0..<129 { ackInbound("q\(i)", message(sendId: "S\(i)")) }
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 128)
		setRoutes(eoa: eoa, routes: [entry(peer)])
		XCTAssertEqual(sent.count, 128)
		let ids = sent.compactMap { (try? JSONSerialization.jsonObject(with: Data(($0["payload"] as! String).utf8)) as? [String: Any])?["text"] as? String }
		XCTAssertFalse(ids.contains { $0.contains("\"armorHash\":\"q0\"") })
	}

	func testDR10_aForeignEoaIsRefusedAndRoutesStay() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let answer = setRoutes(eoa: "0x00000000000000000000000000000000000000ff", routes: [])
		XCTAssertEqual(answer?["ok"] as? Bool, false)
		XCTAssertEqual(answer?["error"] as? String, "signer_mismatch")
		XCTAssertEqual(BeamioConetChatModule.testCurrentSession()?.routes.count, 1)
		XCTAssertEqual(setRoutes(eoa: nil, routes: [])?["error"] as? String, "bad_request")
	}

	func testDR11_aDestroyedSessionHoldsNoRoutesAndNoQueue() {
		let old = BeamioConetChatModule.testCurrentSession()
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("h11a", message(sendId: "S11a"))
		XCTAssertEqual(sent.count, 1)
		old?.receiptLock.lock()
		old?.receiptQueue.append((peer, "S11", "h11", Date(), BeamioInboxIO.generation))
		old?.receiptLock.unlock()
		BeamioConetChatModule.testDestroySession()
		sent = []
		XCTAssertEqual(old?.routes.count, 0)
		XCTAssertEqual(old?.receiptQueue.count, 0)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		ackInbound("h11b", message(sendId: "S11b"))
		XCTAssertEqual(sent.count, 0)
	}

	func testDR12_badEntriesAreDroppedAndOverLimitChangesNothing() {
		let bad = entry(peer, user: "no armor here")
		setRoutes(eoa: eoa, routes: [entry(peer), bad, ["junk": 1], "str"])
		XCTAssertEqual(BeamioConetChatModule.testCurrentSession()?.routes.count, 1)
		let many = (0..<257).map { entry(String(format: "0x%040x", $0 + 1)) }
		let over = setRoutes(eoa: eoa, routes: many)
		XCTAssertEqual(over?["error"] as? String, "bad_request")
		XCTAssertEqual(BeamioConetChatModule.testCurrentSession()?.routes.count, 1)
		let huge = armor + String(repeating: "A", count: 33 * 1024)
		let big = setRoutes(eoa: eoa, routes: [entry(peer, user: huge)])
		XCTAssertEqual(big?["error"] as? String, "bad_request")
		XCTAssertEqual(BeamioConetChatModule.testCurrentSession()?.routes.count, 1)
		XCTAssertEqual(setRoutes(eoa: eoa, routes: [])?["ok"] as? Bool, true)
	}

	func testDR13_anEmptySendIdIsNotReceipted() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("h13a", message(sendId: nil))
		ackInbound("h13b", message(sendId: ""))
		XCTAssertEqual(sent.count, 0)
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 0)
	}

	func testDR14_theReceiptFormat() throws {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("h14", message(sendId: "S14", text: "secret words"))
		let one = try XCTUnwrap(sent.first)
		XCTAssertEqual(one["beamioNoPush"] as? Bool, true)
		let payload = try XCTUnwrap(one["payload"] as? String)
		XCTAssertFalse(payload.contains("secret words"))
		let outer = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any])
		XCTAssertEqual(Set(outer.keys), ["sendId", "from", "text", "createdAt"])
		XCTAssertEqual(outer["from"] as? String, "me")
		let inner = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data((outer["text"] as! String).utf8)) as? [String: Any])
		XCTAssertEqual(Set(inner.keys), ["type", "sendId", "armorHash", "deliveredAt", "from"])
		XCTAssertEqual(inner["type"] as? String, "beamio_chat_delivery_receipt_v1")
		XCTAssertEqual(inner["from"] as? String, eoa)
	}
	func testDR15_setRoutesAlwaysAnswers() {
		let good = setRoutes(eoa: eoa, routes: [entry(peer), ["junk": 1]], reqId: 910)
		XCTAssertEqual(good?["ok"] as? Bool, true)
		let result = good?["result"] as? [String: Any]
		XCTAssertEqual(result?["accepted"] as? Int, 1)
		XCTAssertEqual(result?["dropped"] as? Int, 1)
		XCTAssertEqual(setRoutes(eoa: eoa, routes: "nope", reqId: 911)?["error"] as? String, "bad_request")
		XCTAssertEqual(BeamioConetChatModule.testCurrentSession()?.routes.count, 1)
		XCTAssertEqual(setRoutes(eoa: nil, routes: [], reqId: 912)?["error"] as? String, "bad_request")
		XCTAssertEqual(setRoutes(eoa: "0x00000000000000000000000000000000000000ff", routes: [], reqId: 913)?["error"] as? String, "signer_mismatch")
		XCTAssertEqual(BeamioConetChatModule.testCurrentSession()?.routes.count, 1)
		// no session: always answered, never silent (here the gate answers before the command)
		BeamioConetChatModule.testDestroySession()
		let none = setRoutes(eoa: eoa, routes: [], reqId: 914)
		XCTAssertNotNil(none)
		XCTAssertEqual(none?["ok"] as? Bool, false)
	}

	func testDR16_theSameFromAndSendIdIsReceiptedOnce() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("h16a", message(sendId: "S16"))
		ackInbound("h16b", message(sendId: "S16"))
		ackInbound("h16c", message(sendId: "S16"))
		XCTAssertEqual(sent.count, 1)
		let s = BeamioConetChatModule.testCurrentSession()
		for i in 0..<1100 { ackInbound("k\(i)", message(sendId: "K\(i)")) }
		XCTAssertLessThanOrEqual(s?.receiptedKeys.count ?? 0, 1024)
	}

	func testDR17_atMostTwoReceiptsAreInFlight() {
		autoRelease = false
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let hashes = (0..<5).map { "f\($0)" }
		for h in hashes { BeamioConetChatModule.testStagePending(armorHash: h, plaintext: message(sendId: "I-" + h), from: peer) }
		BeamioConetChatModule.handleCommand(["type": "ackInbound", "reqId": 920, "armorHashes": hashes], emit: { _ in })
		XCTAssertEqual(sent.count, 2)
		var guardLoop = 0
		while !releases.isEmpty, guardLoop < 20 {
			let r = releases.removeFirst()
			releasedCount += 1
			r()
			XCTAssertLessThanOrEqual(sent.count - releasedCount, 2)
			guardLoop += 1
		}
		XCTAssertEqual(sent.count, 5)
		XCTAssertLessThanOrEqual(inFlightPeak, 2)
	}

	func testDR18_whitelistRejectsUnknownAndControlTypes() {
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let typed = [
			"{\"type\":\"beamio_chat_delivery_receipt_v1\",\"sendId\":\"R\"}",
			"{\"type\":\"voice_end_v1\",\"callId\":\"c\",\"sessionId\":\"s\",\"from\":\"\(peer)\"}",
			"{\"type\":\"voice_frame\"}",
			"{\"type\":\"some_future_type\"}",
			"{\"type\":\"system_notice\"}",
		]
		for (i, t) in typed.enumerated() { ackInbound("w\(i)", message(sendId: "W\(i)", text: t)) }
		ackInbound("wt", message(sendId: "WT", extra: ["type": "some_future_type"]))
		XCTAssertEqual(sent.count, 0)
		XCTAssertEqual(BeamioConetChatModule.testPendingAckCount(), 0)
		ackInbound("wok", message(sendId: "WOK"))
		XCTAssertEqual(sent.count, 1)
	}

	/// DR-21: the capability is declared, last of the shipped list, in every build; and the parts it promises all hold in this build.
	func testDR21_theCapabilityIsDeclaredAndItsPartsHold() throws {
		let caps = BeamioConetChatProtocol.capabilities
		XCTAssertEqual(caps.filter { $0 == "receipt.delivery.v1" }.count, 1)
		XCTAssertEqual(caps.firstIndex(of: "receipt.delivery.v1"), caps.firstIndex(of: "wallet.passcode.v1")! + 1)
		XCTAssertTrue((BeamioConetChatProtocol.helloResult()["capabilities"] as? [String] ?? []).contains("receipt.delivery.v1"))
		// the promised parts: answer and eoa check, whitelist, dedupe, in-flight limit, queue limit, clear (each also has its own DR case)
		XCTAssertEqual(setRoutes(eoa: nil, routes: [])?["error"] as? String, "bad_request")
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: message(sendId: "S", extra: ["type": "x"])))
		XCTAssertEqual(BeamioConetChatModule.receiptMaxInFlight, 2)
		XCTAssertEqual(BeamioConetChatModule.receiptQueueMax, 128)
		XCTAssertEqual(BeamioConetChatModule.receiptQueueTTL, 600)
		XCTAssertEqual(BeamioConetChatModule.setRoutesMaxEntries, 256)
		XCTAssertEqual(BeamioConetChatModule.setRoutesMaxArmorBytes, 32 * 1024)
	}

	// MARK: - DR-23..30: what an ordinary chat message is

	private func eligible(_ sendId: String?, text: String = "hi", extra: [String: Any] = [:]) -> String? {
		BeamioConetChatModule.receiptEligibleSendId(plaintext: message(sendId: sendId, text: text, extra: extra))
	}

	func testDR23_aTextMessageIsReceipted() { XCTAssertEqual(eligible("S1"), "S1") }

	func testDR24_aQuoteReplyIsReceipted() {
		XCTAssertEqual(eligible("S2", extra: ["quote": ["id": "x", "text": "t", "from": peer]]), "S2")
	}

	func testDR25_aVoiceMessageIsReceiptedAndItsNestedTypeDoesNotExclude() {
		XCTAssertEqual(eligible("S3", text: "", extra: ["voiceMessage": ["type": "voice", "fragmentHash": "ab", "durationMs": 1200]]), "S3")
	}

	func testDR26_filesImagesVideosPdfsAndArchivesAreReceipted() {
		for kind in ["image", "video", "pdf", nil] as [String?] {
			var manifest: [String: Any] = ["type": "file", "name": "a"]
			if let kind { manifest["mediaKind"] = kind }
			XCTAssertEqual(eligible("F-\(kind ?? "none")", text: "", extra: ["fileMessage": manifest]), "F-\(kind ?? "none")")
		}
	}

	func testDR27_aPaymentCardIsReceipted() {
		XCTAssertEqual(eligible("P1", extra: ["paymentCard": ["amount": "1"]]), "P1")
	}

	func testDR28_controlsAndRecordsAreNotReceipted() {
		for replyType in ["reaction", "paymentRequestCancel", "paymentRequestPaid"] {
			XCTAssertNil(eligible("C-\(replyType)", extra: ["reply": ["replyType": replyType]]), replyType)
		}
		XCTAssertNil(eligible("CR", extra: ["callRecord": ["callId": "c"]]))
		XCTAssertNil(eligible("CT", extra: ["type": "anything"]))
		XCTAssertNil(eligible("CG", extra: ["groupId": "g"]))
	}

	func testDR29_nestedLayers() throws {
		func wrap(_ inner: String, sendId: String?) -> String {
			var payload: [String: Any] = ["text": inner]
			if let sendId { payload["sendId"] = sendId }
			let json = String(data: try! JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
			return json
		}
		let receipt = "{\"type\":\"beamio_chat_delivery_receipt_v1\",\"sendId\":\"in\"}"
		let reply = "{\"sendId\":\"in\",\"reply\":{\"replyType\":\"reaction\"},\"text\":\"x\"}"
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: wrap(receipt, sendId: "out")))
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: wrap(reply, sendId: "out")))
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: wrap("{\"sendId\":\"in\",\"text\":\"hello\"}", sendId: "out")), "out")
		// layer 1 must carry the sendId; an inner one does not stand in for it
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: wrap("{\"sendId\":\"in\",\"text\":\"hello\"}", sendId: nil)))
		// depth: 6 layers pass, 7 do not
		func deep(_ n: Int) -> String {
			var text = "hello"
			for level in stride(from: n, to: 0, by: -1) {
				text = wrap(text, sendId: level == 1 ? "top" : nil)
			}
			return text
		}
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: deep(6)), "top")
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: deep(7)))
	}

	func testDR30_noSendIdPlainTextNonJsonAndNonObjectAreNotReceipted() {
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: "hello"))
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: "[1,2]"))
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: "not json {"))
		XCTAssertNil(eligible(""))
		XCTAssertNil(eligible(nil))
	}

	// MARK: - DR-31..35: leaf and depth

	private func payloadWrap(_ inner: String, sendId: String?) -> String {
		var payload: [String: Any] = ["text": inner]
		if let sendId { payload["sendId"] = sendId }
		return String(data: try! JSONSerialization.data(withJSONObject: payload), encoding: .utf8)!
	}

	/// n nested object layers, the innermost holding `leaf`, the first carrying the sendId.
	private func layers(_ n: Int, leaf: String = "hello") -> String {
		var text = leaf
		for level in stride(from: n, to: 0, by: -1) { text = payloadWrap(text, sendId: level == 1 ? "top" : nil) }
		return text
	}

	func testDR31_aFirstLayerThatIsNotAnObjectIsNotReceipted() {
		for v in ["[1,2]", "\"s\"", "123", "true", "null", "plain"] {
			XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: v), v)
		}
	}

	func testDR32_aLeafThatIsNotAnObjectIsUserText() {
		for leaf in ["[1,2]", "123", "true", "null", "plain"] {
			XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: payloadWrap(leaf, sendId: "S")), "S", leaf)
			// the same inside the signed envelope
			XCTAssertEqual(eligible("S", text: leaf), "S", leaf)
		}
	}

	func testDR33_exactlySixObjectLayersAreReceipted() {
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: layers(6)), "top")
		// the signed envelope is not a layer: six payload layers inside it are also receipted
		let envelope: [String: Any] = ["timestamp": 1, "text": layers(6), "from": peer, "signMessage": "0xsig"]
		let json = String(data: try! JSONSerialization.data(withJSONObject: envelope), encoding: .utf8)!
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: json), "top")
	}

	func testDR34_theSeventhObjectLayerIsNotReceipted() {
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: layers(7)))
		let envelope: [String: Any] = ["timestamp": 1, "text": layers(7), "from": peer, "signMessage": "0xsig"]
		let json = String(data: try! JSONSerialization.data(withJSONObject: envelope), encoding: .utf8)!
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: json))
	}

	func testDR35_aReceiptHiddenDeepIsNotReceipted() {
		let receipt = "{\"type\":\"beamio_chat_delivery_receipt_v1\",\"sendId\":\"in\"}"
		// the receipt object is the 6th layer
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: layers(5, leaf: receipt)))
		// the receipt object is the 7th layer
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: layers(6, leaf: receipt)))
	}

	// MARK: - DR-36..38: the envelope is not a layer; layer 1 carries its own sendId

	private func inEnvelope(_ text: String) -> String {
		let envelope: [String: Any] = ["timestamp": 1, "text": text, "from": peer, "signMessage": "0xsig"]
		return String(data: try! JSONSerialization.data(withJSONObject: envelope), encoding: .utf8)!
	}

	func testDR36_layersCountFromTheEnvelopeText() {
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(layers(6))), "top")
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(layers(7))))
	}

	func testDR37_anInnerSendIdDoesNotStandInForLayer1() {
		let inner = "{\"sendId\":\"in\",\"text\":\"hello\"}"
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(payloadWrap(inner, sendId: nil))))
	}

	func testDR38_anEnvelopeTextThatIsNotAnObjectIsNotReceipted() {
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope("plain text")))
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope("[1,2]")))
	}

	// MARK: - clear paths of the receipt state

	/// An account switch (`clearAndMark`, through `enterIdentity`) empties the routes, the queue and the dedupe sets.
	func testAnAccountSwitchClearsRoutesAndQueue() throws {
		let session = try XCTUnwrap(BeamioConetChatModule.testCurrentSession())
		setRoutes(eoa: eoa, routes: [entry(peer)])
		let other = "0x00000000000000000000000000000000000000c3"
		ackInbound("sw1", message(sendId: "SW1"))      // receipted through the route
		session.receiptLock.lock()
		session.receiptQueue.append((other, "SWQ", "swq", Date(), BeamioInboxIO.generation))
		session.receiptLock.unlock()
		XCTAssertEqual(session.routes.count, 1)
		XCTAssertFalse(session.receiptedKeys.isEmpty)
		XCTAssertTrue(BeamioInboxOwner.write(eoa))
		defer { BeamioInboxOwner.remove(); BeamioConetChatInboxStore.clear(); BeamioConetChatCallLedger.clear() }
		XCTAssertTrue(BeamioConetChatModule.enterIdentity(other))
		XCTAssertEqual(session.routes.count, 0)
		XCTAssertEqual(session.receiptQueue.count, 0)
		XCTAssertTrue(session.receiptedKeys.isEmpty)
		XCTAssertTrue(session.receiptedHashes.isEmpty)
		// and nothing is sent to the old contact afterwards
		sent = []
		ackInbound("sw2", message(sendId: "SW2"))
		XCTAssertEqual(sent.count, 0)
	}

	/// A queued receipt of an earlier generation is dropped at flush, even when a route for its sender exists.
	func testAStaleGenerationReceiptIsDroppedAtFlush() throws {
		let session = try XCTUnwrap(BeamioConetChatModule.testCurrentSession())
		session.routes = [["eoaAddress": peer, "userPublicKeyArmored": armor, "routerArmoredPublicKey": armor]]
		session.receiptLock.lock()
		session.receiptQueue.append((peer, "STALE", "stale", Date(), BeamioInboxIO.generation &- 1))
		session.receiptQueue.append((peer, "FRESH", "fresh", Date(), BeamioInboxIO.generation))
		session.receiptLock.unlock()
		BeamioConetChatModule.testFlushReceipts(now: Date())
		XCTAssertEqual(sent.count, 1)
		let text = (sent.first?["payload"] as? String) ?? ""
		XCTAssertTrue(text.contains("fresh"))
		XCTAssertFalse(text.contains("stale"))
		XCTAssertEqual(BeamioConetChatModule.testReceiptQueueCount(), 0)
	}

	// MARK: - DR-39..41: exclusion wins; the innermost object counts

	func testDR39_aLeafObjectWithAnExcludedFieldIsNotReceipted() {
		for leaf in ["{\"type\":\"x\"}", "{\"groupId\":\"g\"}", "{\"reply\":{}}", "{\"callRecord\":{}}"] {
			XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: payloadWrap(leaf, sendId: "S")), leaf)
			XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(payloadWrap(leaf, sendId: "S"))), leaf)
		}
	}

	func testDR40_aLeafObjectWithoutExcludedFieldsIsUserText() {
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: payloadWrap("{\"a\":1}", sendId: "S")), "S")
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(payloadWrap("{\"a\":1}", sendId: "S"))), "S")
	}

	func testDR41_theInnermostObjectCountsAsALayer() {
		// five wrapping layers plus the innermost object make six: receipted
		XCTAssertEqual(BeamioConetChatModule.receiptEligibleSendId(plaintext: layers(5, leaf: "{\"a\":1}")), "top")
		// six wrapping layers whose text yields a seventh object: not receipted
		XCTAssertNil(BeamioConetChatModule.receiptEligibleSendId(plaintext: layers(6, leaf: "{\"a\":1}")))
	}

	// MARK: - DR-42..44: "carries" means the key exists with a non-null value; exact key names)

	private func receipted(leaf: String) -> Bool {
		BeamioConetChatModule.receiptEligibleSendId(plaintext: payloadWrap(leaf, sendId: "S")) == "S"
			&& BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(payloadWrap(leaf, sendId: "S"))) == "S"
	}

	private func refused(leaf: String) -> Bool {
		BeamioConetChatModule.receiptEligibleSendId(plaintext: payloadWrap(leaf, sendId: "S")) == nil
			&& BeamioConetChatModule.receiptEligibleSendId(plaintext: inEnvelope(payloadWrap(leaf, sendId: "S"))) == nil
	}

	func testDR42_anExcludedFieldWithANullValueIsNotCarried() {
		for leaf in ["{\"type\":null}", "{\"reply\":null}", "{\"groupId\":null}", "{\"callRecord\":null}"] {
			XCTAssertTrue(receipted(leaf: leaf), leaf)
		}
	}

	func testDR43_anExcludedFieldWithAnyNonNullValueIsCarried() {
		for leaf in ["{\"type\":\"\"}", "{\"type\":0}", "{\"type\":false}", "{\"reply\":{}}", "{\"callRecord\":[]}"] {
			XCTAssertTrue(refused(leaf: leaf), leaf)
		}
	}

	func testDR44_keyNamesMatchExactly() {
		for leaf in ["{\"typeOf\":1}", "{\"Type\":\"x\"}"] {
			XCTAssertTrue(receipted(leaf: leaf), leaf)
		}
	}

	/// A deferAck page's session takes a send only with an inboundGeneration; the receipt send must carry it (the receipt was otherwise answered
	/// bad_request on reqId -1 and never left).
	func testTheReceiptSendCarriesTheInboundGenerationAForDeferAckSessionNeeds() throws {
		let session = try XCTUnwrap(BeamioConetChatModule.testCurrentSession())
		session.deferAck = true
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("g1", message(sendId: "G1"))
		let body = try XCTUnwrap(sent.first)
		XCTAssertEqual(BeamioConetChatModule.initiationGeneration(session, body: body), BeamioInboxIO.generation)
		XCTAssertEqual(body["reqId"] as? Int, -1)
		// the guard: without the field the same session refuses the send
		var without = body
		without["inboundGeneration"] = nil
		XCTAssertNil(BeamioConetChatModule.initiationGeneration(session, body: without))
	}

	/// The real path (no send hook) for a deferAck session: the receipt gets past the generation check and asks for its signature, and its
	/// in-flight place is freed when the send ends (here: the signature fails).
	func testARealReceiptSendOfADeferAckSessionReachesTheSignatureAndFreesItsPlace() throws {
		BeamioConetChatModule.receiptSendHook = nil
		let session = try XCTUnwrap(BeamioConetChatModule.testCurrentSession())
		session.deferAck = true
		var signRequests = 0
		let signed = expectation(description: "the receipt asked for its signature")
		BeamioConetChatSignBroker.testSignature = { _, completion in
			signRequests += 1
			signed.fulfill()
			completion(.failure(BeamioConetChatSignBroker.SignError.signFailed))
		}
		defer { BeamioConetChatSignBroker.testSignature = nil }
		setRoutes(eoa: eoa, routes: [entry(peer)])
		ackInbound("real1", message(sendId: "REAL1"))
		wait(for: [signed], timeout: 20)
		XCTAssertEqual(signRequests, 1)
		// the answer frees the place (not the 60 s watchdog)
		let freed = expectation(description: "the in-flight place is freed")
		func poll(_ left: Int) {
			session.receiptLock.lock(); let n = session.receiptInFlight; session.receiptLock.unlock()
			if n == 0 { freed.fulfill() } else if left > 0 { DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) { poll(left - 1) } }
		}
		poll(100)
		wait(for: [freed], timeout: 10)
	}
}
#endif
