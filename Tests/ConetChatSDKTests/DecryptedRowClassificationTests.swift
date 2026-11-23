#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// a decrypted row is classified as not JSON, JSON that is not an object, or an object, and only
/// an object can verify. A field of the wrong type is bad_request for an old page too. Synthetic data only.
final class DecryptedRowClassificationTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		events = []
	}

	func testTheShapeOfADecryptedRow() {
		XCTAssertEqual(BeamioConetChatModule.inboundShape("not json"), .notJSON, "not JSON: the marker path")
		XCTAssertEqual(BeamioConetChatModule.inboundShape(""), .notJSON)
		XCTAssertEqual(BeamioConetChatModule.inboundShape("[1,2]"), .notObject, "a JSON array: a signature failure")
		XCTAssertEqual(BeamioConetChatModule.inboundShape("\"text\""), .notObject, "a JSON string: a signature failure")
		XCTAssertEqual(BeamioConetChatModule.inboundShape("42"), .notObject, "a JSON number: a signature failure")
		XCTAssertEqual(BeamioConetChatModule.inboundShape("true"), .notObject, "a JSON boolean: a signature failure")
		XCTAssertEqual(BeamioConetChatModule.inboundShape("{\"text\":\"x\"}"), .object)
	}

	/// An old page (no deferAck) that sends the field with a wrong type: bad_request, nothing signed, nothing sent.
	func testAnOldPageSendWithAWrongTypeFieldIsBadRequest() {
		startOldPage()
		let pgp = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----"
		let body: [String: Any] = [
			"reqId": 401, "payload": "{\"text\":\"hi\"}", "sendId": "r993-401", "inboundGeneration": "2",
			"to": ["userPublicKeyArmored": pgp, "routerArmoredPublicKey": pgp] as [String: Any],
		]
		BeamioConetChatModule.testSend(body)
		drainMain()
		XCTAssertEqual(ackErrors(401), ["bad_request"])
	}

	/// The same old page's gossipSign envelope with a wrong-type field: bad_request, nothing signed.
	func testAnOldPageEnvelopeWithAWrongTypeFieldIsBadRequest() {
		startOldPage()
		BeamioConetChatModule.testGossipSign(["reqId": 402, "kind": "envelope", "message": "hello", "inboundGeneration": 2.5])
		drainMain()
		XCTAssertEqual(ackErrors(402), ["bad_request"])
	}

	private func startOldPage() {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioConetChatModule.testCurrentSession()?.deferAck = false
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	private func ackErrors(_ reqId: Int) -> [String?] {
		events.compactMap { out -> String?? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack",
			      event["reqId"] as? Int == reqId else { return nil }
			return .some(event["error"] as? String)
		}
	}

	private func drainMain() {
		let e = expectation(description: "main drained")
		DispatchQueue.main.async { e.fulfill() }
		wait(for: [e], timeout: 10)
	}
}
#endif
