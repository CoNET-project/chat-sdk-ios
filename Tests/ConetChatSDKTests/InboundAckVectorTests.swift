#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// EY, EZ, FA, FB, FG, FI, FT: the inbound vectors `inbound-ack-vectors.v1.json` (sixth version, registered,
/// 33 cases, replacing the fifth version `b8ff247c…`; the field `confirmed` is renamed `serverAcked`,)
/// run through `InboundFrameRule.decide`, the function the module applies. Every field a case expects is compared; an unknown field fails.
/// Synthetic fixtures only. The file's sha256 is checked against the registry before use. The file comes from INBOUND_ACK_VECTORS.
final class InboundAckVectorTests: XCTestCase {
	static let expectedSHA256 = "c7382cddccaa5153c81684440b1321b0261ee30c6dc8227437161af72d340811"
	static let expectedCases = 37

	/// IB-01 to IB-03: the browser path, not applicable to native.
	private static let browserPathCases: Set<String> = ["IB-01", "IB-02", "IB-03"]

	private static let knownExpectFields: Set<String> = [
		"displayed", "inboxWrites", "ackSent", "dedupeRecordWritten", "dedupeRecordKept", "frameRetainedOnServer",
		"callSignalDelivered", "armorRetainedLocally", "serverAcked", "recordEvictable", "retryAck",
		"markerWritten", "evicted", "recordCountAfter",
	]

	private func json(_ value: Any?) -> String {
		let v: Any = value ?? NSNull()
		let data = try! JSONSerialization.data(withJSONObject: v, options: [.sortedKeys, .fragmentsAllowed])
		return String(data: data, encoding: .utf8)!
	}

	private func input(_ c: [String: Any]) throws -> (InboundFrameRule.Input, String) {
		let fixture = try XCTUnwrap(c["fixture"] as? [String: Any])
		let frame = try XCTUnwrap(c["frame"] as? [String: Any])
		let hash = try XCTUnwrap(frame["armorHash"] as? String)
		var i = InboundFrameRule.Input()
		i.decrypt = InboundFrameRule.Decrypt(rawValue: try XCTUnwrap(fixture["decrypt"] as? String)) ?? .ok
		// "fail" is a row that is not JSON;: a JSON object missing `signMessage` or `text` is a signature failure (IC-03, IC-04).
		switch (fixture["parse"] as? String) ?? "ok" {
		case "fail": i.parse = .fail
		case "json-missing-signMessage", "json-missing-text": i.parse = .jsonMissingField
		// valid JSON that is not an object (IC-05 array, IC-06 string; a number and a boolean follow the same rule).
		case "json-array", "json-string", "json-number", "json-boolean": i.parse = .jsonNotObject
		default: i.parse = .ok
		}
		i.signatureValid = (frame["signatureValid"] as? Bool) ?? true
		i.inboxRead = InboundFrameRule.InboxRead(rawValue: (fixture["inboxRead"] as? String) ?? "ok") ?? .ok
		i.persist = InboundFrameRule.Persist(rawValue: (fixture["persist"] as? String) ?? "ok") ?? .ok
		i.dedupeKnown = ((fixture["dedupeRecords"] as? [String]) ?? []).contains(hash)
		if let signal = frame["callSignal"] as? [String: Any] {
			let key = BeamioConetChatCallLedger.key(
				callId: (signal["callId"] as? String) ?? "", sessionId: (signal["sessionId"] as? String) ?? ""
			)
			i.callSignalKey = key
			i.callSignalDelivered = ((fixture["callDeliveredKeys"] as? [String]) ?? []).contains(key)
		}
		i.pageAckInbound = (fixture["pageAckInbound"] as? Bool) ?? false
		i.drop = InboundFrameRule.Drop(rawValue: (frame["drop"] as? String) ?? "") ?? .none
		if let records = fixture["records"] as? [[String: Any]] {
			i.records = records.map { r in
				InboundFrameRule.RecordFact(
					armorHash: (r["armorHash"] as? String) ?? "",
					confirmed: (r["serverAcked"] as? Bool) ?? false,
					armorPresent: (r["armorPresent"] as? Bool) ?? false
				)
			}
		}
		i.capacity = (fixture["capacity"] as? Int) ?? 50000
		if let response = fixture["ackResponse"] as? [String: Any] {
			let status = response["status"] as? Int
			let body = response["body"]
			i.ackAnswer = InboundFrameRule.AckAnswer(status: status, body: (body is NSNull) ? nil : body)
		}
		return (i, hash)
	}

	/// The observed values for the fields a case may expect. Nil for an ack field when no answer was given.
	private func observed(_ o: InboundFrameRule.Outcome) -> [String: Any?] {
		[
			"displayed": o.displayed,
			"inboxWrites": o.inboxWrites,
			"ackSent": o.ackSent,
			"dedupeRecordWritten": o.dedupeRecordWritten,
			"dedupeRecordKept": o.dedupeRecordKept,
			"frameRetainedOnServer": o.frameRetainedOnServer,
			"callSignalDelivered": o.callSignalDelivered,
			"armorRetainedLocally": o.armorRetainedLocally,
			"serverAcked": o.ackConfirmed,
			"recordEvictable": o.recordEvictable,
			"retryAck": o.retryAck,
			"markerWritten": o.markerWritten,
			"evicted": o.evicted,
			"recordCountAfter": o.recordCountAfter,
		]
	}

	func testTheInboundAckVectorsMatchTheRule() throws {
		guard let path = ProcessInfo.processInfo.environment["INBOUND_ACK_VECTORS"] else {
			throw XCTSkip("set INBOUND_ACK_VECTORS to interface/protocol/inbound-ack-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(digest, Self.expectedSHA256, "the vector file differs from the registered digest")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, Self.expectedCases)

		var differing: [String] = []
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let (i, hash) = try input(c)
			let outcome = InboundFrameRule.decide(armorHash: hash, i)
			let have = observed(outcome)
			let expect = try XCTUnwrap(c["expect"] as? [String: Any], id)
			for key in expect.keys where !Self.knownExpectFields.contains(key) {
				XCTFail("\(id): the vector expects a field this test does not know: \(key)")
			}
			var ok = true
			var caseDiffering: [String] = []
			for key in expect.keys.sorted() where Self.knownExpectFields.contains(key) {
				let want = json([key: expect[key]!])
				let got = json([key: have[key] ?? nil])
				if want != got {
					ok = false
					caseDiffering.append("\(id).\(key): want \(want) got \(got)")
				}
			}
			// (audit): IB-01 to IB-03 are the browser path, not applicable to native. They are not counted as match; the rule
			// result is recorded only.
			if Self.browserPathCases.contains(id) {
				print("INBOUND-ACK-VECTOR \(id): not applicable; the rule result is recorded: \(ok ?"agrees" : "disagrees")")
			} else {
				print("INBOUND-ACK-VECTOR \(id): \(ok ? "match" : "differs")")
				differing += caseDiffering
			}
		}
		XCTAssertTrue(differing.isEmpty, differing.joined(separator: "\n"))
	}
}
#endif
