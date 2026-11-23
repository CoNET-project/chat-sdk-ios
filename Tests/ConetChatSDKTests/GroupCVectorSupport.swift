import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Shared by the group C tests. One row of `pgp-bridge-command-vectors.v1.json` is compared field by field with the answers the bridge
/// gave for the row's own reqId. The digest is the registered one. Values are never printed: only the names of the fields
/// that differ are returned. Synthetic data only.
enum GroupCVector {
	static let expectedSHA256 = "d5b032d274192088e82d52f1529c42f3eb766e9e8b43b50429935ec5abba51d0"

	/// One row of group C, by its id (`C-01` to `C-29`). The file comes from PGP_BRIDGE_VECTORS, and its digest is checked.
	static func row(_ id: String) throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_BRIDGE_VECTORS"] else {
			throw XCTSkip("set PGP_BRIDGE_VECTORS to interface/protocol/pgp-bridge-command-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == expectedSHA256,
		              "the pgp-bridge vector file differs from the registered digest (the digest is not printed)")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return try XCTUnwrap(cases.first { $0["id"] as? String == id }, id)
	}

	/// Each key the vector expects must equal the answer's value. A vector `null` needs an absent or null value. Returns the names of the keys that differ.
	static func fieldDifferences(_ expected: [String: Any], in got: [String: Any]) -> [String] {
		var differing: [String] = []
		for key in expected.keys.sorted() {
			let want: Any = expected[key] ?? NSNull()
			let have = got[key]
			let haveIsNull = have == nil || have is NSNull
			if want is NSNull {
				if !haveIsNull { differing.append(key) }
			} else if let flag = want as? Bool {
				if (have as? Bool) != flag { differing.append(key) }
			} else if let text = want as? String {
				if (have as? String) != text { differing.append(key) }
			}
		}
		return differing
	}

	/// The key sets must be equal: a key the vector does not list, or a key it lists and the answer lacks, is a difference.
	static func keySetDifferences(_ expected: [String: Any], in got: [String: Any]) -> [String] {
		let missing = Set(expected.keys).subtracting(got.keys).sorted().map { "missing:\($0)" }
		let extra = Set(got.keys).subtracting(expected.keys).sorted().map { "extra:\($0)" }
		return missing + extra
	}

	/// The answers for one row, in the order the bridge gave them, with the row's reqId. The ack is compared with `expect.ack` (its `result` too), and
	/// the other events with `expect.events`, in order. Each object must also have exactly the keys the vector lists. Returns the differing field names,
	/// prefixed by `ack.`, `result.` or `event.`. Empty when they match.
	static func differences(row: [String: Any], answers: [[String: Any]]) throws -> [String] {
		let id = row["id"] as? String ?? "?"
		let expect = try XCTUnwrap(row["expect"] as? [String: Any], id)
		let expectedAck = try XCTUnwrap(expect["ack"] as? [String: Any], id)
		var differing: [String] = []
		let acks = answers.filter { $0["type"] as? String == "ack" }
		if acks.count != 1 {
			differing.append("ack.count=\(acks.count)")
		}
		let ack = acks.first ?? [:]
		differing += fieldDifferences(expectedAck, in: ack).map { "ack.\($0)" }
		differing += keySetDifferences(expectedAck, in: ack).map { "ack.\($0)" }
		if let result = expectedAck["result"] as? [String: Any] {
			differing += fieldDifferences(result, in: ack["result"] as? [String: Any] ?? [:]).map { "ack.result.\($0)" }
			differing += keySetDifferences(result, in: ack["result"] as? [String: Any] ?? [:]).map { "ack.result.\($0)" }
		}
		let expectedEvents = expect["events"] as? [[String: Any]] ?? []
		let events = answers.filter { $0["type"] as? String != "ack" }
		if events.count != expectedEvents.count {
			differing.append("event.count=\(events.count) (expected \(expectedEvents.count))")
		}
		for (answer, want) in zip(events, expectedEvents) {
			differing += fieldDifferences(want, in: answer).map { "event.\($0)" }
			differing += keySetDifferences(want, in: answer).map { "event.\($0)" }
		}
		return differing
	}
}
