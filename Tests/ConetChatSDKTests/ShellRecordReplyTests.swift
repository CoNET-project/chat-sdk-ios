import XCTest
@testable import ConetChatSDK

/// The reply rules of the record bridge (RP-01 to RP-08b, spec to) and the native origin boundary (OR-01 to OR-03,)
/// of `pgp-migration-vectors.v1.json`. The reply rules run against the page-side reference, the boundary against the SDK. Synthetic data only.
final class ShellRecordReplyTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			records[account] = record
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	/// Canonical JSON, so that the outcomes can be compared with the vector's expectations regardless of key order.
	private func canonical(_ value: Any?) -> String {
		// A bare scalar is not a valid top-level JSON object: it is wrapped in an array, and the brackets are removed. Without this every scalar
		// compared as "invalid" on both sides, so it always matched.
		guard let value else { return "null" }
		guard JSONSerialization.isValidJSONObject([value]),
		      let data = try? JSONSerialization.data(withJSONObject: [value], options: [.sortedKeys]),
		      let text = String(data: data, encoding: .utf8)
		else { return "invalid" }
		return String(text.dropFirst().dropLast())
	}

	private func time(_ value: Any?) -> Double {
		(value as? NSNumber)?.doubleValue ?? 0
	}

	private func environment(account: String, allowed: Bool) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { account },
			store: Store(),
			device: Device(),
			originAllowed: allowed,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	/// RP-01 to RP-08b. Each case replays its events in order, at their times, and the outcomes must equal the expectation.
	func testTheReplyRulesMatchTheVectors() throws {
		let cases = try vectorRoot()["replyCases"] as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 9)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			if c["kind"] as? String == "mayWrite" {
				let allowed = BeamioShellRecordReply.writeAfterTimeout(readCompletedSinceTimeout: c["readCompletedSinceTimeout"] as? Bool ?? false)
				XCTAssertEqual(allowed, c["expect"] as? String, id)
				continue
			}
			let correlator = BeamioShellRecordReply.Correlator()
			for event in c["events"] as? [[String: Any]] ?? [] {
				let at = time(event["t"])
				switch event["kind"] as? String {
				case "send":
					correlator.send(reqId: event["reqId"] as? String ?? "", at: at)
				case "tick":
					correlator.tick(at: at)
				case "reply":
					correlator.reply(event["msg"] as? [String: Any] ?? [:], at: at)
				default:
					XCTFail("\(id): unknown event kind")
				}
			}
			XCTAssertEqual(canonical(correlator.outcomes), canonical(c["expect"]), id)
		}
	}

	/// OR-01 to OR-03. A refused origin is not processed and gets no reply. An allowed origin with a valid reqId is answered once. An allowed origin
	/// with no valid reqId is answered once with `bad_request` and a null reqId.
	func testTheNativeBoundaryMatchesTheVectors() throws {
		let cases = try vectorRoot()["originBoundaryCases"] as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 3)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			let expect = c["expect"] as? [String: Any] ?? [:]
			let allowed = input["allowed"] as? Bool ?? false
			let reqIdValid = input["reqIdValid"] as? Bool ?? false
			let body: [String: Any] = reqIdValid
				? ["type": "shellRecordRead", "reqId": "or-1"]
				: ["type": "shellRecordRead"]
			let answer = BeamioShellRecord.boundary(body, env: environment(account: "0xor1", allowed: allowed))
			let replies = answer.map { [BeamioShellRecord.ackEnvelope(for: $0)] } ?? []
			XCTAssertEqual(replies.count, expect["replies"] as? Int, id)
			if var want = expect["reply"] as? [String: Any] {
				// OR-01: "echo-if-valid" stands for the request's reqId when it is legal, and for null when it is not.
				if want["reqId"] as? String == "echo-if-valid" { want["reqId"] = reqIdValid ? "or-1" : NSNull() }
				XCTAssertEqual(canonical(replies.first), canonical(want), id)
			}
		}
	}
}
