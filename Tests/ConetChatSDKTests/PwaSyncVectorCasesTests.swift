import XCTest
@testable import ConetChatSDK

/// AC-02, AC-04, AC-05, AC-06 and PV-05 of account-select-vectors.v2 (registered file, a9b8d563): the cases of the PWA sync commands that the generic account-select harness
/// does not drive. Each case is read from the file; only what the SDK can answer without a store write is driven here (AC-01, AC-03 and AC-07 to AC-09 need the
/// write path and stay with PwaPhraseOverwriteTests). Synthetic values only.
final class PwaSyncVectorCasesTests: XCTestCase {
	override func setUp() { super.setUp(); BeamioPwaWalletSync.restartForTests() }
	override func tearDown() { BeamioPwaWalletSync.restartForTests(); super.tearDown() }

	private func vectorCase(_ id: String) throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: "account-select-vectors.v2")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return try XCTUnwrap(cases.first { $0["id"] as? String == id }, id)
	}

	private func sync(seq: Int, trusted: Bool) -> [String: Any] {
		var body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "seq": seq,
		                           "phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"]
		if trusted { body["trustedOrigin"] = true }
		return BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)
	}

	/// AC-02: an older seq than the latest accepted one is stale_seq (the SDK answers it as the envelope error).
	func testAC02StaleSeq() throws {
		let c = try vectorCase("AC-02")
		let r = (c["input"] as? [String: Any])?["r"] as? [String: Any] ?? [:]
		BeamioPwaWalletSync.recordAccepted(Int64(r["latestSeq"] as? Int ?? 0))
		let a = sync(seq: r["seq"] as? Int ?? 0, trusted: r["trustedOrigin"] as? Bool ?? false)
		XCTAssertEqual(a["error"] as? String, (c["expect"] as? [String: Any])?["code"] as? String)
		XCTAssertEqual(a["ok"] as? Bool, false)
	}

	/// AC-04: a source that is not trusted is untrusted_source.
	func testAC04UntrustedSource() throws {
		let c = try vectorCase("AC-04")
		let r = (c["input"] as? [String: Any])?["r"] as? [String: Any] ?? [:]
		XCTAssertEqual(r["sourceOk"] as? Bool, false)
		let a = sync(seq: r["seq"] as? Int ?? 0, trusted: r["sourceOk"] as? Bool ?? false)
		XCTAssertEqual(a["error"] as? String, (c["expect"] as? [String: Any])?["code"] as? String)
	}

	/// AC-05: bad_request is the fifth value of the sync set: a seq that is not a valid number reaches it.
	func testAC05BadRequestIsInTheSyncSet() throws {
		let c = try vectorCase("AC-05")
		let set = ((c["expect"] as? [String: Any])?["syncSet"] as? String ?? "").split(separator: ",").map(String.init)
		XCTAssertEqual(set, ["ok", "stale_seq", "write_failed", "untrusted_source", "bad_request"])
		var body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "seq": "x", "trustedOrigin": true, "phrase": "abandon"]
		body["seq"] = NSNumber(value: -1)
		XCTAssertEqual(BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)["error"] as? String, "bad_request")
	}

	/// AC-06: the preread answers one of valid, absent, unknown (the closed set of `result.state`).
	func testAC06PrereadStatesAreTheClosedSet() throws {
		let c = try vectorCase("AC-06")
		let set = Set(((c["expect"] as? [String: Any])?["prereadSet"] as? String ?? "").split(separator: ",").map(String.init))
		XCTAssertEqual(set, ["valid", "absent", "unknown"])
		XCTAssertEqual(Set(BeamioPwaWalletSync.Preread.allCases.map(\.rawValue)), set, "the SDK's states are exactly the closed set")
	}

	/// PV-05: a preread the shell judged untrusted is ok:false with untrusted_source (the PWA treats it as unknown).
	func testPV05UntrustedPrereadIsOkFalseUntrustedSource() throws {
		let c = try vectorCase("PV-05")
		let r = (c["input"] as? [String: Any])?["r"] as? [String: Any] ?? [:]
		XCTAssertEqual(r["shellTrusted"] as? Bool, false)
		let a = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 7, "seq": 3], snapshotKnown: true, storageLocked: false)
		let expect = c["expect"] as? [String: Any] ?? [:]
		XCTAssertEqual(a["ok"] as? Bool, expect["ok"] as? Bool)
		XCTAssertEqual(a["error"] as? String, expect["code"] as? String)
	}
}
