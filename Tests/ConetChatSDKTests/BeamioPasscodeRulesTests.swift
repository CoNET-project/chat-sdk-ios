import XCTest
@testable import ConetChatSDK

/// T-69 (spec): the passcode rules against `ui/passcode-vectors.v1.json`, 24 cases including the birthday
/// formats. Reads the file from PASSCODE_VECTORS; skips without it. Synthetic values only.
final class BeamioPasscodeRulesTests: XCTestCase {
	func testPasscodeVectorsMatch() throws {
		guard let path = ProcessInfo.processInfo.environment["PASSCODE_VECTORS"], !path.isEmpty else {
			throw XCTSkip("set PASSCODE_VECTORS to interface/ui/passcode-vectors.v1.json")
		}
		let root = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any]
		let policy = try XCTUnwrap(root?["policy"] as? [String: Any])
		let cases = try XCTUnwrap(policy["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 24)
		XCTAssertEqual(Set(policy["common"] as? [String] ?? []), Set(BeamioPasscodeRules.common.map { String(decoding: $0, as: UTF8.self) }), "the COMMON list matches the file")
		for c in cases {
			let passcode = try XCTUnwrap(c["passcode"] as? String)
			let refusal = BeamioPasscodeRules.refusal(Array((passcode).utf8))
			let expectOk = c["expectOk"] as? Bool ?? false
			XCTAssertEqual(refusal == nil, expectOk, "\(passcode): ok")
			if !expectOk {
				XCTAssertEqual(refusal, c["expectReason"] as? String, "\(passcode): reason")
			}
		}
	}

	func testTheBirthdayFormatIsRefusedWhateverTheOrder() {
		// 20251231 is YYYYMMDD; the spec lists it as a refused example.
		XCTAssertEqual(BeamioPasscodeRules.refusal(Array(("20251231").utf8)), "birthday")
		XCTAssertNil(BeamioPasscodeRules.refusal(Array(("20250230").utf8)), "February 30 is not a date, so it is allowed")
		XCTAssertNil(BeamioPasscodeRules.refusal(Array(("13572468").utf8)))
	}

	func testLengthAndDigits() {
		XCTAssertEqual(BeamioPasscodeRules.refusal(Array(("1357246").utf8)), "too_short")
		XCTAssertEqual(BeamioPasscodeRules.refusal(Array(("1357246813572").utf8)), "too_long")
		XCTAssertEqual(BeamioPasscodeRules.refusal(Array(("1357ab68").utf8)), "non_digit")
	}
}
