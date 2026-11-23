import XCTest
@testable import ConetChatSDK

/// The passcode visual tokens match `ui/passcode-tokens.v1.json`. Reads PASSCODE_TOKENS; skips without it.
final class BeamioPasscodeTokensTests: XCTestCase {
	func testTokensMatchTheSharedFile() throws {
		guard let path = ProcessInfo.processInfo.environment["PASSCODE_TOKENS"], !path.isEmpty else {
			throw XCTSkip("set PASSCODE_TOKENS to interface/ui/passcode-tokens.v1.json")
		}
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any])
		let color = try XCTUnwrap(root["color"] as? [String: String])
		XCTAssertEqual(BeamioPasscodeTokens.colors, color)
		let font = try XCTUnwrap(root["font"] as? [String: [String: Any]])
		XCTAssertEqual(BeamioPasscodeTokens.titleSize, Double(font["title"]?["size"] as? Int ?? -1))
		XCTAssertEqual(BeamioPasscodeTokens.bodySize, Double(font["body"]?["size"] as? Int ?? -1))
		XCTAssertEqual(BeamioPasscodeTokens.captionSize, Double(font["caption"]?["size"] as? Int ?? -1))
		let keypad = try XCTUnwrap(root["keypad"] as? [String: Any])
		let key = try XCTUnwrap(keypad["key"] as? [String: Any])
		XCTAssertEqual(BeamioPasscodeTokens.keyWidth, Double(key["width"] as? Int ?? -1))
		XCTAssertEqual(BeamioPasscodeTokens.keyRadius, Double(key["radius"] as? Int ?? -1))
		let grid = try XCTUnwrap(keypad["grid"] as? [String: Any])
		XCTAssertEqual(BeamioPasscodeTokens.gridCols, grid["cols"] as? Int)
		XCTAssertEqual(BeamioPasscodeTokens.gridRows, grid["rows"] as? Int)
		XCTAssertEqual(BeamioPasscodeTokens.gridLabels, grid["labels"] as? [String])
		let dot = try XCTUnwrap(root["dot"] as? [String: Any])
		XCTAssertEqual(BeamioPasscodeTokens.dotSize, Double(dot["size"] as? Int ?? -1))
		XCTAssertEqual(BeamioPasscodeTokens.dotGap, Double(dot["gap"] as? Int ?? -1))
	}
}
