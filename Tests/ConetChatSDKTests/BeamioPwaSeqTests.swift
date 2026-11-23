import Foundation
import XCTest
@testable import ConetChatSDK

/// The seq range of pwaWalletSync and pwaEmptySignal (project ruling). Synthetic values only.
final class BeamioPwaSeqTests: XCTestCase {
	/// The decoded value of a JSON number, as a bridge request carries it (the number is in an array so that any scalar decodes).
	private func decoded(_ json: String) -> Any? {
		guard let root = try? JSONSerialization.jsonObject(with: Data("[\(json)]".utf8)) as? [Any] else { return nil }
		return root.first
	}

	func testTheRealisticSequenceIsAccepted() {
		XCTAssertEqual(BeamioPwaSeq.parse(decoded("1800000000000")), 1_800_000_000_000)
	}

	func testTheRangeEndsAtTwoToTheFiftyThreeMinusOne() {
		XCTAssertEqual(BeamioPwaSeq.parse(decoded("0")), 0)
		XCTAssertEqual(BeamioPwaSeq.parse(decoded("9007199254740991")), 9_007_199_254_740_991)
		XCTAssertNil(BeamioPwaSeq.parse(decoded("9007199254740992")), "2^53 is bad_request")
		XCTAssertNil(BeamioPwaSeq.parse(decoded("9007199254740993")), "above 2^53 is bad_request")
	}

	func testANegativeNumberIsBadRequest() {
		XCTAssertNil(BeamioPwaSeq.parse(decoded("-1")))
	}

	func testDecimalAndExponentFormsAreBadRequestEvenWhenTheValueIsAnInteger() {
		XCTAssertNil(BeamioPwaSeq.parse(decoded("1.0")), "1.0 is a decimal form")
		XCTAssertNil(BeamioPwaSeq.parse(decoded("1e0")), "1e0 is an exponent form")
	}

	func testANonNumberIsBadRequest() {
		XCTAssertNil(BeamioPwaSeq.parse(decoded("\"5\"")), "a string is not a seq")
		XCTAssertNil(BeamioPwaSeq.parse(decoded("true")), "a boolean is not a seq")
		XCTAssertNil(BeamioPwaSeq.parse(nil), "a missing seq is bad_request")
	}
}
