import XCTest
@testable import ConetChatSDK

/// the default API base is `https://beamio.ca/api`. The init payload's `apiBaseUrl` overrides it, and
/// without one the current value stays. The override rule is a pure function, so it is tested by behaviour. Synthetic values only.
final class ApiBaseUrlDefaultTests: XCTestCase {
	func testTheDefaultApiBaseIsBeamioCa() {
		XCTAssertEqual(BeamioConetChatModule.Session().apiBaseUrl, "https://beamio.ca/api")
	}

	func testAnInitValueOverridesTheDefault() {
		let value = BeamioConetChatModule.resolvedApiBaseUrl(payload: ["apiBaseUrl": "https://override.example/api"], current: "https://beamio.ca/api")
		XCTAssertEqual(value, "https://override.example/api")
	}

	func testAnAbsentInitValueKeepsTheCurrentValue() {
		let value = BeamioConetChatModule.resolvedApiBaseUrl(payload: [:], current: "https://beamio.ca/api")
		XCTAssertEqual(value, "https://beamio.ca/api")
	}

	func testAnEmptyOrBlankInitValueKeepsTheCurrentValue() {
		for given in ["", "   ", "\n\t "] {
			let value = BeamioConetChatModule.resolvedApiBaseUrl(payload: ["apiBaseUrl": given], current: "https://beamio.ca/api")
			XCTAssertEqual(value, "https://beamio.ca/api", "a blank init value (\(given.debugDescription)) keeps the current base")
		}
	}

	func testANonStringInitValueKeepsTheCurrentValue() {
		let value = BeamioConetChatModule.resolvedApiBaseUrl(payload: ["apiBaseUrl": 5], current: "https://beamio.ca/api")
		XCTAssertEqual(value, "https://beamio.ca/api")
	}
}
