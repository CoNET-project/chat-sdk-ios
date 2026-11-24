import XCTest
@testable import ConetChatSDK

/// The numeric rule of a bridge integer (the shared numeric rule): a JS number crosses WKScriptMessage as a double (objCType "d"), and a whole number is
/// accepted. The cases use NSNumber values of the real Objective-C types, not Swift Int literals (which are always "q").
final class BridgeIntegerTests: XCTestCase {
	func testWholeNumbersOfAnyObjCTypeAreAccepted() {
		XCTAssertEqual(String(cString: NSNumber(value: 5.0).objCType), "d")
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: 5.0)), 5)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: Float(5))), 5)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: 5)), 5)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: UInt8(5))), 5)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: 0.0)), 0)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: Double(1 << 40))), 1 << 40)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: 9_007_199_254_740_991.0)), 9_007_199_254_740_991)
	}

	func testNonIntegersAreRefused() {
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: 5.5)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: -1)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: -1.0)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: Double.nan)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: Double.infinity)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: 9_007_199_254_740_992.0)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(NSNumber(value: true)))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration("5"))
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(nil))
	}

	func testReqIdEchoUsesTheSameRule() {
		XCTAssertEqual(BeamioChatRouteRegister.reqIdEcho(NSNumber(value: 7.0)) as? Int, 7)
		XCTAssertNil(BeamioChatRouteRegister.reqIdEcho(NSNumber(value: 7.5)))
		XCTAssertNil(BeamioChatRouteRegister.reqIdEcho(NSNumber(value: true)))
		XCTAssertNil(BeamioChatRouteRegister.reqIdEcho(NSNumber(value: Double.infinity)))
	}

	/// The send path of a new page (deferAck): the generation as a double is the request's generation, not bad_request.
	func testInitiationGenerationTakesADouble() {
		let session = BeamioConetChatModule.Session()
		session.deferAck = true
		XCTAssertEqual(BeamioConetChatModule.initiationGeneration(session, body: ["inboundGeneration": NSNumber(value: 3.0)]), 3)
		XCTAssertNil(BeamioConetChatModule.initiationGeneration(session, body: ["inboundGeneration": NSNumber(value: 3.5)]))
		XCTAssertNil(BeamioConetChatModule.initiationGeneration(session, body: ["inboundGeneration": "3"]))
		XCTAssertNil(BeamioConetChatModule.initiationGeneration(session, body: [:]))
	}
}
