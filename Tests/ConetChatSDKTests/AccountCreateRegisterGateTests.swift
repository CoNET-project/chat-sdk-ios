import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// 0.1.12: the `accountCreateRegister` command has its own gate (`registerEnabled`, open in every non-test build). The first-identity registration keeps the QA-only
/// gate (`enabled`). The two must never share one flag again, or opening the command would start first-identity in a production build.
final class AccountCreateRegisterGateTests: XCTestCase {
	override func tearDown() {
		BeamioNewAccountFeature.enabledForTests = true
		super.tearDown()
	}

	private func source(_ name: String) throws -> String {
		let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
		return try String(contentsOf: root.appendingPathComponent("Sources/ConetChatSDK/\(name)"), encoding: .utf8)
	}

	func testTheCommandReadsItsOwnGateAndFirstIdentityKeepsTheOldOne() throws {
		let module = try source("BeamioConetChatModule.swift")
		XCTAssertTrue(module.contains("guard BeamioNewAccountFeature.registerEnabled else { return createRegisterRefuse(echo, \"not_available\") }"))
		let first = try source("BeamioFirstIdentityRegistration.swift")
		XCTAssertTrue(first.contains("guard BeamioNewAccountFeature.enabled,"), "first-identity keeps the QA-only gate")
		XCTAssertFalse(first.contains("registerEnabled"), "first-identity does not use the command's gate")
	}

	func testTheProductionGateIsOpenOnlyForTheCommand() throws {
		let payload = try source("BeamioAccountRegisterPayload.swift")
		// Release (no QA, no test hooks): the command's gate is true, the first-identity gate is false.
		XCTAssertTrue(payload.contains("static var registerEnabled: Bool {\n\t\t#if BEAMIO_TEST_HOOKS\n\t\treturn enabledForTests\n\t\t#else\n\t\treturn true\n\t\t#endif"))
		XCTAssertTrue(payload.contains("static var enabled: Bool {\n\t\t#if BEAMIO_QA_BUILD\n\t\treturn true\n\t\t#elseif BEAMIO_TEST_HOOKS\n\t\treturn enabledForTests\n\t\t#else\n\t\treturn false\n\t\t#endif"))
	}

	func testATestBuildStillRefusesWhenTheGateIsClosed() {
		BeamioNewAccountFeature.enabledForTests = false
		XCTAssertFalse(BeamioNewAccountFeature.registerEnabled)
		XCTAssertFalse(BeamioNewAccountFeature.enabled)
		BeamioNewAccountFeature.enabledForTests = true
		XCTAssertTrue(BeamioNewAccountFeature.registerEnabled)
	}
}
#endif
