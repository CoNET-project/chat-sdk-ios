import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// The `identity.provision` answer in both capability states (spec T-104, T-105). The production
/// capability list does not declare `identity.native-keys.v1` yet, so the declared branch is exercised with an explicit
/// list here, and nothing is declared in the module.
final class IdentityProvisionAnswerTests: XCTestCase {
	private typealias Answer = BeamioConetChatModule.IdentityProvisionAnswer
	private let eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	private let declared = BeamioConetChatProtocol.capabilities + [BeamioConetChatModule.identityNativeKeysCapability]

	func testDeclaredCapabilityAnswersReadyAndEoa() {
		XCTAssertEqual(BeamioConetChatModule.testIdentityProvisionAnswer(eoa: eoa, ready: true, capabilities: declared),
		               .ready(true, eoa: eoa))
		XCTAssertEqual(BeamioConetChatModule.testIdentityProvisionAnswer(eoa: eoa, ready: false, capabilities: declared),
		               .ready(false, eoa: eoa), "ready = false keeps the account unbound (T-104)")
	}

#if BEAMIO_QA_BUILD
	func testTheQABuildListDeclaresTheCapability() {
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains(BeamioConetChatModule.identityNativeKeysCapability))
	}
#else
	func testUndeclaredCapabilityKeepsTheLegacyAnswer() {
		// The shipped list declares the capability (25.52Y.121); the legacy answer is the one for a list without it.
		let undeclared = BeamioConetChatProtocol.capabilities.filter { $0 != BeamioConetChatModule.identityNativeKeysCapability }
		XCTAssertEqual(BeamioConetChatModule.testIdentityProvisionAnswer(eoa: eoa, ready: true, capabilities: undeclared), .legacyPresent)
		XCTAssertEqual(BeamioConetChatModule.testIdentityProvisionAnswer(eoa: eoa, ready: false, capabilities: undeclared), .legacyMissing)
	}

	func testTheProductionListDeclaresTheCapability() {
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains(BeamioConetChatModule.identityNativeKeysCapability))
	}
#endif
}
#endif
