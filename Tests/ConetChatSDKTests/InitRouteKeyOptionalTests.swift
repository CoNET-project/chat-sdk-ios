import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// The route public key of `init` may be omitted. When present, it must be a PGP public
/// armor, the same rule as `pgpPublicKeyArmored`. Checked on the outcome of the identity payload rules, which `init`
/// runs when the capability is declared (`handleInit`). The capability is not declared in the production list; the
/// function is called with the list it would be declared with, so the rule is exercised without a declaration.
final class InitRouteKeyOptionalTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let armor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-route-public-only\n-----END PGP PUBLIC KEY BLOCK-----"
	private let pgpArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-public-only\n-----END PGP PUBLIC KEY BLOCK-----"

	private func initPayload(route: Any?) -> [String: Any] {
		var identity: [String: Any] = ["eoa": account, "pgpPublicKeyArmored": pgpArmor]
		if let route { identity["ownRouteArmoredPublicKey"] = route }
		return ["identity": identity, "conetRpcUrl": "https://rpc.example.invalid", "chainId": 224422]
	}

	private func outcome(_ payload: [String: Any]) -> [String: Any] {
		BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: payload, route: .initNested, readyFor: { _ in false },
			capabilities: [BeamioConetChatModule.identityNativeKeysCapability]
		)
	}

	/// G1 `init` without the route key: accepted, and the answer carries no route key.
	func testAnInitWithoutTheRouteKeyIsAccepted() {
		let result = outcome(initPayload(route: nil))
		XCTAssertEqual(result["ok"] as? Bool, true)
		XCTAssertEqual(result["eoa"] as? String, account)
		XCTAssertNil(result["ownRouteArmoredPublicKey"])
	}

	/// The key present as a PGP public armor is accepted.
	func testAnInitWithARoutePGPArmorIsAccepted() {
		XCTAssertEqual(outcome(initPayload(route: armor))["ok"] as? Bool, true)
	}

	/// A present key that is not an armor is refused: an empty string, a plain value, and null.
	func testAnInitWithANonArmorRouteKeyIsBadIdentity() {
		for route in ["", "synthetic-route-public-0001", NSNull()] as [Any] {
			let result = outcome(initPayload(route: route))
			XCTAssertEqual(result["ok"] as? Bool, false, "\(route)")
			XCTAssertEqual(result["error"] as? String, "bad_identity", "\(route)")
		}
	}

	/// The flat `provisionIdentity` payload follows the same rule.
	func testAProvisionWithoutTheRouteKeyIsAccepted() {
		let flat: [String: Any] = ["eoa": account, "pgpPublicKeyArmored": pgpArmor]
		let result = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: flat, route: .provision, readyFor: { _ in false },
			capabilities: [BeamioConetChatModule.identityNativeKeysCapability]
		)
		XCTAssertEqual(result["ok"] as? Bool, true)
	}
}
#endif
