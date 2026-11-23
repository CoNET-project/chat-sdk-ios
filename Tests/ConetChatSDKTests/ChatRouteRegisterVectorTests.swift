import CryptoKit
import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// chat-route-register-vectors.v1.json: the native request negatives NR-01 to NR-16 against the checks
/// before the vault and the signature. Not run here, and reported as such: NR-11 and NR-12 (the key fingerprint against
/// the vault, and the missing PGP record) need the vault stage, and the positives PV-1 to PV-4 need the signing stage. Runs
/// with CHAT_ROUTE_REGISTER_VECTORS=<path>; skipped without it. The vector file is not edited to fit the code.
final class ChatRouteRegisterVectorTests: XCTestCase {
	static let expectedSHA256 = "634d98c25e7339b7dac18b0c97525700176d42b94e2ab3b784bb9b5503f3e5c5"

	private func negatives() throws -> [[String: Any]] {
		guard let path = ProcessInfo.processInfo.environment["CHAT_ROUTE_REGISTER_VECTORS"] else {
			throw XCTSkip("set CHAT_ROUTE_REGISTER_VECTORS to interface/protocol/chat-route-register-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
		              "vector file sha256 differs from the published value (the digest is not printed)")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		return try XCTUnwrap(root["nativeRequestNegatives"] as? [[String: Any]])
	}

	/// The device state each case is run in (the expectation column): G0 and G1 do not read the payload, NR-15 is
	/// the native lock, NR-16 is a shell without the capability. The other cases are G2, unlocked, with the capability.
	private func context(_ id: String) -> (gate: BeamioConetChatModule.NativeGate, locked: Bool, capabilities: [String]) {
		let declared = [BeamioChatRouteRegister.capability]
		switch id {
		case "NR-13": return (.g0, false, declared)
		case "NR-14": return (.g1, false, declared)
		case "NR-15": return (.g2, true, declared)
		case "NR-16": return (.g2, false, [])
		default: return (.g2, false, declared)
		}
	}

	func testNativeRequestNegativesGiveTheVectorCodes() throws {
		let cases = try negatives()
		XCTAssertEqual(cases.count, 16, "NR-01 to NR-16")
		var notRun: [String] = []
		for c in cases {
			let id = c["id"] as? String ?? "?"
			if id == "NR-11" || id == "NR-12" {
				notRun.append(id)
				continue
			}
			let expect = c["expect"] as? [String: Any] ?? [:]
			let code = expect["code"] as? String ?? ""
			let request = c["request"] as? [String: Any] ?? [:]
			let ctx = context(id)
			let result = BeamioChatRouteRegister.testStage(
				body: request, gate: ctx.gate, locked: ctx.locked, capabilities: ctx.capabilities)
			XCTAssertEqual(result, .answer(code), id)
		}
		XCTAssertEqual(notRun, ["NR-11", "NR-12"], "the vault stage is not implemented: these two are not run")
	}
}
#endif
