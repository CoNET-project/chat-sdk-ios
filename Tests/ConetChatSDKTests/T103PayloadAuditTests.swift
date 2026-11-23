#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// T-103: when `identity.native-keys.v1` is in force, the payloads of `identity.provision` and `init` carry
/// public material only. A private-key field is refused by name, on both routes and through the commands, before anything else is read.
/// The answers carry only the allowed keys (ok, ready, eoa, present). Synthetic values only; no key material is used here.
final class T103PayloadAuditTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"
	private let capabilities = [BeamioConetChatModule.identityNativeKeysCapability]
	private var events: [[String: Any]] = []

	/// The CRED set of `provisionIdentity` and `init` as lists it (15 names). The test pins the spec's list, not the module's.
	private let forbiddenNames = [
		"privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
		"recoveryCode", "pin", "password", "accountPassword", "encrypKeyArmored", "privateKeyArmor", "privateKeyArmorWrap",
		"mnemonicPhrase", "recoveryWords",
	]

	override func setUp() {
		super.setUp()
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		super.tearDown()
	}

	private func identityPayload(extra: [String: Any] = [:]) -> [String: Any] {
		var identity: [String: Any] = ["eoaAddress": account]
		for (key, value) in extra { identity[key] = value }
		return identity
	}

	func testEveryForbiddenNameIsRefusedOnTheProvisionRoute() {
		for name in forbiddenNames {
			let outcome = BeamioConetChatModule.testIdentityProvisionOutcome(
				payload: identityPayload(extra: [name: "synthetic"]), route: .provision, readyFor: { _ in false }, capabilities: capabilities
			)
			XCTAssertEqual(outcome["ok"] as? Bool, false, "\(name): refused on provisionIdentity")
			XCTAssertEqual(outcome["error"] as? String, "key_over_bridge_refused", name)
			XCTAssertEqual(outcome["field"] as? String, name, "the field name is returned, never the value")
		}
	}

	func testEveryForbiddenNameIsRefusedOnTheInitRoute() {
		for name in forbiddenNames {
			let payload: [String: Any] = ["identity": identityPayload(extra: [name: "synthetic"])]
			let outcome = BeamioConetChatModule.testIdentityProvisionOutcome(
				payload: payload, route: .initNested, readyFor: { _ in false }, capabilities: capabilities
			)
			XCTAssertEqual(outcome["ok"] as? Bool, false, "\(name): refused on init")
			XCTAssertEqual(outcome["error"] as? String, "key_over_bridge_refused", name)
		}
	}

	func testAPublicOnlyPayloadIsAcceptedAndAnswersOnlyTheAllowedKeys() {
		let provision = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: identityPayload(), route: .provision, readyFor: { _ in false }, capabilities: capabilities
		)
		XCTAssertEqual(provision["ok"] as? Bool, true)
		XCTAssertEqual(Set(provision.keys), ["ok", "ready", "eoa"], "the answer carries only the allowed keys")
		let initOutcome = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: ["identity": identityPayload()], route: .initNested, readyFor: { _ in false }, capabilities: capabilities
		)
		XCTAssertEqual(initOutcome["ok"] as? Bool, true)
		XCTAssertEqual(Set(initOutcome.keys), ["ok", "ready", "eoa"])
	}

	func testTheInitCommandRefusesAPrivateKeyFieldBeforeAnyStateChanges() {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		let before = BeamioConetChatModule.testCurrentSession()
		let payload: [String: Any] = ["identity": identityPayload(extra: ["privateKeyHex": "synthetic"])]
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 103, "payload": payload], emit: { _ in })
		drainMain()
		XCTAssertEqual(ackErrors(103), ["key_over_bridge_refused"], "init answers the refusal")
		XCTAssertTrue(BeamioConetChatModule.testCurrentSession() === before, "a refused init does not replace the session")
	}

	func testTheProvisionCommandRefusesAPrivateKeyField() {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		let payload: [String: Any] = ["identity": identityPayload(extra: ["pgpPassphrase": "synthetic"])]
		BeamioConetChatModule.handleCommand(["type": "provisionIdentity", "reqId": 104, "payload": payload], emit: { _ in })
		drainMain()
		XCTAssertEqual(ackErrors(104), ["key_over_bridge_refused"])
	}

	private func ackErrors(_ reqId: Int) -> [String?] {
		events.compactMap { out -> String?? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack",
			      event["reqId"] as? Int == reqId else { return nil }
			return .some(event["error"] as? String)
		}
	}

	private func drainMain() {
		let e = expectation(description: "main drained")
		DispatchQueue.main.async { e.fulfill() }
		wait(for: [e], timeout: 10)
	}
}
#endif
