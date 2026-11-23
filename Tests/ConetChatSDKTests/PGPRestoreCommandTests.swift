import XCTest
@testable import ConetChatSDK

/// The P-IMP-PGP command refusals that need no chain read (spec, vectors C-04, C-05, C-21 to C-24). The other group C
/// cases (C-01 to C-03, C-06 to C-20) need the chain read and the native confirmation panel and are not claimed here.
final class PGPRestoreCommandTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	final class MemoryKeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: MemoryKeyStore!

	override func setUp() {
		super.setUp()
		store = MemoryKeyStore()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// Acks and results are emitted on the main queue, some after a background read: run the main loop until one arrives.
	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			events.append((event["event"] as? [String: Any]) ?? event)
		})
		let deadline = Date().addingTimeInterval(10)
		while events.isEmpty, Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.05))
		}
		RunLoop.main.run(until: Date().addingTimeInterval(0.05))
		return events
	}

	private func command(_ type: String, reqId: String, extra: [String: Any] = [:]) -> [String: Any] {
		var body: [String: Any] = ["type": type, "reqId": reqId, "accountKey": account + ":default"]
		for (k, v) in extra { body[k] = v }
		return body
	}

	private func withRecordOnly() {
		XCTAssertTrue(store.write(eoa: account, key: Data(repeating: 0x44, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
	}

	private func withSession() {
		XCTAssertTrue(store.write(eoa: account, key: Data(repeating: 0x44, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
	}

	// C-05, C-24: no record, no_key; C-04, C-23: record without a session, not_ready. Acks echo the string reqId.

	func testWithoutARecordTheCommandsAreNoKey() {
		for (type, id) in [("pgpRestoreEvaluate", "c3-c-05"), ("pgpIdentityCreate", "c3-c-24")] {
			let events = dispatch(command(type, reqId: id))
			XCTAssertEqual(events.count, 1, type)
			XCTAssertEqual(events.first?["reqId"] as? String, id, type)
			XCTAssertEqual(events.first?["error"] as? String, "no_key", type)
		}
	}

	func testWithARecordButNoSessionTheCommandsAreNotReady() {
		withRecordOnly()
		for (type, id) in [("pgpRestoreEvaluate", "c3-c-04"), ("pgpIdentityCreate", "c3-c-23")] {
			let events = dispatch(command(type, reqId: id))
			XCTAssertEqual(events.first?["error"] as? String, "not_ready", type)
		}
	}

	// C-21, C-22: with the gate open.

	func testAPageConfirmationOfIdentityCreateIsNotNative() {
		withSession()
		let events = dispatch(command("pgpIdentityCreate", reqId: "c3-c-21", extra: ["confirm": true, "idempotencyKey": "idem-c-21"]))
		XCTAssertEqual(events.first?["error"] as? String, "confirmation_not_native")
		XCTAssertNil(events.first?["result"])
	}

	func testObservedVersionFromThePageIsBadRequest() {
		withSession()
		let events = dispatch(command("pgpIdentityCreate", reqId: "c3-c-22", extra: ["observedVersion": 3]))
		XCTAssertEqual(events.first?["error"] as? String, "bad_request")
	}

	func testAForbiddenKeyFieldIsRefusedWithItsCode() {
		withSession()
		let events = dispatch(command("pgpRestore", reqId: "t-kf", extra: ["pgpPassphrase": "x"]))
		XCTAssertEqual(events.first?["error"] as? String, "key_over_bridge_refused")
	}

	/// pgpIdentityCreate prepares only with an idempotency key. Without one: bad_request, and no result.
	func testIdentityCreateWithoutAKeyIsBadRequest() {
		withSession()
		let events = dispatch(command("pgpIdentityCreate", reqId: "t-create"))
		XCTAssertEqual(events.first?["error"] as? String, "bad_request")
		XCTAssertNil(events.first?["result"])
	}

	/// No chain configured (is open): the read fails, so the evaluation is undetermined, never a missing record.
	func testWithoutAChainConfigurationEvaluateIsUndetermined() {
		withSession()
		let events = dispatch(command("pgpRestoreEvaluate", reqId: "t-eval"))
		let result = events.first?["result"] as? [String: Any]
		XCTAssertEqual(result?["state"] as? String, "undetermined")
		XCTAssertEqual(result?["code"] as? String, "pgp_source_unavailable")
	}

	func testAnInvalidReqIdIsBadRequestWithNull() {
		withSession()
		let events = dispatch(["type": "pgpRestore", "reqId": ["x": 1], "accountKey": account + ":default"])
		XCTAssertTrue(events.first?["reqId"] is NSNull)
		XCTAssertEqual(events.first?["error"] as? String, "bad_request")
	}
}
