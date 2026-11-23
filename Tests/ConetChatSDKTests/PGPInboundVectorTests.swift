#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Group A of `pgp-bridge-command-vectors.v1.json` (spec, T-210 to T-212) through the bridge entry point, with the
/// native decrypt and the synthetic key P-1 (from `pgp-restore-acceptance-vectors.v1.json`). Runs only where the X-19
/// framework is linked (iOS builds with Vendor/X19.xcframework); skipped without the two vector paths:
/// PGP_BRIDGE_VECTORS=<pgp-bridge-command-vectors.v1.json> PGP_RESTORE_VECTORS=<pgp-restore-acceptance-vectors.v1.json>
/// Synthetic values only. The key is read from the vector file at run time and is not printed.
final class PGPInboundVectorTests: XCTestCase {
	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: PGPInboundTestStore!

	final class PGPInboundTestStore: BeamioChatWalletKeyStoring {
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

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		store = PGPInboundTestStore()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
		BeamioConetChatSignBroker.clearSigner()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		BeamioChatPgpKeychain.memory = nil
		BeamioConetChatSignBroker.clearSigner()
		super.tearDown()
	}

	private func json(_ env: String) throws -> [String: Any] {
		let path = try XCTUnwrap(ProcessInfo.processInfo.environment[env], "set \(env)")
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			events.append((event["event"] as? [String: Any]) ?? event)
		})
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 10)
		return events
	}

	/// The P-1 key as the account's PGP record, the account's wallet key present, and the gate set by the case's gate.
	private func arrange(gate: String, account: String, privateArmor: String) {
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		store.keys = [:]
		switch gate {
		case "G0":
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		case "G1":
			XCTAssertTrue(store.write(eoa: account, key: Data(repeating: 0x33, count: 32)))
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		default:
			XCTAssertTrue(store.write(eoa: account, key: Data(repeating: 0x33, count: 32)))
			XCTAssertTrue(BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
				privateKeyArmor: privateArmor, publicKeyArmor: privateArmor, pgpKeyId: "syn-p1",
				routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: account
			)))
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		}
	}

	func testGroupAOfTheBridgeVectorsThroughTheEntryPoint() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 framework not linked in this build")
		let bridge = try json("PGP_BRIDGE_VECTORS")
		let restore = try json("PGP_RESTORE_VECTORS")
		let p1 = try XCTUnwrap((restore["syntheticKeys"] as? [String: Any])?["P1"] as? [String: Any])
		let privateArmor = try XCTUnwrap(p1["privateArmor"] as? String)
		let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
		let cases = try XCTUnwrap(bridge["cases"] as? [[String: Any]]).filter { ($0["group"] as? String) == "A" }
		XCTAssertEqual(cases.count, 16)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let gate = c["gate"] as? String ?? "G2"
			if gate == "G2_locked" {
				// The passcode lock is not built in this harness. Covered by PGPInboundTests.testALockedAccount...
				continue
			}
			var request = try XCTUnwrap(c["request"] as? [String: Any])
			// A-13 gives the message as a repeat (char, count) rather than the text itself.
			if let repeatSpec = request.removeValue(forKey: "armoredMessageRepeat") as? [String: Any],
			   let char = repeatSpec["char"] as? String, let count = repeatSpec["count"] as? Int {
				request["armoredMessage"] = String(repeating: char, count: count)
			}
			let expect = try XCTUnwrap((c["expect"] as? [String: Any])?["ack"] as? [String: Any])
			arrange(gate: gate, account: account, privateArmor: privateArmor)
			let events = dispatch(request)
			XCTAssertEqual(events.count, 1, id)
			let ack = try XCTUnwrap(events.first, id)
			XCTAssertEqual(ack["ok"] as? Bool, expect["ok"] as? Bool, id)
			if let error = expect["error"] as? String {
				XCTAssertEqual(ack["error"] as? String, error, id)
			} else if let result = expect["result"] as? [String: Any] {
				let got = (ack["result"] as? [String: Any]) ?? [:]
				let wantPlain = result["plaintext"] as? String ?? ""
				// A-04: a text literal with CRLF comes back with LF (step 6, X-19 v3 DecryptArmoredText).
				XCTAssertEqual(got["plaintext"] as? String, wantPlain, id)
				let wantSignal = result["signal"] as? [String: Any]
				let gotSignal = got["signal"] as? [String: Any]
				if wantSignal == nil {
					XCTAssertNil(gotSignal, id)
				} else {
					XCTAssertEqual(gotSignal?["kind"] as? String, wantSignal?["kind"] as? String, id)
					XCTAssertEqual(gotSignal?["type"] as? String, wantSignal?["type"] as? String, id)
					XCTAssertEqual(gotSignal?["callId"] as? String, wantSignal?["callId"] as? String, id)
					XCTAssertEqual(gotSignal?["sessionId"] as? String, wantSignal?["sessionId"] as? String, id)
					XCTAssertEqual(gotSignal?["rejectReason"] as? String, wantSignal?["rejectReason"] as? String, id)
				}
			}
		}
	}
}
#endif
