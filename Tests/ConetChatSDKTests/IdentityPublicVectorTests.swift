#if BEAMIO_TEST_HOOKS
import Foundation
import XCTest
@testable import ConetChatSDK

/// The 14 cases of `identity-public-vectors.v1.json`, through
/// the bridge entry point. Needs IDENTITY_PUBLIC_VECTORS=<path to the file>; skipped without it. Runs on macOS and iOS. The values
/// are synthetic. The public keys are PGP armor, so the record is written with `save`, the production path. The legacy
/// layout (IP-14) is written with the plain item names the keychain used before per-account storage.
final class IdentityPublicVectorTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	final class IdentityKeyStore: BeamioChatWalletKeyStoring {
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

	final class Sink {
		var events: [[String: Any]] = []
	}

	private var savedStore: BeamioChatWalletKeyStoring?
	private var store = IdentityKeyStore()

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = IdentityKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = nil
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["IDENTITY_PUBLIC_VECTORS"] else {
			throw XCTSkip("set IDENTITY_PUBLIC_VECTORS to interface/protocol/identity-public-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func canonical(_ value: Any) -> String {
		let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
		return String(data: data, encoding: .utf8)!
	}

	/// G0: no record on the device. G1: a record, and the session has not run `init`. G2: a record, and `init` is done.
	private func applyGate(_ state: String?) {
		store.keys = [:]
		BeamioNativeAccountPointer.clear()
		switch state {
		case "G1", "G2":
			store.keys[account] = Data(repeating: 0x11, count: 32)
			BeamioNativeAccountPointer.set(account)
			BeamioConetChatSignBroker.setSignerEoa(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: state == "G2")
		default:
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
	}

	private let privateArmor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-private-only\n-----END PGP PRIVATE KEY BLOCK-----"

	/// The PGP record of the vector, as the IP-01 result holds its public values. `legacy` writes the pre-migration layout.
	private func applyRecord(pgp: Bool, route: Bool, legacy: Bool, expected: [String: Any]) throws {
		guard pgp else { return }
		let publicArmor = try XCTUnwrap(expected["pgpPublicKeyArmored"] as? String)
		let keyId = try XCTUnwrap(expected["pgpKeyID"] as? String)
		let routeArmor = route ? try XCTUnwrap(expected["ownRouteArmoredPublicKey"] as? String) : ""
		if legacy {
			// The plain item names of the layout before per-account storage (BeamioChatPgpKeychain.adoptLegacyRecord).
			let values = BeamioChatPgpKeychain.memory
			values?.values["userPgpPrivateArmor"] = privateArmor
			values?.values["userPgpPublicArmor"] = publicArmor
			values?.values["userPgpKeyId"] = keyId
			values?.values["mailboxRoutePublicArmor"] = routeArmor
			values?.values["recipientEoa"] = account
			return
		}
		let saved = BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: privateArmor, publicKeyArmor: publicArmor, pgpKeyId: keyId, routePublicKeyArmor: routeArmor,
			entryDomains: [], siNodes: [], mailboxIp: "", eoa: account
		))
		XCTAssertTrue(saved)
	}

	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		let sink = Sink()
		BeamioConetChatModule.handleCommand(body, emit: { event in
			sink.events.append((event["event"] as? [String: Any]) ?? event)
		})
		let deadline = Date().addingTimeInterval(5)
		while sink.events.isEmpty, Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.02))
		}
		return sink.events
	}

	func testTheFourteenCasesAnswerTheVectorResults() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 14)
		let forbidden = try XCTUnwrap(root["forbiddenResultKeys"] as? [String])
		// The expected PGP values come from IP-01, the case that has the full record.
		let full = try XCTUnwrap(cases.first { $0["id"] as? String == "IP-01" })
		let fullResult = try XCTUnwrap(((try XCTUnwrap(full["expect"] as? [[String: Any]])).first?["detail"] as? [String: Any])?["event"] as? [String: Any])
		let fullValues = try XCTUnwrap(fullResult["result"] as? [String: Any])

		for c in cases {
			let id = try XCTUnwrap(c["id"] as? String)
			let env = c["env"] as? [String: Any] ?? [:]
			applyGate(env["state"] as? String)
			let legacy = env["pgpLayout"] as? String == "legacy"
			try applyRecord(pgp: env["pgp"] as? Bool == true, route: env["route"] as? Bool == true, legacy: legacy, expected: fullValues)

			let step = try XCTUnwrap((c["steps"] as? [[String: Any]])?.first, id)
			let req = try XCTUnwrap(step["req"] as? [String: Any], id)
			let events = dispatch(req)
			XCTAssertEqual(events.count, 1, "\(id): one answer")
			let expect = try XCTUnwrap(c["expect"] as? [[String: Any]], id)
			let want = try XCTUnwrap((expect.first?["detail"] as? [String: Any])?["event"] as? [String: Any], id)
			if legacy {
				// Read only: the legacy items stay where they are, and nothing is copied to the account's own names.
				let values = BeamioChatPgpKeychain.memory?.values ?? [:]
				XCTAssertNotNil(values["userPgpPrivateArmor"], "\(id): the legacy record is not moved")
				XCTAssertNil(values[BeamioChatPgpKeychain.accountKey(eoa: account) + "|userPgpPrivateArmor"], "\(id): nothing is written")
			}
			if let got = events.first {
				// The vector file (regenerated, 25.52Y.90 第 4 项) states kPresent in the G0 no_key answer, as the shipped pair requires: compared whole.
				XCTAssertEqual(canonical(got), canonical(want), id)
				if let result = got["result"] as? [String: Any] {
					for key in forbidden {
						XCTAssertNil(result[key], "\(id): the result must not carry \(key)")
					}
				}
			}
			// Each case starts from an empty record.
			BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		}
	}
}
#endif
