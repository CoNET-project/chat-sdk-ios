import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The reference table T, the registered copy (`protocol/table-T.v1.json`, 70 names at r2.5.4). The digest is pinned in BundledVectorFile.
/// Every name of T is a bridge name the command table knows. W2 `deriveLocalKeys`, W3 `protocolKeys` and W4 `fragmentKeys` are not bridge names:
/// they answer `unknown_command` in every gate state, before the gate. Synthetic data only.
final class TableTConformanceTests: XCTestCase {
	static let notBridgeNames = ["deriveLocalKeys", "protocolKeys", "fragmentKeys"]

	/// A key store holding the account key when `hasKey` is set (G1 and G2 need the record), and nothing otherwise (G0).
	private final class TableStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private let account = PgpMigrationTestSupport.eoa

	private func tableNames() throws -> [String] {
		// The bundled copy of the registered table, checked by sha256 on every run. No environment override: the registry file on disk is a
		// later revision, and this test pins (70 names, r2.5.4).
		let data = try BundledVectorFile.data(resource: "table-T.v1")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		return try XCTUnwrap(root["names"] as? [String])
	}

	/// Runs `body` at the gate `gate` (G0 without a key record, G1 with a record and no session, G2 with a session) and returns the events.
	private func dispatch(_ body: [String: Any], gate: String) -> [[String: Any]] {
		let savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		let store = TableStore()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
		switch gate {
		case "G0":
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		case "G1":
			store.keys[account] = Data(repeating: 0x11, count: 32)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		default:
			store.keys[account] = Data(repeating: 0x11, count: 32)
			BeamioConetChatSignBroker.setSignerEoa(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		}
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		BeamioConetChatSignBroker.clearSigner()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		return events
	}

	/// The registered table (r2.5.4): 70 names (T0 57, T1 13), the registered digest, and no duplicate. The r2.5.4 table adds
	/// accountCleanupOld, mailboxProbeSign, nativeMnemonicPreread, pgpUpgradeRetry, pwaEmptySignal and pwaWalletSync, and drops nativeImportOpen.
	func testTheTableIsTheRegisteredSeventyNames() throws {
		let names = try tableNames()
		XCTAssertEqual(names.count, 70, "table T has 70 names (r2.5.4)")
		XCTAssertEqual(Set(names).count, names.count, "no name is repeated")
	}

	/// Every name of T is a bridge name the command table knows, so the gate, not `unknown_command`, judges it.
	func testEveryNameOfTheTableIsAKnownBridgeName() throws {
		let names = try tableNames()
		let unknown = names.filter { !BeamioConetChatModule.knownBridgeCommand($0) }
		// v172 section 192.3. Six names of the file are not in `knownBridgeCommand`. Three are old commands the SDK handles on their own path
		// (pwaWalletSync, pwaEmptySignal, nativeMnemonicPreread: untrusted_source stays with them). Two are not defined for the SDK (accountCleanupOld is registered since 2026-11-21, AccountCleanupCommandTests;
		// mailboxProbeSign, pgpUpgradeRetry): not in `knownBridgeCommand`, so answered unknown_command, never let through. pgpUpgradeRetry only has an
		// unreachable case in the dispatch switch (the code is kept, v178/v184): it is not registered. accountCleanupOld and mailboxProbeSign have no code.
		XCTAssertEqual(Set(unknown), Self.oldCommandsOnTheirOwnPath.union(Self.namesAwaitingARuling), "table names the command table does not know: \(unknown.joined(separator: ", "))")
		for name in Self.namesAwaitingARuling {
			for gate in ["G0", "G1", "G2"] {
				let events = dispatch(["type": name, "reqId": 9710], gate: gate)
				XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "\(name) at \(gate)")
			}
		}
		for name in Self.oldCommandsOnTheirOwnPath {
			for gate in ["G0", "G1", "G2"] {
				let events = dispatch(["type": name, "reqId": 9711], gate: gate)
				XCTAssertEqual(events.first?["error"] as? String, "untrusted_source", "\(name) at \(gate): the old command's own source gate answers")
			}
		}
	}

	/// Old commands with their own path (their source gate answers untrusted_source; v163 keeps it for them).
	static let oldCommandsOnTheirOwnPath: Set<String> = ["pwaWalletSync", "pwaEmptySignal", "nativeMnemonicPreread"]
	/// Not registered: answered unknown_command (v172 section 192.3, v184 section 204; accountCleanupOld is a pending item, v180).
	static let namesAwaitingARuling: Set<String> = ["mailboxProbeSign", "pgpUpgradeRetry"]

	/// W2, W3 and W4 are not in T and not bridge names: `unknown_command` before the gate, in G0, G1 and G2 (,).
	func testW2ToW4AreUnknownCommandInEveryGateStateBeforeTheGate() throws {
		let names = try tableNames()
		for name in Self.notBridgeNames {
			XCTAssertFalse(names.contains(name), "\(name) is not a table name")
			XCTAssertFalse(BeamioConetChatModule.knownBridgeCommand(name), "\(name) is not a bridge name")
			for gate in ["G0", "G1", "G2"] {
				let events = dispatch(["type": name, "reqId": 9700], gate: gate)
				XCTAssertEqual(events.count, 1, "\(name) at \(gate): one answer")
				XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "\(name) at \(gate): unknown_command")
			}
		}
	}
}
