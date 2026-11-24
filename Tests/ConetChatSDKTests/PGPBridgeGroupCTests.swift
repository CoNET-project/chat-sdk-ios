#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The group C vectors of `pgp-bridge-command-vectors.v1.json`. The digest is the registered one. Of the
/// 33 cases of group C; those whose gate and request can be driven through the bridge with the seams of the test target are run here: C-04, C-05, C-21 to C-27 and C-31 to C-33.
/// The others need a chain or backup fixture, a native confirmation flow, a pending state, or a write in flight. They are reported as not run, and none
/// of them is claimed as passed. Synthetic data only.
final class PGPBridgeGroupCTests: XCTestCase {
	private final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		/// The key record cannot be read now (the storage state is unknown): the gate answers not_ready with no reason.
		var unreadable = false
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { unreadable ? .unreadable : (keys[eoa.lowercased()] == nil ? .absent : .present) }
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

	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	/// A synthetic hardware layer for the test only: wrap and unwrap are the identity. It is not a security control.
	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	/// The registered digest of `pgp-bridge-command-vectors.v1.json`.
	static let expectedSHA256 = "40ac9784730ddbdda5ed5cce96269973f833db90acd6c9073e890367a77280d6"

	/// The cases run here, by the gate they need. Every other case of group C is listed as not run.
	static let runnable: Set<String> = ["C-04", "C-05", "C-21", "C-22", "C-23", "C-24", "C-25", "C-26", "C-27", "C-31", "C-32", "C-33"]

	private let account = PgpMigrationTestSupport.eoa

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_BRIDGE_VECTORS"] else {
			throw XCTSkip("set PGP_BRIDGE_VECTORS to interface/protocol/pgp-bridge-command-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
		              "the pgp-bridge vector file differs from the registered digest (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// The gate of a case: G0 without a native record, G1 with a record and no session, G2 with a session, and G2 with a passcode locked (the
	/// lock is made on the unlocked session). Returns the restore closure.
	private func arrange(gate: String) -> () -> Void {
		let savedStore = BeamioNativeWallet.keyStore
		let savedVault = BeamioPasscodeSession.shared.vault
		let savedMemory = BeamioChatPgpKeychain.memory
		NativeAccountPointerIsolation.begin()
		let store = Store()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
		let records = MemoryRecords()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		BeamioPasscodeSession.shared.lockAll()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		switch gate {
		case "G0":
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		case "G1":
			store.keys[account] = Data(repeating: 0x11, count: 32)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		case "G2", "G2_locked", "G2_storage_unknown":
			store.keys[account] = Data(repeating: 0x11, count: 32)
			if gate == "G2_storage_unknown" { store.unreadable = true }
			BeamioConetChatSignBroker.setSignerEoa(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
			if gate == "G2_locked" {
				records.data[account] = (try? JSONEncoder().encode(
					BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
				)) ?? Data()
				BeamioPasscodeSession.shared.install(eoa: account, bundle: [UInt8](repeating: 0x33, count: 32))
				BeamioPasscodeSession.shared.lockAll()
			}
		default:
			XCTFail("unknown gate \(gate)")
		}
		return {
			BeamioPasscodeSession.shared.lockAll()
			BeamioPasscodeSession.shared.vault = savedVault
			BeamioChatPgpKeychain.memory = savedMemory
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
	}

	/// Every payload the bridge emits for one request. The main queue is drained first, so a late emit is seen.
	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	/// A-08 (group A, `pgpDecryptInbound` at G2 with the passcode bundle not provided): not_ready with the top level reason passcode_not_provided, and no other event. The row is
	/// driven through the same gate arrangement and compared with the vector row.
	func testA08DecryptWithoutThePasscodeBundleAnswersNotReadyWithTheReason() throws {
		let cases = try vectorUnwrap { try vectorRoot()["cases"] as? [[String: Any]] }
		let row = try XCTUnwrap(cases.first { $0["id"] as? String == "A-08" }, "A-08")
		let request = try XCTUnwrap(row["request"] as? [String: Any])
		let reqId = try XCTUnwrap(request["reqId"] as? String)
		let restore = arrange(gate: row["gate"] as? String ?? "")
		let events = dispatch(request)
		restore()
		XCTAssertEqual(events.filter { $0["reqId"] as? String == reqId }.count, 1, "A-08: one answer")
		let differing = try GroupCVector.differences(row: row, answers: events)
		print("GROUP-A-RUN A-08: \(differing.isEmpty ? "matches the vector" : "differs in \(differing.joined(separator: ", "))")")
		XCTAssertTrue(differing.isEmpty, "A-08: the answers differ from the vector in \(differing.joined(separator: ", "))")
	}

	/// C-04, C-05, C-21 to C-27 and C-31 to C-33: each runs once, in its gate, and answers the vector's ack with no other event (`events` is empty in the vector).
	func testTheRunnableCasesAnswerTheVectorInTheirGate() throws {
		let cases = try vectorUnwrap { try vectorRoot()["cases"] as? [[String: Any]] }.filter { $0["group"] as? String == "C" }
		XCTAssertEqual(cases.count, 33, "group C has 33 cases")
		var ran: [String] = []
		for c in cases {
			let id = c["id"] as? String ?? "?"
			guard Self.runnable.contains(id) else {
				print("GROUP-C-NOT-RUN \(id): needs a chain, backup, confirmation or pending fixture; not claimed as passed")
				continue
			}
			let request = try XCTUnwrap(c["request"] as? [String: Any], id)
			let reqId = try XCTUnwrap(request["reqId"] as? String, id)
			let restore = arrange(gate: c["gate"] as? String ?? "")
			let events = dispatch(request)
			restore()
			let acks = events.filter { $0["reqId"] as? String == reqId }
			XCTAssertEqual(acks.count, 1, "\(id): one answer")
			let differing = try GroupCVector.differences(row: c, answers: events)
			print("GROUP-C-RUN \(id): \(differing.isEmpty ? "matches the vector" : "differs in \(differing.joined(separator: ", "))")")
			XCTAssertTrue(differing.isEmpty, "\(id): the answer differs from the vector in \(differing.joined(separator: ", "))")
			XCTAssertEqual(events.count, 1, "\(id): no other event")
			ran.append(id)
		}
		XCTAssertEqual(ran.sorted(), Self.runnable.sorted(), "every runnable case ran")
	}
}
#endif
