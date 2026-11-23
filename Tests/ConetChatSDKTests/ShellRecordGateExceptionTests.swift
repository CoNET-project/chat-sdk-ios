import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The G0 exception for the record commands: an imported copy of the account lets `shellRecordRead` and `shellRecordWrite`
/// run at G0; a fresh device answers `absent`; the reader's verdicts come first; the origin is judged before everything. Vectors GX-01 to GX-10b of
/// `pgp-migration-vectors.v1.json`. The copy and the record are synthetic.
final class ShellRecordGateExceptionTests: XCTestCase {
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	/// These cases are about a device with no native key: the memory store, not the simulator's unreadable Keychain.
	override func setUp() {
		super.setUp()
		savedNativeStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			records[account] = record
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		// The pin is the file's content: pgp-migration-vectors.v1.json, 0e1814c9 (r2.5.12; the superseded adc87ed2 (r2.5.11) and 06f434ca are refused).
		XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
		               "0e1814c96db11c9c2824f9f2f6cce4f919aaf0438aa6afe69c7ac84752c1c439", "pgp-migration-vectors v1 is the pinned file")
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func canonical(_ value: Any?) -> String {
		// A bare scalar is not a valid top-level JSON object: it is wrapped in an array, and the brackets are removed. Without this every scalar
		// compared as "invalid" on both sides, so it always matched.
		guard let value else { return "null" }
		guard JSONSerialization.isValidJSONObject([value]),
		      let data = try? JSONSerialization.data(withJSONObject: [value], options: [.sortedKeys]),
		      let text = String(data: data, encoding: .utf8)
		else { return "invalid" }
		return String(text.dropFirst().dropLast())
	}

	/// The environment of a GX case: the account is `eoa`, the gate and the origin come from the case, and the legacy reader state sets the first-run.
	private func environment(_ input: [String: Any]) -> (BeamioShellRecord.Environment, Store) {
		let eoa = input["eoa"] as? String ?? "a1"
		let store = Store()
		if let copy = input["store"] as? [String: Any], let record = copy["record"] as? [String: Any] {
			store.records[eoa] = record
		}
		let gate: BeamioConetChatModule.NativeGate
		switch input["gate"] as? String {
		case "G1": gate = .g1
		case "G2": gate = .g2
		default: gate = .g0
		}
		let first: BeamioShellRecord.FirstRunState
		switch input["legacy"] as? String {
		case "absent": first = .confirmedAbsent
		case "unreadable": first = .notRun
		default: first = .notRun
		}
		let device = Device()
		device.state.legacyUnreadable = (input["legacy"] as? String) == "unreadable"
		device.state.legacyConfirmedAbsent = (input["legacy"] as? String) == "absent"
		let env = BeamioShellRecord.Environment(
			account: { eoa },
			store: store,
			device: device,
			originAllowed: (input["origin"] as? String) != "refused",
			migrating: { _ in false },
			firstRun: { _ in first },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved,
			gate: { gate }
		)
		return (env, store)
	}

	/// GX-01 to GX-10b. Each case answers one command, and the ack envelope must equal the expectation.
	func testTheGateExceptionMatchesTheVectors() throws {
		let cases = PgpMigrationTestSupport.sidecar(try vectorRoot()["gateExceptionCases"] as Any) as? [[String: Any]] ?? []
		let answered = cases.filter { ($0["kind"] as? String) != "other" }
		XCTAssertEqual(answered.count, 9)
		for c in answered {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			let req = c["req"] as? [String: Any] ?? [:]
			let kind = c["kind"] as? String ?? ""
			var body: [String: Any] = ["type": kind == "write" ? "shellRecordWrite" : "shellRecordRead", "reqId": req["reqId"] ?? ""]
			if kind == "write", let record = req["record"] { body["record"] = record }
			let (env, _) = environment(input)
			let answer = BeamioShellRecord.answer(body, env: env)
			XCTAssertEqual(canonical(BeamioShellRecord.ackEnvelope(for: answer)), canonical(c["expect"]), id)
		}
	}

	/// GX-06 and GX-07: any other native command gets `no_key` at G0, with or without an imported copy.
	func testOtherNativeCommandsStayNoKeyAtG0WithOrWithoutACopy() throws {
		let cases = PgpMigrationTestSupport.sidecar(try vectorRoot()["gateExceptionCases"] as Any) as? [[String: Any]] ?? []
		let other = cases.filter { ($0["kind"] as? String) == "other" }
		XCTAssertEqual(other.count, 2)
		for c in other {
			let id = c["id"] as? String ?? "?"
			XCTAssertEqual(BeamioConetChatModule.gateRefusal(type: "send", gate: .g0), "no_key", id)
			XCTAssertEqual(canonical(c["expect"]), canonical(["type": "ack", "ok": false, "error": "no_key"]), id)
		}
	}

	/// The record commands are not refused by the gate table; BeamioShellRecord judges them at every gate state.
	func testTheRecordCommandsAreJudgedByTheRecordAtEveryGateState() {
		for type in ["shellRecordRead", "shellRecordWrite"] {
			for gate in [BeamioConetChatModule.NativeGate.g0, .g1, .g2] {
				XCTAssertNil(BeamioConetChatModule.gateRefusal(type: type, gate: gate), "\(type) \(gate)")
			}
		}
	}
}
