import CryptoKit
import XCTest
@testable import ConetChatSDK

/// T-155: every name of no-key-reject-vectors.v1.json is refused with `no_key` while the account has
/// no native record, with no data, no event and no key byte. The list has 27 wallet names, 21 chat names and 3 retired
/// names (51 in all). Runs with NO_KEY_REJECT_VECTORS=<path to the file>; skipped without it. The expectations are the
/// vector file's. Synthetic values only: the secret payloads use 0x11…11, never the test key P.
final class NoKeyRejectVectorTests: XCTestCase {
	static let expectedSHA256 = "7491137e9532fe199aa9f9ff9d57fce09c33f55e2dab7e094c07045220cb08e5"  // registration (; walletCommands 25, noKeyTotal 54)

	/// The account of the synthetic 0x11…11 key (the same as the bridge tests), and a second account with no record.
	private let accountWithKey = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let accountWithoutKey = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let secret = String(repeating: "11", count: 32)

	/// In-memory native store (writes are counted: a refused command must write nothing).
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var writes = 0
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			keys[eoa.lowercased()] = key
			return true
		}
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

	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	/// The two no-key states of T-155: no session at all (cold start), and a session for an account with no native record.
	private enum State: CaseIterable {
		case coldStart
		case sessionWithoutRecord
	}

	private func enter(_ state: State) {
		store.keys = [:]
		switch state {
		case .coldStart: BeamioConetChatSignBroker.clearSigner()
		case .sessionWithoutRecord: BeamioConetChatSignBroker.setSignerEoa(accountWithoutKey)
		}
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["NO_KEY_REJECT_VECTORS"] else {
			throw XCTSkip("set NO_KEY_REJECT_VECTORS to interface/protocol/no-key-reject-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256, "vector file sha256 differs from the published value (the digest is not printed, so a failure leaves no digest in the log)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func rows(_ key: String) throws -> [[String: Any]] {
		try vectorUnwrap { try vectorRoot()[key] as? [[String: Any]] }
	}

	/// One bridge command through the entry point. The answer is posted on the main queue, so the queue is drained first.
	/// Returns every event the command emitted, in order.
	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			events.append((event["event"] as? [String: Any]) ?? event)
		})
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		let type = body["type"] as? String ?? ""
		let line: [String: Any] = ["type": type, "keys": body.keys.sorted()]
		if let data = try? JSONSerialization.data(withJSONObject: line, options: [.sortedKeys]),
		   let text = String(data: data, encoding: .utf8) {
			Self.bridgeRecord.append(text)
		}
		let first = events.first
		let okValue: Any = first?["ok"] ?? NSNull()
		let errorValue: Any = first?["error"] ?? NSNull()
		Self.answerReport.append([
			"command": type,
			"events": events.count,
			"ok": okValue,
			"error": errorValue,
			"hasResult": first?["result"] != nil,
		])
		return events
	}

	/// Test-side records for the log scan. The bridge record holds names and key names only; the answer report holds
	/// codes and counts only. Neither holds a value. Written at the end of the class when BRIDGE_RECORD_PATH or
	/// NO_KEY_REPORT_PATH is set (the scan sources SRC-7 and SRC-9).
	private static var bridgeRecord: [String] = []
	private static var answerReport: [[String: Any]] = []

	override class func tearDown() {
		let env = ProcessInfo.processInfo.environment
		if let path = env["BRIDGE_RECORD_PATH"] {
			let text = bridgeRecord.joined(separator: "\n") + "\n"
			try? text.write(toFile: path, atomically: true, encoding: .utf8)
		}
		if let path = env["NO_KEY_REPORT_PATH"],
		   let data = try? JSONSerialization.data(withJSONObject: answerReport, options: [.prettyPrinted, .sortedKeys]) {
			try? data.write(to: URL(fileURLWithPath: path))
		}
		super.tearDown()
	}

	private func assertNoKeyOnly(_ events: [[String: Any]], reqId: Int, _ id: String) {
		XCTAssertEqual(events.count, 1, "\(id): one answer and nothing else (no event, no output)")
		guard let ack = events.first else { return }
		XCTAssertEqual(ack["type"] as? String, "ack", id)
		XCTAssertEqual(ack["reqId"] as? Int, reqId, id)
		XCTAssertEqual(ack["ok"] as? Bool, false, id)
		XCTAssertEqual(ack["error"] as? String, "no_key", id)
		XCTAssertNil(ack["result"], "\(id): no data is returned")
	}

	/// The body sent for a vector row: its name, and the `kind` or `mode` the row names. The payload carries the account, so
	/// the refusal does not depend on a missing account field.
	private func body(for row: [String: Any], reqId: Int) -> [String: Any] {
		var body: [String: Any] = ["type": row["command"] as? String ?? "", "reqId": reqId,
		                           "payload": ["identity": ["eoaAddress": accountWithoutKey], "eoa": accountWithoutKey]]
		if let kind = row["kind"] as? String { body["kind"] = kind }
		if let mode = row["mode"] as? String { body["mode"] = mode }
		return body
	}

	// MARK: - Counts (the list as published)

	func testTheListHasTheCountsOfTheSpec() throws {
		// The rows are loaded first, so a vector file that is not set skips the test instead of failing each assertion.
		let wallet = try rows("walletCommands").count
		let chat = try rows("chatCommands").count
		let retired = try rows("retiredCommands").count
		let secret = try rows("secretPayloadControls").count
		XCTAssertEqual(wallet, 25, "wallet layer: 25 names")
		XCTAssertEqual(chat, 29, "chat layer: 29 names")
		XCTAssertEqual(retired, 3, "retired: 3 names")
		XCTAssertEqual(wallet + chat, 54, "no-key list: 54 names")
		XCTAssertEqual(secret, 3, "NK-P1 to NK-P3")
	}

	// MARK: - T-155: the 48 no-key names

	/// Every name of the no-key list (54 rows) is answered with the code of its own vector row, in every state: `no_key` for the names of the command
	/// table, `unknown_command` for the names outside it (,). The W2 to W4 and signMessage rows are not excluded.
	func testEveryWalletAndChatNameAnswersItsVectorCodeInEveryState() throws {
		let names = try rows("walletCommands") + rows("chatCommands")
		XCTAssertEqual(names.count, 54, "the no-key list has 54 rows")
		for state in State.allCases {
			enter(state)
			for (index, row) in names.enumerated() {
				let id = row["id"] as? String ?? "?"
				let reqId = 1000 + index
				let expected = row["expectCode"] as? String ?? ""
				XCTAssertTrue(expected == "no_key" || expected == "unknown_command", "\(id): the vector code is a bridge code")
				let events = dispatch(body(for: row, reqId: reqId))
				XCTAssertEqual(events.count, 1, "\(id) (\(state)): one answer and nothing else")
				XCTAssertEqual(events.first?["type"] as? String, "ack", "\(id) (\(state))")
				XCTAssertEqual(events.first?["reqId"] as? Int, reqId, "\(id) (\(state)): reqId echoed")
				XCTAssertEqual(events.first?["ok"] as? Bool, false, "\(id) (\(state))")
				XCTAssertEqual(events.first?["error"] as? String, expected, "\(id) (\(state)): the vector code")
				XCTAssertNil(events.first?["result"], "\(id) (\(state)): no data is returned")
			}
			XCTAssertEqual(store.writes, 0, "nothing is written in \(state)")
			XCTAssertTrue(store.keys.isEmpty, "no record is created in \(state)")
		}
	}

	/// NK-W2 to NK-W4 are bridge rows now. The vector expects `unknown_command`, once, in every state, before the gate. The
	/// wallet functions behind them answer `no_key` and `not_ready` natively (WalletLayerGateTests), not through the bridge.
	func testW2ToW4AreUnknownCommandAsBridgeRowsInEveryState() throws {
		let names: Set<String> = ["deriveLocalKeys", "protocolKeys", "fragmentKeys"]
		let rowsOfThree = try (rows("walletCommands") + rows("chatCommands")).filter { names.contains($0["command"] as? String ?? "") }
		XCTAssertEqual(rowsOfThree.count, 3, "NK-W2 to NK-W4")
		for row in rowsOfThree {
			XCTAssertEqual(row["expectCode"] as? String, "unknown_command", "\(row["id"] ?? "?"): the bridge answer")
		}
		for state in State.allCases {
			enter(state)
			for (index, row) in rowsOfThree.enumerated() {
				let reqId = 3000 + index
				let events = dispatch(body(for: row, reqId: reqId))
				let id = row["id"] as? String ?? "?"
				XCTAssertEqual(events.count, 1, "\(id) (\(state)): one answer")
				XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "\(id) (\(state))")
				XCTAssertEqual(events.first?["reqId"] as? Int, reqId, "\(id) (\(state)): reqId echoed")
			}
		}
	}

	/// The `signMessage` rows differ only by `kind`; a refused kind is refused the same way (kind is checked after no_key).
	func testTheSevenSignMessageKindsAreNotDispatchedInside() throws {
		// the seven `signMessage` kinds are not dispatched by the SDK. Each is `unknown_command`, exactly once, in every state. The outer
		// shell answers `no_key` for them, and that layer is not run here.
		let kinds = try rows("walletCommands").filter { $0["command"] as? String == "signMessage" }
		XCTAssertEqual(kinds.count, 7)
		enter(.sessionWithoutRecord)
		for (index, row) in kinds.enumerated() {
			let reqId = 2000 + index
			let events = dispatch(body(for: row, reqId: reqId))
			XCTAssertEqual(events.count, 1, "\(row["id"] ?? "?"): one answer")
			XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "\(row["id"] ?? "?")")
			XCTAssertEqual(events.first?["reqId"] as? Int, reqId, "\(row["id"] ?? "?"): reqId echoed")
		}
	}

	/// A name in the command table is refused with `no_key` (the gate). A name outside the table is `unknown_command` in every state, judged before
	/// the gate (,): not `no_key`. Neither stores anything.
	func testUnlistedNamesAreUnknownCommandInEveryStateAndTableNamesAreNoKey() {
		for state in State.allCases {
			enter(state)
			for (index, name) in ["notAListedName", "historyFutureCommand"].enumerated() {
				let reqId = 3000 + index
				let events = dispatch(["type": name, "reqId": reqId])
				XCTAssertEqual(events.count, 1, "\(name) (\(state)): one answer")
				XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "\(name) (\(state))")
				XCTAssertEqual(events.first?["reqId"] as? Int, reqId, "\(name) (\(state)): reqId echoed")
			}
		}
		enter(.coldStart)
		for (index, name) in ["historyOpenConversation", "clearIdentity"].enumerated() {
			let reqId = 3010 + index
			assertNoKeyOnly(dispatch(["type": name, "reqId": reqId]), reqId: reqId, name)
		}
		XCTAssertTrue(store.keys.isEmpty)
	}

	// MARK: - T-155: the retired names answer not_supported first (表 C)

	func testTheRetiredNamesAreNotSupportedNotNoKey() throws {
		for state in State.allCases {
			enter(state)
			for (index, row) in try rows("retiredCommands").enumerated() {
				let id = row["id"] as? String ?? "?"
				let reqId = 4000 + index
				let events = dispatch(["type": row["command"] as? String ?? "", "reqId": reqId, "payload": ["eoa": accountWithoutKey]])
				XCTAssertEqual(events.count, 1, "\(id) (\(state))")
				XCTAssertEqual(events.first?["error"] as? String, row["expectCode"] as? String, "\(id) (\(state))")
				XCTAssertNotEqual(events.first?["error"] as? String, "no_key", id)
				XCTAssertNil(events.first?["result"], id)
			}
		}
		XCTAssertEqual(store.writes, 0)
	}

	// MARK: - T-155: the status queries and the secret-payload controls (表 D, 表 E)

	func testWalletStatusReportsNoKeyWithoutAnAccountKey() {
		for state in State.allCases {
			enter(state)
			let events = dispatch(["type": "walletStatus", "reqId": 5001])
			XCTAssertEqual(events.count, 1, "\(state)")
			XCTAssertEqual(events.first?["ok"] as? Bool, true, "\(state)")
			let result = events.first?["result"] as? [String: Any]
			XCTAssertEqual(result?["status"] as? String, "no_key", "\(state)")
			XCTAssertNil(result?["accountKey"], "\(state): no account key is returned without a key")
		}
	}

	func testPasscodeStatusReportsNoRecordAsAllFalse() {
		enter(.coldStart)
		let result = dispatch(["type": "passcodeStatus", "reqId": 5002]).first?["result"] as? [String: Any]
		XCTAssertEqual(result?["set"] as? Bool, false)
		XCTAssertEqual(result?["locked"] as? Bool, false)
		XCTAssertEqual(result?["hasKey"] as? Bool, false)
	}

	/// A private key in an identity command is refused as `key_over_bridge_refused` before the gate, in every state (step 2). `send` is not
	/// such a command: it keeps its gate and answers `no_key`. None of them is echoed or stored.
	func testSecretPayloadsAreRefusedAndNeverEchoed() {
		let pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----"
		let controls: [(String, [String: Any], String)] = [
			("init", ["identity": ["eoaAddress": accountWithoutKey, "privateKeyHex": secret]], "key_over_bridge_refused"),
			("identity.provision", ["eoa": accountWithoutKey, "pgpPrivateKeyArmored": pgp], "key_over_bridge_refused"),
			("send", ["eoa": accountWithoutKey, "walletPrivateKey": secret], "no_key"),
		]
		for state in State.allCases {
			enter(state)
			for (index, control) in controls.enumerated() {
				let reqId = 5100 + index
				let events = dispatch(["type": control.0, "reqId": reqId, "payload": control.1])
				XCTAssertEqual(events.count, 1, "\(control.0) (\(state)): one answer")
				XCTAssertEqual(events.first?["error"] as? String, control.2, "\(control.0) (\(state))")
				XCTAssertEqual(events.first?["reqId"] as? Int, reqId, "\(control.0) (\(state)): reqId echoed")
				let seen = String(describing: events)
				XCTAssertFalse(seen.contains(secret), "\(control.0): the private key value is not echoed")
				XCTAssertFalse(seen.contains("PRIVATE KEY BLOCK"), "\(control.0): the armor is not echoed")
			}
			XCTAssertTrue(store.keys.isEmpty, "no key is stored from a payload in \(state)")
		}
	}

	// MARK: - The gate does not refuse a native-key account

	/// The gate is for accounts with no record only. With a key for the account, `walletStatus` answers its state and the
	/// account key (eoa + ":default", D5), and `passcodeStatus` reports `hasKey: true`.
	func testWithANativeKeyTheExemptStatusQueriesAnswer() {
		store.keys[accountWithKey] = Data(repeating: 0x11, count: 32)
		BeamioConetChatSignBroker.setSignerEoa(accountWithKey)
		BeamioConetChatModule.setNativeGateForTests(account: accountWithKey, sessionReady: true)
		let status = dispatch(["type": "walletStatus", "reqId": 6001]).first?["result"] as? [String: Any]
		XCTAssertEqual(status?["status"] as? String, "unlocked")
		XCTAssertEqual(status?["accountKey"] as? String, accountWithKey + ":default")
		let passcode = dispatch(["type": "passcodeStatus", "reqId": 6002]).first?["result"] as? [String: Any]
		XCTAssertEqual(passcode?["hasKey"] as? Bool, true)
	}

	/// With the account's key present the gate is open: an unlisted name gets `unknown_command`, as before (the no-key
	/// default deny does not apply to a native-key account).
	func testWithANativeKeyAnUnknownNameIsUnknownCommand() {
		store.keys[accountWithKey] = Data(repeating: 0x11, count: 32)
		BeamioConetChatSignBroker.setSignerEoa(accountWithKey)
		BeamioConetChatModule.setNativeGateForTests(account: accountWithKey, sessionReady: true)
		let events = dispatch(["type": "notAListedName", "reqId": 6003])
		XCTAssertEqual(events.first?["error"] as? String, "unknown_command")
		// The refusal is the only output: no other event follows it (; the actual code is reported, not changed, per).
		XCTAssertEqual(events.count, 1, "one answer, no other output")
	}
	/// The envelope first (step 1,): a missing, non-integer, negative, or oversized reqId is `bad_request` with reqId null, for any
	/// name, unknown or not. The integer 0 is valid and echoed (T-179). Nothing is stored.
	func testAnInvalidReqIdIsBadRequestWithNullAndZeroIsValid() {
		enter(.coldStart)
		let invalid: [(String, [String: Any])] = [
			("notAListedName", ["type": "notAListedName"]),
			("hello", ["type": "hello"]),
			("hello", ["type": "hello", "reqId": -1]),
			("hello", ["type": "hello", "reqId": 1.5]),
			("hello", ["type": "hello", "reqId": ""]),
			("send", ["type": "send", "reqId": 9_007_199_254_740_992]),
		]
		for (name, body) in invalid {
			let events = dispatch(body)
			XCTAssertEqual(events.count, 1, "\(name): one answer")
			XCTAssertEqual(events.first?["error"] as? String, "bad_request", name)
			XCTAssertTrue(events.first?["reqId"] is NSNull, "\(name): reqId is null")
		}
		let zero = dispatch(["type": "hello", "reqId": 0])
		XCTAssertEqual(zero.first?["reqId"] as? Int, 0, "the integer 0 is echoed")
		XCTAssertEqual(zero.first?["ok"] as? Bool, true, "hello answers ok with reqId 0")
		XCTAssertTrue(store.keys.isEmpty)
	}

	/// the rejection control of an unknown name in each gate state of this harness (G0, G1, G2). The locked and busy states have no
	/// test hook in the SDK; they are reported as not exercised, not as passed.
	func testAnUnknownNameIsUnknownCommandInEveryGateState() {
		let name = "notAListedName"
		enter(.coldStart)
		var events = dispatch(["type": name, "reqId": 7001])
		XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "G0")
		XCTAssertEqual(events.count, 1, "G0: one answer")
		// G1: a record is on the device, and the session has not completed init.
		store.keys[accountWithKey] = Data(repeating: 0x11, count: 32)
		BeamioConetChatSignBroker.setSignerEoa(accountWithKey)
		BeamioConetChatModule.setNativeGateForTests(account: accountWithKey, sessionReady: false)
		events = dispatch(["type": name, "reqId": 7002])
		XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "G1")
		XCTAssertEqual(events.count, 1, "G1: one answer")
		// G2: the record is on the device and the session is ready.
		BeamioConetChatModule.setNativeGateForTests(account: accountWithKey, sessionReady: true)
		events = dispatch(["type": name, "reqId": 7003])
		XCTAssertEqual(events.first?["error"] as? String, "unknown_command", "G2")
		XCTAssertEqual(events.count, 1, "G2: one answer")
	}

	/// The allowed names of the vector are not gated in the no-key state: no `no_key` answer.
	func testTheAllowedNamesAreNotGatedInTheNoKeyState() throws {
		let allowed = try vectorUnwrap { try vectorRoot()["allowedUnderNoKey"] as? [String] }
		XCTAssertEqual(Set(allowed), ["destroy", "hello", "nativeAccountCreateOpen", "nativeMnemonicPreread", "nativeRecoveryOpen", "passcodeStatus", "pause", "resume", "walletStatus"])
		// The recovery page is registered: without a host, nativeRecoveryOpen answers not_supported.
		BeamioNativeRecovery.onRecoveryRequired = { _ in true }
		defer { BeamioNativeRecovery.onRecoveryRequired = nil }
		enter(.coldStart)
		for (index, name) in allowed.enumerated() {
			let events = dispatch(["type": name, "reqId": 8000 + index])
			XCTAssertFalse(events.contains { ($0["error"] as? String) == "no_key" }, "\(name): an allowed name is not refused with no_key")
		}
		// The loop above opened the page once; close it first, since a second open while one is pending is not_available.
		BeamioNativeRecovery.finish(.cancelled)
		// nativeRecoveryOpen acknowledges (.2) and carries no data.
		// The cancelled result of the page closed above may reach this sink first; the ack is the answer to this command.
		let open = dispatch(["type": "nativeRecoveryOpen", "reqId": 8100]).first { ($0["type"] as? String) == "ack" }
		XCTAssertEqual(open?["ok"] as? Bool, true)
		XCTAssertNil(open?["result"])
	}
}
