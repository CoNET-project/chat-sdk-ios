import XCTest
@testable import ConetChatSDK

/// The page transport of the record bridge (TP-01 to TP-10, spec), the SDK acceptance per platform (SA-01 to SA-04,), the origin
/// check of the chat-module channel and the QA hook rules that every build keeps (HK-03,), from
/// `pgp-migration-vectors.v1.json`. The QA hook's own behaviour (HK-01) is in PgpShellRecordTests, under the QA condition. Synthetic data only.
final class ShellRecordTransportTests: XCTestCase {
	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	/// The first event of a chat-module answer. The emit runs on the main queue, so the test waits for it.
	private func chatEvent(_ body: [String: Any]) -> [String: Any]? {
		let answered = expectation(description: "chat-module answer")
		var payload: [String: Any]?
		let emit: BeamioConetChatModule.WebEmit = { received in
			payload = received
			answered.fulfill()
		}
		BeamioConetChatModule.handleCommand(body, emit: emit)
		wait(for: [answered], timeout: 5)
		return payload?["event"] as? [String: Any]
	}

	func testTheTransportChoiceMatchesTheVectors() throws {
		let cases = try vectorRoot()["transportCases"] as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 10)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			let expect = c["expect"] as? [String: Any] ?? [:]
			guard let platform = BeamioShellRecordTransport.Platform(rawValue: input["platform"] as? String ?? "") else {
				XCTFail("\(id): unknown platform")
				continue
			}
			let choice = BeamioShellRecordTransport.choose(
				platform: platform,
				windowInjected: input["windowInjected"] as? Bool ?? false,
				chatChannel: input["chatChannel"] as? Bool ?? false,
				originAllowed: input["originAllowed"] as? Bool ?? false
			)
			XCTAssertEqual(choice.via, expect["via"] as? String, id)
			XCTAssertEqual(choice.error, expect["error"] as? String, id)
		}
	}

	func testTheSDKAcceptanceMatchesTheVectors() throws {
		let cases = try vectorRoot()["sdkAcceptCases"] as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 4)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			guard let platform = BeamioShellRecordTransport.Platform(rawValue: input["platform"] as? String ?? ""),
			      let channel = BeamioShellRecordTransport.Channel(rawValue: input["channel"] as? String ?? "")
			else {
				XCTFail("\(id): unknown platform or channel")
				continue
			}
			XCTAssertEqual(BeamioShellRecordTransport.sdkAccepts(platform: platform, channel: channel), c["expect"] as? Bool, id)
		}
	}

	/// Every payload the chat-module channel emits for the command. The main queue is drained first, so a late emit is seen.
	private func chatPayloads(_ body: [String: Any]) -> [[String: Any]] {
		var payloads: [[String: Any]] = []
		let emit: BeamioConetChatModule.WebEmit = { payloads.append($0) }
		BeamioConetChatModule.handleCommand(body, emit: emit)
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return payloads
	}

	///,: the chat channel does not receive the origin. The shell has verified the sender before the call, so the SDK answers
	/// shellRecordRead and shellRecordWrite with the record (one answer, reqId echoed), and any other shellRecord* name with `unknown_command`, exactly
	/// once. The rule (`not_supported` on the chat channel) is the Android rule and does not apply to iOS.
	func testTheChatChannelAnswersTheRecordAndUnknownNamesOnceTheShellHasVerifiedTheSender() {
		let read: [String: Any] = ["type": "shellRecordRead", "reqId": "tp-chat-1"]
		let write: [String: Any] = ["type": "shellRecordWrite", "reqId": "tp-chat-2", "record": ["rev": 0, "schemaVersion": 1]]
		let other: [String: Any] = ["type": "shellRecordFlush", "reqId": "tp-chat-3"]
		for reqId in ["tp-chat-1", "tp-chat-2"] {
			let body = reqId == "tp-chat-1" ? read : write
			let payloads = chatPayloads(body)
			XCTAssertEqual(payloads.count, 1, "\(reqId): exactly one answer")
			let event = payloads.first?["event"] as? [String: Any]
			XCTAssertEqual(event?["reqId"] as? String, reqId, "\(reqId): reqId echoed")
			XCTAssertNotEqual(event?["error"] as? String, "not_supported", "\(reqId): the chat channel carries the record")
			XCTAssertNotEqual(event?["error"] as? String, "unknown_command", "\(reqId): a record name is known")
			XCTAssertNotEqual(event?["error"] as? String, "origin_refused", "\(reqId): the SDK does not judge the origin")
		}
		let payloads = chatPayloads(other)
		XCTAssertEqual(payloads.count, 1, "tp-chat-3: exactly one answer")
		let event = payloads.first?["event"] as? [String: Any]
		XCTAssertEqual(event?["ok"] as? Bool, false, "tp-chat-3")
		XCTAssertEqual(event?["error"] as? String, "unknown_command", "tp-chat-3: an unknown shellRecord name")
		XCTAssertEqual(event?["reqId"] as? String, "tp-chat-3", "tp-chat-3: reqId echoed")
		XCTAssertNil(event?["result"], "tp-chat-3: no record is returned")
	}

	/// HK-03: no bridge exposes the QA hook, in any build. A hook-like command name on either channel is not a success, even with a
	/// verified origin, and it never reaches the store.
	func testTheQAHookIsNotReachableFromAnyBridge() {
		for name in ["qaRemoveEOAPrivateKey", "shellRecordQAStripKey"] {
			let windowAnswer = BeamioShellRecord.handle(["type": name, "reqId": "hk-\(name)"], originAllowed: true)
			XCTAssertNotEqual(windowAnswer?["code"] as? String, "ok", name)
			let chatAnswer = chatEvent(["type": name, "reqId": "hk-chat-\(name)"])
			XCTAssertNotEqual(chatAnswer?["ok"] as? Bool, true, name)
		}
	}

	/// Waits until the main queue has run everything queued before this call. Emits are queued there.
	private func drainMainQueue() {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
	}

	/// the record commands are not refused by the gate table. BeamioShellRecord judges them at every gate state.
	func testTheGateDoesNotRefuseRecordCommandsAndDefersToTheRecord() {
		for type in ["shellRecordRead", "shellRecordWrite"] {
			XCTAssertNil(BeamioConetChatModule.gateRefusal(type: type, gate: .g0), type)
			XCTAssertNil(BeamioConetChatModule.gateRefusal(type: type, gate: .g1), type)
			XCTAssertNil(BeamioConetChatModule.gateRefusal(type: type, gate: .g2), type)
		}
		XCTAssertEqual(BeamioConetChatModule.gateRefusal(type: "init", gate: .g0), "no_key")
		XCTAssertNil(BeamioConetChatModule.gateRefusal(type: "init", gate: .g1))
		XCTAssertNil(BeamioConetChatModule.gateRefusal(type: "walletStatus", gate: .g0))
		XCTAssertNil(BeamioConetChatModule.gateRefusal(type: "hello", gate: .g0))
	}

	/// on the chat channel at G0 without an imported copy, the record commands give no record. The test device holds no native
	/// key and no copy, so this runs at G0. The read and the write are the reader's decision (`absent`, `migrating` or the reader's error), and no record leaves the store.
	func testTheChatChannelAtG0GivesNoRecordWithoutACopy() throws {
		// The native key store is empty for this test. The simulator cannot read the Keychain, and a key store that cannot be
		// enumerated is not ready, so G0 is set here by an empty store, not by the Keychain of the host.
		let savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		defer { BeamioNativeWallet.keyStore = savedKeyStore }
		guard BeamioConetChatModule.nativeGate() == .g0 else {
			throw XCTSkip("the test device holds a native key, so G0 cannot be reached here")
		}
		// the chat channel carries the record for a verified sender. At G0 with no copy, no record is read or written.
		let read = chatEvent(["type": "shellRecordRead", "reqId": "g0-read"])
		XCTAssertNotEqual(read?["error"] as? String, "not_supported", "the chat channel answers the record, not not_supported")
		XCTAssertNil((read?["result"] as? [String: Any])?["record"], "no record at G0 without a copy")
		XCTAssertFalse(String(describing: read ?? [:]).contains("privateKeyArmor"))
		// step 3: a write at G0 without a copy gets the reader's decision (absent, migrating or an error), and writes no record.
		let write = chatEvent(["type": "shellRecordWrite", "reqId": "g0-write", "record": ["rev": 0, "schemaVersion": 1]])
		let writeResult = write?["result"] as? [String: Any]
		// The write answer is ok:true with a result code: `write_failed` when no account is held (no record is written).
		XCTAssertTrue(["absent", "migrating", "error", "write_failed"].contains(writeResult?["code"] as? String ?? ""),
		              "the write gets the reader's decision: ok \(String(describing: write?["ok"])), error \(String(describing: write?["error"])), code \(String(describing: writeResult?["code"]))")
		XCTAssertNil(writeResult?["rev"], "no record is written at G0 without a copy")
	}

	/// the production read at G0 reads no record. The account is taken only when the device holds its native key, so the answer
	/// carries no record and no key field.
	func testTheProductionReadAtG0ReadsNoRecord() throws {
		// The native key store is empty for this test. The simulator cannot read the Keychain, and a key store that cannot be
		// enumerated is not ready, so G0 is set here by an empty store, not by the Keychain of the host.
		let savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		defer { BeamioNativeWallet.keyStore = savedKeyStore }
		guard BeamioConetChatModule.nativeGate() == .g0 else {
			throw XCTSkip("the test device holds a native key, so G0 cannot be reached here")
		}
		let answer = BeamioShellRecord.handle(["type": "shellRecordRead", "reqId": "g0-read"], originAllowed: true)
		XCTAssertNil(answer?["record"])
		XCTAssertFalse(String(describing: answer ?? [:]).contains("privateKeyArmor"))
	}

	/// on the window channel (the shell's `handleShellRecordCommand`), a refused origin is not
	/// processed and gets exactly one `origin_refused` answer, with its reqId echoed.
	func testTheWindowChannelAnswersAnUnverifiedOriginOnceWithOriginRefused() {
		var payloads: [[String: Any]] = []
		let capture: BeamioConetChatModule.WebEmit = { payloads.append($0) }
		// An unknown command sets the module's emit, as the bridge does; its answer is drained and discarded.
		BeamioConetChatModule.handleCommand(["type": "noSuchCommand", "reqId": "w-setup"], emit: capture)
		drainMainQueue()
		payloads.removeAll()
		BeamioConetChatModule.handleShellRecordCommand(["type": "shellRecordRead", "reqId": "w-1"], originAllowed: false)
		BeamioConetChatModule.handleShellRecordCommand(["type": "shellRecordWrite", "reqId": "w-2", "record": ["rev": 0]], originAllowed: false)
		drainMainQueue()
		let events = payloads.compactMap { $0["event"] as? [String: Any] }
		XCTAssertEqual(events.count, 2, "one answer per request")
		XCTAssertEqual(events.first { $0["reqId"] as? String == "w-1" }?["error"] as? String, "origin_refused")
		XCTAssertEqual(events.first { $0["reqId"] as? String == "w-2" }?["error"] as? String, "origin_refused")
		XCTAssertEqual(events.first { $0["reqId"] as? String == "w-2" }?["ok"] as? Bool, false)
	}
}

#if BEAMIO_SHELL_RECORD_QA
/// HK-01: the QA hook exists in a QA build and changes exactly one field. It removes `privateKeyArmor` from the profile whose keyID is the
/// account, so the read answers `needs_native_recovery` (AK-20). This class is compiled only under the BEAMIO_SHELL_RECORD_QA condition.
final class ShellRecordQAHookTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		var writes = 0

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			writes += 1
			records[account] = record
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private func environment(account: String, store: Store) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { account },
			store: store,
			device: Device(),
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	func testTheHookExistsInTheQABuildAndLeavesOnlyThePrivateKeyArmor() {
		let eoa = "0xa1b2c3"
		let store = Store()
		XCTAssertFalse(BeamioShellRecordQAHook.removeEOAPrivateKey(account: eoa, store: store), "no record")
		XCTAssertEqual(store.writes, 0)

		store.records[eoa] = [
			"rev": 3,
			"schemaVersion": 2,
			"mnemonicPhrase": "synthetic mnemonic",
			"recoveryWords": "synthetic words",
			"profiles": [["keyID": eoa, "emailAddr": "x", "privateKeyArmor": PgpMigrationTestSupport.armorA]],
		]
		XCTAssertTrue(BeamioShellRecordQAHook.removeEOAPrivateKey(account: eoa, store: store))
		XCTAssertEqual(store.writes, 1)

		let after = store.records[eoa] ?? [:]
		XCTAssertEqual(after["rev"] as? Int, 3)
		XCTAssertEqual(after["schemaVersion"] as? Int, 2)
		XCTAssertEqual(after["mnemonicPhrase"] as? String, "synthetic mnemonic")
		XCTAssertEqual(after["recoveryWords"] as? String, "synthetic words")
		let profile = (after["profiles"] as? [[String: Any]])?.first ?? [:]
		XCTAssertNil(profile["privateKeyArmor"])
		XCTAssertEqual(profile["keyID"] as? String, eoa)
		XCTAssertEqual(profile["emailAddr"] as? String, "x")

		// A second call finds no key to remove and writes nothing.
		XCTAssertFalse(BeamioShellRecordQAHook.removeEOAPrivateKey(account: eoa, store: store))
		XCTAssertEqual(store.writes, 1)
	}

	/// AK-20: after the hook, a read of the record answers `needs_native_recovery` (ack envelope, `result.code` error, `sub` needs_native_recovery).
	func testTheReadAfterTheHookAnswersNeedsNativeRecovery() {
		let eoa = "0xa1b2c3"
		let store = Store()
		store.records[eoa] = ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": eoa, "emailAddr": "x", "privateKeyArmor": PgpMigrationTestSupport.armorA]]]
		XCTAssertTrue(BeamioShellRecordQAHook.removeEOAPrivateKey(account: eoa, store: store))

		let answer = BeamioShellRecord.answer(
			["type": "shellRecordRead", "reqId": "hk-ak20"],
			env: environment(account: eoa, store: store)
		)
		let envelope = BeamioShellRecord.ackEnvelope(for: answer)
		XCTAssertEqual(envelope["ok"] as? Bool, true)
		let result = envelope["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "error")
		XCTAssertEqual(result?["sub"] as? String, "needs_native_recovery")
	}
}
#endif
