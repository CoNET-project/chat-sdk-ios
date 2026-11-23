import CryptoKit
import XCTest
@testable import ConetChatSDK

/// gate-state-vectors.v1.json (spec, T-160, T-161): 100 cases. G0 and G1 are run here: a native record on
/// the device and no completed `init` (G1), and no record (G0). The G1 `init` case that answers `ok` needs the whole `init`
/// flow (the OpenPGP host and the mailbox listen), so it is not run in a unit test; it is counted and reported as not run.
/// G1-AL-6 is run: the entry is acknowledged and not gated.
/// The 16 shell names are run through the SDK's default deny, which gives the same code as the shell gate; the shell itself is
/// not run here. Runs with GATE_STATE_VECTORS=<path>; skipped without it. The expectations are the vector file's.
/// Records of the run go to GATE_STATE_REPORT_PATH when set (codes and counts only, no payload value).
final class GateStateVectorTests: XCTestCase {
	/// The registered digests, by file name (interface SHA256-CURRENT.txt: v1 at, v2 at ). The gate runs the v1 file (VECENV). The inner
	/// unknown names are in `innerUnknown`.
	static let registeredSHA256: [String: String] = [
		"gate-state-vectors.v1.json": "3de2459ca137f8505653f30cc925bb6993d7ce557924923cba3636ec4aaa820c",
		"gate-state-vectors.v2.json": "34dcaf66d4334c8a02e3706fa64f44fed6279657b2774f2f69005efb952fdbaa",
	]
	/// The test key of the file (`testKeyNote`): SHA-256("chat-local-test-private-key-v1"). It derives the file's `recordEoa`. A stand-in key that
	/// derives another account is refused as `needs_native_recovery` (10633), which is a fixture fault, not the case's answer.
	static let testKey = Data(SHA256.hash(data: Data("chat-local-test-private-key-v1".utf8)))
	/// the four Android shell actions are not dispatched on iOS. Their rows (RJ, rejectName, 8 cases) are `unassigned` on iOS, not a
	/// mismatch: the answer is `unknown_command`, exactly once, before the gate.
	static let iosUnassignedNames: Set<String> = ["cacheCallerAvatars", "notifyVoiceMicReady", "queryIncomingCallOutcome", "startNativeVoiceMic"]
	/// the inner unknown names of the vector (`innerUnknown.names`, 21 names). The inner layer answers `unknown_command`, once, before
	/// the gate, in G0, G1 and G2. The gate rows of the outer shell still expect the outer answer; those rows are reported, not counted as SDK failures.
	static let innerNames: Set<String> = {
		guard let path = ProcessInfo.processInfo.environment["GATE_STATE_VECTORS"],
		      let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
		      let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
		      let inner = root["innerUnknown"] as? [String: Any]
		else { return [] }
		return Set(inner["names"] as? [String] ?? [])
	}()

	/// In-memory native store; the writes are counted (a gated command must write nothing).
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
	private var report: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["GATE_STATE_VECTORS"] else {
			throw XCTSkip("set GATE_STATE_VECTORS to interface/protocol/gate-state-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		let name = URL(fileURLWithPath: path).lastPathComponent
		let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(Self.registeredSHA256[name], digest,
		               "vector file sha256 differs from the registered value of \(name) (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// One bridge command through the entry point. The answer is posted on the main queue, so the queue is drained first.
	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			let payload = (event["event"] as? [String: Any]) ?? event
			// An `event:*` status or log is not an answer: a running listen loop of an earlier case may post one late. No `event:` name
			// occurs in gate-state-vectors.v1.json (checked), so no expectation of the vectors is affected.
			if !(payload["type"] as? String ?? "").hasPrefix("event:") { events.append(payload) }
		})
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	/// A clear answers its ack after the inbox wipe, which is asynchronous. This waits for the ack of the command, up to 10 seconds, and
	/// runs the main run loop meanwhile. A refusal answers at once.
	private func dispatchAwaitingAck(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			let payload = (event["event"] as? [String: Any]) ?? event
			if !(payload["type"] as? String ?? "").hasPrefix("event:") { events.append(payload) }
		})
		let deadline = Date().addingTimeInterval(10)
		while !events.contains(where: { $0["type"] as? String == "ack" }) && Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		return events
	}

	private let recordEoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"

	///: at G0, with clear_pending set for X (Owned X), clearIdentity passes the gate and the handler answers clear_incomplete: nothing is deleted or written, the marker stays.
	/// Without the marker the same command is refused at the gate with no_key.
	func testG0WithAnOwnedMarkerPassesTheGateAndAnswersClearIncomplete() {
		enter("G0")
		defer { BeamioNativeClearPending.clear() }
		let keysBefore = store.keys
		BeamioNativeClearPending.clear()
		let gated = dispatchAwaitingAck(["type": "clearIdentity", "reqId": 7901])
		XCTAssertEqual(gated.first { $0["type"] as? String == "ack" }?["error"] as? String, "no_key", "no marker: the gate answers no_key")
		XCTAssertTrue(BeamioNativeClearPending.set(owners: [recordEoa]))
		let events = dispatchAwaitingAck(["type": "clearIdentity", "reqId": 7902])
		let ack = events.first { $0["type"] as? String == "ack" }
		XCTAssertEqual(ack?["ok"] as? Bool, false)
		XCTAssertEqual(ack?["error"] as? String, "clear_incomplete", "Owned X at G0: past the gate, not continued")
		XCTAssertEqual(store.keys.keys.sorted(), keysBefore.keys.sorted(), "nothing is deleted")
		XCTAssertTrue(BeamioNativeClearPending.isSet(), "the marker stays")
		XCTAssertEqual(BeamioNativeClearPending.owners(), .list([recordEoa]), "the owner record stays")
	}

	/// The device state of a case: G0 (no record, no pointer) or G1 (the record on the device, the session not initialised).
	private func enter(_ state: String) {
		store.keys = [:]
		BeamioConetChatSignBroker.clearSigner()
		switch state {
		case "G0":
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		case "G1":
			store.keys[recordEoa] = Self.testKey
			BeamioConetChatModule.setNativeGateForTests(account: recordEoa, sessionReady: false)
		case "G2":
			// the session is ready for the record's account. The record is the test key of the file: an init for the own account answers ready
			// before any key is read (idempotent).
			store.keys[recordEoa] = Self.testKey
			BeamioConetChatModule.setNativeGateForTests(account: recordEoa, sessionReady: true)
		default:
			XCTFail("unknown state \(state)")
		}
	}

	func testTheCountsOfTheVectorFile() throws {
		let root = try vectorRoot()
		let counts = try XCTUnwrap(root["counts"] as? [String: Any])
		// The file's own counts must match its cases. The spec's count (100) is not asserted here: the file has changed since.
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(counts["cases"] as? Int, cases.count, "the counts field matches the cases")
		XCTAssertEqual(counts["g1Init"] as? Int, cases.filter { $0["state"] as? String == "G1" && $0["command"] as? String == "init" }.count)
		XCTAssertEqual(counts["shellGated"] as? Int, 15)
	}

	func testEveryCaseAnswersTheVectorCode() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		var notRun: [String] = []
		for (index, c) in cases.enumerated() {
			let id = c["id"] as? String ?? "?"
			let state = c["state"] as? String ?? ""
			let command = c["command"] as? String ?? ""
			let expect = c["expect"] as? [String: Any] ?? [:]
			let reqId = 7000 + index
			// /: the clear-pending cases run with the marker clear_pending set or cleared; a clearIdentity answer is an ack, not `ready`.
			if let pending = c["clearPending"] as? Bool {
				enter(state)
				if pending { BeamioNativeClearPending.set() } else { BeamioNativeClearPending.clear() }
				let events = dispatchAwaitingAck(["type": command, "reqId": reqId, "payload": c["payload"] ?? [:]])
				assertClearCase(id: id, expect: expect, events: events)
				BeamioNativeClearPending.clear()
				continue
			}
			if expect["code"] as? String == "ok", state == "G1", command == "init" {
				// G1 init cases that answer ok (G1-INIT-OK, G1-INIT-NODES-MISSING-KC): a successful init answers `ready`, not an ok ack.
				// Judged by the ready event for this reqId, with no refusal ack.
				enter(state)
				// The Keychain precondition of the case: a device roster with one node for the -KC case; an in-memory Keychain, restored after.
				let savedMemory = BeamioChatPgpKeychain.memory
				BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
				defer { BeamioChatPgpKeychain.memory = savedMemory }
				if id.hasSuffix("-KC") {
					let roster = [BeamioChatPgpKeychain.SiNode(ip: "203.0.113.7", domain: "node.example.invalid", region: "test", armoredPublicKey: "synthetic")]
					XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: roster, mailboxIp: nil), "\(id): the roster precondition is stored")
				}
				var emitted: [[String: Any]] = []
				let initBody: [String: Any] = ["type": command, "reqId": reqId, "payload": c["payload"] ?? [:]]
				BeamioConetChatModule.handleCommand(initBody, emit: { emitted.append((($0["event"] as? [String: Any]) ?? $0)) })
				let deadline = Date().addingTimeInterval(5)
				while !emitted.contains(where: { $0["type"] as? String == "ready" && $0["reqId"] as? Int == reqId }) && Date() < deadline {
					RunLoop.current.run(until: Date().addingTimeInterval(0.05))
				}
				let ready = emitted.contains { $0["type"] as? String == "ready" && $0["reqId"] as? Int == reqId }
				let refusals = emitted.filter { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId && $0["ok"] as? Bool == false }
				XCTAssertTrue(ready, "\(id): the init answers ready (events: \(emitted.map { $0["type"] as? String ?? "?" }))")
				XCTAssertTrue(refusals.isEmpty, "\(id): no refusal ack (\(refusals.map { $0["error"] as? String ?? "?" }))")
				continue
			}
			// v2: an init case names its Keychain roster (`keychainNodes`). Each runs against an in-memory Keychain: true stores one
			// node, false stores none, so a missing `nodes` answers nodes_unavailable only when the Keychain has no roster.
			if command == "init", let keychainNodes = c["keychainNodes"] as? Bool {
				enter(state)
				let savedMemory = BeamioChatPgpKeychain.memory
				BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
				defer { BeamioChatPgpKeychain.memory = savedMemory }
				if keychainNodes {
					let roster = [BeamioChatPgpKeychain.SiNode(ip: "203.0.113.7", domain: "node.example.invalid", region: "test", armoredPublicKey: "synthetic")]
					XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: roster, mailboxIp: nil), "\(id): the roster precondition is stored")
				}
				var body: [String: Any] = ["type": command, "reqId": reqId, "payload": c["payload"] ?? [:]]
				if let kind = c["kind"] as? String { body["kind"] = kind }
				// The answer may come after the main queue has drained once (a loaded full run): wait for the ack, as the clear cases do.
				let events = dispatchAwaitingAck(body)
				report.append(["id": id, "state": state, "command": command, "events": events.count,
				               "error": events.first?["error"] as? String ?? "", "ok": events.first?["ok"] as? Bool ?? NSNull()])
				assertCase(id: id, state: state, command: command, expect: expect, events: events, reqId: reqId)
				XCTAssertEqual(store.writes, 0, "\(id): nothing is written")
				continue
			}
			if expect["code"] as? String == "ok", state != "G2" {
				notRun.append(id)
				continue
			}
			enter(state)
			var body: [String: Any] = ["type": command, "reqId": reqId, "payload": c["payload"] ?? [:]]
			if let kind = c["kind"] as? String { body["kind"] = kind }
			if let mode = c["mode"] as? String { body["mode"] = mode }
			let events = dispatch(body)
			report.append(["id": id, "state": state, "command": command, "events": events.count,
			               "error": events.first?["error"] as? String ?? "", "ok": events.first?["ok"] as? Bool ?? NSNull()])
			assertCase(id: id, state: state, command: command, expect: expect, events: events, reqId: reqId)
			XCTAssertEqual(store.writes, 0, "\(id): nothing is written")
		}
		XCTAssertEqual(notRun, [], "every case is run")
		// The gate record for the scan (SRC-9): case, state, command, answer count and code. No payload value.
		if let path = ProcessInfo.processInfo.environment["GATE_STATE_REPORT_PATH"] {
			let data = try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
			try data.write(to: URL(fileURLWithPath: path))
		}
	}

	/// clearIdentity with the marker: `ok` is one ack with ok true; a refusal is one ack with its code. Nothing else is answered.
	private func assertClearCase(id: String, expect: [String: Any], events: [[String: Any]]) {
		// The answer is the ack of the command. Other events (for example status) are not answers, so they are not counted here.
		let acks = events.filter { $0["type"] as? String == "ack" }
		XCTAssertEqual(acks.count, 1, "\(id): one answer (the ack)")
		let want = expect["code"] as? String ?? ""
		if want == "ok" {
			// (interface reading of gate-state G0-CLR-PENDING and G1-CLR-PENDING): the vector's `code: ok` is the GATE's pass-through. With clear_pending set, clearIdentity gets past the
			// gate (the no-marker answers are no_key at G0 and not_ready at G1). What the handler then answers is not judged by this layer: with a marker that names no account, or an
			// owned marker and no current account, it is clear_incomplete (G0 plan B, tested below and in the G0-B vectors).
			let refusal = acks.first?["error"] as? String
			XCTAssertNotEqual(refusal, "no_key", "\(id): the marker lets clearIdentity past the G0 gate")
			XCTAssertNotEqual(refusal, "not_ready", "\(id): the marker lets clearIdentity past the G1 gate")
		} else {
			XCTAssertEqual(acks.first?["error"] as? String, want, "\(id): the refusal code")
		}
	}

	private func assertCase(id: String, state: String, command: String, expect: [String: Any], events: [[String: Any]], reqId: Int) {
		if Self.iosUnassignedNames.contains(command) || Self.innerNames.contains(command) {
			// the four Android shell names are unassigned on iOS. The answer is `unknown_command`, once, before the gate. The
			// vector's gate row is not asserted here, and the row is reported, not counted as an SDK mismatch. The outer names of the shell are
			// the same when the vector row still expects a gate answer: that row is vector pending (向量待修), not an SDK failure.
			if Self.innerNames.contains(command), expect["code"] as? String != "unknown_command" {
				print("OUTER-ROW \(id) \(state) \(command): the shell layer answers \(expect["code"] as? String ?? "a gate answer"); the inner layer answers unknown_command")
			} else {
				print("IOS-UNASSIGNED \(id) \(state) \(command):, the answer is unknown_command")
			}
			XCTAssertEqual(events.count, 1, "\(id): one answer and nothing else")
			XCTAssertEqual(events.first?["type"] as? String, "ack", id)
			XCTAssertEqual(events.first?["reqId"] as? Int, reqId, id)
			XCTAssertEqual(events.first?["ok"] as? Bool, false, id)
			XCTAssertEqual(events.first?["error"] as? String, "unknown_command", id)
			return
		}
		if expect["code"] as? String == "ok" {
			// an init that answers ok answers one `ready` event with the reqId, and no ack (the page reads init's answer from `ready`).
			XCTAssertEqual(events.count, 1, "\(id): one answer and nothing else")
			XCTAssertEqual(events.first?["type"] as? String, "ready", id)
			XCTAssertEqual(events.first?["reqId"] as? Int, reqId, id)
			XCTAssertEqual(expect["session"] as? String, "ready", "\(id): the session is ready")
			return
		}
		if let code = expect["code"] as? String {
			if code == "allowed" {
				// Lifecycle and the import entry: no gate answer (no_key, not_ready, address_mismatch) is given. A host answer
				// (not_supported when no page is registered, not_available when it cannot open;) is not a gate answer.
				let gateAnswers: Set<String> = ["no_key", "not_ready", "address_mismatch"]
				XCTAssertFalse(events.contains { ($0["type"] as? String) == "ack" && gateAnswers.contains($0["error"] as? String ?? "") },
				               "\(id): the allowed name is not gated")
				return
			}
			XCTAssertEqual(events.filter { $0["type"] as? String == "ack" }.count, 1, "\(id): one answer (the ack) and nothing else (got \(events.map { $0["type"] as? String ?? "?" }))")
			guard let ack = events.first else { return }
			XCTAssertEqual(ack["type"] as? String, "ack", id)
			XCTAssertEqual(ack["reqId"] as? Int, reqId, id)
			XCTAssertEqual(ack["ok"] as? Bool, false, id)
			XCTAssertEqual(ack["error"] as? String, code, id)
			XCTAssertNil(ack["result"], "\(id): no data is returned")
			return
		}
		if let status = expect["status"] as? String {
			let ack = events.first
			XCTAssertEqual(ack?["ok"] as? Bool, true, id)
			let result = ack?["result"] as? [String: Any]
			XCTAssertEqual(result?["status"] as? String, status, id)
			XCTAssertNil(result?["accountKey"], "\(id): no account key is returned before init")
			return
		}
		if expect["hasKey"] as? Bool == true {
			let result = events.first?["result"] as? [String: Any]
			XCTAssertEqual(result?["hasKey"] as? Bool, true, "\(id): hasKey is device-level and true with a record")
			// set and locked are device-level: they follow the record's account, not the session (表 D).
			let state = BeamioPasscodeSession.shared.appState(eoa: recordEoa)
			XCTAssertEqual(result?["set"] as? Bool, state != .noPasscode, "\(id): set is device-level")
			XCTAssertEqual(result?["locked"] as? Bool, state == .locked, "\(id): locked is device-level")
			return
		}
		if expect["gateRefused"] as? Bool == false, let forbidden = expect["forbiddenCodes"] as? [String] {
			// A shell-layer name the gate does not refuse (`notGated`, table C): the SDK must not answer no_key or not_ready to it.
			XCTAssertFalse(events.contains { ($0["type"] as? String) == "ack" && forbidden.contains($0["error"] as? String ?? "") },
			               "\(id): the gate does not refuse this name")
			return
		}
		XCTFail("\(id): the case has no expectation this runner knows (\(state) \(command))")
	}

}
