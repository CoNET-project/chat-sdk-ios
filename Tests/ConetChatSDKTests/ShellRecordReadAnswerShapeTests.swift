#if BEAMIO_TEST_HOOKS
import XCTest
import CryptoKit
@testable import ConetChatSDK

/// The three vector files of interface spec v160 to v162 (byte-exact copies, pinned by SHA-256): the answer shape of shellRecordRead.
/// Where a vector file (v160, v161) still writes the old envelope-level `ok:false error:not_ready`, v162 section 182.3 voids it: the same
/// answer is `ok:true` with the answer in `result` (the shape vector says so itself). Synthetic values only.
final class ShellRecordReadAnswerShapeTests: XCTestCase {
	private let pins: [String: String] = [
		"shell-record-read-answer-shape.v3": "764170a6c227c6f441b5994b99a90d3802ae16fb76650e747e99bf749a24e98e",
		"shell-record-read-not-ready-reasons.v2": "0a59252b34be0e08b3b0c289f153f6b72850796e7ed3b2ed435a387a9a06e985",
		"unreadable-cause.v3": "1558d3696753d89979c5c2265fcf6a5d4ba2bf0287986e2cc542e9897e830add",
	]

	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { records[account].map { .record($0) } ?? .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { records[account] = record; return true }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	override func setUp() {
		super.setUp()
		BeamioShellRecord.resetNotReadyStreakForTests()
		BeamioKeychainFailureNote.setForTests(nil)
	}

	override func tearDown() {
		BeamioShellRecord.resetNotReadyStreakForTests()
		BeamioKeychainFailureNote.setForTests(nil)
		BeamioNativeKeySnapshot.pinUnknownForTests(false)
		super.tearDown()
	}

	private func vector(_ name: String) throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: name)
		XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), pins[name], "\(name) is the pinned file")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func environment(gate: BeamioConetChatModule.NativeGate = .g0, keyState: BeamioShellRecord.KeyState = .normal,
	                         storageLocked: Bool = false, legacyAbsent: Bool = false, origin: Bool = true) -> BeamioShellRecord.Environment {
		let device = Device()
		device.state.legacyConfirmedAbsent = legacyAbsent
		var env = BeamioShellRecord.Environment(
			account: { nil }, store: Store(), device: device, originAllowed: origin,
			migrating: { _ in false }, firstRun: { _ in legacyAbsent ? .confirmedAbsent : .notRun },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { gate }
		)
		env.keyState = { keyState }
		env.storageLocked = { storageLocked }
		return env
	}

	private func read(_ env: BeamioShellRecord.Environment, reqId: Int = 1, extra: [String: Any] = [:]) -> [String: Any] {
		var body: [String: Any] = ["type": "shellRecordRead", "reqId": reqId]
		for (k, v) in extra { body[k] = v }
		return BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(body, env: env))
	}

	private func result(_ ack: [String: Any]) -> [String: Any] { ack["result"] as? [String: Any] ?? [:] }

	// MARK: the shape vector (SHAPE-01 to SHAPE-11)

	func testShapeVectorStatesAreOkTrueWithResult() throws {
		let v = try vector("shell-record-read-answer-shape.v3")
		let cases = try XCTUnwrap(v["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 11)

		// SHAPE-01 absent
		let absent = read(environment(gate: .g0, legacyAbsent: true))
		XCTAssertEqual(absent["type"] as? String, "ack")
		XCTAssertEqual(absent["ok"] as? Bool, true)
		XCTAssertEqual(result(absent)["code"] as? String, "absent")
		XCTAssertNil(absent["status"], "no top-level status field")
		// SHAPE-03 migrating (a read with no legacy answer yet)
		let migrating = read(environment(gate: .g0, legacyAbsent: false))
		XCTAssertEqual(migrating["ok"] as? Bool, true)
		XCTAssertEqual(result(migrating)["code"] as? String, "migrating")
		// SHAPE-04 storage_locked
		let locked = read(environment(storageLocked: true))
		XCTAssertEqual(locked["ok"] as? Bool, true)
		XCTAssertEqual(result(locked)["code"] as? String, "not_ready")
		XCTAssertEqual(result(locked)["notReadyReason"] as? String, "storage_locked")
		XCTAssertEqual(result(locked)["retryable"] as? Bool, false)
		XCTAssertNil(locked["error"])
		// SHAPE-05 g1_uninitialized
		let g1 = read(environment(gate: .g1))
		XCTAssertEqual(g1["ok"] as? Bool, true)
		XCTAssertEqual(result(g1)["notReadyReason"] as? String, "g1_uninitialized")
		XCTAssertEqual(result(g1)["retryable"] as? Bool, true)
		// SHAPE-06 ambiguous_accounts
		let ambiguous = read(environment(gate: .g2, keyState: .ambiguous))
		XCTAssertEqual(ambiguous["ok"] as? Bool, true)
		XCTAssertEqual(result(ambiguous)["notReadyReason"] as? String, "ambiguous_accounts")
		XCTAssertEqual(result(ambiguous)["retryable"] as? Bool, false)
		// SHAPE-10 origin_refused (envelope level)
		let refused = read(environment(origin: false))
		XCTAssertEqual(refused["ok"] as? Bool, false)
		XCTAssertEqual(refused["error"] as? String, "origin_refused")
		// SHAPE-11 bad_request (a missing reqId is an envelope failure)
		let bad = BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(["type": "shellRecordRead"], env: environment()))
		XCTAssertEqual(bad["ok"] as? Bool, false)
		XCTAssertEqual(bad["error"] as? String, "bad_request")
	}

	func testShapeVectorPersistentIsAResultWithTheReason() {
		let env = environment(storageLocked: true)
		for n in 1 ... 10 { XCTAssertEqual(result(read(env, reqId: n))["code"] as? String, "not_ready", "answer \(n)") }
		let eleventh = read(env, reqId: 11)
		XCTAssertEqual(eleventh["ok"] as? Bool, true)
		XCTAssertEqual(result(eleventh)["code"] as? String, "error")
		XCTAssertEqual(result(eleventh)["sub"] as? String, "not_ready_persistent")
		XCTAssertEqual(result(eleventh)["notReadyReason"] as? String, "storage_locked")
		XCTAssertEqual(result(eleventh)["retryable"] as? Bool, false)
	}

	// MARK: the reasons vector (SRR-01 to SRR-08), in the v162 shape

	func testReasonsVectorReasonsAndReset() throws {
		let v = try vector("shell-record-read-not-ready-reasons.v2")
		let reasons = try XCTUnwrap(v["reasons"] as? [String: [String: Any]])
		XCTAssertEqual(reasons["storage_locked"]?["retryable"] as? Bool, false)
		XCTAssertEqual(reasons["g1_uninitialized"]?["retryable"] as? Bool, true)
		XCTAssertEqual(reasons["ambiguous_accounts"]?["retryable"] as? Bool, false)
		XCTAssertEqual((v["cases"] as? [[String: Any]])?.count, 7)
		// SRR-05 persistent with a retryable reason keeps retryable true in the vector; the SDK answers false once persistent (the shape vector SHAPE-08).
		// SRR-06: nine of one reason, then another reason: the count resets
		let g1 = environment(gate: .g1)
		for n in 1 ... 9 { _ = read(g1, reqId: n) }
		let other = read(environment(storageLocked: true), reqId: 20)
		XCTAssertEqual(result(other)["code"] as? String, "not_ready")
		XCTAssertEqual(result(other)["notReadyReason"] as? String, "storage_locked")
		XCTAssertEqual(result(other)["retryable"] as? Bool, false)
		// SRR-07 absent control: no notReadyReason
		let absent = read(environment(gate: .g0, legacyAbsent: true), reqId: 30)
		XCTAssertNil(result(absent)["notReadyReason"])
	}

	// MARK: the unreadable-cause vector (UNR-01 to UNR-05), in the v162 shape

	private func unreadableAnswer(status: OSStatus?) -> [String: Any] {
		BeamioKeychainFailureNote.setForTests(status.map { BeamioKeychainFailureNote.category(of: $0) })
		return read(environment(gate: .g1), reqId: 40)
	}

	func testUnreadableCauseCarriesCategoryAndRetryable() throws {
		let v = try vector("unreadable-cause.v3")
		XCTAssertEqual((v["cases"] as? [[String: Any]])?.count, 5)
		XCTAssertEqual(BeamioKeychainFailureNote.category(of: -34018), "entitlement")
		XCTAssertEqual(BeamioKeychainFailureNote.category(of: -25308), "device_locked")
		XCTAssertEqual(BeamioKeychainFailureNote.category(of: -50), "other")
		XCTAssertFalse(BeamioKeychainFailureNote.retryable("entitlement"))
		XCTAssertTrue(BeamioKeychainFailureNote.retryable("device_locked"))
		XCTAssertFalse(BeamioKeychainFailureNote.retryable("other"))
	}

	func testUnreadableSnapshotAnswersItsCause() {
		// entitlement and other (not retryable) are final at the first answer; device_locked waits for the limit.
		for (status, cause, retryable) in [(-34018, "entitlement", false), (-25308, "device_locked", true), (-50, "other", false)] {
			BeamioShellRecord.resetNotReadyStreakForTests()
			BeamioKeychainFailureNote.setForTests(BeamioKeychainFailureNote.category(of: OSStatus(status)))
			BeamioNativeKeySnapshot.pinUnreadableForTests(true)
			defer { BeamioNativeKeySnapshot.pinUnreadableForTests(false) }
			let ack = read(environment(gate: .g1), reqId: 40)
			XCTAssertEqual(ack["ok"] as? Bool, true, cause)
			XCTAssertEqual(result(ack)["code"] as? String, retryable ? "not_ready" : "error", cause)
			XCTAssertEqual(result(ack)["sub"] as? String, retryable ? nil : "not_ready_persistent", cause)
			XCTAssertEqual(result(ack)["notReadyReason"] as? String, "unreadable", cause)
			XCTAssertEqual(result(ack)["unreadableCause"] as? String, cause)
			XCTAssertEqual(result(ack)["retryable"] as? Bool, retryable, cause)
		}
		// no recorded status: the cause is other, not retryable
		BeamioShellRecord.resetNotReadyStreakForTests()
		BeamioKeychainFailureNote.setForTests(nil)
		BeamioNativeKeySnapshot.pinUnreadableForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnreadableForTests(false) }
		let ack = read(environment(gate: .g1), reqId: 41)
		XCTAssertEqual(result(ack)["sub"] as? String, "not_ready_persistent")
		XCTAssertEqual(result(ack)["unreadableCause"] as? String, "other")
		XCTAssertEqual(result(ack)["retryable"] as? Bool, false)
	}

	func testPersistentUnreadableKeepsItsCause() {
		BeamioKeychainFailureNote.setForTests("entitlement")
		BeamioNativeKeySnapshot.pinUnreadableForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnreadableForTests(false) }
		let env = environment(gate: .g1)
		for n in 1 ... 10 { _ = read(env, reqId: n) }
		let eleventh = read(env, reqId: 11)
		XCTAssertEqual(result(eleventh)["code"] as? String, "error")
		XCTAssertEqual(result(eleventh)["sub"] as? String, "not_ready_persistent")
		XCTAssertEqual(result(eleventh)["notReadyReason"] as? String, "unreadable")
		XCTAssertEqual(result(eleventh)["unreadableCause"] as? String, "entitlement")
		XCTAssertEqual(result(eleventh)["retryable"] as? Bool, false)
	}
}
#endif

#if BEAMIO_TEST_HOOKS
/// interface spec v165 section 185 and v166 section 186: the shellRecordWrite answer shape and the refusal of a PGP private key (the four SWP cases).
final class ShellRecordWritePgpRefusalTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { records[account].map { .record($0) } ?? .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { records[account] = record; return true }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let eoa = "0x5e5e000000000000000000000000000000000002"

	private func environment(origin: Bool = true, store: Store = Store()) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { self.eoa }, store: store, device: Device(), originAllowed: origin,
			migrating: { _ in false }, firstRun: { _ in .confirmedAbsent }, locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { .g2 }
		)
	}

	private func write(_ record: [String: Any], reqId: String, env: BeamioShellRecord.Environment) -> [String: Any] {
		BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": reqId, "record": record], env: env))
	}

	private func assertRefusedWithoutEcho(_ ack: [String: Any], reqId: String, error: String, file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertEqual(ack["ok"] as? Bool, false, file: file, line: line)
		XCTAssertEqual(ack["error"] as? String, error, file: file, line: line)
		XCTAssertEqual(ack["reqId"] as? String, reqId, file: file, line: line)
		XCTAssertEqual(Set(ack.keys), ["type", "reqId", "ok", "error"], "no record, field name, value or path is echoed", file: file, line: line)
	}

	func testTheFourCasesOfThePgpPrivateRefusalVector() throws {
		let data = try BundledVectorFile.data(resource: "shellrecordwrite-pgp-private-refusal.v1")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		XCTAssertEqual((root["cases"] as? [[String: Any]])?.count, 4)
		// the vector's placeholders are replaced by synthetic values here; the file itself holds none
		let armor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----"
		// SWP-01: the forbidden field name
		assertRefusedWithoutEcho(write(["profiles": [["keyID": eoa, "pgpPrivateKeyArmored": armor]]], reqId: "r-0001", env: environment()), reqId: "r-0001", error: "pgp_private_in_payload")
		// SWP-02: the header alone, in an ordinary string; the path is not returned
		assertRefusedWithoutEcho(write(["note": "x " + armor], reqId: "r-0002", env: environment()), reqId: "r-0002", error: "pgp_private_in_payload")
		// SWP-03: the origin comes first and is answered once
		assertRefusedWithoutEcho(write(["pgpPrivateKeyArmored": armor], reqId: "r-0003", env: environment(origin: false)), reqId: "r-0003", error: "origin_refused")
		// SWP-04: a clean write is ok:true, code ok, rev next (the SDK keeps rev inside the record)
		let store = Store()
		store.records[eoa] = ["rev": 3, "schemaVersion": 1, "profiles": [["keyID": eoa]]]
		let ok = write(["rev": 3, "schemaVersion": 1, "profiles": [["keyID": eoa]]], reqId: "r-0004", env: environment(store: store))
		XCTAssertEqual(ok["ok"] as? Bool, true)
		XCTAssertEqual((ok["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertEqual((ok["result"] as? [String: Any])?["rev"] as? Int, 4)
	}

	func testAPrivateKeyWithoutRevIsStillRefusedAsAPrivateKey() {
		let armor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----"
		assertRefusedWithoutEcho(write(["note": armor], reqId: "r-0005", env: environment()), reqId: "r-0005", error: "pgp_private_in_payload")
	}

	func testWriteStatusAnswersAreResults() {
		// a stale rev: conflict inside result with currentRev
		let store = Store()
		store.records[eoa] = ["rev": 5, "schemaVersion": 1, "profiles": [["keyID": eoa]]]
		let conflict = write(["rev": 3, "schemaVersion": 1, "profiles": [["keyID": eoa]]], reqId: "r-0006", env: environment(store: store))
		XCTAssertEqual(conflict["ok"] as? Bool, true)
		XCTAssertEqual((conflict["result"] as? [String: Any])?["code"] as? String, "conflict")
		XCTAssertEqual((conflict["result"] as? [String: Any])?["currentRev"] as? Int, 5)
	}

	func testTheRecordCommandsRefuseEveryUntrustedSourceAsOriginRefused() {
		for trust in [WindowTrust.originRefused, .notTrusted] {
			for command in ["shellRecordRead", "shellRecordWrite"] {
				var events: [[String: Any]] = []
				let body: [String: Any] = ["reqId": "r-9"]
				if command == "shellRecordRead" { BeamioWindowWallet.shellRecordRead(body, trust: trust) { events.append($0) } }
				else { BeamioWindowWallet.shellRecordWrite(body, trust: trust) { events.append($0) } }
				XCTAssertEqual(events.count, 1, "\(command) \(trust)")
				XCTAssertEqual(events.first?["error"] as? String, "origin_refused", "\(command) \(trust)")
				XCTAssertEqual(events.first?["ok"] as? Bool, false)
			}
		}
	}
}
#endif

#if BEAMIO_TEST_HOOKS
/// The v2 vector files are authoritative (v168 section 188): every case is read from the file, its `state` is set up, shellRecordRead is asked, and the ack the
/// SDK sends is compared with the case's `expect` (reqId removed). Nothing of the expected shape is written by the test.
final class ShellRecordReadV2VectorDrivenTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { true }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	override func setUp() { super.setUp(); BeamioShellRecord.resetNotReadyStreakForTests(); BeamioKeychainFailureNote.setForTests(nil) }
	override func tearDown() {
		BeamioShellRecord.resetNotReadyStreakForTests()
		BeamioKeychainFailureNote.setForTests(nil)
		BeamioNativeKeySnapshot.pinUnreadableForTests(false)
		super.tearDown()
	}

	private func canonical(_ value: Any) -> String {
		guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return "invalid" }
		return String(decoding: data, as: UTF8.self)
	}

	private func environment(gate: BeamioConetChatModule.NativeGate = .g0, keyState: BeamioShellRecord.KeyState = .normal,
	                         storageLocked: Bool = false, legacyAbsent: Bool = false) -> BeamioShellRecord.Environment {
		let device = Device()
		device.state.legacyConfirmedAbsent = legacyAbsent
		var env = BeamioShellRecord.Environment(
			account: { nil }, store: Store(), device: device, originAllowed: true,
			migrating: { _ in false }, firstRun: { _ in legacyAbsent ? .confirmedAbsent : .notRun },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { gate }
		)
		env.keyState = { keyState }
		env.storageLocked = { storageLocked }
		return env
	}

	/// The ack the SDK sends for one read, with its reqId removed.
	private func ask(_ env: BeamioShellRecord.Environment, _ n: Int = 1) -> [String: Any] {
		var ack = BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": n], env: env))
		ack.removeValue(forKey: "reqId")
		return ack
	}

	private func reasonEnvironment(_ reason: String) throws -> BeamioShellRecord.Environment {
		switch reason {
		case "storage_locked": return environment(storageLocked: true)
		case "g1_uninitialized": return environment(gate: .g1)
		case "ambiguous_accounts": return environment(gate: .g2, keyState: .ambiguous)
		case "unreadable": return environment(gate: .g1)
		default: throw XCTSkip("no setup for reason \(reason)")
		}
	}

	private func run(_ resource: String, cases expected: Int, file: StaticString = #filePath, line: UInt = #line) throws {
		let data = try BundledVectorFile.data(resource: resource)
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, expected, file: file, line: line)
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let state = c["state"] as? [String: Any] ?? [:]
			BeamioShellRecord.resetNotReadyStreakForTests()
			BeamioKeychainFailureNote.setForTests(nil)
			BeamioNativeKeySnapshot.pinUnreadableForTests(false)
			var actual: [String: Any]
			if let osStatus = state["osStatus"] as? Int {
				// a keychain read that failed with this status: the snapshot is unreadable and the cause is the category of the status
				BeamioKeychainFailureNote.setForTests(BeamioKeychainFailureNote.category(of: OSStatus(osStatus)))
				BeamioNativeKeySnapshot.pinUnreadableForTests(true)
				actual = ask(environment(gate: .g1))
			} else if let count = state["sameProcessConsecutiveSameReason"] as? Int, let reason = state["reason"] as? String {
				if let cause = state["unreadableCause"] as? String {
					BeamioKeychainFailureNote.setForTests(cause)
					BeamioNativeKeySnapshot.pinUnreadableForTests(true)
				}
				let env = try reasonEnvironment(reason)
				if let next = state["nextReason"] as? String {
					// `count` answers of the first reason, then the next answer is of another reason: the count starts again
					for n in 1 ... count { _ = ask(env, n) }
					actual = ask(try reasonEnvironment(next), count + 1)
				} else {
					// `count` answers have been given in this process: the next one is the persistent answer
					for n in 1 ... count { _ = ask(env, n) }
					actual = ask(env, count + 1)
				}
			} else if state["storageDerivedLock"] as? Bool == true {
				actual = ask(try reasonEnvironment("storage_locked"))
			} else if state["g1Session"] as? String == "not_established" {
				actual = ask(try reasonEnvironment("g1_uninitialized"))
			} else if state["keyCount"] != nil {
				actual = ask(try reasonEnvironment("ambiguous_accounts"))
			} else if state["pageRecord"] as? String == "absent" || state["keychainItem"] as? String == "absent" {
				actual = ask(environment(gate: .g0, legacyAbsent: true))
			} else {
				XCTFail("\(id): no setup for this state", file: file, line: line)
				continue
			}
			XCTAssertEqual(canonical(actual), canonical(c["expect"] as Any), id, file: file, line: line)
		}
	}

	func testEveryCaseOfTheNotReadyReasonsV2VectorMatchesTheAckTheSdkSends() throws {
		try run("shell-record-read-not-ready-reasons.v2", cases: 7)
	}

	func testEveryCaseOfTheUnreadableCauseV3VectorMatchesTheAckTheSdkSends() throws {
		try run("unreadable-cause.v3", cases: 5)
	}
}
#endif
