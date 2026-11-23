import CryptoKit
import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// The P-IMP-PGP commands with the chain read (spec,; group C cases C-01, C-02, C-03, C-06 to C-09) through the
/// bridge entry point. The chain is a mock (AddressPGPChain.transport) built from the restore acceptance vectors: the
/// `setChain` and `setReadable` steps of each case. The backup password is the account key of the backup-compatibility
/// vector P-1 (synthetic). Runs only where the X-19 framework is linked (iOS builds with Vendor/X19.xcframework).
/// PGP_RESTORE_VECTORS=<pgp-restore-acceptance-vectors.v1.json> PGP_BACKUP_VECTORS=<pgp-backup-compat-vectors.v1.json>
final class PGPRestoreChainTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let contract = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2"

	private var savedTransport: ((URL, Data) -> Result<Data, Error>)!
	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: MemoryKeyStore!
	private var restore: [String: Any] = [:]
	private var backupRoot: [String: Any] = [:]

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

	/// The chain as the mock holds it.
	private var chainExists = false
	private var chainPublicArmor = ""
	private var chainBackup = ""
	private var chainReadable = true

	override func setUp() {
		super.setUp()
		savedTransport = AddressPGPChain.transport
		AddressPGPChain.configuration = AddressPGPChain.Configuration(
			contract: contract, chainId: 224422, rpcURL: URL(string: "https://rpc.example.invalid/")!
		)
		AddressPGPChain.transport = { [unowned self] _, body in self.answer(body) }
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		store = MemoryKeyStore()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
		BeamioConetChatSignBroker.clearSigner()
	}

	override func tearDown() {
		AddressPGPChain.transport = savedTransport
		AddressPGPChain.configuration = nil
		BeamioNativeWallet.keyStore = savedStore
		BeamioChatPgpKeychain.memory = nil
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		super.tearDown()
	}

	// MARK: - Vectors

	private func json(_ env: String) throws -> [String: Any] {
		// The bundled copy with its registered digest: pgp-restore-acceptance and pgp-backup-compat.
		let resource = env == "PGP_RESTORE_VECTORS" ? "pgp-restore-acceptance-vectors.v1" : "pgp-backup-compat-vectors.v1"
		let data = try BundledVectorFile.data(resource: resource, env: env)
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func loadVectors() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 framework not linked in this build")
		restore = try json("PGP_RESTORE_VECTORS")
		backupRoot = try json("PGP_BACKUP_VECTORS")
	}

	private func blob(_ name: String) throws -> String {
		let entry = try XCTUnwrap((restore["backups"] as? [String: Any])?[name] as? [String: Any])
		return try XCTUnwrap(entry["base64"] as? String)
	}

	private func privateArmor(_ identity: String) throws -> String {
		let keys = try XCTUnwrap(restore["syntheticKeys"] as? [String: Any])
		return try XCTUnwrap((keys[identity] as? [String: Any])?["privateArmor"] as? String)
	}

	/// The account key of the backup vector's first positive: the password string is "0x" + the key hex.
	private func installAccountKey() throws {
		let positive = try XCTUnwrap((backupRoot["positives"] as? [[String: Any]])?.first)
		let password = try XCTUnwrap(positive["passwordString"] as? String)
		var bytes: [UInt8] = []
		var index = password.index(password.startIndex, offsetBy: 2)
		while index < password.endIndex {
			let next = password.index(index, offsetBy: 2)
			bytes.append(UInt8(password[index ..< next], radix: 16) ?? 0)
			index = next
		}
		XCTAssertTrue(store.write(eoa: account, key: Data(bytes)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
	}

	/// Applies one case's chain steps: `identity` (a synthetic key name, or nil for no record) and `blob` (a backup name).
	private func setChain(identity: String?, blob: String) throws {
		chainReadable = true
		if let identity {
			chainExists = true
			chainPublicArmor = try privateArmor(identity)
		} else {
			chainExists = false
			chainPublicArmor = ""
		}
		chainBackup = try self.blob(blob)
	}

	// MARK: - Mock node

	private func word(_ n: Int) -> [UInt8] {
		[UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) }
	}

	private func encodedString(_ s: String) -> [UInt8] {
		let data = Array(s.utf8)
		return word(data.count) + data + [UInt8](repeating: 0, count: (32 - data.count % 32) % 32)
	}

	private func hex(_ bytes: [UInt8]) -> String {
		"0x" + bytes.map { String(format: "%02x", $0) }.joined()
	}

	private func answer(_ body: Data) -> Result<Data, Error> {
		guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
		      let method = object["method"] as? String
		else { return .failure(AddressPGPChain.ReadError.malformed) }
		if !chainReadable { return .failure(AddressPGPChain.ReadError.transport("timeout")) }
		let result: Any
		switch method {
		case "eth_blockNumber":
			result = "0x1f4"
		case "eth_call":
			let call = ((object["params"] as? [Any])?.first as? [String: Any]) ?? [:]
			let data = (call["data"] as? String) ?? ""
			if data.hasPrefix(hex(AddressPGPChain.selector("_pgpKeys(address)"))) {
				let s1 = encodedString(""), s2 = encodedString(chainPublicArmor), s3 = encodedString("")
				let head = 128
				let raw = word(head) + word(head + s1.count) + word(head + s1.count + s2.count) + word(chainExists ? 1 : 0)
				result = hex(raw + s1 + s2 + s3)
			} else {
				result = hex(word(32) + encodedString(chainBackup))
			}
		default:
			return .failure(AddressPGPChain.ReadError.rpc("unsupported"))
		}
		return .success(try! JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": result]))
	}

	// MARK: - Commands

	/// Sends one command and waits for the events it produces (acks and results arrive on the main queue).
	private func dispatch(_ type: String, reqId: String, extra: [String: Any] = [:], expectingEvents count: Int) -> [[String: Any]] {
		var events: [[String: Any]] = []
		let done = expectation(description: "events for \(type)")
		BeamioConetChatModule.handleCommand(
			["type": type, "reqId": reqId, "accountKey": account + ":default"].merging(extra) { $1 },
			emit: { event in
				events.append((event["event"] as? [String: Any]) ?? event)
				if events.count == count { done.fulfill() }
			}
		)
		wait(for: [done], timeout: 15)
		return events
	}

	private func result(of events: [[String: Any]], reqId: String) -> [String: Any]? {
		events.first { ($0["reqId"] as? String) == reqId && $0["type"] as? String == "ack" }?["result"] as? [String: Any]
	}

	// MARK: - C-01, C-02, C-03: evaluation

	func testC01BackupMissingIsAFailureWithTheEntry() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_EMPTY")
		let events = dispatch("pgpRestoreEvaluate", reqId: "c3-c-01", expectingEvents: 1)
		let r = try XCTUnwrap(events.first?["result"] as? [String: Any])
		XCTAssertEqual(r["state"] as? String, "failed")
		XCTAssertEqual(r["failureClass"] as? String, "backup_missing")
		XCTAssertEqual(r["code"] as? String, "pgp_backup_missing")
		XCTAssertEqual(r["offerEntry"] as? Bool, true)
		XCTAssertEqual(r["uiKey"] as? String, "chat.restore_failed.body")
	}

	func testC02NoRecordIsTheFirstIdentityNotAFailure() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: nil, blob: "B_EMPTY")
		let r = try XCTUnwrap(dispatch("pgpRestoreEvaluate", reqId: "c3-c-02", expectingEvents: 1).first?["result"] as? [String: Any])
		XCTAssertEqual(r["state"] as? String, "first_identity")
		XCTAssertNil(r["failureClass"] as? String)
		XCTAssertEqual(r["uiKey"] as? String, "chat.first_identity.body")
	}

	func testC03AReadFailureIsUndeterminedAndNeverANoRecord() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		chainReadable = false
		let r = try XCTUnwrap(dispatch("pgpRestoreEvaluate", reqId: "c3-c-03", expectingEvents: 1).first?["result"] as? [String: Any])
		XCTAssertEqual(r["state"] as? String, "undetermined")
		XCTAssertEqual(r["code"] as? String, "pgp_source_unavailable")
		XCTAssertEqual(r["uiKey"] as? String, "chat.restore_retry.body")
	}

	func testEvaluationWritesNothingLocally() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		_ = dispatch("pgpRestoreEvaluate", reqId: "c3-c-eval", expectingEvents: 1)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "the evaluation must not write the record")
	}

	// MARK: - C-06 to C-09: restore

	func testC06RestoreWritesTheRecordAndReadsItBack() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		let events = dispatch("pgpRestore", reqId: "c3-c-06", expectingEvents: 2)
		let ack = try XCTUnwrap(events.first { $0["type"] as? String == "ack" })
		XCTAssertEqual((ack["result"] as? [String: Any])?["accepted"] as? Bool, true)
		let result = try XCTUnwrap(events.first { $0["type"] as? String == "pgpRestoreResult" })
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertEqual(result["state"] as? String, "ok")
		let stored = try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: account))
		XCTAssertEqual(stored.privateKeyArmor, try privateArmor("P1"))
	}

	func testC07AFingerprintMismatchStoresNothing() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P2_UNDER_A")
		let result = try XCTUnwrap(dispatch("pgpRestore", reqId: "c3-c-07", expectingEvents: 2).first { $0["type"] as? String == "pgpRestoreResult" })
		XCTAssertEqual(result["code"] as? String, "pgp_fingerprint_mismatch")
		XCTAssertEqual(result["failureClass"] as? String, "fingerprint_mismatch")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account))
	}

	func testC08BackupWithoutARegistrationIsRegistrationMissing() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: nil, blob: "B_P1_OK")
		let result = try XCTUnwrap(dispatch("pgpRestore", reqId: "c3-c-08", expectingEvents: 2).first { $0["type"] as? String == "pgpRestoreResult" })
		XCTAssertEqual(result["code"] as? String, "pgp_registration_missing")
		XCTAssertEqual(result["failureClass"] as? String, "registration_missing")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account))
	}

	func testC09AnUndecryptableBackupIsDecryptFailed() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_GCM_FAIL")
		let result = try XCTUnwrap(dispatch("pgpRestore", reqId: "c3-c-09", expectingEvents: 2).first { $0["type"] as? String == "pgpRestoreResult" })
		XCTAssertEqual(result["code"] as? String, "pgp_backup_undecryptable")
		XCTAssertEqual(result["failureClass"] as? String, "decrypt_failed")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account))
	}

	/// The answer carries no key material, armor or backup text.
	func testNoResultCarriesArmorOrBackup() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		let events = dispatch("pgpRestoreEvaluate", reqId: "c3-c-leak", expectingEvents: 1)
		let text = String(describing: events)
		XCTAssertFalse(text.contains("PRIVATE KEY"))
		XCTAssertFalse(text.contains(try blob("B_P1_OK")))
	}

	// MARK: - Group C rows against the vector

	/// The answers for one group C row must match the vector row, through the shared comparator (keys included).
	private func assertRow(_ id: String, events: [[String: Any]]) throws {
		let differing = try GroupCVector.differences(row: try GroupCVector.row(id), answers: events)
		print("GROUP-C-RUN \(id): \(differing.isEmpty ? "matches the vector" : "differs in \(differing.joined(separator: ", "))")")
		XCTAssertTrue(differing.isEmpty, "\(id): the answer differs from the vector in \(differing.joined(separator: ", "))")
	}

	/// C-01: a backup that is missing is a failure with the entry. Evaluation only; nothing is written.
	func testGroupCRowC01BackupMissing() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_EMPTY")
		try assertRow("C-01", events: dispatch("pgpRestoreEvaluate", reqId: "c3-c-01", expectingEvents: 1))
	}

	/// C-02: no record and no backup is the first identity, not a failure.
	func testGroupCRowC02FirstIdentity() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: nil, blob: "B_EMPTY")
		try assertRow("C-02", events: dispatch("pgpRestoreEvaluate", reqId: "c3-c-02", expectingEvents: 1))
	}

	/// C-03: a read that fails is `undetermined` with the retry, never a no-record answer.
	func testGroupCRowC03ReadFailureIsUndetermined() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		chainReadable = false
		try assertRow("C-03", events: dispatch("pgpRestoreEvaluate", reqId: "c3-c-03", expectingEvents: 1))
	}

	/// C-06: a consistent backup is written locally and read back. The ack is `accepted` before the result.
	func testGroupCRowC06RestoreWrites() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		try assertRow("C-06", events: dispatch("pgpRestore", reqId: "c3-c-06", expectingEvents: 2))
	}

	/// C-07: a fingerprint that does not match stores nothing and overwrites nothing (class 3).
	func testGroupCRowC07FingerprintMismatch() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P2_UNDER_A")
		let events = dispatch("pgpRestore", reqId: "c3-c-07", expectingEvents: 2)
		try assertRow("C-07", events: events)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "C-07: nothing is stored")
	}

	/// C-08: a backup without a registration is `registration_missing` (class 4).
	func testGroupCRowC08RegistrationMissing() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: nil, blob: "B_P1_OK")
		let events = dispatch("pgpRestore", reqId: "c3-c-08", expectingEvents: 2)
		try assertRow("C-08", events: events)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "C-08: nothing is stored")
	}

	/// C-09: a backup that does not decrypt is `pgp_backup_undecryptable` (class 2).
	func testGroupCRowC09Undecryptable() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_GCM_FAIL")
		let events = dispatch("pgpRestore", reqId: "c3-c-09", expectingEvents: 2)
		try assertRow("C-09", events: events)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "C-09: nothing is stored")
	}

	/// C-17: not run against the vector (,). The write path is not approved, so the whole command answers `waiting_registration`, with
	/// no chain read and no `already_exists`. Not counted as passed.
	func testGroupCRowC17RestoredWaitsForRegistration() throws {
		try loadVectors()
		try installAccountKey()
		try setChain(identity: "P1", blob: "B_P1_OK")
		let saved = BeamioPGPIdentityCreate.registration
		BeamioPGPIdentityCreate.registration = nil
		defer { BeamioPGPIdentityCreate.registration = saved }
		let events = dispatch("pgpIdentityCreate", reqId: "c3-c-17", extra: ["idempotencyKey": "idem-c-17"], expectingEvents: 1)
		let ack = events.first { $0["type"] as? String == "ack" }
		XCTAssertEqual(ack?["ok"] as? Bool, false, "C-17: refused in the ack while the write path is not approved")
		XCTAssertEqual(ack?["error"] as? String, "waiting_registration", "C-17: waiting_registration, not already_exists")
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account), "C-17: nothing is pending")
		print("GROUP-C-NOT-RUN C-17: 未执行")
	}

	// MARK: - M-01 to M-04: the whole shared-vector replay (backup missing)

	private final class CountingRegistrar: BeamioPGPIdentityCreate.Registering {
		var calls = 0
		func register(eoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error> { calls += 1; return .success(()) }
	}

	/// Replays every step of M-01..M-04: `setChain`, `restore` and `resume` (the evaluation), `tapEntry` (prepare of the replace path) and `keygen`
	/// (the native confirmation). The SDK-owned parts of `expect` are compared: step results and codes, the failure reply fields, the chain, the local
	/// record and pending, and every counter. `observedVersion` and the `awaiting_confirm` page state belong to the page.
	func testMGroupFullReplayFromTheSharedVector() throws {
		try loadVectors()
		let cases = try XCTUnwrap(restore["cases"] as? [[String: Any]]).filter { ($0["group"] as? String) == "M" }
		XCTAssertEqual(cases.map { $0["id"] as? String }, ["M-01", "M-02", "M-03", "M-04"])
		let savedGenerate = BeamioPGPIdentityCreate.generateKeyPair
		let savedRegistration = BeamioPGPIdentityCreate.registration
		defer {
			BeamioPGPIdentityCreate.generateKeyPair = savedGenerate
			BeamioPGPIdentityCreate.registration = savedRegistration
		}
		for c in cases {
			let id = c["id"] as? String ?? "?"
			BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
			BeamioPGPIdentityCreate.resetInFlightIdentities()
			BeamioPGPIdentityCreate.resetCompletedIdentities()
			store.keys = [:]
			try installAccountKey()
			var keygen = 0
			let registrar = CountingRegistrar()
			BeamioPGPIdentityCreate.generateKeyPair = { _ in keygen += 1; return .failure(NSError(domain: "m", code: 1)) }
			BeamioPGPIdentityCreate.registration = registrar
			let steps = try XCTUnwrap((c["input"] as? [String: Any])?["steps"] as? [[String: Any]])
			let expect = try XCTUnwrap(c["expect"] as? [String: Any])
			let wanted = try XCTUnwrap(expect["stepResults"] as? [[String: Any]])
			XCTAssertEqual(steps.count, wanted.count, id)
			var lastReply: [String: Any] = [:]
			for (n, step) in steps.enumerated() {
				let op = step["op"] as? String ?? "?"
				let want = wanted[n]
				var got = "ok", code: String?
				switch op {
				case "setChain":
					try setChain(identity: step["identity"] as? String, blob: step["blob"] as? String ?? "")
				case "restore", "resume":
					let events = dispatch("pgpRestoreEvaluate", reqId: "m-\(id)-\(n)", expectingEvents: 1)
					let r = try XCTUnwrap(events.first?["result"] as? [String: Any], id)
					lastReply = r
					if (r["state"] as? String) == "failed" { got = "failed:" + (r["failureClass"] as? String ?? "?") }
				case "tapEntry":
					// the entry opens the replace path: prepare only, no key and no write. The expected `.ready(.replace)` is fixed here: the vector does not name
					// the mode, and M-01..M-04 all run on a chain that already holds an identity.
					XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "m-tap"), .ready(.replace), id)
				case "keygen":
					let outcome = BeamioPGPIdentityCreate.confirm(
						eoa: account, idempotencyKey: step["idemKey"] as? String ?? "",
						source: (step["confirmSource"] as? String) == "native" ? .native : .webView, nativeConfirmed: step["nativeConfirmed"] as? Bool ?? false)
					if case .failed(let why) = outcome { got = "rejected"; code = why } else { got = "other:\(outcome)" }
				default:
					XCTFail("\(id): unknown op \(op)")
				}
				XCTAssertEqual(got, want["result"] as? String, "\(id) step \(n) \(op)")
				if let wantCode = want["code"] as? String { XCTAssertEqual(code, wantCode, "\(id) step \(n)") }
			}
			// the failure reply fields of the last evaluation
			let final = try XCTUnwrap(expect["final"] as? [String: Any])
			let ui = try XCTUnwrap(((final["devices"] as? [String: Any])?["A"] as? [String: Any])?["ui"] as? [String: Any])
			XCTAssertEqual(lastReply["failureClass"] as? String, ui["failureClass"] as? String, id)
			XCTAssertEqual(lastReply["code"] as? String, ui["code"] as? String, id)
			XCTAssertEqual(lastReply["offerEntry"] as? Bool, ui["offerEntry"] as? Bool, id)
			// no local identity, nothing pending, and the counters of the vector
			XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "\(id) localIdentity null")
			let pending = BeamioChatPgpKeychain.loadPending(eoa: account)
			XCTAssertTrue(pending == nil || pending?.privateArmor.isEmpty == true, "\(id) no key pending")
			let counters = try XCTUnwrap(final["counters"] as? [String: Any])
			XCTAssertEqual(keygen, counters["keygen"] as? Int, "\(id) keygen")
			XCTAssertEqual(registrar.calls, counters["registrations"] as? Int, "\(id) registrations")
			XCTAssertEqual(counters["onchainWrites"] as? Int, 0, id)
			XCTAssertEqual(counters["localWrites"] as? Int, 0, id)
			XCTAssertEqual(counters["walletWrites"] as? Int, 0, id)
			// the chain is as set: the mock was only read
			XCTAssertTrue(chainExists, id)
			XCTAssertEqual(chainBackup, try blob("B_EMPTY"), id)
		}
	}
}
#endif
