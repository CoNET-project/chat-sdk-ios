import XCTest
@testable import ConetChatSDK

/// `pgp-migration-vectors.v1.json`: each state
/// case runs through the `pgpMigrate` bridge command
/// with the in-memory store, the X-19 functions and the injected chain and approval. Needs PGP_MIGRATION_VECTORS=<path>
/// (TEST_RUNNER_ prefix on the simulator) and the iOS simulator, where X-19 is linked; skipped without them.
///
/// Checked per step: the ack (`ok` or the refusal code), the single result event (code and fp, or none), the interruption
/// (no event after a checkpoint), and the state of L, N and M against the fp labels. The bridge events must never carry
/// private material. The six PWA event cases (P-01 to P-06) belong to the PWA side and are not run here.
final class PgpMigrationVectorTests: XCTestCase {
	private typealias MemoryStore = PgpMigrationTestSupport.MemoryStore
	private typealias Crypto = PgpMigrationTestSupport.Crypto

	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	private var events: [[String: Any]] = []
	private var busyAccount: String?

	/// In-memory passcode records and a pass-through hardware, so that a passcode can be set without the host Keychain.
	private final class PasscodeRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class PasscodeHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedKeyStore = BeamioNativeWallet.keyStore
		savedVault = BeamioPasscodeSession.shared.vault
		events = []
		busyAccount = nil
	}

	override func tearDown() {
		if let busyAccount { BeamioPgpMigrationImport.end(account: busyAccount) }
		BeamioConetChatModule.pgpMigrationEnvironmentOverride = nil
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedKeyStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	func testStateCasesMatchTheVectors() throws {
		try PgpMigrationTestSupport.requireX19()
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 36, "36 state cases")
		for c in cases {
			runCase(c)
		}
	}

	/// The unregistration cases: called on the native API, not the bridge. The recovery source
	/// faults (pReadable, chainRegistered) and the checkpoint at afterMarkerDeleted are injected.
	func testUnregisterCasesMatchTheVectors() throws {
		try PgpMigrationTestSupport.requireX19()
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["unregisterCases"] as? [[String: Any]])
		XCTAssertTrue([8, 12].contains(cases.count), "UG-01 to UG-08, or UG-01 to UG-12")
		for c in cases {
			runUnregisterCase(c)
		}
	}

	/// The migration state cases: the state derived from the copy, the marker and the last code.
	func testMigrationStateCasesMatchTheVectors() throws {
		try PgpMigrationTestSupport.requireX19()
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["migrationStateCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 7, "SS-01 to SS-07")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let st = c["st"] as? [String: Any] ?? [:]
			let store = MemoryStore()
			let account = PgpMigrationTestSupport.account
			if let l = st["L"] as? [String: Any] {
				// SS-07: L is present with its own fingerprint (verified needs L to agree).
				let key = PgpMigrationTestSupport.key(l["fp"] as? String ?? "A")
				store.legacyRecords[PgpMigrationTestSupport.eoa] = PgpMigrationTestSupport.legacy(privateKey: key, publicKey: key)
			}
			if let n = st["N"] as? [String: Any] {
				store.stagedRecords[account] = PgpMigrationTestSupport.staged(PgpMigrationTestSupport.key(n["fp"] as? String ?? "A"))
			}
			if let m = st["M"] as? [String: Any] {
				store.markerRecords[account] = PgpMigrationTestSupport.marker(PgpMigrationTestSupport.key(m["fp"] as? String ?? "A"))
			}
			if let code = st["lastCode"] as? String {
				store.lastCodes[account] = code
			}
			let got = BeamioPgpMigrationImport.derivedState(store: store, eoa: PgpMigrationTestSupport.eoa, account: account, crypto: Crypto())
			XCTAssertEqual(got.rawValue, c["expect"] as? String, "\(id): state")
		}
	}

	/// The source selection cases, through the same choice that `run` uses. P is given as the
	/// bytes the shell would hand over, with its layout and account match; L is the record of the account in the store.
	func testSourceCasesMatchTheVectors() throws {
		try PgpMigrationTestSupport.requireX19()
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["sourceCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 7, "SR-01 to SR-07")
		let eoa = PgpMigrationTestSupport.eoa
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			let store = MemoryStore()
			if let l = input["L"] as? [String: Any], let label = l["fp"] as? String {
				let key = PgpMigrationTestSupport.key(label)
				store.legacyRecords[eoa] = PgpMigrationTestSupport.legacy(privateKey: key, publicKey: key)
			}
			var source: BeamioPgpMigrationImport.LegacyPgpSource?
			if let p = input["P"] as? [String: Any] {
				let key = PgpMigrationTestSupport.key(p["fp"] as? String ?? "A")
				source = BeamioPgpMigrationImport.LegacyPgpSource(
					privateArmor: Array(key.privateArmor.utf8),
					publicArmor: Array(key.publicArmor.utf8),
					keyId: key.keyId,
					matchedAccount: (p["matched"] as? Bool) == true,
					measuredLayout: (p["layout"] as? String) == "measured"
				)
			}
			let env = PgpMigrationTestSupport.environment(store: store, crypto: Crypto(), registeredArmor: nil)
			let choice = BeamioPgpMigrationImport.sourceChoice(eoa: eoa, source: source, env: env)
			let expect = c["expect"] as? [String: Any] ?? [:]
			XCTAssertEqual(choice.use, expect["use"] as? String, "\(id): use")
			XCTAssertEqual(choice.code, expect["code"] as? String, "\(id): code")
		}
	}

	private func runUnregisterCase(_ c: [String: Any]) {
		// The page W-class fields (UG-09 to UG-12): present or not, and removed by a successful unregister.
		let wallet = PgpMigrationTestSupport.WalletProbe(present: ((c["given"] as? [String: Any])?["W"] as? Bool) == true)
		let id = c["id"] as? String ?? "?"
		let given = c["given"] as? [String: Any] ?? [:]
		let store = MemoryStore()
		let crypto = Crypto()
		let eoa = PgpMigrationTestSupport.eoa
		let account = PgpMigrationTestSupport.account
		seedRecords(given, store: store, crypto: crypto, eoa: eoa, account: account)

		for step in c["steps"] as? [[String: Any]] ?? [] {
			let faults = step["faults"] as? [String: Any] ?? [:]
			let interrupt = faults["interrupt"] as? String
			let env = PgpMigrationTestSupport.environment(
				store: store,
				crypto: crypto,
				registeredArmor: PgpMigrationTestSupport.key("A").publicArmor,
				chainBackupRegistered: faults["chainRegistered"] as? Bool ?? false,
				sourcePReadable: faults["pReadable"] as? Bool ?? false,
					wallet: wallet,
				interrupt: interrupt == "afterMarkerDeleted" ? .afterMarkerDeleted : nil
			)
			// UG-07: an invalid EOA is refused; UG-08: a run of the same account already in progress answers busy.
			let invalid = (faults["invalidEoa"] as? Bool) == true
			let busy = (faults["busy"] as? Bool) == true
			if busy {
				XCTAssertTrue(BeamioPgpMigrationImport.begin(account: account), "\(id): the busy fixture")
			}
			let outcome = BeamioPgpMigrationImport.unregisterInternal(
				eoa: invalid ? "0xnot-an-eoa" : eoa,
				workspace: BeamioChatPgpKeychain.defaultWorkspace,
				env: env
			)
			if busy {
				BeamioPgpMigrationImport.end(account: account)
			}

			let expect = step["expect"] as? [String: Any] ?? [:]
			XCTAssertEqual(outcome.interrupted, expect["interrupted"] as? Bool ?? false, "\(id): interrupted")
			if let want = expect["code"] as? String {
				XCTAssertEqual(outcome.code, want, "\(id): code")
			}
			assertState(expect["state"] as? [String: Any] ?? [:], store: store, eoa: eoa, account: account, id: id)
			if let want = (expect["state"] as? [String: Any])?["W"] as? Bool {
				XCTAssertEqual(wallet.present, want, "\(id): the page W-class fields")
			}
			// L is never removed by the unregistration.
			if (given["L"] as? [String: Any]) != nil {
				XCTAssertNotNil(store.legacyRecords[eoa], "\(id): L is kept")
			}
		}
	}

	// MARK: One case

	private func runCase(_ c: [String: Any]) {
		let id = c["id"] as? String ?? "?"
		let given = c["given"] as? [String: Any] ?? [:]
		let store = MemoryStore()
		let crypto = Crypto()
		let eoa = PgpMigrationTestSupport.eoa
		let account = PgpMigrationTestSupport.account
		setUpGate(given["gate"] as? String ?? "G2", store: store, eoa: eoa)
		seedRecords(given, store: store, crypto: crypto, eoa: eoa, account: account)

		if given["busy"] as? Bool == true {
			XCTAssertTrue(BeamioPgpMigrationImport.begin(account: account), "\(id): the busy fixture")
			busyAccount = account
		}
		let f0Label = (given["L"] as? [String: Any]).flatMap { $0["pubFp"] as? String }
			?? (given["N"] as? [String: Any]).flatMap { $0["fp"] as? String }
			?? "A"
		let otherLabel = f0Label == "A" ? "B" : "A"

		for step in c["steps"] as? [[String: Any]] ?? [] {
			let req = step["req"] as? [String: Any] ?? [:]
			let faults = step["faults"] as? [String: Any] ?? [:]
			store.failStagedWrite = faults["writeN"] as? Bool ?? false
			store.failMarkerWrite = faults["writeM"] as? Bool ?? false
			store.rereadMismatch = faults["rereadN"] as? Bool ?? false
			crypto.verifyFails = faults["challenge"] as? Bool ?? false
			let chain = faults["chain"] as? String
			let interrupt = faults["interrupt"] as? String
			// "unregistered": nothing is registered on chain (case 2).
			let registered: String? = chain == "unregistered"
				? nil
				: (chain == "mismatch" ? PgpMigrationTestSupport.key(otherLabel).publicArmor : PgpMigrationTestSupport.key(f0Label).publicArmor)
			BeamioConetChatModule.pgpMigrationEnvironmentOverride = PgpMigrationTestSupport.environment(
				store: store,
				crypto: crypto,
				registeredArmor: registered,
				chainUnavailable: chain == "unavailable",
				x19Approved: faults["x19Approved"] as? Bool ?? true,
				interrupt: interrupt == "afterN" ? .afterStagedWrite : (interrupt == "afterM" ? .afterMarkerWrite : nil)
			)

			events = []
			BeamioConetChatModule.handleCommand(req, emit: { [weak self] event in
				self?.events.append((event["event"] as? [String: Any]) ?? event)
			})
			waitForAnswer()

			let expect = step["expect"] as? [String: Any] ?? [:]
			let ack = events.first { $0["type"] as? String == "ack" }
			let ackValue = (ack?["ok"] as? Bool) == true ? "ok" : (ack?["error"] as? String)
			XCTAssertEqual(ackValue, expect["ack"] as? String, "\(id): ack")

			let result = events.first { $0["type"] as? String == "pgpMigrateResult" }
			let wantEvent = expect["event"] as? String
			XCTAssertEqual(result?["code"] as? String, wantEvent, "\(id): result code")
			XCTAssertEqual(result == nil, wantEvent == nil, "\(id): one result or none")
			XCTAssertEqual(result?["fp"] as? String, fp16(of: expect["fp"]), "\(id): fp")
			if expect["interrupted"] as? Bool == true {
				XCTAssertNil(result, "\(id): an interrupted run sends no event")
			}
			for event in events {
				XCTAssertFalse(String(describing: event).contains("PRIVATE KEY"), "\(id): no private material in events")
			}
			assertState(expect["state"] as? [String: Any] ?? [:], store: store, eoa: eoa, account: account, id: id)
		}
		if let busyAccount {
			BeamioPgpMigrationImport.end(account: busyAccount)
			self.busyAccount = nil
		}
	}

	private func setUpGate(_ gate: String, store: MemoryStore, eoa: String) {
		let keyStore = NativeAccountCreateTests.CreateKeyStore()
		BeamioNativeWallet.keyStore = keyStore
		let records = PasscodeRecords()
		let vault = BeamioPasscodeVault(records: records, hardware: PasscodeHardware())
		switch gate {
		case "G0":
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		case "G1", "G2", "G2locked":
			keyStore.keys[eoa] = Data(repeating: 0x11, count: 32)
			BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: gate != "G1")
			if gate == "G2locked" {
				// A passcode record for the account, with no unlocked bundle: the account is LOCKED (T-77).
				let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", blob: Data(repeating: 0x11, count: 32))
				records.data[eoa.lowercased()] = try? JSONEncoder().encode(passcodeRecord)
			}
		default:
			XCTFail("unknown gate \(gate)")
		}
		BeamioPasscodeSession.shared.vault = vault
		BeamioPasscodeSession.shared.lockAll()
	}

	/// The records of the case: L, N and M, built from the fp labels.
	private func seedRecords(
		_ given: [String: Any],
		store: MemoryStore,
		crypto: Crypto,
		eoa: String,
		account: String
	) {
		if let l = given["L"] as? [String: Any] {
			let privateKey = PgpMigrationTestSupport.key(l["fp"] as? String ?? "A")
			let publicKey = PgpMigrationTestSupport.key(l["pubFp"] as? String ?? "A")
			let armor = l["armor"] as? String ?? "ok"
			let storedEoa = (l["eoa"] as? String) == "other" ? PgpMigrationTestSupport.otherEoa : eoa
			let priv = armor == "bad" ? "not an armored key" : privateKey.privateArmor
			if armor == "encrypted" { crypto.encryptedPrivateArmor = priv }
			store.legacyRecords[eoa] = PgpMigrationTestSupport.legacy(
				privateKey: privateKey, publicKey: publicKey, eoa: storedEoa, privateArmor: priv
			)
		}
		if let n = given["N"] as? [String: Any] {
			store.stagedRecords[account] = PgpMigrationTestSupport.staged(PgpMigrationTestSupport.key(n["fp"] as? String ?? "A"))
		}
		if let m = given["M"] as? [String: Any] {
			store.markerRecords[account] = PgpMigrationTestSupport.marker(PgpMigrationTestSupport.key(m["fp"] as? String ?? "A"))
		}
	}

	private func assertState(_ want: [String: Any], store: MemoryStore, eoa: String, account: String, id: String) {
		if let wantL = want["L"] as? Bool {
			XCTAssertEqual(store.legacyRecords[eoa] != nil, wantL, "\(id): L present")
		}
		if want.keys.contains("N") {
			let got = store.stagedRecords[account]?.fp16
			XCTAssertEqual(got, fp16(of: want["N"]), "\(id): N")
		}
		if want.keys.contains("M") {
			let got = store.markerRecords[account]?.fp16
			XCTAssertEqual(got, fp16(of: want["M"]), "\(id): M")
		}
	}

	/// The fp16 of an fp label of the vectors (: "A" or "B"; null for none).
	private func fp16(of value: Any?) -> String? {
		guard let label = value as? String else { return nil }
		return PgpMigrationTestSupport.key(label).fp16
	}

	/// Lets the main queue deliver the ack and the result the bridge posts (the ack first, then the result).
	private func waitForAnswer(timeout: TimeInterval = 15) {
		let deadline = Date().addingTimeInterval(timeout)
		while !events.contains(where: { $0["type"] as? String == "ack" }) && Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.01))
		}
		RunLoop.main.run(until: Date().addingTimeInterval(0.02))
	}
}
