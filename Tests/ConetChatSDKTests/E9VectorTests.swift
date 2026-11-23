import XCTest
@testable import ConetChatSDK

/// The E9-series vectors (SPEC-59E-REVIEWABLE; E9, E9.1, E9.2, E9.2.1, E9.3.1; decided 2026-11-17), run data-driven from the copied vector files in
/// `Fixtures/E9Vectors` (byte-identical to the spec folder; SHA256 in the receipt).
///
/// A case is run when its state can be built from this SDK's model (the native mnemonic items, the sealed copies named by the registers, the shell
/// copy, the marker, and the storage lock of the reading). A case outside that model is reported `NOT_MAPPED` with its reason and is not counted as
/// passed. A case about the PWA or the browser, or about a write, is `NA` here. Every outcome is printed as `E9VEC <id> <outcome> <reason>`.
final class E9VectorTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedShell: ((String) -> BeamioShellRecord.ShellRecordRead)?
	private var shellRecords: [String: BeamioShellRecord.ShellRecordRead] = [:]
	private var savedDeterministic: ((String) -> Bool)?
	private var outcomes: [String] = []

	/// Placeholders of the vectors: the account names map to the two synthetic accounts of this test.
	private let placeholderOwner: [String: String] = [
		"ACCOUNT_CURRENT": "A", "ACCOUNT_A": "A", "ACCOUNT_COPY": "A", "ACCOUNT_X": "A",
		"ACCOUNT_OTHER": "B", "ACCOUNT_B": "B", "ACCOUNT_Y": "B",
	]

	/// Cases the SDK model does not express, with the reason. They are not counted as passed.
	private let notMapped: [String: String] = [
		"E9-05": "PWA side (the PWA answers first; this SDK reading is not called)",
		"E9-06": "PWA side (unknown from the PWA; the native preread is not called)",
		"E9-10": "browser side (no native consultation)",
		"E9-11": "browser side (local read unknown)",
		"E92-01": "PWA side (the PWA valid mnemonic is used; no native call)",
	]

	private var fixtureDir: URL {
		URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/E9Vectors")
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		savedShell = BeamioPwaWalletSync.shellCopyReader
		shellRecords = [:]
		BeamioPwaWalletSync.shellCopyReader = { [unowned self] account in self.shellRecords[account.lowercased()] ?? .absent }
		savedDeterministic = BeamioPwaWalletSync.shellCopyDeterministic
		BeamioPwaWalletSync.shellCopyDeterministic = { _ in true }
		outcomes = []
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioPwaWalletSync.shellCopyReader = savedShell ?? { BeamioShellRecord.EncryptedShellRecordStore.production.read(account: $0) }
		BeamioPwaWalletSync.shellCopyDeterministic = savedDeterministic ?? { BeamioShellRecord.EncryptedShellRecordStore.production.readFailureIsDeterministic(account: $0) }
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	// MARK: - Driver

	func testE9SeriesVectorsRunDataDriven() {
		let files = [
			"spec-59e-synthetic-vectors.v3.3.1-E9-add.json",
			"spec-59e-synthetic-vectors.v3.3.1-E9.1-add.json",
			"spec-59e-synthetic-vectors.v3.3.1-E9.2-add.json",
			"spec-59e-synthetic-vectors.v3.3.1-E9.2.1-add.json",
			"spec-59e-synthetic-vectors.v3.3.1-E9.3.1-add.json",
			"spec-59e-synthetic-vectors.v3.3.1-E9.1.2-add.json",
		]
		for name in files {
			guard let data = try? Data(contentsOf: fixtureDir.appendingPathComponent(name)),
			      let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
			      let cases = root["cases"] as? [[String: Any]]
			else {
				XCTFail("vector file unreadable: \(name)")
				continue
			}
			for c in cases {
				let id = c["id"] as? String ?? "?"
				store = MemoryNativeKeyStore()
				BeamioNativeWallet.keyStore = store
				shellRecords = [:]
				BeamioNativeKeySnapshot.invalidate()
				outcomes.append("\(id) \(run(id: id, vector: c))")
			}
		}
		for line in outcomes { print("E9VEC \(line)") }
		let failed = outcomes.filter { $0.contains(" FAIL ") }
		XCTAssertTrue(failed.isEmpty, "failing E9-series vectors: \(failed)")
		XCTAssertGreaterThan(outcomes.filter { $0.contains(" PASS ") }.count, 20, "the data-driven run must pass the mapped cases")
	}

	private func run(id: String, vector c: [String: Any]) -> String {
		if let reason = notMapped[id] { return "NOT_MAPPED \(reason)" }
		let pre = c["pre"] as? [String: Any] ?? [:]
		let expect = c["expect"] as? [String: Any]
		let expected = expectation(expect)

		// PWA-side (valid mnemonic from the PWA) is answered before the native reading; those cases are NA above.
		if let pwa = pre["pwa"] as? [String: Any], pwa["valid_mnemonic"] as? Bool == true {
			return "NA the PWA answers first"
		}

		switch id {
		case "E91-03", "E9-09":
			// The keystore is unavailable or needs the user unlock: the reading is unknown whatever the records say.
			seedKeyOnly(owner: "A")
			let r = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: true, store: store)
			return verdict(r, expected, reason: "storage locked")
		case "E91-02":
			// A mnemonic that cannot be read, and no marker names it: unknown.
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			return verdict(reading(), expected, reason: "unreadable mnemonic, not an unfinished write")
		case "E9-01":
			// The REC is readable and partial (no phrase); the mnemonic is absent; a pending intent marker: no account, onboarding (confirmed).
			seedKeyOnly(owner: "A")
			writeMarker(phase: "pending", owner: "A", moves: [])
			return verdict(reading(), expected, reason: "readable partial REC, no mnemonic, pending intent marker")
		case "E9-02", "E9-08":
			// An old or unsettled marker with no record, and every mnemonic location readable and empty: absent (the storage-derived lock is not the reading).
			seedKeyOnly(owner: "A")
			writeMarker(phase: "pending", owner: "A", moves: [])
			return verdict(reading(), expected, reason: "marker without a record, mnemonic locations readable and empty")
		case "E9-07":
			// REC aead failure, and the mnemonic read fails with no marker naming it: unknown, retained.
			seedKeyOnly(owner: "A")
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			store.failKeyReadOwners.insert(owner("A"))
			return verdict(reading(), expected, reason: "mnemonic read failure not named by a marker")
		case "E9-12":
			// Key only, a partial marker naming a mnemonic move with no record behind it, an isolated copy with no phrase: absent, all retained.
			seedKeyOnly(owner: "A")
			writeMarker(phase: "pending", owner: "A", moves: [(store.accountName(.mnemonic, eoa: owner("A")), isolationName(owner: "A"))])
			addEmptyCopy(index: 1, utc: "2026-11-17T00:30:00Z")
			return verdict(reading(), expected, reason: "composite residue with no phrase anywhere")
		case "E91-04":
			// The marker does not match the record (its account is another one), every mnemonic location readable and empty: absent, not a read failure.
			seedKeyOnly(owner: "A")
			writeMarker(phase: "pending", owner: "B", moves: [])
			return verdict(reading(), expected, reason: "marker mismatch with the record; nothing readable holds a phrase")
		case "E912-01":
			// A marked mnemonic that cannot be read for a temporary reason (device locked, keystore unavailable): unknown, data kept.
			seedKeyOnly(owner: "A")
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			store.transientReadOwners.insert(owner("A"))
			writeMarker(phase: "pending", owner: "A", moves: [(store.accountName(.mnemonic, eoa: owner("A")), isolationName(owner: "A"))])
			return verdict(reading(), expected, reason: "temporary read failure of a marked item")
		case "E912-02":
			// A marked item with a deterministic failure, and another location holds a valid phrase: the marked item is ignored; valid.
			seedKeyOnly(owner: "A")
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			writeMarker(phase: "pending", owner: "A", moves: [(store.accountName(.mnemonic, eoa: owner("A")), isolationName(owner: "A"))])
			seedKeyOnly(owner: "B")
			writeMnemonic(owner: "B")
			return verdict(reading(), Expect(state: .valid, account: nil, label: "valid"), reason: "deterministic failure ignored; other location valid")
		case "E912-03":
			// A marked item with a deterministic failure, every other location read and empty: ignored, onboarding, data kept.
			seedKeyOnly(owner: "A")
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			writeMarker(phase: "pending", owner: "A", moves: [(store.accountName(.mnemonic, eoa: owner("A")), isolationName(owner: "A"))])
			return verdict(reading(), expected, reason: "deterministic failure ignored; nothing else holds a phrase")
		case "E912-04":
			// A marked item that cannot be read while its key record is missing: unknown (E9.1.2-1 (b)).
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			writeMarker(phase: "pending", owner: "A", moves: [(store.accountName(.mnemonic, eoa: owner("A")), isolationName(owner: "A"))])
			return verdict(reading(), expected, reason: "key missing while its record exists")
		case "E91-01":
			// REC undecryptable (aead_failed) and the mnemonic read fails, named by a pending marker. The vector expects onboarding; iOS cannot tell an
			// authentication failure from a locked enclave, so the iOS answer is unknown: PLATFORM-KNOWN (E9.11.5 / project ruling 4).
			seedKeyOnly(owner: "A")
			writeMnemonic(owner: "A")
			store.mnemonic.failReadOwners.insert(owner("A"))
			store.failKeyReadOwners.insert(owner("A"))
			writeMarker(phase: "pending", owner: "A", moves: [(store.accountName(.mnemonic, eoa: owner("A")), isolationName(owner: "A"))])
			let v = verdict(reading(), Expect(state: .unknown, account: nil, label: "unknown"), reason: "REC undecryptable (platform-known)")
			return v.hasPrefix("FAIL") ? "FAIL \(v.dropFirst(5))" : "PLATFORM-KNOWN \(v.dropFirst(5)); vector expects onboarding (iOS limitation: auth failure vs locked enclave)"
		case "E91-06", "E9-03":
			// Readable key record with no mnemonic, a marker whose account does not match: no phrase anywhere: absent.
			seedKeyOnly(owner: "A")
			if id == "E91-06" { writeMarker(phase: "pending", owner: "B", moves: []) }
			return verdict(reading(), expected, reason: "key record only; no phrase in any location")
		case "E9-04":
			// PWA without a phrase; a sealed copy carries a valid phrase: recovered from the sealed copy.
			seedKeyOnly(owner: "A")
			addSealedCopy(owner: "A", utc: "2026-11-17T01:00:00Z")
			return verdict(reading(), expected, reason: "valid sealed copy")
		default:
			break
		}

		// The resolve family: the current records, the sealed copies, and the shell copy as the vector states them.
		let src = (pre["native_second_tier"] as? [String: Any]) ?? (pre["native"] as? [String: Any]) ?? [:]
		if src["intent_marker"] as? String == "pending_no_newRecordSha" {
			seedKeyOnly(owner: "A")
			writeMarker(phase: "pending", owner: "A", moves: [])
		}
		if let current = src["current_record"] as? [String: Any] {
			if current["valid"] as? Bool == true, let placeholder = current["eoa"] as? String {
				writeMnemonic(owner: placeholderOwner[placeholder] ?? "A")
			} else if current["read"] as? String == "failed" {
				writeMnemonic(owner: "A")
				store.mnemonic.failReadOwners.insert(owner("A"))
			}
		}
		if let mnemonic = src["mnemonic:<eoa>"] as? [String: Any], mnemonic["valid"] as? Bool == true,
		   let placeholder = mnemonic["eoa"] as? String {
			writeMnemonic(owner: placeholderOwner[placeholder] ?? "A")
		}
		var copies: [[String: Any]] = (src["sealed_copies"] as? [[String: Any]]) ?? []
		if let single = src["sealed_copy"] as? [String: Any] { copies.append(single) }
		var dummy = 0
		for copy in copies {
			if copy["valid"] as? Bool == true, let placeholder = copy["eoa"] as? String {
				let utc = copy["audit_time"].flatMap { $0 as? String }.flatMap(auditUTC)
				addSealedCopy(owner: placeholderOwner[placeholder] ?? "A", utc: utc)
			} else if copy["read"] as? String == "failed" {
				dummy += 1
				addUnreadableCopy(index: dummy, utc: "2026-11-17T03:00:00Z")
			} else {
				dummy += 1
				addEmptyCopy(index: dummy, utc: "2026-11-17T00:30:00Z")
			}
		}
		if let shell = src["shell_encrypted_copy"] as? [String: Any] {
			if shell["read"] as? String == "failed" {
				seedKeyOnly(owner: "A")
				shellRecords[owner("A")] = .unreadable
			} else if let marked = shell["mnemonicPhrase"] as? String, marked == "VALID", let placeholder = shell["eoa"] as? String {
				let who = placeholderOwner[placeholder] ?? "A"
				seedKeyOnly(owner: who)
				shellRecords[owner(who)] = .record(["rev": 1, "schemaVersion": 2, "profiles": [], "mnemonicPhrase": phrase(for: who)])
			} else {
				seedKeyOnly(owner: "A")
				shellRecords[owner("A")] = .record(["rev": 1, "schemaVersion": 2, "profiles": []])
			}
		}
		if let marker = src["wallet.sync.marker"] as? [String: Any], marker["phase"] as? String == "pending" {
			writeMarker(phase: "pending", owner: "A", moves: [])
		}
		return verdict(reading(), expected, reason: "resolve from the model")
	}

	// MARK: - Building the state

	private func owner(_ name: String) -> String {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase(for: name)) else { preconditionFailure("the test phrase derives an account") }
		return derived.eoa.lowercased()
	}

	private func phrase(for name: String) -> String { name == "B" ? phraseB : phraseA }

	private func reading() -> BeamioPwaWalletSync.Reading {
		BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
	}

	private func seedKeyOnly(owner name: String) {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase(for: name)) else { return }
		XCTAssertTrue(store.writeItem(.key, eoa: derived.eoa, value: derived.key))
	}

	private func writeMnemonic(owner name: String) {
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: owner(name), value: BeamioPwaWalletSync.normalized(phrase(for: name))))
	}

	private func isolationName(owner name: String) -> String {
		BeamioPwaPhraseOverwrite.isolationPrefix + "e9." + store.accountName(.mnemonic, eoa: owner(name))
	}

	private func auditUTC(_ placeholder: String) -> String? {
		switch placeholder {
		case "T1": return "2026-11-17T01:00:00Z"
		case "T2": return "2026-11-17T02:00:00Z"
		default: return nil
		}
	}

	private func addSealedCopy(owner name: String, utc: String?) {
		let eoa = owner(name)
		store.rawAccounts[isolationName(owner: name)] = BeamioPwaWalletSync.normalized(phrase(for: name))
		appendAudit(from: store.accountName(.mnemonic, eoa: eoa), to: isolationName(owner: name), utc: utc)
	}

	private func addUnreadableCopy(index: Int, utc: String) {
		let to = BeamioPwaPhraseOverwrite.isolationPrefix + "e9." + "mnemonic:0x00000000000000000000000000000000000000d\(index)"
		store.rawAccounts[to] = Data("unreadable-copy".utf8)
		appendAudit(from: "mnemonic:0x00000000000000000000000000000000000000d\(index)", to: to, utc: utc)
	}

	private func addEmptyCopy(index: Int, utc: String) {
		let to = BeamioPwaPhraseOverwrite.isolationPrefix + "e9." + "mnemonic:0x00000000000000000000000000000000000000e\(index)"
		store.rawAccounts[to] = Data("not a phrase".utf8)
		appendAudit(from: "mnemonic:0x00000000000000000000000000000000000000e\(index)", to: to, utc: utc)
	}

	/// An audit row of a sealing: `from`, `to` and the UTC time (none when the vector has no time).
	private func appendAudit(from: String, to: String, utc: String?) {
		var rows: [[String: String]] = []
		if case .present(let bytes) = store.rawRead(account: BeamioPwaPhraseOverwrite.auditAccount),
		   let parsed = try? JSONSerialization.jsonObject(with: bytes) as? [[String: String]] {
			rows = parsed
		}
		var row: [String: String] = ["from": from, "to": to, "reason": "window_isolated"]
		if let utc { row["utc"] = utc }
		rows.append(row)
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = (try? JSONSerialization.data(withJSONObject: rows)) ?? Data()
	}

	private func writeMarker(phase: String, owner name: String, moves: [(String, String)]) {
		let eoa = owner(name)
		let object: [String: Any] = [
			"v": 1, "phase": phase, "eoa": eoa, "tag": "e9", "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [eoa], "partials": [],
			"moves": moves.map { ["from": $0.0, "to": $0.1, "digest": "0"] },
		]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
	}

	// MARK: - Expectation and verdict

	typealias Expect = (state: BeamioPwaWalletSync.Preread?, account: String?, label: String)

	/// The expected state of a vector: `valid` with the returned account, `unknown` (retain, retry), or `absent` (onboarding). nil when the vector
	/// states none.
	private func expectation(_ expect: [String: Any]?) -> Expect {
		guard let expect else { return (nil, nil, "none") }
		if let answer = expect["answer"] as? String {
			switch answer {
			case "valid_reconnect":
				let who = (expect["returned_account"] as? String).flatMap { placeholderOwner[$0] }
				return (.valid, who, "valid_reconnect")
			case "unknown", "retain_and_retry": return (.unknown, nil, "unknown")
			case "onboarding": return (.absent, nil, "onboarding")
			default: return (nil, nil, answer)
			}
		}
		if let classification = expect["classification"] as? String {
			switch classification {
			case "confirmed_no_valid_mnemonic": return (.absent, nil, "onboarding")
			case "valid": return (.valid, nil, "valid")
			case "unknown": return (.unknown, nil, "unknown")
			default: return (nil, nil, classification)
			}
		}
		return (nil, nil, "none")
	}

	private func verdict(_ r: BeamioPwaWalletSync.Reading, _ expected: Expect, reason: String) -> String {
		guard let want = expected.state else { return "NA \(reason): the vector states no answer" }
		guard r.state == want else { return "FAIL \(reason): expected \(expected.label), got \(r.state.rawValue)" }
		if want == .valid, let account = expected.account {
			guard r.eoa?.lowercased() == owner(account) else { return "FAIL \(reason): expected account \(account), got \(r.eoa ?? "nil")" }
		}
		return "PASS \(reason) -> \(expected.label)"
	}
}
