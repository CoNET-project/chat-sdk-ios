import Security
import XCTest
@testable import ConetChatSDK

/// The native page-record bridge of the shell: the native answers of the
/// cases TR-01 to TR-19 (TR-08b included), the wallet merge cases WM-01 to WM-08, the first-run import cases IM-01 to IM-08 of
/// `pgp-migration-vectors.v1.json`, and the decisions D1 to D14 and section 7 notes. Synthetic data only. The vector file is shared
/// with the migration tests (PGP_MIGRATION_VECTORS, TEST_RUNNER_ prefix on the simulator). No X-19 call is made here.
final class PgpShellRecordTests: XCTestCase {
	private var eoa = PgpMigrationTestSupport.eoa
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

	/// The device state of a test: the account pointer, the marker and the confirmed absence.
	private final class MemoryDevice: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	/// The record of the account in memory. A write replaces the record as a whole.
	private final class MemoryShellStore: BeamioShellRecord.ShellRecordStore {
		func copyRecords() -> [[String: Any]]? { Array(records.values) }
		var records: [String: [String: Any]] = [:]
		var failWrite = false
		var writes = 0

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			if failWrite { return false }
			writes += 1
			records[account] = record
			return true
		}

		func hasAnyRecord() -> Bool { !records.isEmpty }
		/// a failed enumeration of the page copies (AK-40, AK-41).
		var enumFailed = false
		func pageCopyEnumeration() -> BeamioShellRecord.PageCopyEnumeration {
			enumFailed ? .failed : (records.isEmpty ? .absent : .present)
		}
	}

	/// The key storage in memory. `readResult` replaces the answer of every read (a key that cannot be read).
	private final class MemoryKeys: BeamioShellRecord.KeyStorage {
		var keys: [String: Data] = [:]
		var readResult: BeamioShellRecord.KeyRead?
		var writes = 0

		func readKey(account: String) -> BeamioShellRecord.KeyRead {
			if let readResult { return readResult }
			guard let key = keys[account] else { return .notFound }
			return .found(key)
		}

		func writeKey(account: String, _ key: Data) -> Bool {
			writes += 1
			keys[account] = key
			return true
		}
	}

	private typealias ShellRecordStore = BeamioShellRecord.ShellRecordStore

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	/// Canonical JSON of a value, so that a stored record can be compared with the vector's record.
	private func canonical(_ value: Any?) -> String {
		// A bare string, number or bool is not a valid top-level JSON object, so it is wrapped in an array and the brackets are removed. Without this
		// every scalar compared as "null", and an ack result code was never checked.
		guard let value else { return "null" }
		guard JSONSerialization.isValidJSONObject([value]),
		      let data = try? JSONSerialization.data(withJSONObject: [value], options: [.sortedKeys]),
		      let text = String(data: data, encoding: .utf8)
		else { return "invalid" }
		return String(text.dropFirst().dropLast())
	}

	/// A device with the marker legacy_store_unreadable set or not.
	private func deviceWith(marker: Bool, found: Bool = false, confirmedAbsent: Bool = false) -> MemoryDevice {
		let device = MemoryDevice()
		device.state.legacyUnreadable = marker
		device.state.legacyFound = found
		device.state.legacyConfirmedAbsent = confirmedAbsent
		return device
	}

	/// The per-account first-run values of a case are device-level flags now: notRun, confirmedAbsent, importNotDone, legacyUnreadable.
	private func deviceFor(firstRun: BeamioShellRecord.FirstRunState, marker: Bool) -> MemoryDevice {
		deviceWith(marker: marker || firstRun == .legacyUnreadable, found: firstRun == .importNotDone, confirmedAbsent: firstRun == .confirmedAbsent)
	}

	private func environment(
		account: String,
		store: ShellRecordStore,
		firstRun: BeamioShellRecord.FirstRunState = .confirmedAbsent,
		allowed: Bool = true,
		migrating: Bool = false,
		walletCopyApproved: Bool = BeamioShellRecord.walletCopyApproved,
		marker: Bool = false,
		device: MemoryDevice? = nil
	) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { account },
			store: store,
			device: device ?? deviceFor(firstRun: firstRun, marker: marker),
			originAllowed: allowed,
			migrating: { _ in migrating },
			firstRun: { _ in firstRun },
			locked: { _ in false },
			walletCopyApproved: walletCopyApproved
		)
	}

	/// The environment of a TR vector case. The first-run state comes from `ctx.firstRun`; the default is a confirmed empty legacy store.
	private func environment(_ ctx: [String: Any], store: MemoryShellStore) -> BeamioShellRecord.Environment {
		let state: BeamioShellRecord.FirstRunState
		switch ctx["firstRun"] as? String {
		case "notRun": state = .notRun
		case "legacyUnreadable": state = .notRun
		case "importNotDone": state = .notRun
		default: state = .confirmedAbsent
		}
		return environment(
			account: eoa,
			store: store,
			firstRun: state,
			allowed: (ctx["origin"] as? String) == "allowed",
			migrating: (ctx["migrating"] as? Bool) == true,
			// The W-class copy is approved; a context may still say otherwise.
			walletCopyApproved: (ctx["walletCopyApproved"] as? Bool) ?? BeamioShellRecord.walletCopyApproved,
			marker: (ctx["firstRun"] as? String) == "legacyUnreadable"
		)
	}

	/// The request of a case. A read has no request body in the vectors (type and reqId only).
	private func request(_ c: [String: Any], kind: String, ctx: [String: Any]) -> [String: Any] {
		guard kind == "write" else {
			return ["type": "shellRecordRead", "reqId": "r1"]
		}
		var body = c["req"] as? [String: Any] ?? [:]
		if body["type"] == nil { body["type"] = "shellRecordWrite" }
		// TR-03: a request of the stated size, padded with a top-level field that is never reached (the size check comes first).
		if let target = ctx["sizeBytes"] as? Int {
			var record = body["record"] as? [String: Any] ?? [:]
			record["pad"] = ""
			body["record"] = record
			let base = BeamioShellRecord.jsonSize(body) ?? 0
			record["pad"] = String(repeating: "x", count: max(0, target - base))
			body["record"] = record
		}
		return body
	}

	/// The answer of one vector case checked against its expectation. Names are compared as sets: the paths only, sorted.
	private func assertCase(_ c: [String: Any]) {
		let id = c["id"] as? String ?? "?"
		// one line per case with its own verdict (the same convention as [AK-CASE]), so that TR-03 is confirmed by itself
		let trFailuresBefore = testRun?.failureCount ?? 0
		defer { print("[TR-CASE] \(id) \((testRun?.failureCount ?? 0) == trFailuresBefore ? "PASS" : "FAIL")") }
		let kind = c["kind"] as? String ?? "read"
		let ctx = c["ctx"] as? [String: Any] ?? [:]
		eoa = (ctx["eoa"] as? String) ?? PgpMigrationTestSupport.eoa
		let store = MemoryShellStore()
		store.failWrite = (ctx["writeFailed"] as? Bool) == true
		// TR-19: a read whose answer, envelope included, has the stated size.
		if kind == "read", let target = ctx["responseBytes"] as? Int {
			var record: [String: Any] = (c["store"] as? [String: Any])?["record"] as? [String: Any] ?? [:]
			record["pad"] = ""
			let envelope = BeamioShellRecord.jsonSize(["code": "ok", "schemaVersion": 1, "record": record, "reqId": "r1"]) ?? 0
			record["pad"] = String(repeating: "x", count: max(0, target - envelope))
			store.records[eoa] = record
		}
		if kind != "read" || ctx["responseBytes"] == nil, let seeded = c["store"] as? [String: Any], let record = seeded["record"] as? [String: Any] {
			store.records[eoa] = record
		}

		let answer = BeamioShellRecord.answer(
			request(c, kind: kind, ctx: ctx),
			env: environment(ctx, store: store),
			nativeWrite: (ctx["nativeWrite"] as? Bool) == true
		)
		let expect = c["expect"] as? [String: Any] ?? [:]
		XCTAssertEqual(answer["code"] as? String, expect["code"] as? String, "\(id): code")

		if expect.keys.contains("reqId") {
			if expect["reqId"] is NSNull {
				XCTAssertTrue(answer["reqId"] is NSNull, "\(id): reqId is null")
			} else {
				XCTAssertEqual(answer["reqId"] as? String, expect["reqId"] as? String, "\(id): reqId echoed")
			}
		}
		if let want = expect["currentRev"] as? Int {
			XCTAssertEqual(answer["currentRev"] as? Int, want, "\(id): currentRev")
		}
		if let want = expect["rev"] as? Int {
			XCTAssertEqual(answer["rev"] as? Int, want, "\(id): rev")
		}
		if let want = expect["names"] as? [String] {
			let got = answer["names"] as? [String] ?? []
			XCTAssertEqual(Set(got), Set(want), "\(id): the names only, never values")
			XCTAssertEqual(got, Set(got).utf8Sorted, "\(id): names in UTF-8 byte order")
		}
		if let want = expect["sub"] as? String {
			XCTAssertEqual(answer["sub"] as? String, want, "\(id): sub-code")
		}
		if let want = expect["record"] as? [String: Any] {
			XCTAssertEqual(canonical(answer["record"]), canonical(want), "\(id): the record, W-class fields redacted")
		}
		if let want = expect["walletFieldsRedacted"] as? Bool {
			XCTAssertEqual(answer["walletFieldsRedacted"] as? Bool, want, "\(id): walletFieldsRedacted")
		}
		if let want = expect["schemaVersion"] as? Int {
			XCTAssertEqual(answer["schemaVersion"] as? Int, want, "\(id): the reply's schemaVersion")
		}
		if expect.keys.contains("store") {
			if expect["store"] is NSNull {
				XCTAssertNil(store.records[eoa], "\(id): the store is unchanged (absent)")
			} else if let wanted = (expect["store"] as? [String: Any])?["record"] {
				XCTAssertEqual(canonical(store.records[eoa]), canonical(wanted), "\(id): the stored record")
			}
		}
	}

	func testTheNativeAnswersOfTheShellRecordCasesMatchTheVectors() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(PgpMigrationTestSupport.sidecar(root["shellRecordCases"] as Any) as? [[String: Any]])
		XCTAssertEqual(cases.count, 47, "TR-01 to TR-47 (TR-14 absent, TR-08b included),")
		for c in cases {
			assertCase(c)
		}
	}

	// MARK: Origin, flags and the first read

	func testAWriteWithoutTheShellsOriginVerdictIsRefusedAndStoresNothing() {
		let store = MemoryShellStore()
		let body: [String: Any] = ["type": "shellRecordWrite", "reqId": "w9", "record": ["rev": 0, "schemaVersion": 1]]
		let answer = BeamioShellRecord.answer(body, env: environment(account: eoa, store: store, allowed: false))
		XCTAssertEqual(answer["code"] as? String, "origin_refused")
		XCTAssertTrue(store.records.isEmpty, "nothing reaches the store without the origin verdict")
	}

	func testTheMigratingStateAnswersBeforeTheRecord() {
		let store = MemoryShellStore()
		store.records[eoa] = ["rev": 1, "schemaVersion": 2]
		let read = BeamioShellRecord.answer(
			["type": "shellRecordRead", "reqId": "r3"],
			env: environment(account: eoa, store: store, migrating: true)
		)
		XCTAssertEqual(read["code"] as? String, "migrating", "a half-made record is never read")
	}

	func testTheShellFlagsDecideMigrating() {
		BeamioShellRecord.beginPreWebViewMigration(eoa: eoa)
		XCTAssertTrue(BeamioShellRecord.isMigrating(eoa))
		BeamioShellRecord.finishPreWebViewMigration(eoa: eoa)
		XCTAssertFalse(BeamioShellRecord.isMigrating(eoa))
	}

	/// D8: an absence is answered only when the legacy store is confirmed empty. Any other first state is an error.
	func testAFirstReadIsAbsentOnlyWhenTheLegacyStoreIsConfirmedEmpty() {
		let store = MemoryShellStore()
		func read(_ state: BeamioShellRecord.FirstRunState, marker: Bool = false, found: Bool = false) -> [String: Any] {
			BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "r4"], env: environment(account: eoa, store: store, firstRun: state, device: deviceWith(marker: marker, found: found, confirmedAbsent: state == .confirmedAbsent)))
		}
		XCTAssertEqual(read(.confirmedAbsent)["code"] as? String, "absent")
		XCTAssertEqual(read(.notRun)["code"] as? String, "migrating", "an unread legacy store is migrating")
		XCTAssertEqual(read(.notRun, found: true)["sub"] as? String, "import_not_done")
		// E9.11.29 r2 (K.3, IM-03): the unreadable marker answers a read `error legacy_store_unreadable`, superseding the U.6 migrating row for reads.
		// group A: with no native key on the device the read stays migrating (U.6); with a native key (even a key only) it is error legacy_store_unreadable (KR-05).
		let savedKeys = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = savedKeys }
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		XCTAssertEqual(read(.notRun, marker: true)["code"] as? String, "migrating", "no native key: migrating")
		let keyOnly = MemoryNativeKeyStore()
		keyOnly.keys[eoa] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = keyOnly
		XCTAssertEqual(read(.notRun, marker: true)["code"] as? String, "error")
		XCTAssertEqual(read(.notRun, marker: true)["sub"] as? String, "legacy_store_unreadable")
		XCTAssertEqual(read(.notRun, found: true)["code"] as? String, "error")
	}

	func testTheWalletCopyApprovalIsGrantedForTheEncryptedCopy() {
		XCTAssertTrue(BeamioShellRecord.walletCopyApproved, "the encrypted copy is approved")
	}

	/// The W-class copy: approved for schemaVersion 2 only. Schema 1 stays refused even when approved.
	func testTheWalletCopyIsRefusedForSchemaOneEvenWhenApproved() {
		let store = MemoryShellStore()
		let body: [String: Any] = [
			"type": "shellRecordWrite", "reqId": "w10",
			"record": ["rev": 0, "schemaVersion": 1, "profiles": [["privateKeyArmor": PgpMigrationTestSupport.armorA]]],
		]
		let answer = BeamioShellRecord.answer(body, env: environment(account: eoa, store: store))
		XCTAssertEqual(answer["code"] as? String, "wallet_copy_not_approved")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertNil(store.records[eoa])
	}

	/// D5: a stored copy with W fields takes only schemaVersion 2 writes; schema 1 and a missing schemaVersion are refused.
	func testAStoredWalletCopyTakesOnlySchemaTwoWrites() {
		let store = MemoryShellStore()
		store.records[eoa] = ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": eoa, "emailAddr": "a", "privateKeyArmor": PgpMigrationTestSupport.armorA]]]
		for schema in [1, nil] as [Int?] {
			var record: [String: Any] = ["rev": 1, "profiles": [["keyID": eoa, "emailAddr": "b"]]]
			if let schema { record["schemaVersion"] = schema }
			let answer = BeamioShellRecord.answer(
				["type": "shellRecordWrite", "reqId": "w12", "record": record],
				env: environment(account: eoa, store: store)
			)
			XCTAssertEqual(answer["code"] as? String, "wallet_copy_not_approved", "schemaVersion \(schema.map(String.init) ?? "missing")")
			XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		}
		XCTAssertEqual(store.records[eoa]?["rev"] as? Int, 1, "the stored copy is unchanged")
	}

	/// A record that exists but cannot be opened is reported as such, never as absent, and is not overwritten.
	func testAnUnopenableRecordIsUnreadableAndNotOverwritten() {
		final class Unopenable: ShellRecordStore {
			var writes = 0
			func read(account: String) -> BeamioShellRecord.ShellRecordRead { .unreadable }
			func write(account: String, _ record: [String: Any]) -> Bool {
				writes += 1
				return true
			}
		}
		let store = Unopenable()
		let env = environment(account: eoa, store: store)
		let read = BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "r9"], env: env)
		XCTAssertEqual(read["code"] as? String, "error")
		XCTAssertEqual(read["sub"] as? String, "record_unreadable")

		let write = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w11", "record": ["rev": 0, "schemaVersion": 2]],
			env: env
		)
		XCTAssertEqual(write["code"] as? String, "write_failed")
		XCTAssertEqual(store.writes, 0, "the unknown record is not overwritten")
	}

	/// Section 7: a record whose rev is not an integer is never answered as a record and never overwritten (fail closed).
	func testARecordWithoutAnIntegerRevFailsClosed() {
		let store = MemoryShellStore()
		store.records[eoa] = ["rev": "one", "schemaVersion": 2]
		let read = BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "r13"], env: environment(account: eoa, store: store))
		XCTAssertEqual(read["code"] as? String, "error")
		XCTAssertEqual(read["sub"] as? String, "record_unreadable")
		let write = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w13", "record": ["rev": 0, "schemaVersion": 2]],
			env: environment(account: eoa, store: store)
		)
		XCTAssertEqual(write["code"] as? String, "write_failed")
		XCTAssertEqual(store.writes, 0)
	}

	// MARK: Whitelist, placement and PGP fields

	/// D10 (T-295, TR-15): a PGP public field is not a page field; the write is refused as a bad request, naming the paths only.
	func testAPGPPublicFieldIsABadRequestAndNamesOnlyThePaths() {
		let store = MemoryShellStore()
		let body: [String: Any] = [
			"type": "shellRecordWrite", "reqId": "w14",
			"record": ["rev": 0, "schemaVersion": 1, "profiles": [["emailAddr": "c", "chatManager": ["router": "r", "pgpKey": ["publicKey": "PUB", "keyID": "K"]]]]],
		]
		let answer = BeamioShellRecord.answer(body, env: environment(account: eoa, store: store))
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(
			(answer["names"] as? [String] ?? []).sorted(),
			["profiles[*].chatManager.pgpKey.keyID", "profiles[*].chatManager.pgpKey.publicKey"],
			"the paths only, never the values"
		)
		XCTAssertNil(store.records[eoa])
	}

	/// D13 (TR-16): a W-class key under a whitelisted subtree is refused as key-shaped content, naming the path only.
	func testAWalletKeyUnderASubtreeIsKeyShapedContent() {
		let store = MemoryShellStore()
		let body: [String: Any] = [
			"type": "shellRecordWrite", "reqId": "w15",
			"record": ["rev": 0, "schemaVersion": 2, "profiles": [["keyID": eoa, "data": ["privateKeyArmor": PgpMigrationTestSupport.armorA]]]],
		]
		let answer = BeamioShellRecord.answer(body, env: environment(account: eoa, store: store))
		XCTAssertEqual(answer["code"] as? String, "key_shaped_content")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].data.privateKeyArmor"])
		XCTAssertNil(store.records[eoa])
	}

	/// D14: the size is the raw request as received (rawByteCount); a request over the limit is too large.
	func testTheRawRequestSizeCountsTowardTheLimit() {
		let store = MemoryShellStore()
		let body: [String: Any] = ["type": "shellRecordWrite", "reqId": "w16", "record": ["rev": 0, "schemaVersion": 1]]
		let answer = BeamioShellRecord.answer(
			body,
			env: environment(account: eoa, store: store),
			rawByteCount: BeamioShellRecord.requestLimit + 1
		)
		// v171 section 191: a request over the limit is a bad_request (an envelope failure); too_large is for an answer over the limit
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertTrue(store.records.isEmpty)
	}

	/// D14: the answer envelope counts too. A record that fits alone but not with its envelope is too large.
	func testTheAnswerEnvelopeCountsTowardTheLimit() {
		let store = MemoryShellStore()
		var record: [String: Any] = ["rev": 1, "schemaVersion": 1, "pad": ""]
		let base = BeamioShellRecord.jsonSize(record) ?? 0
		record["pad"] = String(repeating: "x", count: BeamioShellRecord.sizeLimit - 10 - base)
		store.records[eoa] = record
		XCTAssertEqual(BeamioShellRecord.jsonSize(record), BeamioShellRecord.sizeLimit - 10)
		let read = BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "r17"], env: environment(account: eoa, store: store))
		XCTAssertEqual(read["code"] as? String, "too_large")
		XCTAssertNil(read["record"])
	}

	// MARK: Merge by keyID

	/// D6: the W fields belong to the profile whose keyID is the account, not to the profile at the same position.
	func testWalletFieldsMatchTheProfileByKeyIDNotByPosition() {
		let store = MemoryShellStore()
		store.records[eoa] = [
			"rev": 1, "schemaVersion": 2,
			"profiles": [["keyID": "0xother", "emailAddr": "o"], ["keyID": eoa, "emailAddr": "a", "privateKeyArmor": PgpMigrationTestSupport.armorA]],
		]
		let answer = BeamioShellRecord.answer(
			[
				"type": "shellRecordWrite", "reqId": "w18",
				"record": ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": eoa, "emailAddr": "b"], ["keyID": "0xother", "emailAddr": "o2"]]],
			],
			env: environment(account: eoa, store: store)
		)
		XCTAssertEqual(answer["code"] as? String, "ok")
		let profiles = store.records[eoa]?["profiles"] as? [[String: Any]]
		XCTAssertEqual(profiles?[0]["privateKeyArmor"] as? String, PgpMigrationTestSupport.armorA, "restored on the profile whose keyID is the account")
		XCTAssertNil(profiles?[1]["privateKeyArmor"])
	}

	/// WM-08: a W field on a profile whose keyID is not the account is a conflict with reason w_account_unmatched; nothing stored.
	func testAWalletFieldOnAnotherKeyIDIsAnUnmatchedConflict() {
		let store = MemoryShellStore()
		store.records[eoa] = ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": eoa, "privateKeyArmor": PgpMigrationTestSupport.armorA]]]
		let answer = BeamioShellRecord.answer(
			[
				"type": "shellRecordWrite", "reqId": "w19",
				"record": ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": eoa], ["keyID": "0xother", "privateKeyArmor": PgpMigrationTestSupport.armorA]]],
			],
			env: environment(account: eoa, store: store)
		)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(answer["reason"] as? String, "w_account_unmatched")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertEqual(store.records[eoa]?["rev"] as? Int, 1)
	}

	/// D6: a stored key that no profile of the account matches is never dropped by a write that omits it.
	func testAStoredKeyWithNoMatchingProfileIsNotDropped() {
		let store = MemoryShellStore()
		store.records[eoa] = ["rev": 1, "schemaVersion": 2, "profiles": [["emailAddr": "a", "privateKeyArmor": PgpMigrationTestSupport.armorA]]]
		let before = canonical(store.records[eoa])
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w20", "record": ["rev": 1, "schemaVersion": 2, "profiles": [["emailAddr": "b"]]]],
			env: environment(account: eoa, store: store)
		)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertEqual(canonical(store.records[eoa]), before, "the stored copy is unchanged")
	}

	// MARK: Native observer

	func testTheNativeObserverNeverReceivesTheWalletFields() {
		let store = MemoryShellStore()
		store.records[eoa] = [
			"rev": 1, "schemaVersion": 2, "mnemonicPhrase": "M",
			"profiles": [["keyID": eoa, "privateKeyArmor": PgpMigrationTestSupport.armorA, "emailAddr": "a"]],
			"walletVault": ["mnemonicPhrase": "M", "other": 1],
		]
		let full = BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "r21"], env: environment(account: eoa, store: store))
		let fullRecord = full["record"] as? [String: Any] ?? [:]
		XCTAssertEqual(fullRecord["mnemonicPhrase"] as? String, "M", "the WebView keeps the W fields")

		let observed = BeamioShellRecord.observerView(full)
		let record = observed["record"] as? [String: Any] ?? [:]
		XCTAssertNil(record["mnemonicPhrase"])
		XCTAssertNil((record["profiles"] as? [[String: Any]])?.first?["privateKeyArmor"])
		XCTAssertEqual((record["profiles"] as? [[String: Any]])?.first?["emailAddr"] as? String, "a", "the other fields stay")
		XCTAssertEqual((record["walletVault"] as? [String: Any])?["other"] as? Int, 1)
		XCTAssertEqual((record["walletVault"] as? [String: Any])?["mnemonicPhrase"] as? String, "M", "walletVault is not a W-class field")
	}

	// MARK: Unregister

	func testRemovingTheWalletFieldsKeepsTheRestAndBumpsTheRev() {
		let store = MemoryShellStore()
		store.records[eoa] = [
			"rev": 2, "schemaVersion": 2, "mnemonicPhrase": "M",
			"profiles": [["keyID": eoa, "privateKeyArmor": PgpMigrationTestSupport.armorA, "emailAddr": "a"]],
		]
		XCTAssertTrue(BeamioShellRecord.removeWalletFields(account: eoa, store: store))
		let record = store.records[eoa] ?? [:]
		XCTAssertEqual(record["rev"] as? Int, 3)
		XCTAssertNil(record["mnemonicPhrase"])
		XCTAssertNil(record["walletVault"])
		XCTAssertNil((record["profiles"] as? [[String: Any]])?.first?["privateKeyArmor"])
		XCTAssertEqual((record["profiles"] as? [[String: Any]])?.first?["emailAddr"] as? String, "a")
	}

	// MARK: First-run import

	/// The IM vectors of: the import result, the stored copy, and the first read after the import. The legacy store of a step is
	/// the one of `legacyNext` when the step gives it, otherwise the one in effect before the step.
	func testTheFirstRunImportCasesMatchTheVectors() throws {
		let savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		defer { BeamioNativeWallet.keyStore = savedKeyStore }
		let root = try vectorRoot()
		let cases = try XCTUnwrap(PgpMigrationTestSupport.sidecar(root["importCases"] as Any) as? [[String: Any]])
		XCTAssertEqual(cases.count, 11, "IM-01 to IM-11")
		for c in cases {
			BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
			let id = c["id"] as? String ?? "?"
			// one line per case with its own verdict (the same convention as [AK-CASE]), so that IM-03 and IM-08 are confirmed one by one
			let imFailuresBefore = testRun?.failureCount ?? 0
			defer { print("[IM-CASE] \(id) \((testRun?.failureCount ?? 0) == imFailuresBefore ? "PASS" : "FAIL")") }
			let initial = c["init"] as? [String: Any] ?? [:]
			var legacyState = initial["legacy"] as? [String: Any] ?? [:]
			// The account is the vector's recordAddr: from the initial legacy record, or from the first step that gives one (IM-08).
			let stepRecordAddr = (c["steps"] as? [[String: Any]] ?? []).compactMap { $0["legacyNext"] as? [String: Any] }.first?["recordAddr"] as? String
			let storedKeyID = ((((initial["store"] as? [String: Any])?["record"] as? [String: Any])?["profiles"] as? [[String: Any]])?.first)?["keyID"] as? String
			let account = ((legacyState["recordAddr"] as? String) ?? stepRecordAddr ?? (initial["derivedAddr"] as? String) ?? storedKeyID ?? eoa).lowercased()
			let derived = initial["derivedAddr"] as? String
			let store = MemoryShellStore()
			// One device for the whole case: the import's marker is what the later read answers.
			let device = MemoryDevice()
			if let seeded = initial["store"] as? [String: Any], let record = seeded["record"] as? [String: Any] {
				store.records[account] = record
			}
			var states: [String: BeamioShellRecord.FirstRunState] = [:]
			let steps = c["steps"] as? [[String: Any]] ?? []
			for (index, step) in steps.enumerated() {
				if let next = step["legacyNext"] as? [String: Any] {
					legacyState = next
				} else if let state = step["legacyNext"] as? String {
					legacyState = ["state": state]
				}
				let faults = step["faults"] as? [String: Any] ?? [:]
				let expect = step["expect"] as? [String: Any] ?? [:]
				store.failWrite = (faults["writeFailed"] as? Bool) == true
				// Each step gets its own legacy read: the import zeroes the bytes it is given.
				let legacy: BeamioShellRecord.LegacyWalletRead
				switch legacyState["state"] as? String {
				case "found":
					let bytes = try JSONSerialization.data(withJSONObject: legacyState["record"] as Any)
					legacy = .found(BeamioShellRecord.LegacyWalletRecord(bytes: [UInt8](bytes)))
				case "unreadable":
					legacy = .unreadable
				default:
					legacy = .absent
				}
				let code = BeamioShellRecord.importFirstRun(
					eoa: account,
					legacy: legacy,
					store: store,
					device: device, addressOf: { _ in derived },
					setState: { states[$0] = $1 }
				)
				let tag = "\(id) step \(index)"
				XCTAssertEqual(code.rawValue, expect["importCode"] as? String, "\(tag): import code")
				if expect["store"] is NSNull {
					XCTAssertNil(store.records[account], "\(tag): nothing is stored")
				} else if let storeExpect = expect["store"] as? [String: Any], let record = storeExpect["record"] as? [String: Any] {
					XCTAssertEqual(canonical(store.records[account]), canonical(record), "\(tag): the stored copy")
				}
				if let read = expect["read"] as? [String: Any] {
					let answer = BeamioShellRecord.answer(
						["type": "shellRecordRead", "reqId": "ri"],
						env: environment(account: account, store: store, firstRun: states[account] ?? .notRun, device: device)
					)
					XCTAssertEqual(answer["code"] as? String, read["code"] as? String, "\(tag): read code")
					if let sub = read["sub"] as? String {
						XCTAssertEqual(answer["sub"] as? String, sub, "\(tag): read sub-code")
					}
					if let record = read["record"] as? [String: Any] {
						XCTAssertEqual(canonical(answer["record"]), canonical(record), "\(tag): the record read back")
					}
				}
			}
		}
	}

	/// D8: the import never creates a wallet over an existing copy, and a readable copy is never replaced.
	func testAnExistingCopyIsNeverReplacedByAnImport() {
		let store = MemoryShellStore()
		store.records[eoa] = ["rev": 3, "schemaVersion": 2]
		let legacy = BeamioShellRecord.LegacyWalletRead.found(BeamioShellRecord.LegacyWalletRecord(bytes: Array("{}".utf8)))
		let code = BeamioShellRecord.importFirstRun(eoa: eoa, legacy: legacy, store: store, device: MemoryDevice(), addressOf: { _ in nil }, setState: { _, _ in })
		XCTAssertEqual(code, .exists)
		XCTAssertEqual(store.records[eoa]?["rev"] as? Int, 3)
	}

	// MARK: Keychain and the encrypted copy

	/// D1, D11: the key item is AfterFirstUnlockThisDeviceOnly and never synchronized.
	func testTheKeyItemIsAfterFirstUnlockThisDeviceOnlyAndNeverSynchronized() {
		let add = BeamioShellRecord.KeychainKeyStorage.addAttributes(account: eoa, key: Data(repeating: 1, count: 32))
		XCTAssertEqual(add[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
		XCTAssertEqual(add[kSecAttrSynchronizable as String] as? Bool, false)
		XCTAssertEqual(BeamioShellRecord.KeychainKeyStorage.itemAttributes(account: eoa)[kSecAttrSynchronizable as String] as? Bool, false)
	}

	/// D2, D3: the directory and the file are excluded from backup; the file starts with the version byte.
	func testTheEncryptedCopyIsExcludedFromBackupAndVersioned() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-backup-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: MemoryKeys())
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: eoa, ["rev": 1, "schemaVersion": 2]))
		XCTAssertEqual(try directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
		let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
		XCTAssertEqual(files.count, 1, "no temporary file is left behind")
		guard let first0 = files.first else { return XCTFail("no file written") }
		XCTAssertEqual(try first0.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true)
		XCTAssertEqual(try Data(contentsOf: first0).first, BeamioShellRecord.formatVersion)
		XCTAssertEqual(store.read(account: eoa), .record(["rev": 1, "schemaVersion": 2]))
	}

	/// D3: the account key is the lowercase EOA with the workspace.
	func testTheAccountKeyIsTheLowercaseEoaAndTheWorkspace() {
		XCTAssertEqual(BeamioShellRecord.accountKey("0xABCdef"), "0xabcdef:default")
	}

	/// Section 7 (store directory): without a storage directory the store fails closed; nothing falls back to a temporary directory.
	func testWithoutAStorageDirectoryTheStoreFailsClosed() {
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: nil, keys: MemoryKeys())
		XCTAssertEqual(store.read(account: eoa), .unreadable)
		XCTAssertFalse(store.write(account: eoa, ["rev": 0, "schemaVersion": 2]))
	}

	/// Section 7 (loadKey): a key that cannot be read is never replaced by a new one.
	func testAKeyThatCannotBeReadIsNeverReplaced() {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-key-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let keys = MemoryKeys()
		keys.readResult = .failed
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: keys)
		XCTAssertFalse(store.write(account: eoa, ["rev": 0, "schemaVersion": 2]))
		XCTAssertEqual(keys.writes, 0, "no new key is written over an unreadable one")
	}

	/// The encrypted copy: sealed on disk, bound to its account, and unreadable without its key.
	func testTheEncryptedCopyIsSealedOnDiskAndBoundToTheAccount() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-test-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let keys = MemoryKeys()
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: keys)
		let secret = "SECRET-EOA-KEY-7f3a9c"
		let record: [String: Any] = ["rev": 1, "schemaVersion": 2, "profiles": [["privateKeyArmor": secret]]]

		XCTAssertEqual(store.read(account: eoa), .absent)
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: eoa, record))
		XCTAssertEqual(store.read(account: eoa), .record(record))

		let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
		XCTAssertEqual(files.count, 1)
		guard let firstFile = files.first else { return XCTFail("no file written") }
		let onDisk = try Data(contentsOf: firstFile)
		XCTAssertNil(String(data: onDisk, encoding: .utf8)?.range(of: secret), "the copy on disk does not hold the key in clear")
		XCTAssertNil(String(data: onDisk, encoding: .utf8)?.range(of: "privateKeyArmor"))

		// Another account cannot open this copy: its file name and its authenticated data differ.
		XCTAssertEqual(store.read(account: PgpMigrationTestSupport.otherEoa), .absent)

		// Without its key the copy is unreadable, not absent.
		keys.keys = [:]
		XCTAssertEqual(store.read(account: eoa), .unreadable)
	}

	// MARK: Wallet merge vectors

	/// The wallet merge cases. The account of the vectors is `ctx.eoa` (the keyID "a1"). An omitted W field keeps the stored value, a
	/// differing one conflicts, a first write is accepted, only a native write replaces W fields, schema 1 is refused for a stored copy,
	/// and a W field on another keyID is an unmatched conflict.
	func testWalletMergeCasesMatchTheVectors() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(PgpMigrationTestSupport.sidecar(root["walletMergeCases"] as Any) as? [[String: Any]])
		XCTAssertEqual(cases.count, 13, "WM-01 to WM-13")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let ctx = c["ctx"] as? [String: Any] ?? [:]
		eoa = (ctx["eoa"] as? String) ?? PgpMigrationTestSupport.eoa
			let account = (ctx["eoa"] as? String) ?? eoa
			let store = MemoryShellStore()
			if let seeded = c["store"] as? [String: Any], let record = seeded["record"] as? [String: Any] {
				store.records[account] = record
			}
			var body = c["req"] as? [String: Any] ?? [:]
			body["type"] = "shellRecordWrite"
			let answer = BeamioShellRecord.answer(
				body,
				env: environment(account: account, store: store, allowed: (ctx["origin"] as? String) == "allowed"),
				nativeWrite: (ctx["nativeWrite"] as? Bool) == true
			)
			let expect = c["expect"] as? [String: Any] ?? [:]
			XCTAssertEqual(answer["code"] as? String, expect["code"] as? String, "\(id): code")
			XCTAssertEqual(answer["reqId"] as? String, expect["reqId"] as? String, "\(id): reqId")
			if let want = expect["rev"] as? Int {
				XCTAssertEqual(answer["rev"] as? Int, want, "\(id): rev")
			}
			if let want = expect["currentRev"] as? Int {
				XCTAssertEqual(answer["currentRev"] as? Int, want, "\(id): currentRev")
			}
			if let want = expect["reason"] as? String {
				XCTAssertEqual(answer["reason"] as? String, want, "\(id): reason")
			}
			if let want = expect["names"] as? [String] {
				let got = answer["names"] as? [String] ?? []
				XCTAssertEqual(Set(got), Set(want), "\(id): names")
				XCTAssertEqual(got, Set(got).utf8Sorted, "\(id): names in UTF-8 byte order")
			}
			if let storeExpect = expect["store"] as? [String: Any], let record = storeExpect["record"] as? [String: Any] {
				XCTAssertEqual(canonical(store.records[account]), canonical(record), "\(id): the stored record")
			}
		}
	}

	/// review: key-shaped names inside the container subtrees are refused, not only the two W names.
	func testTheKeyShapedNamesUnderTheContainersAreKeyShapedContent() {
		let cases: [(String, String)] = [
			("tokens", "privateKeyHex"), ("data", "seed"), ("phoneCalls", "walletPrivateKey"),
			("data", "pgpPassphraseX"), ("data", "pgpPrivateKey"), ("spClub", "privateKeyArmored"),
		]
		for (container, key) in cases {
			let store = MemoryShellStore()
			let profile: [String: Any] = ["keyID": eoa, container: [key: "x"]]
			let answer = BeamioShellRecord.answer(
				["type": "shellRecordWrite", "reqId": "w30", "record": ["rev": 0, "schemaVersion": 2, "profiles": [profile]]],
				env: environment(account: eoa, store: store)
			)
			XCTAssertEqual(answer["code"] as? String, "key_shaped_content", "\(container).\(key)")
			XCTAssertEqual(answer["names"] as? [String], ["profiles[*].\(container).\(key)"], "the path only")
			XCTAssertNil(store.records[eoa])
		}
	}

	/// review: a scalar key is an exact path; a path beneath it is not whitelisted.
	func testAScalarPathIsExactAndRefusesSubPaths() {
		let store = MemoryShellStore()
		let profile: [String: Any] = ["keyID": eoa, "emailAddr": ["x": "1"]]
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w31", "record": ["rev": 0, "schemaVersion": 2, "profiles": [profile]]],
			env: environment(account: eoa, store: store)
		)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].emailAddr.x"])
	}

	/// Records whether the account is migrating at the moment of each write, and answers with `writesOK`.
	private final class ProbeStore: BeamioShellRecord.ShellRecordStore {
		let account: String
		let writesOK: Bool
		var sawMigrating: Bool?

		init(account: String, writesOK: Bool = true) {
			self.account = account
			self.writesOK = writesOK
		}

		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .absent }

		func write(account: String, _ record: [String: Any]) -> Bool {
			sawMigrating = BeamioShellRecord.isMigrating(account)
			return writesOK
		}
	}

	private func walletLegacy() throws -> BeamioShellRecord.LegacyWalletRead {
		let json: [String: Any] = ["profiles": [["keyID": eoa, "emailAddr": "a", "privateKeyArmor": PgpMigrationTestSupport.armorA]], "mnemonicPhrase": "M"]
		return .found(BeamioShellRecord.LegacyWalletRecord(bytes: [UInt8](try JSONSerialization.data(withJSONObject: json))))
	}

	private func importEnvironment() -> BeamioPgpMigrationImport.Environment {
		PgpMigrationTestSupport.environment(
			store: PgpMigrationTestSupport.MemoryStore(),
			crypto: PgpMigrationTestSupport.Crypto(),
			registeredArmor: nil
		)
	}

	/// review: the first-run import marks the account migrating for its whole run, so a read during it is `migrating`.
	func testTheFirstRunImportMarksTheAccountMigratingForItsWholeRun() throws {
		let probe = ProbeStore(account: eoa)
		let outcome = BeamioPgpMigrationImport.importFirstRun(
			eoa: eoa,
			walletRecord: try walletLegacy(),
			pgpSource: nil,
			store: probe,
			device: MemoryDevice(), addressOf: { _ in PgpMigrationTestSupport.eoa },
			env: importEnvironment()
		)
		XCTAssertEqual(outcome.wallet, .importOk)
		XCTAssertEqual(probe.sawMigrating, true, "the account is migrating while the copy is written")
		XCTAssertFalse(BeamioShellRecord.isMigrating(eoa), "the import clears the mark it set")
		XCTAssertNotNil(outcome.pgp, "the PGP part runs once the wallet copy is in place")
	}

	/// A mark the shell set before the import is not cleared by the import.
	func testAnAccountMigratingBeforeTheImportStaysMigratingAfterIt() throws {
		BeamioShellRecord.beginPreWebViewMigration(eoa: eoa)
		defer { BeamioShellRecord.finishPreWebViewMigration(eoa: eoa) }
		let outcome = BeamioPgpMigrationImport.importFirstRun(
			eoa: eoa,
			walletRecord: try walletLegacy(),
			pgpSource: nil,
			store: ProbeStore(account: eoa),
			device: MemoryDevice(), addressOf: { _ in PgpMigrationTestSupport.eoa },
			env: importEnvironment()
		)
		XCTAssertEqual(outcome.wallet, .importOk)
		XCTAssertTrue(BeamioShellRecord.isMigrating(eoa), "the import does not clear a mark the shell set")
	}

	/// A failed wallet copy keeps the legacy store and does not run the PGP migration (step 2c).
	func testAFailedWalletCopyDoesNotRunThePGPMigration() throws {
		let outcome = BeamioPgpMigrationImport.importFirstRun(
			eoa: eoa,
			walletRecord: try walletLegacy(),
			pgpSource: nil,
			store: ProbeStore(account: eoa, writesOK: false),
			device: MemoryDevice(), addressOf: { _ in PgpMigrationTestSupport.eoa },
			env: importEnvironment()
		)
		XCTAssertEqual(outcome.wallet, .importFailed)
		XCTAssertNil(outcome.pgp)
		XCTAssertFalse(BeamioShellRecord.isMigrating(eoa))
	}

	/// the PGP migration runs only in the import branch. An absent legacy store and an existing copy skip it.
	func testThePGPMigrationRunsOnlyInTheImportBranch() {
		let absent = BeamioPgpMigrationImport.importFirstRun(
			eoa: eoa,
			walletRecord: .absent,
			pgpSource: nil,
			store: ProbeStore(account: eoa),
			device: MemoryDevice(), addressOf: { _ in PgpMigrationTestSupport.eoa },
			env: importEnvironment()
		)
		XCTAssertEqual(absent.wallet, .absent)
		XCTAssertNil(absent.pgp, "absent does not run the PGP migration")

		let exists = BeamioPgpMigrationImport.importFirstRun(
			eoa: eoa,
			walletRecord: .absent,
			pgpSource: nil,
			store: PresentStore(),
			device: MemoryDevice(), addressOf: { _ in PgpMigrationTestSupport.eoa },
			env: importEnvironment()
		)
		XCTAssertEqual(exists.wallet, .exists)
		XCTAssertNil(exists.pgp, "exists does not run the PGP migration")
	}

	/// A native copy that already exists (rev 2). Reads and writes of it are not replaced by an import.
	private final class PresentStore: BeamioShellRecord.ShellRecordStore {
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .record(["rev": 2, "schemaVersion": 2]) }
		func write(account: String, _ record: [String: Any]) -> Bool { false }
	}

	/// FM-01: the authenticated data is the lowercase EOA, ":default", and the version byte 0x01.
	func testFM01TheAuthenticatedDataIsTheLowercaseEoaWorkspaceAndTheVersionByte() {
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: nil, keys: MemoryKeys())
		let hex = store.aad("0xAbC0000000000000000000000000000000000001").map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(hex, "3078616263303030303030303030303030303030303030303030303030303030303030303030303030313a64656661756c7401")
	}

	/// FM-02: the file is the version byte, the 12-byte nonce, the ciphertext of n bytes and the 16-byte tag: 29 + n bytes.
	func testFM02TheFileIsVersionNonceCiphertextAndTagWithTotalLength29PlusN() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-fm02-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: MemoryKeys())
		let record: [String: Any] = ["rev": 1, "schemaVersion": 2, "emailAddr": "a"]
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: eoa, record))
		let plain = try XCTUnwrap(BeamioShellRecord.canonicalJSON(record)).count
		let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
		XCTAssertEqual(files.count, 1)
		guard let first = files.first else { return }
		let onDisk = try Data(contentsOf: first)
		XCTAssertEqual(onDisk.count, 29 + plain)
		XCTAssertEqual(onDisk.first, BeamioShellRecord.formatVersion)
	}

	/// FM-03: a version byte other than 0x01 is record_unreadable: not decrypted, not absent, not overwritten.
	func testFM03AVersionByteOtherThanOneIsUnreadable() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-fm03-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: MemoryKeys())
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: eoa, ["rev": 1, "schemaVersion": 2]))
		let url = store.fileURL(in: directory, eoa)
		var bytes = try Data(contentsOf: url)
		bytes[0] = 0x02
		try bytes.write(to: url)
		XCTAssertEqual(store.read(account: eoa), .unreadable)
	}

	/// FM-04: a file of another account (its authenticated data differs) is record_unreadable, not absent.
	func testFM04AFileOfAnotherAccountIsUnreadableNotAbsent() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-fm04-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let other = "0x1111111111111111111111111111111111111111"
		let keys = MemoryKeys()
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: keys)
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: eoa, ["rev": 1, "schemaVersion": 2]))
		// The other account gets the same key, and the file of this account is moved to its place.
		keys.keys[other] = keys.keys[eoa]
		try FileManager.default.copyItem(at: store.fileURL(in: directory, eoa), to: store.fileURL(in: directory, other))
		XCTAssertEqual(store.read(account: other), .unreadable)
	}

	/// FM-05: a file shorter than 29 bytes is record_unreadable.
	func testFM05AFileShorterThan29BytesIsUnreadable() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-record-fm05-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: MemoryKeys())
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: eoa, ["rev": 1, "schemaVersion": 2]))
		let url = store.fileURL(in: directory, eoa)
		let bytes = try Data(contentsOf: url)
		try bytes.prefix(28).write(to: url)
		XCTAssertEqual(store.read(account: eoa), .unreadable)
	}

	/// (CJ-01, CJ-02): the canonical JSON of the vectors: object keys in UTF-8 byte order, no whitespace.
	func testTheCanonicalJSONMatchesTheCJVectors() throws {
		let root = try vectorRoot()
		guard let cases = root["canonicalCases"] as? [[String: Any]] else {
			throw XCTSkip("canonicalCases is in; the pinned snapshot does not have it")
		}
		XCTAssertEqual(cases.count, 2, "CJ-01 and CJ-02")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = try XCTUnwrap(c["input"])
			let expect = try XCTUnwrap(c["expect"] as? String)
			XCTAssertEqual(BeamioShellRecord.canonicalText(input), expect, id)
		}
	}

	/// the page reads an `ack` envelope with `ok` and `result.code`; the observer copy of the envelope has no W-class fields.
	func testTheAnswerReachesThePageAsAnAckEnvelopeWithResultCode() {
		let ok = BeamioShellRecord.ackEnvelope(for: ["code": "ok", "rev": 1, "reqId": "w1"])
		XCTAssertEqual(ok["type"] as? String, "ack")
		XCTAssertEqual(ok["reqId"] as? String, "w1")
		XCTAssertEqual(ok["ok"] as? Bool, true)
		XCTAssertEqual((ok["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertNil((ok["result"] as? [String: Any])?["reqId"], "the request id is at the top of the envelope")
		// A content-level refusal is ok:true with the code in result.
		let conflict = BeamioShellRecord.ackEnvelope(for: ["code": "conflict", "currentRev": 2, "reqId": "w2"])
		XCTAssertEqual(conflict["ok"] as? Bool, true)
		XCTAssertEqual((conflict["result"] as? [String: Any])?["code"] as? String, "conflict")
		// An envelope-level failure is ok:false with error and no result.
		let refused = BeamioShellRecord.ackEnvelope(for: ["code": "origin_refused", "reqId": "w3"])
		XCTAssertEqual(refused["ok"] as? Bool, false)
		XCTAssertEqual(refused["error"] as? String, "origin_refused")
		XCTAssertNil(refused["result"])

		let read: [String: Any] = ["code": "ok", "schemaVersion": 1, "record": ["mnemonicPhrase": "M", "rev": 1], "reqId": "r1"]
		let observed = BeamioShellRecord.observerEnvelope(BeamioShellRecord.ackEnvelope(for: read))
		XCTAssertNil((observed["result"] as? [String: Any])?["record"].flatMap { ($0 as? [String: Any])?["mnemonicPhrase"] })
	}

	/// the device-level legacy state decides a read without an account pointer. An unreadable legacy store is an error on every read, never absent.
	func testTheDeviceStateFileIsExcludedFromBackup() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("device-state-\(UUID().uuidString)")
		defer { try? FileManager.default.removeItem(at: directory) }
		let url = directory.appendingPathComponent("device-state.json")
		let store = BeamioShellRecord.FileDeviceStateStore(url: url)
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		store.update { $0.accountEstablished = true }
		XCTAssertTrue(store.load().accountEstablished, "the state is kept")
		XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true, "the state file is excluded from backup")
		XCTAssertEqual(try directory.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true, "its directory is excluded too")
		// A later update keeps the exclusion, because the file is replaced.
		store.update { $0.legacyUnreadable = false }
		XCTAssertEqual(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup, true, "still excluded after the replacement")
		XCTAssertTrue(store.load().accountEstablished, "the earlier state is kept")
	}

	func testTheWhitelistIsWithinTheOneHundredEightLimit() {
		XCTAssertLessThanOrEqual(BeamioShellRecord.whitelistedExact.count + BeamioShellRecord.whitelistedContainers.count, 108)
		XCTAssertFalse(BeamioShellRecord.whitelistedExact.contains("profiles[*].chatManager.keyID"), "revoked")
		XCTAssertFalse(BeamioShellRecord.whitelistedExact.contains("passcode.status"), "revoked")
	}

	/// PY.15 4 (project ruling): the legacy report is saved once the account pointer is set; the pointer, not the report, decides the read.
	func testTheLegacyReportIsSavedOnceTheAccountPointerIsSet() {
		let device = MemoryDevice()
		device.state.accountEstablished = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device), .ok)
		XCTAssertTrue(device.state.legacyUnreadable, "saved as the recent report")
		XCTAssertTrue(device.state.accountEstablished, "the resolved account state is unchanged")
	}

	/// the ack cases AK-01 to AK-16 of the vectors. Each case sets the account pointer, the marker and the legacy report it names.
	/// AK-56 cross-check (25.52Y.110 第 1 条, the coordinator's condition for the Swift table): the addresses of the mapped names are the
	/// addresses of the fixed test keys, derived by two independent paths (the signer and the shell's derivation) and by an external library
	/// (ethers, run on 2026-11-16): a1 = 0x9858effd232b4033e47d90003d41ec34ecaeda94, a2 = 0x2b5ad5c4795c026514f8317c7a215e218dccd6cf.
	/// The generator metadata holds no addresses (only the rule), so this record is the cross-check until the interface side lists them.
	func testTheAK56NamesAreTheAddressesOfTheFixedKeys() throws {
		// The record of 25.52Y.112 (interface/protocol/ak56-fixture-addresses.json, derivation: private key = keccak256(utf8(seed))).
		let record: [String: String] = [
			"a1": "0x62e94b62b86ab4dda336015b3c36e7e101599285",
			"a2": "0x26d3c917fda48a65b0474ec694adc9df27966028",
		]
		let names = PgpMigrationTestSupport.ak56Names
		// A failed or empty derivation fails this test: every name is present and non-empty, and no name maps to "".
		XCTAssertFalse(names.values.contains(""), "no mapped name is empty")
		for name in ["a1", "a2"] {
			let key = try XCTUnwrap(PgpMigrationTestSupport.ak56Key(name), "\(name): the key is derived from its seed")
			XCTAssertEqual(key.count, 32, "\(name): a 32-byte key")
			let expected = try XCTUnwrap(record[name], name)
			XCTAssertEqual(names[name], expected, "\(name): the mapped address equals the record")
			XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), expected, "\(name): the signer derivation equals the record")
			XCTAssertEqual(BeamioShellRecord.productionAddress(try XCTUnwrap(PgpMigrationTestSupport.ak56Armor(name)))?.lowercased(), expected, "\(name): the shell derivation equals the record")
		}
		XCTAssertNotEqual(names["a1"], names["a2"], "two different keys")
		XCTAssertEqual(names["EOA"], PgpMigrationTestSupport.ak56Armor("a1"), "the placeholder is the canonical armor of a1")
	}

	func testTheAckCasesMatchTheVectors() throws {
		let root = try vectorRoot()
		guard let cases = root["ackCases"] as? [[String: Any]] else {
			throw XCTSkip("ackCases is in")
		}
		XCTAssertGreaterThanOrEqual(cases.count, 20, "AK-01 to AK-20 and later revisions")
		for c in cases {
			runAckCase(Self.withAK56Names(c), nativeKey: false)
		}
	}

	/// The variant with a native key on the device: AK-15 and AK-36 keep their expectations.
	func testTheAckCasesWithANativeKeyMatchTheVectors() throws {
		let root = try vectorRoot()
		guard let cases = root["ackCases"] as? [[String: Any]] else {
			throw XCTSkip("ackCases is in")
		}
		let variant = cases.filter { ["AK-15", "AK-36"].contains($0["id"] as? String ?? "") }
		XCTAssertEqual(variant.count, 2, "AK-15 and AK-36")
		for c in variant {
			runAckCase(c, nativeKey: true)
		}
	}

	/// The fixture key of an AK-56 account, by its mapped address (25.52Y.110 第 1 条). nil for any other address.
	private static func fixtureArmor(for address: String) -> String? {
		for name in ["a1", "a2"] where address == PgpMigrationTestSupport.ak56Names[name] {
			return PgpMigrationTestSupport.ak56Armor(name)
		}
		return nil
	}

	/// AK-56 only: the symbolic names of the case are replaced by the fixture values (25.52Y.110 第 1 条). The expectation is not changed.
	private static func withAK56Names(_ c: [String: Any]) -> [String: Any] {
		guard (c["id"] as? String) == "AK-56" else { return c }
		let names = PgpMigrationTestSupport.ak56Names
		func map(_ value: Any) -> Any {
			if let text = value as? String { return names[text] ?? text }
			if let list = value as? [Any] { return list.map(map) }
			if let dict = value as? [String: Any] { return dict.mapValues(map) }
			return value
		}
		return (map(c) as? [String: Any]) ?? c
	}

	/// One ack case: the request, the device state the case names, and the expectation of the vector. With `nativeKey`, a native key is on the device.
	/// The account model of the AK set (item 8, item 1): an account is known when a native EOA key exists for it (ctx.eoa). A case
	/// without a key is acctUnknown (ctx.acctUnknown, explicit). With no key at all, the account is the one whose page copy holds an EOA private key
	/// ((a)). `keys` lists the accounts that hold a native key; `pointerAcct` names the account of the pointer. A creation case without
	/// `explicitChoice` predates the field and is an explicit choice. The non-AK record cases keep the legacy convention (harnessCtx) and do not run here.
	private func answerAckCase(_ c: [String: Any], nativeKey: Bool) -> [String: Any] {
		let memoryKeys = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = memoryKeys
		let ctx = c["ctx"] as? [String: Any] ?? [:]
		// v3.1 ctx.nativeMnemonic (AK-65): a valid mnemonic account record (test-only public phrase) is seeded on the device, which is different from ctx.nativeKey (a private key only,
		// key-only, AK-37). The derived account of the public test phrase stands for the case's eoa: the shell judges the record at device level (hasAnyRecord), not by its name.
		if (ctx["nativeMnemonic"] as? Bool) == true { ValidTestAccounts.install(memoryKeys) }
		let acctUnknown = ctx["acctUnknown"] as? Bool == true
		let creationTxn = ctx["creationTxn"] as? Bool == true
		let creationMode = ctx["creationMode"] as? Bool == true
		let explicitChoice = (ctx["explicitChoice"] as? Bool) ?? true
		let pointerAcct = ctx["pointerAcct"] as? String
		let caseNativeKey = ctx["nativeKey"] as? Bool == true
		// The native keys of the case: the listed accounts; else the variant's default key. ctx.eoa only names the account (25.52Y.110 ruling for AK-18): it seeds no key.
		var keys: [String] = []
		if let listed = ctx["keys"] as? [String] {
			keys = listed
		} else if nativeKey || caseNativeKey {
			keys = [PgpMigrationTestSupport.eoa]
		}
		// AK-56 (25.52Y.110 第 1 条): the keys of the mapped accounts are the fixture keys, so the derivation of the account is real.
		let fixtureKeys = (c["id"] as? String) == "AK-56"
		let writeKeys = {
			for name in keys {
				var key = Data(repeating: 0x11, count: 32)
				if fixtureKeys, let armor = Self.fixtureArmor(for: name), let bytes = AddressPGPChain.bytes(fromHex: armor) {
					key = Data(bytes)
				}
				_ = BeamioNativeWallet.keyStore.write(eoa: name, key: key)
			}
		}
		// A creation case writes its keys after the absence report: the reader reports before a key is generated (item 4).
		let lateKeys = creationMode || creationTxn
		let store = MemoryShellStore()
		store.enumFailed = (ctx["enumFailed"] as? Bool) == true
		// The seeded copy belongs to the pointer's account, else the known account, else the account named by its own profile (keyID), else the default.
		if let seeded = c["store"] as? [String: Any], let record = seeded["record"] as? [String: Any] {
			store.records[pointerAcct ?? (ctx["eoa"] as? String) ?? Self.profileKeyID(record) ?? PgpMigrationTestSupport.eoa] = record
		}
		// The account of the command: the creation mode has none (the pending account has no key yet); the pointer names the account; else the known
		// account; else the one key; else, with no key at all, the account of the page copy that holds an EOA private key (item 1).
		let account: String?
		if creationMode && explicitChoice {
			account = nil
		} else if let pointerAcct {
			account = pointerAcct
		} else if let known = ctx["eoa"] as? String, !acctUnknown {
			account = known
		} else if keys.count == 1 {
			account = keys[0]
		} else if keys.isEmpty {
			account = BeamioShellRecord.accountOfCopyWithKey(store: store)
		} else {
			account = nil
		}
		let keyState: BeamioShellRecord.KeyState
		if let pointerAcct {
			keyState = keys.contains(pointerAcct) ? .normal : .pointerKeyMissing
		} else if keys.count > 1 {
			keyState = .ambiguous
		} else {
			keyState = .normal
		}
		eoa = account ?? pointerAcct ?? PgpMigrationTestSupport.eoa
		let device = MemoryDevice()
		if (ctx["marker"] as? Bool) == true && !lateKeys { device.state.legacyUnreadable = true }
		if (ctx["pointer"] as? Bool) == true || pointerAcct != nil { device.state.accountEstablished = true }
		// The account pointer (PY.18 b) is the native pointer, not only the device flag: the case's pointer names its account.
		BeamioNativeAccountPointer.clear()
		if (ctx["pointer"] as? Bool) == true || pointerAcct != nil {
			// A case with no named pointer account and a second account (AK-43): the pointer names another account, not the case's own.
			let otherAccount = eoa == PgpMigrationTestSupport.eoa ? "0x0000000000000000000000000000000000000001" : PgpMigrationTestSupport.eoa
			BeamioNativeAccountPointer.set(pointerAcct ?? (creationTxn ? otherAccount : eoa))
		}
		if !lateKeys { writeKeys() }
		var first = BeamioShellRecord.FirstRunState.notRun
		switch ctx["legacy"] as? String {
		case "absent", "empty":
			BeamioShellRecord.reportLegacyStore(.absent, device: device, store: account == nil ? store : nil, creation: creationMode)
		case "unreadable":
			BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: account == nil ? store : nil, creation: creationMode)
		case "found":
			BeamioShellRecord.reportLegacyStore(.found, device: device, creation: creationMode)
		default:
			break
		}
		if (ctx["marker"] as? Bool) == true && lateKeys { device.state.legacyUnreadable = true }
		if lateKeys { writeKeys() }
		var env = BeamioShellRecord.Environment(
			account: { account },
			store: store,
			device: device,
			originAllowed: (ctx["origin"] as? String) == "allowed",
			migrating: { _ in false },
			firstRun: { _ in first },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved,
			creationTransaction: { _ in creationTxn && explicitChoice },
			keyState: { keyState },
			creationMode: { creationMode && explicitChoice }
		)
		// ctx.locked of the AK vectors is the DEVICE-LEVEL STORAGE lock (the project lead ruling), not the passcode lock: it maps to storageLocked.
		// The passcode lock (a record whose bundle is not provided) is the `locked` closure and has its own vectors (SRP).
		env.storageLocked = { (ctx["locked"] as? Bool) == true }
		let body: [String: Any]
		if (c["kind"] as? String) == "write" {
			body = request(c, kind: "write", ctx: ctx)
		} else {
			// a case that states its own request body (the shape vectors, UF-01) is sent as it is; the AK reads have none
			body = (c["req"] as? [String: Any]) ?? ["type": "shellRecordRead", "reqId": c["reqId"] as? String ?? "?"]
		}
		// The size the shell reports for the request (interface Y.52, the same principle as Android): the case's sizeBytes or responseBytes context,
		// when the case states one; the re-serialized body is the fallback only.
		let stated = (ctx["sizeBytes"] as? Int) ?? (ctx["responseBytes"] as? Int)
		return BeamioShellRecord.ackEnvelope(for: BeamioShellRecord.answer(body, env: env, rawByteCount: stated))
	}

	/// One ack case checked against its expectation. The answer comes from `answerAckCase`, the account model of the case.
	private func runAckCase(_ c: [String: Any], nativeKey: Bool) {
		let id = c["id"] as? String ?? "?"
		// one line per case with its own verdict, so that a case is confirmed as passed by what it printed, not by the absence of a failure
		let failuresBefore = testRun?.failureCount ?? 0
		defer { print("[AK-CASE] \(id) \((testRun?.failureCount ?? 0) == failuresBefore ? "PASS" : "FAIL")") }
		let ack = answerAckCase(c, nativeKey: nativeKey)
		let expect = c["expect"] as? [String: Any] ?? [:]
		XCTAssertEqual(ack["type"] as? String, "ack", "\(id): type")
		XCTAssertEqual(ack["ok"] as? Bool, expect["ok"] as? Bool, "\(id): ok")
		if expect["reqId"] is NSNull {
			XCTAssertTrue(ack["reqId"] is NSNull, "\(id): reqId is null")
		} else {
			XCTAssertEqual(ack["reqId"] as? String, expect["reqId"] as? String, "\(id): reqId")
		}
		if let error = expect["error"] as? String {
			XCTAssertEqual(ack["error"] as? String, error, "\(id): error")
		}
		if let want = expect["result"] as? [String: Any] {
			let got = ack["result"] as? [String: Any] ?? [:]
			for (key, value) in want {
				if key == "names" {
					XCTAssertEqual(Set(got["names"] as? [String] ?? []), Set(value as? [String] ?? []), "\(id): names")
				} else {
					XCTAssertEqual(canonical(got[key]), canonical(value), "\(id): \(key)")
				}
			}
		}
	}

	/// The keyID of the first profile of a record (the account a page copy names), for a seeded copy without a pointer or a known account.
	static func profileKeyID(_ record: [String: Any]) -> String? {
		(record["profiles"] as? [Any])?.compactMap { ($0 as? [String: Any])?["keyID"] as? String }.first
	}

	/// shell-record-shape-and-kr04-write-vectors.v1.json (UF-01 to UF-06, KW-01 to KW-03), set SHELL_RECORD_SHAPE_VECTORS=<path>.: UF-01 and UF-02 are content level
	/// (the file's `altExpect`; the interface owner updates `expect` to the same, the updated file prevails). UF-05 is the dispatch layer: unknown_command, before the gate.
	/// Prints `[SHAPE-CASE] <id> PASS|FAIL`; KW cases also check that no page copy was written.
	func testTheShellRecordShapeAndKr04WriteVectors() throws {
		guard let path = ProcessInfo.processInfo.environment["SHELL_RECORD_SHAPE_VECTORS"] else {
			throw XCTSkip("set SHELL_RECORD_SHAPE_VECTORS to interface/protocol/shell-record-shape-and-kr04-write-vectors.v1.json")
		}
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 9)
		for var c in cases {
			let id = c["id"] as? String ?? "?"
			let failuresBefore = testRun?.failureCount ?? 0
			defer { print("[SHAPE-CASE] \(id) \((testRun?.failureCount ?? 0) == failuresBefore ? "PASS" : "FAIL")") }
			if let alt = c["altExpect"] as? [String: Any] { c["expect"] = alt }
			if id == "UF-05" {
				var events: [[String: Any]] = []
				BeamioConetChatModule.handleCommand(["type": "shellRecordFoo", "reqId": 5], emit: { events.append($0) })
				let deadline = Date().addingTimeInterval(3)
				while !events.contains(where: { (($0["event"] as? [String: Any]) ?? $0)["type"] as? String == "ack" }) && Date() < deadline {
					RunLoop.current.run(until: Date().addingTimeInterval(0.05))
				}
				let acks = events.map { ($0["event"] as? [String: Any]) ?? $0 }.filter { $0["type"] as? String == "ack" }
				XCTAssertEqual(acks.count, 1, "UF-05: one answer")
				XCTAssertEqual(acks.first?["ok"] as? Bool, false)
				XCTAssertEqual(acks.first?["error"] as? String, "unknown_command")
				continue
			}
			if c["reqId"] is String == false { c["reqId"] = "?" }
			runAckCase(c, nativeKey: false)
		}
	}

	/// AK-32: the steps of a case are given in full. Each step has its own ctx and store, and its legacy state is the
	/// one it names. Nothing carries over from the previous step. Only the result object of a step is compared, not the `ok` envelope.
	func testTheAckStepCasesMatchTheVectors() throws {
		let root = try vectorRoot()
		guard let cases = root["ackStepCases"] as? [[String: Any]] else {
			throw XCTSkip("ackStepCases is not in the vectors")
		}
		XCTAssertEqual(cases.count, 2, "AK-32 and CL-02 are the step cases")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			for (index, step) in (c["steps"] as? [[String: Any]] ?? []).enumerated() {
				// Each step is answered as its own case of the account model (item 8): its own ctx and store, a fresh native key store.
				var stepCase: [String: Any] = [
					"id": "\(id)-\(index + 1)",
					"ctx": step["ctx"] as? [String: Any] ?? [:],
					"kind": "read",
					"reqId": "\(id)-\(index + 1)",
				]
				if let seeded = step["store"] { stepCase["store"] = seeded }
				let ack = answerAckCase(stepCase, nativeKey: false)
				let got = ack["result"] as? [String: Any] ?? [:]
				let expect = step["expect"] as? [String: Any] ?? [:]
				XCTAssertEqual(canonical(got), canonical(expect), "\(id) step \(index + 1): the result object")
			}
		}
	}

	func testAFieldOutsideTheFixedCommandSetIsABadRequest() {
		let store = MemoryShellStore()
		let body: [String: Any] = ["type": "shellRecordRead", "reqId": "r2", "accountKey": "x"]
		let answer = BeamioShellRecord.answer(body, env: environment(account: eoa, store: store))
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["accountKey"], "only the field name, never the value")
	}
}
