import XCTest
@testable import ConetChatSDK

/// The W-class value rules (spec,). An object or an array on a W path (`profiles[*].privateKeyArmor` with keyID = account,
/// top-level `mnemonicPhrase`, top-level `recoveryWords`) is refused with `bad_request` naming the path; nothing is echoed or stored and the old
/// record is kept. A wrapper under `privateKeyArmorWrap` is `key_shaped_content`, and key shape is judged before the W type (items 2 and 3).
/// Strings, numbers, booleans and null follow the W merge rules (item 5). Synthetic data only.
final class ShellRecordWalletTypeTests: XCTestCase {
	/// A device whose last reader report was an absence: the confirmed absence is device-level now.
	private func absentDevice() -> Device {
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		return device
	}
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	/// A device with no native key (these are shell writes): the memory store, not the simulator's unreadable Keychain.
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

	/// The account is the address of the sidecar account key, so that `armorA` derives it.
	private let account = PgpMigrationTestSupport.eoa

	/// A device-key wrapper as the 0.53.x page wrote it, in one key order (`{ct, eoa, iv, kdf, mode, salt, v}`). Every value is synthetic.
	private var wrapper: [String: Any] {
		["ct": "c3ludGhldGlj", "eoa": account, "iv": "aXY=", "kdf": "scrypt", "mode": "aes-256-gcm", "salt": "c2FsdA==", "v": 1]
	}

	/// The same wrapper with the keys in the other order of the spec (`{v, mode, eoa, kdf, salt, iv, ct}`). The key order does not count.
	private var wrapperOtherOrder: [String: Any] {
		["v": 1, "mode": "aes-256-gcm", "eoa": account, "kdf": "scrypt", "salt": "c2FsdA==", "iv": "aXY=", "ct": "c3ludGhldGlj"]
	}

	private func environment(_ store: Store) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: absentDevice(),
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	private func write(_ record: [String: Any], store: Store) -> [String: Any] {
		BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": "wt-1", "record": record], env: environment(store))
	}

	private func profile(_ extra: [String: Any] = [:]) -> [String: Any] {
		var p: [String: Any] = ["keyID": account, "privateKeyArmor": PgpMigrationTestSupport.armorA]
		for (k, v) in extra { p[k] = v }
		return p
	}

	/// A wrapper in the top-level `mnemonicPhrase` is refused, and the store stays empty.
	func testAWrapperMnemonicPhraseIsRefused() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": wrapper, "profiles": [profile()]], store: store)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["mnemonicPhrase"])
		XCTAssertTrue(store.records.isEmpty)
	}

	/// A list in the top-level `recoveryWords` is refused.
	func testANonStringRecoveryWordsIsRefused() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "recoveryWords": ["one", "two"], "profiles": [profile()]], store: store)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["recoveryWords"])
		XCTAssertTrue(store.records.isEmpty)
	}

	/// A wrapper in a profile's `privateKeyArmor` is refused, and the path is named once.
	func testANonStringProfilePrivateKeyArmorIsRefused() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": wrapper])]], store: store)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertTrue(store.records.isEmpty)
	}

	/// Control: string W values are stored, with rev 1.
	func testStringWalletValuesAreStored() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": "synthetic phrase", "profiles": [profile()]], store: store)
		XCTAssertEqual(answer["code"] as? String, "ok")
		XCTAssertEqual(answer["rev"] as? Int, 1)
		XCTAssertEqual(store.records[account]?["mnemonicPhrase"] as? String, "synthetic phrase")
	}

	/// The other key order of the wrapper is refused on each W path, and each path is named.
	func testTheOtherWrapperOrderIsRefusedOnEveryWalletPath() {
		for (path, record) in [
			("mnemonicPhrase", ["rev": 0, "schemaVersion": 2, "mnemonicPhrase": wrapperOtherOrder, "profiles": [profile()]] as [String: Any]),
			("recoveryWords", ["rev": 0, "schemaVersion": 2, "recoveryWords": wrapperOtherOrder, "profiles": [profile()]] as [String: Any]),
			("profiles[*].privateKeyArmor", ["rev": 0, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": wrapperOtherOrder])]] as [String: Any]),
		] {
			let store = Store()
			let answer = write(record, store: store)
			XCTAssertEqual(answer["code"] as? String, "bad_request", path)
			XCTAssertEqual(answer["names"] as? [String], [path], path)
			XCTAssertTrue(store.records.isEmpty, path)
		}
	}

	/// Arrays on the W paths are refused, and each path is named.
	func testArraysOnWalletPathsAreRefused() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": ["a", "b"], "profiles": [profile(["privateKeyArmor": ["x"]])]], store: store)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["mnemonicPhrase", "profiles[*].privateKeyArmor"])
		XCTAssertTrue(store.records.isEmpty)
	}

	/// A refused wrapper leaves the stored record as it was: same rev, same string values.
	func testAStoredRecordIsKeptWhenAWrapperIsRefused() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": "synthetic phrase", "profiles": [profile()]], store: store)["code"] as? String, "ok")
		let answer = write(["rev": 1, "schemaVersion": 2, "mnemonicPhrase": wrapper, "profiles": [profile()]], store: store)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
		XCTAssertEqual(store.records[account]?["mnemonicPhrase"] as? String, "synthetic phrase")
	}

	/// A wrapper under `privateKeyArmorWrap` is key-shaped content, both in a profile and at the top level.
	func testAWrapperUnderPrivateKeyArmorWrapIsKeyShaped() {
		let profileStore = Store()
		let inProfile = write(["rev": 0, "schemaVersion": 2, "profiles": [profile(["privateKeyArmorWrap": wrapper])]], store: profileStore)
		XCTAssertEqual(inProfile["code"] as? String, "key_shaped_content")
		XCTAssertEqual(inProfile["names"] as? [String], ["profiles[*].privateKeyArmorWrap"])
		XCTAssertTrue(profileStore.records.isEmpty)

		let topStore = Store()
		let topLevel = write(["rev": 0, "schemaVersion": 2, "privateKeyArmorWrap": wrapperOtherOrder, "profiles": [profile()]], store: topStore)
		XCTAssertEqual(topLevel["code"] as? String, "key_shaped_content")
		XCTAssertEqual(topLevel["names"] as? [String], ["privateKeyArmorWrap"])
		XCTAssertTrue(topStore.records.isEmpty)
	}

	/// Key shape is judged before the W type: a record with a key-shaped wrapper and a W wrapper answers `key_shaped_content`.
	func testKeyShapeIsJudgedBeforeTheWalletType() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": wrapper, "profiles": [profile(["privateKeyArmorWrap": wrapperOtherOrder])]], store: store)
		XCTAssertEqual(answer["code"] as? String, "key_shaped_content")
		XCTAssertTrue(store.records.isEmpty)
	}

	/// Scalars follow the W merge rules: a number, a boolean or null is stored on a fresh write (ok), not refused.
	func testScalarsFollowTheMergeRules() {
		for value: Any in [12345, true, NSNull()] {
			let store = Store()
			let answer = write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": value, "profiles": [profile()]], store: store)
			XCTAssertEqual(answer["code"] as? String, "ok", "\(value)")
			XCTAssertEqual(answer["rev"] as? Int, 1)
		}
	}

	/// A scalar that differs from the stored value is a merge conflict (the W merge rule), not a bad request.
	func testADifferentScalarIsAMergeConflict() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "mnemonicPhrase": "synthetic phrase", "profiles": [profile()]], store: store)["code"] as? String, "ok")
		let answer = write(["rev": 1, "schemaVersion": 2, "mnemonicPhrase": 12345, "profiles": [profile()]], store: store)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
	}

	/// WM-09: on a first write, a profile whose keyID is not the account carries privateKeyArmor while another profile matches. The
	/// whole record is refused as a conflict with reason w_account_unmatched, and nothing is stored.
	func testAForeignKeyOnAFirstWriteIsAConflictAsAWhole() {
		let store = Store()
		let answer = write(
			["rev": 0, "schemaVersion": 2, "profiles": [["keyID": account, "emailAddr": "a"], ["keyID": "0xother", "privateKeyArmor": "OTHER"]], "mnemonicPhrase": "M"],
			store: store
		)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(answer["reason"] as? String, "w_account_unmatched")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertTrue(store.records.isEmpty)
	}

	/// The PGP header is found in its normalized form (N): case, width, a combining mark, a zero-width character and separators do not hide it.
	/// The check is the same one for read, import and write, and it refuses the write before anything is stored.
	func testThePGPHeaderIsFoundInItsNormalizedForm() {
		let forms = [
			"begin pgp private key",
			"BEGIN\u{00A0}PGP PRIVATE KEY",
			"ＢＥＧＩＮ　ＰＧＰ　ＰＲＩＶＡＴＥ　ＫＥＹ",
			"BEGIN PGP PRIVATE\u{0301} KEY",
			"BEGIN\u{200B} PGP PRIVATE KEY",
			"BEGIN-PGP-PRIVATE-KEY",
		]
		for (index, form) in forms.enumerated() {
			XCTAssertTrue(BeamioShellRecord.containsPGPHeader(form), "form \(index)")
			let store = Store()
			let answer = write(["rev": 0, "schemaVersion": 2, "profiles": [profile()], "note": form], store: store)
			XCTAssertEqual(answer["code"] as? String, "pgp_private_in_payload", "form \(index)")
			XCTAssertTrue(store.records.isEmpty, "form \(index)")
		}
		XCTAssertFalse(BeamioShellRecord.containsPGPHeader("BEGIN PGP PUBLIC KEY BLOCK"), "a public block is not a private header")
	}

	/// The sidecar keys: the account key derives the account, and the other key derives another address.
	func testTheSidecarKeysDeriveTheirAddresses() {
		XCTAssertEqual(BeamioShellRecord.productionAddress(PgpMigrationTestSupport.armorA)?.lowercased(), PgpMigrationTestSupport.eoa)
		XCTAssertNotEqual(BeamioShellRecord.productionAddress(PgpMigrationTestSupport.armorOther)?.lowercased(), PgpMigrationTestSupport.eoa)
	}

	/// The derivation check (Q1,): a page write whose key does not derive the account is refused, and nothing is stored.
	func testAPageKeyThatDoesNotDeriveTheAccountIsRefused() {
		let store = Store()
		let answer = write(["rev": 0, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": PgpMigrationTestSupport.armorOther])]], store: store)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertTrue(store.records.isEmpty)
	}

	/// The canonical form is required on write (Q1): an armor without `0x`, or in upper case, is refused even when it derives the account.
	func testANonCanonicalKeyIsRefusedOnWrite() {
		let bare = String(PgpMigrationTestSupport.armorA.dropFirst(2))
		let forms = [bare, "0X" + bare, PgpMigrationTestSupport.armorA.uppercased()]
		for (index, armor) in forms.enumerated() {
			let store = Store()
			let answer = write(["rev": 0, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": armor])]], store: store)
			XCTAssertEqual(answer["code"] as? String, "bad_request", "non-canonical form \(index)")
			XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"], "non-canonical form \(index)")
			XCTAssertTrue(store.records.isEmpty, "non-canonical form \(index)")
		}
	}

	/// A native replacement is held to the same check. A key that does not derive the account is refused; the stored copy keeps its rev and key.
	func testANativeReplacementMustDeriveTheAccount() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "profiles": [profile()], "mnemonicPhrase": "M"], store: store)["code"] as? String, "ok")
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "wt-n", "record": ["rev": 1, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": PgpMigrationTestSupport.armorOther])], "mnemonicPhrase": "M"]],
			env: environment(store),
			nativeWrite: true
		)
		XCTAssertEqual(answer["code"] as? String, "bad_request")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
		XCTAssertEqual(((store.records[account]?["profiles"] as? [[String: Any]])?.first)?["privateKeyArmor"] as? String, PgpMigrationTestSupport.armorA)
	}

	/// Order (step 8 before step 9): a W-merge conflict is judged before the derivation check. A page write with a different key that does not
	/// derive the account is a `w_differs` conflict (WM-02), and the store keeps its value.
	func testAMergeConflictIsJudgedBeforeTheDerivationCheck() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "profiles": [profile()], "mnemonicPhrase": "M"], store: store)["code"] as? String, "ok")
		let answer = write(["rev": 1, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": PgpMigrationTestSupport.armorOther])], "mnemonicPhrase": "M"], store: store)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(answer["reason"] as? String, "w_differs")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
	}

	/// Order (step 7 before step 8): a stale rev with a key that does not derive the account is a plain rev conflict, with no reason.
	func testARevConflictIsJudgedBeforeTheDerivationCheck() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "profiles": [profile()], "mnemonicPhrase": "M"], store: store)["code"] as? String, "ok")
		let answer = write(["rev": 0, "schemaVersion": 2, "profiles": [profile(["privateKeyArmor": PgpMigrationTestSupport.armorOther])]], store: store)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertNil(answer["reason"])
		XCTAssertEqual(answer["currentRev"] as? Int, 1)
	}

	/// Order (step 7 before step 8), reviewer c of a652dee: a stale rev with a request profile under another keyID that carries a
	/// privateKeyArmor is a plain rev conflict (no reason). Nothing is written and the stored record keeps its rev and its key.
	func testAStaleRevWithAForeignKeyIsAPlainRevConflict() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "profiles": [profile()], "mnemonicPhrase": "M"], store: store)["code"] as? String, "ok")
		let answer = write(["rev": 0, "schemaVersion": 2, "profiles": [["keyID": "zz", "privateKeyArmor": "EOA"]]], store: store)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(answer["currentRev"] as? Int, 1)
		XCTAssertNil(answer["reason"], "a rev conflict carries no reason")
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
		XCTAssertEqual(((store.records[account]?["profiles"] as? [[String: Any]])?.first)?["privateKeyArmor"] as? String, PgpMigrationTestSupport.armorA)
	}

	/// The first-run import normalizes a legacy key before the write checks: a bare 64-hex key becomes `0x` and lower case, and the
	/// import succeeds. The key does not change.
	func testALegacyBareKeyIsNormalizedOnFirstRunImport() {
		let bare = String(PgpMigrationTestSupport.armorA.dropFirst(2))
		let store = Store()
		var seen: [String] = []
		let code = importLegacy(armor: bare, store: store) { armor in
			seen.append(armor)
			return PgpMigrationTestSupport.eoa
		}
		XCTAssertEqual(code, .importOk)
		XCTAssertEqual(seen, [PgpMigrationTestSupport.armorA], "the address check sees the normalized key")
		XCTAssertEqual(((store.records[account]?["profiles"] as? [[String: Any]])?.first)?["privateKeyArmor"] as? String, PgpMigrationTestSupport.armorA)
	}

	/// An upper-case `0X` key with upper-case hex is normalized the same way.
	func testALegacyUpperCaseKeyIsNormalizedOnFirstRunImport() {
		let upper = "0X" + String(PgpMigrationTestSupport.armorA.dropFirst(2)).uppercased()
		let store = Store()
		XCTAssertEqual(importLegacy(armor: upper, store: store) { _ in PgpMigrationTestSupport.eoa }, .importOk)
		XCTAssertEqual(((store.records[account]?["profiles"] as? [[String: Any]])?.first)?["privateKeyArmor"] as? String, PgpMigrationTestSupport.armorA)
	}

	/// A legacy key that cannot be normalized is import_failed, and the store is not written.
	func testALegacyKeyThatCannotBeNormalizedIsImportFailed() {
		let store = Store()
		XCTAssertEqual(importLegacy(armor: "not-a-key", store: store) { _ in PgpMigrationTestSupport.eoa }, .importFailed)
		XCTAssertTrue(store.records.isEmpty)
	}

	/// A normalized key that does not derive the account is address_mismatch, and nothing is written.
	func testANormalizedLegacyKeyThatDoesNotDeriveTheAccountIsAddressMismatch() {
		let bare = String(PgpMigrationTestSupport.armorOther.dropFirst(2))
		let store = Store()
		XCTAssertEqual(importLegacy(armor: bare, store: store) { _ in "0x1111111111111111111111111111111111111111" }, .addressMismatch)
		XCTAssertTrue(store.records.isEmpty)
	}

	/// The legacy record of one profile under the account, with the key given, through the first-run import.
	private func importLegacy(armor: String, store: Store, derive: (String) -> String?) -> BeamioShellRecord.FirstRunImportCode {
		let json: [String: Any] = ["profiles": [["keyID": account, "emailAddr": "a", "privateKeyArmor": armor]], "mnemonicPhrase": "M"]
		let data = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
		return BeamioShellRecord.importFirstRun(
			eoa: account,
			legacy: .found(BeamioShellRecord.LegacyWalletRecord(bytes: [UInt8](data))),
			store: store,
			device: Device(),
			addressOf: derive,
			setState: { _, _ in }
		)
	}

	/// WM-08: a foreign key on a write over a stored record is a conflict, and the stored record keeps its rev and its key.
	func testAForeignKeyOverAStoredRecordKeepsTheRecord() {
		let store = Store()
		XCTAssertEqual(write(["rev": 0, "schemaVersion": 2, "profiles": [profile()], "mnemonicPhrase": "M"], store: store)["code"] as? String, "ok")
		let answer = write(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": "zz", "privateKeyArmor": "EOA"]]], store: store)
		XCTAssertEqual(answer["code"] as? String, "conflict")
		XCTAssertEqual(answer["reason"] as? String, "w_account_unmatched")
		XCTAssertEqual(answer["names"] as? [String], ["profiles[*].privateKeyArmor"])
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
		XCTAssertEqual(((store.records[account]?["profiles"] as? [[String: Any]])?.first)?["privateKeyArmor"] as? String, PgpMigrationTestSupport.armorA)
	}
}
