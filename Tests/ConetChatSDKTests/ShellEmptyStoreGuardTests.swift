import XCTest
@testable import ConetChatSDK

/// B-1: the shell-record empty-store answer. `absent` opens the write gate, so it is answered only when this device
/// holds no native wallet record for the account. With a native record present, an empty shell record is `error` (`account_record_missing`), and the
/// write gate stays closed. Synthetic values only.
final class ShellEmptyStoreGuardTests: XCTestCase {
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

		func hasAnyRecord() -> Bool { !records.isEmpty }
	}

	/// An in-memory key storage for the encrypted store.
	private final class KeysStore: BeamioShellRecord.KeyStorage {
		var keys: [String: Data] = [:]

		func readKey(account: String) -> BeamioShellRecord.KeyRead {
			keys[account].map { .found($0) } ?? .notFound
		}

		func writeKey(account: String, _ key: Data) -> Bool {
			keys[account] = key
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var keyStore = MemoryNativeKeyStore()
	private var device = Device()

	override func setUp() {
		NativeAccountPointerIsolation.begin()
		super.setUp()
		savedKeyStore = BeamioNativeWallet.keyStore
		keyStore = MemoryNativeKeyStore()
		device = Device()
		BeamioNativeWallet.keyStore = keyStore
		// The first-run state is process state: each test starts with none for the account.
		BeamioShellRecord.setFirstRunState(account, .notRun)
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioShellRecord.setFirstRunState(account, .notRun)
		BeamioNativeWallet.keyStore = savedKeyStore
		super.tearDown()
	}

	private func environment(accountPointer: Bool = true, firstRun: BeamioShellRecord.FirstRunState = .notRun) -> BeamioShellRecord.Environment {
		let pointer = accountPointer ? account : nil
		return BeamioShellRecord.Environment(
			account: { pointer },
			store: Store(),
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in firstRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	private func read(_ env: BeamioShellRecord.Environment) -> [String: Any] {
		BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "b1"], env: env)
	}

	/// The fixture key is not the account's key (it does not derive), so the key record is unreadable: the normal read answers needs_native_recovery.
	private func assertNeedsNativeRecovery(_ answer: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertEqual(answer["sub"] as? String, "needs_native_recovery", file: file, line: line)
	}

	/// A second synthetic phrase (BIP-39 entropy ff…ff) and the EOA the product derives from it: the record of another account.
	private let otherPhrase = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

	private func otherAccountEoa() -> String? {
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: otherPhrase) else { return nil }
		return BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
	}

	private func putNativeRecord() {
		_ = keyStore.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
	}

	/// The B-1 case: the shell reported the legacy store confirmed absent, the native record exists, and the account is not established. Before the
	/// guard this answered `absent`, which opens the write gate. Now it is an error.
	func testAnAbsentAnswerIsNotGivenWhileANativeRecordExists() {
		device.state.legacyConfirmedAbsent = true
		putNativeRecord()
		let answer = read(environment())
		// item 2 (B): this account's own key without its copy is migrating, never absent.
		// 57 项（§25.52U.6 第 1 行，指针已设而记录缺失）：shellRecordRead 答 error / account_record_missing（r2.5.11）。
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_record_missing")
		XCTAssertNotEqual(answer["code"] as? String, "absent")
	}

	/// Unchanged: no native record and the legacy store confirmed empty is `absent`, the first-install answer.
	func testAbsentIsAnsweredWhenThereIsNoNativeRecord() {
		device.state.legacyConfirmedAbsent = true
		let answer = read(environment())
		XCTAssertEqual(answer["code"] as? String, "absent")
	}

	/// Unchanged: a native record with the legacy store not read yet is `migrating`, not an error and not `absent`.
	/// migrating applies only when the account pointer is empty (第 57 项，r2.5.11): the input is changed to a pointer-empty environment.
	func testMigratingStaysMigratingWhileANativeRecordExists() {
		putNativeRecord()
		let answer = read(environment(accountPointer: false, firstRun: .notRun))
		XCTAssertEqual(answer["code"] as? String, "migrating")
	}

	/// Unchanged: an established account is `account_record_missing` whatever the native record says.
	func testAnEstablishedAccountIsAccountRecordMissing() {
		device.state.accountEstablished = true
		putNativeRecord()
		let answer = read(environment())
		// item 6(b) and B: the pointer's account has its own key but no copy: account_record_missing (the comment above).
		// 57 项（§25.52U.6 第 1 行，指针已设而记录缺失）：shellRecordRead 答 error / account_record_missing（r2.5.11）。
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_record_missing")
	}

	/// Unchanged: without an account pointer no native record can be looked up for the account, so the answer is judged as before.
	func testWithoutAnAccountPointerTheAnswerIsAsBefore() {
		device.state.legacyConfirmedAbsent = true
		let answer = read(environment(accountPointer: false))
		XCTAssertEqual(answer["code"] as? String, "absent")
	}

	/// R-1, as (ERRATUM, keystore-replica v2 KR-08, §25.52U.6 row 6): no account pointer, the legacy store confirmed empty, a valid native account that reads: the read answers `absent`
	/// (`account_record_missing` is for a pointer that is set). The creation read, not this one, keeps a second account from being made: it answers migrating.
	func testANativeRecordForAnotherAccountIsAbsentOnTheReadWithoutAPointer() {
		device.state.legacyConfirmedAbsent = true
		guard let otherEoa = otherAccountEoa() else { return XCTFail("the second synthetic phrase must derive") }
		_ = keyStore.writeItem(.mnemonic, eoa: otherEoa, value: Data(otherPhrase.utf8))
		let answer = read(environment(accountPointer: false))
		XCTAssertEqual(answer["code"] as? String, "absent")
	}

	/// R-2: a confirmed absence is cleared once a native record is found. The cleared flag cannot answer absent later either.
	func testAStaleConfirmedAbsenceIsClearedWhenANativeRecordIsFound() {
		device.state.legacyConfirmedAbsent = true
		putNativeRecord()
		// The stale absence is cleared (R-2). With the pointer set and the shell record missing: account_record_missing (57 项, r2.5.11).
		let answer = read(environment())
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_record_missing")
		XCTAssertFalse(device.state.legacyConfirmedAbsent, "the stale confirmed absence is cleared")
		// The record goes away: the cleared flag does not bring absent back. The answer is migrating, as for a device with no confirmed absence.
		keyStore.keys = [:]
		keyStore.mnemonic = TestMnemonicItems()
		XCTAssertEqual(read(environment())["code"] as? String, "migrating")
	}

	/// The low item: an import that finds no legacy record does not report the absence while a native record exists.
	func testTheImportDoesNotReportAnAbsenceWhileANativeRecordExists() {
		putNativeRecord()
		var states: [BeamioShellRecord.FirstRunState] = []
		let code = BeamioShellRecord.importFirstRun(
			eoa: account, legacy: .absent, store: Store(), device: device,
			addressOf: { _ in nil }, setState: { _, state in states.append(state) }
		)
		XCTAssertEqual(code, .exists)
		XCTAssertTrue(states.isEmpty, "no first-run state is set")
		XCTAssertFalse(device.state.legacyConfirmedAbsent, "no absence is reported")
	}

	/// Unchanged: with no native record, a confirmed absence of the legacy store is reported and sets the state.
	func testTheImportReportsAnAbsenceWhenNoNativeRecordExists() {
		var states: [BeamioShellRecord.FirstRunState] = []
		let code = BeamioShellRecord.importFirstRun(
			eoa: account, legacy: .absent, store: Store(), device: device,
			addressOf: { _ in nil }, setState: { _, state in states.append(state) }
		)
		XCTAssertEqual(code, .absent)
		// The absence is device-level now: no per-account state is set, the device state is.
		XCTAssertTrue(states.isEmpty)
		XCTAssertTrue(device.state.legacyConfirmedAbsent)
	}

	/// Review 5018e1f (blocker): the first-run state of this process says confirmed absent (an earlier import, no native key), then a native key
	/// appears and the shell record is missing. A page write must stay closed, and nothing is written.
	func testAPageWriteStaysClosedWhileANativeRecordExistsWhateverTheFirstRunState() {
		device.state.legacyConfirmedAbsent = true
		putNativeRecord()
		let store = Store()
		let env = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .notRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w1", "record": ["rev": 0, "schemaVersion": 1]], env: env
		)
		XCTAssertEqual(answer["code"] as? String, "migrating")
		XCTAssertNil(store.records[account], "nothing is written while the native record exists")
	}

	/// The same first-run state without a native record: the write gate opens as before (the answer is not migrating).
	func testAPageWriteIsUnchangedWithoutANativeRecord() {
		device.state.legacyConfirmedAbsent = true
		let store = Store()
		let env = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .notRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w2", "record": ["rev": 0, "schemaVersion": 1]], env: env
		)
		XCTAssertNotEqual(answer["code"] as? String, "migrating")
	}

	/// R-2 on the process state: an empty read clears a confirmed first-run absence once a native record is found.
	func testTheFirstRunAbsenceIsClearedWhenANativeRecordIsFound() {
		// R-2: an empty read clears a confirmed absence once a native record is found.
		device.state.legacyConfirmedAbsent = true
		putNativeRecord()
		_ = read(environment(firstRun: .notRun))
		XCTAssertFalse(device.state.legacyConfirmedAbsent)
	}

	/// PY.15 4 (project ruling): an absence while a native key record exists is saved and answers ok. The read still does not answer absent (R-2).
	func testAnAbsenceIsSavedWhileANativeRecordExistsAndAnswersOk() {
		putNativeRecord()
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.absent, device: device), .ok)
		XCTAssertTrue(device.state.legacyConfirmedAbsent, "saved as the recent report")
	}

	/// The environment with no account pointer and the store given.
	private func pointerEmptyEnvironment(store: BeamioShellRecord.ShellRecordStore, firstRun: BeamioShellRecord.FirstRunState = .notRun) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { nil },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in firstRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	/// The pointer-empty path: no account is known, the shell store holds a record of another account, and the
	/// legacy store is confirmed empty. The answer is a fail-closed error, never absent. The subcode is the interface reading, pending the ruling.
	func testWithoutAnAccountAShellRecordOfAnotherAccountIsNotAbsent() {
		device.state.legacyConfirmedAbsent = true
		let store = Store()
		store.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		let answer = read(pointerEmptyEnvironment(store: store))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_mismatch")
		XCTAssertNotEqual(answer["code"] as? String, "absent")
	}

	/// item 4: the account is known and its own record is absent. Another account's record on the device does not change that: the
	/// answer is absent. The native key is judged by item 2, not by another account's page copy.
	func testAKnownAccountIsAbsentWhileAnotherAccountsShellRecordExists() {
		device.state.legacyConfirmedAbsent = true
		let store = Store()
		store.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		let env = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .notRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		let answer = read(env)
		XCTAssertEqual(answer["code"] as? String, "absent")
	}

	/// AK-35: the pointer is set, the legacy store is confirmed absent, and the shell store holds a record of another account. The answer
	/// is account_mismatch, not account_record_missing.
	func testAPointerWithAnotherAccountsRecordIsAccountMismatch() {
		device.state.accountEstablished = true
		device.state.legacyConfirmedAbsent = true
		let store = Store()
		store.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		let answer = read(pointerEmptyEnvironment(store: store))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_mismatch")
	}

	/// AK-08: the pointer is set and there is no record at all: the answer stays account_record_missing.
	func testAPointerWithNoRecordIsStillAccountRecordMissing() {
		device.state.accountEstablished = true
		device.state.legacyConfirmedAbsent = true
		let answer = read(pointerEmptyEnvironment(store: Store()))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_record_missing")
	}

	/// AK-09: no account is known, the pointer is empty, and the legacy store was read and holds a record that is not imported.
	/// The answer is import_not_done, not migrating. The finding is device-level: it does not depend on an account.
	func testAFoundLegacyRecordIsImportNotDoneWithoutAnAccount() {
		BeamioShellRecord.reportLegacyStore(.found, device: device)
		XCTAssertTrue(device.state.legacyFound)
		let answer = read(pointerEmptyEnvironment(store: Store()))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "import_not_done")
	}

	/// A later absence report replaces the found finding (the state is the latest report): the answer is absent again.
	func testAnAbsenceReportClearsAFoundLegacyRecord() {
		BeamioShellRecord.reportLegacyStore(.found, device: device)
		BeamioShellRecord.reportLegacyStore(.absent, device: device)
		XCTAssertFalse(device.state.legacyFound)
		XCTAssertEqual(read(pointerEmptyEnvironment(store: Store()))["code"] as? String, "absent")
	}

	/// AK-28: while the device marker is set, a write is refused whatever the store holds, the native record included.
	func testAWriteIsMigratingWhileTheMarkerIsSet() {
		device.state.legacyUnreadable = true
		let store = Store()
		store.records[account] = ["rev": 1, "schemaVersion": 1]
		let env = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .notRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w28", "record": ["rev": 1, "schemaVersion": 1]], env: env
		)
		XCTAssertEqual(answer["code"] as? String, "migrating")
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1, "nothing is written while the marker is set")
	}

	/// the write gate reads the device marker only. A per-account first-run value does not refuse a write by itself.
	func testAWriteIsNotBlockedByAFirstRunStateAlone() {
		let store = Store()
		store.records[account] = ["rev": 1, "schemaVersion": 1]
		let env = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .legacyUnreadable },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		let answer = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "w5b", "record": ["rev": 1, "schemaVersion": 1]], env: env
		)
		XCTAssertNotEqual(answer["code"] as? String, "migrating")
	}

	/// The stale state of: a first-run report of an unreadable legacy store, then the marker is cleared by an absence report. The write is not refused.
	func testAStaleFirstRunUnreadableDoesNotBlockAWriteAfterTheMarkerIsCleared() {
		let saved = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		defer { BeamioNativeWallet.keyStore = saved }
		var states: [BeamioShellRecord.FirstRunState] = []
		_ = BeamioShellRecord.importFirstRun(
			eoa: account, legacy: .unreadable, store: Store(), device: device,
			addressOf: { _ in nil }, setState: { _, state in states.append(state) }
		)
		XCTAssertTrue(device.state.legacyUnreadable)
		BeamioShellRecord.reportLegacyStore(.absent, device: device)
		XCTAssertFalse(device.state.legacyUnreadable, "the absence report clears the marker")
		let env = BeamioShellRecord.Environment(
			account: { self.account }, store: Store(), device: device, originAllowed: true,
			migrating: { _ in false }, firstRun: { _ in states.last ?? .notRun },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		// after the marker is cleared, a read does not answer legacy_store_unreadable. Read before any write: the store is empty.
		let readAnswer = read(env)
		XCTAssertEqual(readAnswer["code"] as? String, "absent")
		XCTAssertNotEqual(readAnswer["sub"] as? String, "legacy_store_unreadable")
		let answer = BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": "s1", "record": ["rev": 0, "schemaVersion": 1]], env: env)
		XCTAssertNotEqual(answer["code"] as? String, "migrating")
	}

	/// Unchanged: with no account and no shell record, a confirmed absence is absent (the first install).
	func testWithoutAnAccountAnEmptyShellStoreIsStillAbsent() {
		device.state.legacyConfirmedAbsent = true
		XCTAssertEqual(read(pointerEmptyEnvironment(store: Store()))["code"] as? String, "absent")
	}

	/// Unchanged: with no account and the legacy store not read, a shell record of another account is migrating, not absent and not an error.
	/// item 2: with no account known, a page copy of another account gives account_mismatch, also before the legacy store is read.
	func testWithoutAnAccountAShellRecordIsAccountMismatchBeforeTheLegacyRead() {
		let store = Store()
		store.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		let answer = read(pointerEmptyEnvironment(store: store))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "account_mismatch")
	}

	/// The production store lists its records (item 3): a missing directory holds none, a written record is found, and no directory fails closed.
	func testTheProductionStoreReportsItsRecords() throws {
		let directory = FileManager.default.temporaryDirectory.appendingPathComponent("shell-any-\(UUID().uuidString)", isDirectory: true)
		defer { try? FileManager.default.removeItem(at: directory) }
		let store = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: KeysStore())
		XCTAssertFalse(store.hasAnyRecord(), "a missing directory holds no record")
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(store.write(account: account, ["rev": 0, "schemaVersion": 1]))
		XCTAssertTrue(store.hasAnyRecord(), "a written record is found")
		XCTAssertTrue(BeamioShellRecord.EncryptedShellRecordStore(directory: nil, keys: KeysStore()).hasAnyRecord(), "no directory fails closed")
	}
	/// with no account known, an unreadable report sets the marker only when every page copy is enumerated and none exists.
	func testAnUnreadableReportWithoutAnAccountSetsTheMarkerOnlyWhenNoPageCopyExists() {
		BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: Store())
		XCTAssertTrue(device.state.legacyUnreadable)
		let other = Device()
		let withRecord = Store()
		withRecord.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		BeamioShellRecord.reportLegacyStore(.unreadable, device: other, store: withRecord)
		// A (item 3): the marker is device-level and does not depend on another account's copy.
		XCTAssertTrue(other.state.legacyUnreadable)
		XCTAssertFalse(other.state.legacyConfirmedAbsent)
	}

	/// with an account known (the first-run import), the caller has checked its own page copy: no enumeration, the marker is set.
	func testAnUnreadableReportWithAnAccountKnownSetsTheMarker() {
		BeamioShellRecord.reportLegacyStore(.unreadable, device: device)
		XCTAssertTrue(device.state.legacyUnreadable)
	}
	/// with no account known, an absence is reported only when every page copy is enumerated and none exists.
	func testAnAbsenceReportWithoutAnAccountIsNotAcceptedWhilePageCopiesExist() {
		let withRecord = Store()
		withRecord.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		BeamioShellRecord.reportLegacyStore(.absent, device: device, store: withRecord)
		// A (item 3): the report is device-level; another account's copy does not stop it. The read with no account stays account_mismatch.
		XCTAssertTrue(device.state.legacyConfirmedAbsent)
		XCTAssertEqual(read(pointerEmptyEnvironment(store: withRecord))["sub"] as? String, "account_mismatch")
	}

	/// with no account known and every page copy enumerated as absent, the absence is reported and answered.
	func testAnAbsenceReportWithoutAnAccountIsAcceptedWhenNoPageCopyExists() {
		BeamioShellRecord.reportLegacyStore(.absent, device: device, store: Store())
		XCTAssertTrue(device.state.legacyConfirmedAbsent)
		XCTAssertEqual(read(pointerEmptyEnvironment(store: Store()))["code"] as? String, "absent")
	}
	/// A store whose enumeration of the page copies fails.
	private final class FailingStore: BeamioShellRecord.ShellRecordStore {
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .unreadable }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { false }
		func hasAnyRecord() -> Bool { true }
		func pageCopyEnumeration() -> BeamioShellRecord.PageCopyEnumeration { .failed }
	}

	/// (AK-40): with no account known and the enumeration failed, the read is record_unreadable, never absent, and the absence is not reported.
	func testAFailedEnumerationIsRecordUnreadableWithoutAnAccount() {
		// A: the report is device-level. No copy enumeration decides it (item 3). The read stays record_unreadable.
		BeamioShellRecord.reportLegacyStore(.absent, device: device, store: FailingStore())
		XCTAssertTrue(device.state.legacyConfirmedAbsent, "the report is recorded at device level")
		let answer = read(pointerEmptyEnvironment(store: FailingStore()))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "record_unreadable")
		XCTAssertFalse(device.state.legacyUnreadable, "no marker is set on a failed enumeration")
	}

	/// (AK-41): with no account known and the enumeration failed, a write is migrating (the read is not complete).
	func testAFailedEnumerationMakesAWriteMigratingWithoutAnAccount() {
		let env = pointerEmptyEnvironment(store: FailingStore())
		let answer = BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": "w41", "record": ["rev": 0, "schemaVersion": 1]], env: env)
		XCTAssertEqual(answer["code"] as? String, "migrating")
	}

	/// with no account known and a page copy present, a write is migrating, not write_failed. Nothing is written.
	func testAPresentPageCopyMakesAWriteMigratingWithoutAnAccount() {
		let withRecord = Store()
		withRecord.records["0x2222222222222222222222222222222222222222"] = ["rev": 1, "schemaVersion": 2]
		let answer = BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": "w41p", "record": ["rev": 0, "schemaVersion": 1]], env: pointerEmptyEnvironment(store: withRecord))
		XCTAssertEqual(answer["code"] as? String, "migrating")
		XCTAssertEqual(withRecord.records["0x2222222222222222222222222222222222222222"]?["rev"] as? Int, 1, "nothing is written")
	}

	/// (table, "native record empty"): with no account known and every page copy absent, a write is never write_failed. Only a confirmed empty
	/// legacy store with an empty pointer and no native record is allowed, and that case is not stored yet (no account to key it under), so it is migrating too.
	func testAWriteWithNoAccountAndNoPageCopyIsMigratingNeverWriteFailed() {
		var confirmed = BeamioShellRecord.DeviceState()
		confirmed.legacyConfirmedAbsent = true
		var found = confirmed
		found.legacyFound = true
		var unreadable = confirmed
		unreadable.legacyUnreadable = true
		var pointerSet = confirmed
		pointerSet.accountEstablished = true
		let states: [(String, BeamioShellRecord.DeviceState)] = [
			("not confirmed", BeamioShellRecord.DeviceState()),
			("confirmed empty", confirmed),
			("found", found),
			("unreadable", unreadable),
			("pointer set", pointerSet),
		]
		for (name, state) in states {
			device.state = state
			let store = Store()
			let answer = BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": "w41a", "record": ["rev": 0, "schemaVersion": 1]], env: pointerEmptyEnvironment(store: store))
			XCTAssertEqual(answer["code"] as? String, "migrating", name)
			XCTAssertTrue(store.records.isEmpty, "\(name): nothing is written")
		}
	}
}
