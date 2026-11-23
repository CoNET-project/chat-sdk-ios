import XCTest
@testable import ConetChatSDK

/// The reader contract of the shell: at start the reader reports `found`, `absent` or `unreadable` through the
/// device-level entry (`reportLegacyStore`), before the WebView. One case for each report. The native key store is an empty memory store: the simulator has
/// no Keychain entitlement, and a Keychain that cannot answer is fail closed (any key record counts).
final class ShellReaderContractTests: XCTestCase {
	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool {
			records[account] = record
			return true
		}
		func hasAnyRecord() -> Bool { !records.isEmpty }
	}

	private var device: Device!
	private var savedKeyStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		NativeAccountPointerIsolation.begin()
		super.setUp()
		device = Device()
		savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedKeyStore
		super.tearDown()
	}

	/// A read with no account known, no pointer and no key: the answer that the reported state gives.
	private func read(_ store: Store) -> [String: Any] {
		let env = BeamioShellRecord.Environment(
			account: { nil },
			store: store,
			device: device,
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .notRun },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		return BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "r"], env: env)
	}

	/// `found`: the legacy store holds a record that is not imported yet. The read is import_not_done.
	func testTheFoundReportMakesTheReadImportNotDone() {
		BeamioShellRecord.reportLegacyStore(.found, device: device)
		XCTAssertTrue(device.state.legacyFound)
		let answer = read(Store())
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "import_not_done")
	}

	/// `absent`: the legacy store is read completely and holds nothing, and no page copy exists. The read is absent.
	func testTheAbsentReportWithNoPageCopyAnswersAbsent() {
		BeamioShellRecord.reportLegacyStore(.absent, device: device, store: Store())
		XCTAssertTrue(device.state.legacyConfirmedAbsent)
		XCTAssertEqual(read(Store())["code"] as? String, "absent")
	}

	/// `unreadable`: the legacy store cannot be read now. The device marker is set, and the read is an error legacy_store_unreadable
	/// (E9.11.29 r2, K.3, IM-03; kept by the requirement, KR-05 on the PWA baseline): never absent, never a new wallet, retried at the next start.
	func testTheUnreadableReportSetsTheMarkerAndTheReadIsUnreadable() {
		BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: Store())
		XCTAssertTrue(device.state.legacyUnreadable)
		// group A: the error answer needs a native key on the device; with none the read is migrating (U.6).
		let savedKeys = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = savedKeys }
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		XCTAssertEqual(read(Store())["code"] as? String, "migrating", "no native key: migrating")
		let keyOnly = MemoryNativeKeyStore()
		keyOnly.keys["0x00000000000000000000000000000000000000a1"] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = keyOnly
		let answer = read(Store())
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "legacy_store_unreadable")
	}

	/// PY.15 4 (project ruling), as (ERRATUM, keystore-replica v2 KR-08): with a valid native account on the device and no pointer, an absence report is saved and answers ok, and the
	/// read answers `absent` (the legacy store is confirmed empty; the creation read, not this one, answers migrating while the account exists).
	func testAnAbsenceReportWithANativeKeyIsSavedAndTheReadIsAbsentWithoutAPointer() {
		// a valid account (its key and the mnemonic that derives it): a key alone is no account since Y.163 items 31 and 32
		ValidTestAccounts.install(BeamioNativeWallet.keyStore as! MemoryNativeKeyStore)
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.absent, device: device, store: Store()), .ok)
		XCTAssertTrue(device.state.legacyConfirmedAbsent, "saved")
		XCTAssertEqual(read(Store())["code"] as? String, "absent")
	}

	/// R-2 (item 6): a native record found after an absence is stale: the absence is cleared. The read of that first call answers `absent` with no pointer and a readable valid account (
	/// KR-08); the cleared flag cannot answer absent later (the next read is migrating).
	func testANativeRecordClearsAStaleAbsence() {
		device.state.legacyConfirmedAbsent = true
		ValidTestAccounts.install(BeamioNativeWallet.keyStore as! MemoryNativeKeyStore)
		let answer = read(Store())
		XCTAssertFalse(device.state.legacyConfirmedAbsent)
		XCTAssertEqual(answer["code"] as? String, "absent")
		XCTAssertEqual(read(Store())["code"] as? String, "migrating", "the cleared flag does not bring absent back")
	}
}
