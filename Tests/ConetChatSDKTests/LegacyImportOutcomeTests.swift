import Foundation
import XCTest
@testable import ConetChatSDK

/// E9.11.31 r3 / 3c: a found legacy record whose import is refused (address_mismatch, import_failed) keeps the device finding, so the
/// read answers `error import_not_done` (§25.52K.5); nothing is written to the page copy or the native key store. Synthetic values only.
final class LegacyImportOutcomeTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { records[account].map { .record($0) } ?? .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { records[account] = record; return true }
		func hasAnyRecord() -> Bool { !records.isEmpty }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var keyStore = MemoryNativeKeyStore()
	private var device = Device()
	private var store = Store()

	override func setUp() {
		NativeAccountPointerIsolation.begin()
		super.setUp()
		savedKeyStore = BeamioNativeWallet.keyStore
		keyStore = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = keyStore
		device = Device()
		store = Store()
		BeamioShellRecord.setFirstRunState(account, .notRun)
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedKeyStore
		BeamioShellRecord.setFirstRunState(account, .notRun)
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// A found legacy record with one profile under the account, through the first-run import with the given derivation.
	private func importFound(armor: String, derive: @escaping (String) -> String?) -> BeamioShellRecord.FirstRunImportCode {
		let json: [String: Any] = ["profiles": [["keyID": account, "emailAddr": "a", "privateKeyArmor": armor]], "mnemonicPhrase": "M"]
		let data = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
		return BeamioShellRecord.importFirstRun(
			eoa: account,
			legacy: .found(BeamioShellRecord.LegacyWalletRecord(bytes: [UInt8](data))),
			store: store,
			device: device,
			addressOf: derive,
			setState: { _, _ in }
		)
	}

	private func readAnswer() -> [String: Any] {
		let env = BeamioShellRecord.Environment(
			account: { nil }, store: store, device: device, originAllowed: true,
			migrating: { _ in false }, firstRun: { _ in .notRun },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		return BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "io1"], env: env)
	}

	/// 3c: address_mismatch → error import_not_done; the page copy and the native key store stay empty; the legacy finding holds.
	func testAddressMismatchAnswersImportNotDone() {
		let code = importFound(armor: PgpMigrationTestSupport.armorA) { _ in "0x1111111111111111111111111111111111111111" }
		XCTAssertEqual(code, .addressMismatch)
		XCTAssertTrue(device.state.legacyFound, "the found finding holds until a successful import")
		XCTAssertTrue(store.records.isEmpty, "nothing is written to the page copy")
		XCTAssertFalse(BeamioNativeWallet.hasAnyRecord(), "no native key is written")
		let answer = readAnswer()
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "import_not_done")
	}

	/// 3c: import_failed (a key that cannot be normalized) → error import_not_done, nothing written.
	func testImportFailedAnswersImportNotDone() {
		let code = importFound(armor: "not-a-key") { _ in PgpMigrationTestSupport.eoa }
		XCTAssertEqual(code, .importFailed)
		XCTAssertTrue(device.state.legacyFound)
		XCTAssertTrue(store.records.isEmpty)
		let answer = readAnswer()
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "import_not_done")
	}
}
