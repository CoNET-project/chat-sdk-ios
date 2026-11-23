import Foundation
import XCTest
@testable import ConetChatSDK

/// E9.11.29 r2 (LEG-1..4) and the fresh-install fix: the device state file beside the page copies is not a page copy, and an unreadable
/// legacy store answers a read `error legacy_store_unreadable` (§25.52K.3), never `absent` and never a new wallet. Synthetic values only.
final class LegacyReportAnswerTests: XCTestCase {
	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private final class Keys: BeamioShellRecord.KeyStorage {
		var keys: [String: Data] = [:]
		func readKey(account: String) -> BeamioShellRecord.KeyRead {
			keys[account].map { .found($0) } ?? .notFound
		}
		@discardableResult func writeKey(account: String, _ key: Data) -> Bool {
			keys[account] = key
			return true
		}
	}

	private final class EmptyStore: BeamioShellRecord.ShellRecordStore {
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { false }
		func hasAnyRecord() -> Bool { false }
	}

	private var directory: URL?
	private var device = Device()
	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var keyStore = MemoryNativeKeyStore()

	override func setUp() {
		NativeAccountPointerIsolation.begin()
		super.setUp()
		savedKeyStore = BeamioNativeWallet.keyStore
		keyStore = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = keyStore
		device = Device()
		directory = FileManager.default.temporaryDirectory.appendingPathComponent("leg-\(UUID().uuidString)", isDirectory: true)
		try? FileManager.default.createDirectory(at: directory!, withIntermediateDirectories: true)
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedKeyStore
		NativeAccountPointerIsolation.end()
		if let directory { try? FileManager.default.removeItem(at: directory) }
		super.tearDown()
	}

	private func productionShapedStore() -> BeamioShellRecord.EncryptedShellRecordStore {
		BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: Keys())
	}

	private func environment(store: BeamioShellRecord.ShellRecordStore) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { nil }, store: store, device: device, originAllowed: true,
			migrating: { _ in false }, firstRun: { _ in .notRun },
			locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	private func read(_ env: BeamioShellRecord.Environment) -> [String: Any] {
		BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "l1"], env: env)
	}

	/// The device state file of the device (135 bytes in production) sits in the page-copy directory.
	private func placeDeviceState() {
		guard let directory else { return }
		let state = Data(repeating: 0x7b, count: 135)
		try? state.write(to: directory.appendingPathComponent(BeamioShellRecord.deviceStateFileName))
	}

	/// Fresh install: the device state file is the only file beside the (absent) page copies. It is not a page copy: absent, not present.
	func testTheDeviceStateFileIsNotAPageCopy() {
		placeDeviceState()
		XCTAssertEqual(productionShapedStore().pageCopyEnumeration(), .absent)
	}

	/// Control: a real page copy beside the device state file still counts as a page copy (present).
	func testAPageCopyBesideTheDeviceStateFileStillCounts() {
		placeDeviceState()
		guard let directory else { return XCTFail("directory") }
		try? Data(repeating: 0x11, count: 64).write(to: directory.appendingPathComponent(String(repeating: "a", count: 64) + ".bin"))
		XCTAssertEqual(productionShapedStore().pageCopyEnumeration(), .present)
	}

	/// Fresh install with the device state beside it: the confirmed absence answers absent, so onboarding can start (the iOS QA blocker).
	func testFreshInstallWithADeviceStateFileAnswersAbsent() {
		placeDeviceState()
		device.state.legacyConfirmedAbsent = true
		let answer = read(environment(store: productionShapedStore()))
		XCTAssertEqual(answer["code"] as? String, "absent", "absent opens onboarding; the device state file is not a page copy")
		XCTAssertNil(answer["sub"] as? String)
	}

	/// LEG-1: absent, no pointer, no native record: shellRecordRead answers absent.
	func testLEG1AbsentAnswersAbsent() {
		device.state.legacyConfirmedAbsent = true
		XCTAssertEqual(read(environment(store: EmptyStore()))["code"] as? String, "absent")
		XCTAssertFalse(BeamioNativeWallet.hasAnyRecord(), "nothing is generated")
	}

	/// LEG-2 (before import): found, not imported, shellRecordRead answers error import_not_done.
	func testLEG2FoundAnswersImportNotDoneBeforeImport() {
		device.state.legacyFound = true
		let answer = read(environment(store: EmptyStore()))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "import_not_done")
	}

	/// LEG-3: unreadable: error legacy_store_unreadable; never absent; no new wallet; retried at the next start.
	func testLEG3UnreadableAnswersLegacyStoreUnreadable() {
		device.state.legacyUnreadable = true
		// group A: with no native key on the device the read is migrating ( U.6); with a native key (a key only counts) it is error legacy_store_unreadable (KR-05).
		let savedKeys = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = savedKeys }
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		XCTAssertEqual(read(environment(store: EmptyStore()))["code"] as? String, "migrating", "no native key: migrating")
		let keyOnly = MemoryNativeKeyStore()
		keyOnly.keys["0x00000000000000000000000000000000000000a1"] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = keyOnly
		let answer = read(environment(store: EmptyStore()))
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "legacy_store_unreadable")
		XCTAssertNotEqual(answer["code"] as? String, "absent", "an unreadable store is never absent")
		XCTAssertFalse(BeamioNativeWallet.hasAnyRecord(), "no new wallet is generated")
		XCTAssertTrue(device.state.legacyUnreadable, "the marker stays until the next report, so the next start retries")
	}

	/// LEG-3, the creation read (no account known) answers the same error.
	func testLEG3UnreadableCreationReadAnswersLegacyStoreUnreadable() {
		device.state.legacyUnreadable = true
		let answer = BeamioShellRecord.creationModeReadAnswer(env: environment(store: EmptyStore()), reqId: "l3")
		XCTAssertEqual(answer["code"] as? String, "error")
		XCTAssertEqual(answer["sub"] as? String, "legacy_store_unreadable")
	}

	/// LEG-3, a write under an unreadable store stays migrating: nothing is written and no wallet is created.
	func testLEG3UnreadableWriteStaysMigrating() {
		device.state.legacyUnreadable = true
		let env = environment(store: EmptyStore())
		let answer = BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": "l3w", "record": ["rev": 0, "schemaVersion": 2]], env: env)
		XCTAssertNotEqual(answer["code"] as? String, "absent")
		XCTAssertNotEqual(answer["code"] as? String, "ok")
		XCTAssertFalse(BeamioNativeWallet.hasAnyRecord())
	}

	/// LEG-4 (control): no report at all: shellRecordRead answers migrating, never absent and never an error with a legacy sub.
	func testLEG4NoReportAnswersMigrating() {
		let answer = read(environment(store: EmptyStore()))
		XCTAssertEqual(answer["code"] as? String, "migrating")
		XCTAssertNotEqual(answer["sub"] as? String, "legacy_store_unreadable")
	}
}
