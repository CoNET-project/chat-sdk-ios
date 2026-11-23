#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The guard that keeps a second account from being made while one exists (KR-08): with no pointer, the legacy store confirmed empty and a valid native account that reads, the NORMAL read
/// answers `absent`, but the CREATION read answers `migrating`, writes no page copy, and never answers `absent`. Production path: `BeamioWindowWallet.shellRecordRead` over the real read judgement and a store
/// that holds a valid mnemonic account.
final class CreationReadProtectionTests: XCTestCase {
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

	private var saved: BeamioChatWalletKeyStoring?
	private var native = MemoryNativeKeyStore()

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeAccountPointer.clear()
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		saved = BeamioNativeWallet.keyStore
		native = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = native
	}

	override func tearDown() {
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = saved ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func read(creation: Bool, store: Store, device: Device) -> [String: Any] {
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { nil }, store: store, device: device, originAllowed: false, migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent }, locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved,
			gate: { .g0 }, creationMode: { creation }
		)
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": creation ? 9910 : 9911], trust: .trusted) { out = $0 }
		return (out["result"] as? [String: Any]) ?? out
	}

	/// The creation read meets a native record: migrating, not absent, nothing written, the account untouched; the normal read of the same state is absent (KR-08), so the page can show the account
	/// but cannot create a new one.
	func testTheCreationReadMeetingANativeRecordIsMigratingAndTheNormalReadIsAbsent() {
		let acct = ValidTestAccounts.install(native)
		let store = Store(), device = Device()
		device.state.legacyConfirmedAbsent = true
		let creation = read(creation: true, store: store, device: device)
		XCTAssertEqual(creation["code"] as? String, "migrating", "the creation read never answers absent while a native account exists")
		XCTAssertNotEqual(creation["code"] as? String, "absent")
		XCTAssertTrue(store.records.isEmpty, "no page copy is written by the creation read")
		XCTAssertEqual(native.keys[acct.eoa], acct.key, "the account's key is untouched")
		XCTAssertEqual(native.itemState(.mnemonic, eoa: acct.eoa), .present, "and its mnemonic")
		// the same state, the normal read
		let normal = read(creation: false, store: Store(), device: device)
		XCTAssertEqual(normal["code"] as? String, "absent", "KR-08: the normal read is absent")
		// the creation read again, after the normal read cleared the stale absence: still not absent
		XCTAssertNotEqual(read(creation: true, store: store, device: device)["code"] as? String, "absent")
	}

	/// An unreadable native key does not lift the guard either: the creation read stays migrating.
	func testTheCreationReadStaysMigratingWhenTheNativeKeyCannotBeRead() {
		let acct = ValidTestAccounts.install(native)
		native.keys[acct.eoa] = Data(repeating: 0x11, count: 5)   // a key record that does not derive its account
		let store = Store(), device = Device()
		device.state.legacyConfirmedAbsent = true
		XCTAssertEqual(read(creation: true, store: store, device: device)["code"] as? String, "migrating")
		XCTAssertTrue(store.records.isEmpty)
	}
}
#endif
