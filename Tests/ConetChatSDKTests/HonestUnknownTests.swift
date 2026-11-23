import XCTest
@testable import ConetChatSDK

/// a key that cannot be read for a real reason is reported as an unreadable store (not_ready), never as a missing
/// key. Three real failures are tested, each with a control that really is missing and is reported as missing:
/// the keychain cannot be read, the device protection (the Secure Enclave key) is not ready, and the stored data is damaged.
final class HonestUnknownTests: XCTestCase {
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

	private final class Legacy: BeamioChatWalletKeyStoring {
		func write(eoa: String, key: Data) -> Bool { true }
		func read(eoa: String) -> Data? { nil }
		func enumerateKeyOwners() -> [String]? { [] }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private var records: ShellPasscodeCoreTests.MemRecords!
	private var hardware: ShellPasscodeCoreTests.MemHardware!
	private var store: BeamioPasscodeWalletStore!
	private var saved: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		records = ShellPasscodeCoreTests.MemRecords()
		hardware = ShellPasscodeCoreTests.MemHardware()
		store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: Legacy(), session: BeamioPasscodeSession())
		saved = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = saved
		super.tearDown()
	}

	private func key() -> Result<Bool, BeamioNativeWallet.Failure> {
		BeamioNativeWallet.withAccountKeyUnchecked(eoa: eoa) { _ in true }
	}

	private func deviceRecord(blob: Data) {
		records.values[eoa] = try? JSONEncoder().encode(BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob))
	}

	/// the control: no record anywhere is a missing key, and only then
	func testNoRecordAtAllIsReportedAsAMissingKey() {
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .absent)
		XCTAssertEqual(key(), .failure(.walletKeyMissing))
	}

	/// 1. the keychain cannot be read: unknown, never a missing key
	func testAKeychainThatCannotBeReadIsReportedUnreadableNotMissing() {
		deviceRecord(blob: Data([1]))
		records.unavailable = true
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .unreadable)
		XCTAssertEqual(key(), .failure(.storageUnreadable))
		records.unavailable = false
		records.values = [:]
		XCTAssertEqual(key(), .failure(.walletKeyMissing), "control: a readable keychain with no record is missing")
	}

	/// 2. the device protection is not ready (no hardware key to unwrap with): unknown, never a missing key
	func testADeviceProtectionThatIsNotReadyIsReportedUnreadableNotMissing() {
		deviceRecord(blob: Data(repeating: 7, count: 48))
		XCTAssertFalse(hardware.hasKey(eoa: eoa), "the hardware key is not there yet")
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .unreadable)
		XCTAssertEqual(key(), .failure(.storageUnreadable))
		// control: once the hardware key is ready and the record unwraps, the key is there
		hardware.present.insert(eoa)
		let aad = BeamioPasscodeWrap.aadH(eoa: eoa)
		deviceRecord(blob: aad + Data([0xFF]) + Data(repeating: 0x11, count: 32))
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .present)
	}

	/// 3. damaged data (a record that cannot be decoded): unknown, never a missing key
	func testDamagedDataIsReportedUnreadableNotMissing() {
		records.values[eoa] = Data("not a passcode record".utf8)
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .unreadable)
		XCTAssertEqual(key(), .failure(.storageUnreadable))
	}

	/// a passcode record whose bundle has not been provided gives no key: unknown and retryable, not a missing key
	func testAPasscodeRecordWithoutItsBundleIsReportedUnreadableNotMissing() {
		records.values[eoa] = try? JSONEncoder().encode(BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data([2])))
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .present)
		XCTAssertNil(store.read(eoa: eoa))
		XCTAssertEqual(key(), .failure(.storageUnreadable))
	}
}
