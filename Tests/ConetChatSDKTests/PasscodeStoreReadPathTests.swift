#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// 25.52Y.80 and the account-onboarding reset rule (2026-11-15): a read may clean up a legacy key only after the new device record is written,
/// read back, unwrapped and compared with the key. The order is write, then read-back, then the legacy removal. A failed read-back keeps the
/// legacy item and rolls the record back. A record that is there but cannot be decoded is not migrated, overwritten or deleted. A failed device
/// write is never reported as a success. Synthetic bytes only; no key material is printed.
final class PasscodeStoreReadPathTests: XCTestCase {
	/// The order of the store's effects, shared by the doubles.
	final class Log {
		var events: [String] = []
	}

	/// Passcode records with a switch that damages the read-back after a write (the record reads back as bytes that are no record).
	private final class Records: BeamioPasscodeRecordStoring {
		let log: Log
		var data: [String: Data] = [:]
		var writes = 0
		var deletes = 0
		var tamperAfterWrite = false
		var failWrites = false
		private var tamperPending = false
		init(log: Log) {
			self.log = log
		}
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		func readRecord(eoa: String) -> Data? {
			log.events.append("record-read")
			if tamperPending {
				tamperPending = false
				return Data("not a passcode record".utf8)
			}
			return data[eoa.lowercased()]
		}
		func writeRecord(eoa: String, _ value: Data) -> Bool {
			writes += 1
			log.events.append("record-write")
			if failWrites { return false }
			data[eoa.lowercased()] = value
			if tamperAfterWrite { tamperPending = true }
			return true
		}
		func deleteRecord(eoa: String) {
			deletes += 1
			log.events.append("record-delete")
			data[eoa.lowercased()] = nil
		}
	}

	/// The legacy single-key store, with its deletions counted and ordered.
	private final class Legacy: BeamioChatWalletKeyStoring {
		let log: Log
		/// The EOA key items (`walletKey:<eoa>`), and the other items of the account (`mnemonic:<eoa>`), kept apart as the Keychain keeps them.
		var keys: [String: Data] = [:]
		var items: [String: Data] = [:]
		var deletes = 0
		var deletedAccounts: [String] = []
		init(log: Log) {
			self.log = log
		}
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		/// Removes the EOA key item of this account only (the store's `delete` is `walletKey:<eoa>` alone).
		func delete(eoa: String) {
			deletes += 1
			deletedAccounts.append(eoa.lowercased())
			log.events.append("legacy-delete")
			keys[eoa.lowercased()] = nil
		}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	/// Identity hardware for the test only: wrap and unwrap are the identity. It is not a security control.
	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let legacyKey = Data(repeating: 0x22, count: 32)
	private let newKey = Data(repeating: 0x33, count: 32)
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		// This class tests the withdrawn device and passcode record formats (never published). The production `write` and `delete` of the store are off
		//; the test seam turns the old behaviour on here only, so that the formats stay covered.
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = true
		savedStore = BeamioNativeWallet.keyStore
		// the snapshot judges the global store after each write; a memory store keeps the test off the Keychain
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	override func tearDown() {
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = false
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private struct Fixture {
		let log: Log
		let records: Records
		let legacy: Legacy
		let store: BeamioPasscodeWalletStore
	}

	private func fixture() -> Fixture {
		let log = Log()
		let records = Records(log: log)
		let legacy = Legacy(log: log)
		let store = BeamioPasscodeWalletStore(records: records, hardware: IdentityHardware(), legacy: legacy, session: BeamioPasscodeSession())
		return Fixture(log: log, records: records, legacy: legacy, store: store)
	}

	/// project requirement (keep published data): a read that finds a legacy key only reads it. Nothing is written, nothing is deleted, no device record
	/// is created; each later read gives the same key from the same old item.
	func testAReadOfALegacyKeyNeitherWritesNorDeletesAnything() {
		let f = fixture()
		f.legacy.keys[account] = legacyKey

		XCTAssertEqual(f.store.read(eoa: account), legacyKey)

		XCTAssertFalse(f.log.events.contains("record-write"), "no device record is written")
		XCTAssertFalse(f.log.events.contains("legacy-delete"), "the legacy item is not deleted")
		XCTAssertNil(f.records.data[account], "no device record exists")
		XCTAssertEqual(f.legacy.deletes, 0)
		XCTAssertEqual(f.legacy.keys[account], legacyKey, "the old item is byte for byte as it was")
		XCTAssertEqual(f.store.read(eoa: account), legacyKey, "a later read answers the same key from the old item")
		XCTAssertEqual(f.records.deletes, 0)
	}

	/// A failing record store changes nothing either: the legacy key is still read, nothing is written, nothing is deleted.
	func testAFailingRecordStoreDoesNotChangeTheLegacyRead() {
		let f = fixture()
		f.legacy.keys[account] = legacyKey
		f.records.tamperAfterWrite = true

		XCTAssertEqual(f.store.read(eoa: account), legacyKey, "the legacy key is still read")

		XCTAssertFalse(f.log.events.contains("legacy-delete"))
		XCTAssertEqual(f.legacy.keys[account], legacyKey)
		XCTAssertNil(f.records.data[account])
		XCTAssertEqual(f.records.deletes, 0, "nothing was written, so nothing is rolled back")
	}

	/// A read removes no key item of any account and leaves the mnemonic item of the account as it is.
	func testAReadRemovesNoKeyItemOfAnyAccountAndLeavesTheMnemonicItem() {
		let f = fixture()
		let other = "0x2222222222222222222222222222222222222222"
		let phrase = Data("synthetic phrase for the test only".utf8)
		f.legacy.keys[account] = legacyKey
		f.legacy.keys[other] = newKey
		f.legacy.items["mnemonic:\(account)"] = phrase

		XCTAssertEqual(f.store.read(eoa: account), legacyKey)

		XCTAssertEqual(f.legacy.keys[account], legacyKey, "this account's key item is kept")
		XCTAssertEqual(f.legacy.keys[other], newKey, "another account's key item is kept")
		XCTAssertEqual(f.legacy.items["mnemonic:\(account)"], phrase, "the mnemonic item is kept byte for byte")
		XCTAssertEqual(f.legacy.deletedAccounts, [], "no removal at all")
	}

	/// A record that is there but cannot be decoded is an unknown state: no key is returned (the legacy key is not a fallback, requirement item 3, a2767b6 "preserve unknown
	/// keychain state"), and neither the record nor the legacy item changes.
	func testAnUndecodableRecordIsNeitherMigratedNorOverwritten() {
		let f = fixture()
		f.legacy.keys[account] = legacyKey
		let garbage = Data("unreadable record bytes".utf8)
		f.records.data[account] = garbage

		XCTAssertNil(f.store.read(eoa: account), "an unknown state returns no key and does not fall back to the legacy key")

		XCTAssertEqual(f.records.writes, 0, "the unreadable record is not overwritten")
		XCTAssertEqual(f.records.deletes, 0)
		XCTAssertEqual(f.records.data[account], garbage)
		XCTAssertEqual(f.legacy.deletes, 0, "the legacy item is kept")
		XCTAssertEqual(f.legacy.keys[account], legacyKey)
	}

	/// 25.52Y.85 第 6 項 (gate 4): with no verified copy (the device write fails), the legacy item is not removed, and no record is left behind.
	func testWithoutAWrittenCopyTheLegacyItemIsKept() {
		let f = fixture()
		f.legacy.keys[account] = legacyKey
		f.records.failWrites = true

		XCTAssertEqual(f.store.read(eoa: account), legacyKey, "the legacy key is still readable")

		XCTAssertEqual(f.legacy.deletes, 0, "no copy was verified, so no legacy item is removed")
		XCTAssertEqual(f.legacy.keys[account], legacyKey)
		XCTAssertNil(f.records.data[account])
	}

	/// A device-record write whose read-back fails is rolled back to the record that was there before. It reports false, and it deletes
	/// nothing else (the legacy record is untouched).
	func testAWriteWhoseReadBackFailsIsRolledBackAndReportsFailure() {
		let f = fixture()
		f.legacy.keys[account] = legacyKey
		XCTAssertTrue(f.store.write(eoa: account, key: legacyKey), "the first write verifies")
		guard let previous = f.records.data[account] else { return XCTFail("the first write stored no record") }

		f.records.tamperAfterWrite = true
		XCTAssertFalse(f.store.write(eoa: account, key: newKey), "a read-back that fails is not a success")

		XCTAssertEqual(f.records.data[account], previous, "the previous record is put back as it was")
		XCTAssertEqual(f.legacy.deletes, 0, "the legacy record is not deleted by a failed write")
		XCTAssertEqual(f.legacy.keys[account], legacyKey)
	}

	/// With no record before, a failed read-back removes the record this write made, and nothing else.
	func testAFailedReadBackWithNoPriorRecordRemovesOnlyItsOwnRecord() {
		let f = fixture()
		f.legacy.keys["0x2222222222222222222222222222222222222222"] = legacyKey
		f.records.tamperAfterWrite = true
		XCTAssertFalse(f.store.write(eoa: account, key: newKey))

		XCTAssertNil(f.records.data[account], "the record this write made is removed")
		XCTAssertEqual(f.records.deletes, 1, "one deletion: the record of this write")
		XCTAssertEqual(f.legacy.deletes, 0)
		XCTAssertEqual(f.legacy.keys["0x2222222222222222222222222222222222222222"], legacyKey, "another account's legacy key is untouched")
	}

	/// The control: a write whose read-back verifies reports success and keeps its record.
	func testAVerifiedWriteReportsSuccessAndKeepsItsRecord() {
		let f = fixture()
		XCTAssertTrue(f.store.write(eoa: account, key: newKey))
		XCTAssertNotNil(f.records.data[account])
		XCTAssertEqual(f.records.deletes, 0)
		XCTAssertEqual(f.store.read(eoa: account), newKey)
	}
}
#endif
