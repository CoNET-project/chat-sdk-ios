import CryptoKit
import XCTest
@testable import ConetChatSDK

/// (keep published data): what the published iOS 1.5.8 (chat-sdk-ios 0.1.8) left on the device is never rewritten, moved or deleted by the
/// SDK that follows it: the `walletKey` keychain item, the PGP keychain items and the roster file. No device record is created and no hardware key.
final class PublishedDataPreservedTests: XCTestCase {
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

	private final class Legacy: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var deletes = 0
		var writes = 0
		func write(eoa: String, key: Data) -> Bool { writes += 1; keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { deletes += 1; keys[eoa.lowercased()] = nil }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private func digest(_ data: Data?) -> String { SHA256.hash(data: data ?? Data()).map { String(format: "%02x", $0) }.joined() }

	func testAnUpgradeLeavesTheWalletKeyThePgpItemsAndTheRosterFileUnchanged() throws {
		let savedPgp = BeamioChatPgpKeychain.memory
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		defer { BeamioChatPgpKeychain.memory = savedPgp }
		// what the published build left: the walletKey item (synthetic key), the PGP/roster items
		let key = Data(repeating: 0x42, count: 32)
		let legacy = Legacy()
		legacy.keys[eoa] = key
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: [BeamioChatPgpKeychain.SiNode(ip: "203.0.113.9", domain: "n.example.invalid", region: "t", armoredPublicKey: "SYNTHETIC")], mailboxIp: "203.0.113.10"))
		let pgpBefore = BeamioChatPgpKeychain.memory?.values ?? [:]
		let rosterBefore = BeamioChatPgpKeychain.loadSiNodes()
		let mailboxBefore = BeamioChatPgpKeychain.loadMailboxIp()
		let keyDigestBefore = digest(legacy.keys[eoa])

		let records = ShellPasscodeCoreTests.MemRecords()
		let hardware = ShellPasscodeCoreTests.MemHardware()
		let store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: BeamioPasscodeSession())
		// the operations an upgraded app runs on the key store
		XCTAssertEqual(store.read(eoa: eoa), key, "the published key is still read")
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .present)
		_ = store.enumerateKeyOwners()
		_ = store.enumerateKeyEntries()
		XCTAssertFalse(store.write(eoa: eoa, key: Data(repeating: 0x77, count: 32)), "a new key is not written as a device record; the honest answer is false")
		store.delete(eoa: eoa)

		XCTAssertEqual(digest(legacy.keys[eoa]), keyDigestBefore, "the walletKey bytes are unchanged")
		XCTAssertEqual(legacy.deletes, 0, "the walletKey item is not deleted, not by delete either")
		XCTAssertEqual(legacy.writes, 0, "the walletKey item is not overwritten")
		XCTAssertTrue(records.values.isEmpty, "no device record is created")
		XCTAssertTrue(hardware.present.isEmpty, "no hardware key is created")
		XCTAssertEqual(BeamioChatPgpKeychain.memory?.values ?? [:], pgpBefore, "the PGP items are unchanged")
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), rosterBefore, "the roster is unchanged")
		XCTAssertEqual(BeamioChatPgpKeychain.loadMailboxIp(), mailboxBefore)
	}

	func testTheProductionWriteAnswersFalseAndCreatesNothingForAnyAccount() {
		let records = ShellPasscodeCoreTests.MemRecords()
		let hardware = ShellPasscodeCoreTests.MemHardware()
		let store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: Legacy(), session: BeamioPasscodeSession())
		XCTAssertFalse(store.write(eoa: eoa, key: Data(repeating: 0x11, count: 32)))
		XCTAssertTrue(records.values.isEmpty)
		XCTAssertTrue(hardware.present.isEmpty)
		XCTAssertEqual(store.keyRecordState(eoa: eoa), .absent, "and the account still has no record")
	}
}
