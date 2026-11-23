import XCTest
@testable import ConetChatSDK

/// Exercises the PWA sync path with the production passcode store implementation backed by real Keychain services.
/// Only per-test synthetic accounts and task-unique Keychain namespaces are used.
final class PwaWalletSyncPasscodeStoreTests: XCTestCase {
	private final class UnavailableRecords: BeamioPasscodeRecordStoring {
		var writes = 0
		func readRecord(eoa: String) -> Data? { nil }
		func readRecordState(eoa: String) -> BeamioPasscodeRecordRead { .unavailable }
		func writeRecord(eoa: String, _ data: Data) -> Bool { writes += 1; return false }
		func deleteRecord(eoa: String) {}
		func hasAnyRecord() -> Bool { true }
		func enumerateRecordOwners() -> [String]? { nil }
		func enumerateRecordCreations() -> [BeamioChatKeyCreation]? { nil }
	}
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedPointer = ""
	private var legacy: BeamioChatWalletKeychainStore!
	private var records: BeamioPasscodeKeychainRecords!
	private var hardware: BeamioPasscodeKeychainHardware!
	private var session: BeamioPasscodeSession!
	private var store: BeamioPasscodeWalletStore!
	private var eoa = ""
	private var phrase = ""
	private var key = Data()

	override func setUp() {
		super.setUp()
		// withdrawn overwrite and sealing format (never published): the test seam turns the old phrase write on here only
		BeamioPwaWalletSync.legacyPhraseWriteForTests = true
		// This class tests the withdrawn device and passcode record formats (never published). The production `write` and `delete` of the store are off
		//; the test seam turns the old behaviour on here only, so that the formats stay covered.
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = true
		savedStore = BeamioNativeWallet.keyStore
		savedPointer = BeamioNativeAccountPointer.get()
		let suffix = UUID().uuidString.lowercased()
		legacy = BeamioChatWalletKeychainStore(service: "com.beamio.qa.raw-sync.\(suffix)")
		records = BeamioPasscodeKeychainRecords(service: "com.beamio.qa.passcode-record.\(suffix)")
		hardware = BeamioPasscodeKeychainHardware(seTagPrefix: "com.beamio.qa.passcode.h.\(suffix).",
		                                         fallbackService: "com.beamio.qa.passcode.h-fallback.\(suffix)")
		session = BeamioPasscodeSession()
		session.vault = BeamioPasscodeVault(records: records, hardware: hardware)
		store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: session)
		BeamioNativeWallet.keyStore = store
		let entropy = Array(UUID().uuidString.utf8.prefix(16))
		guard let generated = BeamioNativeAccountCreate.phrase(entropy: entropy),
		      let derived = BeamioPwaWalletSync.derivedAccount(phrase: generated) else {
			XCTFail("synthetic BIP-39 fixture must derive")
			return
		}
		phrase = generated
		key = derived.key
		eoa = derived.eoa
		BeamioNativeAccountPointer.set(eoa)
	}

	override func tearDown() {
		BeamioPwaWalletSync.legacyPhraseWriteForTests = false
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = false
		if !eoa.isEmpty {
			_ = store?.deleteItem(.mnemonic, eoa: eoa)
			_ = store?.deleteItem(.intent, eoa: eoa)
			_ = store?.deleteItem(.commit, eoa: eoa)
			_ = store?.deleteItem(.key, eoa: eoa)
			hardware?.deleteKey(eoa: eoa)
			_ = BeamioWalletCredentialBlob.delete(eoa: eoa)
		}
		BeamioNativeWallet.keyStore = savedStore
		BeamioNativeAccountPointer.set(savedPointer)
		super.tearDown()
	}

	func testPhraseOnlyResidueRepairsTheSameProductionStoreAccountWithoutReplacingLegacyItems() throws {
		let mnemonicAccount = legacy.accountName(.mnemonic, eoa: eoa)
		let intentAccount = legacy.accountName(.intent, eoa: eoa)
		let commitAccount = legacy.accountName(.commit, eoa: eoa)
		XCTAssertTrue(legacy.writeItem(.mnemonic, eoa: eoa, value: Data(phrase.utf8)))
		XCTAssertTrue(legacy.writeItem(.intent, eoa: eoa, value: Data("synthetic-intent".utf8)))
		XCTAssertTrue(legacy.writeItem(.commit, eoa: eoa, value: Data("synthetic-commit".utf8)))
		XCTAssertEqual(store.itemState(.key, eoa: eoa), .absent)
		XCTAssertEqual(BeamioPwaWalletSync.phraseOnlyResidueEOA(store: store), eoa)
		let mnemonicBefore = legacy.rawRead(account: mnemonicAccount)
		let intentBefore = legacy.rawRead(account: intentAccount)
		let commitBefore = legacy.rawRead(account: commitAccount)

		let answer = BeamioPwaWalletSync.answer([
			"type": "pwaWalletSync", "reqId": 41, "trustedOrigin": true, "seq": 1, "phrase": phrase,
		], snapshotKnown: true, storageLocked: false)

		XCTAssertTrue(answer["ok"] as? Bool == true)
		XCTAssertEqual((answer["result"] as? [String: Any])?["sync"] as? String, "updated")
		XCTAssertEqual(store.read(eoa: eoa), key, "the normal passcode/device wrapping path reads back the same derived key")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8))
		XCTAssertEqual(legacy.rawRead(account: mnemonicAccount), mnemonicBefore, "the sealed legacy phrase bytes are unchanged")
		XCTAssertEqual(legacy.rawRead(account: intentAccount), intentBefore, "the old intent bytes are unchanged")
		XCTAssertEqual(legacy.rawRead(account: commitAccount), commitBefore, "the old commit bytes are unchanged")
		XCTAssertEqual(store.itemState(.key, eoa: eoa), .present)
	}

	func testRawAdapterRefusesPhraseReadsAndWritesForLockedPasscodeAccounts() throws {
		var keyBytes = [UInt8](key)
		let imported = BeamioNativeKeyImport.storeDerivedKey(&keyBytes, expectedEoa: eoa, store: store, mnemonic: Array(phrase.utf8))
		guard case .imported = imported else { return XCTFail("synthetic production-store import should succeed") }
		let passcode = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 0x53, count: 16), blob: Data(repeating: 0x24, count: 48))
		let encoded = try JSONEncoder().encode(passcode)
		XCTAssertTrue(records.writeRecord(eoa: eoa, encoded))
		XCTAssertTrue(session.isLocked(eoa: eoa))
		let mnemonicAccount = legacy.accountName(.mnemonic, eoa: eoa)
		let keyAccount = store.accountName(.key, eoa: eoa)
		let wrappedBefore = records.readRecord(eoa: eoa)
		XCTAssertEqual(store.rawRead(account: mnemonicAccount), .unreadable)
		XCTAssertFalse(store.rawWrite(account: mnemonicAccount, bytes: Data("should-not-write".utf8)))
		XCTAssertEqual(store.rawRead(account: keyAccount), .unreadable)
		XCTAssertFalse(store.rawWrite(account: keyAccount, bytes: Data("replacement".utf8)))
		XCTAssertFalse(store.rawDelete(account: keyAccount))
		XCTAssertEqual(records.readRecord(eoa: eoa), wrappedBefore, "a locked raw write/delete cannot replace the passcode-wrapped record")
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), nil)
	}

	func testKeychainReadFailureStaysUnknownAndNeverLooksLikeAnAbsentPasscodeRecord() {
		let records = UnavailableRecords()
		let testSession = BeamioPasscodeSession()
		testSession.vault = BeamioPasscodeVault(records: records, hardware: hardware)
		let testStore = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: testSession)

		XCTAssertEqual(testSession.appState(eoa: eoa), .unknown)
		XCTAssertTrue(testSession.isLocked(eoa: eoa), "unknown storage state refuses access")
		XCTAssertEqual(testStore.keyRecordState(eoa: eoa), .unreadable)
		XCTAssertNil(testStore.read(eoa: eoa))
		XCTAssertFalse(testStore.rawWrite(account: testStore.accountName(.key, eoa: eoa), bytes: key))
		XCTAssertEqual(records.writes, 0)
	}
}
