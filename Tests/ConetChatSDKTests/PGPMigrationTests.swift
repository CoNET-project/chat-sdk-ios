#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// PGP identity restore for a migrated account. Backup vectors from
/// pgp-backup-compat-vectors.v1.json (P-1, P-2) with their EOA keys. Synthetic data only. Runs with PGP_BACKUP_VECTORS
/// (TEST_RUNNER_ prefix). The identity steps need the X-19 framework, so they run only on iOS builds where it is linked.
final class PGPMigrationTests: XCTestCase {
	/// In-memory native key store (the wallet module's store in tests).
	private final class KeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}


	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = KeyStore()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = nil
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func vectors() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PGP_BACKUP_VECTORS"] else {
			throw XCTSkip("set PGP_BACKUP_VECTORS to interface/protocol/pgp-backup-compat-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func hexBytes(_ text: String) -> [UInt8] {
		var out: [UInt8] = []
		var index = text.startIndex
		while index < text.endIndex {
			let next = text.index(index, offsetBy: 2)
			out.append(UInt8(text[index..<next], radix: 16) ?? 0)
			index = next
		}
		return out
	}

	/// Installs the EOA key of positive `index` for its account. The key is the one in the vector's password string.
	/// The restore of an account, inside that account's G2 gate: the restore reads the account key through the wallet function.
	private func restoreAsG2(_ eoa: String, backupBase64: String, oldPublicArmor: String) -> BeamioPGPMigration.Outcome {
		let restoreG2 = WalletG2Gate.enter(account: eoa)
		defer { restoreG2() }
		return BeamioPGPMigration.restore(eoa: eoa, backupBase64: backupBase64, oldPublicArmor: oldPublicArmor)
	}

	private func installAccount(_ index: Int) throws -> (eoa: String, backup: String, password: String, privateArmor: String, publicArmor: String) {
		let root = try vectors()
		let p = try XCTUnwrap((root["positives"] as? [[String: Any]])?[index])
		let eoa = try XCTUnwrap(p["eoa"] as? String)
		let password = try XCTUnwrap(p["passwordString"] as? String)
		let pgp = try XCTUnwrap(p["pgp"] as? [String: Any])
		let backup = try XCTUnwrap((p["backup"] as? [String: Any])?["base64"] as? String)
		let store = BeamioNativeWallet.keyStore as? KeyStore
		store?.keys[eoa.lowercased()] = Data(hexBytes(String(password.dropFirst(2))))
		return (eoa, backup, password, try XCTUnwrap(pgp["privateArmor"] as? String), try XCTUnwrap(pgp["publicArmor"] as? String))
	}

	// MARK: - Any build

	func testNoKeyLeavesThePhaseRestoring() throws {
		let account = try installAccount(0)
		(BeamioNativeWallet.keyStore as? KeyStore)?.keys.removeAll()
		XCTAssertEqual(restoreAsG2(account.eoa, backupBase64: account.backup, oldPublicArmor: account.publicArmor),
		               .refused("no_key"))
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: account.eoa), .restoring)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account.eoa), "nothing is stored")
	}

	/// A tampered backup (N-4) is refused as decrypt_failed, and nothing is stored.
	func testATamperedBackupIsDecryptFailedAndStoresNothing() throws {
		let account = try installAccount(0)
		let root = try vectors()
		let negative = try XCTUnwrap((root["negatives"] as? [[String: Any]])?.first { $0["id"] as? String == "N-4" })
		let tampered = try XCTUnwrap((negative["backup"] as? [String: Any])?["base64"] as? String)
		XCTAssertEqual(restoreAsG2(account.eoa, backupBase64: tampered, oldPublicArmor: account.publicArmor),
		               .refused("decrypt_failed"))
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: account.eoa), .restoring)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account.eoa))
	}

	/// The EOA key of another account (N-1's password string) is refused as account_mismatch: the key must derive the account.
	func testAKeyOfAnotherAccountIsRefused() throws {
		let account = try installAccount(0)
		let root = try vectors()
		let negative = try XCTUnwrap((root["negatives"] as? [[String: Any]])?.first { $0["id"] as? String == "N-1" })
		let otherPassword = try XCTUnwrap(negative["passwordString"] as? String)
		(BeamioNativeWallet.keyStore as? KeyStore)?.keys[account.eoa.lowercased()] = Data(hexBytes(String(otherPassword.dropFirst(2))))
		XCTAssertEqual(restoreAsG2(account.eoa, backupBase64: account.backup, oldPublicArmor: account.publicArmor),
		               .refused("account_mismatch"))
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account.eoa))
	}

	/// Without the X-19 framework the identity cannot be checked, so nothing is stored (: a key that is not verified
	/// against the old public key is not kept).
	func testWithoutTheFrameworkTheIdentityIsUnverifiedAndNothingIsStored() throws {
		try XCTSkipIf(BeamioPGPNative.linked, "framework linked: covered by the identity tests")
		let account = try installAccount(0)
		XCTAssertEqual(restoreAsG2(account.eoa, backupBase64: account.backup, oldPublicArmor: account.publicArmor),
		               .refused("identity_unverified"))
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: account.eoa), .restoring)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account.eoa))
	}

	// MARK: - Framework linked (iOS builds): identity, readback, cold start, interrupted retry

	func testRestoreStoresTheRecordCompletesAndSurvivesARestart() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X19 xcframework not linked in this build")
		let account = try installAccount(0)
		XCTAssertEqual(restoreAsG2(account.eoa, backupBase64: account.backup, oldPublicArmor: account.publicArmor), .restored)
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: account.eoa), .complete)
		let stored = try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: account.eoa))
		XCTAssertEqual(stored.privateKeyArmor, account.privateArmor)
		XCTAssertEqual(stored.publicKeyArmor, account.publicArmor)
		XCTAssertEqual(stored.eoa.lowercased(), account.eoa.lowercased())
		// Cold start: the phase is kept, so a repeat does not decrypt again (a garbage backup still succeeds).
		XCTAssertEqual(restoreAsG2(account.eoa, backupBase64: "AAAA", oldPublicArmor: account.publicArmor), .restored)
	}

	/// Two accounts restored one after another (P-1, then P-2): neither overwrites the other, and each reads back its own key.
	/// Deleting one account afterwards leaves the other readable.
	func testTwoAccountsRestoredOneAfterAnotherDoNotOverwriteEachOther() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X19 xcframework not linked in this build")
		let first = try installAccount(0)
		let second = try installAccount(1)
		XCTAssertEqual(restoreAsG2(first.eoa, backupBase64: first.backup, oldPublicArmor: first.publicArmor), .restored)
		XCTAssertEqual(restoreAsG2(second.eoa, backupBase64: second.backup, oldPublicArmor: second.publicArmor), .restored)
		let a = try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: first.eoa))
		let b = try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: second.eoa))
		XCTAssertEqual(a.privateKeyArmor, first.privateArmor)
		XCTAssertEqual(a.publicKeyArmor, first.publicArmor)
		XCTAssertEqual(b.privateKeyArmor, second.privateArmor)
		XCTAssertEqual(b.publicKeyArmor, second.publicArmor)
		XCTAssertNotEqual(a.privateKeyArmor, b.privateKeyArmor)
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: first.eoa), .complete)
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: second.eoa), .complete)
		BeamioChatPgpKeychain.clear(eoa: second.eoa)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: second.eoa))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: first.eoa)?.privateKeyArmor, first.privateArmor)
	}

	/// An old public key of another key stops the restore (identity_mismatch) and stores nothing. A retry with the right
	/// key completes it.
	func testMismatchedOldKeyStopsAndTheRetryCompletes() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X19 xcframework not linked in this build")
		let first = try installAccount(0)
		let second = try installAccount(1)
		XCTAssertEqual(restoreAsG2(first.eoa, backupBase64: first.backup, oldPublicArmor: second.publicArmor),
		               .refused("identity_mismatch"))
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: first.eoa), .restoring)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: first.eoa), "nothing stored after a mismatch")
		XCTAssertEqual(restoreAsG2(first.eoa, backupBase64: first.backup, oldPublicArmor: first.publicArmor), .restored)
		XCTAssertEqual(BeamioPGPMigration.phase(eoa: first.eoa), .complete)
	}
}
#endif
