#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// (1)(4): a legacy record that still carries PGP private material is read through `shellRecordRead` (the window entry) without
/// any PGP private field leaving the native side, and without the value showing in the answer. Synthetic armor text only.
final class PgpReadStripTests: XCTestCase {
	private let account = PgpMigrationTestSupport.eoa
	private let secretArmor = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nSYNTHETIC-SECRET-0123456789\n-----END PGP PRIVATE KEY BLOCK-----"

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
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private var store = Store()
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		store = Store()
		savedNativeStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	override func tearDown() {
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	private func install() {
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: false,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	/// A legacy record: the PGP private armor sits under `profiles[*].pgpKey` and `profiles[*].chatManager.pgpKey`, and the top-level passphrase.
	private func legacyRecord() -> [String: Any] {
		[
			"rev": 4,
			"schemaVersion": 1,
			"profiles": [[
				"keyID": account,
				"pgpKey": ["privateKeyArmor": secretArmor, "publicKeyArmor": "PUBLIC-ARMOR"],
				"chatManager": ["pgpKey": ["privateKeyArmor": secretArmor, "privateKey": secretArmor]],
			]],
			"pgpPassphrase": "SYNTHETIC-PASS",
			"preferences": ["theme": "dark"],
		]
	}

	/// The window read of a legacy record: the answer carries no PGP private field and no value of one, anywhere in the JSON.
	func testTheReadStripsEveryPGPPrivateFieldAndTheValueNeverShows() throws {
		store.records[account] = legacyRecord()
		install()
		var answer: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": 9201], trust: .trusted) { answer = $0 }
		let data = try JSONSerialization.data(withJSONObject: answer, options: [])
		let text = String(decoding: data, as: UTF8.self)
		XCTAssertFalse(text.contains("SYNTHETIC-SECRET"), "the PGP armor value never leaves the native side")
		XCTAssertFalse(text.contains("SYNTHETIC-PASS"), "the passphrase never leaves")
		XCTAssertFalse(text.contains("BEGIN PGP PRIVATE"), "no PGP private header leaves")
		let profile = ((answer["result"] as? [String: Any])?["record"] as? [String: Any])?["profiles"] as? [[String: Any]]
		XCTAssertNil(profile?.first?["pgpKey"], "the profile's PGP object is stripped")
		XCTAssertNil(profile?.first?["chatManager"], "a chat manager with only the PGP key is removed")
		XCTAssertEqual(((answer["result"] as? [String: Any])?["record"] as? [String: Any])?["preferences"] as? [String: String], ["theme": "dark"], "other fields are read as before")
	}

	/// 1: the spec's list also names `profile.pgpPrivateKeyArmored` and `chatManager.pgpKey.privateKeyObj`; neither leaves the native side.
	func testTheSpecListFieldsAreStrippedToo() throws {
		var record = legacyRecord()
		var profile = (record["profiles"] as? [[String: Any]])?.first ?? [:]
		profile["pgpPrivateKeyArmored"] = secretArmor
		profile["chatManager"] = ["pgpKey": ["privateKeyObj": secretArmor, "publicKeyArmor": "PUBLIC-ARMOR"], "name": "chat"]
		record["profiles"] = [profile]
		store.records[account] = record
		install()
		var answer: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": 9203], trust: .trusted) { answer = $0 }
		let data = try JSONSerialization.data(withJSONObject: answer, options: [])
		let text = String(decoding: data, as: UTF8.self)
		XCTAssertFalse(text.contains("SYNTHETIC-SECRET"), "no PGP private value leaves, in any listed field")
		let out = (answer["result"] as? [String: Any])?["record"] as? [String: Any]
		let outProfile = (out?["profiles"] as? [[String: Any]])?.first
		XCTAssertNil(outProfile?["pgpPrivateKeyArmored"])
		XCTAssertEqual((outProfile?["chatManager"] as? [String: Any])?["name"] as? String, "chat", "the chat manager's other fields stay")
	}

	/// A PGP private header left on a path the stripping does not reach closes the read: the answer is an error, and the value does not leave.
	func testAPGPHeaderOnAnUnstrippedPathClosesTheRead() throws {
		var record = legacyRecord()
		record["note"] = secretArmor
		store.records[account] = record
		install()
		var answer: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": 9202], trust: .trusted) { answer = $0 }
		let data = try JSONSerialization.data(withJSONObject: answer, options: [])
		let text = String(decoding: data, as: UTF8.self)
		XCTAssertFalse(text.contains("SYNTHETIC-SECRET"), "the record is not answered, so the armor does not leave")
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "error")
		XCTAssertEqual((answer["result"] as? [String: Any])?["sub"] as? String, "record_unreadable")
	}
}
#endif
