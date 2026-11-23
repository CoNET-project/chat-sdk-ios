#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// an account whose native key exists but whose page copy is missing. The state must move on: the native side builds the
/// copy from the key, and a read answers the record. A failed store answers `migrating` and the next read retries. Synthetic data only.
final class ReplicaCreationTests: XCTestCase {
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		var failWrite = false

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			if failWrite { return false }
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
	private var device = Device()
	private var account = ""
	private var key: [UInt8] = []
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		// Each case starts with an empty native account pointer (25.52Y.110 第 2 条 (c)); the device flag below is the case's own state.
		NativeAccountPointerIsolation.begin()
		BeamioNativeAccountPointer.clear()
		store = Store()
		device = Device()
		// The account is established on the device (its pointer is set) and its native key exists, but no page copy does.
		device.state.accountEstablished = true
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let eoa = BeamioNativeEthSigner.address(privateKey: derived)
		else { fatalError("the test vector does not derive") }
		account = eoa.lowercased()
		key = derived
		savedNativeStore = BeamioNativeWallet.keyStore
		// A page copy is built for a valid mnemonic account only (v227 section 247.2): the account is the one the test phrase derives, with its mnemonic item.
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: account, key: Data(key))
		_ = nativeStore.writeItem(.mnemonic, eoa: account, value: BeamioPwaWalletSync.normalized(phrase))
		BeamioNativeWallet.keyStore = nativeStore
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

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	private func windowRead(_ reqId: Int) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": reqId], trust: .trusted) { out = $0 }
		return out
	}

	private var expectedArmor: String {
		"0x" + key.map { String(format: "%02x", $0) }.joined()
	}

	/// The stuck state moves on: the first read builds the copy natively and answers `ok`, with the account's key in canonical form.
	func testTheMissingCopyIsBuiltFromTheNativeKeyAndTheReadCompletes() {
		let answer = windowRead(9301)
		XCTAssertEqual(answer["ok"] as? Bool, true)
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "ok", "the read completes instead of migrating")
		let profiles = (result?["record"] as? [String: Any])?["profiles"] as? [[String: Any]]
		XCTAssertEqual(profiles?.first?["keyID"] as? String, account)
		XCTAssertEqual(profiles?.first?["privateKeyArmor"] as? String, expectedArmor, "the key is the native key in canonical form")
		XCTAssertNotNil(store.records[account], "the copy is stored natively")
	}

	/// REP-01 / KR-01 (v2): a key-only orphan (no valid mnemonic) is no account: no copy is built, nothing is derived or written, the orphan key stays.
	func testAKeyOnlyOrphanIsNotReplicated() {
		let orphan = MemoryNativeKeyStore()
		_ = orphan.write(eoa: account, key: Data(key))
		BeamioNativeWallet.keyStore = orphan
		let answer = windowRead(9320)
		let code = (answer["result"] as? [String: Any])?["code"] as? String
		XCTAssertNotEqual(code, "ok", "no copy is built from an orphan key")
		XCTAssertNil(store.records[account], "nothing is written")
		XCTAssertEqual(orphan.keys[account], Data(key), "the orphan key is untouched")
		// the replica builder itself, called directly: absent, nothing written
		let direct = BeamioShellRecord.replicaAnswer(env: BeamioShellRecord.environmentOverride!, account: account, reqId: 9321)
		XCTAssertEqual(direct["code"] as? String, "absent")
		XCTAssertNil(store.records[account])
	}

	/// REP-01 variants: a mnemonic that is readable but does not derive the account, or cannot be read, is not verified: migrating, no copy written, no key derived into a copy.
	func testAMnemonicThatIsNotVerifiedBuildsNoCopy() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.key, eoa: account, value: Data(key))
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(ValidTestAccounts.phraseB.utf8))   // another account's phrase: invalid for this account
		BeamioNativeWallet.keyStore = items
		XCTAssertEqual(BeamioShellRecord.replicaAnswer(env: BeamioShellRecord.environmentOverride!, account: account, reqId: 9322)["code"] as? String, "migrating")
		items.failRead = [.mnemonic]
		XCTAssertEqual(BeamioShellRecord.replicaAnswer(env: BeamioShellRecord.environmentOverride!, account: account, reqId: 9323)["code"] as? String, "migrating")
		XCTAssertNil(store.records[account], "no copy without a verified mnemonic")
	}

	/// After the copy exists, the next read answers the same record (no second build, the state is stable).
	func testASecondReadAnswersTheStoredCopy() {
		_ = windowRead(9302)
		let again = windowRead(9303)
		XCTAssertEqual((again["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 1)
	}

	/// A failed store answers `migrating`, nothing is stored, and the next read, once the store works, completes (retry).
	func testAFailedStoreAnswersMigratingAndTheNextReadRetries() {
		store.failWrite = true
		let failed = windowRead(9304)
		XCTAssertEqual((failed["result"] as? [String: Any])?["code"] as? String, "migrating")
		XCTAssertNil(store.records[account], "a failed store leaves nothing behind")
		store.failWrite = false
		let retried = windowRead(9305)
		XCTAssertEqual((retried["result"] as? [String: Any])?["code"] as? String, "ok", "the retry completes")
		XCTAssertNotNil(store.records[account])
	}

	/// an account with its phrase natively gets the top-level `mnemonicPhrase` in the copy, with the key in canonical form.
	func testAMnemonicAccountGetsItsPhraseInTheCopy() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.key, eoa: account, value: Data(key))
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		BeamioNativeWallet.keyStore = items
		let answer = windowRead(9307)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertEqual(store.records[account]?["mnemonicPhrase"] as? String, phrase)
	}

	/// / reviewer: a phrase that is present but cannot be read is migrating; the copy is not written, and the next read retries.
	func testAnUnreadablePhraseKeepsTheCopyUnwrittenAndAnswersMigrating() {
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.key, eoa: account, value: Data(key))
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		items.failRead = [.mnemonic]
		BeamioNativeWallet.keyStore = items
		let answer = windowRead(9308)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "migrating")
		XCTAssertNil(store.records[account], "no copy without the phrase")
		items.failRead = []
		let retry = windowRead(9309)
		XCTAssertEqual((retry["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertEqual(store.records[account]?["mnemonicPhrase"] as? String, phrase)
	}

	/// An upgraded device: a native key, no page copy, and no device state at all (the state file is absent). The read builds the copy.
	func testAnUpgradedDeviceWithNoStateFileBuildsTheCopy() {
		device.state = BeamioShellRecord.DeviceState()
		let answer = windowRead(9310)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertNotNil(store.records[account])
	}

	/// A write never creates the copy: only the read builds it. A write with no copy is answered as before (not stored).
	func testAWriteDoesNotBuildTheCopy() {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordWrite(["reqId": 9306, "record": ["rev": 0, "schemaVersion": 1]], trust: .trusted) { out = $0 }
		XCTAssertNil(store.records[account], "the page's write path does not create the native copy")
		XCTAssertNotNil(out["ok"])
	}
}
#endif
