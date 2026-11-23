#if BEAMIO_TEST_HOOKS
import Foundation
import XCTest
@testable import ConetChatSDK

/// PY.19 (ruling B): an unreadable report does not latch an established account; it latches only a device whose account is not established.
/// The normal read path answers replicaAnswer for a readable key with no copy, and needs_native_recovery for an unreadable key. Synthetic keys only.
final class ShellEstablishedUnreadableTests: XCTestCase {
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var account = ""
	private var key: [UInt8] = []
	private var savedKeyStore: BeamioChatWalletKeyStoring?

	private final class PageStore: BeamioShellRecord.ShellRecordStore {
		var result: BeamioShellRecord.ShellRecordRead = .absent
		var writes = 0
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { result }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { writes += 1; return true }
		func hasAnyRecord() -> Bool { if case .absent = result { return false }; return true }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let eoa = BeamioNativeEthSigner.address(privateKey: derived)?.lowercased()
		else { fatalError("the test vector does not derive") }
		account = eoa
		key = derived
		savedKeyStore = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = savedKeyStore ?? BeamioPasscodeWalletStore.standard
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeAccountPointer.clear()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private var armor: String { "0x" + key.map { String(format: "%02x", $0) }.joined() }

	/// `withMnemonic`: also the mnemonic item of the account (the phrase of this file derives it). Since the mnemonic ownership rule (Y.163 items 31 and 32) a key alone is no account:
	/// the tests that need the account on the device ask for the mnemonic.
	private func installKey(withMnemonic: Bool = false) {
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: account, key: Data(key))
		if withMnemonic { _ = nativeStore.writeItem(.mnemonic, eoa: account, value: BeamioPwaWalletSync.normalized(phrase)) }
		BeamioNativeWallet.keyStore = nativeStore
	}

	private func environment(_ page: PageStore, device: Device, account: String?) {
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { account }, store: page, device: device, originAllowed: false,
			migrating: { _ in false }, firstRun: { _ in .confirmedAbsent }, locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { .g2 }, creationMode: { false }
		)
	}

	private func windowRead(_ reqId: Int) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": reqId], trust: .trusted) { out = $0 }
		return out
	}

	/// An established account: pointer set, the copy readable, its EOA equal to the keychain's current account.
	func testAnEstablishedAccountDoesNotLatchOnAnUnreadableReportAndReadsOk() {
		installKey()
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatSignBroker.setSignerEoa(account)
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		let device = Device()
		device.state.accountEstablished = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: page), .ok, "saved, not a failure")
		XCTAssertFalse(device.state.legacyUnreadable, "an established account is not latched")
		XCTAssertEqual(device.state.legacyReportValue, "unreadable", "the report value is saved")
		XCTAssertFalse(BeamioShellRecord.isLegacyReportWriteFailed)
		environment(page, device: device, account: account)
		XCTAssertEqual((windowRead(9601)["result"] as? [String: Any])?["code"] as? String, "ok", "the read goes on to the home")
	}

	/// An account that is not established: an unreadable report latches the device; the read is an error legacy_store_unreadable (E9.11.29 r2, K.3),
	/// no account is created, and the key stays.
	func testAnUnestablishedAccountLatchesOnAnUnreadableReportAndReadsLegacyStoreUnreadable() {
		installKey()
		let page = PageStore()
		let device = Device()
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: page), .ok)
		XCTAssertTrue(device.state.legacyUnreadable, "the latch is for an account that is not established")
		environment(page, device: device, account: account)
		let answer = windowRead(9602)["result"] as? [String: Any]
		XCTAssertEqual(answer?["code"] as? String, "error")
		XCTAssertEqual(answer?["sub"] as? String, "legacy_store_unreadable")
		XCTAssertEqual(page.writes, 0, "no account copy is created from the unreadable state")
		XCTAssertTrue(BeamioNativeWallet.hasKey(eoa: account), "the key is not deleted")
	}

	/// The normal read path: a readable key of the account with no copy builds the copy from the key (replicaAnswer), the EOA equal to the keychain.
	func testAReadableKeyWithNoCopyBuildsTheCopyInTheNormalRead() {
		installKey(withMnemonic: true)   // a page copy is built for a valid mnemonic account only (v227 section 247.2)
		let page = PageStore()
		let device = Device()
		device.state.accountEstablished = true
		environment(page, device: device, account: account)
		let result = windowRead(9603)["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "ok")
		let profile = ((result?["record"] as? [String: Any])?["profiles"] as? [[String: Any]])?.first
		XCTAssertEqual(profile?["keyID"] as? String, account, "the copy's EOA equals the keychain account")
		XCTAssertEqual(profile?["privateKeyArmor"] as? String, armor)
	}

	/// The normal read path: a key record of the account that cannot be read answers needs_native_recovery, never a creation.
	func testAnUnreadableKeyInTheNormalReadNeedsNativeRecovery() {
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: account, key: Data(repeating: 0x11, count: 5))
		_ = nativeStore.writeItem(.mnemonic, eoa: account, value: BeamioPwaWalletSync.normalized(phrase))   // the account is on the device by its mnemonic; its key record is damaged
		BeamioNativeWallet.keyStore = nativeStore
		let page = PageStore()
		let device = Device()
		device.state.accountEstablished = true
		environment(page, device: device, account: account)
		let answer = windowRead(9604)
		let sub = (answer["result"] as? [String: Any])?["sub"] as? String ?? answer["error"] as? String
		XCTAssertEqual(sub, "needs_native_recovery")
		XCTAssertEqual(page.writes, 0)
	}

	/// A keychain whose records are locked: the account is named, but no key can be read.
	private final class LockedKeyStore: BeamioChatWalletKeyStoring {
		let inner = MemoryNativeKeyStore()
		func write(eoa: String, key: Data) -> Bool { inner.write(eoa: eoa, key: key) }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) { inner.delete(eoa: eoa) }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .present }
		func hasAnyKeyRecord() -> Bool { inner.hasAnyKeyRecord() }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { inner.keys.keys.map { .locked(eoa: $0) } }
		/// The attributes still name the owner while locked: the owner is read without a key.
		func enumerateKeyOwners() -> [String]? { Array(inner.keys.keys) }
		// the mnemonic ownership rule (Y.163 items 31 and 32): the locked record is a valid account by its header
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
	}

	/// PY.17: the locked case: the attributes name the account while locked, so the timeout judgement matches by the attribute, with no unwrap.
	func testALockedKeychainMatchesByTheAttributes() {
		let locked = LockedKeyStore()
		_ = locked.write(eoa: account, key: Data(key))
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = locked
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: page), .readable(eoaMatchesKeychain: true))
	}

	/// PY.19: an established account with a latched unreadable flag from earlier does not block the write; the write guard is for an unestablished account.
	func testAnEstablishedAccountIsNotBlockedByTheUnreadableFlagForWrites() {
		installKey()
		BeamioNativeAccountPointer.set(account)
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		let device = Device()
		device.state.accountEstablished = true
		device.state.legacyUnreadable = true
		environment(page, device: device, account: account)
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordWrite(["reqId": 9605, "record": ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]]], trust: .trusted) { out = $0 }
		let code = (out["result"] as? [String: Any])?["code"] as? String ?? out["error"] as? String
		XCTAssertNotEqual(code, "migrating", "the unreadable flag does not block the established account's write")
	}

	/// PY.19: an unestablished account with the unreadable flag: the write is migrating (the latch holds).
	func testAnUnestablishedAccountIsBlockedByTheUnreadableFlagForWrites() {
		installKey()
		let page = PageStore()
		let device = Device()
		device.state.legacyUnreadable = true
		environment(page, device: device, account: account)
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordWrite(["reqId": 9606, "record": ["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]]], trust: .trusted) { out = $0 }
		XCTAssertEqual((out["result"] as? [String: Any])?["code"] as? String, "migrating")
		XCTAssertEqual(page.writes, 0)
	}

	/// no session is started (the session signer is empty). The keychain state names the account, so an established
	/// account's unreadable report (the read timeout) does not latch, and the read goes on to the home.
	func testAColdStartEstablishedAccountWithAnUnreadableReportGoesHome() {
		installKey()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeAccountPointer.set(account)
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		let device = Device()
		device.state.accountEstablished = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: page), .ok)
		XCTAssertFalse(device.state.legacyUnreadable, "the cold start does not latch an established account")
		environment(page, device: device, account: account)
		XCTAssertEqual((windowRead(9607)["result"] as? [String: Any])?["code"] as? String, "ok", "the read goes on to the home")
	}

	/// The keychain state cannot be enumerated (the address is not readable): the account is unknown, so the copy is not a match and
	/// the report is not an established account's; the read fails closed (no record is created and the key stays).
	func testAnUnenumerableKeychainFailsClosedAndKeepsTheKey() {
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: account, key: Data(key))
		let unenumerable = UnenumerableKeyStore(inner: nativeStore)
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = unenumerable
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		BeamioNativeAccountPointer.set(account)
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: page), .readable(eoaMatchesKeychain: false))
		XCTAssertTrue(nativeStore.keys[account] != nil, "the key is not deleted")
	}

	/// A store that cannot enumerate its records (fail closed), delegating the rest to a memory store.
	private final class UnenumerableKeyStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { nil }
		let inner: MemoryNativeKeyStore
		init(inner: MemoryNativeKeyStore) { self.inner = inner }
		func write(eoa: String, key: Data) -> Bool { inner.write(eoa: eoa, key: key) }
		func read(eoa: String) -> Data? { inner.read(eoa: eoa) }
		func delete(eoa: String) { inner.delete(eoa: eoa) }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { inner.keyRecordState(eoa: eoa) }
		func hasAnyKeyRecord() -> Bool { inner.hasAnyKeyRecord() }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { nil }
	}

	/// the positive cold-start case: the keychain holds the account, no session is started (the session signer is empty), and the
	/// copy's EOA and key match the keychain account: readable(true). The cold-start deviation is gone.
	func testAColdStartKeychainAccountMatchesWithoutASession() {
		installKey(withMnemonic: true)
		BeamioConetChatSignBroker.clearSigner()
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: page), .readable(eoaMatchesKeychain: true))
	}

	/// A store that counts every key read and every entry check. The timeout judgement must use the attributes only.
	private final class CountingStore: BeamioChatWalletKeyStoring {
		let inner = MemoryNativeKeyStore()
		var reads = 0
		var entryChecks = 0
		var owners: [String]?
		func write(eoa: String, key: Data) -> Bool { inner.write(eoa: eoa, key: key) }
		func read(eoa: String) -> Data? { reads += 1; return inner.read(eoa: eoa) }
		func delete(eoa: String) { inner.delete(eoa: eoa) }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .present }
		func hasAnyKeyRecord() -> Bool { inner.hasAnyKeyRecord() }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { entryChecks += 1; return nil }
		func enumerateKeyOwners() -> [String]? { owners }
		// the mnemonic ownership rule (Y.163 items 31 and 32): the account list is the owners; listing is not a key read and is not counted
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { owners?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (owners ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
	}

	/// the timeout judgement uses the record attributes only: no key read, no entry check (no unwrap), and it matches.
	func testTheTimeoutJudgementReadsNoKeyRecordAndMatchesByTheAttributes() {
		let counting = CountingStore()
		counting.owners = [account]
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = counting
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: page), .readable(eoaMatchesKeychain: true))
		XCTAssertEqual(counting.reads, 0, "no key record is read")
		XCTAssertEqual(counting.entryChecks, 0, "no record is checked (no unwrap)")
	}

	/// a record whose attributes do not name the owner gives no match (fail closed).
	func testAnAttributeWithoutTheOwnerIsNotAMatch() {
		let counting = CountingStore()
		counting.owners = nil
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = counting
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: page), .readable(eoaMatchesKeychain: false))
	}

	/// the attribute owner differs from the copy's EOA: not a match.
	func testAnOwnerDifferentFromTheCopyIsNotAMatch() {
		let counting = CountingStore()
		counting.owners = ["0x0000000000000000000000000000000000000033"]
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = counting
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: page), .readable(eoaMatchesKeychain: false))
	}

	///: the timeout judgement, with the product keychain store, does not reach the key-record entry checks (no unwrap, no blob read).
	func testTheTimeoutJudgementWithTheProductStoreReachesNoEntryCheck() {
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		BeamioKeychainCounters.reset()
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		_ = BeamioShellRecord.pageCopyState(eoa: account, store: page)
		XCTAssertEqual(BeamioKeychainCounters.entryChecks, 0, "no key record is checked on the timeout path")
		XCTAssertEqual(BeamioKeychainCounters.entryEnumerations, 0, "the entry enumeration is not used on the timeout path")
	}

	///: a pointer-set device whose keychain account cannot be named keeps the unreadable state in memory only (not persisted),
	/// and a read is migrating; once the copy matches the keychain account, the next read entry clears it and the read goes on.
	func testAnUnnamedKeychainKeepsTheUnreadableStateInMemoryOnlyAndReJudges() {
		let savedStore = BeamioNativeWallet.keyStore
		let empty = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = empty
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard; BeamioShellRecord.setSessionUnreadable(false) }
		BeamioNativeAccountPointer.set(account)
		let page = PageStore()
		page.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": armor]]])
		let device = Device()
		device.state.accountEstablished = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device, store: page), .ok)
		XCTAssertFalse(device.state.legacyUnreadable, "not persisted into the device state")
		XCTAssertTrue(BeamioShellRecord.isSessionUnreadable, "held in memory")
		environment(page, device: device, account: account)
		// An established account's read is not blocked by the unreadable state (PY.19): the read goes on.
		XCTAssertEqual((windowRead(9608)["result"] as? [String: Any])?["code"] as? String, "ok")
		// The keychain now names the account (unlocked / readable): the next read entry re-judges and clears the in-memory state.
		_ = empty.write(eoa: account, key: Data(key))
		_ = empty.writeItem(.mnemonic, eoa: account, value: BeamioPwaWalletSync.normalized(phrase))
		XCTAssertEqual((windowRead(9609)["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertFalse(BeamioShellRecord.isSessionUnreadable, "re-judged and cleared once the keychain names the account")
	}
}
#endif
