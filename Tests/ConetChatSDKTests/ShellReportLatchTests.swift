#if BEAMIO_TEST_HOOKS
import Foundation
import XCTest
@testable import ConetChatSDK

/// PY.15 11: while the last legacy report is not written, every read answers migrating, at the entry of the read command.
/// A real tampered read back is judged `write_failed`. Synthetic data only; no key is read (the latch answers before any key).
final class ShellReportLatchTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { true }
		func hasAnyRecord() -> Bool { false }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let account = "0x0000000000000000000000000000000000000009"
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		savedNativeStore = BeamioNativeWallet.keyStore
		BeamioShellRecord.setLegacyReportWriteFailed(true)
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		BeamioShellRecord.environmentOverride = nil
		BeamioShellRecord.FileDeviceStateStore.afterWriteHook = nil
		super.tearDown()
	}

	private func environment(account: String?, gate: BeamioConetChatModule.NativeGate, creation: Bool, device: Device = Device()) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { account },
			store: Store(),
			device: device,
			originAllowed: false,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved,
			gate: { gate },
			creationMode: { creation }
		)
	}

	private func windowRead(_ reqId: Int) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": reqId], trust: .trusted) { out = $0 }
		return out
	}

	private func code(_ reqId: Int) -> String? {
		(windowRead(reqId)["result"] as? [String: Any])?["code"] as? String
	}

	/// The creation-mode read answers migrating while the latch is set (not the pending account's absent).
	func testTheCreationModeReadIsMigratingWhileTheLatchIsSet() {
		BeamioShellRecord.environmentOverride = environment(account: nil, gate: .g0, creation: true)
		XCTAssertEqual(code(9501), "migrating")
	}

	/// G0 with no account known: the reader's no-account branch answers migrating while the latch is set.
	func testTheG0ReadWithNoAccountIsMigratingWhileTheLatchIsSet() {
		BeamioShellRecord.environmentOverride = environment(account: nil, gate: .g0, creation: false)
		XCTAssertEqual(code(9502), "migrating")
	}

	/// G0 with an account and no imported copy: the reader's G0 branch answers migrating while the latch is set.
	func testTheG0ReadWithAnAccountIsMigratingWhileTheLatchIsSet() {
		BeamioShellRecord.environmentOverride = environment(account: account, gate: .g0, creation: false)
		XCTAssertEqual(code(9503), "migrating")
	}

	/// Clearing the latch (a written report) removes the migrating answer's cause: the flag is clear, and only the reader decides again.
	func testAClearedLatchIsClear() {
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		XCTAssertFalse(BeamioShellRecord.isLegacyReportWriteFailed)
	}

	/// A real tampered read back: the write lands, then the file is changed before the read back. The write is not confirmed: write_failed.
	func testATamperedReadBackIsWriteFailed() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("shell-tamper-\(UUID().uuidString)", isDirectory: true)
		defer { try? FileManager.default.removeItem(at: root) }
		let url = root.appendingPathComponent("device-state.json")
		let store = BeamioShellRecord.FileDeviceStateStore(url: url)
		BeamioShellRecord.FileDeviceStateStore.afterWriteHook = { written in
			let other: [String: Any] = ["accountEstablished": false, "legacyUnreadable": false, "legacyConfirmedAbsent": false, "legacyFound": true]
			let data = try! JSONSerialization.data(withJSONObject: other, options: [.sortedKeys])
			try! data.write(to: written)
		}
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		let result = BeamioShellRecord.reportLegacyStore(.unreadable, device: store)
		XCTAssertEqual(result, .writeFailed)
		XCTAssertTrue(BeamioShellRecord.isLegacyReportWriteFailed)
		// The stored file is the tampered one: the new state did not read back, so nothing is confirmed.
		XCTAssertTrue(store.load().legacyFound)
		XCTAssertFalse(store.load().legacyUnreadable)
	}

	/// PY.15 4 (project ruling): an absence reported while a native key record exists is saved and answers ok. The read still does not answer
	/// absent, and no account is created from the report: the key in the native store answers the copy (replicaAnswer), never a creation.
	func testAnAbsentWithANativeRecordIsSavedAndAnswersOkAndTheReadDoesNotAnswerAbsent() {
		let nativeStore = MemoryNativeKeyStore()
		let key = Data(repeating: 0x11, count: 32)
		_ = nativeStore.write(eoa: account, key: key)
		BeamioNativeWallet.keyStore = nativeStore
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		let device = Device()
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.absent, device: device), .ok, "saved, not bad_request")
		XCTAssertTrue(device.state.legacyConfirmedAbsent, "the recent report is saved")
		XCTAssertFalse(device.state.accountEstablished, "the report does not change the resolved account state")
		BeamioShellRecord.environmentOverride = environment(account: account, gate: .g0, creation: false, device: device)
		let code = (windowRead(9510)["result"] as? [String: Any])?["code"] as? String
		XCTAssertNotEqual(code, "absent", "a native record is never answered absent")
		XCTAssertNotEqual(code, "error", "the read is judged, not refused by the report")
	}

	/// PY.15 4 (project ruling): an account pointer that is already set, outside the creation mode, saves the report and answers ok.
	/// The resolved state is unchanged and nothing is imported.
	func testAReportWithAnEstablishedPointerIsSavedAndAnswersOk() {
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		let device = Device()
		device.state.accountEstablished = true
		XCTAssertEqual(BeamioShellRecord.reportLegacyStore(.unreadable, device: device, creation: false), .ok)
		XCTAssertTrue(device.state.legacyUnreadable, "saved")
		XCTAssertTrue(device.state.accountEstablished, "the resolved account state is unchanged")
		XCTAssertFalse(device.state.legacyFound, "nothing is imported")
	}

	/// PY.15 11: the G1 gate does not bypass the latch: the read is migrating, not not_ready.
	func testTheG1ReadIsMigratingWhileTheLatchIsSet() {
		BeamioShellRecord.environmentOverride = environment(account: account, gate: .g1, creation: false)
		XCTAssertEqual(code(9505), "migrating")
	}

	/// PY.15 11: every read entry is covered by the latch. A write is not a read entry and is not changed here.
	func testTheLatchCoversTheWindowReadEntryForEveryBranch() {
		BeamioShellRecord.environmentOverride = environment(account: nil, gate: .g0, creation: true)
		XCTAssertEqual(code(9506), "migrating", "creation mode")
		BeamioShellRecord.environmentOverride = environment(account: nil, gate: .g0, creation: false)
		XCTAssertEqual(code(9507), "migrating", "G0 without account")
		BeamioShellRecord.environmentOverride = environment(account: account, gate: .g0, creation: false)
		XCTAssertEqual(code(9508), "migrating", "G0 without copy")
		BeamioShellRecord.environmentOverride = environment(account: account, gate: .g2, creation: false)
		XCTAssertEqual(code(9509), "migrating", "account branch")
	}

	/// PY.18: a creation read with a native key present and a saved absent is never absent (the report alone does not admit).
	func testACreationReadWithANativeKeyIsNeverAbsentAfterASavedAbsent() {
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		let nativeStore = MemoryNativeKeyStore()
		ValidTestAccounts.install(nativeStore)   // a valid account on the device: a key alone is no record (Y.163 items 31 and 32)
		BeamioNativeWallet.keyStore = nativeStore
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.environmentOverride = environment(account: nil, gate: .g0, creation: true, device: device)
		let answer = (windowRead(9511)["result"] as? [String: Any])?["code"] as? String
		XCTAssertNotEqual(answer, "absent", "a key on the device is never a creation")
		XCTAssertEqual(answer, "migrating")
	}

	/// PY.18: the three empty conditions admit the creation read as absent (the legacy store confirmed empty, no pointer, no key, no copy).
	func testTheThreeEmptyConditionsAdmitTheCreationReadAsAbsent() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		BeamioNativeAccountPointer.clear()
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.environmentOverride = environment(account: nil, gate: .g0, creation: true, device: device)
		XCTAssertEqual(BeamioShellRecord.creationRefusal(device: device.state, store: Store()), nil)
		XCTAssertEqual((windowRead(9512)["result"] as? [String: Any])?["code"] as? String, "absent")
	}

	/// PY.18: a set pointer refuses the creation admission; a latched write failure refuses it too.
	func testAPointerOrALatchRefusesTheCreationAdmission() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(BeamioShellRecord.creationRefusal(device: device.state, store: Store()), "pointer_set")
		BeamioNativeAccountPointer.clear()
		BeamioShellRecord.setLegacyReportWriteFailed(true)
		XCTAssertEqual(BeamioShellRecord.creationRefusal(device: device.state, store: Store()), "report_write_failed")
		BeamioShellRecord.setLegacyReportWriteFailed(false)
	}

	/// PY.17: the input must equal the keychain state's current account. The keychain holds the key of account A; the input is B: not a match.
	func testAnInputDifferentFromTheKeychainAccountIsNotAMatch() {
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
		      let keychainAccount = BeamioNativeEthSigner.address(privateKey: derived)?.lowercased()
		else { return XCTFail("the vector does not derive") }
		let otherAccount = "0x0000000000000000000000000000000000000022"
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: keychainAccount, key: Data(derived))
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = nativeStore
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let store = PageStore()
		store.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": otherAccount, "privateKeyArmor": "0x" + String(repeating: "22", count: 32)]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: otherAccount, store: store), .readable(eoaMatchesKeychain: false))
	}

	/// PY.17: the unlocked case: the keychain's account is the input, the copy's EOA is the input, and the key matches: a match.
	func testAnUnlockedKeychainAccountMatchesTheCopy() {
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
		      let eoa = BeamioNativeEthSigner.address(privateKey: derived)?.lowercased()
		else { return XCTFail("the vector does not derive") }
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: eoa, key: Data(derived))
		// the account is on the device by its mnemonic (the mnemonic ownership rule, Y.163 items 31 and 32): the phrase above derives it
		_ = nativeStore.writeItem(.mnemonic, eoa: eoa, value: BeamioPwaWalletSync.normalized("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = nativeStore
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let store = PageStore()
		store.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": eoa, "privateKeyArmor": "0x" + derived.map { String(format: "%02x", $0) }.joined()]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: eoa, store: store), .readable(eoaMatchesKeychain: true))
	}

	/// PY.17: the cold start, before any record is read: no keychain account, so the copy is not a match (fail closed).
	func testAColdStartWithNoKeychainAccountIsNotAMatch() {
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		defer { BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard }
		let store = PageStore()
		store.result = .record(["rev": 1, "schemaVersion": 2, "profiles": [["keyID": account, "privateKeyArmor": "0x" + String(repeating: "11", count: 32)]]])
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: account, store: store), .readable(eoaMatchesKeychain: false))
	}

	/// PY.17: an empty pointer input fails closed (unreadable), never absent and never matching.
	func testAnEmptyPointerInputFailsClosed() {
		XCTAssertEqual(BeamioShellRecord.pageCopyState(eoa: "", store: PageStore()), .unreadable)
	}

	private final class PageStore: BeamioShellRecord.ShellRecordStore {
		var result: BeamioShellRecord.ShellRecordRead = .absent
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { result }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { true }
		func hasAnyRecord() -> Bool { false }
	}

	/// a readable key of the account, with the latch clear, saved absent and creation mode: the copy is built from the key, never absent.
	/// PY.19 第 1 项 (interface ruling 5.59): the creation read never builds a copy from a key; any native key is migrating.
	func testAReadableKeyInTheCreationReadIsMigratingAndNeverAbsent() throws {
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		// A real key: the account is the address derived from the key (the unchecked read requires it).
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
		      let eoa = BeamioNativeEthSigner.address(privateKey: derived)?.lowercased()
		else { throw XCTSkip("the test vector does not derive") }
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: eoa, key: Data(derived))
		_ = nativeStore.writeItem(.mnemonic, eoa: eoa, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA))   // the account is on the device by its mnemonic (Y.163 items 31 and 32)
		BeamioNativeWallet.keyStore = nativeStore
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.environmentOverride = environment(account: eoa, gate: .g0, creation: true, device: device)
		let answer = windowRead(9513)
		let code = (answer["result"] as? [String: Any])?["code"] as? String
		XCTAssertNotEqual(code, "absent")
		XCTAssertEqual(code, "migrating", "a native key in the creation read is migrating (PY.19 1); replicaAnswer is not called")
	}

	/// a key of the account that cannot be read answers needs_native_recovery, never absent and never a creation.
	func testAnUnreadableKeyInTheCreationReadIsMigratingNotNativeRecovery() {
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		let nativeStore = MemoryNativeKeyStore()
		// an account on the device by its mnemonic, whose key record cannot be read (5 bytes): a key alone would be no record (Y.163 items 31 and 32)
		let acct = ValidTestAccounts.accountA
		_ = nativeStore.write(eoa: acct.eoa, key: Data(repeating: 0x11, count: 5))
		_ = nativeStore.writeItem(.mnemonic, eoa: acct.eoa, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA))
		BeamioNativeWallet.keyStore = nativeStore
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.environmentOverride = environment(account: acct.eoa, gate: .g0, creation: true, device: device)
		let answer = windowRead(9514)
		let sub = (answer["result"] as? [String: Any])?["sub"] as? String ?? (answer["error"] as? String)
		XCTAssertNotEqual((answer["result"] as? [String: Any])?["code"] as? String, "absent")
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "migrating", "PY.19 1: an unreadable key is migrating in the creation read")
		XCTAssertNil(sub, "no needs_native_recovery leaves the creation read")
	}
}
#endif
