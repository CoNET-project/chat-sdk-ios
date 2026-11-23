#if BEAMIO_TEST_HOOKS
import Foundation
import XCTest
@testable import ConetChatSDK

/// 25.52Y.99 第 4 至 6 项: a flag repair on the read path that does not persist is never a success. The answer is
/// `ok:true`, `result.code = "error"`, `result.sub = "record_unreadable"`, the record is kept, and no write or delete follows.
/// Synthetic keys only: the test phrase is the BIP-39 vector.
final class ShellReadFlagRepairTests: XCTestCase {
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

	/// A device state whose writes do not persist.
	private final class FailingDevice: BeamioShellRecord.DeviceStateStore {
		var state: BeamioShellRecord.DeviceState
		init(_ state: BeamioShellRecord.DeviceState) { self.state = state }
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { false }
	}

	/// A device state whose writes persist.
	private final class PersistingDevice: BeamioShellRecord.DeviceStateStore {
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

	private func installKey() {
		let nativeStore = MemoryNativeKeyStore()
		_ = nativeStore.write(eoa: account, key: Data(key))
		// the account is on the device by its mnemonic (the mnemonic ownership rule, Y.163 items 31 and 32): the phrase of this file derives it
		_ = nativeStore.writeItem(.mnemonic, eoa: account, value: BeamioPwaWalletSync.normalized(phrase))
		BeamioNativeWallet.keyStore = nativeStore
	}

	private func environment(_ page: PageStore, device: BeamioShellRecord.DeviceStateStore) {
		let owner = account
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { owner }, store: page, device: device, originAllowed: false,
			migrating: { _ in false }, firstRun: { _ in .confirmedAbsent }, locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved, gate: { .g2 }, creationMode: { false }
		)
	}

	private func windowRead(_ reqId: Int) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": reqId], trust: .trusted) { out = $0 }
		return out
	}

	/// A readable record that owns the account: the device would take `accountEstablished` from it, so the repair must persist.
	private var ownedRecord: [String: Any] {
		[BeamioShellRecord.revKey: 1, "schemaVersion": 1, "profiles": [["keyID": account]]]
	}

	func testAFlagRepairThatDoesNotPersistAnswersRecordUnreadableAndKeepsTheRecord() {
		installKey()
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatSignBroker.setSignerEoa(account)
		let page = PageStore()
		page.result = .record(ownedRecord)
		environment(page, device: FailingDevice(BeamioShellRecord.DeviceState()))

		let answer = windowRead(41)
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(answer["ok"] as? Bool, true, "the envelope is ok: the read was judged")
		XCTAssertEqual(result?["code"] as? String, "error")
		XCTAssertEqual(result?["sub"] as? String, "record_unreadable")
		XCTAssertNil(result?["record"], "the record is not returned")
		XCTAssertEqual(page.writes, 0, "the read path writes nothing and deletes nothing")
	}

	func testTheSameRepairThatPersistsStillAnswersOk() {
		installKey()
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatSignBroker.setSignerEoa(account)
		let page = PageStore()
		page.result = .record(ownedRecord)
		environment(page, device: PersistingDevice())

		let answer = windowRead(42)
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "ok")
		XCTAssertNil(result?["sub"])
	}

	func testTheConfirmedAbsenceRepairThatDoesNotPersistAnswersRecordUnreadable() {
		installKey()
		var state = BeamioShellRecord.DeviceState()
		state.legacyConfirmedAbsent = true
		let page = PageStore()
		page.result = .absent
		environment(page, device: FailingDevice(state))

		let answer = windowRead(43)
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "error")
		XCTAssertEqual(result?["sub"] as? String, "record_unreadable")
		XCTAssertNotEqual(result?["sub"] as? String, "clear_incomplete")
		XCTAssertNotEqual(result?["code"] as? String, "write_failed")
		XCTAssertEqual(page.writes, 0)
	}
}
#endif
