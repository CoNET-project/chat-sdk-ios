#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// 第 8 項 with: the window entries `BeamioWindowWallet.shellRecordRead` and `shellRecordWrite` answer the
/// split of. Status answers (`absent`, `migrating`, `too_large`) and storage errors (`storage_locked`, `record_unreadable`) are
/// `ok:true` with `result.code` (`error` plus `result.sub` for the storage errors). Envelope failures are `ok:false` with `error`.
/// The production environment is replaced through `BeamioShellRecord.environmentOverride` (test builds only); nothing reaches the Keychain.
/// Synthetic data only.
final class ShellRecordWindowAnswerTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		var unreadable = false

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			if unreadable { return .unreadable }
			return records[account].map { .record($0) } ?? .absent
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

	private let account = PgpMigrationTestSupport.eoa
	private var store = Store()
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		NativeAccountPointerIsolation.begin()
		super.setUp()
		store = Store()
		savedNativeStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	/// The record environment for the window entries: the account is established (`confirmedAbsent`), the store is locked or migrating as the
	/// test says. The origin inside the entries is the shell's `trusted`, so the environment's own origin flag is irrelevant here.
	private func install(locked: Bool = false, migrating: Bool = false) {
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: device,
			originAllowed: false,
			migrating: { _ in migrating },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in locked },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	/// One answer of the window entry. The entries answer synchronously.
	private func windowRead(_ body: [String: Any]) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(body, trust: .trusted) { out = $0 }
		return out
	}

	private func windowWrite(_ body: [String: Any]) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordWrite(body, trust: .trusted) { out = $0 }
		return out
	}

	/// Status answer: an account with no record reads `absent`, as `ok:true` with `result.code`.
	func testAbsentIsAnOkResultCode() {
		install()
		let answer = windowRead(["reqId": 9101])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertNil(answer["error"], "absent is not an envelope failure")
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "absent")
	}

	/// Status answer: a migrating store answers `migrating` as `ok:true` with `result.code`.
	func testMigratingIsAnOkResultCode() {
		install(migrating: true)
		let answer = windowRead(["reqId": 9102])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertNil(answer["error"])
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "migrating")
	}

	/// a passcode record whose bundle has not been provided answers `not_ready` with the reason `passcode_not_provided`, `ok:true`, in `result`.
	func testAMissingPasscodeBundleIsNotReadyWithItsReason() {
		store.records[account] = ["rev": 1, "schemaVersion": 1]
		install(locked: true)
		let answer = windowRead(["reqId": 9103])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertNil(answer["error"], "a storage error is not an envelope failure")
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "passcode_not_provided")
		XCTAssertEqual(result?["retryable"] as? Bool, true)
	}

	/// Storage error: an unreadable record answers `record_unreadable` the same way.
	func testRecordUnreadableIsResultCodeErrorWithSub() {
		store.unreadable = true
		install()
		let answer = windowRead(["reqId": 9104])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertNil(answer["error"])
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "error")
		XCTAssertEqual(result?["sub"] as? String, "record_unreadable")
	}

	/// Status answer: a record larger than the limit answers `too_large` as `ok:true` with `result.code`, not as an envelope.
	func testTooLargeIsAnOkResultCode() {
		var record: [String: Any] = ["rev": 1, "schemaVersion": 1]
		record["padding"] = String(repeating: "x", count: BeamioShellRecord.sizeLimit + 1024)
		store.records[account] = record
		install()
		let answer = windowRead(["reqId": 9105])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertNil(answer["error"], "too_large is a status answer, not an envelope failure")
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "too_large")
	}

	/// The window write answers a status the same way: a migrating store is `ok:true` with `result.code` `migrating`.
	func testWriteMigratingIsAnOkResultCode() {
		install(migrating: true)
		let answer = windowWrite(["reqId": 9106, "record": ["rev": 0, "schemaVersion": 1]])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertNil(answer["error"])
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "migrating")
	}

	/// The envelope failures stay envelopes: an untrusted call is `origin_refused` with `ok:false`.
	func testUntrustedCallStaysAnEnvelopeFailure() {
		install()
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": 9107], trust: .originRefused) { out = $0 }
		XCTAssertEqual(out["ok"] as? Bool, false)
		XCTAssertEqual(out["error"] as? String, "origin_refused")
	}
}
#endif
