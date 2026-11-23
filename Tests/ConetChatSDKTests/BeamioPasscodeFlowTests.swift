import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The passcode run, the app state (NO_PASSCODE, LOCKED, UNLOCKED), the wallet store over the vault,
/// and the Keychain storage on the host. Synthetic key and synthetic digits only.
final class BeamioPasscodeFlowTests: XCTestCase {
	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class MemoryHardware: BeamioPasscodeHardwareKeyStoring {
		var keys: [String: SymmetricKey] = [:]
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { keys[eoa.lowercased()] != nil }
		func createKey(eoa: String) -> Bool { keys[eoa.lowercased()] = SymmetricKey(size: .bits256); return true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data {
			guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
			return try BeamioPasscodeWrap.seal(plain, key: k, aad: aad)
		}
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data {
			guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
			return try BeamioPasscodeWrap.open(blob, key: k, aad: aad)
		}
		func deleteKey(eoa: String) { keys[eoa.lowercased()] = nil }
	}

	/// Legacy raw-key store (the pre-passcode wallet store). Since the mnemonic ownership rule (Y.163 items 31 and 32) an account is a valid mnemonic record, and the passcode store
	/// reads mnemonic items and the restore marks through its legacy layer: the layer is the shared mnemonic-capable double (setUp installs the account's mnemonic and commit).
	private typealias MemoryLegacy = MemoryNativeKeyStore

	/// The account the public test phrase A derives and its key: a valid mnemonic account (the mnemonic item is in the legacy store, see setUp).
	private var eoa: String { ValidTestAccounts.accountA.eoa }
	private var bundle: Data { ValidTestAccounts.accountA.key }
	private var records: MemoryRecords!
	private var hardware: MemoryHardware!
	private var legacy: MemoryLegacy!
	private var vault: BeamioPasscodeVault!
	private var savedVault: BeamioPasscodeVault?
	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var clock: Double = 1_800_000_000
	private let session = BeamioPasscodeSession.shared

	private func digits(_ s: String) -> [UInt8] { Array(s.utf8) }

	override func setUp() {
		super.setUp()
		records = MemoryRecords()
		hardware = MemoryHardware()
		legacy = MemoryLegacy()
		_ = legacy.writeItem(.mnemonic, eoa: eoa, value: BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA))
		_ = legacy.writeItem(.commit, eoa: eoa, value: Data(#"{"v":1,"eoa":"\#(eoa)","committedAt":"2026-11-15T00:00:00Z"}"#.utf8))
		clock = 1_800_000_000
		vault = BeamioPasscodeVault(records: records, hardware: hardware, now: { Date(timeIntervalSince1970: self.clock) })
		savedVault = session.vault
		session.vault = vault
		session.lockAll()
		NativeAccountPointerIsolation.begin()
		// the wallet functions answer only in G2 for the account; the passcode lock is judged inside that G2 case.
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: session)
		// The account starts with a device key (no passcode), as the wallet has today.
		_ = hardware.createKey(eoa: eoa)
		records.data[eoa] = try! JSONEncoder().encode(BeamioPasscodeRecord(
			mode: "device", salt: nil, blob: try! hardware.wrap(bundle, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))))
	}

	override func tearDown() {
		session.lockAll()
		session.vault = savedVault
		BeamioNativeWallet.keyStore = savedKeyStore
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func enable(_ passcode: String) -> BeamioPasscodeRunResult? {
		let run = BeamioPasscodeRunner(mode: .enable, eoa: eoa, vault: vault, session: session)
		_ = run.submit(digits(passcode))
		return run.submit(digits(passcode)).result
	}

	// MARK: - Run

	func testEnableRunsThroughPolicyMismatchAndMatch() {
		let run = BeamioPasscodeRunner(mode: .enable, eoa: eoa, vault: vault, session: session)
		XCTAssertEqual(run.submit(digits("11111111")), .init(state: .setupNew, message: "policy", result: nil))
		XCTAssertEqual(run.submit(digits("13572468")), .init(state: .setupConfirm, message: nil, result: nil))
		XCTAssertEqual(run.submit(digits("24681357")), .init(state: .setupNew, message: "mismatch", result: nil))
		XCTAssertEqual(run.submit(digits("13572468")).state, .setupConfirm)
		XCTAssertEqual(run.submit(digits("13572468")), .init(state: .done, message: nil, result: .ok))
		XCTAssertTrue(vault.isSet(eoa: eoa))
		XCTAssertEqual(session.appState(eoa: eoa), .locked, "after enabling, the account is LOCKED until it is unlocked")
	}

	func testUnlockWrongThenRightInstallsTheBundleAndIsUnlocked() {
		XCTAssertEqual(enable("13572468"), .ok)
		let run = BeamioPasscodeRunner(mode: .unlock, eoa: eoa, vault: vault, session: session)
		XCTAssertEqual(run.submit(digits("24681358")), .init(state: .unlock, message: "wrong", result: nil))
		XCTAssertEqual(run.submit(digits("13572468")), .init(state: .done, message: nil, result: .ok))
		XCTAssertEqual(session.appState(eoa: eoa), .unlocked)
		XCTAssertFalse(session.isLocked(eoa: eoa))
		XCTAssertEqual(BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: session).read(eoa: eoa), bundle)
	}

	/// rule 6: the SDK keeps no retry count and no cooldown. Many wrong passcodes are each reported wrong, never `backoff`, and the right one
	/// opens at once; the page owns the count and the cooldown.
	func testManyWrongAttemptsAreEachReportedWrongNeverBackoffAndTheRightOneOpens() {
		XCTAssertEqual(enable("13572468"), .ok)
		let run = BeamioPasscodeRunner(mode: .unlock, eoa: eoa, vault: vault, session: session)
		for _ in 0 ..< 12 {
			let step = run.submit(digits("24681358"))
			XCTAssertNil(step.result, "no terminal result from wrong attempts")
			XCTAssertEqual(step.message, "wrong")
		}
		XCTAssertEqual(session.appState(eoa: eoa), .locked)
		XCTAssertEqual(run.submit(digits("13572468")), .init(state: .done, message: nil, result: .ok), "the right passcode opens at once, no cooldown")
		XCTAssertEqual(session.appState(eoa: eoa), .unlocked)
	}

	func testChangeVerifiesTheOldPasscodeThenWritesTheNewOne() {
		XCTAssertEqual(enable("13572468"), .ok)
		let run = BeamioPasscodeRunner(mode: .change, eoa: eoa, vault: vault, session: session)
		XCTAssertEqual(run.submit(digits("24681358")), .init(state: .verifyOld, message: "wrong", result: nil))
		XCTAssertEqual(run.submit(digits("13572468")), .init(state: .setupNew, message: nil, result: nil))
		XCTAssertEqual(run.submit(digits("24681357")).state, .setupConfirm)
		XCTAssertEqual(run.submit(digits("24681357")), .init(state: .done, message: nil, result: .ok))
		let check = BeamioPasscodeRunner(mode: .unlock, eoa: eoa, vault: vault, session: session)
		XCTAssertEqual(check.submit(digits("13572468")).message, "wrong")
		XCTAssertEqual(BeamioPasscodeRunner(mode: .unlock, eoa: eoa, vault: vault, session: session).submit(digits("24681357")).result, .ok)
	}

	func testDisableReturnsToADeviceKeyRecord() {
		XCTAssertEqual(enable("13572468"), .ok)
		let run = BeamioPasscodeRunner(mode: .disable, eoa: eoa, vault: vault, session: session)
		XCTAssertEqual(run.submit(digits("13572468")), .init(state: .done, message: nil, result: .ok))
		XCTAssertFalse(vault.isSet(eoa: eoa))
		XCTAssertEqual(session.appState(eoa: eoa), .noPasscode)
	}

	func testCancelEndsTheRunAndWipesTheDigits() {
		let run = BeamioPasscodeRunner(mode: .enable, eoa: eoa, vault: vault, session: session)
		_ = run.submit(digits("13572468"))
		XCTAssertEqual(run.cancel().result, .cancelled)
		XCTAssertEqual(run.submit(digits("13572468")).result, .cancelled, "a finished run stays finished")
	}

	// MARK: - App state and the wallet store

	func testNoPasscodeIsNoPasscodeAndReadsTheDeviceKey() {
		XCTAssertEqual(session.appState(eoa: eoa), .noPasscode)
		XCTAssertEqual(BeamioNativeWallet.keyStore.read(eoa: eoa), bundle)
	}

	/// the SDK keeps no application-level lock, so a signature is not refused `locked`. A passcode record whose bundle the UI has not
	/// provided gives no key (no plaintext key is readable), and the signing function reports that as an unreadable store, never as a missing key.
	/// Once the passcode is provided the key is available.
	func testWithoutTheBundleNoPlaintextKeyIsReadableAndSigningReportsAnUnreadableStoreNotAMissingKey() {
		XCTAssertEqual(enable("13572468"), .ok)
		XCTAssertNil(BeamioNativeWallet.keyStore.read(eoa: eoa), "no key in memory before unlock")
		XCTAssertEqual(BeamioNativeWallet.signEip191(eoa: eoa, message: "x"), .failure(.storageUnreadable), "a record that exists but gives no key: not no_key, not locked")
		let run = BeamioPasscodeRunner(mode: .unlock, eoa: eoa, vault: vault, session: session)
		_ = run.submit(digits("13572468"))
		if case .failure(let failure) = BeamioNativeWallet.signEip191(eoa: eoa, message: "x") {
			XCTFail("the signing key is available after unlock: \(failure)")
		}
	}

	/// positive: a cold start of an account with no passcode needs no unlock step; a valid signing request is answered with a signature.
	func testAColdStartOfADeviceAccountSignsWithNoUnlockStep() {
		XCTAssertEqual(session.appState(eoa: eoa), .noPasscode)
		guard case .success = BeamioNativeWallet.signEip191(eoa: eoa, message: "x") else { return XCTFail("a device account signs with no unlock step") }
	}

	func testLockAllForgetsTheBundle() {
		XCTAssertEqual(enable("13572468"), .ok)
		_ = BeamioPasscodeRunner(mode: .unlock, eoa: eoa, vault: vault, session: session).submit(digits("13572468"))
		session.lockAll()
		XCTAssertEqual(session.appState(eoa: eoa), .locked)
		XCTAssertNil(session.bundle(eoa: eoa))
	}

	/// project requirement (keep published data): the published `walletKey` item is only read. It is not moved into a device record, the old item stays
	/// byte for byte (the digest before and after is the same), no device record and no hardware key is created, and a second read gives the same key.
	func testAPublishedLegacyKeyIsOnlyReadNeverMovedOrDeleted() {
		records.data[eoa] = nil
		hardware.keys[eoa] = nil
		legacy.keys[eoa] = bundle
		let before = SHA256.hash(data: legacy.keys[eoa] ?? Data()).map { String(format: "%02x", $0) }.joined()
		let store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: session)
		XCTAssertEqual(store.read(eoa: eoa), bundle)
		XCTAssertEqual(store.read(eoa: eoa), bundle, "a second read gives the same key")
		XCTAssertEqual(legacy.keys[eoa], bundle, "the old item is still there")
		XCTAssertEqual(SHA256.hash(data: legacy.keys[eoa] ?? Data()).map { String(format: "%02x", $0) }.joined(), before, "its bytes did not change")
		XCTAssertNil(records.data[eoa], "no device record is created")
		XCTAssertNil(hardware.keys[eoa], "no hardware key is created")
	}

	func testAWriteIsRefusedWhileAPasscodeIsSet() {
		XCTAssertEqual(enable("13572468"), .ok)
		let store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: legacy, session: session)
		XCTAssertFalse(store.write(eoa: eoa, key: Data(repeating: 0x22, count: 32)), "no downgrade to a weaker record")
	}
}

/// Keychain storage on the host: records and the H key, with unique service names. On hosts without a Secure Enclave the
/// fallback path is the one exercised; the Secure Enclave path needs the device (iPhone SE, 60-second and SE checks are
/// listed for the device acceptance).
final class BeamioPasscodeKeychainTests: XCTestCase {
	func testRecordRoundTripAndHardwareWrapBindsTheAccount() throws {
		let suffix = UUID().uuidString.lowercased()
		let eoa = "0x3333333333333333333333333333333333333333"
		let records = BeamioPasscodeKeychainRecords(service: "com.beamio.test.passcode.record.\(suffix)")
		let hw = BeamioPasscodeKeychainHardware(seTagPrefix: "com.beamio.test.passcode.h.se.\(suffix).",
		                                        fallbackService: "com.beamio.test.passcode.h-fallback.\(suffix)")
		defer {
			records.deleteRecord(eoa: eoa)
			hw.deleteKey(eoa: eoa)
		}
		XCTAssertNil(records.readRecord(eoa: eoa))
		XCTAssertTrue(records.writeRecord(eoa: eoa, Data("record".utf8)))
		XCTAssertEqual(records.readRecord(eoa: eoa), Data("record".utf8))
		XCTAssertTrue(hw.createKey(eoa: eoa))
		let aad = BeamioPasscodeWrap.aadH(eoa: eoa)
		let blob = try hw.wrap(Data(repeating: 0x11, count: 32), eoa: eoa, aad: aad)
		XCTAssertEqual(try hw.unwrap(blob, eoa: eoa, aad: aad), Data(repeating: 0x11, count: 32))
		XCTAssertThrowsError(try hw.unwrap(blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: "0x4444444444444444444444444444444444444444")),
		                     "the blob is bound to the account")
		hw.deleteKey(eoa: eoa)
		XCTAssertFalse(hw.hasKey(eoa: eoa))
	}
}

/// The bridge: `passcodeStatus` answers the two flags; `passcodeRun` answers the result code. No passcode and no
/// key crosses the bridge in either direction.
final class BeamioPasscodeBridgeTests: XCTestCase {
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private var savedVault: BeamioPasscodeVault?
	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var records: BeamioPasscodeFlowRecords!

	/// `passcodeRun` is a wallet command: the account needs a native record first. The passcode flow itself is
	/// not touched; the record is only checked for presence here.
	private func withNativeRecord() {
		let store = ChatLocalWalletBoundaryTests.MemoryWalletKeyStore()
		store.keys[eoa] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		// passcodeRun is answered in G2 only: the session has completed init for the record account.
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedKeyStore = BeamioNativeWallet.keyStore
		records = BeamioPasscodeFlowRecords()
		let hardware = BeamioPasscodeFlowHardware()
		_ = hardware.createKey(eoa: eoa)
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: hardware)
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		BeamioPasscodePresenter.present = nil
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioPasscodePresenter.present = nil
		BeamioConetChatSignBroker.clearSigner()
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedKeyStore
		super.tearDown()
	}

	private func runBridge(_ body: [String: Any]) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(body, emit: { event in
			if (event["event"] as? [String: Any])?["type"] as? String == "ack" {
				ack = event["event"] as? [String: Any]
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		return ack
	}

	func testTheBridgeEntryIsChatModuleCommandDispatchedOnType() {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.chatModuleCommand(["type": "passcodeStatus", "reqId": 9], emit: { event in
			if (event["event"] as? [String: Any])?["type"] as? String == "ack" {
				ack = event["event"] as? [String: Any]
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		XCTAssertEqual((ack?["result"] as? [String: Any])?["set"] as? Bool, false)
	}

	func testStatusOfAnAccountWithoutAPasscode() {
		let ack = runBridge(["type": "passcodeStatus", "reqId": 1])
		XCTAssertEqual(ack?["ok"] as? Bool, true)
		XCTAssertEqual((ack?["result"] as? [String: Any])?["set"] as? Bool, false)
		XCTAssertEqual((ack?["result"] as? [String: Any])?["locked"] as? Bool, false, "NO_PASSCODE: locked is false (P-STATUS)")
	}

	func testRunReturnsTheCodeOfThePresenterAndTheBackoffSeconds() {
		withNativeRecord()
		BeamioPasscodePresenter.present = { _, _, _, done in done(.backoff(30)) }
		let ack = runBridge(["type": "passcodeRun", "reqId": 2, "mode": "unlock", "copy": ["title": "t"]])
		XCTAssertEqual((ack?["result"] as? [String: Any])?["code"] as? String, "backoff")
		XCTAssertEqual((ack?["result"] as? [String: Any])?["cooldownSec"] as? Int, 30)
	}

	func testRunWithoutAnOverlayIsAnError() {
		withNativeRecord()
		let ack = runBridge(["type": "passcodeRun", "reqId": 3, "mode": "enable", "copy": [:]])
		XCTAssertEqual((ack?["result"] as? [String: Any])?["code"] as? String, "error")
	}

	func testAnUnknownModeIsRefused() {
		withNativeRecord()
		BeamioPasscodePresenter.present = { _, _, _, done in done(.ok) }
		let ack = runBridge(["type": "passcodeRun", "reqId": 4, "mode": "reveal", "copy": [:]])
		XCTAssertEqual(ack?["ok"] as? Bool, false)
		XCTAssertEqual(ack?["error"] as? String, "bad_mode")
	}

	/// Without a native record `passcodeRun` is `no_key` in every mode, before the presenter is reached (NK-PC1 to NK-PC4).
	func testPasscodeRunWithoutARecordIsNoKeyAndShowsNothing() {
		var shown = false
		BeamioPasscodePresenter.present = { _, _, _, _ in shown = true }
		let ack = runBridge(["type": "passcodeRun", "reqId": 5, "mode": "enable", "copy": [:]])
		XCTAssertEqual(ack?["error"] as? String, "no_key")
		XCTAssertFalse(shown, "no overlay is presented without a native record")
	}
}

/// Memory records and hardware for the bridge tests.
final class BeamioPasscodeFlowRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
	var data: [String: Data] = [:]
	func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
	func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
	func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
}

final class BeamioPasscodeFlowHardware: BeamioPasscodeHardwareKeyStoring {
	var keys: [String: SymmetricKey] = [:]
	var isSecureEnclave: Bool { false }
	func hasKey(eoa: String) -> Bool { keys[eoa.lowercased()] != nil }
	func createKey(eoa: String) -> Bool { keys[eoa.lowercased()] = SymmetricKey(size: .bits256); return true }
	func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data {
		guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
		return try BeamioPasscodeWrap.seal(plain, key: k, aad: aad)
	}
	func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data {
		guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
		return try BeamioPasscodeWrap.open(blob, key: k, aad: aad)
	}
	func deleteKey(eoa: String) { keys[eoa.lowercased()] = nil }
}
