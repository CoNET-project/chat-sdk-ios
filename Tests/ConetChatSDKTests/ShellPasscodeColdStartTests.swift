#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The accounts the shell passcode commands write (passcodeProvision, passcodeDisable) and the key-state snapshot of a cold start. The real commands run over the product wallet store and the
/// real mark store on the in-memory Keychain, with in-memory passcode records and hardware key. Synthetic phrase and passcode only.
final class ShellPasscodeColdStartTests: XCTestCase {
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let pass = "73920461"
	private var records: ShellPasscodeCoreTests.MemRecords!
	private var hardware: ShellPasscodeCoreTests.MemHardware!
	private var savedVault: BeamioPasscodeVault?
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedMarks: BeamioNativeMarkReading!
	private var savedPgpMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var nextReq = 7_000_000_000_000
	private var chatReq = 8_000_000_000_000

	private var account: String {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { fatalError() }
		defer { BeamioNativeWallet.wipe(&key) }
		return BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		AdmittedCreationDevice.install()
		BeamioChatWalletTestMemory.items = [:]
		records = ShellPasscodeCoreTests.MemRecords()
		hardware = ShellPasscodeCoreTests.MemHardware()
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: hardware, staging: ShellPasscodeCoreTests.MemRecords())
		BeamioPasscodeSession.shared.lockAll()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: BeamioChatWalletKeychainStore.standard, session: BeamioPasscodeSession.shared)
		savedMarks = BeamioNativeKeySnapshot.markStore
		BeamioNativeKeySnapshot.markStore = BeamioChatWalletKeychainStore.standard
		BeamioShellPasscodeCommands.resetForTests()
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeySnapshot.invalidate()
		// no SI node roster from another test: init must stop at the node stage
		BeamioPwaWalletSync.restartForTests()   // forgets the published preread of an earlier test
		savedPgpMemory = BeamioChatPgpKeychain.memory
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = savedPgpMemory
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeKeySnapshot.markStore = savedMarks
		BeamioNativeWallet.keyStore = savedStore
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioChatWalletTestMemory.items = [:]
		AdmittedCreationDevice.remove()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private var kc: BeamioChatWalletKeychainStore { BeamioChatWalletKeychainStore.standard }

	private func shell(_ fields: [String: Any]) -> [String: Any] {
		var body = fields
		body["reqId"] = nextReq; let id = nextReq; nextReq += 1
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioShellPasscodeCommands.handle(body) { payload in
			if payload["type"] as? String == "ack", payload["reqId"] as? Int == id, ack == nil { ack = payload; done.fulfill() }
		}
		wait(for: [done], timeout: 20)
		let drain = expectation(description: "drain")
		DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { drain.fulfill() }
		wait(for: [drain], timeout: 5)
		return ack ?? [:]
	}

	private func command(_ type: String, _ extra: [String: Any] = [:]) -> [String: Any] {
		chatReq += 1
		var body: [String: Any] = ["type": type, "reqId": chatReq]
		for (k, v) in extra { body[k] = v }
		var answer: [String: Any]?
		let done = expectation(description: type)
		BeamioConetChatModule.handleCommand(body) { payload in
			guard answer == nil, let event = payload["event"] as? [String: Any], "\(event["reqId"] ?? "")" == "\(body["reqId"] ?? "")" else { return }
			answer = event; done.fulfill()
		}
		wait(for: [done], timeout: 10)
		return answer ?? [:]
	}

	private func coldStart() -> BeamioNativeKeySnapshot.Entry? {
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeAccountPointer.set(account)
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		return BeamioNativeKeySnapshot.current()
	}

	private func label(_ e: BeamioNativeKeySnapshot.Entry?) -> String {
		guard let e else { return "unknown" }
		return "storageLock=\(String(describing: e.storageLock)) accountLocked=\(e.accountLocked) unreadable=\(e.unreadable) recordAccountPresent=\(e.recordAccount != nil)"
	}

	private func lockLabel(_ e: BeamioNativeKeySnapshot.Entry?) -> String {
		guard let e else { return "unknown" }
		if e.unreadable && e.storageLock == nil { return "unreadable" }
		switch e.storageLock {
		case .none: return "none"
		case .some(.markerMissing): return "markerMissing"
		case .some(.recordMissing): return "recordMissing"
		}
	}

	private func prereadResult() -> [String: Any] {
		BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: Int(nextReq), seq: 300_000 + Int(nextReq % 1000))["result"] as? [String: Any] ?? [:]
	}

	private func provisionThroughTheCommand() {
		let ack = shell(["type": "passcodeProvision", "eoa": account, "phrase": phrase, "passcode": pass])
		XCTAssertEqual(ack["ok"] as? Bool, true, "\(ack)")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account)
		let names = (BeamioChatWalletTestMemory.items ?? [:]).keys.map { $0.components(separatedBy: "\u{1}").last ?? "" }
		XCTAssertTrue(names.contains("mnemonic:" + account), "provision leaves the v3 header as the plain mnemonic item (no commit mark is written)")
		XCTAssertFalse(names.contains { $0.hasPrefix("commit:") })
	}

	/// The real passcodeProvision: the account is the passcode record (hardware-wrapped key, phrase under the passcode) plus a v3 header as the plain mnemonic item and the credential blob key. It never
	/// writes a commit mark, so before the vault-record exemption this layout was `markerMissing` at every state (unlocked, cold start, unlocked again, after disable).
	func testProvisionedAccountColdStartIsNotLockedAndOpensAfterTheUnlock() {
		provisionThroughTheCommand()
		XCTAssertEqual(lockLabel({ BeamioNativeKeySnapshot.invalidate(); BeamioNativeKeySnapshot.sessionStartIfNeeded(); return BeamioNativeKeySnapshot.current() }()), "none", "right after the provision")

		// cold start: the session is gone, the passcode record stays
		let cold = coldStart()
		XCTAssertEqual(lockLabel(cold), "none", "cold start: storageLock is none")
		XCTAssertEqual(cold?.accountLocked, true, "cold start: the account is passcode-locked")
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		let locked = command("walletStatus")["result"] as? [String: Any]
		XCTAssertEqual(locked?["status"] as? String, "not_ready")
		XCTAssertEqual(locked?["notReadyReason"] as? String, "g1_uninitialized", "at G1 the answer is the G1 form; the passcode reason belongs to a ready session")
		let read = prereadResult()
		XCTAssertNil(read["mnemonic"], "the preread never returns the phrase of a passcode account")
		XCTAssertEqual(read["code"] as? String, "read_error")
		// The page's unlock screen is driven by passcodeStatus, not by a reason on init's refusal: the status must say the passcode is set and the account is locked.
		let coldStatus = command("passcodeStatus", ["eoa": account])["result"] as? [String: Any]
		XCTAssertEqual(coldStatus?["set"] as? Bool, true, "\(String(describing: coldStatus))")
		XCTAssertEqual(coldStatus?["locked"] as? Bool, true)
		XCTAssertEqual(coldStatus?["hasKey"] as? Bool, true)
		XCTAssertEqual(command("init", ["payload": ["identity": ["eoa": account]]])["error"] as? String, "not_ready", "locked: init is refused")
		XCTAssertEqual(command("deriveSubkeys")["error"] as? String, "not_ready")

		// unlock through the real command: init now passes the key stage
		let unlock = shell(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		XCTAssertEqual(unlock["ok"] as? Bool, true, "\(unlock)")
		let openStatus = command("passcodeStatus", ["eoa": account])["result"] as? [String: Any]
		XCTAssertEqual(openStatus?["set"] as? Bool, true)
		XCTAssertEqual(openStatus?["locked"] as? Bool, false, "after the unlock the status says unlocked")
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(lockLabel(BeamioNativeKeySnapshot.current()), "none")
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.accountLocked, false)
		XCTAssertEqual(command("init", ["payload": ["identity": ["eoa": account]]])["error"] as? String, "nodes_unavailable", "unlocked: init reaches the node stage")
	}

	/// passcodeDisable: the record becomes the device record and the phrase goes back into the device-bound item. No lock; init passes the key stage without a passcode.
	func testDisabledPasscodeLeavesNoLock() {
		provisionThroughTheCommand()
		let disable = shell(["type": "passcodeDisable", "eoa": account, "passcode": pass])
		XCTAssertEqual(disable["ok"] as? Bool, true, "\(disable)")
		let cold = coldStart()
		XCTAssertEqual(lockLabel(cold), "none")
		XCTAssertEqual(cold?.accountLocked, false)
		XCTAssertEqual((command("walletStatus")["result"] as? [String: Any])?["notReadyReason"] as? String, "g1_uninitialized")
		XCTAssertEqual(command("init", ["payload": ["identity": ["eoa": account]]])["error"] as? String, "nodes_unavailable")
	}

	/// An undecodable vault record exempts nothing: with a plain mnemonic item and no commit mark the account stays `markerMissing` (fail closed).
	func testAnUndecodableVaultRecordDoesNotExempt() {
		provisionThroughTheCommand()
		XCTAssertTrue(records.writeRecord(eoa: account, Data("not a record".utf8)))
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(lockLabel(BeamioNativeKeySnapshot.current()), "markerMissing")
	}

	// MARK: - a write moves the published preread on (the same process, no restart)

	/// The preread of the current epoch is cached. A write of the key records, the marks, the pointer or the passcode state must make the next preread read the store again, whichever path wrote.
	private func prereadNow() -> [String: Any] {
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		nextReq += 1
		return BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: 9_000_000 + Int(nextReq % 1000), seq: 400_000 + Int(nextReq % 100_000))["result"] as? [String: Any] ?? [:]
	}

	func testPrereadAfterARecoveryInTheSameProcessIsTheNewState() {
		XCTAssertEqual(prereadNow()["code"] as? String, "confirmed_missing", "before: nothing is stored (and this reading is cached)")
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore), .imported)
		let after = prereadNow()
		XCTAssertEqual(after["code"] as? String, "ok", "after the recovery the preread reads the new account, not the cached absence: \(after)")
		XCTAssertEqual(after["eoa"] as? String, account)
		XCTAssertEqual(after["mnemonic"] as? String, phrase)
	}

	func testPrereadAfterACreationInTheSameProcessIsTheNewState() {
		XCTAssertEqual(prereadNow()["code"] as? String, "confirmed_missing")
		let made = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: [UInt8](repeating: 0x42, count: 16), userExplicit: true)
		guard case .made(let material) = made else { return XCTFail("the creation must succeed: \(made)") }
		let after = prereadNow()
		XCTAssertEqual(after["code"] as? String, "ok", "\(after)")
		XCTAssertEqual(after["eoa"] as? String, material.eoa)
	}

	/// passcodeProvision writes the passcode record, the header and the pointer: the cached absence must go, and the new reading must not carry the phrase (a passcode account never returns it). Then
	/// passcodeDisable writes the device record and the device-bound phrase: the reading changes again.
	func testPrereadFollowsThePasscodeCommandsInTheSameProcess() {
		XCTAssertEqual(prereadNow()["code"] as? String, "confirmed_missing")
		provisionThroughTheCommand()
		let provisioned = prereadNow()
		XCTAssertNotEqual(provisioned["code"] as? String, "confirmed_missing", "the provision moved the epoch on: \(provisioned)")
		// (A session that is unlocked reads through the store, so the reading may carry the phrase while it is unlocked; a locked account never does, see the cold start test.)
		let disabled = shell(["type": "passcodeDisable", "eoa": account, "passcode": pass])
		XCTAssertEqual(disabled["ok"] as? Bool, true, "\(disabled)")
		let afterDisable = prereadNow()
		XCTAssertNotEqual(afterDisable["code"] as? String, "confirmed_missing", "\(afterDisable)")
	}

	/// The exemption is for the plain mnemonic item only. An intent is a half-written key-record import whatever record sits beside it, so a valid passcode record or a valid device record with an
	/// intent still gives `markerMissing`. Widening the exemption to the intent clause would make this test fail.
	private func intentJSON() -> Data {
		(try? JSONSerialization.data(withJSONObject: ["v": 1, "eoa": account, "mnemonicPlanned": true, "blobKeyPlanned": true, "startedAt": "1970-01-01T00:00:00Z", "phase": "begun", "keep": false] as [String: Any], options: [.sortedKeys])) ?? Data()
	}

	func testAPasscodeRecordWithAnIntentIsStillMarkerMissing() {
		provisionThroughTheCommand()
		XCTAssertTrue(kc.writeItem(.intent, eoa: account, value: intentJSON()))
		XCTAssertEqual(lockLabel(coldStart()), "markerMissing", "a valid passcode record does not exempt an intent")
	}

	func testADeviceRecordWithAnIntentIsStillMarkerMissing() {
		provisionThroughTheCommand()
		XCTAssertEqual(shell(["type": "passcodeDisable", "eoa": account, "passcode": pass])["ok"] as? Bool, true)
		XCTAssertEqual(lockLabel(coldStart()), "none", "the device record alone is not a lock")
		XCTAssertTrue(kc.writeItem(.intent, eoa: account, value: intentJSON()))
		XCTAssertEqual(lockLabel(coldStart()), "markerMissing", "a valid device record does not exempt an intent")
	}
}
#endif
