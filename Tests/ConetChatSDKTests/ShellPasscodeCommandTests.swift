import XCTest
@testable import ConetChatSDK

/// The six shell passcode bridge commands (frozen protocol v1 §1.6, §2, §3, §4, §12). Synthetic values, memory stores.
final class ShellPasscodeCommandTests: XCTestCase {
	private final class KeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let pass = "73920461"
	private let pass2 = "58204716"
	private var records: ShellPasscodeCoreTests.MemRecords!
	private var hardware: ShellPasscodeCoreTests.MemHardware!
	private var savedVault: BeamioPasscodeVault?
	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: KeyStore!
	private var nextReq = 7_000_000_000_000
	private let eventLock = NSLock()
	private var events: [[String: Any]] = []

	private var account: String {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { fatalError() }
		defer { BeamioNativeWallet.wipe(&key) }
		return BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		records = ShellPasscodeCoreTests.MemRecords()
		hardware = ShellPasscodeCoreTests.MemHardware()
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: hardware, staging: ShellPasscodeCoreTests.MemRecords())
		BeamioPasscodeSession.shared.lockAll()
		savedStore = BeamioNativeWallet.keyStore
		store = KeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioShellPasscodeCommands.resetForTests()
		BeamioShellPasscodeCommands.now = { Date() }
		events = []
	}

	override func tearDown() {
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedStore
		BeamioShellPasscodeCommands.now = { Date() }
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// Sends one command and waits for its ack. Returns the ack; every payload is kept in `events`.
	@discardableResult
	private func send(_ fields: [String: Any], waitFor: Int? = nil) -> [String: Any]? {
		let id = waitFor ?? nextReq
		var body = fields
		if body["reqId"] == nil { body["reqId"] = nextReq; nextReq += 1 }
		let done = expectation(description: "ack")
		BeamioShellPasscodeCommands.handle(body) { [self] payload in
			eventLock.lock()
			events.append(payload)
			eventLock.unlock()
			if payload["type"] as? String == "ack", payload["reqId"] as? Int == (body["reqId"] as? Int) || payload["reqId"] is NSNull { done.fulfill() }
		}
		_ = id
		wait(for: [done], timeout: 20)
		// events that follow the ack (state, repair request) are sent from the same queue turn; let it drain
		let drain = expectation(description: "drain")
		DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { drain.fulfill() }
		wait(for: [drain], timeout: 5)
		eventLock.lock()
		defer { eventLock.unlock() }
		return events.last { $0["type"] as? String == "ack" && ($0["reqId"] as? Int == body["reqId"] as? Int || $0["reqId"] is NSNull) }
	}

	private func events(ofType type: String) -> [[String: Any]] {
		eventLock.lock()
		defer { eventLock.unlock() }
		return events.filter { $0["type"] as? String == type }
	}

	private func provision() -> [String: Any]? {
		send(["type": "passcodeProvision", "eoa": account, "phrase": phrase, "passcode": pass])
	}

	func testProvisionAnswersTheVerifiedAddressSetsThePointerAndUnlocksTheSession() {
		let ack = provision()
		XCTAssertEqual(ack?["ok"] as? Bool, true)
		let result = ack?["result"] as? [String: Any]
		XCTAssertEqual(result?["passcode"] as? String, "set")
		XCTAssertEqual(result?["verifiedAddress"] as? String, account)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), account)
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .unlocked)
		let state = events(ofType: "passcodeState").last
		XCTAssertEqual(state?["set"] as? Bool, true)
		XCTAssertEqual(state?["locked"] as? Bool, false)
		// a second provision answers already_set and changes nothing
		let before = records.values
		XCTAssertEqual(send(["type": "passcodeProvision", "eoa": account, "phrase": phrase, "passcode": pass2])?["error"] as? String, "already_set")
		XCTAssertEqual(records.values, before)
	}

	func testFieldAllowListsAndTheReqIdRange() {
		let base: [String: Any] = ["type": "passcodeUnlock", "eoa": account, "passcode": pass]
		var extra = base; extra["phrase"] = phrase
		XCTAssertEqual(send(extra)?["error"] as? String, "bad_request", "unlock may not carry a phrase")
		var key = base; key["privateKeyHex"] = "00"
		XCTAssertEqual(send(key)?["error"] as? String, "key_over_bridge_refused")
		var low = base; low["reqId"] = 5
		XCTAssertEqual(send(low)?["error"] as? String, "bad_request", "outside the page range")
		var high = base; high["reqId"] = 7_500_000_000_000
		XCTAssertEqual(send(high)?["error"] as? String, "bad_request", "the native range is not a page range")
		var badEoa = base; badEoa["eoa"] = "0x12"
		XCTAssertEqual(send(badEoa)?["error"] as? String, "bad_request")
		var noPass = base; noPass["passcode"] = ""
		XCTAssertEqual(send(noPass)?["error"] as? String, "bad_request")
		var change: [String: Any] = ["type": "passcodeChange", "eoa": account, "oldPasscode": pass, "newPasscode": pass2, "passcode": pass]
		XCTAssertEqual(send(change)?["error"] as? String, "bad_request")
		change["passcode"] = nil
		change["phrase"] = phrase
		XCTAssertEqual(send(change)?["error"] as? String, "bad_request")
	}

	func testOtherCommandsMayNotCarryTheProtocolCredentials() {
		for type in ["walletStatus", "init", "send", "passcodeStatus", "passcodeRun"] {
			for field in ["phrase", "passcode", "oldPasscode", "newPasscode"] {
				XCTAssertEqual(BeamioShellPasscodeCommands.strayCredentialField(type: type, body: ["type": type, field: "x"]), field, "\(type) \(field)")
			}
		}
		XCTAssertNil(BeamioShellPasscodeCommands.strayCredentialField(type: "passcodeUnlock", body: ["passcode": "x"]))
		XCTAssertNil(BeamioShellPasscodeCommands.strayCredentialField(type: "walletStatus", body: ["type": "walletStatus"]))
	}

	func testTheSixNamesAreInTheGateAndCommandTables() {
		for name in BeamioShellPasscodeCommands.names {
			XCTAssertTrue(BeamioConetChatModule.dispatchedCommands.contains(name), name)
			XCTAssertTrue(BeamioConetChatModule.noKeyCommandTable.contains(name), name)
			XCTAssertTrue(BeamioConetChatModule.gateExemptCommands.contains(name), name)
			XCTAssertTrue(BeamioConetChatModule.knownBridgeCommand(name), name)
		}
		XCTAssertTrue(BeamioConetChatModule.statusCommands.contains("passcodeStatus"))
		XCTAssertEqual(BeamioShellPasscodeCommands.names.count, 5, "passcodeStatus is the existing status command; the incoming-call bind is a native API, not a bridge command")
	}

	func testAccountRules() {
		BeamioNativeAccountPointer.set("0x2222222222222222222222222222222222222222")
		XCTAssertEqual(provision()?["error"] as? String, "other_account_present")
		XCTAssertTrue(records.values.isEmpty)
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["error"] as? String, "eoa_mismatch")
		XCTAssertTrue(events(ofType: "nativeRepairRequest").isEmpty, "eoa_mismatch asks for no repair")
		BeamioNativeAccountPointer.clear()
		store.keys["0x3333333333333333333333333333333333333333"] = Data(repeating: 1, count: 32)
		XCTAssertEqual(provision()?["error"] as? String, "other_account_present", "another account's record is never overwritten")
		XCTAssertTrue(records.values.isEmpty)
	}

	func testUnlockAnswersAndAsksForRepairOnlyWhereTheFrozenTableSays() {
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["error"] as? String, "no_record")
		XCTAssertEqual(events(ofType: "nativeRepairRequest").last?["cause"] as? String, "no_record")
		_ = provision()
		BeamioPasscodeSession.shared.lockAll()
		let ok = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		XCTAssertEqual((ok?["result"] as? [String: Any])?["unlocked"] as? Bool, true)
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .unlocked)
		// not_ready asks for no repair
		let requests = events(ofType: "nativeRepairRequest").count
		records.unavailable = true
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["error"] as? String, "not_ready")
		records.unavailable = false
		XCTAssertEqual(events(ofType: "nativeRepairRequest").count, requests)
	}

	func testRepairNeedsAPendingRequestThatMatchesAndIsIdempotent() throws {
		_ = provision()
		BeamioPasscodeSession.shared.lockAll()
		// the UI knows pass2 and the native record is under pass: passcode_mismatch
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass2])?["error"] as? String, "wrong_passcode")
		let request = try XCTUnwrap(events(ofType: "nativeRepairRequest").last)
		let requestId = try XCTUnwrap(request["reqId"] as? Int)
		XCTAssertEqual(request["cause"] as? String, "passcode_mismatch")
		XCTAssertEqual(request["eoa"] as? String, account)
		XCTAssertTrue((7_500_000_000_000 ..< 7_600_000_000_000).contains(requestId))
		XCTAssertEqual(send(["type": "nativeRepairProvide", "eoa": account, "phrase": phrase, "passcode": pass2, "requestReqId": requestId + 1])?["error"] as? String, "no_request")
		let before = records.values
		XCTAssertEqual(send(["type": "nativeRepairProvide", "eoa": account, "phrase": phrase, "passcode": pass2, "requestReqId": requestId])?["ok"] as? Bool, true)
		XCTAssertNotEqual(records.values, before)
		let result = events(ofType: "nativeRepairResult").last
		XCTAssertEqual(result?["ok"] as? Bool, true)
		XCTAssertEqual(result?["reqId"] as? Int, requestId)
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .unlocked)
		// the same request again: the same answer, nothing rewritten
		let afterRepair = records.values
		let again = send(["type": "nativeRepairProvide", "eoa": account, "phrase": phrase, "passcode": pass2, "requestReqId": requestId])
		XCTAssertEqual(again?["ok"] as? Bool, true)
		XCTAssertEqual(records.values, afterRepair)
		// a wrong phrase for a fresh request is refused and keeps the record
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["error"] as? String, "wrong_passcode")
		let second = try XCTUnwrap(events(ofType: "nativeRepairRequest").last?["reqId"] as? Int)
		let guarded = records.values
		XCTAssertEqual(send(["type": "nativeRepairProvide", "eoa": account, "phrase": "legal winner thank year wave sausage worth useful legal winner thank yellow",
		                     "passcode": pass, "requestReqId": second])?["error"] as? String, "eoa_mismatch")
		XCTAssertEqual(records.values, guarded)
	}

	func testAPendingRequestExpiresAfterSixtySeconds() throws {
		var clock = Date()
		BeamioShellPasscodeCommands.now = { clock }
		_ = provision()
		BeamioPasscodeSession.shared.lockAll()
		_ = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass2])
		let requestId = try XCTUnwrap(events(ofType: "nativeRepairRequest").last?["reqId"] as? Int)
		clock = clock.addingTimeInterval(61)
		XCTAssertEqual(send(["type": "nativeRepairProvide", "eoa": account, "phrase": phrase, "passcode": pass2, "requestReqId": requestId])?["error"] as? String, "no_request")
	}

	func testChangeAndDisable() {
		_ = provision()
		XCTAssertEqual(send(["type": "passcodeChange", "eoa": account, "oldPasscode": pass2, "newPasscode": pass])?["error"] as? String, "wrong_passcode")
		XCTAssertEqual(send(["type": "passcodeChange", "eoa": account, "oldPasscode": pass, "newPasscode": "12345678"])?["error"] as? String, "weak_passcode")
		let weak = events(ofType: "ack").last
		XCTAssertEqual(weak?["reason"] as? String, "common")
		let changed = send(["type": "passcodeChange", "eoa": account, "oldPasscode": pass, "newPasscode": pass2])
		XCTAssertEqual((changed?["result"] as? [String: Any])?["changed"] as? Bool, true)
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["error"] as? String, "wrong_passcode")
		let disabled = send(["type": "passcodeDisable", "eoa": account, "passcode": pass2])
		XCTAssertEqual((disabled?["result"] as? [String: Any])?["disabled"] as? Bool, true)
		let state = events(ofType: "passcodeState").last
		XCTAssertEqual(state?["set"] as? Bool, false)
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass2])?["error"] as? String, "not_set")
	}

	func testAnInterruptedWriteIsReconciledAtTheUnlock() {
		_ = provision()
		BeamioPasscodeSession.shared.lockAll()
		// a stale staged copy beside a usable record is removed and the unlock goes on
		let stagingStore = ShellPasscodeCoreTests.MemRecords()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: hardware, staging: stagingStore)
		stagingStore.values[account] = records.values[account]
		XCTAssertEqual((send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["result"] as? [String: Any])?["unlocked"] as? Bool, true)
		XCTAssertTrue(stagingStore.values.isEmpty)
		// the record is damaged and the staged copy is usable: both kept, rollback_pending
		BeamioPasscodeSession.shared.lockAll()
		let good = records.values[account]!
		stagingStore.values[account] = good
		records.values[account] = Data("garbage".utf8)
		let ack = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		XCTAssertEqual(ack?["error"] as? String, "write_failed")
		XCTAssertEqual(ack?["reason"] as? String, "rollback_pending")
		XCTAssertEqual(stagingStore.values[account], good)
		XCTAssertEqual(records.values[account], Data("garbage".utf8))
	}

	// MARK: session clearing and the pointer (r2k, r2l)

	private func installedSession(for eoa: String) {
		BeamioPasscodeSession.shared.install(eoa: eoa, bundle: [UInt8](repeating: 9, count: 32), mnemonicKey: [UInt8](repeating: 7, count: 32))
	}

	func testAnEmptyPointerUnlockAnswersNoRecordAndBuildsNoSession() {
		_ = provision()
		BeamioPasscodeSession.shared.lockAll()
		BeamioNativeAccountPointer.clear()
		let ack = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		XCTAssertEqual(ack?["error"] as? String, "no_record", "not not_set, not unlocked")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "no session")
		XCTAssertEqual(events(ofType: "nativeRepairRequest").last?["cause"] as? String, "no_record")
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty, "an unlock does not write the pointer")
	}

	func testProvisionWritesThePointerBeforeTheSessionAndAnEmptyToXSwitchLeavesNoSession() {
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty)
		installedSession(for: account) // a session that must not outlive the switch
		BeamioNativeAccountPointer.set(account)
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "empty → X: the session is empty")
		_ = provision()
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .value(account))
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: account), "the pointer first, then the session")
	}

	func testEveryPointerChangeEndsTheSessions() {
		BeamioNativeAccountPointer.set(account)
		installedSession(for: account)
		BeamioNativeAccountPointer.set(account) // the same value: nothing changes
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: account))
		BeamioNativeAccountPointer.set("0x5555555555555555555555555555555555555555")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "another account")
		installedSession(for: account)
		BeamioNativeAccountPointer.clear()
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "cleared")
		installedSession(for: account)
		BeamioNativeAccountPointer.clear() // already empty: no change
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: account))
		XCTAssertNil(BeamioPasscodeSession.shared.mnemonicKey(eoa: "0x5555555555555555555555555555555555555555"))
	}

	func testAnotherAccountsPointerEndsTheSessionAndRefuses() {
		_ = provision()
		installedSession(for: account)
		// the pointer is written around the hook (another account, set by a flow that does not call set)
		BeamioNativeAccountPointer.defaults.set("0x5555555555555555555555555555555555555555", forKey: "beamio.native.account.v1")
		let ack = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		XCTAssertEqual(ack?["error"] as? String, "eoa_mismatch")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "the session is cleared")
		XCTAssertNil(BeamioPasscodeSession.shared.mnemonicKey(eoa: account), "and its P key")
	}

	func testAnUnreadablePointerRefusesAndNeitherClearsNorUnlocks() {
		_ = provision()
		installedSession(for: account)
		BeamioNativeAccountPointer.defaults.set(12345, forKey: "beamio.native.account.v1") // not a string: cannot be read
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .unreadable)
		let ack = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		XCTAssertEqual(ack?["error"] as? String, "not_ready")
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: account), "unknown: not cleared")
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["error"] as? String, "not_ready")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "unknown: not unlocked")
	}

	func testChangeRebuildsTheSessionAndDisableEndsIt() {
		_ = provision()
		XCTAssertNotNil(BeamioPasscodeSession.shared.mnemonicKey(eoa: account))
		let oldKey = BeamioPasscodeSession.shared.mnemonicKey(eoa: account)
		_ = send(["type": "passcodeChange", "eoa": account, "oldPasscode": pass, "newPasscode": pass2])
		// rebuilt from the new record: unlocked, with the new P key (not the old one), and no second unlock asked for
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: account))
		XCTAssertNotNil(BeamioPasscodeSession.shared.mnemonicKey(eoa: account))
		XCTAssertNotEqual(BeamioPasscodeSession.shared.mnemonicKey(eoa: account), oldKey, "the old P key is gone")
		XCTAssertEqual(events(ofType: "passcodeState").last?["locked"] as? Bool, false)
		_ = send(["type": "passcodeDisable", "eoa": account, "passcode": pass2])
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account))
		XCTAssertNil(BeamioPasscodeSession.shared.mnemonicKey(eoa: account))
	}

	func testARepairWithAnEmptyPointerWritesThePointerBeforeTheSession() throws {
		_ = provision()
		BeamioPasscodeSession.shared.lockAll()
		BeamioNativeAccountPointer.clear()
		records.values.removeAll()
		_ = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])
		let requestId = try XCTUnwrap(events(ofType: "nativeRepairRequest").last?["reqId"] as? Int)
		let ack = send(["type": "nativeRepairProvide", "eoa": account, "phrase": phrase, "passcode": pass, "requestReqId": requestId])
		XCTAssertEqual(ack?["ok"] as? Bool, true)
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .value(account))
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: account))
	}

	func testNoSecretAppearsInAnyAnswer() {
		_ = provision()
		_ = send(["type": "passcodeUnlock", "eoa": account, "passcode": pass2])
		eventLock.lock()
		let text = String(describing: events)
		eventLock.unlock()
		for secret in [phrase, pass, pass2, "abandon"] { XCTAssertFalse(text.contains(secret), "an answer carries a secret") }
	}
}

/// The capability `wallet.passcode.v1` (frozen protocol §1.5): in the main list, in every build, never only in the QA list.
final class ShellPasscodeCapabilityTests: XCTestCase {
	func testTheCapabilityIsInTheMainListAndNotOnlyInTheQaList() {
		XCTAssertEqual(BeamioConetChatProtocol.passcodeCapability, "wallet.passcode.v1")
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains("wallet.passcode.v1"))
		XCTAssertFalse(BeamioConetChatProtocol.qaCapabilities.contains("wallet.passcode.v1"))
		let base = BeamioConetChatProtocol.capabilities.filter { !BeamioConetChatProtocol.qaCapabilities.contains($0) }
		XCTAssertTrue(base.contains("wallet.passcode.v1"), "declared without the QA additions")
		XCTAssertTrue(base.contains("identity.native-keys.v1"), "the key capability stays")
		let hello = BeamioConetChatProtocol.helloResult()
		XCTAssertTrue((hello["capabilities"] as? [String] ?? []).contains("wallet.passcode.v1"))
	}
}

/// The locked-exemption vector (passcode-locked-exemption-vectors.v2, frozen protocol §12) and the narrowing at G1.
final class ShellPasscodeLockedExemptionTests: XCTestCase {
	private func vector() throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: "passcode-locked-exemption-vectors.v2")
		return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	func testTheNamesTheVectorAllowsAreTheOnesTheGateLetsThrough() throws {
		let root = try vector()
		let allowed = try XCTUnwrap(root["allowedWhen"] as? [String: [String]])
		for state in ["g0", "locked_passcode_required"] {
			let names = Set(try XCTUnwrap(allowed[state]))
			XCTAssertEqual(names, BeamioShellPasscodeCommands.names.union(["passcodeStatus"]), state)
			for name in names {
				XCTAssertTrue(BeamioConetChatModule.gateExemptCommands.contains(name) || BeamioConetChatModule.statusCommands.contains(name), name)
			}
		}
	}

	func testTheVectorsG1AndEmptyPointerCasesMatchWhatIsTested() throws {
		let cases = try XCTUnwrap(try vector()["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 102)
		let g1 = cases.filter { $0["state"] as? String == "g1" }
		XCTAssertEqual(Set(g1.compactMap { $0["command"] as? String }), BeamioShellPasscodeCommands.names, "the five new commands at G1")
		for c in g1 { XCTAssertEqual((c["expect"] as? [String: Any])?["error"] as? String, "not_ready", c["id"] as? String ?? "") }
		let pointer = try XCTUnwrap(cases.first { $0["state"] as? String == "g2_pointer_empty" })
		XCTAssertEqual(pointer["command"] as? String, "passcodeUnlock")
		XCTAssertEqual((pointer["expect"] as? [String: Any])?["error"] as? String, "no_record")
	}

	func testTheNamesThatAreGatedWhenLockedAreNotExempt() throws {
		let gated = try XCTUnwrap(try vector()["gatedWhenLocked"] as? [String])
		XCTAssertFalse(gated.isEmpty)
		for name in gated {
			XCTAssertFalse(BeamioConetChatModule.gateExemptCommands.contains(name), "\(name) must stay behind the lock")
			XCTAssertFalse(BeamioShellPasscodeCommands.names.contains(name), name)
		}
	}

	func testTheFiveCommandsAnswerNotReadyAtG1() throws {
		final class Keys: BeamioChatWalletKeyStoring {
			var keys: [String: Data] = [:]
			func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
			func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
			func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
			func delete(eoa: String) { keys[eoa.lowercased()] = nil }
			func migrationMarkerExists(eoa: String) -> Bool { false }
			func setMigrationMarker(eoa: String) -> Bool { true }
		}
		NativeAccountPointerIsolation.begin()
		let saved = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = saved; NativeAccountPointerIsolation.end() }
		// G1: the device has the account's key and the pointer names it, but this session has not started for it
		let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
		let keys = Keys()
		keys.keys[eoa] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = keys
		BeamioNativeAccountPointer.set(eoa)
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeAccountPointer.set(eoa)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		for (index, name) in BeamioShellPasscodeCommands.names.sorted().enumerated() {
			var answer: [String: Any]?
			let id = 7_000_000_000_100 + index
			BeamioConetChatModule.handleCommand(["type": name, "reqId": id, "eoa": eoa, "passcode": "73920461"], emit: { out in
				if let event = out["event"] as? [String: Any], event["reqId"] as? Int == id { answer = event }
			})
			let deadline = Date().addingTimeInterval(5)
			while answer == nil && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
			XCTAssertEqual(answer?["error"] as? String, "not_ready", name)
		}
	}
}

/// A session lock also wipes the keys that were derived from the wallet key and held in memory (the local library's DEK and keys).
final class SessionClearDerivedKeysTests: XCTestCase {
	func testLockAllWipesTheLocalLibraryKeys() throws {
		NativeAccountPointerIsolation.begin()
		let account = "0x1111111111111111111111111111111111111111"
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("derived-keys-\(UUID().uuidString)")
		defer {
			BeamioConetChatModule.attachStoresForTests(local: nil, history: nil)
			NativeAccountPointerIsolation.end()
			try? FileManager.default.removeItem(at: root)
		}
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		let store = BeamioConetChatLocalStore(rootDirectory: root)
		try store.unlock(accountKey: account + ":default", localRoot: chatTestLocalRoot)
		XCTAssertNotNil(store.dek, "unlocked: the DEK is held")
		BeamioConetChatModule.attachStoresForTests(local: store, history: nil)
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertNil(store.dek, "the lock wiped the derived keys")
	}

	func testLockAllWipesTheHistoryMasterAndTheStoreIsNotReadyAfterIt() {
		NativeAccountPointerIsolation.begin()
		let account = "0x1111111111111111111111111111111111111111"
		defer {
			BeamioConetChatModule.attachStoresForTests(local: nil, history: nil)
			NativeAccountPointerIsolation.end()
		}
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		let history = BeamioConetChatHistoryStore(
			eoa: account, chainId: 224422, conetRpcUrl: "https://rpc.invalid", ipfsBaseUrl: "https://ipfs.invalid", ipfsWriteBaseUrl: nil,
			apiBaseUrl: "https://api.invalid", registryAddress: "0x" + String(repeating: "2", count: 40), log: { _, _ in })
		history.setMasterForTests(Data(repeating: 0xAB, count: 32))
		XCTAssertTrue(history.holdsMasterForTests)
		XCTAssertNotNil(history.localLibraryMaster())
		BeamioConetChatModule.attachStoresForTests(local: nil, history: history)
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertFalse(history.holdsMasterForTests, "the master is gone")
		XCTAssertNil(history.localLibraryMaster(), "and the store is not ready")
	}
}

/// Option B: a lock keeps the voice registration of a ringing call; only an account switch or a logout ends it.
final class LockKeepsCallResourcesTests: XCTestCase {
	private let sid = String(repeating: "ab", count: 16)
	private let wk = Data(repeating: 3, count: 32).base64EncodedString()
	private let account = "0x1111111111111111111111111111111111111111"
	private let other = "0x2222222222222222222222222222222222222222"

	private func signs() -> Bool {
		if case .success = BeamioVoiceEphemeral.sign(sid: sid, wk: wk, relayKeyId: "r1", timestamp: 1) { return true }
		return false
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeAccountPointer.set(account)
		XCTAssertTrue(BeamioVoiceEphemeral.register(sid: sid, privateKey: [UInt8](repeating: 0x5a, count: 32)))
	}

	override func tearDown() {
		BeamioVoiceEphemeral.clearAll()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	func testALockKeepsTheRegistrationAndWipesTheSessionSecrets() {
		BeamioPasscodeSession.shared.install(eoa: account, bundle: [UInt8](repeating: 9, count: 32), mnemonicKey: [UInt8](repeating: 7, count: 32))
		XCTAssertTrue(signs())
		BeamioPasscodeSession.shared.lockAll(reason: .lock)
		XCTAssertTrue(signs(), "the call that rings keeps its channel key")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "the wallet secrets are gone")
		XCTAssertNil(BeamioPasscodeSession.shared.mnemonicKey(eoa: account))
		BeamioPasscodeSession.shared.lockAll() // the default reason is lock
		XCTAssertTrue(signs())
		BeamioPasscodeSession.shared.lockAll(reason: .passcodeChange)
		XCTAssertTrue(signs())
		BeamioPasscodeSession.shared.lockAll(reason: .passcodeDisable)
		XCTAssertTrue(signs())
	}

	func testAnAccountSwitchEndsTheRegistration() {
		BeamioNativeAccountPointer.set(other)
		XCTAssertFalse(signs())
	}

	func testALogoutEndsTheRegistration() {
		BeamioNativeAccountPointer.clear()
		XCTAssertFalse(signs())
	}

	func testTheWalletKeyIsStillRefusedWhileLockedAndTheCallKeyIsNot() {
		// the temporary call key signs the listen while the wallet is locked; the wallet-key signature is refused (no session, no bundle)
		BeamioPasscodeSession.shared.lockAll(reason: .lock)
		XCTAssertTrue(signs())
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "no wallet key is available to sign with")
	}
}

/// The per-account generation (interface addendum 5): an unlock does not move it; a lock, a logout and an account switch do.
final class SessionGenerationTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"

	func testOnlyLockLogoutAndSwitchMoveTheGeneration() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		BeamioNativeAccountPointer.set(account)
		let session = BeamioPasscodeSession.shared
		let g0 = session.generation(eoa: account)
		session.install(eoa: account, bundle: [UInt8](repeating: 9, count: 32), mnemonicKey: [UInt8](repeating: 7, count: 32))
		XCTAssertEqual(session.generation(eoa: account), g0, "an unlock does not move it")
		session.lockAll(reason: .passcodeChange)
		XCTAssertEqual(session.generation(eoa: account), g0, "a change does not move it")
		session.lockAll(reason: .passcodeDisable)
		XCTAssertEqual(session.generation(eoa: account), g0, "a disable does not move it")
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.generation(eoa: account), g0, "a lock of a session that is already locked does not (addendum 23 §3)")
		session.install(eoa: account, bundle: [UInt8](repeating: 9, count: 32), mnemonicKey: [UInt8](repeating: 7, count: 32))
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.generation(eoa: account), g0 + 1, "a lock of an unlocked session does")
		session.lockAll(reason: .logout)
		XCTAssertEqual(session.generation(eoa: account), g0 + 2)
		BeamioNativeAccountPointer.set("0x2222222222222222222222222222222222222222")
		XCTAssertEqual(session.generation(eoa: account), g0 + 3, "a switch moves the account that was left")
	}
}

/// The `passcodeState` event carries `reason` when a session ends, sent after the keys are wiped; `set` and `locked` only when the state is known.
final class PasscodeStateReasonTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"
	private let other = "0x2222222222222222222222222222222222222222"
	private var seen: [[String: Any]] = []
	private let seenLock = NSLock()
	private var records: ShellPasscodeCoreTests.MemRecords!
	private var savedVault: BeamioPasscodeVault?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		records = ShellPasscodeCoreTests.MemRecords()
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: ShellPasscodeCoreTests.MemHardware(), staging: ShellPasscodeCoreTests.MemRecords())
		BeamioPasscodeSession.shared.lockAll()
		BeamioNativeAccountPointer.set(account)
		seen = []
		// any command sets the module's event output; hello is the lightest
		BeamioConetChatModule.handleCommand(["type": "hello", "reqId": 1], emit: { [self] out in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "passcodeState" else { return }
			seenLock.lock(); seen.append(event); seenLock.unlock()
		})
		drain()
		seenLock.lock(); seen = []; seenLock.unlock()
	}

	override func tearDown() {
		BeamioPasscodeSession.shared.vault = savedVault
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func drain() {
		let until = Date().addingTimeInterval(0.3)
		while Date() < until { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
	}

	private func events() -> [[String: Any]] {
		drain()
		seenLock.lock()
		defer { seenLock.unlock() }
		return seen
	}

	private func session() { BeamioPasscodeSession.shared.install(eoa: account, bundle: [UInt8](repeating: 9, count: 32), mnemonicKey: [UInt8](repeating: 7, count: 32)) }

	func testALockOfAnUnlockedSessionSendsReasonLockWithTheKnownState() {
		session()
		BeamioPasscodeSession.shared.lockAll(reason: .lock)
		let e = events()
		XCTAssertEqual(e.count, 1)
		XCTAssertEqual(e.first?["reason"] as? String, "lock")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "the keys are gone when the event is seen")
	}

	func testALockWithNoUnlockedSessionSendsNothing() {
		BeamioPasscodeSession.shared.lockAll(reason: .lock) // a cold start: nothing turned locked
		XCTAssertTrue(events().isEmpty)
	}

	func testAnAccountSwitchSendsItsReason() {
		session()
		BeamioNativeAccountPointer.set(other)
		let e = events()
		XCTAssertEqual(e.last?["reason"] as? String, "account_switch")
		XCTAssertEqual(e.last?["set"] as? Bool, false, "the new account has no passcode record here")
		XCTAssertEqual(e.last?["locked"] as? Bool, false)
		BeamioNativeAccountPointer.set(other) // no change: nothing is sent
		XCTAssertEqual(events().count, e.count)
	}

	func testALogoutSendsItsReasonAndNoUnknownState() {
		session()
		BeamioNativeAccountPointer.clear()
		let last = events().last
		XCTAssertEqual(last?["reason"] as? String, "logout")
		XCTAssertNil(last?["set"], "no account is known: no false stands in for it")
		XCTAssertNil(last?["locked"])
	}

	func testChangeAndDisableSendTheirReasons() {
		BeamioPasscodeSession.shared.lockAll(reason: .passcodeChange)
		BeamioPasscodeSession.shared.lockAll(reason: .passcodeDisable)
		XCTAssertEqual(events().compactMap { $0["reason"] as? String }, ["passcode_change", "passcode_disable"])
	}

	func testAStateThatCannotBeReadCarriesNeitherSetNorLocked() {
		BeamioPasscodeSession.shared.vault = nil // the lock state is unknown
		let payload = BeamioPasscodeSession.shared.statePayload(eoa: account, reason: nil)
		XCTAssertNil(payload["set"])
		XCTAssertNil(payload["locked"])
		XCTAssertNil(payload["reason"], "an unlock or a status event has no reason")
		XCTAssertEqual(payload["type"] as? String, "passcodeState")
	}
}

/// D: a session clear overwrites the key bytes in place with zeros (not only drops them). The probe records each wipe: length, non-zero before, all zero after.
final class SessionClearZeroBytesTests: XCTestCase {
	func testLockAllZeroesBundleMnemonicKeyHistoryMasterAndLocalRoot() throws {
		NativeAccountPointerIsolation.begin()
		let account = "0x1111111111111111111111111111111111111111"
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("zero-bytes-\(UUID().uuidString)")
		defer {
			_ = BeamioWipeProbe.stop()
			BeamioConetChatModule.attachStoresForTests(local: nil, history: nil)
			NativeAccountPointerIsolation.end()
			try? FileManager.default.removeItem(at: root)
		}
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		// the caller keeps its own references: the session must not share their storage
		let callerBundle = [UInt8](repeating: 0xA5, count: 77), callerKey = [UInt8](repeating: 0x5A, count: 33)
		BeamioPasscodeSession.shared.install(eoa: account, bundle: callerBundle, mnemonicKey: callerKey)
		let history = BeamioConetChatHistoryStore(
			eoa: account, chainId: 224422, conetRpcUrl: "https://rpc.invalid", ipfsBaseUrl: "https://ipfs.invalid", ipfsWriteBaseUrl: nil,
			apiBaseUrl: "https://api.invalid", registryAddress: "0x" + String(repeating: "2", count: 40), log: { _, _ in })
		history.setMasterForTests(Data(repeating: 0xAB, count: 41))
		let store = BeamioConetChatLocalStore(rootDirectory: root)
		try store.unlock(accountKey: account + ":default", localRoot: chatTestLocalRoot)
		BeamioConetChatModule.attachStoresForTests(local: store, history: history)
		let before = BeamioPasscodeSession.shared.storedAddressesForTests(eoa: account)
		XCTAssertNotNil(before.bundle)
		XCTAssertNotNil(before.mnemonicKey)
		BeamioWipeProbe.start()
		BeamioPasscodeSession.shared.lockAll()
		let events = BeamioWipeProbe.stop()
		// in place: the buffers that were wiped are the very storage the session held (a copy-on-write copy would sit at another address)
		for address in [before.bundle, before.mnemonicKey] {
			let hit = events.filter { $0.address == address }
			XCTAssertEqual(hit.count, 1, "the held storage was wiped once, in place")
			XCTAssertTrue(hit.allSatisfy { $0.hadNonZero && $0.allZero })
		}
		for length in [77, 33, 41, chatTestLocalRoot.count] {
			let seen = events.filter { $0.count == length }
			XCTAssertFalse(seen.isEmpty, "a \(length)-byte buffer was wiped")
			XCTAssertTrue(seen.allSatisfy { $0.hadNonZero }, "it held key bytes before the wipe (\(length))")
			XCTAssertTrue(seen.allSatisfy { $0.allZero }, "it is all zero after the wipe (\(length))")
		}
		XCTAssertTrue(events.allSatisfy { $0.allZero }, "no wipe left a non-zero byte")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account))
		XCTAssertTrue(callerBundle.allSatisfy { $0 == 0xA5 } && callerKey.allSatisfy { $0 == 0x5A }, "the caller's own copies are the caller's to wipe; the session did not touch them")
		// the history master and the local root are Data: counted by length (residual: their storage address is not probed)
	}
}

/// Addenda 13, 14: `callId` on `passcodeUnlock`; the bind and unbind are native SDK calls of the shell, not bridge commands.
final class IncomingCallBindTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"
	private let other = "0x2222222222222222222222222222222222222222"
	private var nextReq = 7_000_000_000_400

	override func tearDown() {
		BeamioShellPasscodeCommands.callMismatchEffective = true
		super.tearDown()
	}

	override func setUp() {
		super.setUp()
		BeamioShellPasscodeCommands.callMismatchEffective = true
		BeamioShellPasscodeCommands.resetForTests()
		BeamioPasscodeSession.shared.lockAll(reason: .logout)
	}

	private func call(_ fields: [String: Any]) -> [String: Any] {
		var body = fields
		body["reqId"] = nextReq; nextReq += 1
		var ack: [String: Any] = [:]
		let done = expectation(description: "ack")
		BeamioShellPasscodeCommands.handle(body) { payload in
			if payload["type"] as? String == "ack" { ack = payload; done.fulfill() }
		}
		wait(for: [done], timeout: 10)
		return ack
	}

	private func bind(_ id: String, _ eoa: String) { XCTAssertTrue(BeamioPasscodeSession.shared.bindIncomingCall(callId: id, eoa: eoa)) }

	/// Addendum 25: a call id the unlock would refuse for its format is not registered either.
	func testBindRefusesAnInvalidCallIdOrAccountAndRegistersNothing() {
		let session = BeamioPasscodeSession.shared
		for bad in ["", "short", String(repeating: "a", count: 7), String(repeating: "a", count: 129), "has space 12", "dot.dot.dot1", "colon:colon1"] {
			XCTAssertFalse(session.bindIncomingCall(callId: bad, eoa: account), bad)
			XCTAssertNil(session.incomingCall(callId: bad), bad)
		}
		XCTAssertFalse(session.bindIncomingCall(callId: "call-ok-0001", eoa: "0x12"))
		XCTAssertNil(session.incomingCall(callId: "call-ok-0001"))
		XCTAssertTrue(session.bindIncomingCall(callId: String(repeating: "a", count: 8), eoa: account))
		XCTAssertTrue(session.bindIncomingCall(callId: String(repeating: "b", count: 128), eoa: account))
		XCTAssertTrue(session.bindIncomingCall(callId: "0123456789abcdef0123456789abcdef", eoa: account.uppercased().replacingOccurrences(of: "0X", with: "0x")))
		XCTAssertEqual(session.incomingCall(callId: "0123456789abcdef0123456789abcdef")?.eoa, account)
	}

	func testBindAndUnbindAreNativeCallsNotBridgeCommands() {
		bind("call-1-xx", account)
		XCTAssertEqual(BeamioPasscodeSession.shared.incomingCall(callId: "call-1-xx")?.eoa, account)
		BeamioPasscodeSession.shared.unbindIncomingCall(callId: "call-1-xx")
		XCTAssertNil(BeamioPasscodeSession.shared.incomingCall(callId: "call-1-xx"))
		BeamioPasscodeSession.shared.unbindIncomingCall(callId: "call-1-xx") // an unknown call is a no-op
		XCTAssertNil(BeamioShellPasscodeCommands.allowedFields["incomingCallBind"])
		XCTAssertFalse(BeamioShellPasscodeCommands.names.contains("incomingCallBind"))
		XCTAssertFalse(BeamioConetChatModule.knownBridgeCommand("incomingCallBind"))
		XCTAssertFalse(BeamioConetChatModule.knownBridgeCommand("incomingCallUnbind"))
	}

	/// Addendum 14 §2: a page cannot register or clear a call. Through the bridge both names are unknown commands, at G0 and while locked alike.
	func testThroughTheBridgeBindAndUnbindAreRefusedAndTheRegistrationIsUnchanged() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		for gate in ["G0", "locked"] {
			if gate == "locked" { BeamioNativeAccountPointer.set(account) }
			bind("call-keep-xx", account)
			for type in ["incomingCallBind", "incomingCallUnbind"] {
				var answers: [[String: Any]] = []
				let done = expectation(description: "\(type) \(gate)")
				BeamioConetChatModule.handleCommand(["type": type, "reqId": nextReq, "callId": "call-keep-xx", "eoa": account]) { event in
					answers.append((event["event"] as? [String: Any]) ?? event)
					if (event["event"] as? [String: Any] ?? event)["type"] as? String == "ack" { done.fulfill() }
				}
				nextReq += 1
				wait(for: [done], timeout: 10)
				let ack = answers.first { $0["type"] as? String == "ack" }
				XCTAssertEqual(ack?["ok"] as? Bool, false, "\(type) at \(gate)")
				XCTAssertEqual(ack?["error"] as? String, "unknown_command", "\(type) at \(gate)")
			}
			XCTAssertEqual(BeamioPasscodeSession.shared.incomingCall(callId: "call-keep-xx")?.eoa, account, "the registration is unchanged at \(gate)")
			BeamioPasscodeSession.shared.unbindIncomingCall(callId: "call-keep-xx")
		}
	}

	func testBadFieldsAreBadRequest() {
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": ""])["error"] as? String, "bad_request")
		// length bounds (addendum 25): 7 too short, 8 and 128 good, 129 too long
		XCTAssertEqual(BeamioShellPasscodeCommands.validCallId(String(repeating: "a", count: 7)), nil)
		XCTAssertNotNil(BeamioShellPasscodeCommands.validCallId(String(repeating: "a", count: 8)))
		XCTAssertNotNil(BeamioShellPasscodeCommands.validCallId(String(repeating: "a", count: 128)))
		XCTAssertNil(BeamioShellPasscodeCommands.validCallId(String(repeating: "a", count: 129)))
		XCTAssertNotNil(BeamioShellPasscodeCommands.validCallId("0123456789abcdef0123456789abcdef"), "the current 32-hex id")
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": String(repeating: "a", count: 7)])["error"] as? String, "bad_request")
		for bad in ["a.b", "a:b", "a/b", "é"] {
			XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": bad])["error"] as? String, "bad_request", bad)
		}
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": String(repeating: "a", count: 129)])["error"] as? String, "bad_request")
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": 5])["error"] as? String, "bad_request")
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "a b"])["error"] as? String, "bad_request")
	}

	func testUnlockWithAnUnboundOrOtherCallIsRefusedBeforeAnyPasscodeCheck() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		// no vault record exists at all: a passcode check would answer something else; the account and the call are judged first (account first, addendum 16)
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-9-xx"])["error"] as? String, "account_mismatch", "no current native account")
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-9-xx"])["error"] as? String, "call_mismatch", "unbound call, account right")
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": other, "passcode": "73920461", "callId": "call-9-xx"])["error"] as? String, "account_mismatch", "the account is judged before the call")
		bind("call-1-xx", account)
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-2-xx"])["error"] as? String, "call_mismatch", "another call, account right")
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": other, "passcode": "73920461", "callId": "call-1-xx"])["error"] as? String, "account_mismatch")
		XCTAssertNotNil(BeamioPasscodeSession.shared.incomingCall(callId: "call-1-xx"), "a refusal does not consume the call")
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account), "nothing was unlocked")
	}

	/// Addendum 14: the eoa must be the bound one and the current native account.
	func testTheAccountMustBeBoundAndCurrent() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		BeamioNativeAccountPointer.set(other)
		bind("call-1-xx", account)
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-1-xx"])["error"] as? String, "account_mismatch", "bound, but not the current account")
		BeamioNativeAccountPointer.set(account) // an account switch clears the bound calls, so the binding follows it
		bind("call-3-xx", other)
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-3-xx"])["error"] as? String, "account_mismatch", "current, but not the bound account")
		XCTAssertNotNil(BeamioPasscodeSession.shared.incomingCall(callId: "call-3-xx"))
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: account))
	}

	func testAMatchingCallGoesOnToThePasscodeCheck() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		BeamioNativeAccountPointer.set(account)
		bind("call-1-xx", account)
		let error = call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-1-xx"])["error"] as? String
		XCTAssertNotEqual(error, "call_mismatch")
		XCTAssertNotEqual(error, "account_mismatch")
	}

	func testLogoutAndAccountSwitchClearTheBoundCallsButAPlainLockKeepsThem() {
		bind("call-1-xx", account)
		BeamioPasscodeSession.shared.lockAll(reason: .lock)
		XCTAssertNotNil(BeamioPasscodeSession.shared.incomingCall(callId: "call-1-xx"))
		BeamioPasscodeSession.shared.lockAll(reason: .accountSwitch)
		XCTAssertNil(BeamioPasscodeSession.shared.incomingCall(callId: "call-1-xx"))
		bind("call-2-xx", account)
		BeamioPasscodeSession.shared.lockAll(reason: .logout)
		XCTAssertNil(BeamioPasscodeSession.shared.incomingCall(callId: "call-2-xx"))
	}

	/// Addendum 23 §3: a lock of an already locked session does not move the generation, so a bound call stays good once the session is unlocked.
	func testALockWhileLockedKeepsTheGenerationAndTheBoundCall() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end(); BeamioPasscodeSession.shared.lockAll(reason: .logout) }
		let session = BeamioPasscodeSession.shared
		BeamioNativeAccountPointer.set(account)
		bind("call-1-xx", account)
		let g = session.generation(eoa: account)
		session.lockAll(reason: .lock)
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.generation(eoa: account), g, "locked already: no increment")
		session.install(eoa: account, bundle: [UInt8](repeating: 7, count: 40))
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: "call-1-xx"), .allow)
		// logout and account switch still move it while locked
		session.lockAll(reason: .lock)
		let h = session.generation(eoa: account)
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.generation(eoa: account), h)
		session.lockAll(reason: .logout)
		XCTAssertEqual(session.generation(eoa: account), h + 1)
	}

	/// The code table is in force: a mismatch is call_mismatch. With the switch off the old answer (bad_request) is still what the SDK gives.
	func testAMismatchAnswersCallMismatchAndTheSwitchOffKeepsTheOldAnswer() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		BeamioNativeAccountPointer.set(account)
		XCTAssertTrue(BeamioShellPasscodeCommands.callMismatchEffective, "in force by default")
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-9-xx"])["error"] as? String, "call_mismatch")
		// a malformed id is bad_request either way
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "a b"])["error"] as? String, "bad_request")
		BeamioShellPasscodeCommands.callMismatchEffective = false
		XCTAssertEqual(call(["type": "passcodeUnlock", "eoa": account, "passcode": "73920461", "callId": "call-9-xx"])["error"] as? String, "bad_request", "the old answer")
	}

}


/// The project owner's rule: the native unlock lasts until the next cold start; the UI lock does not touch it.
/// A real passcode record (memory stores), the commands as the page sends them.
final class NativeUnlockPersistsTests: XCTestCase {
	private final class KeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		var forcedRecordState: BeamioChatWalletKeyRecordState?
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState {
			forcedRecordState ?? (keys[eoa.lowercased()] != nil ? .present : .absent)
		}
	}
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let pass = "73920461"
	private let callA = "call-aaaa-0001", callB = "call-bbbb-0002"
	private var records: ShellPasscodeCoreTests.MemRecords!
	private var savedVault: BeamioPasscodeVault?
	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: KeyStore!
	private var nextReq = 7_000_000_000_800
	private let lock = NSLock()
	private var events: [[String: Any]] = []

	private var account: String {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { fatalError() }
		defer { BeamioNativeWallet.wipe(&key) }
		return BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		records = ShellPasscodeCoreTests.MemRecords()
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: ShellPasscodeCoreTests.MemHardware(), staging: ShellPasscodeCoreTests.MemRecords())
		BeamioPasscodeSession.shared.lockAll(reason: .logout)
		savedStore = BeamioNativeWallet.keyStore
		store = KeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioShellPasscodeCommands.resetForTests()
		BeamioShellPasscodeCommands.callMismatchEffective = true
		events = []
	}

	override func tearDown() {
		BeamioPasscodeSession.shared.lockAll(reason: .logout)
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	@discardableResult
	private func send(_ fields: [String: Any]) -> [String: Any]? {
		var body = fields
		body["reqId"] = nextReq; nextReq += 1
		let id = body["reqId"] as? Int
		let done = expectation(description: "ack")
		BeamioShellPasscodeCommands.handle(body) { [self] payload in
			lock.lock(); events.append(payload); lock.unlock()
			if payload["type"] as? String == "ack", payload["reqId"] as? Int == id { done.fulfill() }
		}
		wait(for: [done], timeout: 20)
		let drain = expectation(description: "drain")
		DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { drain.fulfill() }
		wait(for: [drain], timeout: 5)
		lock.lock(); defer { lock.unlock() }
		return events.last { $0["type"] as? String == "ack" && $0["reqId"] as? Int == id }
	}

	private func provision() {
		XCTAssertEqual(send(["type": "passcodeProvision", "eoa": account, "phrase": phrase, "passcode": pass])?["ok"] as? Bool, true)
	}

	private func stateEvents(reason: String) -> Int {
		lock.lock(); defer { lock.unlock() }
		return events.filter { $0["type"] as? String == "passcodeState" && $0["reason"] as? String == reason }.count
	}

	/// `uiLock()` is kept for the shell's calls and does nothing: no state, no passcodeState event, native session and generation untouched.
	func testTheUiLockCallIsANoOp() {
		provision()
		let session = BeamioPasscodeSession.shared
		XCTAssertEqual(session.appState(eoa: account), .unlocked)
		let g = session.generation(eoa: account)
		var seen: [[String: Any]] = []
		let seenLock = NSLock()
		BeamioConetChatModule.handleCommand(["type": "hello", "reqId": 1], emit: { out in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "passcodeState" else { return }
			seenLock.lock(); seen.append(event); seenLock.unlock()
		})
		let settle = expectation(description: "settle")
		DispatchQueue.main.async { settle.fulfill() }
		wait(for: [settle], timeout: 5)
		seenLock.lock(); seen = []; seenLock.unlock()
		session.lockAll(reason: .uiLock)
		session.uiLock()
		let drain = expectation(description: "drain")
		DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { drain.fulfill() }
		wait(for: [drain], timeout: 5)
		seenLock.lock(); defer { seenLock.unlock() }
		XCTAssertEqual(session.appState(eoa: account), .unlocked, "the native session stays")
		XCTAssertNotNil(session.bundle(eoa: account))
		XCTAssertEqual(session.generation(eoa: account), g, "no generation change")
		XCTAssertFalse(session.isUiLocked(eoa: account))
		XCTAssertTrue(seen.isEmpty, "no ui_lock event is sent")
	}

	func testAnswerAuthorizationOnlyNeedsTheBindingAndThePointedAccount() {
		provision()
		let session = BeamioPasscodeSession.shared
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .deny, "not bound")
		XCTAssertTrue(session.bindIncomingCall(callId: callA, eoa: account))
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow, "bound on the pointed account")
		session.uiLock()
		XCTAssertFalse(session.isUiLocked(eoa: account), "the SDK records no UI lock")
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow, "the UI lock call changes nothing")
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow, "a plain lock keeps the binding and decides nothing")
		BeamioNativeAccountPointer.set("0x2222222222222222222222222222222222222222")
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .deny, "another pointed account")
		BeamioNativeAccountPointer.set(account)
		session.lockAll(reason: .logout)
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .deny, "a logout ends the binding")
	}

	// MARK: the native lock and the UI lock (v253 sections 272.1 and 272.2)
	// Where it is implemented: `isLocked` (BeamioPasscodeSession.swift:49) is the native lock and is the only lock the command gate reads
	// (BeamioConetChatModule.swift:801); `uiLock()` (131) and `markUiUnlocked` (139) only move the UI lock, which the incoming-call authorization reads
	// (`incomingCallAuthorizeAnswer`, :110); `generation(eoa:)` (:172) moves on a lock of an unlocked session, a logout and an account switch.

	/// One command of the page at G2, answered through the real command entry. Returns the ack error word, or nil when no error word came.
	private func pageCommandAnswer(_ type: String, reqId: Int) -> [String: Any]? {
		var answer: [String: Any]?
		let lock = NSLock()
		BeamioConetChatModule.handleCommand(["type": type, "reqId": reqId], emit: { out in
			lock.lock(); defer { lock.unlock() }
			if let event = out["event"] as? [String: Any], event["reqId"] as? Int == reqId { answer = event }
			else if out["reqId"] as? Int == reqId { answer = out }
		})
		let deadline = Date().addingTimeInterval(5)
		while Date() < deadline {
			lock.lock(); let got = answer; lock.unlock()
			if got != nil { break }
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		lock.lock(); defer { lock.unlock() }
		return answer
	}

	private func pageCommandError(_ type: String, reqId: Int) -> String? { pageCommandAnswer(type, reqId: reqId)?["error"] as? String }

	/// replaces v253 272.1 and 272.2 in the SDK: there is no lock answer. Under the UI lock a chat send is not refused `locked`; with no unlocked
	/// bundle (the cold start of a passcode account) it is not refused `locked` either: it reaches its own checks. A key that cannot be read for real is
	/// reported by the checks that need it, as not_ready, never as locked.
	func testSendIsNotHeldByTheUiLockAndAnswersNotReadyWithItsReasonWithoutTheBundle() {
		provision()
		let session = BeamioPasscodeSession.shared
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		session.uiLock()
		// UI lock: the native session stays and nothing is held back: a send is not answered not_ready/passcode_not_provided either (it goes on to its own checks)
		let underUiLock = pageCommandAnswer("send", reqId: 8_100)
		XCTAssertNotEqual(underUiLock?["error"] as? String, "locked")
		XCTAssertNil(underUiLock?["reason"], "no passcode_not_provided while the bundle is there")
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.appState(eoa: account), .locked, "no unlocked bundle")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioNativeAccountPointer.set(account)
		for (id, type) in [(8_101, "send"), (8_102, "sendGroup")] {
			let answer = pageCommandAnswer(type, reqId: id)
			XCTAssertEqual(answer?["ok"] as? Bool, false, type)
			XCTAssertEqual(answer?["error"] as? String, "not_ready", "\(type): no bundle, the answer is not_ready")
			XCTAssertEqual(answer?["reason"] as? String, "passcode_not_provided", type)
		}
	}

	/// 272.2, a new cold start: a new process has a new session object. It holds no unlocked bundle, no bound call and no generation of the old
	/// one, so nothing of the old authorization is reused.
	func testANewColdStartDoesNotReuseTheOldAuthorization() {
		provision()
		let session = BeamioPasscodeSession.shared
		XCTAssertTrue(session.bindIncomingCall(callId: "call-cold-1", eoa: account))
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: "call-cold-1"), .allow, "the running process is unlocked and bound")
		let fresh = BeamioPasscodeSession()
		fresh.vault = session.vault
		XCTAssertEqual(fresh.appState(eoa: account), .locked, "the passcode is set and the new session holds no bundle")
		XCTAssertTrue(fresh.isLocked(eoa: account))
		XCTAssertNil(fresh.bundle(eoa: account))
		XCTAssertNil(fresh.incomingCall(callId: "call-cold-1"), "no call binding survives a new session")
		XCTAssertEqual(fresh.incomingCallAuthorizeAnswer(callId: "call-cold-1"), .deny)
		XCTAssertEqual(fresh.generation(eoa: account), 0)
	}

	/// the generation is no authorization rule. A call bound before a lock stays allowed after the session is unlocked again.
	func testAGenerationChangeDoesNotEndTheBinding() {
		provision()
		let session = BeamioPasscodeSession.shared
		XCTAssertTrue(session.bindIncomingCall(callId: "call-gen-old", eoa: account))
		let g = session.generation(eoa: account)
		session.lockAll(reason: .lock)
		XCTAssertEqual(session.generation(eoa: account), g + 1, "the counter still moves")
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": pass])?["ok"] as? Bool, true)
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: "call-gen-old"), .allow, "the generation decides nothing")
	}

	func testAnAccountWithoutAPasscodeIsAllowedWithoutAUiGate() {
		// a device record: no passcode set, the native key is readable (B i)
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		defer { BeamioNativeWallet.wipe(&key) }
		let session = BeamioPasscodeSession.shared
		_ = BeamioNativeAccountPointer.set(account)
		XCTAssertTrue(session.bindIncomingCall(callId: callA, eoa: account))
		// no record at all: protectionState absent counts as no passcode
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow)
		session.uiLock()
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow, "no passcode set: no UI gate")
	}

	/// A passcode unlock that fails while the native session is unlocked answers wrong_passcode and leaves the session (and a bound call) as it was.
	func testAWrongPasscodeWhileUnlockedDoesNotLockTheNativeSession() {
		provision()
		let session = BeamioPasscodeSession.shared
		XCTAssertTrue(session.bindIncomingCall(callId: callA, eoa: account))
		let g = session.generation(eoa: account)
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": "00000000", "callId": callA])?["error"] as? String, "wrong_passcode")
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": "00000000"])?["error"] as? String, "wrong_passcode")
		XCTAssertEqual(session.appState(eoa: account), .unlocked, "still unlocked")
		XCTAssertNotNil(session.bundle(eoa: account))
		XCTAssertEqual(session.generation(eoa: account), g)
		XCTAssertNotNil(session.incomingCall(callId: callA), "the call is still bound")
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow, "a failed check opened no UI lock and closed nothing")
		// the SDK keeps no UI lock: a failed unlock with a callId changes nothing either
		session.uiLock()
		XCTAssertEqual(send(["type": "passcodeUnlock", "eoa": account, "passcode": "00000000", "callId": callA])?["error"] as? String, "wrong_passcode")
		XCTAssertFalse(session.isUiLocked(eoa: account))
		XCTAssertEqual(session.incomingCallAuthorizeAnswer(callId: callA), .allow)
		XCTAssertEqual(session.appState(eoa: account), .unlocked)
	}

	private func viaModule(_ fields: [String: Any]) -> [String: Any]? {
		var body = fields
		body["reqId"] = nextReq; nextReq += 1
		var ack: [String: Any]?
		let done = expectation(description: "module ack")
		BeamioConetChatModule.handleCommand(body) { out in
			let event = (out["event"] as? [String: Any]) ?? out
			if event["type"] as? String == "ack" { ack = event; done.fulfill() }
		}
		wait(for: [done], timeout: 10)
		return ack
	}

	/// v41 s45.5 (the `locked` answer is superseded by): nativeIdentityCheck is not exempt; without the bundle it answers not_ready.
	func testNativeIdentityCheckIsGatedLikeAnyOtherCommand() {
		provision()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		let session = BeamioPasscodeSession.shared
		let unlocked = viaModule(["type": "nativeIdentityCheck", "eoa": account])
		XCTAssertEqual((unlocked?["result"] as? [String: Any])?["match"] as? Bool, true, "unlocked: a yes")
		session.uiLock()
		XCTAssertEqual((viaModule(["type": "nativeIdentityCheck", "eoa": account])?["result"] as? [String: Any])?["match"] as? Bool, true, "the UI lock does not gate it")
		session.lockAll(reason: .lock)
		let locked = viaModule(["type": "nativeIdentityCheck", "eoa": account])
		XCTAssertEqual(locked?["ok"] as? Bool, false)
		// no `locked` answer. Without the passcode bundle the answer is not_ready with the reason passcode_not_provided (vector IC-3).
		XCTAssertEqual(locked?["error"] as? String, "not_ready")
		XCTAssertEqual(locked?["reason"] as? String, "passcode_not_provided")
		XCTAssertFalse(BeamioConetChatModule.gateExemptCommands.contains("nativeIdentityCheck"))
		XCTAssertTrue(BeamioConetChatModule.knownBridgeCommand("nativeIdentityCheck"))
	}

	private func flat(_ ack: [String: Any]?) -> [String: Any] {
		// the page-visible reply of the vector: ok, the result fields, and error
		var out: [String: Any] = ["ok": ack?["ok"] as? Bool ?? false]
		for (k, v) in (ack?["result"] as? [String: Any]) ?? [:] { out[k] = v }
		if let e = ack?["error"] { out["error"] = e }
		if let r = ack?["reason"] { out["reason"] = r }
		return out
	}

	/// v43 s47 / v44 s49: IC-1..IC-5 of the shared increment vector, with the page-visible shape rules.
	func testTheSharedVectorIdentityCheckCasesIC1ToIC5() throws {
		let data = try BundledVectorFile.data(resource: "native-unlock-judgement-vectors.v3")
		let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["identityCheckCases"] as? [[String: Any]])
		XCTAssertEqual(cases.map { $0["id"] as? String }, (1 ... 5).map { "IC-\($0)" })
		let session = BeamioPasscodeSession.shared
		for c in cases {
			let id = c["id"] as? String ?? "?"
			// the native state of the case
			// a fresh device for each case
			session.lockAll(reason: .logout)
			BeamioNativeAccountPointer.clear()
			store.keys = [:]
			records = ShellPasscodeCoreTests.MemRecords()
			session.vault = BeamioPasscodeVault(records: records, hardware: ShellPasscodeCoreTests.MemHardware(), staging: ShellPasscodeCoreTests.MemRecords())
			provision()
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
			let nativeState = c["nativeState"] as? String ?? ""
			if nativeState == "locked" { session.lockAll(reason: .lock) }
			// the request: the vector's addresses stand for "same mnemonic" and "different mnemonic"
			var request = (c["request"] as? [String: Any]) ?? [:]
			if nativeState == "unlocked_same_mnemonic" || nativeState == "locked" { if request["eoa"] != nil { request["eoa"] = account } }
			if nativeState == "unlocked_different_mnemonic" { request["eoa"] = "0x2222222222222222222222222222222222222222" }
			request["type"] = "nativeIdentityCheck"
			let reply = flat(viaModule(request))
			let want = try XCTUnwrap(c["reply"] as? [String: Any])
			XCTAssertEqual(reply["ok"] as? Bool, want["ok"] as? Bool, id)
			XCTAssertEqual(reply["match"] as? Bool, want["match"] as? Bool, id)
			XCTAssertEqual(reply["error"] as? String, want["error"] as? String, id)
			XCTAssertEqual(reply["reason"] as? String, want["reason"] as? String, "\(id): the reason, only IC-3 carries one")
			// shape rules: ok always; match only when ok; error only when not ok; nothing else
			XCTAssertEqual(reply["match"] != nil, reply["ok"] as? Bool == true, "\(id) match only with ok")
			XCTAssertEqual(reply["error"] != nil, reply["ok"] as? Bool == false, "\(id) error only without ok")
			XCTAssertTrue(Set(reply.keys).isSubset(of: ["ok", "match", "error", "reason"]), "\(id) no other field")
		}
	}

	/// v43 s47: `passcodeStatus.nativeLocked` is a boolean; only false means unlocked; `locked` and `walletState` keep their meaning (NL-1, NL-2, NL-7 on the
	/// SDK side; the page-side judgement of NL-3..NL-6 is checked below against the vector).
	func testPasscodeStatusCarriesNativeLocked() throws {
		let session = BeamioPasscodeSession.shared
		provision()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		func status() -> [String: Any] { (viaModule(["type": "passcodeStatus"])?["result"] as? [String: Any]) ?? [:] }
		var r = status()
		XCTAssertEqual(r["nativeLocked"] as? Bool, false, "unlocked")
		XCTAssertEqual(r["locked"] as? Bool, false)
		XCTAssertNotNil(r["walletState"], "walletState stays, and is not the judgement")
		session.uiLock()
		XCTAssertEqual(status()["nativeLocked"] as? Bool, false, "a UI lock leaves it")
		session.lockAll(reason: .lock)
		r = status()
		XCTAssertEqual(r["nativeLocked"] as? Bool, true, "native locked")
		XCTAssertEqual(r["locked"] as? Bool, true)
		session.lockAll(reason: .logout)
		XCTAssertEqual(status()["nativeLocked"] as? Bool, true, "no account: locked (fail closed)")
		// the page-side judgement of the vector: only a boolean false means unlocked
		let data = try BundledVectorFile.data(resource: "native-unlock-judgement-vectors.v1")
		let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		for c in try XCTUnwrap(root["passcodeStatusCases"] as? [[String: Any]]) {
			let id = c["id"] as? String ?? "?"
			let reply = (c["reply"] as? [String: Any]) ?? [:]
			let value = reply["nativeLocked"]
			let unlocked: Bool = {
				guard let n = value as? NSNumber, CFGetTypeID(n as CFTypeRef) == CFBooleanGetTypeID() else { return false }
				return !n.boolValue
			}()
			XCTAssertEqual(unlocked, c["expectPageNativeUnlocked"] as? Bool, id)
		}
	}

	/// v45 s50: at G1 (session start not complete) nativeLocked is true, fail closed; the optional `eoa` of passcodeStatus.
	func testPasscodeStatusAtG1IsLockedAndTheEoaFieldIsJudged() {
		provision()
		func status(_ fields: [String: Any] = [:]) -> [String: Any]? {
			var body: [String: Any] = ["type": "passcodeStatus"]
			for (k, v) in fields { body[k] = v }
			return viaModule(body)
		}
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual((status()?["result"] as? [String: Any])?["nativeLocked"] as? Bool, false, "G2, unlocked")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		XCTAssertEqual((status()?["result"] as? [String: Any])?["nativeLocked"] as? Bool, true, "G1: locked, fail closed, although the passcode session is unlocked")
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		// the optional eoa
		XCTAssertEqual((status(["eoa": account])?["result"] as? [String: Any])?["nativeLocked"] as? Bool, false)
		XCTAssertEqual(status(["eoa": "0x2222222222222222222222222222222222222222"])?["error"] as? String, "account_mismatch")
		XCTAssertEqual(status(["eoa": "not-an-address"])?["error"] as? String, "bad_request")
		XCTAssertEqual(status(["eoa": 5])?["error"] as? String, "bad_request")
		XCTAssertEqual((status(["eoa": account.uppercased().replacingOccurrences(of: "0X", with: "0x")])?["result"] as? [String: Any])?["nativeLocked"] as? Bool, false, "case does not matter")
		BeamioPasscodeSession.shared.lockAll(reason: .logout)
		BeamioNativeAccountPointer.clear()
		XCTAssertEqual(status(["eoa": account])?["error"] as? String, "account_mismatch", "no current native account")
	}

	/// v2 of the shared vector (v45 s50): NL-8..NL-11 on the SDK's own answer, NL-1..NL-11 on the page-side judgement.
	func testTheSharedVectorV2NativeLockedCases() throws {
		let data = try BundledVectorFile.data(resource: "native-unlock-judgement-vectors.v2")
		let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["passcodeStatusCases"] as? [[String: Any]])
		XCTAssertEqual(cases.map { $0["id"] as? String }, (1 ... 11).map { "NL-\($0)" })
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		defer { BeamioNativeWallet.wipe(&key) }
		let session = BeamioPasscodeSession.shared
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let reply = (c["reply"] as? [String: Any]) ?? [:]
			// the page-side judgement: only a boolean false is unlocked
			let unlocked: Bool = {
				guard let n = reply["nativeLocked"] as? NSNumber, CFGetTypeID(n as CFTypeRef) == CFBooleanGetTypeID() else { return false }
				return !n.boolValue
			}()
			XCTAssertEqual(unlocked, c["expectPageNativeUnlocked"] as? Bool, id)
			guard let state = c["state"] as? String else { continue }
			// the SDK's own answer for the described device
			session.lockAll(reason: .logout)
			BeamioNativeAccountPointer.clear()
			store.keys = [:]
			store.forcedRecordState = nil
			records = ShellPasscodeCoreTests.MemRecords()
			session.vault = BeamioPasscodeVault(records: records, hardware: ShellPasscodeCoreTests.MemHardware(), staging: ShellPasscodeCoreTests.MemRecords())
			let passcodeSet = c["passcodeSet"] as? Bool ?? false
			if passcodeSet {
				provision()
			} else {
				BeamioNativeAccountPointer.set(account)
				store.keys[account] = Data(key)
			}
			if c["keyRecordReadable"] as? Bool == false { store.forcedRecordState = .unreadable }
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: state != "G1")
			let result = viaModule(["type": "passcodeStatus"])?["result"] as? [String: Any]
			XCTAssertEqual(result?["nativeLocked"] as? Bool, reply["nativeLocked"] as? Bool, id)
			XCTAssertEqual(result?["set"] as? Bool, reply["set"] as? Bool, id)
		}
	}

	func testNativeIdentityCheck() {
		let session = BeamioPasscodeSession.shared
		// native not unlocked: not_ready
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(send(["type": "nativeIdentityCheck", "eoa": account])?["error"] as? String, "not_ready", "no key to derive from")
		BeamioNativeAccountPointer.clear()
		provision()
		let same = send(["type": "nativeIdentityCheck", "eoa": account])
		XCTAssertEqual(same?["ok"] as? Bool, true)
		XCTAssertEqual((same?["result"] as? [String: Any])?["match"] as? Bool, true)
		let other = send(["type": "nativeIdentityCheck", "eoa": "0x2222222222222222222222222222222222222222"])
		XCTAssertEqual((other?["result"] as? [String: Any])?["match"] as? Bool, false)
		XCTAssertEqual(send(["type": "nativeIdentityCheck", "eoa": account.uppercased().replacingOccurrences(of: "0X", with: "0x")])?["ok"] as? Bool, true)
		XCTAssertEqual(send(["type": "nativeIdentityCheck", "eoa": "0x12"])?["error"] as? String, "bad_request")
		// through the module: a secret may not come in, and the name is not one of the gate-exempt six
		var viaModule: [String: Any]?
		let refused = expectation(description: "module ack")
		BeamioConetChatModule.handleCommand(["type": "nativeIdentityCheck", "reqId": nextReq, "eoa": account, "phrase": phrase]) { out in
			let event = (out["event"] as? [String: Any]) ?? out
			if event["type"] as? String == "ack" { viaModule = event; refused.fulfill() }
		}
		nextReq += 1
		wait(for: [refused], timeout: 10)
		XCTAssertEqual(viaModule?["error"] as? String, "key_over_bridge_refused", "no secret may come in")
		XCTAssertFalse(BeamioConetChatModule.gateExemptCommands.contains("nativeIdentityCheck"))
		XCTAssertEqual(send(["type": "nativeIdentityCheck", "eoa": account, "extra": 1])?["error"] as? String, "bad_request")
		// the UI lock does not change the answer; the session is untouched by the check
		session.uiLock()
		XCTAssertEqual((send(["type": "nativeIdentityCheck", "eoa": account])?["result"] as? [String: Any])?["match"] as? Bool, true)
		XCTAssertEqual(session.appState(eoa: account), .unlocked)
		// native locked (process end): not_ready
		session.lockAll(reason: .lock)
		XCTAssertEqual(send(["type": "nativeIdentityCheck", "eoa": account])?["error"] as? String, "not_ready")
	}
}
