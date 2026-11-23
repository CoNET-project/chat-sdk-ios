import XCTest
@testable import ConetChatSDK

/// Native account creation. Synthetic entropy only: the BIP-39 test vectors
/// (16 zero bytes, and 16 bytes of 0xff). The phrase, the key and the result are checked to stay inside the native layer.
final class NativeAccountCreateTests: XCTestCase {
	/// The public BIP-39 test phrase for 16 zero bytes, and its account at m/44'/60'/0'/0/0.
	private let zeroPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let zeroEoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let zeroEntropy = [UInt8](repeating: 0x00, count: 16)
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	/// A mnemonic-capable double: the key record is `keys`; the mnemonic, intent and commit items are `mnemonic` (TestMnemonicItems), so the
	/// creation writes and reads them as the product store does (25.52Y.163 第 2 至 4 項).
	final class CreateKeyStore: BeamioChatMnemonicKeyStoring {
		var mnemonic = TestMnemonicItems()
		func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
			kind == .key ? (keys[eoa.lowercased()] == nil ? .absent : .present) : mnemonic.itemState(kind, eoa: eoa)
		}
		func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
			kind == .key ? write(eoa: eoa, key: value) : mnemonic.writeItem(kind, eoa: eoa, value: value)
		}
		func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? {
			kind == .key ? read(eoa: eoa) : mnemonic.readItem(kind, eoa: eoa)
		}
		func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
			if kind == .key { delete(eoa: eoa); return keys[eoa.lowercased()] == nil }
			return mnemonic.deleteItem(kind, eoa: eoa)
		}
		func intentOwners() -> [String]? { mnemonic.intentOwners() }
		func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? { mnemonic.mnemonicRecordCreations() }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		/// Every key held is a valid record for these tests (the vectors of the create tests write well-formed keys).
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { keys.keys.map { .valid(eoa: $0) } }
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var writeFail = false
		var readbackFail = false
		var writes = 0

		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			if writeFail { return false }
			keys[eoa.lowercased()] = key
			return true
		}

		/// With `readbackFail`, the bytes read back differ from the bytes written (step 4).
		func read(eoa: String) -> Data? {
			guard let value = keys[eoa.lowercased()] else { return nil }
			guard readbackFail, !value.isEmpty else { return value }
			var flipped = value
			flipped[flipped.count - 1] ^= 0x01
			return flipped
		}

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

	private var savedStore: BeamioChatWalletKeyStoring?
	/// PY.18 (r3rz): the creation is admitted only with a confirmed empty legacy store, so the tests run with that device state.
	private final class EmptyDevice: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState(accountEstablished: false, legacyUnreadable: false, legacyConfirmedAbsent: true, legacyFound: false)
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}
	private var store = CreateKeyStore()
	private var hostCalls = 0
	private var hostAnswer = true
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = CreateKeyStore()
		BeamioNativeWallet.keyStore = store
		hostCalls = 0
		hostAnswer = true
		events = []
		// The binding lookup is answered without a call here: no binding, so the creation step is reached. The lookup itself is
		// tested in BeamioAccountBindingMockTests and BeamioAccountBindingLiveTests.
		BeamioAccountBindingLookup.override = { _ in .noBinding }
		BeamioNativeAccountCreate.onCreateRequired = { [weak self] in
			guard let self else { return false }
			self.hostCalls += 1
			return self.hostAnswer
		}
		BeamioNativeAccountPointer.clear()
		BeamioShellRecord.testDeviceOverride = EmptyDevice()
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
	}

	override func tearDown() {
		BeamioShellRecord.testDeviceOverride = nil
		BeamioAccountBindingLookup.override = nil
		BeamioNativeAccountCreate.onCreateRequired = nil
		// A page left open sends its `cancelled` asynchronously: deliver it to this test, not to the next one.
		BeamioConetChatModule.closeAccountCreatePage()
		_ = drain()
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// Lets the main queue run the answers that are posted asynchronously, then returns the events sent since `from`.
	private func drain(from: Int = 0) -> [[String: Any]] {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return Array(events.dropFirst(from))
	}

	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		let from = events.count
		BeamioConetChatModule.handleCommand(body, emit: { [weak self] event in
			let payload = (event["event"] as? [String: Any]) ?? event
			// a new pointer (empty → the new account) is announced by a passcodeState event (reason account_switch): not part of what these tests count
			if payload["type"] as? String == "passcodeState" { return }
			self?.events.append(payload)
		})
		return drain(from: from)
	}

	private func open(reqId: Int = 1) -> [[String: Any]] {
		dispatch(["type": "nativeAccountCreateOpen", "reqId": reqId, "account": zeroEoa])
	}

	/// G1: a native record on the device and no `init` yet. G2: the same, with the session ready.
	private func enterG1() {
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
	}

	private func enterG2() {
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
	}

	// MARK: - gate and ack (T-237)

	func testG0OpensThePageAndAcksOk() {
		let answer = open()
		XCTAssertEqual(answer.count, 1)
		XCTAssertEqual(answer.first?["type"] as? String, "ack")
		XCTAssertEqual(answer.first?["ok"] as? Bool, true)
		XCTAssertNil(answer.first?["error"])
		XCTAssertEqual(hostCalls, 1)
		XCTAssertTrue(BeamioConetChatModule.accountCreatePageOpen())
	}

	func testG1AndG2AnswerNotAvailableAndOpenNothing() {
		enterG1()
		let g1 = open(reqId: 2)
		XCTAssertEqual(g1.first?["ok"] as? Bool, false)
		XCTAssertEqual(g1.first?["error"] as? String, "not_available")
		enterG2()
		let g2 = open(reqId: 3)
		XCTAssertEqual(g2.first?["error"] as? String, "not_available")
		XCTAssertEqual(hostCalls, 0, "G1 and G2 never call the host")
		XCTAssertFalse(BeamioConetChatModule.accountCreatePageOpen())
	}

	func testWithoutAHostEveryStateIsNotSupported() {
		BeamioNativeAccountCreate.onCreateRequired = nil
		XCTAssertEqual(open().first?["error"] as? String, "not_supported", "G0")
		enterG1()
		XCTAssertEqual(open(reqId: 2).first?["error"] as? String, "not_supported", "G1")
		enterG2()
		XCTAssertEqual(open(reqId: 3).first?["error"] as? String, "not_supported", "G2")
		XCTAssertFalse(BeamioConetChatModule.accountCreatePageOpen())
	}

	func testAHostThatDoesNotOpenAcksNotAvailable() {
		hostAnswer = false
		let answer = open()
		XCTAssertEqual(answer.first?["ok"] as? Bool, false)
		XCTAssertEqual(answer.first?["error"] as? String, "not_available")
		XCTAssertFalse(BeamioConetChatModule.accountCreatePageOpen())
	}

	// MARK: - input (T-238)

	func testAnExtraFieldIsBadRequestAndTheHostIsNotCalled() {
		let answer = dispatch(["type": "nativeAccountCreateOpen", "reqId": 4, "extra": "x"])
		XCTAssertEqual(answer.first?["error"] as? String, "bad_request")
		XCTAssertEqual(hostCalls, 0)
	}

	func testACredentialFieldIsRefusedWithoutEchoingItsValue() {
		let secret = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		let answer = dispatch(["type": "nativeAccountCreateOpen", "reqId": 5, "mnemonic": secret])
		XCTAssertEqual(answer.first?["error"] as? String, "key_over_bridge_refused")
		XCTAssertEqual(hostCalls, 0)
		XCTAssertFalse(String(describing: answer).contains("abandon"), "the value is not echoed")
	}

	// MARK: - generation, write, read-back, rollback (T-239)

	func testTheZeroEntropyPhraseIsTheBip39Vector() {
		XCTAssertEqual(BeamioNativeAccountCreate.phrase(entropy: zeroEntropy), zeroPhrase)
		let ones = [UInt8](repeating: 0xff, count: 16)
		XCTAssertEqual(BeamioNativeAccountCreate.phrase(entropy: ones),
		               "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
		XCTAssertNil(BeamioNativeAccountCreate.phrase(entropy: [UInt8](repeating: 0, count: 15)))
	}

	func testConfirmWritesTheKeyReadsItBackAndSendsTheAddress() {
		_ = open()
		let writesBefore = store.writes
		XCTAssertEqual(BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy), .ok(eoa: zeroEoa))
		let sent = drain(from: 1)
		XCTAssertEqual(sent.count, 1, "one result for one confirmation")
		XCTAssertEqual(sent.first?["type"] as? String, "nativeAccountCreateResult")
		XCTAssertEqual(accountCreateCode(sent.first), "ok")
		XCTAssertEqual(accountCreateEoa(sent.first), zeroEoa)
		XCTAssertEqual(store.writes - writesBefore, 1)
		XCTAssertEqual(store.keys[zeroEoa]?.count, 32, "the 32-byte key is stored, not the phrase")
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "the account is on the device, not yet initialised")
		XCTAssertFalse(BeamioConetChatModule.accountCreatePageOpen(), "ok closes the page")
	}

	func testAnExistingKeyIsNotOverwritten() {
		_ = open()
		let old = Data(repeating: 0x22, count: 32)
		// No pointer, so the gate is G0; the key is already in the store under the derived address, which the store check finds.
		store.keys[zeroEoa] = old
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		let sent = drain(from: 1)
		XCTAssertEqual(accountCreateCode(sent.first), "already_exists")
		XCTAssertNil(accountCreateEoa(sent.first))
		XCTAssertEqual(store.keys[zeroEoa], old, "the existing key is kept")
		XCTAssertTrue(BeamioConetChatModule.accountCreatePageOpen(), "a failure keeps the page open for a retry")
	}

	func testAFailedWriteLeavesNothingAndTheRetrySucceeds() {
		_ = open()
		store.writeFail = true
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		XCTAssertEqual(accountCreateCode(drain(from: 1).first), "write_failed")
		XCTAssertNil(store.keys[zeroEoa], "rolled back: the device has no key")
		XCTAssertTrue(BeamioConetChatModule.accountCreatePageOpen())

		store.writeFail = false
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		let sent = drain(from: 2)
		XCTAssertEqual(accountCreateCode(sent.first), "ok")
		XCTAssertEqual(accountCreateEoa(sent.first), zeroEoa)
	}

	func testAFailedReadBackIsRolledBack() {
		_ = open()
		store.readbackFail = true
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		let sent = drain(from: 1)
		XCTAssertEqual(accountCreateCode(sent.first), "readback_failed")
		XCTAssertNil(accountCreateEoa(sent.first))
		XCTAssertNil(store.keys[zeroEoa], "rolled back: the device has no key")
	}

	func testNothingIsGeneratedWithoutAnOpenPage() {
		XCTAssertEqual(BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy), .failed(.notAvailable))
		XCTAssertEqual(store.writes, 0)
		XCTAssertTrue(drain().isEmpty)
	}

	func testTheGateIsJudgedAgainAtConfirmation() {
		_ = open()
		enterG2()
		let writesBefore = store.writes
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		XCTAssertEqual(accountCreateCode(drain(from: 1).first), "already_exists")
		XCTAssertEqual(store.writes, writesBefore, "nothing is written when the device already has a key")
	}

	// MARK: - result, close and boundary (T-240)

	func testClosingBeforeAnyResultSendsCancelled() {
		_ = open()
		XCTAssertTrue(BeamioNativeAccountCreate.close())
		let sent = drain(from: 1)
		XCTAssertEqual(sent.count, 1)
		XCTAssertEqual(accountCreateCode(sent.first), "cancelled")
		XCTAssertNil(accountCreateEoa(sent.first))
		XCTAssertFalse(BeamioNativeAccountCreate.close(), "no page is open any more")
	}

	func testClosingAfterAFailureSendsNothingMore() {
		_ = open()
		store.writeFail = true
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		XCTAssertTrue(BeamioNativeAccountCreate.close())
		let sent = drain(from: 1)
		XCTAssertEqual(sent.map { accountCreateCode($0) }, ["write_failed"], "no cancelled after a result")
	}

	/// T-240: the `ok` result carries the address, the key as stored, and the phrase. The creation makes no recovery code.
	func testTheOkResultCarriesTheAddressOnly() {
		_ = open()
		XCTAssertEqual(BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy), .ok(eoa: zeroEoa))
		let result = drain(from: 1).first ?? [:]
		// 2(b): the creation result is the address only. The phrase and the key stay in the native store ((b)).
		XCTAssertEqual(Set(result.keys), ["type", "reqId", "ok", "result"], "the ok result is the nested form (25.52Y.137 第 6 项)")
		XCTAssertEqual(Set((accountCreateResult(result) ?? [:]).keys), ["code", "eoa", "cleanupPending"], "the ok result carries the address and cleanupPending only")
		XCTAssertEqual(accountCreateEoa(result), zeroEoa)
		XCTAssertNil(result["mnemonicPhrase"], "the phrase does not pass the bridge")
		XCTAssertNil(result["privateKeyArmor"], "the key does not pass the bridge")
		XCTAssertNil(result["recoveryWords"], "the creation makes no recovery code (25.46.7)")
	}

	/// T-240: a result that is not `ok` carries neither the address nor a W field.
	func testAFailedResultCarriesNoWalletFields() {
		_ = open()
		store.keys[zeroEoa] = Data(repeating: 0x11, count: 32)
		XCTAssertEqual(BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy), .failed(.alreadyExists))
		let result = drain(from: 1).first ?? [:]
		XCTAssertEqual(Set(result.keys), ["type", "reqId", "ok", "result"])
		XCTAssertEqual(Set((accountCreateResult(result) ?? [:]).keys), ["code"], "a failed result carries the code only")
	}

	/// T-240,: the native observer gets the `ok` result without the W fields. The WebView gets them whole (see above).
	func testTheObserverGetsTheResultWithoutTheWalletFields() {
		var observed: [[String: Any]] = []
		let saved = BeamioConetChatModule.nativeObserver
		BeamioConetChatModule.nativeObserver = { payload in observed.append((payload["event"] as? [String: Any]) ?? [:]) }
		defer { BeamioConetChatModule.nativeObserver = saved }
		_ = open()
		_ = BeamioNativeAccountCreate.createAccount(store: store, entropy: zeroEntropy)
		_ = drain(from: 1)
		let last = observed.last ?? [:]
		XCTAssertEqual(accountCreateCode(last), "ok")
		XCTAssertEqual(accountCreateEoa(last), zeroEoa)
		XCTAssertNil(last["privateKeyArmor"])
		XCTAssertNil(last["mnemonicPhrase"])
	}

	/// T-249: the two binding codes are forwarded, and carry no `eoa`.
	func testTheBindingCodesAreForwardedWithoutAnAddress() {
		_ = open(reqId: 9)
		let bound = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 9, "code": "already_bound"])
		XCTAssertTrue(bound.forwarded)
		let withEoa = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 9, "code": "lookup_unavailable", "eoa": zeroEoa])
		XCTAssertFalse(withEoa.forwarded)
		XCTAssertEqual(withEoa.reason, "eoa_not_allowed")
		let unavailable = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 9, "code": "lookup_unavailable"])
		XCTAssertTrue(unavailable.forwarded)
		let sent = drain(from: 1)
		XCTAssertEqual(sent.map { accountCreateCode($0) }, ["already_bound", "lookup_unavailable"])
		XCTAssertEqual(Set((sent.first ?? [:]).keys), ["type", "reqId", "ok", "result"], "the event keys: no eoa outside the result")
		XCTAssertEqual(Set((accountCreateResult(sent.first) ?? [:]).keys), ["code"], "no eoa with a binding code")
	}

	/// 25.52Y.148: the three wallet fields never reach the page. A result that carries one is refused as a whole (`field_not_allowed`, with
	/// the field names only), whatever its code, and the page stays open. A valid ok without them is forwarded without any of the three.
	func testTheWalletFieldsNeverReachThePage() {
		_ = open(reqId: 7)
		let armor = "0x" + String(repeating: "ab", count: 32)
		let onCancelled = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 7, "code": "cancelled", "privateKeyArmor": armor])
		XCTAssertFalse(onCancelled.forwarded)
		XCTAssertEqual(onCancelled.reason, "field_not_allowed")
		XCTAssertEqual(onCancelled.fields, ["privateKeyArmor"])
		let nullPhrase = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 7, "code": "ok", "eoa": zeroEoa, "mnemonicPhrase": NSNull()])
		XCTAssertFalse(nullPhrase.forwarded, "a null is a field present")
		XCTAssertEqual(nullPhrase.reason, "field_not_allowed")
		XCTAssertEqual(nullPhrase.fields, ["mnemonicPhrase"])
		let words = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 7, "code": "ok", "eoa": zeroEoa, "recoveryWords": "x"])
		XCTAssertFalse(words.forwarded)
		XCTAssertEqual(words.fields, ["recoveryWords"])
		let all = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 7, "code": "ok", "eoa": zeroEoa, "privateKeyArmor": armor, "mnemonicPhrase": zeroPhrase, "recoveryWords": "x"])
		XCTAssertFalse(all.forwarded)
		XCTAssertEqual(all.fields, ["mnemonicPhrase", "privateKeyArmor", "recoveryWords"])
		XCTAssertTrue(BeamioConetChatModule.accountCreatePageOpen(), "every drop keeps the page open")
		XCTAssertEqual(drain(from: 1).count, 0, "no drop reaches the page")
		let valid = BeamioConetChatModule.deliverAccountCreateResult(["type": "nativeAccountCreateResult", "reqId": 7, "code": "ok", "eoa": zeroEoa])
		XCTAssertTrue(valid.forwarded)
		let sent = drain(from: 1)
		XCTAssertEqual(sent.count, 1, "only the valid ok is forwarded")
		XCTAssertNil(sent.first?["privateKeyArmor"], "the page never receives the private key")
		XCTAssertNil(sent.first?["mnemonicPhrase"], "the page never receives the phrase")
		XCTAssertNil(sent.first?["recoveryWords"], "the page never receives the recovery words")
		XCTAssertEqual(Set((accountCreateResult(sent.first) ?? [:]).keys), ["code", "eoa", "cleanupPending"])
	}
}
