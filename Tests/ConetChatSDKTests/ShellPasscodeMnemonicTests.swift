#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The mnemonic around the passcode record (frozen protocol §7): the item becomes a header, the phrase lives in the record,
/// a locked account gives no phrase, `walletStatus` says `passcode_required`, disable puts the phrase back. Production passcode store over the test
/// memory (never the Keychain); synthetic phrase.
final class ShellPasscodeMnemonicTests: XCTestCase {
	private let service = "com.beamio.beamio.chat-wallet"
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let pass = "73920461"
	private var eoa = ""
	private var records: ShellPasscodeCoreTests.MemRecords!
	private var hardware: ShellPasscodeCoreTests.MemHardware!
	private var store: BeamioPasscodeWalletStore!
	private var savedMemory: [String: Data]?
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	private let lock = NSLock()
	private var events: [[String: Any]] = []
	private var nextReq = 7_000_000_000_000

	override func setUp() {
		super.setUp()
		// This class tests the withdrawn device and passcode record formats (never published). The production `write` and `delete` of the store are off
		//; the test seam turns the old behaviour on here only, so that the formats stay covered.
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = true
		savedMemory = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		NativeAccountPointerIsolation.begin()
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail("fixture") }
		eoa = BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
		BeamioNativeWallet.wipe(&key)
		records = ShellPasscodeCoreTests.MemRecords()
		hardware = ShellPasscodeCoreTests.MemHardware()
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: hardware, staging: ShellPasscodeCoreTests.MemRecords())
		BeamioPasscodeSession.shared.lockAll()
		store = BeamioPasscodeWalletStore(records: records, hardware: hardware, legacy: BeamioChatWalletKeychainStore.standard, session: BeamioPasscodeSession.shared)
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		BeamioShellPasscodeCommands.resetForTests()
		events = []
	}

	override func tearDown() {
		BeamioPasscodeWalletStore.deviceRecordWritesForTests = false
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedStore
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		NativeAccountPointerIsolation.end()
		BeamioChatWalletTestMemory.items = savedMemory
		super.tearDown()
	}

	private func send(_ fields: [String: Any]) -> [String: Any]? {
		var body = fields
		let id = nextReq
		body["reqId"] = id
		nextReq += 1
		let done = expectation(description: "ack")
		BeamioShellPasscodeCommands.handle(body) { [self] payload in
			lock.lock(); events.append(payload); lock.unlock()
			if payload["type"] as? String == "ack", payload["reqId"] as? Int == id { done.fulfill() }
		}
		wait(for: [done], timeout: 20)
		lock.lock()
		defer { lock.unlock() }
		return events.last { $0["type"] as? String == "ack" && $0["reqId"] as? Int == id }
	}

	/// The account as an import leaves it: a device key record and a device-bound phrase item.
	private func existingDeviceAccount() {
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		XCTAssertTrue(store.write(eoa: eoa, key: Data(key)))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: eoa, value: Data(phrase.utf8)))
		BeamioNativeAccountPointer.set(eoa)
	}

	private func rawItem() -> Data? { BeamioChatWalletTestMemory.get(service, "mnemonic:" + eoa) }

	func testProvisionTurnsTheItemIntoAHeaderAndTheRecordKeepsThePhrase() throws {
		existingDeviceAccount()
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8))
		XCTAssertEqual((send(["type": "passcodeProvision", "eoa": eoa, "phrase": phrase, "passcode": pass])?["result"] as? [String: Any])?["passcode"] as? String, "set")
		let header = try XCTUnwrap(rawItem())
		XCTAssertTrue(BeamioShellMnemonicItem.isHeader(header, owner: eoa))
		XCTAssertNil(header.range(of: Data(phrase.utf8)), "no phrase in the header")
		XCTAssertNil(header.range(of: Data("abandon".utf8)))
		// unlocked: the phrase reads from the record, and the account judges valid
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8))
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa), .valid)
		// locked: no phrase, not read at all
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertNil(store.readItem(.mnemonic, eoa: eoa))
		XCTAssertEqual(store.itemState(.mnemonic, eoa: eoa), .present, "the header: valid and locked, not unreadable")
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa), .valid)
		XCTAssertTrue(store.lockedMnemonicHeaderIsValid(owner: eoa))
		guard case .unreadable = store.rawRead(account: store.accountName(.mnemonic, eoa: eoa)) else { return XCTFail("a locked raw read must be refused") }
		// the unlock brings it back
		XCTAssertEqual((send(["type": "passcodeUnlock", "eoa": eoa, "passcode": pass])?["result"] as? [String: Any])?["unlocked"] as? Bool, true)
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8))
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa), .valid)
	}

	func testAFreshAccountGetsTheHeaderAndJudgesValidWhenUnlocked() {
		XCTAssertEqual((send(["type": "passcodeProvision", "eoa": eoa, "phrase": phrase, "passcode": pass])?["result"] as? [String: Any])?["verifiedAddress"] as? String, eoa)
		XCTAssertTrue(BeamioShellMnemonicItem.isHeader(rawItem() ?? Data(), owner: eoa))
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa), .valid)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), eoa)
	}

	func testTheHeaderIsNotWrittenOverWhileLockedAndAnOldItemSurvives() {
		existingDeviceAccount()
		let before = rawItem()
		XCTAssertFalse(store.writeMnemonicHeader(eoa: eoa), "no passcode record holds the phrase: the old item is the only copy")
		XCTAssertEqual(rawItem(), before)
		XCTAssertFalse(store.lockedMnemonicHeaderIsValid(owner: eoa))
		// a phrase write beside a header is refused (no second copy)
		_ = send(["type": "passcodeProvision", "eoa": eoa, "phrase": phrase, "passcode": pass])
		XCTAssertFalse(store.writeItem(.mnemonic, eoa: eoa, value: Data(phrase.utf8)))
	}

	func testDisablePutsThePhraseBackUnderTheDeviceLayer() {
		existingDeviceAccount()
		_ = send(["type": "passcodeProvision", "eoa": eoa, "phrase": phrase, "passcode": pass])
		XCTAssertTrue(BeamioShellMnemonicItem.isHeader(rawItem() ?? Data(), owner: eoa))
		let result = send(["type": "passcodeDisable", "eoa": eoa, "passcode": pass])
		XCTAssertEqual((result?["result"] as? [String: Any])?["disabled"] as? Bool, true)
		XCTAssertFalse(BeamioShellMnemonicItem.isHeader(rawItem() ?? Data(), owner: eoa))
		XCTAssertEqual(store.readItem(.mnemonic, eoa: eoa), Data(phrase.utf8))
		XCTAssertEqual(store.mnemonicAccountState(owner: eoa), .valid)
	}

	func testWalletStatusAnswersPasscodeRequiredWhileLocked() throws {
		existingDeviceAccount()
		_ = send(["type": "passcodeProvision", "eoa": eoa, "phrase": phrase, "passcode": pass])
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		var answer: [String: Any]?
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 41], emit: { out in
			if let event = out["event"] as? [String: Any], event["reqId"] as? Int == 41 { answer = event["result"] as? [String: Any] }
		})
		let deadline = Date().addingTimeInterval(5)
		while answer == nil && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
		// the real state, not an application lock
		XCTAssertEqual(answer?["status"] as? String, "not_ready")
		XCTAssertEqual(answer?["notReadyReason"] as? String, "passcode_not_provided")
		XCTAssertEqual(answer?["retryable"] as? Bool, true)
		XCTAssertNil(answer?["accountKey"], "this answer carries no accountKey")
	}
}
#endif
