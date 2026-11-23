#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// walletStatus and the preread must give the same account judgement (RULING-59E-classification-single-judgement-WK26, items 1, 3, 4; E9.1-4).
/// Each scenario runs `walletStatus` through the command, as the page sends it, and the preread reading of the same store.
/// Synthetic accounts and phrases only; no key material is returned by either answer.
final class WalletStatusRulingTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private var accountA: (eoa: String, key: Data) {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { preconditionFailure("the test phrase derives an account") }
		return derived
	}

	private func ackResult(_ reqId: Int) -> [String: Any]? {
		events.compactMap { out -> [String: Any]? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack",
			      event["reqId"] as? Int == reqId else { return nil }
			return event["result"] as? [String: Any]
		}.first
	}

	private func walletStatus(_ reqId: Int) -> [String: Any]? {
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": reqId], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while ackResult(reqId) == nil, Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		return ackResult(reqId)
	}

	private func preread() -> BeamioPwaWalletSync.Reading {
		BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
	}

	/// Item 1: a valid current mnemonic with its key and the pointer: walletStatus is the normal account and the preread is valid.
	func testNormalAccountAgreesWithThePreread() {
		let a = accountA
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		BeamioNativeAccountPointer.set(a.eoa)
		// G2: the session of this account is ready (after init). Before init the account is G1, and walletStatus is g1_uninitialized by design.
		BeamioConetChatModule.setNativeGateForTests(account: a.eoa, sessionReady: true)
		BeamioNativeKeySnapshot.invalidate()
		let status = walletStatus(9101)
		XCTAssertEqual(preread().state, .valid)
		XCTAssertEqual(status?["status"] as? String, "unlocked", "a valid current mnemonic is a normal account, not not_ready or no_key")
	}

	/// Item 4: a real read failure of the current mnemonic: walletStatus and the preread are both unknown (unreadable).
	func testReadFailureIsUnknownInBothAnswers() {
		let a = accountA
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.mnemonic.failReadOwners.insert(a.eoa.lowercased())
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioNativeKeySnapshot.invalidate()
		let status = walletStatus(9102)
		XCTAssertEqual(preread().state, .unknown, "the preread is unknown on a read failure")
		XCTAssertEqual(status?["status"] as? String, "not_ready", "walletStatus is not_ready on a read failure")
		XCTAssertEqual(status?["notReadyReason"] as? String, "unreadable", "walletStatus names the read failure")
	}

	/// Item 3: the current record is absent and a sealed copy holds a valid phrase: walletStatus describes the current record (no_key), the preread
	/// answers valid from the third position.
	func testSealedCopyOnlyIsNoKeyInWalletStatusAndValidInThePreread() {
		let a = accountA
		store.rawAccounts[BeamioPwaPhraseOverwrite.isolationPrefix + "t3." + store.accountName(.mnemonic, eoa: a.eoa)] =
			BeamioPwaWalletSync.normalized(phraseA)
		let row: [[String: String]] = [["from": store.accountName(.mnemonic, eoa: a.eoa),
		                                "to": BeamioPwaPhraseOverwrite.isolationPrefix + "t3." + store.accountName(.mnemonic, eoa: a.eoa),
		                                "utc": "2026-11-17T01:00:00Z"]]
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = (try? JSONSerialization.data(withJSONObject: row)) ?? Data()
		let status = walletStatus(9103)
		XCTAssertEqual(preread().state, .valid, "the sealed copy is the third position: valid")
		XCTAssertEqual(preread().eoa, a.eoa)
		XCTAssertEqual(status?["status"] as? String, "no_key", "walletStatus describes the current record, which is absent")
	}

	/// Item 1 (the record-without-mnemonic side): a key record only is no account for both answers (E7, 第 31、32 項).
	func testKeyOnlyIsNoAccountInBothAnswers() {
		let a = accountA
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		let status = walletStatus(9104)
		XCTAssertEqual(preread().state, .absent)
		XCTAssertEqual(status?["status"] as? String, "no_key")
	}
	/// project requirement (E9.10.3-3): the E4 settlement lock yields to walletStatus only. With an unsettled overwrite marker and a valid current
	/// mnemonic, walletStatus is the normal account, and the family commands (the write and settlement paths) are still refused not_ready.
	func testSettlementLockStillBlocksFamilyCommandsButNotWalletStatus() {
		let a = accountA
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		let marker: [String: Any] = ["v": 1, "phase": "pending", "eoa": a.eoa, "tag": "lock", "source": "pwaWalletSync",
		                             "utc": "2026-11-17T00:00:00Z", "owners": [a.eoa], "moves": [], "partials": []]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])) ?? Data()
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioConetChatModule.setNativeGateForTests(account: a.eoa, sessionReady: true)
		BeamioNativeKeySnapshot.invalidate()
		XCTAssertTrue(BeamioPwaPhraseOverwrite.settlementLockPending(store: store), "the marker is an unsettled overwrite")
		let status = walletStatus(9201)
		XCTAssertEqual(status?["status"] as? String, "unlocked", "walletStatus yields to the settlement lock")
		BeamioConetChatModule.handleCommand(["type": "walletSignMessage", "reqId": 9202, "message": "x"], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while ackErrorFor(9202) == nil, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
		XCTAssertEqual(ackErrorFor(9202), "not_ready", "the settlement lock still blocks the family commands")
	}

	private func ackErrorFor(_ reqId: Int) -> String? {
		events.compactMap { out -> String?? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack", event["reqId"] as? Int == reqId else { return nil }
			return .some(event["error"] as? String)
		}.first ?? nil
	}
}
#endif
