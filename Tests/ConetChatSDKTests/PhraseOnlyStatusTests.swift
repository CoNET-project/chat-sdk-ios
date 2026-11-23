#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// PHR-01..PHR-04 (v227 section 247.4; requirement item 1): the pointer names an account whose key record is missing and whose mnemonic is left (a phrase-only residue). walletStatus
/// answers `locked` with `phrase_only` and the accountKey when the residue phrase is readable and verified and the session is ready, `not_ready` with `g1_uninitialized` when it is verified and the
/// session is not ready, and `not_ready` with `unreadable` when the phrase is readable but not verified or cannot be read. Never `no_key`. Production path: the real command over a store that
/// holds the account's mnemonic item, the real pointer and the real gate.
final class PhraseOnlyStatusTests: XCTestCase {
	private var store = MemoryNativeKeyStore()
	private var saved: BeamioChatWalletKeyStoring?
	private var events: [[String: Any]] = []
	private let acct = ValidTestAccounts.accountA

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		saved = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		events = []
		BeamioConetChatModule.nativeObserver = { self.events.append($0) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = saved ?? BeamioPasscodeWalletStore.standard
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// The residue: the account's mnemonic item (the given phrase) and no key record; the pointer names the account.
	private func residue(phrase: String = ValidTestAccounts.phraseA, sessionReady: Bool) {
		_ = store.writeItem(.mnemonic, eoa: acct.eoa, value: BeamioPwaWalletSync.normalized(phrase))
		BeamioNativeAccountPointer.set(acct.eoa)
		if sessionReady { BeamioConetChatSignBroker.setSignerEoa(acct.eoa) }
		BeamioConetChatModule.setNativeGateForTests(account: acct.eoa, sessionReady: sessionReady)
		BeamioNativeKeySnapshot.invalidate()
	}

	private func walletStatus(_ reqId: Int) -> [String: Any] {
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": reqId], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		func found() -> [String: Any]? {
			events.compactMap { ($0["event"] as? [String: Any]) }.first { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }?["result"] as? [String: Any]
		}
		while found() == nil, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
		return found() ?? [:]
	}

	func testPHR01_ResidueValidSessionReadyIsLockedPhraseOnly() {
		residue(sessionReady: true)
		XCTAssertEqual(BeamioNativeWallet.keyStore.keyRecordState(eoa: acct.eoa), .absent)
		let r = walletStatus(9901)
		XCTAssertEqual(r["status"] as? String, "locked")
		XCTAssertEqual(r["reason"] as? String, "phrase_only")
		XCTAssertEqual(r["accountKey"] as? String, acct.eoa + ":default")
	}

	func testPHR02_ResidueValidNotReadyIsG1Uninitialized() {
		residue(sessionReady: false)
		let r = walletStatus(9902)
		XCTAssertEqual(r["status"] as? String, "not_ready")
		XCTAssertEqual(r["notReadyReason"] as? String, "g1_uninitialized")
		XCTAssertNil(r["accountKey"])
	}

	func testPHR03_ResidueReadableButInvalidIsUnreadableInBothSessionStates() {
		for ready in [true, false] {
			setUp2()
			residue(phrase: ValidTestAccounts.phraseB, sessionReady: ready)   // readable, but it does not derive the pointer's account
			let r = walletStatus(9903 + (ready ? 0 : 10))
			XCTAssertEqual(r["status"] as? String, "not_ready", "ready=\\(ready)")
			XCTAssertEqual(r["notReadyReason"] as? String, "unreadable", "ready=\\(ready)")
			XCTAssertNotEqual(r["status"] as? String, "no_key")
		}
	}

	func testPHR04_ResidueUnreadableIsUnreadableInBothSessionStates() {
		for ready in [true, false] {
			setUp2()
			residue(sessionReady: ready)
			store.mnemonic.failReadOwners = [acct.eoa]   // the item is there and cannot be read
			let r = walletStatus(9904 + (ready ? 0 : 10))
			XCTAssertEqual(r["status"] as? String, "not_ready", "ready=\\(ready)")
			XCTAssertEqual(r["notReadyReason"] as? String, "unreadable", "ready=\\(ready)")
			XCTAssertNotEqual(r["status"] as? String, "no_key")
		}
	}

	/// A fresh store, pointer and gate for the second pass of a case.
	private func setUp2() {
		tearDown(); setUp()
	}
}
#endif
