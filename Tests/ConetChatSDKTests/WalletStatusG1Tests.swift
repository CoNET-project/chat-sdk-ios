import XCTest
@testable import ConetChatSDK

/// `walletStatus`, the G1 branch (Y.163, draft §23.1, §24.2 P2): the shell record is judged for readability first. A record that exists and cannot
/// be read answers `not_ready` with `unreadable`, never `g1_uninitialized`. A readable record keeps `g1_uninitialized`. The rule is a pure function
/// (`walletStatusG1Exit`), tested without a store. Synthetic test key material; no chain is reached.
final class WalletStatusG1Tests: XCTestCase {
	/// A record that exists and cannot be read now.
	final class UnreadableStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { nil }
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .unreadable }
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private var savedStore: BeamioChatWalletKeyStoring!
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// The `result` of the walletStatus ack for `reqId`, once the main queue has drained.
	private func walletStatusResult(_ reqId: Int) -> [String: Any]? {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		return events.compactMap { $0["event"] as? [String: Any] }
			.first { $0["reqId"] as? Int == reqId && $0["type"] as? String == "ack" }?["result"] as? [String: Any]
	}

	func testAnUnreadableRecordInG1IsNotReadyUnreadable() {
		BeamioNativeWallet.keyStore = UnreadableStore()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "an unreadable record still exists, so the device is G1")
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 9401], emit: { _ in })
		let answer = walletStatusResult(9401)
		XCTAssertEqual(answer?["status"] as? String, "not_ready")
		XCTAssertEqual(answer?["notReadyReason"] as? String, "unreadable", "unreadable is never g1_uninitialized")
		XCTAssertNil(answer?["accountKey"], "no key material in the answer")
	}

	/// A readable mnemonic account (the record the gate counts, `hasRecord`): restored from the public BIP-39 test phrase, then G1 until init.
	func testAReadableRecordInG1KeepsG1Uninitialized() {
		let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { return XCTFail("the test phrase derives an account") }
		let store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		XCTAssertEqual(BeamioNativeRestore.restoreWrite(phrase: phrase, userExplicit: true, sessionIsG2: false, store: store), .ok(eoa: derived.eoa))
		BeamioConetChatModule.setNativeGateForTests(account: derived.eoa, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 9402], emit: { _ in })
		let answer = walletStatusResult(9402)
		XCTAssertEqual(answer?["status"] as? String, "not_ready")
		XCTAssertEqual(answer?["notReadyReason"] as? String, "g1_uninitialized", "a readable record waiting for init keeps its own reason")
	}

	/// The rule, in every combination: any unreadable input is `unreadable`; only the readable inputs keep `g1_uninitialized`.
	func testTheG1ExitRuleIsUnreadableWhenAnyInputIsUnreadable() {
		XCTAssertEqual(BeamioConetChatModule.walletStatusG1Exit(recordState: .unreadable, markersUnreadable: false, snapshotUnreadable: false), "unreadable")
		XCTAssertEqual(BeamioConetChatModule.walletStatusG1Exit(recordState: .present, markersUnreadable: true, snapshotUnreadable: false), "unreadable")
		XCTAssertEqual(BeamioConetChatModule.walletStatusG1Exit(recordState: .present, markersUnreadable: false, snapshotUnreadable: true), "unreadable")
		XCTAssertEqual(BeamioConetChatModule.walletStatusG1Exit(recordState: .present, markersUnreadable: false, snapshotUnreadable: false), "g1_uninitialized")
		XCTAssertEqual(BeamioConetChatModule.walletStatusG1Exit(recordState: .absent, markersUnreadable: false, snapshotUnreadable: false), "g1_uninitialized")
		XCTAssertEqual(BeamioConetChatModule.walletStatusG1Exit(recordState: nil, markersUnreadable: false, snapshotUnreadable: false), "g1_uninitialized")
	}

	/// The diagnostic labels are fixed words, and name no account or key material.
	func testTheDiagnosticLabelsAreFixedWords() {
		XCTAssertEqual(BeamioConetChatModule.stateLabel(.absent), "absent")
		XCTAssertEqual(BeamioConetChatModule.stateLabel(.present), "present")
		XCTAssertEqual(BeamioConetChatModule.stateLabel(.unreadable), "unreadable")
		XCTAssertEqual(BeamioConetChatModule.stateLabel(nil), "none")
	}
}
