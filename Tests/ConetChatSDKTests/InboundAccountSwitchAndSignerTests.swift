#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// an account switch that cannot clear the old inbox closes the chat module for the new account (fail closed); the owner marker rule
/// ((2)); a row without a usable hash is isolated (m1, (6)); an envelope or group signature is bound to the session's account and to
/// the generation of the request ((4)); a refused signer is answered as `signer_mismatch` ((3)). Synthetic data only.
final class InboundAccountSwitchAndSignerTests: XCTestCase {
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
	private let account = "0x0000000000000000000000000000000000000003"
	private let other = "0x0000000000000000000000000000000000000004"
	private let peer = "0x0000000000000000000000000000000000000009"
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		resetAll()
	}

	override func tearDown() {
		resetAll()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		super.tearDown()
	}

	private func resetAll() {
		flushInboxIO()
		BeamioInboxFile.failRemovals = false
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.failReads = false
		BeamioConetChatCallLedger.failWrites = false
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.testDetachPageEmit()
		BeamioConetChatModule.callControlObserver = nil
		BeamioInboxOwner.remove()
		BeamioConetChatInboxStore.clear()
		BeamioConetChatCallLedger.clear()
		BeamioConetChatModule.gossipRetry.clear()
		BeamioConetChatSignBroker.clearSigner()
		events = []
	}

	// MARK: - helpers

	private func hash(_ i: Int) -> String {
		"0x" + String(format: "%064x", i)
	}

	private var inboxURL: URL {
		BeamioInboxFile.folder!.appendingPathComponent("inbox_v1.json")
	}

	private func row(_ i: Int) -> [String: Any] {
		["h": hash(i), "a": armor, "v": "d", "t": Date().timeIntervalSince1970, "c": false, "s": false]
	}

	private func writeInbox(_ rows: [Any]) {
		let data = try! JSONSerialization.data(withJSONObject: rows)
		try! data.write(to: inboxURL)
	}

	private func inboxRows() -> [Any] {
		guard let data = try? Data(contentsOf: inboxURL) else { return [] }
		return (try? JSONSerialization.jsonObject(with: data) as? [Any]) ?? []
	}

	/// Lets the inbox IO queue and the main queue run through a short chain.
	private func flushInboxIO(rounds: Int = 4) {
		for _ in 0..<rounds {
			let e = expectation(description: "inbox IO round")
			BeamioInboxIO.perform(generation: BeamioInboxIO.generation, { true }) { _ in e.fulfill() }
			wait(for: [e], timeout: 10)
		}
	}

	private func clearAndWait() {
		let e = expectation(description: "clear replied")
		BeamioConetChatModule.testClearOrder { _ in e.fulfill() }
		wait(for: [e], timeout: 10)
	}

	private func startSession() -> BeamioConetChatModule.Session {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		return BeamioConetChatModule.testCurrentSession()!
	}

	private func capture() {
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	private func drainMain() {
		let e = expectation(description: "main drained")
		DispatchQueue.main.async { e.fulfill() }
		wait(for: [e], timeout: 10)
	}

	private func acks(_ reqId: Int) -> [(ok: Bool, error: String?)] {
		events.compactMap { out in
			guard let event = out["event"] as? [String: Any],
                  event["type"] as? String == "ack",
                  event["reqId"] as? Int == reqId
			else { return nil }
			return (ok: event["ok"] as? Bool ?? false, error: event["error"] as? String)
		}
	}

	private func generationEvents() -> [Int] {
		events.compactMap { out in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "inboundGeneration" else { return nil }
			return event["generation"] as? Int
		}
	}

	private func lastGenerationEvent() -> Int? {
		generationEvents().last
	}

	private func signBody(_ reqId: Int, kind: String, generation: Int?) -> [String: Any] {
		var body: [String: Any] = ["reqId": reqId, "kind": kind, "message": "{\"text\":\"hello\"}"]
		if let generation {
			body["inboundGeneration"] = generation
		}
		return body
	}

	// MARK: - (2): the owner marker

	/// No marker and an empty inbox: the marker is written for the account, and nothing is cleared.
	func testAnEmptyInboxWithNoMarkerTakesTheAccountWithoutAClear() {
		let generation = BeamioInboxIO.generation
		XCTAssertTrue(BeamioConetChatModule.claimInboundOwner(account))
		XCTAssertEqual(BeamioInboxOwner.read(), .account(account))
		XCTAssertEqual(BeamioInboxIO.generation, generation, "no clear ran")
	}

	/// No marker but data present: the owner is unknown, so the data is cleared first, and the marker is written after the clear.
	func testDataWithNoMarkerIsClearedBeforeTheMarkerIsWritten() {
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(1), armor: armor, viaDomain: "d"))
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered("call-u|sess-u"))
		let generation = BeamioInboxIO.generation
		XCTAssertTrue(BeamioConetChatModule.claimInboundOwner(account))
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hash(1)), "the unknown record is gone")
		XCTAssertEqual(BeamioConetChatCallLedger.state("call-u|sess-u"), .none, "the unknown call state is gone")
		XCTAssertNotEqual(BeamioInboxIO.generation, generation, "the clear ran")
		XCTAssertEqual(BeamioInboxOwner.read(), .account(account))
	}

	// MARK: - (1): fail closed

	/// When the old inbox cannot be cleared, the chat module does not start for the new account: no session, no signer, and the marker stays
	/// with the old account. A retry that clears enters the account.
	func testAFailedClearClosesTheChatModuleForTheNewAccount() {
		XCTAssertTrue(BeamioInboxOwner.write(account))
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(2), armor: armor, viaDomain: "d"))
		_ = startSession()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioInboxFile.failRemovals = true
		XCTAssertFalse(BeamioConetChatModule.enterIdentity(other), "a clear that fails does not enter the new account")
		BeamioInboxFile.failRemovals = false
		XCTAssertNil(BeamioConetChatModule.testCurrentSession(), "the chat module is closed for the new account")
		XCTAssertTrue(BeamioConetChatSignBroker.currentSignerEoa().isEmpty, "the signer is cleared")
		XCTAssertEqual(BeamioInboxOwner.read(), .account(account), "the marker stays with the old account")

		XCTAssertTrue(BeamioConetChatModule.enterIdentity(other), "a retry that clears enters the account")
		XCTAssertEqual(BeamioInboxOwner.read(), .account(other))
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hash(2)), "the old inbox is gone")
	}

	/// The wipe for an account switch reports its result before it returns.
	func testTheWipeForAnAccountSwitchReportsItsResultBeforeItReturns() {
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(3), armor: armor, viaDomain: "d"))
		BeamioInboxFile.failRemovals = true
		XCTAssertFalse(BeamioInboxIO.wipeNow { BeamioConetChatInboxStore.clear() })
		BeamioInboxFile.failRemovals = false
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hash(3)))
		XCTAssertTrue(BeamioInboxIO.wipeNow { BeamioConetChatInboxStore.clear() })
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hash(3)))
	}

	// MARK: - (6): m1 isolation

	/// A row without a usable hash is isolated: the rest of the inbox keeps running, the row is kept verbatim, and nothing from it is listed,
	/// shown or acked. Its code is reported.
	func testARowWithoutAHashIsIsolatedAndTheInboxKeepsRunning() {
		let broken: [String: Any] = ["a": "", "t": 0, "c": true, "s": false]
		writeInbox([row(1), broken, row(2)])
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(3), armor: armor, viaDomain: "d"), "a new frame is still stored")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hash(1)))
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hash(2)))
		XCTAssertEqual(Set(BeamioConetChatInboxStore.list().map { $0.armorHash }), [hash(1), hash(2), hash(3)],
                       "the isolated row is never listed")
		XCTAssertEqual(BeamioConetChatInboxStore.quarantineCodes(), ["row_without_hash"])
		let rows = inboxRows()
		XCTAssertEqual(rows.count, 4, "the isolated row is written back with the others")
		XCTAssertEqual(rows.filter { ($0 as? [String: Any])?["h"] == nil }.count, 1, "and it is still the same single row")
	}

	/// An element that is not an object is isolated too, with its own code.
	func testAnElementThatIsNotAnObjectIsIsolatedWithItsOwnCode() {
		writeInbox([row(5), 7])
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(6), armor: armor, viaDomain: "d"))
		XCTAssertEqual(BeamioConetChatInboxStore.quarantineCodes(), ["row_not_an_object"])
	}

	/// A file that is not an array is still unreadable: nothing is written over it, nothing is acked.
	func testAFileThatIsNotAnInboxArrayIsNeverOverwritten() {
		let data = Data("{\"rows\":[]}".utf8)
		try! data.write(to: inboxURL)
		XCTAssertFalse(BeamioConetChatInboxStore.put(armorHash: hash(4), armor: armor, viaDomain: "d"))
		XCTAssertEqual(try! Data(contentsOf: inboxURL), data)
		XCTAssertTrue(BeamioConetChatInboxStore.holdsAnyRow())
		XCTAssertTrue(BeamioConetChatInboxStore.quarantineCodes().isEmpty)
	}

	// MARK: - (4): gossipSign for envelope and group

	/// An envelope is bound to the session's account: another signer is refused with signer_mismatch, before anything is signed.
	func testAnEnvelopeIsRefusedWhenTheSignerIsAnotherAccount() {
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(other)
		BeamioConetChatModule.testGossipSign(signBody(31, kind: "envelope", generation: BeamioInboxIO.generation))
		drainMain()
		XCTAssertEqual(acks(31).first?.error, "signer_mismatch")
	}

	/// A group request without a generation, or with an older one, is refused with stale_generation.
	func testAGroupRequestWithAStaleOrMissingGenerationIsRefused() {
		// the field is required from a new page (init declared deferAck); the test is that page.
		startSession().deferAck = true
		capture()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.testGossipSign(signBody(32, kind: "group", generation: nil))
		drainMain()
		XCTAssertEqual(acks(32).first?.error, "bad_request", "the request must carry inboundGeneration")
		BeamioConetChatModule.testGossipSign(signBody(33, kind: "group", generation: BeamioInboxIO.generation - 1))
		drainMain()
		XCTAssertTrue(acks(33).isEmpty, "an older generation is dropped, with no answer")
	}

	/// A request made before an identity clear is refused after it.
	func testARequestFromBeforeAnIdentityClearIsRefused() {
		_ = startSession()
		BeamioConetChatSignBroker.setSignerEoa(account)
		let earlier = BeamioInboxIO.generation
		clearAndWait()
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(account)
		// The page declared deferAck: its request carries the generation it started in. An old page takes the arrival generation.
		startSession().deferAck = true
		BeamioConetChatModule.testGossipSign(signBody(34, kind: "envelope", generation: earlier))
		drainMain()
		XCTAssertTrue(acks(34).isEmpty, "a request from before an identity clear is dropped ()")
	}

	/// An envelope needs a session to bind to.
	func testAnEnvelopeNeedsASessionToBindTo() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		capture()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.testGossipSign(signBody(35, kind: "envelope", generation: BeamioInboxIO.generation))
		drainMain()
		XCTAssertEqual(acks(35).first?.error, "not_ready")
	}

	/// The session's account is the signer and the generation is current: the request reaches the signature. This build holds no key for the
	/// account, so the signature is refused for that reason, not for the binding.
	func testAnEnvelopeForTheSessionsAccountReachesTheSignature() {
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.testGossipSign(signBody(36, kind: "envelope", generation: BeamioInboxIO.generation))
		drainMain()
		XCTAssertEqual(acks(36).first?.error, "no_key")
	}

	// MARK: - C, D (review of d2055d7): the listen callbacks

	/// A frame decrypted for a listen is handled only while its session is current and its identity has not been cleared.
	func testAListenFrameIsDroppedOnceItsSessionIsReplacedOrCleared() {
		let first = startSession()
		let generation = BeamioInboxIO.generation
		XCTAssertTrue(BeamioConetChatModule.listenFrameIsCurrent(first, generation: generation), "the current session and identity pass")
		let second = startSession()
		XCTAssertFalse(BeamioConetChatModule.listenFrameIsCurrent(first, generation: generation), "a frame of a replaced session is dropped")
		XCTAssertTrue(BeamioConetChatModule.listenFrameIsCurrent(second, generation: BeamioInboxIO.generation))
		let e = expectation(description: "cleared")
		BeamioConetChatModule.testClearOrder { _ in e.fulfill() }
		wait(for: [e], timeout: 10)
		XCTAssertFalse(BeamioConetChatModule.listenFrameIsCurrent(second, generation: generation), "a frame from before the clear is dropped")
	}

	// MARK: -,: the generation event and the field

	/// an `inboundGeneration` is a JSON integer from 0 to 2^53-1. A boolean, a string, a decimal, a negative or out-of-range value is not.
	func testTheInboundGenerationFieldAcceptsOnlyNonNegativeIntegers() {
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(0), 0)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(2), 2)
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(9_007_199_254_740_991), 9_007_199_254_740_991)
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(nil), "missing")
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration("2"), "a string")
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(2.5), "a decimal")
		// iOS judges by value; a JS number arrives as a double, so a whole 2.0 is the integer 2.
		XCTAssertEqual(BeamioConetChatModule.parseInboundGeneration(2.0), 2, "a whole double is an integer on the iOS bridge")
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(-1), "a negative number")
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(9_007_199_254_740_992), "above 2^53-1")
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(true), "a boolean")
		XCTAssertNil(BeamioConetChatModule.parseInboundGeneration(false), "a boolean")
	}

	/// IG-23: an envelope whose `inboundGeneration` is a string is refused with bad_request, before anything is signed.
	func testAnEnvelopeWithAStringGenerationIsBadRequest() {
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(account)
		var body = signBody(37, kind: "envelope", generation: nil)
		body["inboundGeneration"] = "\(BeamioInboxIO.generation)"
		BeamioConetChatModule.testGossipSign(body)
		drainMain()
		XCTAssertEqual(acks(37).first?.error, "bad_request")
	}

	/// the generation goes out after init succeeds and after each advance: a clear, and a failed clear.
	func testTheInboundGenerationEventFollowsEveryAdvance() {
		capture()
		let generationBefore = BeamioInboxIO.generation
		clearAndWait()
		drainMain()
		XCTAssertEqual(BeamioInboxIO.generation, generationBefore + 1)
		XCTAssertEqual(lastGenerationEvent(), BeamioInboxIO.generation, "the clear is announced with the advanced generation")
		XCTAssertTrue(BeamioInboxOwner.write(account))
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(3), armor: armor, viaDomain: "d"))
		BeamioInboxFile.failRemovals = true
		XCTAssertFalse(BeamioConetChatModule.enterIdentity(other))
		BeamioInboxFile.failRemovals = false
		drainMain()
		XCTAssertEqual(lastGenerationEvent(), BeamioInboxIO.generation, "a failed clear is announced with the advanced generation")
	}

	// MARK: - (3): the signer_mismatch code

	/// A route registration for another signer's account is answered with signer_mismatch, not no_pgp_key.
	func testARouteRegistrationForAnotherSignerIsAnsweredWithSignerMismatch() {
		BeamioConetChatSignBroker.setSignerEoa(other)
		XCTAssertEqual(BeamioConetChatModule.routeRegisterSignerRefusal(account: account), "signer_mismatch")
		BeamioConetChatSignBroker.setSignerEoa(account)
		XCTAssertNil(BeamioConetChatModule.routeRegisterSignerRefusal(account: account))
	}

	/// A refused signer is reported as signer_mismatch; any other failure keeps its own message or the fallback.
	func testASignerRefusalIsReportedAsSignerMismatch() {
		XCTAssertEqual(BeamioConetChatModule.signFailureCode(BeamioConetChatSignBroker.SignError.signerChanged), "signer_mismatch")
		XCTAssertEqual(BeamioConetChatModule.signFailureCode(BeamioConetChatSignBroker.SignError.walletKeyMissing, fallback: "fallback"),
                       "fallback")
	}
}
#endif
