#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// and the audit of 6c62630: the interleavings after the identity clear, the held call-signal claim, the replay that
/// writes its record first, the call-ledger cap (E-64), the account switch and the staged receipts. Synthetic data only.
final class InboundInterleavingTests: XCTestCase {
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
	private let account = "0x0000000000000000000000000000000000000003"
	private let other = "0x0000000000000000000000000000000000000004"
	private let peer = "0x0000000000000000000000000000000000000009"
	private let frameHash = "0x" + String(repeating: "7", count: 64)
	private let otherFrameHash = "0x" + String(repeating: "6", count: 64)
	private let chatLine = "{\"text\":\"hello\"}"
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		resetAll()
	}

	override func tearDown() {
		resetAll()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		super.tearDown()
	}

	private func resetAll() {
		flushInboxIO()
		BeamioConetChatCallLedger.failWrites = false
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatModule.testClearImmediateRetryThrottle()
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.callControlObserver = nil
		BeamioInboxOwner.remove()
		BeamioConetChatInboxStore.clear()
		BeamioConetChatCallLedger.clear()
		BeamioConetChatModule.gossipRetry.clear()
		events = []
	}

	/// Runs the inbox IO queue and the main-queue completions after it. Each round lets one more hop of a chain run.
	private func flushInboxIO(rounds: Int = 4) {
		for _ in 0..<rounds {
			let e = expectation(description: "inbox IO round")
			BeamioInboxIO.perform(generation: BeamioInboxIO.generation, { true }) { _ in e.fulfill() }
			wait(for: [e], timeout: 10)
		}
	}

	@discardableResult
	private func clearAndWait() -> Bool {
		let e = expectation(description: "clear replied")
		var result = false
		BeamioConetChatModule.testClearOrder { ok in
			result = ok
			e.fulfill()
		}
		wait(for: [e], timeout: 10)
		return result
	}

	private func startSession() -> BeamioConetChatModule.Session {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		return BeamioConetChatModule.testCurrentSession()!
	}

	private func pendingAckCount(_ s: BeamioConetChatModule.Session) -> Int {
		s.pendingLock.lock()
		defer { s.pendingLock.unlock() }
		return s.pendingAcks.count
	}

	private func key(_ callId: String, _ sessionId: String) -> String {
		BeamioConetChatCallLedger.key(callId: callId, sessionId: sessionId)
	}

	private func pending(_ callId: String, _ sessionId: String) -> BeamioConetChatCallLedger.Pending {
		BeamioConetChatCallLedger.Pending(
			key: key(callId, sessionId), type: "end", callId: callId, sessionId: sessionId, from: peer
		)
	}

	/// A call-control line as the gate wants it: an envelope whose `from` is the peer, around a signal that carries the same `from`.
	private func callLine(_ type: String, _ callId: String, _ sessionId: String) -> String {
		let inner = "{\"type\":\"\(type)\",\"callId\":\"\(callId)\",\"sessionId\":\"\(sessionId)\",\"from\":\"\(peer)\"}"
		let escaped = inner.replacingOccurrences(of: "\"", with: "\\\"")
		return "{\"timestamp\":1,\"text\":\"\(escaped)\",\"from\":\"\(peer)\",\"signMessage\":\"0x00\"}"
	}

	private var ledgerURL: URL {
		BeamioInboxFile.folder!.appendingPathComponent("call_signals_v1.json")
	}

	private var signAttempts: Int {
		BeamioConetChatSignBroker.testSignAttempts
	}

	/// The event:message payloads the page would have received.
	private func messageEvents() -> [[String: Any]] {
		events.compactMap { out in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "event:message" else { return nil }
			return event
		}
	}

	private func deliveredRowCount() -> Int {
		guard let data = try? Data(contentsOf: ledgerURL),
              let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return -1 }
		return rows.filter { ($0["st"] as? String) == "delivered" }.count
	}

	// MARK: - B1-a: a held claim is neither recorded nor acked

	func testAHeldCallSignalIsNotRecordedAndNotAcked() {
		let session = startSession()
		XCTAssertTrue(BeamioConetChatCallLedger.claim(pending("call-held", "sess-held")), "another path holds the key")
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: callLine("voice_end_v1", "call-held", "sess-held"), from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertTrue(handed.isEmpty, "a held key is not handed over twice")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "nothing is stored while the key is held elsewhere")
		XCTAssertNil(BeamioConetChatModule.gossipRetry.failures[frameHash], "nothing is acked, so nothing is retried")

		// The other path lets go; the mailbox sends the frame again and the signal is handed over exactly once.
		BeamioConetChatCallLedger.release(key("call-held", "sess-held"))
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: callLine("voice_end_v1", "call-held", "sess-held"), from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertEqual(handed, ["call-held"])
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-held", "sess-held")), .delivered)
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
	}

	func testADeliveredCallSignalIsNotHandedOverAgainButTheFrameIsRecorded() {
		let session = startSession()
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key("call-old", "sess-old")))
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: callLine("voice_end_v1", "call-old", "sess-old"), from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertTrue(handed.isEmpty, "a signal already delivered is not handed over again")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "its signal is on record, so the frame is recorded")
	}

	// MARK: - B1-b: the replay writes its record before it shows the frame

	func testAFailedLedgerWriteDoesNotTouchTheReplay() {
		// v68 section 75.2: a stored frame handed over again is history. It never touches the call ledger, so a ledger that cannot be written
		// neither stops its display nor hands a signal over.
		let session = startSession()
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		let line = callLine("voice_end_v1", "call-r", "sess-r")
		BeamioConetChatCallLedger.failWrites = true
		BeamioConetChatModule.handOverVerified(
			session: session, plaintext: line, from: peer, armorHash: frameHash, viaDomain: "d",
			generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		BeamioConetChatCallLedger.failWrites = false
		XCTAssertEqual(messageEvents().count, 1, "the replayed frame is shown")
		XCTAssertEqual(pendingAckCount(session), 1)
		XCTAssertTrue(handed.isEmpty, "a replay never hands a signal to the shell")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-r", "sess-r")), .none, "and writes no record")
	}

	// MARK: - D8 and E-64: the call ledger cap

	func testTheCapEvictsTheOldestDeliveredKeysAndNeverAPendingSignal() {
		_ = startSession()
		var rows: [[String: Any]] = []
		for i in 0..<3 {
			rows.append(["k": "pending-\(i)|s", "st": "pending", "type": "end", "callId": "pending-\(i)", "sessionId": "s", "from": peer, "t": 1.0])
		}
		for i in 0..<BeamioConetChatCallLedger.maxDelivered {
			rows.append(["k": "old-\(i)|s", "st": "delivered", "t": 2.0])
		}
		let data = try! JSONSerialization.data(withJSONObject: rows)
		XCTAssertTrue(BeamioInboxFile.replace(ledgerURL, with: data))
		XCTAssertEqual(deliveredRowCount(), BeamioConetChatCallLedger.maxDelivered)

		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key("new", "s")))

		XCTAssertEqual(deliveredRowCount(), BeamioConetChatCallLedger.maxDelivered, "the delivered rows stay at the cap")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("old-0", "s")), .none, "the oldest delivered key is evicted")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("old-1", "s")), .delivered, "the next one is kept")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("new", "s")), .delivered)
		XCTAssertEqual(BeamioConetChatCallLedger.pendingSignals().count, 3, "pending signals never age out")
		// An evicted key that comes again is claimed and handed over again (the call layer keeps one signal per key).
		XCTAssertEqual(BeamioConetChatCallLedger.claimOutcome(pending("old-0", "s")), .claimed)
		BeamioConetChatCallLedger.release(key("old-0", "s"))
	}

	// MARK: - (2): staged receipts

	func testAnOldPageSettlesItsStagedReceiptsAndANewPageKeepsThem() {
		let session = startSession()
		session.deferAck = false
		session.pendingLock.lock()
		session.pendingAcks[frameHash] = (plaintext: chatLine, from: peer, at: Date())
		session.pendingLock.unlock()
		BeamioConetChatModule.settleReceiptsForOldPage(session)
		XCTAssertEqual(pendingAckCount(session), 0, "an old page displays them now, so their receipts go out at display")

		session.deferAck = true
		session.pendingLock.lock()
		session.pendingAcks[frameHash] = (plaintext: chatLine, from: peer, at: Date())
		session.pendingLock.unlock()
		BeamioConetChatModule.settleReceiptsForOldPage(session)
		XCTAssertEqual(pendingAckCount(session), 1, "a new page keeps them until its ackInbound")
	}

	// MARK: - (3): a server-acked record registers no retry

	func testAServerAckedRecordRegistersNoRetryWhenItsReAckFails() {
		let session = startSession()
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		XCTAssertTrue(BeamioConetChatInboxStore.markServerAcked([frameHash]))
		// A duplicate of a server-acked frame. This session has no route key, so its ack cannot be sent and would be retried.
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer, armorHash: frameHash, armor: armor, viaDomain: "d",
			generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertNil(BeamioConetChatModule.gossipRetry.failures[frameHash], "a server-acked record registers no retry")
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.timers.isEmpty)

		// Positive control: a new frame whose ack cannot be sent is retried.
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer, armorHash: otherFrameHash, armor: armor, viaDomain: "d",
			generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[otherFrameHash], 1)
	}

	// MARK: - (1): an account switch runs the full clear

	func testAnAccountSwitchRunsTheFullClearAndTheSameAccountDoesNot() {
		BeamioConetChatModule.claimInboundOwner(account)
		XCTAssertEqual(BeamioInboxOwner.read(), .account(account), "the owner is recorded when the inbox has none")
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key("call-a", "sess-a")))
		_ = BeamioConetChatModule.gossipRetry.recordFailure(frameHash)
		let generation = BeamioInboxIO.generation

		// The same account: nothing goes (positive control).
		BeamioConetChatModule.claimInboundOwner(account)
		flushInboxIO()
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
		XCTAssertEqual(BeamioInboxIO.generation, generation)

		// Another account: the full clear runs, the generation advances, and the marker moves to the new account.
		BeamioConetChatModule.claimInboundOwner(other)
		flushInboxIO()
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "the previous account's dedupe record is gone")
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty, "the previous account's inbox is gone")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-a", "sess-a")), .none, "the previous account's call ledger is gone")
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.failures.isEmpty, "the previous account's retries are gone")
		XCTAssertNotEqual(BeamioInboxIO.generation, generation, "the generation advanced")
		XCTAssertEqual(BeamioInboxOwner.read(), .account(other))
	}

	func testAnUnreadableOwnerMarkerIsNotAssumedToBeTheAccountStartingNow() {
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		XCTAssertTrue(BeamioInboxFile.replace(BeamioInboxFile.folder!.appendingPathComponent("owner_v1.txt"), with: Data()))
		XCTAssertEqual(BeamioInboxOwner.read(), .unknown)
		BeamioConetChatModule.claimInboundOwner(account)
		flushInboxIO()
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "an unknown owner starts the clear")
		XCTAssertEqual(BeamioInboxOwner.read(), .account(account))
	}

	func testTheClearRemovesTheOwnerMarker() {
		BeamioConetChatModule.claimInboundOwner(account)
		XCTAssertEqual(BeamioInboxOwner.read(), .account(account))
		clearAndWait()
		XCTAssertEqual(BeamioInboxOwner.read(), .absent, "the identity clear removes the owner marker")
	}
	// MARK: - Checklist rows E-04 to E-17, E-29 to E-35, E-40, E-42 (gate-open acceptance)

	private func acceptChat(_ session: BeamioConetChatModule.Session, _ hash: String) {
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer,
			armorHash: hash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
	}

	private func acceptCall(_ session: BeamioConetChatModule.Session, _ type: String, _ callId: String, _ hash: String) {
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: callLine(type, callId, "sess-" + callId), from: peer,
			armorHash: hash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
	}

	private func capturingEvents() {
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	/// E-04: the end signal reaches the call layer before the frame is stored; a store that cannot write shows and acks nothing.
	func testAnEndSignalIsHandedOverBeforeAFailedStoreShowsOrAcksAnything() {
		let session = startSession()
		capturingEvents()
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		BeamioConetChatInboxStore.failWrites = true
		acceptCall(session, "voice_end_v1", "call-e4", frameHash)
		flushInboxIO()
		BeamioConetChatInboxStore.failWrites = false
		XCTAssertEqual(handed, ["call-e4"], "the signal is handed over once, before the store")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-e4", "sess-call-e4")), .delivered)
		XCTAssertTrue(messageEvents().isEmpty, "the frame is not shown when the store cannot write it")
		XCTAssertNil(BeamioConetChatModule.gossipRetry.failures[frameHash], "nothing is acked")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
	}

	/// E-05: a copy of a delivered end signal is not handed over again, and is acked again.
	func testADuplicateEndSignalIsNotHandedOverAgainButIsAcked() {
		let session = startSession()
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		acceptCall(session, "voice_end_v1", "call-e5", frameHash)
		flushInboxIO()
		acceptCall(session, "voice_end_v1", "call-e5", frameHash)
		flushInboxIO()
		XCTAssertEqual(handed, ["call-e5"], "the signal goes out once")
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 2, "the copy is acked again: its ack is attempted")
	}

	/// E-06, E-08: a signal taken with no observer waits as pending, and goes out when an observer registers.
	func testAPendingSignalIsHandedOverWhenTheObserverRegisters() {
		let session = startSession()
		acceptCall(session, "voice_end_v1", "call-e6", frameHash)
		flushInboxIO()
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-e6", "sess-call-e6")), .pending)
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		flushInboxIO()
		XCTAssertEqual(handed, ["call-e6"], "the registration flushes the waiting signal once")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-e6", "sess-call-e6")), .delivered)
	}

	/// E-07: two paths claiming the same key at once get one claim.
	func testTwoPathsClaimingOneKeyAtOnceGetOneClaim() {
		final class Counter {
			let lock = NSLock()
			var value = 0
		}
		let p = pending("call-race", "sess-race")
		for _ in 0..<200 {
			BeamioConetChatCallLedger.release(p.key)
			let counter = Counter()
			DispatchQueue.concurrentPerform(iterations: 8) { _ in
				if BeamioConetChatCallLedger.claimOutcome(p) == .claimed {
					counter.lock.lock()
					counter.value += 1
					counter.lock.unlock()
				}
			}
			XCTAssertEqual(counter.value, 1, "exactly one path holds the claim")
		}
		BeamioConetChatCallLedger.release(p.key)
	}

	/// E-09 (live path): a ledger that cannot write shows, acks and records nothing.
	func testAFailedLedgerWriteOnTheLivePathShowsAndAcksNothing() {
		let session = startSession()
		capturingEvents()
		BeamioConetChatCallLedger.failWrites = true
		acceptCall(session, "voice_end_v1", "call-e9", frameHash)
		flushInboxIO()
		BeamioConetChatCallLedger.failWrites = false
		XCTAssertTrue(messageEvents().isEmpty, "not shown")
		XCTAssertNil(BeamioConetChatModule.gossipRetry.failures[frameHash], "not acked")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "not recorded")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-e9", "sess-call-e9")), .none)
	}

	/// E-10, E-11, E-12: a new frame is stored, shown once and acked; a timeout signal is handed over too; a plain message never enters the
	/// call ledger.
	func testANewFrameIsStoredShownOnceAndAckedAndATimeoutSignalIsHandedOver() {
		let session = startSession()
		capturingEvents()
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		acceptChat(session, frameHash)
		flushInboxIO()
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "stored")
		XCTAssertEqual(messageEvents().count, 1, "shown once")
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 1, "acked: the ack is attempted once")
		XCTAssertTrue(BeamioConetChatCallLedger.pendingSignals().isEmpty, "a plain message is not a call signal (E-11)")
		acceptCall(session, "voice_call_timeout_v1", "call-e10", otherFrameHash)
		flushInboxIO()
		XCTAssertEqual(handed, ["call-e10"], "the timeout signal is handed over")
		XCTAssertEqual(messageEvents().count, 2, "and shown with its frame")
	}

	/// E-13: a frame the store cannot write is not shown, acked or recorded; a later arrival is a new frame.
	func testAFrameThatCannotBeStoredIsNotShownOrAckedAndArrivesAsNewLater() {
		let session = startSession()
		capturingEvents()
		BeamioConetChatInboxStore.failWrites = true
		acceptChat(session, frameHash)
		flushInboxIO()
		BeamioConetChatInboxStore.failWrites = false
		XCTAssertTrue(messageEvents().isEmpty)
		XCTAssertNil(BeamioConetChatModule.gossipRetry.failures[frameHash])
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
		acceptChat(session, frameHash)
		flushInboxIO()
		XCTAssertEqual(messageEvents().count, 1, "the later arrival is a new frame and is shown")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
	}

	/// E-17: a copy of a stored frame is not shown again, and is acked again.
	func testADuplicateIsNotShownTwiceButIsAckedAgain() {
		let session = startSession()
		capturingEvents()
		acceptChat(session, frameHash)
		flushInboxIO()
		acceptChat(session, frameHash)
		flushInboxIO()
		XCTAssertEqual(messageEvents().count, 1, "not shown twice")
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 2, "acked again")
	}

	/// E-31: a session that declared deferAck acks at the store, and keeps the receipt until the page's ackInbound.
	func testADeferAckSessionAcksAtStoreAndKeepsTheReceiptForTheAckInbound() {
		let session = startSession()
		session.deferAck = true
		acceptChat(session, frameHash)
		flushInboxIO()
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 1, "the ack goes at the store, before any ackInbound")
		XCTAssertEqual(pendingAckCount(session), 1, "the receipt waits for the page's ackInbound")
	}

	/// E-29, E-30: the page's ackInbound takes the armor out and keeps the record; a repeat has no effect.
	func testAnAckInboundRemovesTheArmorKeepsTheRecordAndARepeatHasNoEffect() {
		let session = startSession()
		session.deferAck = true
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		session.pendingLock.lock()
		session.pendingAcks[frameHash] = (plaintext: chatLine, from: peer, at: Date())
		session.pendingLock.unlock()
		BeamioConetChatModule.testAckInbound([frameHash])
		flushInboxIO()
		XCTAssertEqual(pendingAckCount(session), 0, "the staged receipt is taken")
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty, "the armor leaves the inbox")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "the record stays for dedupe")
		BeamioConetChatModule.testAckInbound([frameHash])
		flushInboxIO()
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
		XCTAssertEqual(pendingAckCount(session), 0, "a repeat changes nothing")
	}

	/// E-33, E-35: every send is signed again; the listen handshake sends each unconfirmed ack once, now.
	func testEachAckSendIsSignedAgainAndTheHandshakeSendsTheUnconfirmedOnesNow() {
		let session = startSession()
		session.ownRouteArmoredPublicKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic\n-----END PGP PUBLIC KEY BLOCK-----"
		BeamioConetChatSignBroker.setSignerEoa(account)
		let before = signAttempts
		acceptChat(session, frameHash)
		flushInboxIO()
		acceptChat(session, frameHash)
		flushInboxIO()
		XCTAssertEqual(signAttempts, before + 2, "two sends, two signatures")

		BeamioConetChatModule.testClearImmediateRetryThrottle()
		let beforeHandshake = signAttempts
		BeamioConetChatModule.retryUnconfirmedGossipAcksNow()
		let drained = expectation(description: "handshake retry drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 10)
		XCTAssertEqual(signAttempts, beforeHandshake + 1, "one unconfirmed ack is sent now, once")
	}

	/// E-40: a timer whose token has been replaced is not due; the retry book never gives up on its own (E-34).
	func testAStaleRetryTokenIsNotDueAndTheRetryNeverGivesUpOnItsOwn() {
		var book = BeamioGossipRetryBook()
		let first = book.recordFailure(frameHash)
		let second = book.recordFailure(frameHash)
		XCTAssertFalse(book.isDue(frameHash, token: first.token), "a replaced timer does nothing")
		XCTAssertTrue(book.isDue(frameHash, token: second.token))
		book.fired(frameHash)
		XCTAssertFalse(book.isDue(frameHash, token: second.token))
		var last = (failures: 0, token: 0)
		for _ in 0..<40 {
			last = book.recordFailure(frameHash)
		}
		XCTAssertEqual(last.failures, 42, "every failure counts")
		XCTAssertTrue(book.isDue(frameHash, token: last.token))
		XCTAssertEqual(GossipRetrySchedule.delay(failures: last.failures - 1), 600, "the wait stops at ten minutes; the retry does not stop")
	}

	/// B1-b for an ordinary message: the call ledger holds call signals only (deliverCallSignal, its pending flush and the identity clear are its only
	/// users), so a stored ordinary frame handed over again is shown whatever the ledger does. Its duplicate display is guarded by the inbox store.
	func testAnOrdinaryStoredFrameIsShownWhateverTheLedgerDoes() {
		let session = startSession()
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
		let line = "{\"timestamp\":1,\"text\":\"hello\",\"from\":\"\(peer)\",\"signMessage\":\"0x00\"}"
		BeamioConetChatCallLedger.failWrites = true
		BeamioConetChatModule.handOverVerified(
			session: session, plaintext: line, from: peer, armorHash: frameHash, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		BeamioConetChatCallLedger.failWrites = false
		XCTAssertEqual(messageEvents().count, 1)
		XCTAssertEqual(pendingAckCount(session), 1)
		XCTAssertFalse(FileManager.default.fileExists(atPath: ledgerURL.path), "the ledger was not touched")
	}

	/// The gate in the module: a line that fails it is an ordinary line (stored, shown, acked), and nothing reaches the shell.
	func testAGatedOutLineIsStoredAndNothingIsHandedOver() {
		let session = startSession()
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		// the recovered signer is the peer, but the envelope claims another from: the signal is dropped
		let line = callLine("voice_end_v1", "call-gate", "sess-gate").replacingOccurrences(
			of: "\"from\":\"\(peer)\",\"signMessage\"", with: "\"from\":\"0x00000000000000000000000000000000000000bb\",\"signMessage\""
		)
		XCTAssertNotEqual(line, callLine("voice_end_v1", "call-gate", "sess-gate"), "the outer from was changed")
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: line, from: peer, armorHash: frameHash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertTrue(handed.isEmpty, "a gated-out signal is not handed over")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-gate", "sess-gate")), .none, "and leaves no record")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "the line itself is stored")
	}

	/// E-42 (v68 section 75.2): a replayed (stored) call line is shown again on each attach until the page confirms it, and never hands a signal over.
	func testAReplayedCallLineIsShownAgainAndHandsNothingOver() {
		let session = startSession()
		capturingEvents()
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		let line = callLine("voice_end_v1", "call-e42", "sess-call-e42")
		for _ in 0..<2 {
			BeamioConetChatModule.handOverVerified(
				session: session, plaintext: line, from: peer, armorHash: frameHash, viaDomain: "d",
				generation: BeamioInboxIO.generation
			)
			flushInboxIO()
		}
		XCTAssertTrue(handed.isEmpty, "a replay hands no signal over")
		XCTAssertEqual(messageEvents().count, 2, "the frame is handed to the page on each attach")
	}
}
#endif
