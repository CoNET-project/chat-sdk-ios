#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// and; review F1 to F7; gate-open items E-60 and E-61. A clear runs `destroy` first, then the wipe on the inbox IO queue, and
/// the reply goes after the wipe. A job, a completion, a verification, a call hand-over, a signature or a retry of an earlier generation
/// changes nothing. Synthetic data only.
final class IdentityClearTests: XCTestCase {
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
	private let account = "0x0000000000000000000000000000000000000003"
	private let other = "0x0000000000000000000000000000000000000004"
	private let peer = "0x0000000000000000000000000000000000000009"
	private let frameHash = "0x" + String(repeating: "9", count: 64)
	private let otherFrameHash = "0x" + String(repeating: "8", count: 64)
	private let chatLine = "{\"text\":\"hello\"}"

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
		BeamioInboxFile.failRemovals = false
		BeamioConetChatModule.callControlObserver = nil
		BeamioConetChatInboxStore.clear()
		BeamioConetChatCallLedger.clear()
		BeamioConetChatModule.gossipRetry.clear()
	}

	/// Runs the inbox IO queue and the main-queue completions after it. Each round lets one more hop of a chain run.
	private func flushInboxIO(rounds: Int = 4) {
		for _ in 0..<rounds {
			let e = expectation(description: "inbox IO round")
			BeamioInboxIO.perform(generation: BeamioInboxIO.generation, { true }) { _ in e.fulfill() }
			wait(for: [e], timeout: 10)
		}
	}

	/// The identity clear in the order `clearIdentity` uses: `destroy`, then the wipe. Returns the wipe's result once the reply has come.
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

	private var inboxURL: URL {
		BeamioInboxFile.folder!.appendingPathComponent("inbox_v1.json")
	}

	private var signAttempts: Int {
		BeamioConetChatSignBroker.testSignAttempts
	}

	// MARK: - The clear leaves nothing behind (F1, F7)

	func testTheClearLeavesNoInboundStateBehind() {
		let session = startSession()
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "domain.example"))
		XCTAssertTrue(BeamioConetChatCallLedger.markPending(pending("call-clear", "sess-clear")))
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key("call-old", "sess-old")))
		XCTAssertTrue(BeamioConetChatCallLedger.claim(pending("call-held", "sess-held")))
		_ = BeamioConetChatModule.gossipRetry.recordFailure(frameHash)
		BeamioConetChatModule.testAddPendingAck(frameHash)
		XCTAssertFalse(BeamioConetChatInboxStore.list().isEmpty)
		XCTAssertEqual(BeamioConetChatCallLedger.pendingSignals().count, 1)
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures.count, 1)
		XCTAssertEqual(pendingAckCount(session), 1)

		XCTAssertTrue(clearAndWait(), "the wipe succeeds")

		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty, "the inbox, with its armor, is gone")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "the dedupe record is gone")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-clear", "sess-clear")), .none)
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-old", "sess-old")), .none, "a delivered key of the old identity is gone")
		XCTAssertTrue(BeamioConetChatCallLedger.pendingSignals().isEmpty)
		XCTAssertTrue(BeamioConetChatCallLedger.claim(pending("call-held", "sess-held")), "a claim held before the clear is gone")
		BeamioConetChatCallLedger.release(key("call-held", "sess-held"))
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.failures.isEmpty, "no retry is counted any more")
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.timers.isEmpty, "no retry timer is due any more")
		XCTAssertNil(BeamioConetChatModule.testCurrentSession(), "the session is dropped")
		XCTAssertEqual(pendingAckCount(session), 0, "the session object that flows still hold has no pending acks (F1)")
	}

	// MARK: - The reply (F4, E-60)

	func testTheReplyComesOnlyAfterTheWipe() {
		_ = startSession()
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		let e = expectation(description: "reply")
		var replied = false
		var emptyAtReply = false
		BeamioConetChatModule.testClearOrder { ok in
			replied = true
			emptyAtReply = ok && BeamioConetChatInboxStore.list().isEmpty && BeamioConetChatCallLedger.pendingSignals().isEmpty
			e.fulfill()
		}
		XCTAssertFalse(replied, "the reply is not sent before the wipe has run (F4)")
		wait(for: [e], timeout: 10)
		XCTAssertTrue(emptyAtReply, "at the reply the wipe has finished and reported success")
	}

	// MARK: - A failed removal is reported (F5)

	func testAFailedRemovalIsReportedNotSwallowed() {
		_ = startSession()
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: frameHash, armor: armor, viaDomain: "d"))
		XCTAssertTrue(BeamioConetChatCallLedger.markDelivered(key("call-d", "sess-d")))
		BeamioInboxFile.failRemovals = true
		XCTAssertFalse(BeamioConetChatInboxStore.clear(), "the store reports a removal that failed")
		let ok = clearAndWait()
		BeamioInboxFile.failRemovals = false
		XCTAssertFalse(ok, "a removal that fails makes the clear report failure, so the reply is ok:false")
		XCTAssertTrue(FileManager.default.fileExists(atPath: inboxURL.path), "the file that could not be removed is still there")
	}

	// MARK: - Interleavings of the inbox IO queue (F2)

	func testAJobQueuedBeforeTheClearIsWipedWithItAndItsCompletionIsDropped() {
		_ = startSession()
		var completed = false
		BeamioInboxIO.perform(generation: BeamioInboxIO.generation, {
			BeamioConetChatInboxStore.admit(armorHash: self.frameHash, armor: self.armor, viaDomain: "d")
		}) { _ in completed = true }
		XCTAssertTrue(clearAndWait())
		flushInboxIO()
		XCTAssertFalse(completed, "a completion queued in an earlier generation does not run")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "a write queued before the wipe is wiped with it")
	}

	func testAJobQueuedAfterTheClearIsNeverQueued() {
		_ = startSession()
		let earlier = BeamioInboxIO.generation
		clearAndWait()
		var stored = false
		var marked = false
		BeamioInboxIO.perform(generation: earlier, {
			BeamioConetChatInboxStore.admit(armorHash: self.frameHash, armor: self.armor, viaDomain: "d")
		}) { _ in stored = true }
		BeamioInboxIO.perform(generation: earlier, {
			BeamioConetChatCallLedger.markDelivered(self.key("call-late", "sess-late"))
		}) { _ in marked = true }
		flushInboxIO()
		XCTAssertFalse(stored, "a job of an earlier generation is not queued after the clear")
		XCTAssertFalse(marked)
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "nothing of an earlier generation is written")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-late", "sess-late")), .none, "a delivered mark of an earlier generation writes nothing")
	}

	// MARK: - Verification and call hand-over that complete after the clear (F2)

	func testAVerifiedFrameFromAnEarlierGenerationWritesNothing() {
		let session = startSession()
		let earlier = BeamioInboxIO.generation
		let signsBefore = signAttempts
		clearAndWait()
		var observed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in observed.append(callId) }
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: callLine("voice_end_v1", "call-v", "sess-v"), from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: earlier
		)
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer,
			armorHash: otherFrameHash, armor: armor, viaDomain: "d", generation: earlier
		)
		flushInboxIO()
		XCTAssertTrue(observed.isEmpty, "a call signal of an earlier generation is not handed over")
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty, "nothing is stored")
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: otherFrameHash))
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.failures.isEmpty, "no ack is attempted, so none is retried")
		XCTAssertEqual(signAttempts, signsBefore, "nothing is signed")
	}

	func testAFrameVerifiedAfterTheClearIsStoredUnderTheNewGeneration() {
		_ = startSession()
		clearAndWait()
		let current = startSession()
		BeamioConetChatModule.acceptVerifiedInbound(
			session: current, plaintext: chatLine, from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash), "a flow that starts after the clear stores the frame")
		XCTAssertEqual(BeamioConetChatInboxStore.list().map { $0.armorHash }, [frameHash])
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 1, "no route key here, so the ack is retried as a new flow")
	}

	func testACallSignalFromAnEarlierGenerationIsNotHandedOver() {
		let old = startSession()
		let earlier = BeamioInboxIO.generation
		var handed: [String] = []
		BeamioConetChatModule.callControlObserver = { _, callId, _, _ in handed.append(callId) }
		clearAndWait()
		BeamioConetChatModule.acceptVerifiedInbound(
			session: old, plaintext: callLine("voice_end_v1", "call-s", "sess-s"), from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: earlier
		)
		flushInboxIO()
		XCTAssertTrue(handed.isEmpty, "the call layer gets nothing from an earlier generation")
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-s", "sess-s")), .none)
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: frameHash))

		// Positive control: the current generation hands the signal over once, and records it as delivered.
		let current = startSession()
		BeamioConetChatModule.acceptVerifiedInbound(
			session: current, plaintext: callLine("voice_end_v1", "call-s", "sess-s"), from: peer,
			armorHash: frameHash, armor: armor, viaDomain: "d", generation: BeamioInboxIO.generation
		)
		flushInboxIO()
		XCTAssertEqual(handed, ["call-s"])
		XCTAssertEqual(BeamioConetChatCallLedger.state(key("call-s", "sess-s")), .delivered)
	}

	// MARK: - Ack failures after the clear register no retry (F3)

	func testAFailedAckFromAnEarlierGenerationRegistersNoRetry() {
		let old = startSession()
		let earlier = BeamioInboxIO.generation
		clearAndWait()
		BeamioConetChatModule.testRecordGossipFailure(session: old, armorHash: frameHash, generation: earlier)
		XCTAssertNil(BeamioConetChatModule.gossipRetry.failures[frameHash], "a failure of an earlier generation registers no retry")
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.timers.isEmpty)

		// Positive control: the current generation registers its retry.
		let current = startSession()
		BeamioConetChatModule.testRecordGossipFailure(session: current, armorHash: frameHash, generation: BeamioInboxIO.generation)
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 1)
	}

	// MARK: - The signer must be the session's account (F3)

	func testTheSignerMustBeTheSessionAccount() {
		let session = startSession()
		BeamioConetChatSignBroker.setSignerEoa(other)
		var succeeded: Bool?
		let refused = expectation(description: "refused")
		let before = signAttempts
		BeamioConetChatModule.postSignedMailboxCommand(
			session: session, routerArmoredPublicKey: "unused", command: ["command": "probe"]
		) { ok, _ in
			succeeded = ok
			refused.fulfill()
		}
		wait(for: [refused], timeout: 10)
		XCTAssertEqual(succeeded, false)
		XCTAssertEqual(signAttempts, before, "nothing is signed for an account that is not the signer")

		// Positive control: the signer is the session's account, so the wallet is asked.
		BeamioConetChatSignBroker.setSignerEoa(account)
		let asked = expectation(description: "asked")
		let beforeAsked = signAttempts
		BeamioConetChatModule.postSignedMailboxCommand(
			session: session, routerArmoredPublicKey: "unused", command: ["command": "probe"]
		) { _, _ in
			asked.fulfill()
		}
		wait(for: [asked], timeout: 10)
		XCTAssertEqual(signAttempts, beforeAsked + 1)
	}

	func testTheBrokerRefusesToSignForAnotherSigner() {
		BeamioConetChatSignBroker.setSignerEoa(account)
		var got: Result<String, Error>?
		let before = signAttempts
		BeamioConetChatSignBroker.requestEip191(message: "probe", expectedEoa: other) { got = $0 }
		guard case .failure(let error)? = got else {
			XCTFail("the broker must refuse a signer other than the one asked for")
			return
		}
		XCTAssertEqual(error as? BeamioConetChatSignBroker.SignError, .signerChanged)
		XCTAssertEqual(signAttempts, before, "no signature is made for another signer")

		// Positive control: the signer asked for is the signer, so the wallet is asked (it has no key here, so it fails).
		BeamioConetChatSignBroker.requestEip191(message: "probe", expectedEoa: account) { _ in }
		XCTAssertEqual(signAttempts, before + 1)
	}

	func testASignRequestFromAnEarlierGenerationIsNotSigned() {
		let session = startSession()
		let earlier = BeamioInboxIO.generation
		clearAndWait()
		// The account is the signer again, so only the generation can refuse this request.
		BeamioConetChatSignBroker.setSignerEoa(account)
		let before = signAttempts
		var succeeded: Bool?
		let refused = expectation(description: "refused")
		BeamioConetChatModule.postSignedMailboxCommand(
			session: session, routerArmoredPublicKey: "unused", command: ["command": "probe"], generation: earlier
		) { ok, _ in
			succeeded = ok
			refused.fulfill()
		}
		wait(for: [refused], timeout: 10)
		XCTAssertEqual(succeeded, false)
		XCTAssertEqual(signAttempts, before, "a command of an earlier generation is not signed")
	}

	// MARK: - No resend after the clear (E-61)

	func testNoAckIsResentAfterTheClear() {
		_ = startSession()
		BeamioConetChatSignBroker.setSignerEoa(account)
		_ = BeamioConetChatModule.gossipRetry.recordFailure(frameHash)
		let before = signAttempts
		clearAndWait()
		// The listen handshake and the return to the foreground both retry at once. After a clear neither sends anything.
		BeamioConetChatModule.retryUnconfirmedGossipAcksNow()
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 10)
		XCTAssertTrue(BeamioConetChatModule.gossipRetry.pendingHashes.isEmpty)
		XCTAssertEqual(signAttempts, before, "no ack is re-signed with the new identity")
	}
}
#endif
