#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// every chat signature path checks the signer before it signs (one refusal test per class), and an in-flight send or ack whose
/// callback never comes times out. Synthetic data only.
final class InFlightSignerTests: XCTestCase {
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
	private let account = "0x0000000000000000000000000000000000000003"
	private let other = "0x0000000000000000000000000000000000000004"
	private let peer = "0x0000000000000000000000000000000000000009"
	private let frameHash = "0x" + String(repeating: "5", count: 64)
	private let routeKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-route\n-----END PGP PUBLIC KEY BLOCK-----"
	private let userKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-user\n-----END PGP PUBLIC KEY BLOCK-----"
	private let chatLine = "{\"text\":\"hello\"}"
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
		BeamioConetChatSignBroker.testHangSigning = false
		BeamioConetChatModule.testSetInFlightTimeout(30)
		BeamioConetChatSignBroker.clearSigner()
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.testDetachPageEmit()
		BeamioConetChatModule.gossipRetry.clear()
		BeamioConetChatModule.testClearImmediateRetryThrottle()
		events = []
	}

	// MARK: - helpers

	private var signAttempts: Int {
		BeamioConetChatSignBroker.testSignAttempts
	}

	private func startSession() -> BeamioConetChatModule.Session {
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		return BeamioConetChatModule.testCurrentSession()!
	}

	private func capture() {
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	/// Lets the main queue run what is queued on it.
	private func drainMain() {
		let e = expectation(description: "main drained")
		DispatchQueue.main.async { e.fulfill() }
		wait(for: [e], timeout: 10)
	}

	/// Lets the inbox IO queue and the main queue run through a short chain.
	private func settle() {
		for _ in 0..<4 {
			let e = expectation(description: "IO round")
			BeamioInboxIO.perform(generation: BeamioInboxIO.generation, { true }) { _ in e.fulfill() }
			wait(for: [e], timeout: 10)
		}
	}

	/// Waits `seconds` on the test thread while the main queue runs its timers.
	private func pause(_ seconds: TimeInterval) {
		let e = expectation(description: "pause")
		DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { e.fulfill() }
		wait(for: [e], timeout: seconds + 10)
	}

	/// The answers the page received for one reqId, in order.
	private func acks(_ reqId: Int) -> [(ok: Bool, error: String?)] {
		events.compactMap { out in
			guard let event = out["event"] as? [String: Any],
                  event["type"] as? String == "ack",
                  event["reqId"] as? Int == reqId
			else { return nil }
			return (ok: event["ok"] as? Bool ?? false, error: event["error"] as? String)
		}
	}

	private func sendBody(reqId: Int) -> [String: Any] {
		[
			"reqId": reqId,
			"payload": chatLine,
			"sendId": "send-\(reqId)",
			"to": ["userPublicKeyArmored": userKey, "routerArmoredPublicKey": routeKey] as [String: Any],
		]
	}

	private func groupBody(reqId: Int) -> [String: Any] {
		[
			"reqId": reqId,
			"request": [
				"body": "group hello",
				"groupId": "g-1",
				"roster": ["groupId": "g-1", "members": [] as [[String: Any]]] as [String: Any],
			] as [String: Any],
		]
	}

	private func historyStore() -> BeamioConetChatHistoryStore {
		BeamioConetChatHistoryStore(
			eoa: account, chainId: 224_422, conetRpcUrl: "https://rpc.invalid", ipfsBaseUrl: "https://ipfs.invalid",
			ipfsWriteBaseUrl: nil, apiBaseUrl: "https://api.invalid",
			registryAddress: "0x0000000000000000000000000000000000000001", openPgp: nil, log: { _, _ in }
		)
	}

	// MARK: - one refusal per signing class

	/// The ack (gossip_delivery_ack): another account is not signed for; the refused ack goes back to pending retry.
	func testAnAckIsNotSignedForAnotherAccount() {
		let session = startSession()
		session.ownRouteArmoredPublicKey = routeKey
		BeamioConetChatSignBroker.setSignerEoa(other)
		let before = signAttempts
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer, armorHash: frameHash, armor: armor,
			viaDomain: "d", generation: BeamioInboxIO.generation
		)
		settle()
		XCTAssertEqual(signAttempts, before, "no signature is made for another account (ack)")
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 1, "the refused ack goes back to pending retry")

		// Positive control: the signer is the session's account, so the ack is asked to sign.
		BeamioConetChatSignBroker.setSignerEoa(account)
		let beforeOk = signAttempts
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer, armorHash: frameHash, armor: armor,
			viaDomain: "d", generation: BeamioInboxIO.generation
		)
		settle()
		XCTAssertEqual(signAttempts, beforeOk + 1, "the session's account is asked (the duplicate's ack)")
	}

	/// The mailbox command: another account is not signed for, and the command completes as a failure.
	func testAMailboxCommandIsNotSignedForAnotherAccount() {
		let session = startSession()
		BeamioConetChatSignBroker.setSignerEoa(other)
		let before = signAttempts
		var succeeded: Bool?
		let e = expectation(description: "mailbox command answered")
		BeamioConetChatModule.postSignedMailboxCommand(
			session: session, routerArmoredPublicKey: routeKey, command: ["command": "probe"]
		) { ok, _ in
			succeeded = ok
			e.fulfill()
		}
		wait(for: [e], timeout: 10)
		XCTAssertEqual(succeeded, false)
		XCTAssertEqual(signAttempts, before, "no signature is made for another account (mailbox command)")
	}

	/// The single chat send: another account is not signed for; the page is answered with a failure.
	func testASingleChatSendIsNotSignedForAnotherAccount() {
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(other)
		let before = signAttempts
		BeamioConetChatModule.testSend(sendBody(reqId: 7))
		drainMain()
		XCTAssertEqual(signAttempts, before, "no signature is made for another account (single send)")
		XCTAssertEqual(acks(7).count, 1)
		XCTAssertEqual(acks(7).first?.ok, false)
		XCTAssertEqual(acks(7).first?.error, "signer_mismatch", "a refused signer is answered as signer_mismatch ((3))")

		// Positive control: the session's account is asked (no key in this test, so the send then fails).
		BeamioConetChatSignBroker.setSignerEoa(account)
		let beforeOk = signAttempts
		BeamioConetChatModule.testSend(sendBody(reqId: 8))
		drainMain()
		XCTAssertEqual(signAttempts, beforeOk + 1, "the session's account is asked (single send)")
	}

	/// The group text: another account is not signed for; the page is answered with a failure.
	func testAGroupTextIsNotSignedForAnotherAccount() {
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(other)
		let before = signAttempts
		BeamioConetChatModule.testSendGroup(groupBody(reqId: 9))
		drainMain()
		XCTAssertEqual(signAttempts, before, "no signature is made for another account (group text)")
		XCTAssertEqual(acks(9).first?.ok, false)
		XCTAssertEqual(acks(9).first?.error, "signer_mismatch")

		BeamioConetChatSignBroker.setSignerEoa(account)
		let beforeOk = signAttempts
		BeamioConetChatModule.testSendGroup(groupBody(reqId: 10))
		drainMain()
		XCTAssertEqual(signAttempts, beforeOk + 1, "the session's account is asked (group text)")
	}

	/// The history record's self-signature: another account is not signed for.
	func testTheHistoryRecordIsNotSignedForAnotherAccount() {
		let store = historyStore()
		BeamioConetChatSignBroker.setSignerEoa(other)
		let before = signAttempts
		XCTAssertThrowsError(try store.testSelfSign())
		XCTAssertEqual(signAttempts, before, "no signature is made for another account (history record)")

		BeamioConetChatSignBroker.setSignerEoa(account)
		let beforeOk = signAttempts
		_ = try? store.testSelfSign()
		XCTAssertEqual(signAttempts, beforeOk + 1, "the store's own account is asked (history record)")
	}

	/// The listen authentication: an account that is not the signer is not signed for.
	func testAListenAuthIsNotSignedForAnotherAccount() {
		BeamioConetChatSignBroker.setSignerEoa(other)
		let before = signAttempts
		var got: Result<String, Error>?
		BeamioConetChatSignBroker.requestListenAuth(eoa: account, message: "listen") { got = $0 }
		guard case .failure(let error)? = got else {
			XCTFail("the listen authentication must be refused for another account")
			return
		}
		XCTAssertEqual(error as? BeamioConetChatSignBroker.SignError, .signerChanged)
		XCTAssertEqual(signAttempts, before, "no signature is made for another account (listen authentication)")

		BeamioConetChatSignBroker.setSignerEoa(account)
		let beforeOk = signAttempts
		BeamioConetChatSignBroker.requestListenAuth(eoa: account, message: "listen") { _ in }
		XCTAssertEqual(signAttempts, beforeOk + 1, "the signer's account is asked (listen authentication)")
	}

	/// The synchronous form, used by the history store: another signer is refused before any signature.
	func testTheSynchronousSignatureRefusesAnotherSigner() {
		BeamioConetChatSignBroker.setSignerEoa(account)
		let before = signAttempts
		switch BeamioConetChatSignBroker.requestEip191Sync(message: "probe", expectedEoa: other) {
		case .success:
			XCTFail("another signer must be refused")
		case .failure(let error):
			XCTAssertEqual(error as? BeamioConetChatSignBroker.SignError, .signerChanged)
		}
		XCTAssertEqual(signAttempts, before)
	}

	// MARK: - in-flight timeouts

	/// An ack whose signature never answers times out, and goes back to pending retry.
	func testAnAckWithoutACallbackGoesBackToPending() {
		let session = startSession()
		session.ownRouteArmoredPublicKey = routeKey
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatSignBroker.testHangSigning = true
		BeamioConetChatModule.testSetInFlightTimeout(0.1)
		let before = signAttempts
		BeamioConetChatModule.acceptVerifiedInbound(
			session: session, plaintext: chatLine, from: peer, armorHash: frameHash, armor: armor,
			viaDomain: "d", generation: BeamioInboxIO.generation
		)
		settle()
		pause(0.5)
		XCTAssertEqual(signAttempts, before + 1, "the ack is asked to sign once")
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.failures[frameHash], 1, "no callback: the in-flight ack is back to pending retry")
		XCTAssertEqual(BeamioConetChatModule.gossipRetry.pendingHashes, [frameHash])
	}

	/// A send whose signature never answers is answered once, as a timeout the page keeps pending.
	func testASendWithoutACallbackIsAnsweredOnceAsATimeout() {
		_ = startSession()
		capture()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatSignBroker.testHangSigning = true
		BeamioConetChatModule.testSetInFlightTimeout(0.1)
		BeamioConetChatModule.testSend(sendBody(reqId: 11))
		pause(0.5)
		XCTAssertEqual(acks(11).count, 1, "the page is answered once")
		XCTAssertEqual(acks(11).first?.ok, false)
		XCTAssertEqual(acks(11).first?.error, "send_timeout", "a timeout is a failure the page keeps pending")
	}

	/// The first answer of an in-flight operation is delivered; a later one is dropped, and so is a late one after the timeout.
	func testAnInFlightAnswerIsDeliveredOnceAndALateOneIsDropped() {
		var delivered: [Int] = []
		let first = BeamioInFlightOnce<Int>(timeout: 0.1, timeoutValue: 7) { delivered.append($0) }
		XCTAssertTrue(first.finish(1))
		XCTAssertFalse(first.finish(2))
		pause(0.3)
		XCTAssertEqual(delivered, [1], "the first answer wins, and the timer does not answer again")

		var late: [Int] = []
		let slow = BeamioInFlightOnce<Int>(timeout: 0.1, timeoutValue: 7) { late.append($0) }
		pause(0.3)
		XCTAssertFalse(slow.finish(2), "a late answer after the timeout is dropped")
		XCTAssertEqual(late, [7], "the timeout answer is the one delivered")
	}
	/// (F3): a route registration is not given the PGP record of another account, so it is refused (`no_pgp_key`) before any signature.
	func testARouteRegistrationIsRefusedForAnotherAccount() {
		BeamioConetChatSignBroker.setSignerEoa(other)
		XCTAssertNil(BeamioConetChatModule.routeRegisterSecrets(account: account), "the record of another account is not read")
	}

	/// (F3): the W3 values, which come from the history master's domain signature, are not given for another account.
	func testTheHistoryMasterIsNotGivenToAnotherAccount() {
		BeamioConetChatSignBroker.setSignerEoa(other)
		XCTAssertNil(BeamioConetChatModule.protocolValues(account: account), "another account gets no history master")
	}
}
#endif
