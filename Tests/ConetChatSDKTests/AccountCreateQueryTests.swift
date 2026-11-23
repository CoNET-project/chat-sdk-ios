import XCTest
@testable import ConetChatSDK

/// The pending binding query of `nativeAccountCreateOpen`. A query is answered once: by the
/// lookup, or by the watchdog at the 10-second total with `lookup_unavailable`. A later answer of a settled query changes nothing. While a query
/// is pending, every open is `not_available` and no second query starts. The watchdog is shortened here; the 10-second total is the default.
final class AccountCreateQueryTests: XCTestCase {
	private let account = "alice"
	private var savedDeferred: ((BeamioAccountBindingLookup.Account, @escaping (BeamioAccountBindingLookup.Outcome) -> Void) -> Void)?
	private var savedWatchdog: TimeInterval = BeamioAccountBindingLookup.totalBudget
	private var savedHost: (() -> Bool)?
	private var held: [(BeamioAccountBindingLookup.Outcome) -> Void] = []
	private var hostCalls = 0
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedDeferred = BeamioAccountBindingLookup.deferred
		savedWatchdog = BeamioConetChatModule.queryWatchdog
		savedHost = BeamioNativeAccountCreate.onCreateRequired
		BeamioAccountBindingLookup.deferred = { [weak self] _, completion in self?.held.append(completion) }
		BeamioConetChatModule.queryWatchdog = 0.2
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeAccountCreate.onCreateRequired = { [weak self] in
			self?.hostCalls += 1
			return true
		}
		held = []
		hostCalls = 0
		events = []
	}

	override func tearDown() {
		// A query a test left pending is answered now, so its watchdog cannot write into a later test's events.
		for completion in held { completion(.unavailable("test_end")) }
		held = []
		drain(0.05)
		BeamioAccountBindingLookup.deferred = savedDeferred
		BeamioConetChatModule.queryWatchdog = savedWatchdog
		BeamioNativeAccountCreate.onCreateRequired = savedHost
		BeamioConetChatModule.closeAccountCreatePage()
		drain(0.1)
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	/// Sends one open with the reqId given, and returns nothing: the events arrive on the main queue (see `drain`).
	private func open(_ reqId: String) {
		let body: [String: Any] = ["type": "nativeAccountCreateOpen", "reqId": reqId, "account": account]
		BeamioConetChatModule.handleCommand(body, emit: { [weak self] event in
			self?.events.append((event["event"] as? [String: Any]) ?? event)
		})
	}

	/// Runs the main queue for the time given, so the events and the watchdog run.
	private func drain(_ seconds: TimeInterval) {
		let until = Date().addingTimeInterval(seconds)
		while Date() < until {
			RunLoop.main.run(until: Date().addingTimeInterval(0.01))
		}
	}

	private func acks(_ reqId: String) -> [[String: Any]] {
		events.filter { $0["type"] as? String == "ack" && $0["reqId"] as? String == reqId }
	}

	private func results(_ reqId: String) -> [[String: Any]] {
		events.filter { $0["type"] as? String == "nativeAccountCreateResult" && $0["reqId"] as? String == reqId }
	}

	func testTheDefaultWatchdogIsTheTenSecondTotal() {
		XCTAssertEqual(BeamioAccountBindingLookup.totalBudget, 10, "the watchdog's default is the total")
	}

	/// a query that the lookup never answers is answered `lookup_unavailable` at the watchdog, once. A late answer of it changes nothing.
	func testAPendingQueryIsAnsweredByTheWatchdogOnce() {
		open("W1")
		drain(0.05)
		XCTAssertTrue(events.isEmpty, "a pending query sends nothing yet")
		drain(0.5)
		XCTAssertEqual(acks("W1").first?["ok"] as? Bool, true)
		XCTAssertEqual(acks("W1").first?["page"] as? String, "none")
		XCTAssertEqual(accountCreateCode(results("W1").first), "lookup_unavailable")
		XCTAssertEqual(hostCalls, 0, "a lookup that was not answered opens no page")
		let settled = events.count
		held.first?(.noBinding)
		drain(0.2)
		XCTAssertEqual(events.count, settled, "a late answer of a settled query is ignored")
		XCTAssertEqual(hostCalls, 0)
	}

	/// M-1 and: while a query is pending, the same reqId and any other reqId are `not_available`, and no second query starts.
	func testWhilePendingEveryOpenIsRefusedAndNoSecondQueryStarts() {
		open("W2")
		open("W2")
		open("W3")
		XCTAssertEqual(held.count, 1, "no second query starts")
		drain(0.05)
		XCTAssertEqual(acks("W2").count, 1)
		XCTAssertEqual(acks("W2").first?["ok"] as? Bool, false)
		XCTAssertEqual(acks("W2").first?["error"] as? String, "not_available")
		XCTAssertEqual(acks("W3").first?["error"] as? String, "not_available")
		XCTAssertEqual(hostCalls, 0)
		held.first?(.noBinding)
		drain(0.1)
		XCTAssertEqual(hostCalls, 1, "the first request's answer opens the page once")
		XCTAssertEqual(acks("W2").filter { $0["ok"] as? Bool == true }.count, 1, "the first request's answer is not re-sent")
		XCTAssertEqual(acks("W2").last?["page"] as? String, "opened")
	}

	/// a reqId whose page has finished stays refused after another page opens and closes. A new page does not clear the set.
	func testAFinishedReqIdStaysRefusedWhenAnotherPageOpens() {
		open("F1")
		held[0](.noBinding)
		drain(0.05)
		XCTAssertEqual(hostCalls, 1)
		let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
		XCTAssertTrue(BeamioConetChatModule.deliverAccountCreateResult(
			["type": "nativeAccountCreateResult", "reqId": "F1", "code": "ok", "eoa": eoa]
		).forwarded)
		open("F2")
		held[1](.noBinding)
		drain(0.05)
		XCTAssertEqual(hostCalls, 2)
		BeamioConetChatModule.closeAccountCreatePage()
		drain(0.05)
		let queriesBefore = held.count
		open("F1")
		drain(0.05)
		XCTAssertEqual(acks("F1").last?["error"] as? String, "not_available", "a finished reqId is refused after another page opened and closed")
		XCTAssertEqual(held.count, queriesBefore, "no query starts for the refused reqId")
		XCTAssertEqual(hostCalls, 2, "no page opens for the refused reqId")
	}

	/// An answered query frees the slot: the next open starts a new query.
	func testAnAnsweredQueryFreesTheSlot() {
		open("W4")
		held.first?(.alreadyBound)
		drain(0.1)
		XCTAssertEqual(accountCreateCode(results("W4").first), "already_bound")
		open("W5")
		XCTAssertEqual(held.count, 2, "the slot is free, so the next open starts its own query")
	}
}
