import XCTest
@testable import ConetChatSDK

/// The result of the open recovery page (spec; iOS shell 2026-11-13, ruling (a)): one result per confirmation,
/// a failure keeps the page open for a retry, `ok` closes it, and a close after a result sends nothing more.
final class NativeResultPageTests: XCTestCase {
	private let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private var savedHost: ((String) -> Bool)?
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedHost = BeamioNativeRecovery.onRecoveryRequired
		BeamioNativeRecovery.onRecoveryRequired = { _ in true }
		BeamioNativeAccountPointer.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		events = []
	}

	override func tearDown() {
		BeamioConetChatModule.closeRecoveryPage()
		_ = drain()
		BeamioNativeRecovery.onRecoveryRequired = savedHost
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// Lets the main queue deliver the events posted asynchronously, then returns the events sent since `from`.
	private func drain(from: Int = 0) -> [[String: Any]] {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return Array(events.dropFirst(from))
	}

	private func open(reqId: String) -> [[String: Any]] {
		let from = events.count
		BeamioConetChatModule.handleCommand(["type": "nativeRecoveryOpen", "reqId": reqId], emit: { [weak self] event in
			self?.events.append((event["event"] as? [String: Any]) ?? event)
		})
		return drain(from: from)
	}

	func testAFailureKeepsThePageOpenAndAnOkClosesIt() {
		XCTAssertEqual(open(reqId: "R-1").first?["ok"] as? Bool, true)
		XCTAssertTrue(BeamioConetChatModule.finishRecovery(code: "invalid_format", eoa: nil, cooldownSec: nil))
		XCTAssertTrue(BeamioConetChatModule.recoveryPageOpen(), "a failure keeps the page open")

		XCTAssertTrue(BeamioConetChatModule.finishRecovery(code: "ok", eoa: eoa, cooldownSec: nil))
		let sent = drain(from: 1)
		XCTAssertEqual(sent.count, 2, "a result per confirmation")
		XCTAssertEqual(sent.first?["code"] as? String, "invalid_format")
		XCTAssertEqual(sent.last?["code"] as? String, "ok")
		XCTAssertEqual(sent.last?["eoa"] as? String, eoa)
		XCTAssertFalse(BeamioConetChatModule.recoveryPageOpen(), "ok closes the page")
		XCTAssertFalse(BeamioConetChatModule.finishRecovery(code: "ok", eoa: eoa, cooldownSec: nil), "no page, no result")
	}

	func testBackoffKeepsThePageOpenAndACloseAfterItSendsNothing() {
		XCTAssertEqual(open(reqId: "R-2").first?["ok"] as? Bool, true)
		XCTAssertTrue(BeamioConetChatModule.finishRecovery(code: "backoff", eoa: nil, cooldownSec: 30))
		XCTAssertTrue(BeamioConetChatModule.recoveryPageOpen())
		XCTAssertTrue(BeamioConetChatModule.closeRecoveryPage())
		let sent = drain(from: 1)
		XCTAssertEqual(sent.map { $0["code"] as? String }, ["backoff"], "no cancelled after a result")
		XCTAssertEqual(sent.first?["cooldownSec"] as? Int, 30)
		XCTAssertFalse(BeamioConetChatModule.recoveryPageOpen())
	}

	func testACloseBeforeAnyResultSendsCancelled() {
		XCTAssertEqual(open(reqId: "R-3").first?["ok"] as? Bool, true)
		XCTAssertTrue(BeamioConetChatModule.closeRecoveryPage())
		let sent = drain(from: 1)
		XCTAssertEqual(sent.map { $0["code"] as? String }, ["cancelled"])
		XCTAssertEqual(sent.first?["reqId"] as? String, "R-3")
	}

	/// B7 (r3rz §25.52Y.48): each of the three paths (success, cancelled, backoff) carries the reqId of the open page.
	func testTheSuccessResultCarriesTheReqId() {
		XCTAssertEqual(open(reqId: "R-21").first?["ok"] as? Bool, true)
		XCTAssertTrue(BeamioConetChatModule.finishRecovery(code: "ok", eoa: eoa, cooldownSec: nil))
		let sent = drain(from: 1)
		XCTAssertEqual(sent.last?["code"] as? String, "ok")
		XCTAssertEqual(sent.last?["reqId"] as? String, "R-21", "the success result names the open reqId")
	}

	func testTheCancelledResultCarriesTheReqId() {
		XCTAssertEqual(open(reqId: "R-22").first?["ok"] as? Bool, true)
		XCTAssertTrue(BeamioConetChatModule.closeRecoveryPage())
		let sent = drain(from: 1)
		XCTAssertEqual(sent.first?["code"] as? String, "cancelled")
		XCTAssertEqual(sent.first?["reqId"] as? String, "R-22", "the cancelled result names the open reqId")
	}

	func testTheBackoffResultCarriesTheReqId() {
		XCTAssertEqual(open(reqId: "R-23").first?["ok"] as? Bool, true)
		XCTAssertTrue(BeamioConetChatModule.finishRecovery(code: "backoff", eoa: nil, cooldownSec: 60))
		let sent = drain(from: 1)
		XCTAssertEqual(sent.first?["code"] as? String, "backoff")
		XCTAssertEqual(sent.first?["reqId"] as? String, "R-23", "the backoff result names the open reqId")
	}
}
