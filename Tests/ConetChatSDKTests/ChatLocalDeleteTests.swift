import XCTest
@testable import ConetChatSDK

/// Native deletion of one message and of one conversation: the store results of DL-01 to DL-05, the argument rules of DL-06,
/// DL-07 and DL-09, the envelope rule of DL-08, the origin rule of, and the page-record rule of DL-10a and DL-10b. Synthetic data only.
final class ChatLocalDeleteTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			records[account] = record
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private var roots: [URL] = []
	private let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let convA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	private let convB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	private let convC = "0xcccccccccccccccccccccccccccccccccccccccc"
	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait, fontScale: 1.0)

	override func tearDown() {
		for r in roots { try? FileManager.default.removeItem(at: r) }
		roots = []
		super.tearDown()
	}

	/// A fresh, unlocked store with messages in two conversations. The message ids are the sendKeys (the sendIds given here).
	private func makeSeededStore() throws -> BeamioConetChatLocalStore {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("chat-delete-\(UUID().uuidString)", isDirectory: true)
		roots.append(root)
		let store = BeamioConetChatLocalStore(rootDirectory: root)
		try store.unlock(accountKey: account + ":default", localRoot: Data(repeating: 4, count: 32))
		try store.addPendingLocal(convKey: convA, sendId: "m1", sortTs: 1000, dir: "out", body: "a1")
		try store.addPendingLocal(convKey: convA, sendId: "m2", sortTs: 2000, dir: "out", body: "a2")
		try store.addPendingLocal(convKey: convB, sendId: "m1", sortTs: 1000, dir: "out", body: "b1")
		try store.addPendingLocal(convKey: convB, sendId: "m3", sortTs: 3000, dir: "out", body: "b3")
		return store
	}

	/// The bodies of the live messages of a conversation, in order. A tombstone has no body and is not shown.
	private func liveBodies(_ store: BeamioConetChatLocalStore, _ conv: String) -> [String] {
		store.openConversation(convKey: conv, viewport: viewport).items.compactMap { $0.body }
	}

	/// DL-01: a message delete touches only the selected message. The other message of its conversation and the other conversation stay.
	func testDL01MessageDeleteTouchesOnlyTheSelectedMessage() throws {
		let store = try makeSeededStore()
		XCTAssertEqual(store.deleteMessage(convKey: convA, sendKey: "m1"), true)
		XCTAssertEqual(liveBodies(store, convA), ["a2"])
		XCTAssertEqual(liveBodies(store, convB), ["b1", "b3"])
	}

	/// DL-02 and DL-03: an absent message, and a message that is already a tombstone, give `false` and change nothing (idempotent).
	func testDL02DL03AbsentAndTombstonedMessagesGiveFalse() throws {
		let store = try makeSeededStore()
		XCTAssertEqual(store.deleteMessage(convKey: convA, sendKey: "mX"), false)
		XCTAssertEqual(liveBodies(store, convA), ["a1", "a2"])
		XCTAssertEqual(store.deleteMessage(convKey: convA, sendKey: "m1"), true)
		XCTAssertEqual(store.deleteMessage(convKey: convA, sendKey: "m1"), false)
		XCTAssertEqual(liveBodies(store, convA), ["a2"])
	}

	/// DL-04: a conversation delete removes only that conversation. The other conversation keeps its messages. A message that arrives afterwards in the
	/// deleted conversation is an ordinary new message, and the conversation shows again.
	func testDL04ConversationDeleteTouchesOnlyThatConversation() throws {
		let store = try makeSeededStore()
		var deletedEvents = 0
		_ = store.subscribe(convKey: nil) { event in
			if case .deleted = event { deletedEvents += 1 }
		}
		// A `deleted` event is sent for a message inside an open window (the same rule as sync), so the conversation is opened first.
		_ = store.openConversation(convKey: convB, viewport: viewport)
		XCTAssertEqual(store.deleteConversation(convKey: convB), true)
		// Events are delivered on the store's notify queue. A barrier there lets every handler run before the count is read.
		store.notifyQueue.sync {}
		XCTAssertEqual(deletedEvents, 2)
		XCTAssertEqual(liveBodies(store, convB), [])
		XCTAssertEqual(liveBodies(store, convA), ["a1", "a2"])
		XCTAssertFalse(try store.listConversations(limit: 10, cursor: nil).rows.contains { $0.convKey == convB })
		try store.addPendingLocal(convKey: convB, sendId: "m9", sortTs: 9000, dir: "out", body: "b9")
		XCTAssertEqual(liveBodies(store, convB), ["b9"])
	}

	/// DL-05: a conversation that does not exist gives `false`, and nothing changes.
	func testDL05AbsentConversationGivesFalse() throws {
		let store = try makeSeededStore()
		XCTAssertEqual(store.deleteConversation(convKey: convC), false)
		XCTAssertEqual(liveBodies(store, convA), ["a1", "a2"])
		XCTAssertEqual(liveBodies(store, convB), ["b1", "b3"])
	}

	/// DL-06, DL-07, DL-09: the argument rules. A conversation address is `0x` and 40 lowercase hex digits. A message id is 1 to 128 visible ASCII
	/// characters.
	func testDL06DL07DL09ArgumentRules() {
		XCTAssertTrue(BeamioConetChatModule.isDeleteConvKey(convA))
		XCTAssertFalse(BeamioConetChatModule.isDeleteConvKey("0xABC"))
		XCTAssertFalse(BeamioConetChatModule.isDeleteConvKey("nope"))
		XCTAssertFalse(BeamioConetChatModule.isDeleteConvKey(convA.uppercased()))
		XCTAssertTrue(BeamioConetChatModule.isDeleteMessageId("m1"))
		XCTAssertFalse(BeamioConetChatModule.isDeleteMessageId(""))
		XCTAssertFalse(BeamioConetChatModule.isDeleteMessageId("a b"))
		XCTAssertTrue(BeamioConetChatModule.isDeleteMessageId(String(repeating: "a", count: 128)))
		XCTAssertFalse(BeamioConetChatModule.isDeleteMessageId(String(repeating: "a", count: 129)))
	}

	/// DL-08: a request id that is not valid gives the envelope-level `bad_request` with a null reqId, so the echo of the id is refused.
	func testDL08InvalidReqIdIsNotEchoed() {
		XCTAssertNil(BeamioChatRouteRegister.reqIdEcho(""))
	}

	/// the chat channel does not judge the origin; the shell does before it calls the SDK. The two deletes are answered by the gate and the
	/// record like any other command: exactly one answer each, and no origin answer from the SDK.
	func testTheDeleteCommandsAreAnsweredOnceAndTheSDKDoesNotJudgeTheOrigin() {
		var payloads: [[String: Any]] = []
		let capture: BeamioConetChatModule.WebEmit = { payloads.append($0) }
		BeamioConetChatModule.handleCommand(["type": "noSuchCommand", "reqId": "d-setup"], emit: capture)
		drainMainQueue()
		payloads.removeAll()
		BeamioConetChatModule.handleCommand(["type": "historyDeleteMessage", "reqId": "d1", "convKey": convA, "messageId": "m1"], emit: capture)
		BeamioConetChatModule.handleCommand(["type": "historyDeleteConversation", "reqId": "d2", "convKey": convA], emit: capture)
		drainMainQueue()
		let events = payloads.compactMap { $0["event"] as? [String: Any] }
		XCTAssertEqual(events.filter { $0["reqId"] as? String == "d1" }.count, 1, "d1 is answered once")
		XCTAssertEqual(events.filter { $0["reqId"] as? String == "d2" }.count, 1, "d2 is answered once")
		XCTAssertTrue(events.allSatisfy { $0["error"] as? String != "origin_refused" }, "the SDK gives no origin answer")
	}

	private func drainMainQueue() {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
	}

	/// DL-10a and DL-10b: a conversation entry in the page record is removed only from a fresh read. A stale `rev` gives `conflict` and the stored
	/// record stays as it was. A matching `rev` gives `ok`, the `rev` goes up by one, and only that entry is removed. The entries are at
	/// `profiles[*].chats[*]`.
	func testDL10PageRecordEntryDeleteFollowsTheRev() {
		let store = Store()
		store.records[account] = [
			"rev": 3,
			"schemaVersion": 1,
			"profiles": [["chats": [["address": convA, "emailAddr": "a"], ["address": convB, "emailAddr": "b"]]]],
		]
		let env = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: Device(),
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
		func entries() -> [String?] {
			let profiles = store.records[account]?["profiles"] as? [[String: Any]] ?? []
			let chats = profiles.first?["chats"] as? [[String: Any]] ?? []
			return chats.map { $0["address"] as? String }
		}

		let stale = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "dl10a",
			 "record": ["rev": 2, "schemaVersion": 1, "profiles": [["chats": [["address": convB, "emailAddr": "b"]]]]]],
			env: env
		)
		XCTAssertEqual(stale["code"] as? String, "conflict")
		XCTAssertEqual(stale["currentRev"] as? Int, 3)
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 3)
		XCTAssertEqual(entries(), [convA, convB])

		let fresh = BeamioShellRecord.answer(
			["type": "shellRecordWrite", "reqId": "dl10b",
			 "record": ["rev": 3, "schemaVersion": 1, "profiles": [["chats": [["address": convB, "emailAddr": "b"]]]]]],
			env: env
		)
		XCTAssertEqual(fresh["code"] as? String, "ok")
		XCTAssertEqual(fresh["rev"] as? Int, 4)
		XCTAssertEqual(store.records[account]?["rev"] as? Int, 4)
		XCTAssertEqual(entries(), [convB])
	}
}
