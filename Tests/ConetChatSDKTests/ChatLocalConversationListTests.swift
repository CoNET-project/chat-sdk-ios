import CryptoKit
import XCTest
@testable import ConetChatSDK

/// T-40 (spec 6.7): session list. Pages without duplicates, in the reference order (lastSortTs desc, then conv_blind
/// ascending), `reply` rows do not make a conversation visible, and the list is empty while locked.
final class ChatLocalConversationListTests: XCTestCase {
	func testSessionListPagesInReferenceOrderAndClearsOnLock() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("convlist-\(UUID().uuidString)", isDirectory: true)
		let library = BeamioConetChatLocalStore(rootDirectory: root)
		let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
		let localRoot = Data(repeating: 9, count: 32)
		try library.unlock(accountKey: account + ":default", localRoot: localRoot)

		let c1 = "0x0000000000000000000000000000000000000001"
		let c2 = "0x0000000000000000000000000000000000000002"
		let c3 = "0x0000000000000000000000000000000000000003"
		let c4 = "0x0000000000000000000000000000000000000004"
		let c5 = "0x0000000000000000000000000000000000000005"  // only a reply row: not listed
		let text = { (t: String) in #"{"sendId":"x","from":"them","text":"\#(t)","createdAt":1}"# }
		let reply = #"{"id":"tmp_9","from":"me","text":"","createdAt":1,"reply":{"messageId":"s","reactionKey":"like"}}"#
		_ = try library.importBatch(accountKey: account + ":default", rows: [
			BeamioChatImportRow(convKey: c1, dir: "in", ts: 200, sendId: "a1", body: text("one-old")),
			BeamioChatImportRow(convKey: c1, dir: "in", ts: 300, sendId: "a2", body: text("one")),
			BeamioChatImportRow(convKey: c2, dir: "in", ts: 500, sendId: "b1", body: text("two")),
			BeamioChatImportRow(convKey: c3, dir: "in", ts: 500, sendId: "c1", body: text("three")),
			BeamioChatImportRow(convKey: c4, dir: "in", ts: 100, sendId: "d1", body: text("four")),
			BeamioChatImportRow(convKey: c5, dir: "out", ts: 900, sendId: "e1", body: reply),
		])

		// Reference order from the same key derivation: ties at 500 are ordered by the blinded conversation id.
		let idx = BeamioChatLocalCrypto.idxKey(localRoot: localRoot)
		let blind = { (c: String) in BeamioChatLocalCrypto.blind(idxKey: idx, c) }
		let expected = [(c2, 500), (c3, 500), (c1, 300), (c4, 100)]
			.sorted { a, b in a.1 != b.1 ? a.1 > b.1 : blind(a.0) < blind(b.0) }
			.map { $0.0 }

		var got: [BeamioChatConversationRow] = []
		var cursor: String?
		var pages = 0
		repeat {
			let page = try library.listConversations(limit: 2, cursor: cursor)
			got += page.rows
			cursor = page.nextCursor
			pages += 1
		} while cursor != nil && pages < 10
		XCTAssertEqual(got.map { $0.convKey }, expected, "no duplicates and the reference order")
		XCTAssertEqual(pages, 2, "two pages of at most two rows")
		let c1Row = try XCTUnwrap(got.first { $0.convKey == c1 })
		XCTAssertEqual(c1Row.lastPreview, "one", "the preview is the newest visible text")
		XCTAssertEqual(c1Row.lastSortTs, 300)
		XCTAssertFalse(got.contains { $0.convKey == c5 }, "a conversation with only reply rows is not listed")

		library.lock()
		XCTAssertEqual(try library.listConversations(limit: 100, cursor: nil).rows, [], "cleared on lock (6.5)")
	}

	func testABadCursorIsRefused() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("convlist-bad-\(UUID().uuidString)", isDirectory: true)
		let library = BeamioConetChatLocalStore(rootDirectory: root)
		try library.unlock(accountKey: "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a:default", localRoot: Data(repeating: 9, count: 32))
		XCTAssertThrowsError(try library.listConversations(limit: 10, cursor: "not-a-cursor!")) { error in
			XCTAssertEqual(error as? BeamioChatLocalError, .cursorInvalid)
		}
	}
}
