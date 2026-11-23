import XCTest
@testable import ConetChatSDK

/// `reply` rows are never shown and take no height. They still move the scan cursor.
final class ChatLocalReplyVisibilityTests: XCTestCase {
	func testReplyRowsAreNeverShown() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("reply-\(UUID().uuidString)", isDirectory: true)
		let library = BeamioConetChatLocalStore(rootDirectory: root)
		let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
		try library.unlock(accountKey: account + ":default", localRoot: Data(repeating: 7, count: 32))
		let conv = "0x2222222222222222222222222222222222222222"
		let text = #"{"sendId":"s-1","from":"them","text":"hi","createdAt":1767225601234}"#
		let reply = #"{"id":"tmp_1","from":"me","text":"","createdAt":1767225609000,"reply":{"messageId":"s-1","reactionKey":"like"}}"#
		_ = try library.importBatch(accountKey: account + ":default", rows: [
			BeamioChatImportRow(convKey: conv, dir: "in", ts: 1767225601234, sendId: "s-1", body: text),
			BeamioChatImportRow(convKey: conv, dir: "out", ts: 1767225609000, sendId: "s-2", body: reply),
		])
		let page = library.openConversation(convKey: conv, viewport: BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait))
		XCTAssertEqual(page.items.map { $0.kind }, [.text])
		XCTAssertEqual(page.items.first?.body, "hi", "the shown body is the text field")
	}
}
