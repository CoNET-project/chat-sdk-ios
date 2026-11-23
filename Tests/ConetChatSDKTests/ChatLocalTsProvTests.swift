import XCTest
@testable import ConetChatSDK

/// D16: ts_prov covers the local write path only. Inbound index records carry
/// no ts_prov (`unknown_inbound`) and are never corrections. The correction is T-60; the empty-sendId case is R-4.
final class ChatLocalTsProvTests: XCTestCase {
	private let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let conv = "0x5555555555555555555555555555555555555555"
	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait)

	private func library() throws -> BeamioConetChatLocalStore {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("tsprov-\(UUID().uuidString)", isDirectory: true)
		let lib = BeamioConetChatLocalStore(rootDirectory: root)
		try lib.unlock(accountKey: account + ":default", localRoot: Data(repeating: 3, count: 32))
		return lib
	}

	private func sortTsList(_ lib: BeamioConetChatLocalStore) -> [Int64] {
		lib.openConversation(convKey: conv, viewport: viewport).items.map { $0.sortTs }
	}

	/// T-60: a receive-time row (ts_prov 1) is corrected by the sender time of the same sendKey (ts_prov 0). One visible
	/// row remains, at the sender time, and the superseded row never shows.
	func testT60ReceiveTimeRowIsCorrectedBySenderTime() throws {
		let lib = try library()
		try lib.addPendingLocal(convKey: conv, sendId: "k-60", sortTs: 1000, dir: "in", body: "late", tsProvided: false)
		XCTAssertEqual(sortTsList(lib), [1000])
		// The sender time comes from a local write (ts_prov 0). An import has an unknown source (ts_prov 2) and corrects nothing.
		try lib.addPendingLocal(convKey: conv, sendId: "k-60", sortTs: 500, dir: "in", body: "late", tsProvided: true)
		XCTAssertEqual(sortTsList(lib), [500], "one visible row, at the sender time")
		XCTAssertEqual(lib.openConversation(convKey: conv, viewport: viewport).items.compactMap { $0.body }, ["late"])
	}

	/// An imported row (ts_prov 2, unknown source) does not rewrite a receive-time row, and a sender-time row is kept (rule 5).
	func testSenderTimeRowIsKept() throws {
		let lib = try library()
		try lib.addPendingLocal(convKey: conv, sendId: "k-keep", sortTs: 1000, dir: "in", body: "kept", tsProvided: true)
		_ = try lib.importBatch(accountKey: account + ":default", rows: [
			BeamioChatImportRow(convKey: conv, dir: "in", ts: 500, sendId: "k-keep", body: "kept"),
		])
		XCTAssertEqual(sortTsList(lib), [1000])
	}

	/// R-4: with an empty sendId the sendKey depends on ts, so a different ts is a different row. Nothing is corrected.
	func testEmptySendIdIsNeverCorrected() throws {
		let lib = try library()
		try lib.addPendingLocal(convKey: conv, sendId: nil, sortTs: 1000, dir: "in", body: "same", tsProvided: false)
		_ = try lib.importBatch(accountKey: account + ":default", rows: [
			BeamioChatImportRow(convKey: conv, dir: "in", ts: 500, sendId: nil, body: "same"),
		])
		XCTAssertEqual(sortTsList(lib).sorted(), [500, 1000], "two rows: nothing is corrected")
	}
}
