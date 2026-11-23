import XCTest
@testable import ConetChatSDK

/// The kind and the pending count are ciphertext. The plaintext columns are
/// gone, and the values are read back through the encrypted meta.
final class ChatLocalCiphertextFieldsTests: XCTestCase {
	private final class Counter {
		var calls = 0
	}

	private let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let conv = "0x6666666666666666666666666666666666666666"

	func testKindAndPendingCountAreReadBackFromCiphertextOnly() throws {
		let root = FileManager.default.temporaryDirectory.appendingPathComponent("cipher-\(UUID().uuidString)", isDirectory: true)
		let lib = BeamioConetChatLocalStore(rootDirectory: root)
		try lib.unlock(accountKey: account + ":default", localRoot: Data(repeating: 4, count: 32))
		let reply = #"{"id":"tmp_9","from":"me","text":"","createdAt":1,"reply":{"messageId":"s","reactionKey":"like"}}"#
		_ = try lib.importBatch(accountKey: account + ":default", rows: [
			BeamioChatImportRow(convKey: conv, dir: "in", ts: 1000, sendId: "c1", body: #"{"sendId":"c1","from":"them","text":"imported text","createdAt":1}"#),
			BeamioChatImportRow(convKey: conv, dir: "out", ts: 2000, sendId: "c2", body: reply),
		])
		try lib.addPendingLocal(convKey: conv, sendId: "c3", sortTs: 3000, dir: "out", body: "pending text")

		let page = try lib.listConversations(limit: 10, cursor: nil)
		XCTAssertEqual(page.rows.count, 1)
		XCTAssertEqual(page.rows.first?.pendingCount, 1, "the pending count is read from the encrypted meta")
		XCTAssertEqual(page.rows.first?.lastPreview, "pending text", "the newest non-reply row is found by its encrypted kind")

		let path = lib.databasePath(for: account.lowercased() + ":default")
		let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertNil(bytes.range(of: Data("pending_count".utf8)), "no plaintext pending_count column")
		XCTAssertNil(bytes.range(of: Data("reply".utf8)), "no plaintext kind in the file")
		XCTAssertNil(bytes.range(of: Data("pending text".utf8)), "no plaintext body in the file")
	}

	/// Locked: an append does not complete. It is refused before any master or signature is used, so it writes no
	/// provenance and creates no record that would need a signature.
	func testAnAppendWhileLockedSignsNothingAndWritesNoProvenance() {
		let store = BeamioConetChatHistoryStore(
			eoa: account, chainId: 224422, conetRpcUrl: "https://example.invalid", ipfsBaseUrl: "https://example.invalid",
			ipfsWriteBaseUrl: nil, apiBaseUrl: "https://example.invalid", registryAddress: "0x1234567890123456789012345678901234567890",
			openPgp: nil, log: { _, _ in }
		)
		let counter = Counter()
		store.localTsProvSink = { _, _, _ in counter.calls += 1 }
		let done = expectation(description: "append completes")
		var completed: Bool?
		store.append(entry: ["sendId": "locked-1", "peer": conv, "dir": "out", "body": "hello"]) { ok in
			completed = ok
			done.fulfill()
		}
		wait(for: [done], timeout: 5)
		XCTAssertEqual(completed, false, "a locked store refuses the append")
		XCTAssertEqual(counter.calls, 0, "no provenance is written for a refused append")
	}
}
