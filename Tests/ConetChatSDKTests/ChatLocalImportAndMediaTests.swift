import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Media body parser (spec 21, T-32) and native import (spec 11.1 M2–M3, 11.2). Synthetic data only.
final class ChatLocalImportAndMediaTests: XCTestCase {
	private var roots: [URL] = []

	override func tearDown() {
		for r in roots { try? FileManager.default.removeItem(at: r) }
		roots = []
		super.tearDown()
	}

	private func tempRoot() -> URL {
		let u = FileManager.default.temporaryDirectory.appendingPathComponent("chat-local-import-\(UUID().uuidString)", isDirectory: true)
		roots.append(u)
		return u
	}

	private let account = "0x1111111111111111111111111111111111111111:default"
	private let peer = "0x2222222222222222222222222222222222222222"
	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait)

	/// T-32 table (21.3).
	func testMediaParserTable() {
		XCTAssertNil(BeamioChatMediaBody.parse("hello"), "plain text is text")
		XCTAssertNil(BeamioChatMediaBody.parse("你好\n第二行"), "multi-line text is text")
		let img = BeamioChatMediaBody.parse(#"{"v":1,"kind":"image","text":"","media":{"mime":"image/jpeg","size":1,"blob":"b1","width":4,"height":3}}"#)
		XCTAssertEqual(img?.kind, .image)
		XCTAssertEqual(img?.media?.widthPx, 4)
		XCTAssertEqual(img?.media?.heightPx, 3)
		let vid = BeamioChatMediaBody.parse(#"{"v":1,"kind":"video","text":"x","media":{"mime":"video/mp4","size":1,"blob":"b2"}}"#)
		XCTAssertEqual(vid?.kind, .video)
		XCTAssertNil(vid?.media?.widthPx, "no dimensions: the estimate uses 16:9")
		let broken = BeamioChatMediaBody.parse(#"{"v":2,"kind":"image"}"#)
		XCTAssertEqual(broken?.kind, .unknown, "a media body that does not match is never text")
		XCTAssertEqual(broken?.media?.state, "failed")
		let file = BeamioChatMediaBody.parse(#"{"v":1,"kind":"file","text":"","media":{"mime":"application/pdf","size":9,"name":"a.pdf","blob":"b3"}}"#)
		XCTAssertEqual(file?.kind, .file)
	}

	private func importRows(_ n: Int, seed: String) -> [BeamioChatImportRow] {
		(0..<n).map { i in
			BeamioChatImportRow(convKey: peer, dir: i % 2 == 0 ? "in" : "out", ts: 1_780_000_000_000 + Int64(i),
			                    sendId: i % 3 == 0 ? nil : "imp-\(seed)-\(i)", body: "IMPORT-\(seed)-\(i) body", pending: i == 1)
		}
	}

	/// M2 is idempotent; M3 digests agree across two independent libraries built from the same rows.
	func testImportIsIdempotentAndDigestMatches() throws {
		let rows = importRows(20, seed: "a")
		let first = BeamioConetChatLocalStore(rootDirectory: tempRoot())
		try first.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let r1 = try first.importBatch(accountKey: account, rows: rows)
		XCTAssertEqual(r1.imported, 20)
		let again = try first.importBatch(accountKey: account, rows: rows)
		XCTAssertEqual(again.imported, 0, "M2: a second import is a no-op")
		XCTAssertEqual(again.duplicates, 20)
		let v1 = try first.verifyImport(accountKey: account)
		XCTAssertEqual(v1.rows, 20)

		let second = BeamioConetChatLocalStore(rootDirectory: tempRoot())
		try second.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		_ = try second.importBatch(accountKey: account, rows: rows.reversed())
		let v2 = try second.verifyImport(accountKey: account)
		XCTAssertEqual(v2.digest, v1.digest, "M3: the digest does not depend on the import order")

		let page = first.openConversation(convKey: peer, viewport: viewport)
		XCTAssertFalse(page.items.isEmpty)
		XCTAssertTrue(page.items.contains { $0.body == "IMPORT-a-1 body" }, "imported bodies are readable")
	}

	func testImportRejectsWrongAccountOversizedAndBadRows() throws {
		let store = BeamioConetChatLocalStore(rootDirectory: tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		XCTAssertThrowsError(try store.importBatch(accountKey: "0x9999999999999999999999999999999999999999:default", rows: importRows(1, seed: "x"))) {
			XCTAssertEqual($0 as? BeamioChatLocalError, .accountMismatch)
		}
		XCTAssertThrowsError(try store.importBatch(accountKey: account, rows: importRows(201, seed: "y"))) {
			XCTAssertEqual($0 as? BeamioChatLocalError, .batchTooLarge)
		}
		var bad = importRows(1, seed: "z")
		bad[0].ts = nil
		XCTAssertThrowsError(try store.importBatch(accountKey: account, rows: bad)) {
			XCTAssertEqual($0 as? BeamioChatLocalError, .badRow, "a row without sender ts is refused")
		}
		XCTAssertThrowsError(try store.verifyImport(accountKey: "0x9999999999999999999999999999999999999999:default")) {
			XCTAssertEqual($0 as? BeamioChatLocalError, .accountMismatch)
		}
	}
}
