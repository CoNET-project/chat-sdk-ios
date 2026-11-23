import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Spec v1.1 acceptance tests that are specific to the sendKey, pending-sync and lock rules.
final class ChatLocalStoreV11Tests: XCTestCase {
	private var roots: [URL] = []

	override func tearDown() {
		for r in roots { try? FileManager.default.removeItem(at: r) }
		roots = []
		super.tearDown()
	}

	private func tempRoot() -> URL {
		let u = FileManager.default.temporaryDirectory.appendingPathComponent("chat-local-v11-\(UUID().uuidString)", isDirectory: true)
		roots.append(u)
		return u
	}

	private func makeStore(_ root: URL) -> BeamioConetChatLocalStore {
		let s = BeamioConetChatLocalStore(rootDirectory: root)
		s.mediaManifestParser = chatFixtureMediaParser
		return s
	}

	private let account = "0x1111111111111111111111111111111111111111:default"
	private let peerA = "0x2222222222222222222222222222222222222222"
	private let peerB = "0x3333333333333333333333333333333333333333"
	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait, fontScale: 1.0)

	/// Records with the same body, sent with two random legacy UUIDs (4.1 rule 2, 4.2 dedupe, Q-7).
	func testLegacyUUIDMirrorsDedupeToOneRowAndCountRefetch() throws {
		let master = Data(repeating: 0x44, count: 32)
		let idKey = BeamioChatLocalCrypto.idKey(localRoot: chatTestLocalRoot)
		let body = "same body mirrored twice"
		let ts: Int64 = 1_780_000_123_456
		var frags: [String: String] = [:]
		var index: [[String: Any]] = []
		var prev = "0x" + BeamioChatLocalCrypto.hex(BeamioConetChatHistoryStore.hkdf(master: master, info: "frag-genesis", length: 32))
		for (seq, sid) in [(0, "11111111-2222-4333-8444-555555555555"), (1, "66666666-7777-4888-9999-aaaaaaaaaaaa")] {
			let key = BeamioConetChatHistoryStore.hkdf(master: master, info: "frag|\(seq)|\(prev)", length: 32)
			let cipher = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: key, plaintext: Data(body.utf8))
			let cid = Keccak256.hexUtf8(cipher)
			frags[cid] = cipher
			index.append(["seq": seq, "cid": cid, "prevCid": prev, "ts": NSNumber(value: ts), "peer": peerA, "dir": "out", "sendId": sid])
			prev = cid
		}
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let report = store.syncIndex(records: index, historyMaster: master, fetchCipher: ChatSynthHistory.Fetcher(frags).fetch)
		XCTAssertEqual(report.legacyRefetch, 0, "r1: UUID sendIds are kept, nothing is derived or refetched")
		XCTAssertEqual(report.folded, 1, "r1 4.5: the second mirror folds into the earliest one")
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertEqual(page.items.count, 1, "T-22: the same message mirrored twice is one row")
		XCTAssertEqual(page.items.first?.body, body)
		// The earliest record (seq 0) survives with its own UUID as sendKey.
		let expected = BeamioChatLocalCrypto.stableId(idxKey: BeamioChatLocalCrypto.idxKey(localRoot: chatTestLocalRoot),
		                                              sendKey: "11111111-2222-4333-8444-555555555555")
		XCTAssertEqual(page.items.first?.stableId, expected, "stable_id comes from the surviving sendKey (UUID kept, r1 4.1)")
	}

	/// The same sendKey twice with different bodies: the first arrival is kept (4.4). Tail-first sync means the
	/// higher seq is the first arrival, so its body is the one stored. (Conflicts are counted only for fetched
	/// rows; a stored sendKey is skipped without a fetch, so its body is not compared, see receipt.)
	func testSameSendKeyKeepsTheFirstArrival() throws {
		let master = Data(repeating: 0x45, count: 32)
		var frags: [String: String] = [:]
		var index: [[String: Any]] = []
		var prev = "0x" + BeamioChatLocalCrypto.hex(BeamioConetChatHistoryStore.hkdf(master: master, info: "frag-genesis", length: 32))
		for (seq, body) in [(0, "first version"), (1, "second version")] {
			let key = BeamioConetChatHistoryStore.hkdf(master: master, info: "frag|\(seq)|\(prev)", length: 32)
			let cipher = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: key, plaintext: Data(body.utf8))
			let cid = Keccak256.hexUtf8(cipher)
			frags[cid] = cipher
			index.append(["seq": seq, "cid": cid, "prevCid": prev, "ts": NSNumber(value: 1_780_000_000_000 + Int64(seq)),
			              "peer": peerA, "dir": "in", "sendId": "dup-key-1"])
			prev = cid
		}
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let report = store.syncIndex(records: index, historyMaster: master, fetchCipher: ChatSynthHistory.Fetcher(frags).fetch)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		// One sendKey is one stable_id (I2), so one row. The first arrival (higher seq, processed first) is kept.
		XCTAssertEqual(page.items.count, 1)
		XCTAssertEqual(page.items.first?.body, "second version")
		XCTAssertEqual(report.tsMismatch, 1, "the later sortTs does not overwrite the stored one (5)")
	}

	/// Before the full sync completes, a window with no older rows is `pending`, not `end` (6.4, T-23).
	/// When older rows arrive, `olderAvailable` fires for that window.
	func testOlderStateIsPendingUntilSyncCompletes() throws {
		let h = ChatSynthHistory(seed: 77, messages: 60, convs: [peerB])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		// A local outgoing row, newer than anything synced, and no sync yet.
		try store.addPendingLocal(convKey: peerB, sendId: "pend-x", sortTs: 1_790_000_000_000, dir: "out", body: "later")
		let collector = ChatEventCollector(store)
		let before = store.openConversation(convKey: peerB, viewport: viewport)
		XCTAssertEqual(before.items.count, 1)
		XCTAssertEqual(before.olderState, .pending, "no older rows yet, but the sync is not complete")
		XCTAssertNotNil(before.olderCursor, "pending keeps a cursor so the UI can ask again")

		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		store.notifyQueue.sync {}
		XCTAssertTrue(collector.olderAvailable.contains(peerB), "olderAvailable for the waiting window")
		let after = store.openConversation(convKey: peerB, viewport: viewport)
		XCTAssertEqual(after.olderState, .more, "older rows now exist")
		let path = store.databasePath(for: account)
		let raw = try ChatLocalSQLite(path: path)
		XCTAssertEqual(try raw.scalarText("SELECT v FROM meta WHERE k = 'syncComplete'"), "1")
		raw.close()
	}

	/// Logout: the UI is told first (`locked`), then the library answers `locked` (6.5, T-26).
	func testLockTellsTheUIBeforeClearing() throws {
		let h = ChatSynthHistory(seed: 78, messages: 40, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let collector = ChatEventCollector(store)
		store.lock()
		store.notifyQueue.sync {}
		XCTAssertTrue(collector.locked, "locked event delivered")
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertEqual(page.source, .locked)
		XCTAssertTrue(page.items.isEmpty)
	}

	/// T-25: a run of tombstones longer than the raw budget (2000) gives an empty page with `scanExhausted`
	/// and `olderState: more`, never `end`, so the UI keeps asking.
	func testAllTombstonePageExhaustsBudgetAndStaysMore() throws {
		let master = Data(repeating: 0x46, count: 32)
		var index: [[String: Any]] = []
		var frags: [String: String] = [:]
		for seq in 0..<2100 {
			// Tombstones only: no fragment needed. Each has a deterministic sendKey and a unique cid.
			index.append(["seq": seq, "cid": "0x" + String(format: "%064x", seq + 1), "prevCid": "0x0",
			              "ts": NSNumber(value: 1_780_000_000_000 + Int64(seq)), "peer": peerA, "dir": "in",
			              "sendId": "gone-\(seq)", "deleted": true])
		}
		_ = frags.count
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let report = store.syncIndex(records: index, historyMaster: master, fetchCipher: { _ in nil })
		XCTAssertEqual(report.tombstones, 2100)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertTrue(page.items.isEmpty, "tombstones are never returned")
		XCTAssertTrue(page.scanExhausted, "T-25: the 2000-row budget ended the scan")
		XCTAssertEqual(page.olderState, .more, "T-25: never reported as the end")
		XCTAssertNotNil(page.olderCursor, "the cursor points at the last scanned raw row")
		let next = try store.loadOlder(convKey: peerA, cursor: page.olderCursor!, viewport: viewport)
		XCTAssertTrue(next.items.isEmpty)
		// The 100 remaining raw rows reach the oldest row and the sync is complete, so the end is known (6.4).
		XCTAssertEqual(next.olderState, .end, "after the last raw row, with sync complete, the end is known")
		XCTAssertNil(next.olderCursor)
	}

	/// T-13 extended: sendIds, conversation addresses and bodies are not in any library file.
	func testNoPlainIdentifiersInLibraryFiles() throws {
		let h = ChatSynthHistory(seed: 79, messages: 300, convs: [peerA, peerB])
		let root = tempRoot()
		let store = makeStore(root)
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		store.lock()
		let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
		let markers = ["FIXTURE-79", "sid-79-", peerA, peerB]
		for marker in markers {
			var hits = 0
			for f in files {
				hits += countOccurrences(of: Array(marker.utf8), in: [UInt8](try Data(contentsOf: f)))
			}
			XCTAssertEqual(hits, 0, "T-13: \(marker) found in a library file")
		}
	}

	private func countOccurrences(of needle: [UInt8], in hay: [UInt8]) -> Int {
		guard needle.count > 0, hay.count >= needle.count else { return 0 }
		var n = 0
		for i in 0...(hay.count - needle.count) where hay[i] == needle[0] {
			if Array(hay[i..<(i + needle.count)]) == needle { n += 1 }
		}
		return n
	}
}
