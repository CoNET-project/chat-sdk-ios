import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Acceptance tests for the local chat library (interface spec v1.0, section 14.2).
/// Synthetic data only: no real chats, keys, or media.
final class ChatLocalStoreTests: XCTestCase {
	private var roots: [URL] = []

	override func tearDown() {
		for r in roots { try? FileManager.default.removeItem(at: r) }
		roots = []
		super.tearDown()
	}

	private func tempRoot() -> URL {
		let u = FileManager.default.temporaryDirectory.appendingPathComponent("chat-local-\(UUID().uuidString)", isDirectory: true)
		roots.append(u)
		return u
	}

	private func makeStore(_ root: URL) -> BeamioConetChatLocalStore {
		let s = BeamioConetChatLocalStore(rootDirectory: root)
		s.mediaManifestParser = chatFixtureMediaParser
		return s
	}

	private let account = "0x1111111111111111111111111111111111111111"
	private let peerA = "0x2222222222222222222222222222222222222222"
	private let peerB = "0x3333333333333333333333333333333333333333"
	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait, fontScale: 1.0)

	private func smallHistory(seed: UInt32 = 7, messages: Int = 400) -> ChatSynthHistory {
		ChatSynthHistory(seed: seed, messages: messages, convs: [peerA, peerB, "0x4444444444444444444444444444444444444444"])
	}

	// MARK: - Stable IDs and ordering

	func testSendKeyAndStableIdRulesV11() {
		let master = Data(repeating: 0x5A, count: 32)
		let idKey = BeamioChatLocalCrypto.idKey(localRoot: chatTestLocalRoot)
		let idxKey = BeamioChatLocalCrypto.idxKey(localRoot: chatTestLocalRoot)
		let k1 = BeamioChatLocalCrypto.sendKeyDerived(idKey: idKey, peer: peerA, dir: "in", ts: 1000, body: "hi")
		let k2 = BeamioChatLocalCrypto.sendKeyDerived(idKey: idKey, peer: peerA, dir: "in", ts: 1000, body: "hi")
		XCTAssertEqual(k1, k2, "sendKey must be deterministic (4.1)")
		XCTAssertTrue(k1.hasPrefix("x"))
		let sid = BeamioChatLocalCrypto.stableId(idxKey: idxKey, sendKey: k1)
		XCTAssertEqual(sid.count, 43, "stable_id is 43 ASCII characters (4.3)")
		XCTAssertTrue(sid.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
		let other = BeamioChatLocalCrypto.stableId(idxKey: BeamioChatLocalCrypto.idxKey(localRoot: Data(repeating: 0x01, count: 32)), sendKey: k1)
		XCTAssertNotEqual(sid, other, "a different master must give a different stable_id")
		XCTAssertFalse(k1.contains("hi"))
		XCTAssertTrue(BeamioChatLocalCrypto.isRandomUUID("123e4567-e89b-12d3-a456-426614174000"))
		XCTAssertFalse(BeamioChatLocalCrypto.isRandomUUID("1700000000000-abcdef"), "PWA ms-random sendId is not a UUID")
	}

	func testSameMillisecondOrdersByStableIdBytes() {
		let a = BeamioChatLocalKey(sortTs: 5, stableId: "a-sid")
		let b = BeamioChatLocalKey(sortTs: 5, stableId: "b-sid")
		let c = BeamioChatLocalKey(sortTs: 4, stableId: "z-sid")
		XCTAssertTrue(c < a)
		XCTAssertTrue(a < b)
		XCTAssertFalse(b < a)
	}

	// MARK: - Sync, first screen, paging

	func testPagingConcatenatesToTruthWithoutGapsOrDuplicates() throws {
		let h = smallHistory()
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let fetcher = ChatSynthHistory.Fetcher(h.fragments)
		let report = store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: fetcher.fetch)
		XCTAssertFalse(report.locked)
		XCTAssertEqual(report.failed, 0)
		XCTAssertGreaterThan(report.inserted, 0)

		for (conv, truth) in h.truth {
			var pages: [BeamioChatPage] = []
			var page = store.openConversation(convKey: conv, viewport: viewport)
			pages.append(page)
			while page.olderState == .more, let cursor = page.olderCursor {
				page = try store.loadOlder(convKey: conv, cursor: cursor, viewport: viewport)
				pages.append(page)
				XCTAssertLessThan(pages.count, 1000, "paging did not terminate")
			}
			let collected = pages.reversed().flatMap { $0.items }
			XCTAssertEqual(collected.map(\.stableId), truth.map(\.stableId), "conv \(conv): pages must equal truth, no gaps or duplicates")
			XCTAssertEqual(Set(collected.map(\.stableId)).count, collected.count)
			for (item, expected) in zip(collected, truth) {
				XCTAssertEqual(item.sortTs, expected.sortTs)
				XCTAssertEqual(item.kind, expected.kind)
				XCTAssertEqual(item.revision, expected.revision)
				if expected.kind == .text { XCTAssertEqual(item.body, expected.body) }
				if let m = expected.media { XCTAssertEqual(item.media?.mime, m.mime) }
			}
		}
	}

	func testFirstScreenSpansOneViewportPerSpec62() throws {
		let h = ChatSynthHistory(seed: 11, messages: 3000, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertEqual(page.source, .local)
		XCTAssertFalse(page.short)
		XCTAssertFalse(page.capped)
		XCTAssertEqual(page.olderState, .more)
		XCTAssertNotNil(page.olderCursor)
		let sum = page.items.reduce(0.0) { $0 + $1.layout.hPt }
		// Items are ascending, so the row that crossed the boundary is the oldest visible one (oracle: visible[last]).
		let last = page.items.first?.layout.hPt ?? 0
		// spec 6.2: heightPt <= sum <= heightPt + last
		XCTAssertGreaterThanOrEqual(sum, viewport.heightPt, "first screen must cover the viewport")
		XCTAssertLessThanOrEqual(sum, viewport.heightPt + last + 0.05, "first screen must not run past the last row")
		XCTAssertLessThan(sum - last, viewport.heightPt, "the oldest visible row is the one that crossed the boundary")
	}

	func testShortPageWhenLocalDataIsLessThanOneScreen() throws {
		let h = ChatSynthHistory(seed: 12, messages: 3, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		let expected = h.truth[peerA]?.count ?? 0
		XCTAssertEqual(page.items.count, expected, "all local rows are returned when they do not fill a screen")
		XCTAssertTrue(page.short, "spec 6.2: short=true is not an error")
		XCTAssertEqual(page.olderState, .end)
		XCTAssertNil(page.olderCursor)
	}

	func testCapStopsAnAbnormalViewportAndSetsCapped() throws {
		let h = ChatSynthHistory(seed: 13, messages: 400, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let huge = BeamioChatViewport(widthPt: 390, heightPt: 1_000_000, orientation: .portrait, fontScale: 1.0)
		let page = store.openConversation(convKey: peerA, viewport: huge)
		XCTAssertTrue(page.capped, "safety cap must flag capped")
		XCTAssertLessThanOrEqual(page.items.count, BeamioConetChatLocalStore.pageCap)
		XCTAssertEqual(page.olderState, .more)
	}

	func testCursorIsBoundToItsConversation() throws {
		let h = ChatSynthHistory(seed: 14, messages: 600, convs: [peerA, peerB])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let pageA = store.openConversation(convKey: peerA, viewport: viewport)
		guard let cursor = pageA.olderCursor else { return XCTFail("fixture must have older rows") }
		XCTAssertThrowsError(try store.loadOlder(convKey: peerB, cursor: cursor, viewport: viewport)) { error in
			XCTAssertEqual(error as? BeamioChatLocalError, .cursorInvalid)
		}
		XCTAssertNoThrow(try store.loadOlder(convKey: peerA, cursor: cursor, viewport: viewport))
	}

	func testSameMillisecondMessagesAreOrderedAcrossPages() throws {
		let h = ChatSynthHistory(seed: 21, messages: 1500, convs: [peerA])
		XCTAssertGreaterThan(Double(h.sameMsCount) / Double(h.messageCount), 0.05, "fixture must have at least 5% same-millisecond messages")
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		var all: [BeamioChatItem] = []
		var page = store.openConversation(convKey: peerA, viewport: viewport)
		all.insert(contentsOf: page.items, at: 0)
		while page.olderState == .more, let c = page.olderCursor {
			page = try store.loadOlder(convKey: peerA, cursor: c, viewport: viewport)
			all.insert(contentsOf: page.items, at: 0)
		}
		for (x, y) in zip(all, all.dropFirst()) {
			XCTAssertTrue(x.sortTs < y.sortTs || (x.sortTs == y.sortTs && x.stableId.utf8.lexicographicallyPrecedes(y.stableId.utf8)))
		}
	}

	func testOfflineFirstScreenAndNoNetworkOnReadPath() throws {
		let h = smallHistory()
		let root = tempRoot()
		let fetcher = ChatSynthHistory.Fetcher(h.fragments)
		do {
			let store = makeStore(root)
			try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
			store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: fetcher.fetch)
			store.lock()
		}
		// Cold start, offline: no fetcher is wired, so any network call would be visible here.
		fetcher.reset()
		let cold = makeStore(root)
		try cold.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let page = cold.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertFalse(page.items.isEmpty, "offline first screen must come from the local library")
		if let c = page.olderCursor { _ = try cold.loadOlder(convKey: peerA, cursor: c, viewport: viewport) }
		XCTAssertEqual(fetcher.calls, 0, "T-16: read path made network calls")
	}

	func testFirstScreenDoesNotWaitForBlockedSync() throws {
		let h = smallHistory(messages: 300)
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		// Second sync with new records, whose fetch blocks for 2 s. Reads must not wait for it.
		let extra = ChatSynthHistory(seed: 99, messages: 12, convs: [peerA], master: h.master)
		let slow = ChatSynthHistory.Fetcher(extra.fragments)
		slow.delay = 2.0
		let done = expectation(description: "sync finished")
		DispatchQueue.global().async {
			store.syncIndex(records: extra.index, historyMaster: extra.master, fetchCipher: slow.fetch)
			done.fulfill()
		}
		Thread.sleep(forTimeInterval: 0.2)
		let start = Date()
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		let elapsed = Date().timeIntervalSince(start)
		XCTAssertFalse(page.items.isEmpty)
		XCTAssertLessThan(elapsed, 0.05, "T-15: first screen waited for sync (\(elapsed) s)")
		wait(for: [done], timeout: 30)
	}

	func testResyncFetchesNothingAlreadyStored() throws {
		let h = smallHistory()
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let first = ChatSynthHistory.Fetcher(h.fragments)
		let r1 = store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: first.fetch)
		XCTAssertGreaterThan(first.calls, 0)
		let second = ChatSynthHistory.Fetcher(h.fragments)
		let r2 = store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: second.fetch)
		XCTAssertEqual(second.calls, 0, "9.2: already stored bodies must not be downloaded again")
		XCTAssertEqual(r2.fetched, 0)
		XCTAssertEqual(r2.failed, 0)
		XCTAssertGreaterThan(r1.inserted, 0)
	}

	func testRelinearizedCidUpdatesWithoutRefetch() throws {
		let h = smallHistory()
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		// Simulate a PWA relinearization: same messages, new cid (sendId rows only, so bodies are known).
		var moved = h.index
		var changed = 0
		for i in moved.indices where moved[i]["sendId"] != nil && moved[i]["deleted"] == nil {
			moved[i]["cid"] = "0xRELIN\(i)"
			changed += 1
		}
		let fetcher = ChatSynthHistory.Fetcher([:])
		let report = store.syncIndex(records: moved, historyMaster: h.master, fetchCipher: fetcher.fetch)
		XCTAssertEqual(fetcher.calls, 0, "T-17: relinearized records must not be downloaded")
		XCTAssertGreaterThan(report.cidUpdated, 0)
		XCTAssertLessThanOrEqual(report.cidUpdated, changed)
	}

	// MARK: - Revisions, tombstones, inserts

	func testRevisionKeepsOrderAndInvalidatesLayout() throws {
		let store = makeStore(tempRoot())
		let master = Data(repeating: 0x33, count: 32)
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let h = ChatSynthHistory(seed: 3, messages: 40, convs: [peerA], master: master)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let before = store.openConversation(convKey: peerA, viewport: viewport)
		// Pick a row on the first screen, so the update reaches the open window.
		guard let shown = before.items.first(where: { $0.kind == .text && $0.revision == 0 }),
		      let target = (h.truth[peerA] ?? []).first(where: { $0.stableId == shown.stableId }) else {
			return XCTFail("fixture must have a text row with revision 0")
		}
		XCTAssertTrue(store.reportLayout(convKey: peerA, stableId: target.stableId, viewport: viewport, wPt: 300, hPt: 91))

		// Add a revision: same sendId, higher revision, new body, new fragment.
		let edited = "EDITED body after revision"
		// Fragment key for this record's (seq, prevCid), as the chain writer would use.
		let fragKey = BeamioConetChatHistoryStore.hkdf(master: master, info: "frag|9999|0xprev", length: 32)
		let cipher = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: fragKey, plaintext: Data(edited.utf8))
		let cid = Keccak256.hexUtf8(cipher)
		let rec2: [String: Any] = ["seq": 9999, "cid": cid, "prevCid": "0xprev", "ts": NSNumber(value: target.sortTs),
		                           "peer": peerA, "dir": target.dir, "sendId": target.sendKey, "revision": 1]
		var frags = h.fragments
		frags[cid] = cipher
		let events = ChatEventCollector(store)
		let report = store.syncIndex(records: [rec2], historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(frags).fetch)
		XCTAssertEqual(report.updated, 1)
		store.notifyQueue.sync {}
		XCTAssertTrue(events.updated.contains(target.stableId), "updated event for an open row")

		let after = store.openConversation(convKey: peerA, viewport: viewport)
		guard let row = after.items.first(where: { $0.stableId == target.stableId }) else { return XCTFail("row disappeared") }
		XCTAssertEqual(row.sortTs, target.sortTs, "K must not change on revision (I1)")
		XCTAssertEqual(row.body, edited)
		XCTAssertEqual(row.revision, 1)
		XCTAssertFalse(row.layout.measured, "layout must be invalid after a body revision (8.5)")
	}

	func testTombstoneIsSkippedAndPagingContinues() throws {
		let h = ChatSynthHistory(seed: 5, messages: 60, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let truth = h.truth[peerA] ?? []
		var all: [BeamioChatItem] = []
		var page = store.openConversation(convKey: peerA, viewport: viewport)
		all.insert(contentsOf: page.items, at: 0)
		while page.olderState == .more, let c = page.olderCursor {
			page = try store.loadOlder(convKey: peerA, cursor: c, viewport: viewport)
			all.insert(contentsOf: page.items, at: 0)
		}
		XCTAssertEqual(all.map(\.stableId), truth.map(\.stableId), "tombstones must not appear and must not stop paging")
	}

	func testHistoryInsertEmitsMiddleAndTailEvents() throws {
		let h = ChatSynthHistory(seed: 13, messages: 800, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertEqual(page.olderState, .more)
		let newest = page.items.last!
		let events = ChatEventCollector(store)

		// Middle: a message whose sortTs sits inside the loaded window.
		let middleTs = newest.sortTs - 1
		let midRec: [String: Any] = ["seq": 100_000, "cid": "0xMID", "prevCid": "0x0", "ts": NSNumber(value: middleTs),
		                             "peer": peerA, "dir": "in", "sendId": "mid-1"]
		let midKey = BeamioConetChatHistoryStore.hkdf(master: h.master, info: "frag|100000|0x0", length: 32)
		let midCipher = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: midKey, plaintext: Data("middle".utf8))
		var rec = midRec
		rec["cid"] = Keccak256.hexUtf8(midCipher)
		var frags = h.fragments
		frags[rec["cid"] as! String] = midCipher
		store.syncIndex(records: [rec], historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(frags).fetch)

		// Tail: a message newer than everything loaded.
		let tailKey = BeamioConetChatHistoryStore.hkdf(master: h.master, info: "frag|100001|0x1", length: 32)
		let tailCipher = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: tailKey, plaintext: Data("tail".utf8))
		let tailRec: [String: Any] = ["seq": 100_001, "cid": Keccak256.hexUtf8(tailCipher), "prevCid": "0x1",
		                              "ts": NSNumber(value: newest.sortTs + 10), "peer": peerA, "dir": "out", "sendId": "tail-1"]
		frags[Keccak256.hexUtf8(tailCipher)] = tailCipher
		store.syncIndex(records: [tailRec], historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(frags).fetch)
		store.notifyQueue.sync {}

		let idxK = BeamioChatLocalCrypto.idxKey(localRoot: chatTestLocalRoot)
		let midStable = BeamioChatLocalCrypto.stableId(idxKey: idxK, sendKey: "mid-1")
		let tailStable = BeamioChatLocalCrypto.stableId(idxKey: idxK, sendKey: "tail-1")
		XCTAssertTrue(events.inserted.contains { $0.0 == "middle" && $0.1.contains(midStable) }, "T-11: middle insert event")
		XCTAssertTrue(events.inserted.contains { $0.0 == "tail" && $0.1.contains(tailStable) }, "tail insert event")

		// Paging from the loaded window must not repeat the middle row.
		var seen: [String] = []
		var p = store.openConversation(convKey: peerA, viewport: viewport)
		seen.append(contentsOf: p.items.map(\.stableId))
		while p.olderState == .more, let c = p.olderCursor {
			p = try store.loadOlder(convKey: peerA, cursor: c, viewport: viewport)
			seen.append(contentsOf: p.items.map(\.stableId))
		}
		XCTAssertEqual(seen.filter { $0 == midStable }.count, 1, "no duplicate after middle insert")
	}

	// MARK: - Layout sizes

	func testLayoutStoredMeasuredAndKeyedByViewport() throws {
		let h = ChatSynthHistory(seed: 17, messages: 200, convs: [peerA])
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		let target = page.items.last!
		XCTAssertFalse(target.layout.measured)
		XCTAssertTrue(store.reportLayout(convKey: peerA, stableId: target.stableId, viewport: viewport, wPt: 390, hPt: 240))
		XCTAssertFalse(store.reportLayout(convKey: peerA, stableId: target.stableId, viewport: viewport, wPt: 391, hPt: 241),
		               "differences of 2 pt or less are not written")

		let again = store.openConversation(convKey: peerA, viewport: viewport)
		let hit = again.items.first { $0.stableId == target.stableId }
		XCTAssertEqual(hit?.layout.measured, true)
		XCTAssertEqual(hit?.layout.hPt, 240)

		// Rotation: another bucket, so the old row stays and this one is estimated.
		let landscape = BeamioChatViewport(widthPt: 844, heightPt: 390, orientation: .landscape, fontScale: 1.0)
		let rotated = store.openConversation(convKey: peerA, viewport: landscape)
		let rot = rotated.items.first { $0.stableId == target.stableId }
		XCTAssertEqual(rot?.layout.measured, false, "T-5: new key must not reuse the portrait size")
		let back = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertEqual(back.items.first { $0.stableId == target.stableId }?.layout.measured, true, "T-5: old key kept")
	}

	// MARK: - Accounts, lock, clear, delete, plaintext

	func testAccountIsolation() throws {
		let root = tempRoot()
		let hA = ChatSynthHistory(seed: 41, messages: 120, convs: [peerA], master: Data(repeating: 0x0A, count: 32))
		let hB = ChatSynthHistory(seed: 42, messages: 120, convs: [peerA], master: Data(repeating: 0x0B, count: 32))
		let a = makeStore(root)
		try a.unlock(accountKey: "0xAAAA", localRoot: chatTestLocalRoot)
		a.syncIndex(records: hA.index, historyMaster: hA.master, fetchCipher: ChatSynthHistory.Fetcher(hA.fragments).fetch)
		let b = makeStore(root)
		try b.unlock(accountKey: "0xBBBB", localRoot: chatTestLocalRoot)
		b.syncIndex(records: hB.index, historyMaster: hB.master, fetchCipher: ChatSynthHistory.Fetcher(hB.fragments).fetch)

		let aPage = a.openConversation(convKey: peerA, viewport: viewport)
		let bPage = b.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertTrue(Set(aPage.items.map(\.stableId)).isDisjoint(with: Set(bPage.items.map(\.stableId))), "T-8: no cross-account rows")
		try a.clearLocalCache()
		XCTAssertTrue(a.openConversation(convKey: peerA, viewport: viewport).items.isEmpty)
		XCTAssertFalse(b.openConversation(convKey: peerA, viewport: viewport).items.isEmpty, "T-8: clearing A must not touch B")
	}

	func testLockReturnsLockedAndDropsKeys() throws {
		let h = smallHistory()
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		store.lock()
		XCTAssertFalse(store.isUnlocked)
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		XCTAssertEqual(page.source, .locked)
		XCTAssertTrue(page.items.isEmpty)
	}

	func testClearProtectsPendingRows() throws {
		let h = smallHistory()
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		try store.addPendingLocal(convKey: peerA, sendId: "pending-1", sortTs: 1_790_000_000_000, dir: "out", body: "not yet sent")
		let kept = try store.clearLocalCache(convKey: peerA).pendingKept
		XCTAssertEqual(kept, 1, "T-12: pending row kept and counted")
		let page = store.openConversation(convKey: peerA, viewport: viewport)
		let pendingStable = BeamioChatLocalCrypto.stableId(idxKey: BeamioChatLocalCrypto.idxKey(localRoot: chatTestLocalRoot), sendKey: "pending-1")
		XCTAssertTrue(page.items.contains { $0.stableId == pendingStable && $0.body == "not yet sent" })
	}

	func testDeleteBlockedByPendingUnlessForced() throws {
		let h = smallHistory()
		let root = tempRoot()
		let store = makeStore(root)
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		try store.addPendingLocal(convKey: peerA, sendId: "pending-2", sortTs: 1, dir: "out", body: "x")
		store.lock()
		XCTAssertThrowsError(try store.deleteLocalData(accountKey: account)) { error in
			XCTAssertEqual(error as? BeamioChatLocalError, .pendingPresent(1))
		}
		try store.deleteLocalData(accountKey: account, force: true)
		let fresh = makeStore(root)
		try fresh.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		XCTAssertTrue(fresh.openConversation(convKey: peerA, viewport: viewport).items.isEmpty)
	}

	func testKcvMismatchNeverRebuildsOrClears() throws {
		// 7.3 and T-38: a key that does not match is refused. Nothing is written, cleared or rebuilt.
		let h = smallHistory()
		let root = tempRoot()
		let store = makeStore(root)
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		let before = store.openConversation(convKey: peerA, viewport: viewport).items.count
		store.lock()

		let other = makeStore(root)
		XCTAssertThrowsError(try other.unlock(accountKey: account, localRoot: Data(repeating: 0x78, count: 32))) { error in
			XCTAssertEqual(error as? BeamioChatLocalError, .kcvMismatch)
		}
		XCTAssertFalse(other.isUnlocked)

		let again = makeStore(root)
		try again.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		XCTAssertEqual(again.openConversation(convKey: peerA, viewport: viewport).items.count, before, "the file is untouched")
	}

	func testNewerSchemaIsRejected() throws {
		let h = smallHistory()
		let root = tempRoot()
		let store = makeStore(root)
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.lock()
		let path = store.databasePath(for: account.lowercased())
		let raw = try ChatLocalSQLite(path: path)
		try raw.run("UPDATE meta SET v = '2' WHERE k = 'schemaVersion'")
		raw.close()
		let newer = makeStore(root)
		XCTAssertThrowsError(try newer.unlock(accountKey: account, localRoot: chatTestLocalRoot)) { error in
			XCTAssertEqual(error as? BeamioChatLocalError, .schemaNewer, "T-14")
		}
		XCTAssertFalse(newer.isUnlocked)
	}

	func testPlaintextIsNotInDatabaseFiles() throws {
		let h = ChatSynthHistory(seed: 61, messages: 300, convs: [peerA])
		let root = tempRoot()
		let store = makeStore(root)
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		store.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		try store.addPendingLocal(convKey: peerA, sendId: "p-plain", sortTs: 3, dir: "out", body: "FIXTURE-61-PENDING")
		store.lock()
		let marker = Array("FIXTURE-61".utf8)
		var hits = 0
		let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
		for f in files {
			let data = try Data(contentsOf: f)
			hits += countOccurrences(of: marker, in: [UInt8](data))
		}
		XCTAssertEqual(hits, 0, "T-13: plaintext marker found on disk")
		XCTAssertGreaterThan(files.count, 0)
	}

	func testSyncRecordsMigrationStateAndIndexHash() throws {
		let h = smallHistory()
		let store = makeStore(tempRoot())
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let report = store.syncIndex(records: h.index, indexHash: "0xhead", historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		XCTAssertFalse(report.locked)
		let path = store.databasePath(for: account.lowercased())
		let raw = try ChatLocalSQLite(path: path)
		XCTAssertEqual(try raw.scalarText("SELECT v FROM meta WHERE k = 'migrationState'"), "complete")
		XCTAssertEqual(try raw.scalarText("SELECT v FROM meta WHERE k = 'headIndexHash'"), "0xhead")
		raw.close()
	}

	// MARK: - Helpers

	private func countOccurrences(of needle: [UInt8], in hay: [UInt8]) -> Int {
		guard needle.count > 0, hay.count >= needle.count else { return 0 }
		var n = 0
		for i in 0...(hay.count - needle.count) where hay[i] == needle[0] {
			if Array(hay[i..<(i + needle.count)]) == needle { n += 1 }
		}
		return n
	}
}

/// Collects events. Each callback runs on the store's notify lane.
final class ChatEventCollector {
	private let lock = NSLock()
	private(set) var inserted: [(String, [String])] = []
	private(set) var updated: [String] = []
	private(set) var deleted: [String] = []
	private(set) var olderAvailable: [String] = []
	private(set) var locked = false
	private var token: UUID?
	private weak var store: BeamioConetChatLocalStore?

	init(_ store: BeamioConetChatLocalStore) {
		self.store = store
		token = store.subscribe { [weak self] event in
			guard let self else { return }
			self.lock.lock()
			switch event {
			case .inserted(_, let items, let position):
				self.inserted.append((position, items.map(\.stableId)))
			case .updated(_, let sid, _):
				self.updated.append(sid)
			case .deleted(_, let sid):
				self.deleted.append(sid)
			case .olderAvailable(let conv):
				self.olderAvailable.append(conv)
			case .locked:
				self.locked = true
			default:
				break
			}
			self.lock.unlock()
		}
	}
}
