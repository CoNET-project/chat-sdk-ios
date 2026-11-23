import Foundation
import XCTest
@testable import ConetChatSDK

/// Large-history metrics (spec 14.1). Runs only when CHAT_LOCAL_METRICS=1, because the 50k-row
/// synthetic build takes minutes in a debug build. Environment: macOS host (not a device).
final class ChatLocalMetricsTests: XCTestCase {
	private func percentile(_ values: [Double], _ p: Double) -> Double {
		let s = values.sorted()
		guard !s.isEmpty else { return .nan }
		let rank = Int((p * Double(s.count)).rounded(.up)) - 1
		return s[max(0, min(s.count - 1, rank))]
	}

	func testLargeHistoryFirstScreenAndPagingMetrics() throws {
		guard ProcessInfo.processInfo.environment["CHAT_LOCAL_METRICS"] == "1" else {
			throw XCTSkip("set CHAT_LOCAL_METRICS=1 to run the metrics pass")
		}
		let heavy = "0x2222222222222222222222222222222222222222"
		var convs = Array(repeating: heavy, count: 5)
		for i in 0..<49 { convs.append(String(format: "0x%040x", 0x1000 + i)) }
		let build0 = Date()
		let h = ChatSynthHistory(seed: 20261111, messages: 50_000, convs: convs)
		let buildSec = Date().timeIntervalSince(build0)

		let root = FileManager.default.temporaryDirectory.appendingPathComponent("chat-local-metrics-\(UUID().uuidString)", isDirectory: true)
		defer { try? FileManager.default.removeItem(at: root) }
		let account = "0x1111111111111111111111111111111111111111"
		let store = BeamioConetChatLocalStore(rootDirectory: root)
		store.mediaManifestParser = chatFixtureMediaParser
		try store.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		let fetcher = ChatSynthHistory.Fetcher(h.fragments)
		let sync0 = Date()
		let report = store.syncIndex(records: h.index, indexHash: "0xmetrics", historyMaster: h.master, fetchCipher: fetcher.fetch)
		let syncSec = Date().timeIntervalSince(sync0)
		let heavyCount = h.truth[heavy]?.count ?? 0
		let fileBytes = (try? FileManager.default.attributesOfItem(atPath: store.databasePath(for: account.lowercased()))[.size] as? Int) ?? 0

		let vp = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait, fontScale: 1.0)
		// Warm: same store, many opens (includes decrypt of visible rows only).
		var warmMs: [Double] = []
		var firstCount = 0
		var firstSum = 0.0
		for _ in 0..<30 {
			let t = Date()
			let p = store.openConversation(convKey: heavy, viewport: vp)
			warmMs.append(Date().timeIntervalSince(t) * 1000)
			firstCount = p.items.count
			firstSum = p.items.reduce(0.0) { $0 + $1.layout.hPt }
		}
		// Cold: fresh store instance on the same file (new unlock), opens measured after unlock.
		var coldMs: [Double] = []
		store.lock()
		for _ in 0..<30 {
			let cold = BeamioConetChatLocalStore(rootDirectory: root)
			cold.mediaManifestParser = chatFixtureMediaParser
			try cold.unlock(accountKey: account, localRoot: chatTestLocalRoot)
			let t = Date()
			_ = cold.openConversation(convKey: heavy, viewport: vp)
			coldMs.append(Date().timeIntervalSince(t) * 1000)
			cold.lock()
		}
		// Paging: 30 consecutive loadOlder calls from the first screen.
		let pagingStore = BeamioConetChatLocalStore(rootDirectory: root)
		pagingStore.mediaManifestParser = chatFixtureMediaParser
		try pagingStore.unlock(accountKey: account, localRoot: chatTestLocalRoot)
		var page = pagingStore.openConversation(convKey: heavy, viewport: vp)
		var olderMs: [Double] = []
		var pagesTotal = 0
		var seen = Set<String>()
		var dup = 0
		for p in page.items { seen.insert(p.stableId) }
		while page.olderState == .more, let c = page.olderCursor, olderMs.count < 30 {
			let t = Date()
			page = try pagingStore.loadOlder(convKey: heavy, cursor: c, viewport: vp)
			olderMs.append(Date().timeIntervalSince(t) * 1000)
			pagesTotal += 1
			for p in page.items { if !seen.insert(p.stableId).inserted { dup += 1 } }
		}
		// Layout hit rate: report measured sizes for a first screen, reopen, count measured items.
		var hits = 0
		var total = 0
		for round in 0..<20 {
			let p = pagingStore.openConversation(convKey: heavy, viewport: vp)
			for (i, item) in p.items.enumerated() where !item.layout.measured {
				pagingStore.reportLayout(convKey: heavy, stableId: item.stableId, viewport: vp,
				                         wPt: item.layout.wPt, hPt: 40 + Double((i + round) % 9) * 10)
			}
			let again = pagingStore.openConversation(convKey: heavy, viewport: vp)
			for item in again.items { total += 1; if item.layout.measured { hits += 1 } }
		}
		let hitRate = total == 0 ? 0 : Double(hits) / Double(total)

		// Session list at this size (6.7, review item 6): one call, timed; the conversations of the 50k history.
		var listSamples: [Double] = []
		var listRows = 0
		for _ in 0 ..< 5 {
			let t0 = DispatchTime.now().uptimeNanoseconds
			let page = (try? pagingStore.listConversations(limit: 100, cursor: nil)) ?? BeamioChatConversationPage(rows: [], nextCursor: nil)
			listSamples.append(Double(DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000)
			listRows = page.rows.count
		}
		let listMsP50 = listSamples.sorted()[listSamples.count / 2]

		let result: [String: Any] = [
			"env": "macOS host, arm64, Xcode toolchain, Debug build, synthetic data, NOT device data",
			"listConversationsMsP50": listMsP50, "listConversationsRows": listRows,
			"seed": 20261111, "libraryMessages": h.messageCount, "heavyConvMessages": heavyCount,
			"sameMsRatio": Double(h.sameMsCount) / Double(h.messageCount),
			"mediaRatio": Double(h.mediaCount) / Double(h.messageCount),
			"emptySendIdRatio": Double(h.emptySendIdCount) / Double(h.messageCount),
			"buildSec": buildSec, "fullSyncSec": syncSec, "syncReport": "inserted=\(report.inserted) fetched=\(report.fetched) tombstones=\(report.tombstones) failed=\(report.failed)",
			"dbBytes": fileBytes,
			"firstScreenItems": firstCount, "firstScreenHSum": firstSum, "viewportHeight": vp.heightPt,
			"firstScreenWarmP50Ms": percentile(warmMs, 0.5), "firstScreenWarmP95Ms": percentile(warmMs, 0.95),
			"firstScreenColdP50Ms": percentile(coldMs, 0.5), "firstScreenColdP95Ms": percentile(coldMs, 0.95),
			"loadOlderP50Ms": percentile(olderMs, 0.5), "loadOlderP95Ms": percentile(olderMs, 0.95),
			"loadOlderCount": olderMs.count, "pagesRead": pagesTotal, "duplicatesAcrossPages": dup,
			"layoutHitRate": hitRate,
		]
		let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
		let out = ProcessInfo.processInfo.environment["CHAT_LOCAL_METRICS_OUT"] ?? FileManager.default.temporaryDirectory.appendingPathComponent("chat-local-metrics.json").path
		try data.write(to: URL(fileURLWithPath: out))
		print("METRIC_JSON_PATH \(out)")
		print(String(data: data, encoding: .utf8) ?? "")
		XCTAssertLessThanOrEqual(percentile(warmMs, 0.5), 30, "D6 threshold: first-screen SDK P50")
		XCTAssertLessThanOrEqual(percentile(warmMs, 0.95), 80, "D6 threshold: first-screen SDK P95")
		XCTAssertLessThanOrEqual(percentile(olderMs, 0.95), 60, "D6 threshold: loadOlder P95")
		XCTAssertGreaterThanOrEqual(hitRate, 0.95, "D6 threshold: layout hit rate")
		XCTAssertEqual(dup, 0)
	}
}
