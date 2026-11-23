import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Replays the shared fixture (interface/fixtures/out-10k, spec v1.1 section 15) through the iOS store and
/// compares it with `expected/scenarios.json` and the full truth. Runs only when FIXTURE_ROOT points at the
/// fixture directory (for example.../interface/fixtures/out-10k). Synthetic data only.
final class ChatLocalFixtureReplayTests: XCTestCase {
	private struct Root {
		let dir: URL
		let account = "A"
		var acctDir: URL { dir.appendingPathComponent(account, isDirectory: true) }
	}

	private func fixtureRoot() throws -> Root {
		guard let p = ProcessInfo.processInfo.environment["FIXTURE_ROOT"], !p.isEmpty else {
			throw XCTSkip("set FIXTURE_ROOT to the out-10k fixture directory")
		}
		return Root(dir: URL(fileURLWithPath: p, isDirectory: true))
	}

	private func json(_ url: URL) throws -> [String: Any] {
		try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any] ?? [:]
	}

	/// Cursor value from the expected file: base64url(JSON{...}) → (t, i, c).
	private func decodeExpectedCursor(_ c: String) -> (t: Int64, i: String, c: String)? {
		var b64 = c.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		while b64.count % 4 != 0 { b64 += "=" }
		guard let d = Data(base64Encoded: b64), let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
		      let t = (o["t"] as? NSNumber)?.int64Value, let i = o["i"] as? String, let cc = o["c"] as? String
		else { return nil }
		return (t, i, cc)
	}

	private func loadStore(_ root: Root) throws -> (BeamioConetChatLocalStore, master: Data, convs: Set<String>) {
		let manifest = try json(root.dir.appendingPathComponent("manifest.json"))
		let seed = manifest["seed"] as? String ?? "20261111"
		let master = Data(SHA256.hash(data: Data("fixture-master|\(seed)|\(root.account)".utf8)))
		let pointer = try json(root.acctDir.appendingPathComponent("pointer.json"))
		guard let indexHash = pointer["indexHash"] as? String else { throw XCTSkip("no indexHash") }
		let ipfs = root.acctDir.appendingPathComponent("ipfs", isDirectory: true)
		let indexB64 = try String(contentsOf: ipfs.appendingPathComponent(indexHash), encoding: .utf8)
		let indexJSON = try BeamioConetChatHistoryStore.aesGcmDecrypt(
			key: BeamioConetChatHistoryStore.hkdf(master: master, info: "index-enc", length: 32), b64: indexB64)
		let index = try JSONSerialization.jsonObject(with: Data(indexJSON.utf8)) as? [String: Any] ?? [:]
		let records = index["records"] as? [[String: Any]] ?? []

		// The fixture stores media blobs under A/blobs; a manifest with blobMissing has no file there (T-6).
		let blobDir = root.acctDir.appendingPathComponent("blobs", isDirectory: true)
		let store = BeamioConetChatLocalStore(rootDirectory: FileManager.default.temporaryDirectory
			.appendingPathComponent("chat-local-replay-\(UUID().uuidString)", isDirectory: true))
		store.mediaManifestParser = { BeamioChatMediaBody.parse($0) }
		store.blobAvailable = { name in FileManager.default.fileExists(atPath: blobDir.appendingPathComponent(name).path) }
		// Fixture local root (fixtures/gen-chat-fixture.mjs: sha256("fixture-local-root|seed|account")).
		let localRoot = Data(SHA256.hash(data: Data("fixture-local-root|\(seed)|\(root.account)".utf8)))
		try store.unlock(accountKey: "\(root.account):default", localRoot: localRoot)
		let report = store.syncIndex(records: records, indexHash: indexHash, historyMaster: master, fetchCipher: { cid in
			try? String(contentsOf: ipfs.appendingPathComponent(cid), encoding: .utf8)
		})
		XCTAssertFalse(report.locked)
		XCTAssertEqual(report.failed, 0, "every fragment must hash to its cid and decrypt")
		XCTAssertEqual(report.records, records.count)
		let convs = Set(records.compactMap { $0["peer"] as? String })
		return (store, master, convs)
	}

	private func viewport(_ view: [String: Any]) -> BeamioChatViewport {
		let w = (view["widthPt"] as? NSNumber)?.doubleValue ?? 390
		let h = (view["heightPt"] as? NSNumber)?.doubleValue ?? 780
		return BeamioChatViewport(widthPt: w, heightPt: h, orientation: h >= w ? .portrait : .landscape,
		                          fontScale: (view["fontScale"] as? NSNumber)?.doubleValue ?? 1.0,
		                          layoutVersion: (view["layoutVersion"] as? NSNumber)?.intValue ?? 1)
	}

	private func r1(_ x: Double) -> Double { (x * 10).rounded() / 10 }

	/// The scenario steps (open, measure, loadOlder) against the expected results, then a full walk compared
	/// with the truth (T-2, N6: the visible subset).
	func testScenariosMatchExpectedAndTruth() throws {
		let root = try fixtureRoot()
		let (store, _, _) = try loadStore(root)
		let scen = try json(root.dir.appendingPathComponent("expected/scenarios.json"))
		let conv = ((scen["fixture"] as? [String: Any])?["conv"] as? String ?? "").lowercased()
		XCTAssertFalse(conv.isEmpty)
		let steps = scen["steps"] as? [[String: Any]] ?? []
		XCTAssertFalse(steps.isEmpty)

		var cursor: String?
		var checked = 0
		for step in steps {
			let op = step["op"] as? String ?? ""
			let vp = viewport(step["view"] as? [String: Any] ?? [:])
			switch op {
			case "open":
				let expect = step["expect"] as? [String: Any] ?? [:]
				let page = store.openConversation(convKey: conv, viewport: vp)
				assertPage(page, expect: expect, conv: conv, step: "open")
				cursor = page.olderCursor
				checked += 1
			case "measure":
				let ids = step["ids"] as? [String] ?? []
				let heights = (step["heights"] as? [NSNumber] ?? []).map { $0.doubleValue }
				XCTAssertEqual(ids.count, heights.count)
				for (sid, h) in zip(ids, heights) {
					store.reportLayout(convKey: conv, stableId: sid, viewport: vp, wPt: vp.widthPt, hPt: h)
				}
				checked += 1
			case "loadOlder":
				guard let c = cursor else { return XCTFail("loadOlder without a cursor") }
				let expect = step["expect"] as? [String: Any] ?? [:]
				let page = try store.loadOlder(convKey: conv, cursor: c, viewport: vp)
				assertPage(page, expect: expect, conv: conv, step: "loadOlder")
				cursor = page.olderCursor
				checked += 1
			default:
				XCTFail("unknown step \(op)")
			}
		}
		XCTAssertEqual(checked, steps.count)
		try assertFullWalkMatchesTruth(root: root, store: store, conv: conv)
	}

	private func assertPage(_ page: BeamioChatPage, expect: [String: Any], conv: String, step: String) {
		let ids = page.items.map(\.stableId)
		XCTAssertEqual(ids, expect["ids"] as? [String] ?? [], "\(step): ids (K order, visible only)")
		let sum = page.items.reduce(0.0) { $0 + $1.layout.hPt }
		if let want = (expect["visibleSum"] as? NSNumber)?.doubleValue {
			XCTAssertEqual(r1(sum), want, accuracy: 0.051, "\(step): visibleSum")
		}
		let wantState = expect["olderState"] as? String ?? ""
		XCTAssertEqual(page.olderState.rawValue, wantState, "\(step): olderState")
		if let wantCursor = expect["olderCursor"] as? String {
			let want = decodeExpectedCursor(wantCursor)
			XCTAssertNotNil(want, "\(step): expected cursor parses")
			XCTAssertNotNil(page.olderCursor, "\(step): cursor present")
			if let got = page.olderCursor, let w = want {
				// Our cursor has our own epoch and carries the sort key; compare the key and the conversation.
				var b64 = got.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
				while b64.count % 4 != 0 { b64 += "=" }
				let o = (try? JSONSerialization.jsonObject(with: Data(base64Encoded: b64) ?? Data())) as? [String: Any]
				XCTAssertEqual((o?["t"] as? NSNumber)?.int64Value, w.t, "\(step): cursor sortTs")
				XCTAssertEqual(o?["i"] as? String, w.i, "\(step): cursor stableId")
				XCTAssertEqual(o?["c"] as? String, conv, "\(step): cursor conversation")
				XCTAssertEqual(w.c.lowercased(), conv, "\(step): expected cursor conversation")
			}
		} else {
			XCTAssertNil(page.olderCursor, "\(step): no cursor when the end is reached")
		}
	}

	/// Full walk from the newest row to the oldest, compared with the truth rows of the conversation that
	/// are not tombstones, ascending by K (stable_id in ASCII byte order).
	private func assertFullWalkMatchesTruth(root: Root, store: BeamioConetChatLocalStore, conv: String) throws {
		var truth: [(ts: Int64, sid: String, body: String?, kind: String)] = []
		let lines = try String(contentsOf: root.acctDir.appendingPathComponent("truth.jsonl"), encoding: .utf8).split(separator: "\n")
		for line in lines {
			guard let o = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] else { continue }
			guard (o["convKey"] as? String)?.lowercased() == conv, (o["deleted"] as? Bool) != true else { continue }
			truth.append(((o["sortTs"] as? NSNumber)?.int64Value ?? 0, o["stableId"] as? String ?? "", o["body"] as? String, o["kind"] as? String ?? ""))
		}
		truth.sort { a, b in
			a.ts != b.ts ? a.ts < b.ts : a.sid.utf8.lexicographicallyPrecedes(b.sid.utf8)
		}
		let vp = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait)
		var pages: [BeamioChatPage] = []
		var page = store.openConversation(convKey: conv, viewport: vp)
		pages.append(page)
		while page.olderState == .more, let c = page.olderCursor {
			page = try store.loadOlder(convKey: conv, cursor: c, viewport: vp)
			pages.append(page)
			XCTAssertLessThan(pages.count, 5000, "walk must terminate")
		}
		XCTAssertEqual(page.olderState, .end)
		let walked = pages.reversed().flatMap { $0.items }
		XCTAssertEqual(walked.map(\.stableId), truth.map(\.sid), "T-2: visible pages equal the truth, no gaps or repeats")
		XCTAssertEqual(Set(walked.map(\.stableId)).count, walked.count)
		for (item, t) in zip(walked, truth) where t.kind == "text" {
			XCTAssertEqual(item.body, t.body, "text body matches the truth")
		}
	}
}
