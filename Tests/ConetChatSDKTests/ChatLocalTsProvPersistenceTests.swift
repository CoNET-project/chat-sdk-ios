import XCTest
@testable import ConetChatSDK

/// D16 provenance of this device's own writes is kept until the ingest.
/// Black-box check: a row whose provenance was kept (ts_prov 1) is corrected by a later sender-time row with the same
/// sendKey. A row without it (unknown_inbound) is not. Synthetic data only.
final class ChatLocalTsProvPersistenceTests: XCTestCase {
	private let accountA = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let accountB = "0x2222222222222222222222222222222222222222"
	private let localRootA = Data(repeating: 0x0A, count: 32)
	private let localRootB = Data(repeating: 0x0B, count: 32)
	private let root = FileManager.default.temporaryDirectory.appendingPathComponent("tsprov-p-\(UUID().uuidString)", isDirectory: true)
	private let big = BeamioChatViewport(widthPt: 390, heightPt: 100_000, orientation: .portrait)

	private struct Pick {
		let peer: String
		let sendId: String
		let dir: String
		let ts: Int64
	}

	private func pick(_ h: ChatSynthHistory) throws -> Pick {
		for r in h.index {
			guard let sid = r["sendId"] as? String, !sid.isEmpty, r["revision"] == nil, r["deleted"] == nil,
			      let peer = r["peer"] as? String, let dir = r["dir"] as? String,
			      let ts = (r["ts"] as? NSNumber)?.int64Value
			else { continue }
			return Pick(peer: peer.lowercased(), sendId: sid, dir: dir, ts: ts)
		}
		throw XCTSkip("no index record with a sendId")
	}

	private func store(_ acct: String, _ localRoot: Data) throws -> BeamioConetChatLocalStore {
		let s = BeamioConetChatLocalStore(rootDirectory: root)
		try s.unlock(accountKey: acct + ":default", localRoot: localRoot)
		return s
	}

	/// Number of kept provenance entries, read from the file directly.
	private func keptEntries(_ s: BeamioConetChatLocalStore, _ acct: String) throws -> Int {
		let raw = try ChatLocalSQLite(path: s.databasePath(for: acct.lowercased() + ":default"))
		defer { raw.close() }
		return Int(try raw.scalarInt("SELECT COUNT(*) FROM tsprov"))
	}

	/// Syncs the index (the ingest), then imports the same sendKey with a sender time 5000 ms later.
	/// Returns the sortTs of the row with that sendKey.
	private func syncThenImport(_ s: BeamioConetChatLocalStore, _ acct: String, _ h: ChatSynthHistory, _ p: Pick,
	                            localRoot: Data) throws -> Int64? {
		_ = s.syncIndex(records: h.index, historyMaster: h.master, fetchCipher: ChatSynthHistory.Fetcher(h.fragments).fetch)
		// A local write with the sender time (ts_prov 0) is the correcting write; an import has ts_prov 2 and corrects nothing.
		try s.addPendingLocal(convKey: p.peer, sendId: p.sendId, sortTs: p.ts + 5000, dir: p.dir, body: "imported", tsProvided: true)
		let sid = BeamioChatLocalCrypto.stableId(idxKey: BeamioChatLocalCrypto.idxKey(localRoot: localRoot), sendKey: p.sendId)
		return s.openConversation(convKey: p.peer, viewport: big).items.first { $0.stableId == sid }?.sortTs
	}

	/// The write leaves the provenance behind; the process is killed before the ingest. Restart: the ingest uses it.
	func testProvenanceSurvivesAKillBeforeTheIngest() throws {
		let h = ChatSynthHistory(seed: 91, messages: 12, convs: ["0x5555555555555555555555555555555555555555"])
		let p = try pick(h)
		do {
			let before = try store(accountA, localRootA)
			before.recordLocalTsProv(convKey: p.peer, sendKey: p.sendId, tsProv: 1)
		}  // no lock: the process is gone
		let after = try store(accountA, localRootA)
		XCTAssertEqual(try keptEntries(after, accountA), 1, "the entry is still in the file after the restart")
		let ts = try syncThenImport(after, accountA, h, p, localRoot: localRootA)
		XCTAssertEqual(ts, p.ts + 5000, "the kept provenance (1) lets the sender time correct the row")
	}

	/// Control: no kept provenance, so the ingested row is unknown_inbound and the later sender time does not rewrite it.
	func testWithoutKeptProvenanceTheRowIsNotCorrected() throws {
		let h = ChatSynthHistory(seed: 92, messages: 12, convs: ["0x5555555555555555555555555555555555555555"])
		let p = try pick(h)
		let s = try store(accountA, localRootA)
		let ts = try syncThenImport(s, accountA, h, p, localRoot: localRootA)
		XCTAssertEqual(ts, p.ts, "unknown_inbound: the first ts stays")
	}

	/// Locked: nothing is written, and nothing can be corrected later.
	func testLockedWritesNothing() throws {
		let h = ChatSynthHistory(seed: 93, messages: 12, convs: ["0x5555555555555555555555555555555555555555"])
		let p = try pick(h)
		let s = try store(accountA, localRootA)
		s.lock()
		s.recordLocalTsProv(convKey: p.peer, sendKey: p.sendId, tsProv: 1)
		try s.unlock(accountKey: accountA + ":default", localRoot: localRootA)
		XCTAssertEqual(try keptEntries(s, accountA), 0, "no entry while locked")
		let ts = try syncThenImport(s, accountA, h, p, localRoot: localRootA)
		XCTAssertEqual(ts, p.ts, "no provenance, no correction")
	}

	/// Another account never sees this account's provenance: its own file, its own key.
	func testAccountsDoNotShareProvenance() throws {
		let h = ChatSynthHistory(seed: 94, messages: 12, convs: ["0x5555555555555555555555555555555555555555"])
		let p = try pick(h)
		let a = try store(accountA, localRootA)
		a.recordLocalTsProv(convKey: p.peer, sendKey: p.sendId, tsProv: 1)
		let b = try store(accountB, localRootB)
		let ts = try syncThenImport(b, accountB, h, p, localRoot: localRootB)
		XCTAssertEqual(ts, p.ts, "account B does not see account A's provenance")
		XCTAssertEqual(try keptEntries(a, accountA), 1, "A's entry is untouched")
	}

	/// The ingest consumes the entry: nothing is left behind after the row is ingested.
	func testTheIngestRemovesTheEntry() throws {
		let h = ChatSynthHistory(seed: 95, messages: 12, convs: ["0x5555555555555555555555555555555555555555"])
		let p = try pick(h)
		let s = try store(accountA, localRootA)
		s.recordLocalTsProv(convKey: p.peer, sendKey: p.sendId, tsProv: 1)
		XCTAssertEqual(try keptEntries(s, accountA), 1)
		_ = try syncThenImport(s, accountA, h, p, localRoot: localRootA)
		XCTAssertEqual(try keptEntries(s, accountA), 0, "consumed by the ingest")
	}

	/// The database files hold no plaintext sendKey or conversation address.
	func testNoPlaintextSendKeyInTheDatabaseFiles() throws {
		let h = ChatSynthHistory(seed: 96, messages: 12, convs: ["0x5555555555555555555555555555555555555555"])
		let p = try pick(h)
		let s = try store(accountA, localRootA)
		s.recordLocalTsProv(convKey: p.peer, sendKey: p.sendId, tsProv: 1)
		let path = s.databasePath(for: accountA.lowercased() + ":default")
		for file in [path, path + "-wal"] where FileManager.default.fileExists(atPath: file) {
			let bytes = try Data(contentsOf: URL(fileURLWithPath: file))
			XCTAssertNil(bytes.range(of: Data(p.sendId.utf8)), "no plaintext sendKey in \(file)")
			XCTAssertNil(bytes.range(of: Data(p.peer.utf8)), "no plaintext conversation address in \(file)")
		}
	}
}
