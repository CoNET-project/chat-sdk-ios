#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// and K1 (review of c796412): records do not expire by time; above the limit only server-acked records go, oldest first;
/// a file that cannot be read or does not parse is never overwritten. Synthetic data only. The file is the simulator's own inbox.
final class InboxStoreRulesTests: XCTestCase {
	private let armor = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"

	private var fileURL: URL {
		BeamioInboxFile.folder!.appendingPathComponent("inbox_v1.json")
	}

	private func hash(_ n: Int) -> String {
		"0x" + String(format: "%064x", n)
	}

	private func writeRows(_ rows: [[String: Any]]) {
		let data = try! JSONSerialization.data(withJSONObject: rows)
		try! data.write(to: fileURL, options: .atomic)
	}

	private func fileRows() -> [[String: Any]] {
		let data = try! Data(contentsOf: fileURL)
		return try! JSONSerialization.jsonObject(with: data) as! [[String: Any]]
	}

	private func row(_ n: Int, t: Double, acked: Bool) -> [String: Any] {
		["h": hash(n), "a": "", "v": "", "t": t, "c": true, "s": acked]
	}

	override func setUp() {
		super.setUp()
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.failReads = false
		BeamioConetChatInboxStore.clear()
	}

	override func tearDown() {
		BeamioConetChatInboxStore.failWrites = false
		BeamioConetChatInboxStore.failReads = false
		BeamioConetChatInboxStore.clear()
		super.tearDown()
	}

	/// a record from a year ago still answers the dedupe question.
	func testRecordsDoNotExpireByTime() {
		let yearAgo = Date().timeIntervalSince1970 - 365 * 24 * 3600
		writeRows([["h": hash(1), "a": "", "v": "", "t": yearAgo, "c": false, "s": true]])
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hash(1)))
	}

	/// above the limit, the oldest acknowledged record goes; the unacknowledged ones stay, and the new one is kept.
	func testOnlyAckedRecordsAreEvictedAboveTheLimit() {
		let now = Date().timeIntervalSince1970
		var rows: [[String: Any]] = []
		for n in 0 ..< BeamioConetChatInboxStore.maxRecords {
			rows.append(row(n, t: now - Double(BeamioConetChatInboxStore.maxRecords - n), acked: n < 2))
		}
		writeRows(rows)
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(999_999), armor: armor, viaDomain: "d"))
		let after = fileRows()
		XCTAssertEqual(after.count, BeamioConetChatInboxStore.maxRecords, "one acked record goes, so the total stays at the limit")
		let hashes = Set(after.compactMap { $0["h"] as? String })
		XCTAssertFalse(hashes.contains(hash(0)), "the oldest acked record goes first")
		XCTAssertTrue(hashes.contains(hash(1)), "the next acked record stays")
		XCTAssertTrue(hashes.contains(hash(999_999)), "the new record is kept")
	}

	/// nothing that is unacknowledged is dropped, even above the limit.
	func testUnackedRecordsAreNeverEvicted() {
		let now = Date().timeIntervalSince1970
		var rows: [[String: Any]] = []
		for n in 0 ..< BeamioConetChatInboxStore.maxRecords {
			rows.append(row(n, t: now - Double(n), acked: false))
		}
		writeRows(rows)
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(999_999), armor: armor, viaDomain: "d"))
		XCTAssertEqual(fileRows().count, BeamioConetChatInboxStore.maxRecords + 1, "nothing unacknowledged may be dropped")
		XCTAssertTrue(BeamioConetChatInboxStore.hasRecord(armorHash: hash(0)))
	}

	/// K1: a file that does not parse is not treated as an empty inbox, so a write does not replace it.
	func testAnUnparseableFileIsNeverOverwritten() {
		let garbage = Data("not a json inbox".utf8)
		try! garbage.write(to: fileURL)
		XCTAssertFalse(BeamioConetChatInboxStore.put(armorHash: hash(1), armor: armor, viaDomain: "d"), "a put must report failure")
		XCTAssertFalse(BeamioConetChatInboxStore.confirm([hash(1)]))
		XCTAssertFalse(BeamioConetChatInboxStore.markServerAcked([hash(1)]))
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hash(1)))
		XCTAssertEqual(try! Data(contentsOf: fileURL), garbage, "the file must be left as it was")
	}

	/// K1: a read that fails (the file is protected until the first unlock) writes nothing and shows and acks nothing.
	func testAFailedReadWritesNothing() {
		writeRows([row(1, t: Date().timeIntervalSince1970, acked: false)])
		let before = try! Data(contentsOf: fileURL)
		BeamioConetChatInboxStore.failReads = true
		XCTAssertFalse(BeamioConetChatInboxStore.put(armorHash: hash(2), armor: armor, viaDomain: "d"))
		XCTAssertFalse(BeamioConetChatInboxStore.confirm([hash(1)]))
		XCTAssertFalse(BeamioConetChatInboxStore.markServerAcked([hash(1)]))
		XCTAssertTrue(BeamioConetChatInboxStore.list().isEmpty)
		BeamioConetChatInboxStore.failReads = false
		XCTAssertEqual(try! Data(contentsOf: fileURL), before, "the file must be left as it was")
	}

	/// input: the mailbox's acknowledgement is recorded, and it survives a reread.
	func testAServerAckIsRecordedOnDisk() {
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(3), armor: armor, viaDomain: "d"))
		XCTAssertEqual(fileRows().first?["s"] as? Bool, false)
		XCTAssertTrue(BeamioConetChatInboxStore.markServerAcked([hash(3)]))
		XCTAssertEqual(fileRows().first?["s"] as? Bool, true)
	}

	/// A write that fails is reported, and the file is left as it was.
	func testAFailedWriteLeavesTheFileAsItWas() {
		writeRows([row(1, t: Date().timeIntervalSince1970, acked: false)])
		let before = try! Data(contentsOf: fileURL)
		BeamioConetChatInboxStore.failWrites = true
		XCTAssertFalse(BeamioConetChatInboxStore.markServerAcked([hash(1)]))
		BeamioConetChatInboxStore.failWrites = false
		XCTAssertEqual(try! Data(contentsOf: fileURL), before)
	}
}
#endif

#if BEAMIO_TEST_HOOKS
extension InboxStoreRulesTests {
	/// the armor of an unconfirmed message stays with no time expiry (a week-old armor is still replayed).
	func testArmorDoesNotExpireByTime() {
		let yearAgo = Date().timeIntervalSince1970 - 365 * 24 * 3600
		let armorText = "-----BEGIN PGP MESSAGE-----\nsynthetic\n-----END PGP MESSAGE-----"
		let rows: [[String: Any]] = [["h": "0x" + String(repeating: "c", count: 64), "a": armorText, "v": "", "t": yearAgo, "c": false, "s": false]]
		try! JSONSerialization.data(withJSONObject: rows).write(to: BeamioInboxFile.folder!.appendingPathComponent("inbox_v1.json"))
		XCTAssertEqual(BeamioConetChatInboxStore.list().count, 1, "an unconfirmed message keeps its armor")
	}
}
#endif

#if BEAMIO_TEST_HOOKS
extension InboxStoreRulesTests {
	/// (d): the time of one arrival on an inbox of 5000 records (500 of them unconfirmed, with armor of about 2 KB), measured on the
	/// inbox IO queue as the module runs it. The numbers are printed for the receipt. A loose bound only: a regression signal, not a target.
	func testAnArrivalOnAFiveThousandRecordInboxIsTimed() {
		let now = Date().timeIntervalSince1970
		let bulk = String(repeating: "A", count: 2000)
		let armorText = "-----BEGIN PGP MESSAGE-----\n\(bulk)\n-----END PGP MESSAGE-----"
		var rows: [[String: Any]] = []
		for n in 0 ..< 5000 {
			let unconfirmed = n < 500
			rows.append([
				"h": "0x" + String(format: "%064x", n),
				"a": unconfirmed ? armorText : "",
				"v": "domain.example",
				"t": now - Double(5000 - n),
				"c": !unconfirmed,
				"s": n % 2 == 0,
			])
		}
		try! JSONSerialization.data(withJSONObject: rows).write(to: BeamioInboxFile.folder!.appendingPathComponent("inbox_v1.json"))
		let size = (try? FileManager.default.attributesOfItem(atPath: BeamioInboxFile.folder!.appendingPathComponent("inbox_v1.json").path)[.size] as? Int) ?? -1

		let start = Date()
		let e = expectation(description: "arrival on the IO queue")
		var admitted: BeamioConetChatInboxStore.Admission?
		BeamioInboxIO.perform(generation: BeamioInboxIO.generation, {
			BeamioConetChatInboxStore.admit(armorHash: "0x" + String(repeating: "f", count: 64), armor: armorText, viaDomain: "domain.example")
		}) { a in
			admitted = a
			e.fulfill()
		}
		wait(for: [e], timeout: 60)
		let ms = Int(Date().timeIntervalSince(start) * 1000)
		print("INBOX-ARRIVAL 5000 records, 500 unconfirmed with armor, file \(size) bytes: \(ms) ms (one read, one write, on the IO queue)")

		XCTAssertEqual(admitted?.stored, true, "the new frame must be stored")
		XCTAssertEqual(admitted?.readable, true)
		XCTAssertLessThan(ms, 10_000, "a loose bound: an arrival must not take seconds")
	}
}
#endif

#if BEAMIO_TEST_HOOKS
extension InboxStoreRulesTests {
	/// (review B3, superseded): above the limit, a record the mailbox acked goes with its armor, whether or not the page has confirmed it.
	func testAServerAckedRecordIsEvictedWithItsArmorAboveTheLimit() {
		let now = Date().timeIntervalSince1970
		var rows: [[String: Any]] = []
		for n in 0 ..< BeamioConetChatInboxStore.maxRecords {
			rows.append(["h": hash(n), "a": n == 0 ? armor : "", "v": "", "t": now - Double(BeamioConetChatInboxStore.maxRecords - n),
			             "c": false, "s": n == 0])
		}
		writeRows(rows)
		XCTAssertTrue(BeamioConetChatInboxStore.put(armorHash: hash(999_999), armor: armor, viaDomain: "d"))
		XCTAssertFalse(BeamioConetChatInboxStore.hasRecord(armorHash: hash(0)), "the oldest acked record goes, with its armor")
		XCTAssertEqual(fileRows().count, BeamioConetChatInboxStore.maxRecords)
	}

	/// m1: a row without a hash makes the file unreadable: nothing is written over it, and nothing is dropped silently.
	/// D9: the time of one arrival on an inbox of 50000 records (the limit), 500 of them unconfirmed with armor. Printed for the receipt.
	func testAnArrivalOnAFiftyThousandRecordInboxIsTimed() {
		let now = Date().timeIntervalSince1970
		let bulk = String(repeating: "A", count: 2000)
		let armorText = "-----BEGIN PGP MESSAGE-----\n\(bulk)\n-----END PGP MESSAGE-----"
		var rows: [[String: Any]] = []
		for n in 0 ..< BeamioConetChatInboxStore.maxRecords {
			let unconfirmed = n < 500
			rows.append(["h": hash(n), "a": unconfirmed ? armorText : "", "v": "domain.example",
			             "t": now - Double(BeamioConetChatInboxStore.maxRecords - n), "c": !unconfirmed, "s": n % 2 == 0])
		}
		writeRows(rows)
		let size = (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? Int) ?? -1
		let start = Date()
		let e = expectation(description: "arrival on the IO queue")
		var admitted: BeamioConetChatInboxStore.Admission?
		BeamioInboxIO.perform(generation: BeamioInboxIO.generation, {
			BeamioConetChatInboxStore.admit(armorHash: "0x" + String(repeating: "e", count: 64), armor: armorText, viaDomain: "domain.example")
		}) { a in
			admitted = a
			e.fulfill()
		}
		wait(for: [e], timeout: 120)
		let ms = Int(Date().timeIntervalSince(start) * 1000)
		print("INBOX-ARRIVAL 50000 records, 500 unconfirmed with armor, file \(size) bytes: \(ms) ms (one read, one write, on the IO queue)")
		XCTAssertEqual(admitted?.stored, true)
	}
}
#endif
