import XCTest
@testable import ConetChatSDK

/// The page records over the iOS chat channel: a verified sender reads and writes its record through
/// the same record boundary as the window channel. The chat channel runs here against an in-memory store, through the test seam
/// `BeamioShellRecord.environmentOverride` (test builds only), so nothing reaches the Keychain. The locked store is answered by the record rules
///. Synthetic data only.
final class ChatChannelRecordRoundTripTests: XCTestCase {
	/// A device whose last reader report was an absence: the confirmed absence is device-level now.
	private func absentDevice() -> Device {
		let device = Device()
		device.state.legacyConfirmedAbsent = true
		return device
	}
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]

		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			records[account] = record
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let account = PgpMigrationTestSupport.eoa
	private var store = Store()

	private var savedNativeStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		store = Store()
		// A device with no native key (a shell write, not a native one): the memory store, not the simulator's unreadable Keychain.
		savedNativeStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	override func tearDown() {
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	/// The environment of a session with the record in place: the account is established by the first-run state `confirmedAbsent`, and the store is
	/// locked or not as the test says. The gate is the default G2 of the record environment.
	private func install(locked: Bool) {
		BeamioShellRecord.environmentOverride = BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: absentDevice(),
			originAllowed: false,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in locked },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	/// One answer of the chat channel from a verified sender (`originAllowed` true). The emit runs on the main queue, so the test drains it first.
	private func chatEvent(_ body: [String: Any]) -> [String: Any]? {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		XCTAssertEqual(events.count, 1, "\(body["reqId"] ?? "?"): exactly one answer")
		return events.first
	}

	/// rule 2,: the chat channel writes the record of a verified sender, and reads back what it wrote.
	func testTheChatChannelWritesAndReadsTheRecordOfAVerifiedSender() {
		install(locked: false)
		let written = chatEvent(["type": "shellRecordWrite", "reqId": "rt-write-1", "record": ["rev": 0, "schemaVersion": 1]])
		XCTAssertEqual(written?["reqId"] as? String, "rt-write-1", "the write's reqId is echoed")
		XCTAssertEqual(written?["ok"] as? Bool, true, "the write is answered as the record's business result")
		let writeCode = (written?["result"] as? [String: Any])?["code"] as? String
		XCTAssertNotEqual(writeCode, "write_failed", "the chat channel writes the record")
		let writtenRev = (written?["result"] as? [String: Any])?["rev"] as? Int
		XCTAssertNotNil(writtenRev, "the write answers the new rev")

		let read = chatEvent(["type": "shellRecordRead", "reqId": "rt-read-1"])
		XCTAssertEqual(read?["reqId"] as? String, "rt-read-1", "the read's reqId is echoed")
		XCTAssertEqual(read?["ok"] as? Bool, true)
		let result = read?["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "ok", "the read is the record's answer")
		let stored = result?["record"] as? [String: Any]
		XCTAssertEqual(stored?["rev"] as? Int, writtenRev, "the read returns the rev the write stored")
		XCTAssertEqual(stored?["schemaVersion"] as? Int, 1, "the read returns the record the write stored")
	}

	/// over the chat channel, driven by shell-record-passcode-not-provided.v1 (SRP): a passcode record whose bundle has not been provided answers the read as
	/// a result (SRP-01) and the write as an envelope-level failure (SRP-02), both with the reason passcode_not_provided and retryable true; never
	/// storage_locked or write_failed (SRP-07); nothing is written.
	func testTheChatChannelAnswersAMissingPasscodeBundleAsNotReadyWithItsReason() throws {
		let data = try BundledVectorFile.data(resource: "shell-record-passcode-not-provided.v1")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		func expect(_ prefix: String) throws -> [String: Any] {
			let c = try XCTUnwrap(cases.first { ($0["id"] as? String ?? "").hasPrefix(prefix) }, prefix)
			return try XCTUnwrap(c["expect"] as? [String: Any])
		}
		install(locked: true)
		let read = chatEvent(["type": "shellRecordRead", "reqId": "rt-lock-read"])
		let wantRead = try expect("SRP-01")
		XCTAssertEqual(read?["ok"] as? Bool, wantRead["ok"] as? Bool, "SRP-01")
		XCTAssertEqual(read?["result"] as? [String: AnyHashable], wantRead["result"] as? [String: AnyHashable], "SRP-01: the result is exactly the vector's")
		let write = chatEvent(["type": "shellRecordWrite", "reqId": "rt-lock-write", "record": ["rev": 0, "schemaVersion": 1]])
		let wantWrite = try expect("SRP-02")
		XCTAssertEqual(write?["ok"] as? Bool, wantWrite["ok"] as? Bool, "SRP-02")
		XCTAssertEqual(write?["error"] as? String, wantWrite["error"] as? String, "SRP-02")
		XCTAssertEqual(write?["notReadyReason"] as? String, wantWrite["notReadyReason"] as? String, "SRP-02")
		XCTAssertEqual(write?["retryable"] as? Bool, wantWrite["retryable"] as? Bool, "SRP-02")
		XCTAssertNil(write?["result"], "SRP-02: the write answer is envelope-level, with no result")
		let forbidden = try XCTUnwrap(try expect("SRP-07")["forbiddenCodes"] as? [String])
		let text = String(describing: read) + String(describing: write)
		for word in forbidden { XCTAssertFalse(text.contains(word), "SRP-07: \(word) is not used for the app passcode state") }
		XCTAssertTrue(store.records.isEmpty, "nothing is written")
	}
}
