#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// `accountCleanupOld` through the bridge (`handleCommand`), with an in-memory environment (no real Keychain, no real files). The v3 vector cases
/// BR3-05, BR3-06 and BR3-07 are read from the pinned file and compared with the answers the bridge emits; CU-04 (read-back failure is not_ready),
/// CU-05 (no command: nothing is deleted) and CU-06 (gate not passed: not_ready, nothing deleted) are driven here as well. Synthetic accounts only.
/// Results of these tests are "locked-console subset" when run on a locked Mac: nothing here writes a protected file.
final class AccountCleanupCommandTests: XCTestCase {
	private let new = "0x1111111111111111111111111111111111111111"
	private let old = "0x2222222222222222222222222222222222222222"
	private var store: Set<String> = []
	private var failDelete: Set<String> = []
	private var deleteCalls = 0
	private let lock = NSLock()
	private var saved: (() -> BeamioAccountCleanup.Environment)!

	private var accountsOnDevice: [String] { [new, old, third] }
	private let third = "0x3333333333333333333333333333333333333333"
	/// Set by a test to make the pointer answer another account from then on (an account switch in the middle of a run).
	private var switchedTo: String?
	private var pointerCalls = 0
	private var pointerSequence: [String]?

	private func makeEnv(gate: Bool = true, derived: String? = nil, pointer: String? = nil, mnemonic: BeamioMnemonicAccountState = .valid) -> BeamioAccountCleanup.Environment {
		BeamioAccountCleanup.Environment(
			gatePassed: { gate },
			activeSnapshot: {
				let now: String
				if let seq = self.pointerSequence { now = seq[min(self.pointerCalls, seq.count - 1)]; self.pointerCalls += 1 }
				else { now = self.switchedTo ?? pointer ?? self.new }
				return (now, derived ?? self.new)
			},
			mnemonicState: { $0 == self.new ? mnemonic : .valid },
			keyRecordState: { _ in .present },
			accounts: { self.accountsOnDevice },
			itemsOfOldAccount: { owner in
				self.lock.lock(); defer { self.lock.unlock() }
				return self.store.filter { $0.hasPrefix(owner + "|") }.map { BeamioAccountCleanup.Item(owner: owner, name: String($0.split(separator: "|")[1])) }.sorted { $0.name < $1.name }
			},
			delete: { item in
				self.lock.lock(); defer { self.lock.unlock() }
				self.deleteCalls += 1
				if self.failDelete.contains(item.name) { return false }
				self.store.remove("\(item.owner)|\(item.name)")
				return true
			}
		)
	}

	override func setUp() {
		super.setUp()
		store = ["\(old)|a", "\(old)|b", "\(new)|keep"]
		switchedTo = nil; pointerSequence = nil; pointerCalls = 0
		failDelete = []
		deleteCalls = 0
		saved = BeamioConetChatModule.accountCleanupEnvironment
		BeamioConetChatModule.accountCleanupEnvironment = { self.makeEnv() }
		// the first command of a process runs the session start steps (snapshot, start-up redo); let them finish before the cases
		_ = send(["type": "walletStatus", "reqId": 1])
	}

	override func tearDown() {
		BeamioConetChatModule.accountCleanupEnvironment = saved
		super.tearDown()
	}

	private func send(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		// the module emits on the main queue: wait until what it queued has been delivered
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	private func cleanup(reqId: Int = 7, key: String? = nil, idem: String = "idem-1") -> [String: Any]? {
		send(["type": "accountCleanupOld", "reqId": reqId, "accountKey": key ?? new, "idempotencyKey": idem]).first
	}

	private func vectorCases() throws -> [String: [String: Any]] {
		let data = try BundledVectorFile.data(resource: "accountCleanupOld.v3")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return Dictionary(uniqueKeysWithValues: cases.compactMap { c in (c["id"] as? String).map { ($0, c) } })
	}

	private func expectMatches(_ answer: [String: Any]?, _ expect: [String: Any], file: StaticString = #filePath, line: UInt = #line) {
		guard let answer else { return XCTFail("no answer", file: file, line: line) }
		XCTAssertEqual(answer["type"] as? String, expect["type"] as? String, file: file, line: line)
		XCTAssertEqual(answer["ok"] as? Bool, expect["ok"] as? Bool, file: file, line: line)
		XCTAssertEqual(answer["error"] as? String, expect["error"] as? String, file: file, line: line)
		let want = expect["result"] as? [String: Any] ?? [:]
		let got = answer["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(got["cleanupPending"] as? Bool, want["cleanupPending"] as? Bool, file: file, line: line)
		if let n = want["keptUnattributed"] as? Int { XCTAssertEqual(got["keptUnattributed"] as? Int, n, file: file, line: line) }
		else { XCTAssertNotNil(got["keptUnattributed"] as? Int, "an integer", file: file, line: line) }
	}

	func testTheCommandIsRegisteredAndJudgesItsOwnGate() {
		XCTAssertTrue(BeamioConetChatModule.knownBridgeCommand("accountCleanupOld"))
		XCTAssertTrue(BeamioConetChatModule.dispatchedCommands.contains("accountCleanupOld"))
		XCTAssertTrue(BeamioConetChatModule.gateExemptCommands.contains("accountCleanupOld"))
	}

	// BR3-05 / CU-06: the gate is not passed: not_ready, nothing deleted, nothing listed for deletion
	func testBR3_05_GateNotPassedIsNotReadyAndDeletesNothing() throws {
		let c = try XCTUnwrap(vectorCases()["BR3-05-gate-not_ready"])
		BeamioConetChatModule.accountCleanupEnvironment = { self.makeEnv(gate: false) }
		expectMatches(cleanup(), try XCTUnwrap(c["expect"] as? [String: Any]))
		XCTAssertEqual(deleteCalls, 0)
		XCTAssertEqual(store, ["\(old)|a", "\(old)|b", "\(new)|keep"])
	}

	// BR3-06: an item that cannot be deleted: clear_incomplete, pending
	func testBR3_06_ItemFailureIsClearIncompleteAndPending() throws {
		let c = try XCTUnwrap(vectorCases()["BR3-06-item-clear_incomplete"])
		failDelete = ["b"]
		expectMatches(cleanup(), try XCTUnwrap(c["expect"] as? [String: Any]))
		XCTAssertTrue(store.contains("\(old)|b"), "the failed item stays")
		XCTAssertTrue(store.contains("\(new)|keep"))
	}

	// BR3-07: success, no error field
	func testBR3_07_SuccessHasNoErrorField() throws {
		let c = try XCTUnwrap(vectorCases()["BR3-07-success"])
		let answer = cleanup()
		expectMatches(answer, try XCTUnwrap(c["expect"] as? [String: Any]))
		XCTAssertNil(answer?["error"])
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// CU-04: the read-back fails or disagrees: not_ready / account_mismatch, nothing deleted
	func testCU04_ReadBackFailuresDeleteNothing() {
		BeamioConetChatModule.accountCleanupEnvironment = { self.makeEnv(mnemonic: .unreadable) }
		XCTAssertEqual(cleanup()?["error"] as? String, "not_ready")
		BeamioConetChatModule.accountCleanupEnvironment = { self.makeEnv(derived: self.old) }
		XCTAssertEqual(cleanup()?["error"] as? String, "account_mismatch")
		BeamioConetChatModule.accountCleanupEnvironment = { self.makeEnv(pointer: self.old) }
		XCTAssertEqual(cleanup()?["error"] as? String, "account_mismatch")
		XCTAssertEqual(deleteCalls, 0)
	}

	// the active account is unknown (no pointer, the native key cannot be read): not_ready through the bridge, nothing listed, counted or deleted (, EA-07/EA-08)
	func testActiveAccountUnknownIsNotReadyThroughTheBridge() {
		var e = makeEnv()
		e.activeSnapshot = { ("", nil) }
		BeamioConetChatModule.accountCleanupEnvironment = { e }
		let a = cleanup()
		XCTAssertEqual(a?["ok"] as? Bool, false)
		XCTAssertEqual(a?["error"] as? String, "not_ready")
		let r = a?["result"] as? [String: Any]
		XCTAssertEqual(r?["cleanupPending"] as? Bool, false)
		XCTAssertEqual(r?["keptUnattributed"] as? Int, 0)
		XCTAssertEqual(deleteCalls, 0)
	}

	// CU-05: no command, no deletion; a command of another name never reaches the cleanup
	func testCU05_NoCommandNoDeletionAndOtherNamesAreNotTheCleanup() {
		_ = send(["type": "walletStatus", "reqId": 3])
		_ = send(["type": "accountCleanup", "reqId": 4, "accountKey": new, "idempotencyKey": "x"])
		XCTAssertEqual(deleteCalls, 0)
	}

	func testABadRequestNeverDeletes() {
		XCTAssertEqual(cleanup(key: "0xABC")?["error"] as? String, "bad_request")
		XCTAssertEqual(cleanup(idem: "")?["error"] as? String, "bad_request")
		XCTAssertEqual(send(["type": "accountCleanupOld", "reqId": 8, "accountKey": 5, "idempotencyKey": ["x"]]).first?["error"] as? String, "bad_request")
		XCTAssertEqual(deleteCalls, 0)
		// the result is always present with the two fields
		let r = cleanup(key: "nope")?["result"] as? [String: Any]
		XCTAssertEqual(r?["cleanupPending"] as? Bool, false)
		XCTAssertEqual(r?["keptUnattributed"] as? Int, 0)
	}

	// a repeated callback (same or other idempotency key) finds nothing more and deletes nothing wrong
	func testARepeatedCallbackDeletesNothingMoreAndKeepsTheNewAccount() {
		XCTAssertEqual(cleanup(reqId: 1)?["ok"] as? Bool, true)
		let calls = deleteCalls
		XCTAssertEqual(cleanup(reqId: 2)?["ok"] as? Bool, true)
		XCTAssertEqual(cleanup(reqId: 3, idem: "idem-2")?["ok"] as? Bool, true)
		XCTAssertEqual(deleteCalls, calls)
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// callbacks that arrive at the same time run one after another: each old item is deleted exactly once
	func testConcurrentCallbacksDeleteEachItemOnce() {
		let group = DispatchGroup()
		for i in 0..<6 {
			group.enter()
			DispatchQueue.global().async {
				BeamioConetChatModule.handleCommand(["type": "accountCleanupOld", "reqId": 100 + i, "accountKey": self.new, "idempotencyKey": "c\(i)"]) { _ in }
				group.leave()
			}
		}
		XCTAssertEqual(group.wait(timeout: .now() + 10), .success)
		XCTAssertEqual(deleteCalls, 2, "a and b, once each")
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// a run that stopped half way (pending) is resumed by a later run over a fresh environment, as after a restart: only what is left is deleted
	func testCleanupPendingResumesAfterARestart() {
		failDelete = ["b"]
		let first = cleanup(reqId: 1)
		XCTAssertEqual(first?["error"] as? String, "clear_incomplete")
		XCTAssertEqual((first?["result"] as? [String: Any])?["cleanupPending"] as? Bool, true)
		XCTAssertEqual(store, ["\(old)|b", "\(new)|keep"])
		// restart: nothing of the first run is kept in memory; the environment is built again over the same storage
		failDelete = []
		BeamioConetChatModule.accountCleanupEnvironment = { self.makeEnv() }
		let second = cleanup(reqId: 2, idem: "after-restart")
		XCTAssertEqual(second?["ok"] as? Bool, true)
		XCTAssertEqual((second?["result"] as? [String: Any])?["cleanupPending"] as? Bool, false)
		XCTAssertEqual(store, ["\(new)|keep"])
	}

	// the bridge envelope comes first: without a reqId the answer is bad_request with a null reqId, and nothing is run or deleted
	func testWithoutAReqIdTheEnvelopeRefusesAndNothingIsDeleted() {
		let events = send(["type": "accountCleanupOld", "accountKey": new, "idempotencyKey": "x"])
		XCTAssertEqual(events.first?["error"] as? String, "bad_request")
		XCTAssertEqual(deleteCalls, 0)
		XCTAssertEqual(store.count, 3)
	}

	// the account changes in the middle of a run: the next old account is not touched, the answer is account_mismatch, what was deleted stays deleted
	func testAnAccountSwitchInTheMiddleStopsTheCleanup() {
		store = ["\(old)|a", "\(old)|b", "\(third)|a", "\(third)|b", "\(new)|keep"]
		let base = makeEnv()
		var env = base
		env.delete = { item in
			let done = base.delete(item)
			self.switchedTo = "0x5555555555555555555555555555555555555555"   // the user switches to a stranger right after the first deletion
			return done
		}
		BeamioConetChatModule.accountCleanupEnvironment = { env }
		let a = cleanup()
		XCTAssertEqual(a?["ok"] as? Bool, false)
		XCTAssertEqual(a?["error"] as? String, "account_mismatch")
		XCTAssertEqual(deleteCalls, 2, "the first old account's two items went; nothing of the second one")
		XCTAssertEqual(store, ["\(third)|a", "\(third)|b", "\(new)|keep"])
	}

	// a derived address that cannot be read in the middle of a run is not_ready (and stops)
	func testAnUnreadableDerivedAddressInTheMiddleIsNotReady() {
		store = ["\(old)|a", "\(third)|a", "\(new)|keep"]
		let base = makeEnv()
		var env = base
		var unreadable = false
		env.activeSnapshot = { (self.new, unreadable ? nil : self.new) }
		env.delete = { item in let d = base.delete(item); unreadable = true; return d }
		BeamioConetChatModule.accountCleanupEnvironment = { env }
		XCTAssertEqual(cleanup()?["error"] as? String, "not_ready")
		XCTAssertEqual(store, ["\(third)|a", "\(new)|keep"])
	}

	// defensive guard: an account that is the active one when its turn comes is kept whole and counted, answer ok, the other old account is cleaned.
	// Unreachable in the normal flow; driven here with a pointer that answers the new account for the read-back and the first old account's turn only afterwards.
	func testTheDefensiveGuardKeepsAnActiveCandidateWholeAndCounts() {
		// calls of the pointer: 1 read-back, 2 the guard of `old` (answers old: kept whole, counted), 3 the guard of `third` (new), 4 the re-read before third (new)
		pointerSequence = [new, old, new, new, new, new]
		let a = cleanup()
		XCTAssertEqual(a?["ok"] as? Bool, true, "\(String(describing: a))")
		XCTAssertEqual((a?["result"] as? [String: Any])?["cleanupPending"] as? Bool, false)
		XCTAssertEqual((a?["result"] as? [String: Any])?["keptUnattributed"] as? Int, 2, "the two items of the account that was active")
		XCTAssertTrue(store.contains("\(old)|a") && store.contains("\(old)|b"))
		XCTAssertTrue(store.contains("\(new)|keep"))
	}
}
#endif
