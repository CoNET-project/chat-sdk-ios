#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Takeover item 1 (interface 25.52Y.70 第 4 項, 25.52Y.75): while the native-key snapshot is unknown, walletStatus answers `not_ready` with
/// `notReadyReason: "unreadable"`, every other command answers `not_ready` once, and nothing is read from the key store or written.
/// The store below counts every access, so the test shows that none happens. It also shows that the next session start answers from the store again.
final class NativeKeySnapshotUnknownTests: XCTestCase {
	/// A key store that counts its reads and writes. It holds one valid key record.
	private final class CountingStore: BeamioChatWalletKeyStoring {
		let account: String
		let key: Data
		var reads = 0
		var writes = 0
		init(account: String, key: Data) {
			self.account = account
			self.key = key
		}
		func write(eoa: String, key: Data) -> Bool { writes += 1; return true }
		func read(eoa: String) -> Data? { reads += 1; return eoa.lowercased() == account ? key : nil }
		func delete(eoa: String) { writes += 1 }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { reads += 1; return eoa.lowercased() == account ? .present : .absent }
		func hasAnyKeyRecord() -> Bool { reads += 1; return true }
		func enumerateKeyOwners() -> [String]? { reads += 1; return [account] }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { reads += 1; return [.valid(eoa: account)] }
		// the mnemonic ownership rule (Y.163 items 31 and 32): the store lists its mnemonic accounts (not counted: the reads asserts below count key reads only)
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { [BeamioChatKeyCreation(owner: account, created: nil)] }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { owner.lowercased() == account ? .valid : .absent }
	}

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		ClearPendingIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		BeamioNativeKeySnapshot.pinUnknownForTests(false)
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore
		ClearPendingIsolation.end()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	/// The ack events of one command, after the main queue has drained.
	private func send(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	private func answer(_ events: [[String: Any]], _ reqId: Int) -> String {
		let acks = events.filter { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
		guard acks.count == 1, let event = acks.first,
		      let data = try? JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]) else {
			return "none (\(events.count) events)"
		}
		return String(decoding: data, as: UTF8.self)
	}

	func testWhileTheSnapshotIsUnknownEveryCommandAnswersOnceAndNothingIsReadOrWritten() {
		let store = CountingStore(account: account, key: keyData)
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		XCTAssertFalse(BeamioNativeKeySnapshot.isKnown)
		store.reads = 0
		store.writes = 0

		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9700]), 9700),
		               #"{"ok":true,"reqId":9700,"result":{"notReadyReason":"unreadable","status":"not_ready"},"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "shellRecordRead", "reqId": 9701]), 9701),
		               #"{"ok":true,"reqId":9701,"result":{"code":"not_ready","notReadyReason":"g1_uninitialized","retryable":true},"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "shellRecordWrite", "reqId": 9702, "record": ["rev": 1]]), 9702),
		               #"{"ok":true,"reqId":9702,"result":{"code":"not_ready","notReadyReason":"g1_uninitialized","retryable":true},"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "notAListedName", "reqId": 9705]), 9705),
		               #"{"error":"unknown_command","ok":false,"reqId":9705,"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "init", "reqId": 9706, "payload": ["eoa": account]]), 9706),
		               #"{"error":"not_ready","ok":false,"reqId":9706,"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "walletTransferOnce", "reqId": 9707]), 9707),
		               #"{"error":"not_supported","ok":false,"reqId":9707,"type":"ack"}"#)
		// an envelope the reqId rule refuses (an array is no reqId): bad_request with reqId null, judged before the snapshot answer
		let refused = send(["type": "hello", "reqId": [1]])
		XCTAssertEqual(refused.count, 1)
		XCTAssertEqual(refused.first?["error"] as? String, "bad_request")

		XCTAssertEqual(store.reads, 0, "an unknown snapshot reads no key record")
		XCTAssertEqual(store.writes, 0, "an unknown snapshot writes nothing")
		XCTAssertFalse(BeamioNativeKeySnapshot.isKnown)
	}

	/// Y.88 class A (unknown snapshot): hello and passcodeStatus keep their normal answers; they are not not_ready.
	func testClassALifecycleAndStatusKeepTheirAnswersWhileUnknown() {
		BeamioNativeWallet.keyStore = CountingStore(account: account, key: keyData)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnknownForTests(false) }
		let hello = send(["type": "hello", "reqId": 9720])
		XCTAssertEqual(hello.filter { $0["type"] as? String == "ack" && $0["reqId"] as? Int == 9720 }.first?["ok"] as? Bool, true, "hello answers ok")
		let status = send(["type": "passcodeStatus", "reqId": 9721])
		XCTAssertNotEqual(answer(status, 9721), #"{"error":"not_ready","ok":false,"reqId":9721,"type":"ack"}"#, "passcodeStatus is not not_ready")
	}

	/// Y.88 class D (unknown snapshot): a history read answers ok with source not_ready and no data (25.52DL).
	func testClassDHistoryReadAnswersSourceNotReadyWhileUnknown() {
		BeamioNativeWallet.keyStore = CountingStore(account: account, key: keyData)
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnknownForTests(false) }
		XCTAssertEqual(answer(send(["type": "historyRead", "reqId": 9722]), 9722),
		               #"{"ok":true,"reqId":9722,"result":{"source":"not_ready"},"type":"ack"}"#)
	}

	/// Y.88 class E (unknown snapshot): a key-store command answers not_ready once, reads nothing and writes nothing.
	func testClassEKeyStoreCommandsAnswerNotReadyOnceWhileUnknown() {
		let store = CountingStore(account: account, key: keyData)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnknownForTests(false) }
		store.reads = 0
		store.writes = 0
		XCTAssertEqual(answer(send(["type": "send", "reqId": 9723]), 9723),
		               #"{"error":"not_ready","ok":false,"reqId":9723,"type":"ack"}"#)
		XCTAssertEqual(answer(send(["type": "clearIdentity", "reqId": 9724]), 9724),
		               #"{"error":"not_ready","ok":false,"reqId":9724,"type":"ack"}"#)
		XCTAssertEqual(store.reads, 0)
		XCTAssertEqual(store.writes, 0, "clearIdentity deletes nothing while the snapshot is unknown")
	}

	/// Y.88 class B (unknown snapshot): the three entry commands answer not_ready exactly once, and read nothing from the key store.
	func testClassBEntryOpensAnswerNotReadyOnceWhileUnknown() {
		let store = CountingStore(account: account, key: keyData)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnknownForTests(false) }
		store.reads = 0
		store.writes = 0
		for (offset, name) in ["nativeAccountCreateOpen", "nativeRecoveryOpen"].enumerated() {
			let reqId = 9730 + offset
			let events = send(["type": name, "reqId": reqId])
			XCTAssertEqual(events.count, 1, "\(name): exactly one event")
			XCTAssertEqual(answer(events, reqId), #"{"error":"not_ready","ok":false,"reqId":\#(reqId),"type":"ack"}"#, "\(name): not_ready once")
		}
		// r2.3 (spec 第 41(1) 项): nativeImportOpen is not registered: unknown_command, even while the snapshot is unknown.
		let importEvents = send(["type": "nativeImportOpen", "reqId": 9739])
		XCTAssertEqual(importEvents.count, 1)
		XCTAssertEqual(answer(importEvents, 9739), #"{"error":"unknown_command","ok":false,"reqId":9739,"type":"ack"}"#)
		XCTAssertEqual(store.reads, 0, "the entry opens read no key record while the snapshot is unknown")
		XCTAssertEqual(store.writes, 0)
	}

	/// Y.88 class C (unknown snapshot): the family names answer not_ready exactly once, and read and write nothing.
	func testClassCFamilyCommandsAnswerNotReadyOnceWhileUnknown() {
		let store = CountingStore(account: account, key: keyData)
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		defer { BeamioNativeKeySnapshot.pinUnknownForTests(false) }
		store.reads = 0
		store.writes = 0
		for (offset, name) in ["identityPublic", "walletSignMessage", "pgpRestoreEvaluate"].enumerated() {
			let reqId = 9740 + offset
			let events = send(["type": name, "reqId": reqId])
			XCTAssertEqual(events.count, 1, "\(name): exactly one event")
			XCTAssertEqual(answer(events, reqId), #"{"error":"not_ready","ok":false,"reqId":\#(reqId),"type":"ack"}"#, "\(name): not_ready once")
		}
		XCTAssertEqual(store.reads, 0, "a family command reads no key record while the snapshot is unknown")
		XCTAssertEqual(store.writes, 0)
	}

	/// The unknown state ends at the next session start: the same store is judged once, and the answers are those of the known snapshot (G1).
	func testTheNextSessionStartJudgesTheStoreAgain() {
		let store = CountingStore(account: account, key: keyData)
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioNativeKeySnapshot.pinUnknownForTests(true)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9710]), 9710),
		               #"{"ok":true,"reqId":9710,"result":{"notReadyReason":"unreadable","status":"not_ready"},"type":"ack"}"#)
		BeamioNativeKeySnapshot.pinUnknownForTests(false)
		XCTAssertEqual(answer(send(["type": "walletStatus", "reqId": 9711]), 9711),
		#"{"ok":true,"reqId":9711,"result":{"notReadyReason":"g1_uninitialized","status":"not_ready"},"type":"ack"}"#, "known again: G1 names its reason (25.52Y.117)")
		XCTAssertTrue(BeamioNativeKeySnapshot.isKnown)
	}
}
#endif
