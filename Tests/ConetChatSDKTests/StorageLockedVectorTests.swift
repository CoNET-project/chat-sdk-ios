import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The `storageLocked` group of `negative-tests-v1.json` (, to). A storage-derived Locked: the key record exists and
/// the native side cannot read it (the session is ready for the account). The family commands, the C4 function, `walletStatus` and the route
/// registration answer `not_ready`, once, before the parameters; `no_key` is only for a record that is confirmed absent; `locked` is for the passcode
/// lock. The registered digest is `86b836ef…aaef`. The test store reports the record as unreadable. Synthetic data only.
final class StorageLockedVectorTests: XCTestCase {
	/// A store whose record exists and cannot be read: `read` gives nothing, and the state says unreadable.
	private final class UnreadableStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { nil }
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .unreadable }
	}

	private let account = PgpMigrationTestSupport.eoa

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["NEGATIVE_TESTS"] else {
			throw XCTSkip("set NEGATIVE_TESTS to interface/protocol/negative-tests-v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == "86b836ef90586a665acfe1d935e5b3e10236a4cad07e7f93ef252ef4ef82aaef",
		              "the negative-tests file differs from the registered digest (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// G2 for the account, with the key record unreadable. Returns the restore closure.
	private func arrangeStorageLocked() -> () -> Void {
		let savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		BeamioNativeWallet.keyStore = UnreadableStore()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		return {
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
	}

	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	/// T-133-01 to T-133-15 and T-133-19 (,): each row answers the vector's code once. T-133-19 carries a credential field, and it
	/// answers `key_over_bridge_refused` before the lock. T-133-05 is `chatRouteRegister`, answered in its own path.
	func testTheStorageDerivedLockedFamiliesAnswerTheVectorOnce() throws {
		let section = try vectorUnwrap { try vectorRoot()["storageLocked"] as? [String: Any] }
		let cases = try XCTUnwrap(section["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 16, "the storageLocked group has 16 cases")
		var failures: [String] = []
		for (index, c) in cases.enumerated() {
			let id = c["id"] as? String ?? "?"
			guard let name = (c["commands"] as? [String])?.first else {
				failures.append("\(id): no bridge name in the vector")
				continue
			}
			let reqId = 9300 + index
			let expectCode = c["expect"] as? String ?? ""
			let restore = arrangeStorageLocked()
			var body: [String: Any] = ["type": name, "reqId": reqId]
			if let field = c["credentialField"] as? String { body[field] = "SYNTHETIC-CREDENTIAL" }
			let events = dispatch(body)
			restore()
			let acks = events.filter { $0["reqId"] as? Int == reqId }
			let got = acks.first?["error"] as? String ?? "no ack"
			print("STORAGE-LOCKED-RUN \(id) \(name): \(got == expectCode ? "matches the vector" : "differs: \(got) (expected \(expectCode))")")
			if acks.count != 1 || got != expectCode || events.count != 1 {
				failures.append("\(id) \(name): got \(got), \(acks.count) answers, expected \(expectCode)")
			}
		}
		XCTAssertTrue(failures.isEmpty, "storage-derived Locked answers that differ from the vector: \(failures.joined(separator: "; "))")
	}

	/// T-133-C4: the native C4 function answers `not_ready` with no signature while the record is unreadable. `pgp_locked` is for the
	/// passcode lock only.
	func testTheC4FunctionAnswersNotReadyWhenTheRecordIsUnreadable() throws {
		let section = try vectorUnwrap { try vectorRoot()["storageLocked"] as? [String: Any] }
		let nativeOnly = try XCTUnwrap(section["nativeOnly"] as? [[String: Any]])
		XCTAssertEqual(nativeOnly.count, 1, "one native-only row")
		let savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = UnreadableStore()
		defer { BeamioNativeWallet.keyStore = savedStore }
		let result = BeamioNativeWallet.pgpSign(eoa: account, purposeId: "chatEnvelope", sigType: 0x00, data: Data([1]))
		if case .success = result { XCTFail("C4 signed with an unreadable record") }
		XCTAssertEqual(result.failureRefusalCode, "not_ready", "T-133-C4: the refusal is not_ready, not pgp_locked")
	}

	/// `walletStatus` answers `not_ready` with no accountKey, and never `unlocked`.
	func testWalletStatusAnswersNotReadyWithoutAnAccountKey() {
		let restore = arrangeStorageLocked()
		defer { restore() }
		let events = dispatch(["type": "walletStatus", "reqId": 9400])
		let ack = events.first { $0["reqId"] as? Int == 9400 }
		XCTAssertEqual(ack?["ok"] as? Bool, true)
		let result = ack?["result"] as? [String: Any]
		XCTAssertEqual(result?["status"] as? String, "not_ready", "the status is not_ready")
		XCTAssertNil(result?["accountKey"], "no accountKey is returned")
	}
	/// under a storage-derived Locked the five history reads answer `{ok:true, result:{source:"not_ready"}}`, once, with no data.
	func testHistoryReadsAnswerNotReadyAsABusinessResult() {
		let names = ["historyRead", "historyLoad", "historyLoadOlder", "historyListConversations", "historyOpenConversation"]
		for (index, name) in names.enumerated() {
			let restore = arrangeStorageLocked()
			let reqId = 9600 + index
			let events = dispatch(["type": name, "reqId": reqId])
			restore()
			XCTAssertEqual(events.count, 1, "\(name): one answer")
			let ack = events.first { $0["reqId"] as? Int == reqId }
			XCTAssertEqual(ack?["type"] as? String, "ack", name)
			XCTAssertEqual(ack?["ok"] as? Bool, true, "\(name): ok")
			XCTAssertNil(ack?["error"], "\(name): no error")
			let result = ack?["result"] as? [String: Any]
			XCTAssertEqual(result?["source"] as? String, "not_ready", "\(name): source not_ready")
			XCTAssertEqual(result?.keys.sorted(), ["source"], "\(name): no data")
		}
	}

	/// a history delete while the key record is unreadable answers `not_ready`, once, and deletes nothing (not `busy`).
	func testHistoryDeletesAnswerNotReadyWhenTheRecordIsUnreadable() {
		for (index, type) in ["historyDeleteMessage", "historyDeleteConversation"].enumerated() {
			let restore = arrangeStorageLocked()
			let reqId = 9500 + index
			let events = dispatch(["type": type, "reqId": reqId, "convKey": "0x" + String(repeating: "a", count: 40), "messageId": "m1"])
			restore()
			let acks = events.filter { $0["reqId"] as? Int == reqId }
			XCTAssertEqual(acks.count, 1, "\(type): one answer")
			XCTAssertEqual(acks.first?["ok"] as? Bool, false, type)
			XCTAssertEqual(acks.first?["error"] as? String, "not_ready", "\(type): not_ready")
		}
	}
}

private extension Result where Success == Data, Failure == BeamioNativeWallet.Failure {
	/// The refusal code of a failed C4 call (nil when it signed or has no code).
	var failureRefusalCode: String? {
		if case .failure(let f) = self { return f.refusalCode }
		return nil
	}
}
