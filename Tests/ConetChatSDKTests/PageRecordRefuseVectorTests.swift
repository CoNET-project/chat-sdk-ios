import XCTest
@testable import ConetChatSDK

/// The page-record refusal vectors. Each case is a `shellRecordWrite` that is refused before anything is
/// stored: a PGP forbidden path (`pgp_private_in_payload`), a key-shaped name (`key_shaped_content`), or a name outside the whitelist (`bad_request`).
/// `key_over_bridge_refused` is not used for `shellRecordWrite`. The account placeholder "a1" maps to the account address. Synthetic data only.
final class PageRecordRefuseVectorTests: XCTestCase {
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

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PAGE_RECORD_REFUSE_VECTORS"] else {
			throw XCTSkip("set PAGE_RECORD_REFUSE_VECTORS to interface/protocol/page-record-refuse-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func environment(account: String, store: Store, migrating: Bool) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { account },
			store: store,
			device: Device(),
			originAllowed: true,
			migrating: { _ in migrating },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved
		)
	}

	func testThePageRecordRefusalsMatchTheVectors() throws {
		let cases = PgpMigrationTestSupport.sidecar(try vectorRoot()["cases"] as Any) as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 4, "PR-02, PR-02b, PR-03, PR-04")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let ctx = c["ctx"] as? [String: Any] ?? [:]
			let account = PgpMigrationTestSupport.eoa
			let store = Store()
			let record = c["req"] as? [String: Any] ?? [:]
			let body: [String: Any] = ["type": "shellRecordWrite", "reqId": "pr-\(id)", "record": record]
			let answer = BeamioShellRecord.answer(
				body,
				env: environment(account: account, store: store, migrating: (ctx["migrating"] as? Bool) == true)
			)
			let expect = c["expect"] as? [String: Any] ?? [:]
			XCTAssertEqual(answer["code"] as? String, expect["code"] as? String, "\(id): code")
			XCTAssertEqual(answer["names"] as? [String], expect["names"] as? [String], "\(id): names, UTF-8 order, never values")
			XCTAssertTrue(store.records.isEmpty, "\(id): nothing is stored")
			XCTAssertNil(store.records[account], "\(id): the store stays absent")
		}
	}
}
