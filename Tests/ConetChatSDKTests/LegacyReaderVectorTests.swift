#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// item 11: the legacy store is `absent` only when its directory is missing or readable and empty. Every other
/// unreadable, CRC-failed, truncated, empty or record-less entry makes it `unreadable`, and a store with one such entry is never `found`. The cases are
/// the `legacyReaderCases` of `pgp-migration-vectors` (LR-01 to LR-11). The judgement is checked here; the read answers follow from it through
/// `reportLegacyStore`, and LR-11 (Plan N import) is the same judgement, which must stop an import before it starts.
final class LegacyReaderVectorTests: XCTestCase {
	private func vectorRoot() throws -> [String: Any] {
		// xcodebuild strips the TEST_RUNNER_ prefix before the test process starts, so the plain name is the one that arrives there.
		// The prefixed name is still accepted for a run that sets it on the process itself.
		let env = ProcessInfo.processInfo.environment
		guard let path = env["PGP_MIGRATION_VECTORS"] ?? env["TEST_RUNNER_PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	func testTheLegacyReaderCasesMatchTheVectors() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["legacyReaderCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 16, "LR-01 to LR-16")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			let files = (input["files"] as? [[String: Any]] ?? []).map { f -> BeamioShellRecord.LegacyFileFacts in
				let valid = f["validRecords"] as? Int ?? 0
				return BeamioShellRecord.LegacyFileFacts(
					readable: f["readable"] as? Bool ?? true,
					crcOk: f["crcOk"] as? Bool ?? true,
					truncated: f["truncated"] as? Bool ?? false,
					validRecords: valid,
					// LR-03 and the other vectors without the field: every valid record is a wallet record.
					walletRecords: f["walletRecords"] as? Int ?? valid)
			}
			let got = BeamioShellRecord.judgeLegacyStore(
				dirExists: input["dirExists"] as? Bool ?? false,
				listOk: input["listOk"] as? Bool ?? true,
				files: files)
			let want: BeamioShellRecord.LegacyStoreJudgement
			switch c["expectState"] as? String {
			case "absent": want = .absent
			case "found": want = .found
			default: want = .unreadable
			}
			XCTAssertEqual(got, want, "\(id): the legacy store state")
		}
	}

	/// An empty entry holds no record: it is truncated (fewer bytes than a sealed record) and counts as unreadable, never as found.
	func testAnEmptyEntryIsTruncatedAndHoldsNoRecord() throws {
		let url = FileManager.default.temporaryDirectory.appendingPathComponent("lr-empty-\(UUID().uuidString).bin")
		XCTAssertTrue(FileManager.default.createFile(atPath: url.path, contents: Data()))
		defer { try? FileManager.default.removeItem(at: url) }
		let facts = BeamioShellRecord.legacyFileFacts(at: url)
		XCTAssertTrue(facts.truncated, "a zero-byte entry is truncated")
		XCTAssertEqual(facts.validRecords, 0)
		XCTAssertEqual(BeamioShellRecord.judgeLegacyStore(dirExists: true, listOk: true, files: [facts]), .unreadable)
	}

	/// A missing entry cannot be read: it is unreadable, not absent.
	func testAnEntryThatCannotBeReadIsUnreadable() {
		let url = FileManager.default.temporaryDirectory.appendingPathComponent("lr-missing-\(UUID().uuidString).bin")
		let facts = BeamioShellRecord.legacyFileFacts(at: url)
		XCTAssertFalse(facts.readable)
		XCTAssertEqual(BeamioShellRecord.judgeLegacyStore(dirExists: true, listOk: true, files: [facts]), .unreadable)
	}
}
#endif
