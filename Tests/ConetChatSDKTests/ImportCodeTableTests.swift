import XCTest
@testable import ConetChatSDK

/// The import result code table (spec table, (c), (e)): `rollback_pending` is registered, and every import outcome
/// answers a code of the table, or one of the three codes that are not rows of it (`ok`, `cancelled`, `unavailable`).
final class ImportCodeTableTests: XCTestCase {
	/// The rows of the spec table, in the spec's order.
	private let specRows = [
		"invalid_format", "invalid_key", "invalid_mnemonic", "address_mismatch", "already_exists",
		"write_failed", "readback_failed", "rollback_pending",
	]

	func testTheCodeTableHasTheSpecRowsInOrder() {
		XCTAssertEqual(BeamioNativeKeyImport.codeTable.map { $0.code }, specRows)
	}

	func testRollbackPendingIsRegisteredWithItsCopyKey() {
		let row = BeamioNativeKeyImport.codeTable.first { $0.code == "rollback_pending" }
		XCTAssertEqual(row?.copyKey, "imp.err.rollback")
		XCTAssertEqual(BeamioNativeKeyImport.Outcome.rollbackPending.code, "rollback_pending")
	}

	func testEveryOutcomeAnswersATableCodeOrOneOfTheThreeNonRowCodes() {
		let outcomes: [BeamioNativeKeyImport.Outcome] = [
			.imported, .alreadyPresent, .invalidFormat, .invalidMnemonic, .invalidKey, .addressMismatch,
			.writeFailed, .readBackFailed, .cancelled, .unavailable, .rollbackPending,
		]
		let nonRows: Set<String> = ["ok", "cancelled", "unavailable"]
		let rows = Set(specRows)
		for outcome in outcomes {
			XCTAssertTrue(rows.contains(outcome.code) || nonRows.contains(outcome.code), "\(outcome) answers \(outcome.code)")
		}
	}
}
