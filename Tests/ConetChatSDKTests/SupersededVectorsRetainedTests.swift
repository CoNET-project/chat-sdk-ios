import XCTest

/// The two vector files that the v3 files supersede stay in the test resources, byte for byte (registered sha256). No test runs them: the answer-shape
/// and unreadable-cause tests run the v3 files (the B rule: an unreadable reason that a retry never cures is final at the first answer). This test only
/// proves that the retained files are present and unchanged; `BundledVectorFile.data` checks the digest and fails, never skips.
final class SupersededVectorsRetainedTests: XCTestCase {
	func testSupersededVectorsAreRetainedUnchanged() throws {
		for name in ["shell-record-read-answer-shape.v1", "unreadable-cause.v2"] {
			XCTAssertFalse(try BundledVectorFile.data(resource: name).isEmpty, name)
		}
	}
}
