#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The guard of the test isolation: while the tests ran, nothing in the product's `Application Support/ConetChat` was added, removed or modified. The class name
/// puts it last in the default order; the snapshot was taken at the first use of a test-build path helper. Run alone it only proves the helpers point elsewhere.
final class ZZProductPathGuardTests: XCTestCase {
	/// The test directories of this process are removed when the guard has run (it is the last class of the default order): the inbox folder with the local library,
	/// and the page-copy store's isolated directory.
	override func tearDown() {
		let pid = ProcessInfo.processInfo.processIdentifier
		let tmp = FileManager.default.temporaryDirectory
		for name in (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? [] {
			if name == "beamio-conetchat-test-\(pid)" || name.hasPrefix("beamio-shell-record-test-\(pid)-") {
				try? FileManager.default.removeItem(at: tmp.appendingPathComponent(name))
			}
		}
		super.tearDown()
	}

	private var baselineBeforeThisTest = false

	override func setUp() {
		super.setUp()
		// read before this test touches any helper: a baseline that exists now was taken by an earlier test of the suite
		baselineBeforeThisTest = BeamioProductPathGuard.baselineWasTaken
	}

	/// The verdict logic itself: a late baseline fails, an early one passes unless something changed. (Proves the late-baseline assertion is live.)
	func testTheVerdictFailsALateBaselineAndAChange() {
		XCTAssertNotNil(BeamioProductPathGuard.verdict(baselineTakenBeforeGuard: false, changes: []), "a late baseline is a failure")
		XCTAssertNotNil(BeamioProductPathGuard.verdict(baselineTakenBeforeGuard: true, changes: ["modified x"]))
		XCTAssertNil(BeamioProductPathGuard.verdict(baselineTakenBeforeGuard: true, changes: []))
	}

	func testTheTestsNeverTouchTheProductDirectories() {
		let roots = BeamioProductPathGuard.productRoots.map { $0.standardizedFileURL.path }
		XCTAssertEqual(roots.count, 2)
		let testPaths: [URL?] = [
			BeamioInboxFile.folder, BeamioConetChatLocalStore.defaultRootDirectory(),
			BeamioShellRecord.EncryptedShellRecordStore.testIsolatedDirectory, BeamioShellRecord.testDeviceStateURLForTests,
		]
		for url in testPaths {
			let path = url?.standardizedFileURL.path ?? ""
			XCTAssertFalse(path.isEmpty)
			for root in roots { XCTAssertFalse(path.hasPrefix(root), "a test path is inside a product directory: \(path)") }
		}
		XCTAssertNil(
			BeamioProductPathGuard.verdict(baselineTakenBeforeGuard: baselineBeforeThisTest, changes: BeamioProductPathGuard.changes()),
			"the product directories (ConetChat with local-v1, beamio-shell-record)"
		)
	}
}
#endif
