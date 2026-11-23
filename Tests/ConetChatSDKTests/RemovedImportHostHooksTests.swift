import XCTest

/// r2.5.18 第 59(6) 项 (and 第 41 项): the four host hooks of the removed native import page are deleted, not kept. They are
/// `onImportRequired`, `requestImportIfMissing`, `armPageResult` and `reportPageResult`. The tests that used them assert their absence.
/// The check reads the SDK sources from this file's location (`Sources/ConetChatSDK`), so a reintroduced name fails the run.
enum RemovedImportHostHooks {
	static let names = ["onImportRequired", "requestImportIfMissing", "armPageResult", "reportPageResult"]

	/// The SDK source files of this checkout, by name and text.
	static func sourceFiles() throws -> [(name: String, text: String)] {
		let root = URL(fileURLWithPath: #filePath)
			.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
		let dir = root.appendingPathComponent("Sources/ConetChatSDK", isDirectory: true)
		let urls = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
			.filter { $0.pathExtension == "swift" }
		return try urls.map { (name: $0.lastPathComponent, text: try String(contentsOf: $0, encoding: .utf8)) }
	}

	/// Asserts that none of the four names appears in the SDK source. Nothing is called, nothing is read from the store.
	static func assertAbsent(file: StaticString = #filePath, line: UInt = #line) {
		do {
			let files = try sourceFiles()
			XCTAssertFalse(files.isEmpty, "the SDK sources are found from the test file's path", file: file, line: line)
			for name in names {
				let hits = files.filter { $0.text.contains(name) }.map { $0.name }
				XCTAssertEqual(hits, [], "\(name) is removed (第 59(6) 项); found in \(hits)", file: file, line: line)
			}
		} catch {
			XCTFail("the SDK sources could not be read: \(error)", file: file, line: line)
		}
	}
}

final class RemovedImportHostHooksTests: XCTestCase {
	func testTheFourHostHooksAreNotInTheSDKSource() {
		RemovedImportHostHooks.assertAbsent()
	}
}
