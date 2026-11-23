#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// `hello.nativeApp` (project owner, 2026-11-21; interface spec v158 section 178): the installed host app's version and build, read at run time from the
/// host's main bundle and checked by form. No configuration entry, no default, no SDK version.
final class NativeAppVersionTests: XCTestCase {
	override func tearDown() {
		BeamioConetChatProtocol.hostInfoOverride = nil
		super.tearDown()
	}

	private func hello() -> [String: Any] { BeamioConetChatProtocol.helloResult() }

	func testTheHostBundleValuesAreReportedAsTheyAre() throws {
		BeamioConetChatProtocol.hostInfoOverride = { ["CFBundleShortVersionString": "1.5.9", "CFBundleVersion": "105"] }
		XCTAssertEqual(try XCTUnwrap(hello()["nativeApp"] as? [String: String]), ["platform": "ios", "version": "1.5.9", "build": "105"])
		// another host bundle gives other values: nothing is a constant
		BeamioConetChatProtocol.hostInfoOverride = { ["CFBundleShortVersionString": "2.0.0", "CFBundleVersion": "7"] }
		let app = try XCTUnwrap(hello()["nativeApp"] as? [String: String])
		XCTAssertEqual(app["version"], "2.0.0")
		XCTAssertEqual(app["build"], "7")
		for version in ["1.0", "1.2.3", "1.2.3.4"] {
			BeamioConetChatProtocol.hostInfoOverride = { ["CFBundleShortVersionString": version, "CFBundleVersion": "1"] }
			XCTAssertEqual((hello()["nativeApp"] as? [String: String])?["version"], version, version)
		}
	}

	func testItIsNotTheSdkVersionAndTheSdkVersionStaysItsOwnField() throws {
		BeamioConetChatProtocol.hostInfoOverride = { ["CFBundleShortVersionString": "9.9.9", "CFBundleVersion": "99"] }
		let app = try XCTUnwrap(hello()["nativeApp"] as? [String: String])
		XCTAssertNotEqual(app["version"], BeamioConetChatProtocol.sdkVersion)
		XCTAssertEqual(hello()["sdkVersion"] as? String, BeamioConetChatProtocol.sdkVersion)
	}

	func testAMissingKeyANonStringAnEmptyValueOrAnotherFormGivesNoField() {
		let cases: [[String: Any]?] = [
			nil, [:], ["CFBundleShortVersionString": "1.0"], ["CFBundleVersion": "1"],
			["CFBundleShortVersionString": "", "CFBundleVersion": "1"], ["CFBundleShortVersionString": "1.0", "CFBundleVersion": ""],
			["CFBundleShortVersionString": 1.0, "CFBundleVersion": 1], ["CFBundleShortVersionString": ["1"], "CFBundleVersion": "1"],
			["CFBundleShortVersionString": "1", "CFBundleVersion": "1"], ["CFBundleShortVersionString": "1.", "CFBundleVersion": "1"],
			["CFBundleShortVersionString": "1.2.3.4.5", "CFBundleVersion": "1"], ["CFBundleShortVersionString": "v1.2", "CFBundleVersion": "1"],
			["CFBundleShortVersionString": "1.2-beta", "CFBundleVersion": "1"], ["CFBundleShortVersionString": " 1.2", "CFBundleVersion": "1"],
			["CFBundleShortVersionString": "1.2\n", "CFBundleVersion": "1"], ["CFBundleShortVersionString": "1.2.3\n", "CFBundleVersion": "1"],
			["CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "5\n"], ["CFBundleShortVersionString": "1.2.3\r\n", "CFBundleVersion": "5"], ["CFBundleShortVersionString": "1.a", "CFBundleVersion": "1"],
			["CFBundleShortVersionString": "1.2", "CFBundleVersion": "x"], ["CFBundleShortVersionString": "1.2", "CFBundleVersion": "1.2"],
			["CFBundleShortVersionString": "1.2", "CFBundleVersion": " 1"], ["CFBundleShortVersionString": "1.2", "CFBundleVersion": "-1"],
		]
		for info in cases {
			BeamioConetChatProtocol.hostInfoOverride = { info }
			XCTAssertNil(hello()["nativeApp"], "\(String(describing: info))")
			XCTAssertNil(BeamioConetChatProtocol.nativeApp())
		}
	}

	func testTheDefaultReadsTheMainBundleNotTheSdkBundle() {
		BeamioConetChatProtocol.hostInfoOverride = nil
		let main = Bundle.main.infoDictionary
		let version = main?["CFBundleShortVersionString"] as? String
		let build = main?["CFBundleVersion"] as? String
		let valid = version.map { $0.range(of: #"^\d+(\.\d+){1,3}$"#, options: .regularExpression) != nil } == true
			&& build.map { $0.range(of: #"^\d+$"#, options: .regularExpression) != nil } == true
		if valid, let version, let build {
			XCTAssertEqual(BeamioConetChatProtocol.nativeApp(), ["platform": "ios", "version": version, "build": build])
		} else {
			XCTAssertNil(BeamioConetChatProtocol.nativeApp(), "a main bundle that does not say, or says another form, gives no field")
		}
	}

	/// Source guard (v158 section 178): the host's main bundle is read here, the SDK's resource bundle is not, and no configuration entry exists.
	func testTheSourceReadsTheMainBundleAndHasNoConfigurationEntry() throws {
		let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
			.appendingPathComponent("Sources/ConetChatSDK/BeamioConetChatProtocol.swift")
		guard let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) else { throw XCTSkip("SDK sources not readable in this run") }
		XCTAssertTrue(text.contains("Bundle.main.infoDictionary"))
		XCTAssertTrue(text.contains("CFBundleShortVersionString") && text.contains("CFBundleVersion"))
		XCTAssertFalse(text.contains("Bundle.module"), "the SDK's resource bundle is not the host")
		XCTAssertFalse(text.contains("configureNativeApp"), "no configuration entry (v157 section 177 is void)")
		// the seam that replaces the host Info dictionary exists only in a test build
		let seam = try XCTUnwrap(text.range(of: "static var hostInfoOverride"))
		let before = text[..<seam.lowerBound]
		XCTAssertTrue(before.suffix(300).contains("#if BEAMIO_TEST_HOOKS"), "the override is inside the test hooks")
	}
}
#endif
