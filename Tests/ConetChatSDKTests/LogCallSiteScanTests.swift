#if BEAMIO_TEST_HOOKS
import XCTest

/// SC-05 (static): no logging call of the SDK carries a passcode, a phrase, a derived key or an envelope. Every call of `NSLog`, `os_log`, `Logger`, `print`, `debugPrint`, `dump`,
/// `String(describing:)` and `String(reflecting:)` in the SDK sources is read with its whole argument list (the text of string literals is dropped, interpolations and the
/// arguments are kept), and a secret-named identifier in it fails the test. The shell's own sources are not in this repository; its call sites are scanned by its own suite.
final class LogCallSiteScanTests: XCTestCase {
	private static let sourcesDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
		.appendingPathComponent("Sources/ConetChatSDK")

	private static let call = try! NSRegularExpression(pattern: #"\b(NSLog|os_log|print|debugPrint|dump)\(|\b(Logger|logger|log)\.(log|debug|info|notice|error|fault|warning)\(|String\((describing|reflecting):"#)
	private static let secretName = try! NSRegularExpression(pattern: #"\b(passcode|passphrase|phrase|mnemonic|privateKey|sessionKey|derivedKey|derived|secret|envelope|cipher|bundle|seed|plain|plaintext)\b"#, options: .caseInsensitive)
	private static let literal = try! NSRegularExpression(pattern: #""(?:[^"\\]|\\.)*""#)
	private static let interpolation = try! NSRegularExpression(pattern: #"\\\((.*?)\)"#)

	private func ranges(_ rx: NSRegularExpression, in s: String) -> [NSRange] { rx.matches(in: s, range: NSRange(s.startIndex..., in: s)).map { $0.range } }

	func testNoLoggingCallOfTheSdkCarriesASecret() throws {
		let files = try FileManager.default.contentsOfDirectory(at: Self.sourcesDirectory, includingPropertiesForKeys: nil).filter { $0.pathExtension == "swift" }
		XCTAssertGreaterThan(files.count, 100, "the sources are found")
		var scanned = 0
		var hits: [String] = []
		for file in files {
			let lines = try String(contentsOf: file, encoding: .utf8).components(separatedBy: "\n")
			for (index, line) in lines.enumerated() {
				if line.trimmingCharacters(in: .whitespaces).hasPrefix("//") { continue }
				guard let match = Self.call.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)), let start = Range(match.range, in: line)?.lowerBound else { continue }
				var span = String(line[start...])
				var next = index
				while span.filter({ $0 == "(" }).count > span.filter({ $0 == ")" }).count, next < index + 5, next + 1 < lines.count {
					next += 1
					span += " " + lines[next].trimmingCharacters(in: .whitespaces)
				}
				scanned += 1
				// drop a trailing comment, then the text of the literals (interpolations stay)
				if let comment = span.range(of: " // ") { span = String(span[..<comment.lowerBound]) }
				var kept = span
				for r in ranges(Self.literal, in: span).reversed() {
					guard let swiftRange = Range(r, in: kept) else { continue }
					let literal = String(kept[swiftRange])
					let inner = ranges(Self.interpolation, in: literal).compactMap { Range($0, in: literal).map { String(literal[$0]) } }.joined(separator: " ")
					kept.replaceSubrange(swiftRange, with: inner)
				}
				if !ranges(Self.secretName, in: kept).isEmpty { hits.append("\(file.lastPathComponent):\(index + 1)") }
			}
		}
		XCTAssertGreaterThan(scanned, 50, "the scan reads real logging call sites")
		XCTAssertTrue(hits.isEmpty, "SC-05: a logging call carries a secret-named value at \(hits)")
	}
}
#endif
