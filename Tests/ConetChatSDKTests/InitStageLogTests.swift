import XCTest
@testable import ConetChatSDK

/// The init stage lines (25.52 init diagnostics): the QA line format, the one ack line an init answer writes, and the launch id.
/// Every stage line of one process launch carries the same `launch=` value. Each line carries a reqId, a stage name and a code or a count.
/// No address, key, phrase or record.
final class InitStageLogTests: XCTestCase {
	override func tearDown() {
		BeamioConetChatModule.initQASink = nil
		super.tearDown()
	}

	/// Lets the main queue deliver the events posted asynchronously.
	private func flush() {
		let until = Date().addingTimeInterval(0.2)
		while Date() < until { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
	}

	func testTheQALineIsISOStampedAndCarriesTheFieldsAndTheLaunchId() {
		let line = BeamioConetChatModule.initStageLine(7, "ensureReady", "phase=ok elapsedMs=12", at: Date(timeIntervalSince1970: 0))
		XCTAssertEqual(line, "1970-01-01T00:00:00.000Z [BeamioConetChatInit] reqId=7 stage=ensureReady phase=ok elapsedMs=12 launch=\(BeamioConetChatModule.initLaunchId)")
	}

	func testTheAckDetailCarriesOkCodeAndElapsed() {
		XCTAssertEqual(BeamioConetChatModule.initAckDetail(ok: false, code: "not_ready", elapsedMs: 5), "ok=false code=not_ready elapsedMs=5")
	}

	func testTheLaunchIdIsEightHexCharactersAndStableWithinTheProcess() {
		let id = BeamioConetChatModule.initLaunchId
		XCTAssertNotNil(id.range(of: #"^[0-9A-F]{8}$"#, options: .regularExpression), "8 hex characters, random per launch")
		XCTAssertEqual(BeamioConetChatModule.initLaunchId, id, "one value for the whole process launch")
	}

	func testTheSinkReceivesTheStagesAndTheOneAckOfAnInitWithoutAPayload() {
		// The init answer goes to the page sink that the last command set. This test sets its own collector first and drains
		// the answers of an earlier command, so no event of this test reaches another test's sink.
		var answers: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "initStageLogTestNoop", "reqId": 0], emit: { answers.append(($0["event"] as? [String: Any]) ?? $0) })
		flush()
		answers.removeAll()
		var lines: [String] = []
		BeamioConetChatModule.initQASink = { lines.append($0) }
		BeamioConetChatModule.testHandleInit(["type": "init", "reqId": 5], capabilities: [])
		flush()
		XCTAssertEqual(answers.count, 1, "one answer to the init")
		XCTAssertEqual(answers.first?["error"] as? String, "missing_payload")

		let id = BeamioConetChatModule.initLaunchId
		XCTAssertEqual(lines.count, 3, "start, the payload exit, then the ack")
		XCTAssertTrue(lines[0].hasSuffix(" [BeamioConetChatInit] reqId=5 stage=start entered launch=\(id)"), lines[0])
		XCTAssertTrue(lines[1].hasSuffix(" [BeamioConetChatInit] reqId=5 stage=payload exit=missing_payload launch=\(id)"), lines[1])
		let ackPattern = #" \[BeamioConetChatInit\] reqId=5 stage=ack ok=false code=missing_payload elapsedMs=\d+ launch=[0-9A-F]{8}$"#
		XCTAssertNotNil(lines[2].range(of: ackPattern, options: .regularExpression), lines[2])
		XCTAssertEqual(lines.filter { $0.contains(" stage=ack ") }.count, 1, "one ack per init request")
		// the start line and the ack line carry the same launch id
		XCTAssertEqual(launchValue(lines[0]), launchValue(lines[2]), "start and ack share the launch id")
		XCTAssertEqual(launchValue(lines[0]), id)
		for line in lines {
			XCTAssertNotNil(line.range(of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z "#, options: .regularExpression), line)
			XCTAssertNil(line.range(of: "0x"), "no address in a stage line")
			XCTAssertNil(line.range(of: "mnemonic", options: .caseInsensitive), "no phrase in a stage line")
			XCTAssertNil(line.range(of: "privatekey", options: .caseInsensitive), "no key in a stage line")
		}
	}

	/// The value after the last ` launch=` of a stage line.
	private func launchValue(_ line: String) -> String? {
		line.components(separatedBy: " launch=").last
	}
}

/// The init path logs no part of an address (25.52 init diagnostics, project rulingon the EOA-prefix NSLog). A source check:
/// no NSLog line in the conet chat module prints a prefix or a value of an account.
final class InitLogNoAddressTests: XCTestCase {
	func testNoNSLogOfTheConetChatModulePrintsAnAccountPrefix() throws {
		let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
			.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
			.appendingPathComponent("Sources/ConetChatSDK/BeamioConetChatModule.swift"), encoding: .utf8)
		for line in source.components(separatedBy: "\n") where line.contains("NSLog(") {
			XCTAssertNil(line.range(of: #"prefix\("#), "no address prefix in a log line: \(line)")
		}
	}
}
