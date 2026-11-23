import XCTest
@testable import ConetChatSDK

/// The QA line of a shellRecordRead answer carries the reqId and the enum names only (not_ready reason, sub, cause class).
final class QAShellReadLineTests: XCTestCase {
	func testNotReadyG1CarriesReasonAndRetryable() {
		let answer = BeamioShellRecord.notReadyAnswer(reason: BeamioShellRecord.notReadyG1Uninitialized, retryable: true, reqId: 7)
		XCTAssertEqual(BeamioConetChatModule.qaShellReadLine(reqId: 7, answer: answer),
		               "reqId=7 code=not_ready sub=- reason=g1_uninitialized retryable=true cause=-")
	}

	func testPersistentCarriesSubReasonAndCause() {
		let base: [String: Any] = ["code": "not_ready", "notReadyReason": "unreadable", "retryable": true, "unreadableCause": "device_locked", "reqId": 9]
		var last: [String: Any] = [:]
		BeamioShellRecord.resetNotReadyStreakForTests()
		for _ in 0...BeamioShellRecord.notReadyPersistenceLimit { last = BeamioShellRecord.applyPersistenceLimit(base) }
		XCTAssertEqual(BeamioConetChatModule.qaShellReadLine(reqId: 9, answer: last),
		               "reqId=9 code=error sub=not_ready_persistent reason=unreadable retryable=true cause=device_locked")
		BeamioShellRecord.resetNotReadyStreakForTests()
	}

	func testEnvelopeShapeAndMissingReqId() {
		let envelope: [String: Any] = ["result": ["code": "ok"]]
		XCTAssertEqual(BeamioConetChatModule.qaShellReadLine(reqId: nil, answer: envelope),
		               "reqId=- code=ok sub=- reason=- retryable=- cause=-")
	}

	func testNothingButEnumWordsCanEnterTheLine() {
		let hostile: [String: Any] = ["code": "error", "sub": "0xAbC123 account@host", "notReadyReason": String(repeating: "a", count: 41),
		                              "unreadableCause": "has space", "retryable": true]
		// a 40-digit hex string (an address body or a key fragment) is not in any closed set
		XCTAssertEqual(BeamioConetChatModule.qaShellReadLine(reqId: 1, answer: ["code": "error", "sub": String(repeating: "ab", count: 20)]),
		               "reqId=1 code=error sub=? reason=- retryable=- cause=-")
		XCTAssertEqual(BeamioConetChatModule.qaShellReadLine(reqId: 1, answer: ["code": "deadbeef", "notReadyReason": "made_up", "unreadableCause": "keychain"]),
		               "reqId=1 code=? sub=- reason=? retryable=- cause=?")
		XCTAssertEqual(BeamioConetChatModule.qaShellReadLine(reqId: 1, answer: hostile),
		               "reqId=1 code=error sub=? reason=? retryable=true cause=?")
	}

	func testEchoedReqIdTakesIntegersOnly() {
		XCTAssertEqual(BeamioShellRecord.echoedReqId(["reqId": 12]), 12)
		XCTAssertNil(BeamioShellRecord.echoedReqId(["reqId": "12"]))
		XCTAssertNil(BeamioShellRecord.echoedReqId(["reqId": true]))
		XCTAssertNil(BeamioShellRecord.echoedReqId([:]))
	}
}

final class QAPrereadLineTests: XCTestCase {
	func testStateAndFlagsOnly() {
		let envelope: [String: Any] = ["type": "ack", "reqId": 4, "ok": true, "result": ["code": "read_error"]]
		XCTAssertEqual(BeamioConetChatModule.qaPrereadLine(reqId: 4, snapshotKnown: true, storageLocked: true, envelope: envelope),
		               "reqId=4 snapshotKnown=true storageLocked=true state=read_error error=-")
	}

	func testValidNeverCarriesAccountOrPhrase() {
		let envelope: [String: Any] = ["ok": true, "result": ["code": "ok", "eoa": "0xabc", "mnemonic": "word word word"]]
		let line = BeamioConetChatModule.qaPrereadLine(reqId: 5, snapshotKnown: true, storageLocked: false, envelope: envelope)
		XCTAssertEqual(line, "reqId=5 snapshotKnown=true storageLocked=false state=ok error=-")
		XCTAssertFalse(line.contains("0xabc") || line.contains("word"))
	}

	func testErrorWordAndHostileText() {
		let stale: [String: Any] = ["ok": false, "error": "stale_seq"]
		XCTAssertEqual(BeamioConetChatModule.qaPrereadLine(reqId: nil, snapshotKnown: false, storageLocked: false, envelope: stale),
		               "reqId=- snapshotKnown=false storageLocked=false state=- error=stale_seq")
		let hostile: [String: Any] = ["ok": false, "error": "Has Space"]
		XCTAssertTrue(BeamioConetChatModule.qaPrereadLine(reqId: 1, snapshotKnown: true, storageLocked: false, envelope: hostile).hasSuffix("error=?"))
	}
}
