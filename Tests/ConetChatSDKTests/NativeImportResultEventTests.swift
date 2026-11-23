import XCTest
@testable import ConetChatSDK

/// `nativeImportResult` (25.52Y.95 第 2 条, 25.52Y.97): the five wire codes, the eoa rule, and one result per opened page.
/// Synthetic key 0x11…11 only.
final class NativeImportResultEventTests: XCTestCase {
	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		super.tearDown()
	}

	private let keyHex = String(repeating: "11", count: 32)
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

	func testEveryOutcomeMapsToOneOfTheFiveWireCodes() {
		let table: [(BeamioNativeKeyImport.Outcome, String)] = [
			(.imported, "ok"),
			(.alreadyPresent, "already_exists"),
			(.invalidFormat, "bad_request"),
			(.invalidMnemonic, "bad_request"),
			(.invalidKey, "bad_request"),
			(.addressMismatch, "import_failed"),
			(.writeFailed, "import_failed"),
			(.readBackFailed, "import_failed"),
			(.rollbackPending, "import_failed"),
			(.unavailable, "import_failed"),
			(.cancelled, "cancelled"),
		]
		for (outcome, code) in table {
			XCTAssertEqual(outcome.wireCode, code, "\(outcome)")
		}
		XCTAssertEqual(Set(table.map { $0.1 }), ["ok", "already_exists", "bad_request", "import_failed", "cancelled"])
	}

	func testTheEventCarriesEoaOnlyForOkAndAlreadyExists() {
		let withAccount = BeamioNativeKeyImport.resultEvent(reqId: 1, report: .init(outcome: .imported, eoa: eoa))
		XCTAssertEqual(withAccount["type"] as? String, "nativeImportResult")
		XCTAssertEqual(withAccount["code"] as? String, "ok")
		XCTAssertEqual(withAccount["eoa"] as? String, eoa)
		let exists = BeamioNativeKeyImport.resultEvent(reqId: 2, report: .init(outcome: .alreadyPresent, eoa: eoa))
		XCTAssertEqual(exists["code"] as? String, "already_exists")
		XCTAssertEqual(exists["eoa"] as? String, eoa)
		// An eoa handed to any other result is not forwarded.
		for outcome: BeamioNativeKeyImport.Outcome in [.invalidKey, .addressMismatch, .writeFailed, .cancelled, .rollbackPending] {
			let event = BeamioNativeKeyImport.resultEvent(reqId: 3, report: .init(outcome: outcome, eoa: eoa))
			XCTAssertNil(event["eoa"], "\(outcome) carries no eoa")
			XCTAssertEqual(Set(event.keys), ["type", "reqId", "code"], "\(outcome): only type, reqId and code")
		}
	}

	func testAnImportedKeyReportsItsDerivedAccountInLowerCase() {
		let store = BeamioNativeKeyImportTests.InjectedStore()
		let report = BeamioNativeKeyImport.importPrivateKeyReport(text: keyHex, expectedEoa: "", store: store)
		XCTAssertEqual(report.outcome, .imported)
		XCTAssertEqual(report.eoa, eoa)
	}

	func testAnExistingRecordReportsAlreadyExistsWithTheAccount() {
		let store = BeamioNativeKeyImportTests.InjectedStore()
		store.keys[eoa] = Data(repeating: 0x11, count: 32)
		let report = BeamioNativeKeyImport.importPrivateKeyReport(text: keyHex, expectedEoa: eoa, store: store)
		XCTAssertEqual(report.outcome, .alreadyPresent)
		XCTAssertEqual(report.eoa, eoa)
	}

	func testFailuresBeforeTheAccountIsKnownCarryNoEoa() {
		let store = BeamioNativeKeyImportTests.InjectedStore()
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKeyReport(text: "zz", expectedEoa: "", store: store),
		               .init(outcome: .invalidFormat, eoa: nil))
		let other = "0x" + String(repeating: "0", count: 40)
		let mismatch = BeamioNativeKeyImport.importPrivateKeyReport(text: keyHex, expectedEoa: other, store: store)
		XCTAssertEqual(mismatch.outcome, .addressMismatch)
		XCTAssertNil(mismatch.eoa)
		XCTAssertTrue(store.keys.isEmpty, "nothing is written by a refused import")
	}

	/// r2.5.18 第 59(6) 項: the page-result hooks belong to the removed import page, so they are deleted. The test asserts the removal.
	func testAnArmedPageSendsExactlyOneResult() {
		RemovedImportHostHooks.assertAbsent()
	}

	/// r2.5.18 第 59(6) 項: without an armed page there is no result hook to report to; the hooks are deleted, so the test asserts their absence.
	func testWithoutAnOpenedPageNothingIsSent() {
		RemovedImportHostHooks.assertAbsent()
	}

	/// r2.3 (spec 第 41(1) 项): `nativeImportOpen` is no longer registered. The bridge answers `unknown_command`, opens no page,
	/// and sends no `nativeImportResult`. The method name is kept; its body asserts the removal.
	func testTheBridgeOpensThePageAndSendsTheResultOnce() {
		var emitted: [[String: Any]] = []
		let emit: BeamioConetChatModule.WebEmit = { payload in
			emitted.append((payload["event"] as? [String: Any]) ?? payload)
		}
		BeamioConetChatModule.handleCommand(["type": "nativeImportOpen", "reqId": 77], emit: emit)
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		XCTAssertTrue(emitted.allSatisfy { $0["type"] as? String != "nativeImportResult" }, "no page, no result")
		let ack = emitted.first { $0["type"] as? String == "ack" }
		XCTAssertEqual(ack?["error"] as? String, "unknown_command")
	}

	func testAPageThatDidNotOpenArmsNothing() {
		var emitted: [[String: Any]] = []
		let emit: BeamioConetChatModule.WebEmit = { payload in
			emitted.append((payload["event"] as? [String: Any]) ?? payload)
		}
		BeamioConetChatModule.handleCommand(["type": "nativeImportOpen", "reqId": 78], emit: emit)
		RemovedImportHostHooks.assertAbsent()
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		XCTAssertTrue(emitted.allSatisfy { $0["type"] as? String != "nativeImportResult" })
	}
}
