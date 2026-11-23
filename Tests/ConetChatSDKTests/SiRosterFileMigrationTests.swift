#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The SI roster lives in an Application Support file, not the Keychain. Synthetic nodes only.
final class SiRosterFileMigrationTests: XCTestCase {
	private let nodes: [BeamioChatPgpKeychain.SiNode] = [
		.init(ip: "203.0.113.7", domain: "a.example.test", region: "T1", armoredPublicKey: "synthetic-armor-1"),
		.init(ip: "203.0.113.8", domain: "b.example.test", region: "T2", armoredPublicKey: ""),
	]
	private let account = "siNodesJson"

	private var fileURL: URL { BeamioInboxFile.folder!.appendingPathComponent("si_roster_v1.test-\(ProcessInfo.processInfo.processIdentifier).json") }

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.testFailRosterWrite = false
		BeamioInboxFile.failRemovals = false
		BeamioChatPgpKeychain.testFailDeleteContains = []
	}

	override func tearDown() {
		BeamioInboxFile.testFailProtection = false
		BeamioChatPgpKeychain.testFailRosterWrite = false
		BeamioInboxFile.failRemovals = false
		BeamioChatPgpKeychain.testFailDeleteContains = []
		BeamioChatPgpKeychain.memory = nil
		super.tearDown()
	}

	private func legacyJson() -> String {
		let rows = nodes.map { ["ip": $0.ip, "domain": $0.domain, "region": $0.region, "armoredPublicKey": $0.armoredPublicKey] }
		return String(data: try! JSONSerialization.data(withJSONObject: rows), encoding: .utf8)!
	}

	func testStoreWritesFileAndLeavesNoKeychainItem() {
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: nil))
		XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path))
		XCTAssertNil(BeamioChatPgpKeychain.memory!.values[account])
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertNil(BeamioChatPgpKeychain.rosterDiagnostic)
	}

	func testLegacyKeychainRosterMovesToFileThenKeychainItemIsDeleted() {
		BeamioChatPgpKeychain.memory!.values[account] = legacyJson()
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertTrue(FileManager.default.fileExists(atPath: fileURL.path))
		XCTAssertNil(BeamioChatPgpKeychain.memory!.values[account])
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes, "the second read comes from the file")
	}

	func testFailedFileWriteKeepsKeychainItemAndRetriesLater() {
		BeamioChatPgpKeychain.memory!.values[account] = legacyJson()
		BeamioChatPgpKeychain.testFailRosterWrite = true
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes, "the roster is still answered from the old source")
		XCTAssertNotNil(BeamioChatPgpKeychain.memory!.values[account])
		XCTAssertEqual(BeamioChatPgpKeychain.rosterDiagnostic, "roster_migration_pending")
		BeamioChatPgpKeychain.testFailRosterWrite = false
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertNil(BeamioChatPgpKeychain.memory!.values[account], "the retry completes the move")
		XCTAssertNil(BeamioChatPgpKeychain.rosterDiagnostic)
	}

	func testFailedKeychainDeleteKeepsRosterReadableAndIsRetried() {
		BeamioChatPgpKeychain.memory!.values[account] = legacyJson()
		BeamioChatPgpKeychain.testFailDeleteContains = [account]
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertNotNil(BeamioChatPgpKeychain.memory!.values[account])
		BeamioChatPgpKeychain.testFailDeleteContains = []
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertNil(BeamioChatPgpKeychain.memory!.values[account])
	}

	func testCorruptFileFallsBackToKeychainWithDiagnosticNeverEmpty() {
		BeamioChatPgpKeychain.memory!.values[account] = legacyJson()
		XCTAssertTrue(BeamioInboxFile.replace(fileURL, with: Data("not json".utf8)))
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertEqual(BeamioChatPgpKeychain.rosterDiagnostic, "roster_file_corrupt")
		XCTAssertNotNil(BeamioChatPgpKeychain.memory!.values[account], "the Keychain item is not deleted while the file is bad")
	}

	func testCorruptFileAndNoKeychainItemIsEmptyWithDiagnostic() {
		XCTAssertTrue(BeamioInboxFile.replace(fileURL, with: Data("[]x".utf8)))
		XCTAssertTrue(BeamioChatPgpKeychain.loadSiNodes().isEmpty)
		XCTAssertEqual(BeamioChatPgpKeychain.rosterDiagnostic, "roster_file_corrupt")
	}

	func testStoreWhenFileCannotBeWrittenFallsBackToKeychain() {
		BeamioChatPgpKeychain.testFailRosterWrite = true
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: nil))
		XCTAssertEqual(BeamioChatPgpKeychain.rosterDiagnostic, "roster_file_write_failed")
		BeamioChatPgpKeychain.testFailRosterWrite = false
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
	}

	func testStoreWhenFileCannotBeWrittenAndOldFileExistsKeepsOldRoster() {
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: [nodes[0]], mailboxIp: nil))
		BeamioChatPgpKeychain.testFailRosterWrite = true
		XCTAssertFalse(BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: nil))
		BeamioChatPgpKeychain.testFailRosterWrite = false
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), [nodes[0]], "no stale file shadows a newer Keychain roster")
		XCTAssertNil(BeamioChatPgpKeychain.memory!.values[account])
	}

	func testNewerFileWinsOverLeftoverKeychainItemAndRemovesIt() {
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: nil))
		BeamioChatPgpKeychain.memory!.values[account] = legacyJson().replacingOccurrences(of: "203.0.113.8", with: "203.0.113.9")
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertNil(BeamioChatPgpKeychain.memory!.values[account])
	}

	/// A protection class that cannot be set is not silent: a category-only diagnostic, the roster stays readable, and the next read sets it again.
	func testAFailedProtectionIsReportedKeptForRetryAndRetried() {
		BeamioInboxFile.testFailProtection = true
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: nil), "the data is written")
		XCTAssertEqual(BeamioChatPgpKeychain.rosterDiagnostic, "roster_protection_pending")
		XCTAssertTrue(BeamioInboxFile.protectionRetryPending(fileURL))
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes, "the roster is still read")
		XCTAssertEqual(BeamioChatPgpKeychain.rosterDiagnostic, "roster_protection_pending", "still failing: still reported")
		BeamioInboxFile.testFailProtection = false
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertFalse(BeamioInboxFile.protectionRetryPending(fileURL), "the retry set it")
		XCTAssertNil(BeamioChatPgpKeychain.rosterDiagnostic)
	}

	/// The retry list is in memory and does not survive a restart: every read sets the protection class again, so a file written without it is repaired anyway.
	func testEveryReadSetsTheProtectionAgainEvenAfterARestart() {
		BeamioInboxFile.testFailProtection = true
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: nil))
		BeamioInboxFile.testFailProtection = false
		BeamioInboxFile.forgetProtectionStateForTests()   // the restart: no retry list
		XCTAssertFalse(BeamioInboxFile.protectionRetryPending(fileURL))
		let before = BeamioInboxFile.testProtectionSetCount
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertGreaterThan(BeamioInboxFile.testProtectionSetCount, before, "the read set the protection class")
		let again = BeamioInboxFile.testProtectionSetCount
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes(), nodes)
		XCTAssertGreaterThan(BeamioInboxFile.testProtectionSetCount, again, "and sets it at each read, idempotently")
	}
}
#endif
