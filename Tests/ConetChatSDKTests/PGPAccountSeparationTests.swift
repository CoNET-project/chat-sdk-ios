#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Per-account PGP records: one record per `accountKey` (EOA and workspace). Two accounts on one
/// device never overwrite each other, a read returns only the named account, and a delete removes only that account.
/// Synthetic values only (marker strings, not key material). Runs on the in-memory seam: the simulator test host has no
/// Keychain entitlement (errSecMissingEntitlement, -34018), so the real Keychain round trip is left to the app-host
/// integration build.
final class PGPAccountSeparationTests: XCTestCase {
	private let alice = "0xA11CE00000000000000000000000000000000001"
	private let bob = "0xB0B0000000000000000000000000000000000002"
	private let privateA = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-alice\n-----END PGP PRIVATE KEY BLOCK-----"
	private let privateB = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-bob\n-----END PGP PRIVATE KEY BLOCK-----"
	private let publicA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-alice\n-----END PGP PUBLIC KEY BLOCK-----"
	private let publicB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-bob\n-----END PGP PUBLIC KEY BLOCK-----"
	private let routeA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-route-alice\n-----END PGP PUBLIC KEY BLOCK-----"

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = nil
		super.tearDown()
	}

	private func record(_ privateArmor: String, _ publicArmor: String, keyId: String, eoa: String,
	                    route: String = "") -> BeamioChatPgpKeychain.Secrets {
		BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: privateArmor, publicKeyArmor: publicArmor, pgpKeyId: keyId,
			routePublicKeyArmor: route, entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)
	}

	private func saveAlice() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice)))
	}

	private func saveBoth() {
		saveAlice()
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateB, publicB, keyId: "keyB", eoa: bob)))
	}

	// MARK: - Two accounts, one after another

	func testSecondAccountDoesNotOverwriteTheFirst() {
		saveBoth()
		let a = BeamioChatPgpKeychain.load(eoa: alice)
		let b = BeamioChatPgpKeychain.load(eoa: bob)
		XCTAssertEqual(a?.privateKeyArmor, privateA)
		XCTAssertEqual(a?.publicKeyArmor, publicA)
		XCTAssertEqual(a?.pgpKeyId, "keyA")
		XCTAssertEqual(a?.eoa, alice.lowercased())
		XCTAssertEqual(b?.privateKeyArmor, privateB)
		XCTAssertEqual(b?.publicKeyArmor, publicB)
		XCTAssertEqual(b?.pgpKeyId, "keyB")
		XCTAssertEqual(b?.eoa, bob.lowercased())
	}

	/// Switching accounts reads only the named account's record. An account with no record reads nothing.
	func testSwitchingAccountsReadsOnlyThatAccount() {
		saveAlice()
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: bob))
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: ""))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice.lowercased())?.pgpKeyId, "keyA", "lookup ignores case")
	}

	func testDeletingOneAccountKeepsTheOther() {
		saveBoth()
		BeamioChatPgpKeychain.clear(eoa: alice)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: bob)?.privateKeyArmor, privateB)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: bob)?.pgpKeyId, "keyB")
	}

	func testAccountKeyIsTheEoaAndTheWorkspace() {
		XCTAssertEqual(BeamioChatPgpKeychain.accountKey(eoa: " 0xAbC "), "0xabc:default")
		XCTAssertEqual(BeamioChatPgpKeychain.accountKey(eoa: "0xAbC", workspace: "work"), "0xabc:work")
		XCTAssertEqual(BeamioChatPgpKeychain.accountKey(eoa: "   "), "")
		XCTAssertEqual(BeamioChatPgpKeychain.defaultWorkspace, "default")
	}

	/// A record without an account has no account key, so it is refused and nothing is written.
	func testRecordWithoutAnAccountIsRefused() {
		XCTAssertFalse(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "k", eoa: "")))
		XCTAssertFalse(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "k", eoa: "   ")))
		XCTAssertEqual(BeamioChatPgpKeychain.memory?.values.count, 0)
	}

	// MARK: - Route key and roster

	func testUpsertWritesOnlyTheNamedAccount() {
		saveBoth()
		XCTAssertTrue(BeamioChatPgpKeychain.upsert(eoa: alice, fromWeb: ["routePublicKeyArmor": routeA]))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.routePublicKeyArmor, routeA)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: bob)?.routePublicKeyArmor, "")
		XCTAssertEqual(BeamioChatPgpKeychain.loadRoutePublicArmor(eoa: alice), routeA)
		XCTAssertEqual(BeamioChatPgpKeychain.loadRoutePublicArmor(eoa: bob), "")
	}

	/// A payload that names another account cannot write into the account it is sent for.
	func testUpsertRefusesAPayloadNamingAnotherAccount() {
		saveAlice()
		XCTAssertFalse(BeamioChatPgpKeychain.upsert(eoa: alice, fromWeb: ["eoa": bob, "routePublicKeyArmor": routeA]))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.routePublicKeyArmor, "")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: bob))
	}

	/// The SI roster is device data: every account sees it, and deleting an account leaves it in place.
	func testRosterIsSharedAndSurvivesADelete() {
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(
			nodes: [BeamioChatPgpKeychain.SiNode(ip: "10.0.0.1", domain: "n1.example")], mailboxIp: "10.0.0.9"))
		saveBoth()
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.siNodes.map(\.ip), ["10.0.0.1"])
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: bob)?.siNodes.map(\.ip), ["10.0.0.1"])
		BeamioChatPgpKeychain.clear(eoa: alice)
		XCTAssertEqual(BeamioChatPgpKeychain.loadSiNodes().map(\.ip), ["10.0.0.1"])
		XCTAssertEqual(BeamioChatPgpKeychain.loadMailboxIp(), "10.0.0.9")
	}

	// MARK: - The single record kept before per-account storage (plain item names)

	/// The legacy record is copied only into the account whose EOA it names. The other account never reads it. A read never deletes the plain
	/// items: they stay after the copy.
	func testLegacyRecordIsCopiedOnlyToItsOwnAccountAndNeverDeleted() {
		let values = BeamioChatPgpKeychain.memory
		values?.values["userPgpPrivateArmor"] = privateA
		values?.values["userPgpPublicArmor"] = publicA
		values?.values["userPgpKeyId"] = "legacy-keyA"
		values?.values["recipientEoa"] = alice.lowercased()
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: bob), "another account never reads the legacy record")
		XCTAssertEqual(values?.values["userPgpPrivateArmor"], privateA, "not copied for another account")
		let copied = BeamioChatPgpKeychain.load(eoa: alice)
		XCTAssertEqual(copied?.privateKeyArmor, privateA)
		XCTAssertEqual(copied?.pgpKeyId, "legacy-keyA")
		XCTAssertEqual(values?.values["userPgpPrivateArmor"], privateA, "the plain item stays after the copy: a read path never deletes")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.pgpKeyId, "legacy-keyA", "still there after the second load")
	}

	func testDeletingTheLegacyAccountRemovesTheLegacyRecord() {
		let values = BeamioChatPgpKeychain.memory
		values?.values["userPgpPrivateArmor"] = privateA
		values?.values["recipientEoa"] = alice.lowercased()
		BeamioChatPgpKeychain.clear(eoa: alice)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice))
		XCTAssertNil(values?.values["userPgpPrivateArmor"])
	}

	/// A legacy record with no EOA has no owner, so no account adopts it and it is left in place.
	func testLegacyRecordWithoutAnOwnerIsLeftAlone() {
		let values = BeamioChatPgpKeychain.memory
		values?.values["userPgpPrivateArmor"] = privateA
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice))
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: bob))
		XCTAssertEqual(values?.values["userPgpPrivateArmor"], privateA)
	}

	/// a read-back that does not match rolls back only the record just written. The plain legacy record of the same EOA stays, and so do
	/// its plain items; the scoped record of the account is removed.
	func testAFailedReadBackRemovesOnlyTheRecordJustWrittenAndKeepsTheLegacyRecord() {
		let values = BeamioChatPgpKeychain.memory
		values?.values["userPgpPrivateArmor"] = privateA
		values?.values["userPgpPublicArmor"] = publicA
		values?.values["userPgpKeyId"] = "legacy-keyA"
		values?.values["recipientEoa"] = alice.lowercased()
		let previous = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateB, publicB, keyId: "keyB", eoa: alice)))
		let scopedPrivate = BeamioChatPgpKeychain.kAccount(eoa: alice)
		XCTAssertNotNil(values?.values[scopedPrivate], "the record just written is there before the read-back")

		XCTAssertEqual(BeamioPGPRestoreCommands.verifyReadBack(eoa: alice, armor: privateB, publicArmor: publicB, previous: previous, readBack: { nil }), .mismatchRestored)

		XCTAssertNil(values?.values[scopedPrivate], "the record just written is removed")
		XCTAssertEqual(values?.values["userPgpPrivateArmor"], privateA, "the legacy plain item stays (,)")
		XCTAssertEqual(values?.values["recipientEoa"], alice.lowercased(), "the legacy owner item stays")
		XCTAssertEqual(BeamioChatPgpKeychain.readOnlyRecord(eoa: alice)?.privateKeyArmor, privateA, "the plain legacy record is still the record of the account")
	}

	/// a matching read-back keeps the record written.
	func testAMatchingReadBackKeepsTheRecordWritten() {
		let previous = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		let written = record(privateB, publicB, keyId: "keyB", eoa: alice)
		XCTAssertTrue(BeamioChatPgpKeychain.save(written))
		XCTAssertEqual(BeamioPGPRestoreCommands.verifyReadBack(eoa: alice, armor: privateB, publicArmor: publicB, previous: previous, readBack: { written }), .matched)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.privateKeyArmor, privateB)
	}

	/// synthetic: the account has a scoped record and no plain legacy record. A read-back that does not match puts the old scoped record
	/// back exactly, field by field, and the new record is not left behind.
	func testAFailedReadBackKeepsTheExistingScopedRecordExactly() {
		let values = BeamioChatPgpKeychain.memory
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		XCTAssertNil(values?.values["userPgpPrivateArmor"], "no plain legacy record in this case")
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		XCTAssertFalse(before.isEmpty, "the old scoped record is there")
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateB, publicB, keyId: "keyB", eoa: alice)))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.pgpKeyId, "keyB", "the new record is written before the read-back")

		XCTAssertEqual(BeamioPGPRestoreCommands.verifyReadBack(eoa: alice, armor: privateB, publicArmor: publicB, previous: before, readBack: { nil }), .mismatchRestored)

		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "every field of the old scoped record is back, unchanged")
		let back = BeamioChatPgpKeychain.load(eoa: alice)
		XCTAssertEqual(back?.privateKeyArmor, privateA)
		XCTAssertEqual(back?.publicKeyArmor, publicA)
		XCTAssertEqual(back?.pgpKeyId, "keyA")
		XCTAssertEqual(back?.routePublicKeyArmor, routeA)
		XCTAssertNil(values?.values["userPgpPrivateArmor"], "the rollback creates no legacy item")
	}

	/// synthetic: the account has a scoped record. A matching read-back leaves the new record in effect.
	func testAMatchingReadBackMakesTheNewRecordEffectiveOverAnExistingScopedRecord() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice)))
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		let written = record(privateB, publicB, keyId: "keyB", eoa: alice)
		XCTAssertTrue(BeamioChatPgpKeychain.save(written))

		XCTAssertEqual(BeamioPGPRestoreCommands.verifyReadBack(eoa: alice, armor: privateB, publicArmor: publicB, previous: before, readBack: { written }), .matched)

		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.privateKeyArmor, privateB)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.pgpKeyId, "keyB")
		XCTAssertNotEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "the old record is not put back")
	}

	/// A restore candidate for `writeLocal`, with the key material of the synthetic record.
	private func evaluation(_ armor: String, _ publicArmor: String, _ keyId: String) -> BeamioPGPRestoreCommands.Evaluation {
		BeamioPGPRestoreCommands.Evaluation(
			state: "ok", failureClass: nil, code: nil, offerEntry: false, uiKey: nil,
			armor: armor, chainPublicArmor: publicArmor, chainSubkeyKeyID: keyId, restoredSubkeyKeyID: keyId)
	}

	/// the same key is already stored. `already_exists`, nothing is written, and the route stays as it was.
	func testWriteLocalWithTheSameKeyAnswersAlreadyExistsAndKeepsTheRoute() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateA, publicA, "keyA"))

		XCTAssertEqual(result.code, "already_exists")
		XCTAssertEqual(result.state, "ok")
		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "nothing is written")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.routePublicKeyArmor, routeA, "the route is unchanged")
	}

	/// another key is stored. It is refused, and the stored record is not overwritten.
	func testWriteLocalWithAnotherKeyRefusesAndWritesNothing() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "not_ready")
		XCTAssertEqual(result.state, "undetermined")
		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "the stored record is not overwritten")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.privateKeyArmor, privateA)
	}

	/// no scoped record. The write runs, and the read-back decides.
	func testWriteLocalWithNoRecordWritesAndReadsBack() {
		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "ok")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.privateKeyArmor, privateB)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.pgpKeyId, "keyB")
	}

	/// a partial scoped record (its route, but no private armor) is completed, and its route is kept, not blanked.
	func testWriteLocalCompletesAPartialRecordAndKeepsItsRoute() {
		let values = BeamioChatPgpKeychain.memory
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		values?.values[BeamioChatPgpKeychain.kAccount(eoa: alice)] = nil

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "ok")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.privateKeyArmor, privateB)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.routePublicKeyArmor, routeA, "the route is kept")
	}

	/// the same key, reformatted (CRLF line endings, a trailing space), is still the same key: already_exists, the route stays.
	func testWriteLocalTreatsAReformattedArmorAsTheSameKey() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		let reformatted = privateA.replacingOccurrences(of: "\n", with: "\r\n") + " "

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(reformatted, publicA, "keyA"))

		XCTAssertEqual(result.code, "already_exists")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.routePublicKeyArmor, routeA, "the route is unchanged")
	}

	/// spec: the same key is judged by identity (the primary fingerprint, or the key ID), not by the armor text. The same key ID with
	/// another private armor text is the same identity: already_exists, nothing is written, the route stays.
	func testWriteLocalJudgesTheIdentityNotTheArmorText() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicA, "keyA"))

		XCTAssertEqual(result.code, "already_exists")
		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "nothing is written")
	}

	/// spec: a record whose account is not the account of the restore is not_ready, and nothing is written.
	func testWriteLocalWithARecordOfAnotherAccountIsNotReadyAndWritesNothing() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		BeamioChatPgpKeychain.memory?.values[BeamioChatPgpKeychain.accountKey(eoa: alice) + "|recipientEoa"] = bob.lowercased()
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateA, publicA, "keyA"))

		XCTAssertEqual(result.code, "not_ready")
		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "nothing is written")
	}

	/// M1: only a plain legacy record of the account, with the same key. It is copied to the account first, so the answer is already_exists and
	/// the route of the legacy record is kept. The legacy record is not deleted.
	func testWriteLocalCopiesAPlainLegacyRecordFirstAndAnswersAlreadyExists() {
		let values = BeamioChatPgpKeychain.memory
		values?.values["userPgpPrivateArmor"] = privateA
		values?.values["userPgpPublicArmor"] = publicA
		values?.values["userPgpKeyId"] = "keyA"
		values?.values["mailboxRoutePublicArmor"] = routeA
		values?.values["recipientEoa"] = alice.lowercased()

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateA, publicA, "keyA"))

		XCTAssertEqual(result.code, "already_exists")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.routePublicKeyArmor, routeA, "the route of the legacy record is kept")
		XCTAssertEqual(values?.values["userPgpPrivateArmor"], privateA, "the legacy record is not deleted")
	}

	/// lock: a scoped item that the Keychain cannot return refuses the write (not_ready); nothing is written.
	func testWriteLocalRefusesWhileTheScopedRecordCannotBeRead() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		BeamioChatPgpKeychain.testUnreadableFields = ["userPgpPublicArmor"]
		defer { BeamioChatPgpKeychain.testUnreadableFields = [] }

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "not_ready")
		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "nothing is written")
	}

	/// (spec): a pending migration (its copy N has no marker M, or N and M differ) refuses the write (not_ready). Nothing is
	/// written, and the copy is not overwritten. The detection itself reads the migration store, which the test host cannot read, so the test sets it.
	func testWriteLocalRefusesWhileTheMigrationIsPendingAndLeavesTheCopy() {
		defer { BeamioPGPRestoreCommands.testMigrationPending = nil }
		BeamioPGPRestoreCommands.testMigrationPending = true
		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))
		XCTAssertEqual(result.code, "not_ready")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice), "nothing is written")
	}

	/// (spec): failed, verified and none do not block a restore write.
	func testWriteLocalIsNotBlockedWhenTheMigrationIsNotPending() {
		defer { BeamioPGPRestoreCommands.testMigrationPending = nil }
		BeamioPGPRestoreCommands.testMigrationPending = false
		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))
		XCTAssertEqual(result.code, "ok")
	}

	/// (spec): the PGP record has three states. An unreadable private item is not_ready and nothing is written. A missing record is
	/// absent and is written.
	func testAnUnreadablePrivateItemIsNotReadyAndNothingIsWritten() {
		let values = BeamioChatPgpKeychain.memory
		values?.values[BeamioChatPgpKeychain.kAccount(eoa: alice)] = "not a PGP private key"
		XCTAssertEqual(BeamioChatPgpKeychain.recordState(eoa: alice), .unreadable, "the record exists and does not open")
		let before = values?.values

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "not_ready")
		XCTAssertEqual(values?.values, before, "nothing is written")
	}

	/// the three states of the PGP record.
	func testTheRecordHasThreeStates() {
		XCTAssertEqual(BeamioChatPgpKeychain.recordState(eoa: alice), .absent, "no record")
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		XCTAssertEqual(BeamioChatPgpKeychain.recordState(eoa: alice), .present, "the private key can be read")
		BeamioChatPgpKeychain.memory?.values[BeamioChatPgpKeychain.accountKey(eoa: alice) + "|userPgpPublicArmor"] = nil
		BeamioChatPgpKeychain.testUnreadableFields = ["userPgpPublicArmor"]
		defer { BeamioChatPgpKeychain.testUnreadableFields = [] }
		XCTAssertEqual(BeamioChatPgpKeychain.recordState(eoa: alice), .unreadable, "an item cannot be read")
	}

	/// (distinct outcome): a read-back that differs, with a clean rollback, is readback_failed (undetermined), and the record is as it was.
	func testACleanReadBackFailureIsReadBackFailedWithTheRecordIntact() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		BeamioChatPgpKeychain.memory?.values[BeamioChatPgpKeychain.kAccount(eoa: alice)] = nil
		let before = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		BeamioPGPRestoreCommands.testReadBackOverride = { _ in nil }
		defer { BeamioPGPRestoreCommands.testReadBackOverride = nil }

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "readback_failed")
		XCTAssertEqual(result.state, "undetermined")
		XCTAssertFalse(BeamioChatPgpKeychain.restoreIncomplete(eoa: alice), "a clean rollback leaves no mark")
		XCTAssertEqual(BeamioChatPgpKeychain.scopedSnapshot(eoa: alice), before, "the record is as it was")
	}

	/// (distinct outcome): a read-back that differs, with a rollback that does not complete, is not_ready (terminal). The record is marked.
	func testAnIncompleteRollbackAfterAReadBackFailureIsNotReadyAndMarked() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		BeamioChatPgpKeychain.memory?.values[BeamioChatPgpKeychain.kAccount(eoa: alice)] = nil
		BeamioPGPRestoreCommands.testReadBackOverride = { _ in
			BeamioChatPgpKeychain.testWriteBudget = 0
			return nil
		}
		BeamioChatPgpKeychain.testWriteBudgetExemptFields = ["userPgpRestoreIncomplete"]
		defer {
			BeamioPGPRestoreCommands.testReadBackOverride = nil
			BeamioChatPgpKeychain.testWriteBudget = nil
			BeamioChatPgpKeychain.testWriteBudgetExemptFields = []
		}

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "not_ready", "an incomplete rollback is the terminal answer, not readback_failed")
		XCTAssertEqual(result.state, "undetermined")
		XCTAssertTrue(BeamioChatPgpKeychain.restoreIncomplete(eoa: alice), "the record is marked incomplete")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice), "no reader returns the mixed record")
	}

	/// N1, (spec (ii)): a save whose rollback does not complete is not_ready, the terminal answer. The record is marked
	/// incomplete: no reader returns it and no later restore writes over it. The answer is distinct from a clean failure (next test).
	func testAFailedSaveWhoseRollbackFailsIsNotReadyAndMarkedIncomplete() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		BeamioChatPgpKeychain.memory?.values[BeamioChatPgpKeychain.kAccount(eoa: alice)] = nil
		BeamioChatPgpKeychain.testWriteBudget = 1
		BeamioChatPgpKeychain.testWriteBudgetExemptFields = ["userPgpRestoreIncomplete"]
		defer {
			BeamioChatPgpKeychain.testWriteBudget = nil
			BeamioChatPgpKeychain.testWriteBudgetExemptFields = []
		}

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "not_ready", "an incomplete rollback is the terminal answer, not write_failed")
		XCTAssertEqual(result.state, "undetermined")
		XCTAssertTrue(BeamioChatPgpKeychain.restoreIncomplete(eoa: alice), "the record is marked incomplete")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice), "no reader returns the mixed record")
		let again = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))
		XCTAssertEqual(again.code, "not_ready", "a later restore does not write over the marked record")
	}

	/// a save whose rollback completes is an ordinary failure (write_failed, undetermined), and the record is not marked.
	func testAFailedSaveWithACleanRollbackIsAnOrdinaryFailure() {
		BeamioChatPgpKeychain.testWriteBudget = 0
		defer { BeamioChatPgpKeychain.testWriteBudget = nil }

		let result = BeamioPGPRestoreCommands.writeLocal(eoa: alice, evaluation: evaluation(privateB, publicB, "keyB"))

		XCTAssertEqual(result.code, "write_failed")
		XCTAssertEqual(result.state, "undetermined")
		XCTAssertFalse(BeamioChatPgpKeychain.restoreIncomplete(eoa: alice), "a clean rollback leaves no mark")
	}

	/// N1: a read-back that differs, whose rollback does not complete, is mismatchRestoreFailed.
	func testAReadBackMismatchWhoseRollbackFailsIsReportedAsFailed() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "keyA", eoa: alice, route: routeA)))
		let previous = BeamioChatPgpKeychain.scopedSnapshot(eoa: alice)
		BeamioChatPgpKeychain.testWriteBudget = 0
		defer { BeamioChatPgpKeychain.testWriteBudget = nil }

		XCTAssertEqual(BeamioPGPRestoreCommands.verifyReadBack(eoa: alice, armor: privateB, publicArmor: publicB, previous: previous, readBack: { nil }),
		               .mismatchRestoreFailed)
	}

// MARK: - Wallet key (BeamioChatWalletKeychain): one keychain item per EOA

	/// The wallet key is one item per account (`walletKey:<eoa>`, lower-cased), so two accounts never share an item. The
	/// Keychain round trip itself needs the app-host build (the simulator test host has no entitlement).
	func testWalletKeyItemIsPerAccount() {
		let a = BeamioChatWalletKeychainStore.walletKeyAccount(alice)
		let b = BeamioChatWalletKeychainStore.walletKeyAccount(bob)
		XCTAssertNotEqual(a, b)
		XCTAssertEqual(a, BeamioChatWalletKeychainStore.walletKeyAccount(alice.lowercased()))
		XCTAssertEqual(BeamioChatWalletKeychainStore.walletKeyAccount(" \(alice) "), a)
		XCTAssertEqual(a, "walletKey:" + alice.lowercased())
	}
}
#endif
