#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The PGP migration import, by class: interruption, failure and re-entry, plus the X-19 approval gate,
/// the bridge refusals and the Keychain items. The state vectors are in PgpMigrationVectorTests. X-19 is needed (iOS simulator).
final class PgpMigrationImportTests: XCTestCase {
	private typealias MemoryStore = PgpMigrationTestSupport.MemoryStore
	private typealias Crypto = PgpMigrationTestSupport.Crypto
	private typealias Key = PgpMigrationTestSupport.Key

	private let eoa = PgpMigrationTestSupport.eoa
	private let account = PgpMigrationTestSupport.account
	private var savedMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var savedKeyStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedMemory = BeamioChatPgpKeychain.memory
		savedKeyStore = BeamioNativeWallet.keyStore
		savedVault = BeamioPasscodeSession.shared.vault
		events = []
	}

	override func tearDown() {
		BeamioConetChatModule.pgpMigrationEnvironmentOverride = nil
		BeamioChatPgpKeychain.memory = savedMemory
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedKeyStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	// MARK: Fixtures

	/// L holds key A (private and public). The fixtures of the other tests are built from it.
	private func seeded() -> MemoryStore {
		let store = MemoryStore()
		let a = PgpMigrationTestSupport.key("A")
		store.legacyRecords[eoa] = PgpMigrationTestSupport.legacy(privateKey: a, publicKey: a)
		return store
	}

	private func run(
		_ store: MemoryStore,
		crypto: Crypto = Crypto(),
		registered: String? = PgpMigrationTestSupport.key("A").publicArmor,
		chainUnavailable: Bool = false,
		approved: Bool = true,
		interrupt: BeamioPgpMigrationImport.Checkpoint? = nil
	) -> BeamioPgpMigrationImport.Outcome {
		let env = PgpMigrationTestSupport.environment(
			store: store,
			crypto: crypto,
			registeredArmor: registered,
			chainUnavailable: chainUnavailable,
			x19Approved: approved,
			interrupt: interrupt
		)
		return BeamioPgpMigrationImport.runInternal(eoa: eoa, workspace: BeamioChatPgpKeychain.defaultWorkspace, env: env)
	}

	private func fp16(_ label: String) -> String {
		PgpMigrationTestSupport.key(label).fp16
	}

	// MARK: Interruption

	func testAnInterruptAfterTheCopyResumesWithoutRewritingIt() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let before = PgpMigrationTestSupport.snapshot(store)

		let interrupted = run(store, interrupt: .afterStagedWrite)
		XCTAssertEqual(interrupted, BeamioPgpMigrationImport.Outcome(code: "interrupted", fp: nil, interrupted: true))
		XCTAssertNotNil(store.stagedRecords[account], "the copy stays")
		XCTAssertNil(store.markerRecords[account], "no marker before the checks pass")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa], "the record is not changed")

		let resumed = run(store)
		XCTAssertEqual(resumed, BeamioPgpMigrationImport.Outcome(code: "ok", fp: fp16("A"), interrupted: false))
		XCTAssertEqual(store.stagedWrites, 1, "the copy is not written again")
		XCTAssertEqual(store.markerWrites, 1)
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa])
	}

	func testAnInterruptAfterTheMarkerLeavesAVerifiedAccountThatReportsItAsAlreadyVerified() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()

		XCTAssertTrue(run(store, interrupt: .afterMarkerWrite).interrupted)
		XCTAssertNotNil(store.markerRecords[account], "the marker was written before the stop")

		let again = run(store)
		XCTAssertEqual(again.code, "already_verified")
		XCTAssertEqual(again.fp, fp16("A"))
		XCTAssertEqual(store.stagedWrites, 1)
		XCTAssertEqual(store.markerWrites, 1, "the marker is not written twice")
	}

	// MARK: Failure

	func testAWriteFailureLeavesNothingAndTheRetryVerifies() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let before = PgpMigrationTestSupport.snapshot(store)
		store.failStagedWrite = true

		XCTAssertEqual(run(store).code, "write_failed")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertNil(store.markerRecords[account])
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa])

		store.failStagedWrite = false
		XCTAssertEqual(run(store).code, "ok")
	}

	func testAFailedReadBackDeletesOnlyTheCopyThisRunWrote() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let before = PgpMigrationTestSupport.snapshot(store)
		store.rereadMismatch = true

		XCTAssertEqual(run(store).code, "reread_failed")
		XCTAssertNil(store.stagedRecords[account], "the copy this run wrote is deleted")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa])

		store.rereadMismatch = false
		XCTAssertEqual(run(store).code, "ok")
		XCTAssertEqual(store.stagedWrites, 2, "the failed copy was written once and replaced by the retry")
	}

	func testAFailedChallengeDeletesTheCopyAndKeepsTheRecordThenTheRetryVerifies() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let crypto = Crypto()
		crypto.verifyFails = true

		XCTAssertEqual(run(store, crypto: crypto).code, "challenge_failed")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertNotNil(store.legacyRecords[eoa], "the record is kept")

		crypto.verifyFails = false
		XCTAssertEqual(run(store, crypto: crypto).code, "ok", "the retry needs no key from the caller")
	}

	/// T-281: the challenge's one-bit negative check must fail the challenge when a one-bit change of the
	/// message still verifies. The signing and the positive verification are real X-19; only the tampered message is accepted.
	/// The retry with real verification passes, so the failure comes from the negative check and nothing else.
	func testAOneBitChangeThatStillVerifiesFailsTheChallenge() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let crypto = Crypto()
		crypto.acceptsOneBitChange = true

		XCTAssertEqual(run(store, crypto: crypto).code, "challenge_failed")
		XCTAssertNil(store.stagedRecords[account], "the copy is deleted")
		XCTAssertNotNil(store.legacyRecords[eoa], "the record is kept")

		crypto.acceptsOneBitChange = false
		XCTAssertEqual(run(store, crypto: crypto).code, "ok", "the retry with real verification passes the negative check")
	}

	func testAFailedMarkerWriteKeepsTheCopyAndTheRetryDoesNotRewriteIt() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		store.failMarkerWrite = true

		XCTAssertEqual(run(store).code, "write_failed")
		XCTAssertNotNil(store.stagedRecords[account], "the copy is kept when the marker fails")
		XCTAssertNil(store.markerRecords[account])

		store.failMarkerWrite = false
		XCTAssertEqual(run(store).code, "ok")
		XCTAssertEqual(store.stagedWrites, 1)
	}

	func testACopyWithAnotherFingerprintIsNeverOverwritten() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		store.stagedRecords[account] = PgpMigrationTestSupport.staged(PgpMigrationTestSupport.key("B"))
		let before = PgpMigrationTestSupport.snapshot(store)

		XCTAssertEqual(run(store).code, "fingerprint_mismatch")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), before, "nothing is overwritten or deleted")
		XCTAssertEqual(store.stagedWrites, 0)
	}

	func testAVerifiedCopyThatDisagreesWithTheRecordIsKept() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = MemoryStore()
		let a = PgpMigrationTestSupport.key("A")
		let b = PgpMigrationTestSupport.key("B")
		store.legacyRecords[eoa] = PgpMigrationTestSupport.legacy(privateKey: b, publicKey: b)
		store.stagedRecords[account] = PgpMigrationTestSupport.staged(a)
		store.markerRecords[account] = PgpMigrationTestSupport.marker(a)
		let before = PgpMigrationTestSupport.snapshot(store)

		XCTAssertEqual(run(store, registered: b.publicArmor).code, "fingerprint_mismatch")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), before)
	}

	func testTheChainDisagreeingOrBeingUnreachableKeepsEverything() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let before = PgpMigrationTestSupport.snapshot(store)

		XCTAssertEqual(run(store, registered: PgpMigrationTestSupport.key("B").publicArmor).code, "fingerprint_mismatch")
		XCTAssertEqual(run(store, chainUnavailable: true).code, "chain_unavailable")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), before)
		XCTAssertEqual(store.stagedWrites, 0)
	}

	func testAPassphraseProtectedRecordIsRefusedWithoutWriting() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let crypto = Crypto()
		crypto.encryptedPrivateArmor = PgpMigrationTestSupport.key("A").privateArmor

		XCTAssertEqual(run(store, crypto: crypto).code, "legacy_unreadable")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertNil(store.markerRecords[account])
	}

	// MARK: Re-entry (step 1)

	func testAReRunOfAVerifiedAccountWritesNothing() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		XCTAssertEqual(run(store).code, "ok")
		let after = PgpMigrationTestSupport.snapshot(store)

		let again = run(store)
		XCTAssertEqual(again, BeamioPgpMigrationImport.Outcome(code: "already_verified", fp: fp16("A"), interrupted: false))
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), after)
		XCTAssertEqual(store.stagedWrites, 1)
		XCTAssertEqual(store.markerWrites, 1)
	}

	func testAccountsWithoutAnyRecordReportNone() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = MemoryStore()
		XCTAssertEqual(run(store).code, "none")
		XCTAssertEqual(store.stagedWrites, 0)
		XCTAssertEqual(store.markerWrites, 0)
	}

	// MARK: Source P

	/// The source P of a key label, as the shell would hand over its bytes.
	private func pSource(_ label: String, matched: Bool = true, measured: Bool = true) -> BeamioPgpMigrationImport.LegacyPgpSource {
		let key = PgpMigrationTestSupport.key(label)
		return BeamioPgpMigrationImport.LegacyPgpSource(
			privateArmor: Array(key.privateArmor.utf8),
			publicArmor: Array(key.publicArmor.utf8),
			keyId: key.keyId,
			matchedAccount: matched,
			measuredLayout: measured
		)
	}

	private func runFromSource(
		_ store: MemoryStore,
		source: BeamioPgpMigrationImport.LegacyPgpSource,
		registered: String? = PgpMigrationTestSupport.key("A").publicArmor
	) -> BeamioPgpMigrationImport.Outcome {
		let env = PgpMigrationTestSupport.environment(store: store, crypto: Crypto(), registeredArmor: registered)
		return BeamioPgpMigrationImport.runInternal(
			eoa: eoa,
			workspace: BeamioChatPgpKeychain.defaultWorkspace,
			env: env,
			source: source
		)
	}

	func testARunFromTheSourceMigratesItAndClearsTheBytes() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = MemoryStore()
		let source = pSource("A")
		XCTAssertEqual(runFromSource(store, source: source).code, "ok")
		XCTAssertNotNil(store.stagedRecords[account], "the copy is written from P")
		XCTAssertNotNil(store.markerRecords[account])
		XCTAssertTrue(source.privateArmor.allSatisfy { $0 == 0 }, "the SDK clears the private bytes")
		XCTAssertTrue(source.publicArmor.allSatisfy { $0 == 0 }, "the SDK clears the public bytes")
	}

	func testASourceThatMatchesTheRecordRunsOnTheSourceAndKeepsTheRecord() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let before = PgpMigrationTestSupport.snapshot(store)
		XCTAssertEqual(runFromSource(store, source: pSource("A")).code, "ok")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa], "L is never written")
	}

	func testASourceThatDisagreesWithTheRecordIsRefusedAndNothingIsWritten() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = MemoryStore()
		let b = PgpMigrationTestSupport.key("B")
		store.legacyRecords[eoa] = PgpMigrationTestSupport.legacy(privateKey: b, publicKey: b)
		let before = PgpMigrationTestSupport.snapshot(store)
		let source = pSource("A")
		XCTAssertEqual(runFromSource(store, source: source).code, "fingerprint_mismatch")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), before, "nothing is overwritten or deleted")
		XCTAssertEqual(store.stagedWrites, 0)
		XCTAssertTrue(source.privateArmor.allSatisfy { $0 == 0 })
	}

	func testAnUnmatchedOrUnmeasuredSourceWritesNothing() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = MemoryStore()
		XCTAssertEqual(runFromSource(store, source: pSource("A", matched: false)).code, "account_mismatch")
		XCTAssertEqual(runFromSource(store, source: pSource("A", measured: false)).code, "legacy_unreadable")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertEqual(store.stagedWrites, 0)
	}

	func testAnOversizedSourceIsUnreadableAndCleared() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = MemoryStore()
		let key = PgpMigrationTestSupport.key("A")
		let big = BeamioPgpMigrationImport.LegacyPgpSource(
			privateArmor: [UInt8](repeating: 0x41, count: BeamioPgpMigrationImport.LegacyPgpSource.maxBytes + 1),
			publicArmor: Array(key.publicArmor.utf8),
			keyId: key.keyId
		)
		XCTAssertEqual(runFromSource(store, source: big).code, "legacy_unreadable")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertTrue(big.privateArmor.allSatisfy { $0 == 0 })
	}

	// MARK: Last code and state

	func testTheLastCodeIsWrittenWhenARunFinishesAndNotOnAnInterruption() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		XCTAssertTrue(run(store, interrupt: .afterStagedWrite).interrupted)
		XCTAssertNil(store.lastCode(account: account), "an interruption writes no code")
		XCTAssertEqual(BeamioPgpMigrationImport.derivedState(store: store, eoa: eoa, account: account, crypto: Crypto()), .pending)

		XCTAssertEqual(run(store).code, "ok")
		XCTAssertEqual(store.lastCode(account: account), "ok")
		XCTAssertEqual(BeamioPgpMigrationImport.derivedState(store: store, eoa: eoa, account: account, crypto: Crypto()), .verified)
	}

	func testAFailedRunIsFailedUntilARetryFinishes() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		store.rereadMismatch = true
		XCTAssertEqual(run(store).code, "reread_failed")
		XCTAssertEqual(BeamioPgpMigrationImport.derivedState(store: store, eoa: eoa, account: account, crypto: Crypto()), .failed)

		store.rereadMismatch = false
		XCTAssertEqual(run(store).code, "ok")
		XCTAssertEqual(BeamioPgpMigrationImport.derivedState(store: store, eoa: eoa, account: account, crypto: Crypto()), .verified)
	}

	// MARK: X-19 approval gate

	func testWhileTheApprovalIsClosedNothingIsWritten() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let before = PgpMigrationTestSupport.snapshot(store)

		XCTAssertEqual(run(store, approved: false).code, "verify_unavailable")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), before)
		XCTAssertEqual(store.stagedWrites, 0)
	}

	/// the approval is open for this path only. With the production environment and no chain configured, the run gets as
	/// far as the chain read (after the local checks), which fails, so it writes nothing.
	func testTheProductionRunReachesTheChainReadAndWritesNothingWithoutIt() throws {
		try PgpMigrationTestSupport.requireX19()
		XCTAssertTrue(BeamioPgpMigrationImport.x19Approved, "approved for the migration path only")
		let savedConfiguration = AddressPGPChain.configuration
		AddressPGPChain.configuration = nil
		defer { AddressPGPChain.configuration = savedConfiguration }
		let memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.memory = memory
		let a = PgpMigrationTestSupport.key("A")
		XCTAssertTrue(BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: a.privateArmor, publicKeyArmor: a.publicArmor, pgpKeyId: a.keyId,
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa
		)))
		let stored = memory.values

		XCTAssertEqual(BeamioPgpMigrationImport.run(eoa: eoa).code, "chain_unavailable")
		// The finished run records its last code; no copy or marker may change.
		let copies = memory.values.filter { !$0.key.hasSuffix("|migrationLastCode") }
		XCTAssertEqual(copies, stored.filter { !$0.key.hasSuffix("|migrationLastCode") }, "no copy or marker is written when the chain cannot confirm the registration")
		XCTAssertEqual(memory.values[account + "|migrationLastCode"], "chain_unavailable")
	}

	// MARK: Bridge

	private func command(_ body: [String: Any], environment: BeamioPgpMigrationImport.Environment? = nil) {
		BeamioConetChatModule.pgpMigrationEnvironmentOverride = environment
		events = []
		BeamioConetChatModule.handleCommand(body, emit: { [weak self] event in
			self?.events.append((event["event"] as? [String: Any]) ?? event)
		})
		let deadline = Date().addingTimeInterval(15)
		while !events.contains(where: { $0["type"] as? String == "ack" }) && Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.01))
		}
		RunLoop.main.run(until: Date().addingTimeInterval(0.02))
	}

	func testAPrivateKeyFieldIsRefusedBeforeTheGateAndNothingIsWritten() throws {
		try PgpMigrationTestSupport.requireX19()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		command(["type": "pgpMigrate", "reqId": "r1", "pgpPrivateKeyArmored": "x"])
		let ack = events.first { $0["type"] as? String == "ack" }
		XCTAssertEqual(ack?["error"] as? String, "key_over_bridge_refused")
		XCTAssertFalse(String(describing: events).contains("\"x\""), "the value of the refused field is never echoed")
	}

	func testAnUnknownFieldIsABadRequest() throws {
		try PgpMigrationTestSupport.requireX19()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		command(["type": "pgpMigrate", "reqId": "r1", "note": "x"])
		XCTAssertEqual(events.first { $0["type"] as? String == "ack" }?["error"] as? String, "bad_request")
	}

	func testTheResultEventCarriesOnlyTheCodeAndTheFingerprintPrefix() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = seeded()
		let keyStore = NativeAccountCreateTests.CreateKeyStore()
		keyStore.keys[eoa] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = keyStore
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: PasscodeNoRecords(), hardware: PasscodeNoHardware())

		let env = PgpMigrationTestSupport.environment(store: store, crypto: Crypto(), registeredArmor: PgpMigrationTestSupport.key("A").publicArmor)
		command(["type": "pgpMigrate", "reqId": "r7"], environment: env)

		XCTAssertEqual(events.first { $0["type"] as? String == "ack" }?["ok"] as? Bool, true)
		let result = try XCTUnwrap(events.first { $0["type"] as? String == "pgpMigrateResult" })
		XCTAssertEqual(Set(result.keys), ["type", "reqId", "code", "fp"])
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertEqual(result["fp"] as? String, fp16("A"))
		XCTAssertFalse(String(describing: events).contains("PRIVATE KEY"))
	}

	private final class PasscodeNoRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { [] }
		func readRecord(eoa: String) -> Data? { nil }
		func writeRecord(eoa: String, _ value: Data) -> Bool { true }
		func deleteRecord(eoa: String) {}
	}

	private final class PasscodeNoHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { false }
		func createKey(eoa: String) -> Bool { false }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { throw BeamioPasscodeError.hardwareUnavailable }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { throw BeamioPasscodeError.hardwareUnavailable }
		func deleteKey(eoa: String) {}
	}

	// MARK: Keychain items

	func testTheCopyIsOneItemThatAnUpdateReplacesAndTheMarkerHoldsNoKey() throws {
		try PgpMigrationTestSupport.requireX19()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		let store = BeamioPgpMigrationImport.KeychainStore()
		let a = PgpMigrationTestSupport.staged(PgpMigrationTestSupport.key("A"))
		let b = PgpMigrationTestSupport.staged(PgpMigrationTestSupport.key("B"))

		XCTAssertTrue(store.writeStaged(account: account, a))
		XCTAssertEqual(store.staged(account: account), a)
		XCTAssertTrue(store.writeStaged(account: account, b), "a single update replaces the copy")
		XCTAssertEqual(store.staged(account: account), b)

		let marker = PgpMigrationTestSupport.marker(PgpMigrationTestSupport.key("A"))
		XCTAssertTrue(store.writeMarker(account: account, marker))
		XCTAssertEqual(store.marker(account: account), marker)
		let markerJSON = try XCTUnwrap(BeamioChatPgpKeychain.memory?.values[account + "|migrationMarker"])
		XCTAssertFalse(markerJSON.contains("PRIVATE KEY"))
		XCTAssertFalse(markerJSON.contains("BEGIN"))
	}

	func testTheReadOnlyRecordAdoptsNothingAndWritesNothing() throws {
		try PgpMigrationTestSupport.requireX19()
		let memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.memory = memory
		let a = PgpMigrationTestSupport.key("A")
		// A record in the pre-D5 layout (plain item names), naming this account.
		memory.values["userPgpPrivateArmor"] = a.privateArmor
		memory.values["userPgpPublicArmor"] = a.publicArmor
		memory.values["userPgpKeyId"] = a.keyId
		memory.values["recipientEoa"] = eoa
		let before = memory.values

		let read = try XCTUnwrap(BeamioChatPgpKeychain.readOnlyRecord(eoa: eoa))
		XCTAssertEqual(read.privateKeyArmor, a.privateArmor)
		XCTAssertEqual(read.eoa, eoa)
		XCTAssertEqual(memory.values, before, "the legacy record is read, not moved")
		XCTAssertNil(BeamioChatPgpKeychain.readOnlyRecord(eoa: PgpMigrationTestSupport.otherEoa), "a record of another account is not read")
	}

	// MARK: Unregistration

	/// A copy N and a marker M of key A, and L (key A) when `withRecord` is true.
	private func storedCopy(withRecord: Bool) -> MemoryStore {
		let store = MemoryStore()
		let a = PgpMigrationTestSupport.key("A")
		if withRecord {
			store.legacyRecords[eoa] = PgpMigrationTestSupport.legacy(privateKey: a, publicKey: a)
		}
		store.stagedRecords[account] = PgpMigrationTestSupport.staged(a)
		store.markerRecords[account] = PgpMigrationTestSupport.marker(a)
		return store
	}

	private func unregister(
		_ store: MemoryStore,
		pReadable: Bool = false,
		chainRegistered: Bool = false,
		wallet: PgpMigrationTestSupport.WalletProbe = PgpMigrationTestSupport.WalletProbe(),
		interrupt: BeamioPgpMigrationImport.Checkpoint? = nil
	) -> BeamioPgpMigrationImport.Outcome {
		let env = PgpMigrationTestSupport.environment(
			store: store,
			crypto: Crypto(),
			registeredArmor: nil,
			chainBackupRegistered: chainRegistered,
			sourcePReadable: pReadable,
				wallet: wallet,
			interrupt: interrupt
		)
		return BeamioPgpMigrationImport.unregisterInternal(eoa: eoa, workspace: BeamioChatPgpKeychain.defaultWorkspace, env: env)
	}

	func testUnregisterWithoutAnyRecoverySourceRemovesNothing() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = storedCopy(withRecord: false)
		let before = PgpMigrationTestSupport.snapshot(store)
		XCTAssertEqual(unregister(store).code, "unregister_refused")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store), before, "nothing is removed before the source is confirmed")
	}

	func testUnregisterRemovesTheMarkerFirstAndThenTheCopyAndKeepsTheRecord() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = storedCopy(withRecord: true)
		let before = PgpMigrationTestSupport.snapshot(store)

		let stopped = unregister(store, interrupt: .afterMarkerDeleted)
		XCTAssertTrue(stopped.interrupted)
		XCTAssertNil(store.markerRecords[account], "the marker goes first")
		XCTAssertNotNil(store.stagedRecords[account], "the copy stays until the retry (pending)")
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa], "L is never removed")

		XCTAssertEqual(unregister(store).code, "ok")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertEqual(PgpMigrationTestSupport.snapshot(store)["L|" + eoa], before["L|" + eoa], "L is never removed")
	}

	func testUnregisterWithAReadableSourceRemovesTheCopy() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = storedCopy(withRecord: false)
		XCTAssertEqual(unregister(store, pReadable: true).code, "ok")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertNil(store.markerRecords[account])
	}

	func testUnregisterWithABackupRegisteredOnChainRemovesTheCopy() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = storedCopy(withRecord: false)
		XCTAssertEqual(unregister(store, chainRegistered: true).code, "ok")
		XCTAssertNil(store.stagedRecords[account])
		XCTAssertNil(store.markerRecords[account])
	}

	func testUnregisterRemovesTheWalletFieldsWhenARecoverySourceIsConfirmed() throws {
		try PgpMigrationTestSupport.requireX19()
		let wallet = PgpMigrationTestSupport.WalletProbe(present: true)
		XCTAssertEqual(unregister(seeded(), wallet: wallet).code, "ok")
		XCTAssertFalse(wallet.present, "the W-class fields are removed")
		XCTAssertEqual(wallet.removals, 1)
	}

	/// D9 (UG-12, r3qy/interface): a W-class copy needs a recovery source even without M or N. A W-only account with no source is refused and
	/// keeps its W fields; with a source (P readable) the W fields are removed and the answer is ok. The earlier r3rb expectation is withdrawn.
	func testUnregisterWithOnlyWalletFieldsNeedsARecoverySource() throws {
		try PgpMigrationTestSupport.requireX19()
		let refused = PgpMigrationTestSupport.WalletProbe(present: true)
		XCTAssertEqual(unregister(MemoryStore(), wallet: refused).code, "unregister_refused")
		XCTAssertTrue(refused.present, "UG-12: the W fields are kept")
		XCTAssertEqual(refused.removals, 0)
		let sourced = PgpMigrationTestSupport.WalletProbe(present: true)
		XCTAssertEqual(unregister(MemoryStore(), pReadable: true, wallet: sourced).code, "ok")
		XCTAssertFalse(sourced.present)
		XCTAssertEqual(sourced.removals, 1)
	}

	/// D9: a W-class copy that cannot be removed refuses the unregister, and nothing else is touched.
	func testAFailedWalletRemovalRefusesTheUnregister() throws {
		try PgpMigrationTestSupport.requireX19()
		let store = storedCopy(withRecord: true)
		let wallet = PgpMigrationTestSupport.WalletProbe(present: true, removes: false)
		XCTAssertEqual(unregister(store, wallet: wallet).code, "unregister_refused")
		// deletes the W-class fields last. The marker and the copy go before them; L and the W fields stay.
		XCTAssertNotNil(store.legacyRecords[eoa], "L is never removed")
		XCTAssertTrue(wallet.present, "the W-class fields stay when their removal fails")
	}

	func testUnregisterOfAnAccountWithoutCopiesIsOk() throws {
		try PgpMigrationTestSupport.requireX19()
		XCTAssertEqual(unregister(MemoryStore()).code, "ok")
	}
}
#endif
