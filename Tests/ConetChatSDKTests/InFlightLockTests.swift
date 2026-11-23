import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// The passcode lock found while a PGP command is in flight. The lock is made by
/// `BeamioPasscodeSession.shared.lockAll` after the command has passed its gate, while its chain read is held in the test transport.
/// The transport and the lock are restored in the defer. Synthetic data only.
final class InFlightLockTests: XCTestCase {
	private final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	/// A synthetic hardware layer for the test only: wrap and unwrap are the identity. It is not a security control.
	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private final class RegistrationProbe: BeamioPGPIdentityCreate.Registering {
		var calls = 0
		func register(eoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error> {
			calls += 1
			return .success(())
		}
	}

	private let account = PgpMigrationTestSupport.eoa

	/// G2 with a passcode set and the account unlocked: the gate passes, and a later `lockAll` is a lock found in flight. Returns the restore closure.
	private func arrangeUnlocked() -> () -> Void {
		let savedStore = BeamioNativeWallet.keyStore
		let savedVault = BeamioPasscodeSession.shared.vault
		let savedMemory = BeamioChatPgpKeychain.memory
		let savedConfiguration = AddressPGPChain.configuration
		let savedTransport = AddressPGPChain.transport
		NativeAccountPointerIsolation.begin()
		let store = Store()
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		let records = MemoryRecords()
		let passcode = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[account] = (try? JSONEncoder().encode(passcode)) ?? Data()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		BeamioPasscodeSession.shared.lockAll()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		// the pointer first, then the session: a pointer change ends every session (frozen protocol, session clearing)
		BeamioPasscodeSession.shared.install(eoa: account, bundle: [UInt8](repeating: 0x33, count: 32))
		AddressPGPChain.configuration = AddressPGPChain.Configuration(
			contract: "0x" + String(repeating: "1", count: 40), chainId: 224422, rpcURL: URL(string: "https://rpc.test.invalid")!
		)
		XCTAssertFalse(BeamioPasscodeSession.shared.isLocked(eoa: account), "the account is unlocked before the command starts")
		return {
			AddressPGPChain.transport = savedTransport
			AddressPGPChain.configuration = savedConfiguration
			BeamioPasscodeSession.shared.lockAll()
			BeamioPasscodeSession.shared.vault = savedVault
			BeamioChatPgpKeychain.memory = savedMemory
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
	}

	/// Holds the chain read of the command in flight until the test releases it. The read is the only step the command takes before its output.
	private func holdTheRead(entered: XCTestExpectation, release: DispatchSemaphore) {
		AddressPGPChain.transport = { _, _ in
			entered.fulfill()
			_ = release.wait(timeout: .now() + 20)
			return .failure(AddressPGPChain.ReadError.transport("released by the test"))
		}
	}

	///,: a `pgpRestore` that passed its gate sends `accepted` once, before the read. A lock that comes while the read is held
	/// then gives one `pgpRestoreResult` with `cancelled`. It carries no data and writes nothing locally.
	func testAPGPRestoreLockedInFlightIsCancelledOnceWithNoData() {
		let restore = arrangeUnlocked()
		defer { restore() }
		let entered = expectation(description: "the read of the restore reached the transport")
		let release = DispatchSemaphore(value: 0)
		holdTheRead(entered: entered, release: release)
		var events: [[String: Any]] = []
		let answered = expectation(description: "the restore result arrives after the release")
		let emit: BeamioConetChatModule.WebEmit = { payload in
			guard let event = payload["event"] as? [String: Any], event["reqId"] as? Int == 9101 else { return }
			events.append(event)
			if event["type"] as? String == "pgpRestoreResult" { answered.fulfill() }
		}
		BeamioConetChatModule.handleCommand(["type": "pgpRestore", "reqId": 9101, "accountKey": account + ":default"], emit: emit)
		wait(for: [entered], timeout: 5)
		// the accepted ack is queued to the main queue before the read starts, so it is delivered ahead of any later result. Drain the
		// main queue, then check that it is the only event while the read is held.
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		XCTAssertEqual(events.map { $0["type"] as? String }, ["ack"], "accepted is sent before the read")
		BeamioPasscodeSession.shared.lockAll()
		release.signal()
		wait(for: [answered], timeout: 10)
		// the ack `accepted` is sent before the read, once; then one result.
		XCTAssertEqual(events.count, 2, "the accepted ack, then exactly one result")
		XCTAssertEqual(events.first?["type"] as? String, "ack")
		XCTAssertEqual(events.first?["ok"] as? Bool, true)
		XCTAssertEqual((events.first?["result"] as? [String: Any])?["accepted"] as? Bool, true)
		XCTAssertEqual(events.last?["type"] as? String, "pgpRestoreResult")
		// a passcode lock in flight is not an application-level event any more: the restore is not `cancelled` by it.
		// the held read gave no source, so the restore ends with the source code, not with `cancelled` and not with `locked`
		XCTAssertEqual(events.last?["code"] as? String, "pgp_source_unavailable", "a lock in flight does not cancel the restore")
		XCTAssertEqual(events.last?["state"] as? String, "undetermined")
		XCTAssertNil(events.last?["record"], "no data is returned")
		XCTAssertNil(events.last?["result"], "no data is returned")
	}

	/// a `pgpRestoreEvaluate` whose lock comes before its answer answers `locked`, once, with no evaluation result.
	func testAPGPRestoreEvaluateLockedInFlightAnswersLockedOnce() {
		let restore = arrangeUnlocked()
		defer { restore() }
		let entered = expectation(description: "the read of the evaluation reached the transport")
		let release = DispatchSemaphore(value: 0)
		holdTheRead(entered: entered, release: release)
		var answers: [[String: Any]] = []
		let answered = expectation(description: "the evaluation answers after the release")
		let emit: BeamioConetChatModule.WebEmit = { payload in
			guard let event = payload["event"] as? [String: Any], event["reqId"] as? Int == 9102 else { return }
			answers.append(event)
			answered.fulfill()
		}
		BeamioConetChatModule.handleCommand(["type": "pgpRestoreEvaluate", "reqId": 9102, "accountKey": account + ":default"], emit: emit)
		wait(for: [entered], timeout: 5)
		BeamioPasscodeSession.shared.lockAll()
		release.signal()
		wait(for: [answered], timeout: 10)
		XCTAssertEqual(answers.count, 1, "one answer to the evaluation")
		// no `locked` answer; the evaluation answers from what it read (here the held read gave no source).
		// the evaluation answers from what it read: ok with an undetermined result (the held read gave no source), not `locked`
		XCTAssertNil(answers.first?["error"] as? String, "no error word: not `locked`")
		let evaluation = answers.first?["result"] as? [String: Any]
		XCTAssertEqual(evaluation?["state"] as? String, "undetermined")
		XCTAssertEqual(evaluation?["code"] as? String, "pgp_source_unavailable")
	}

	/// a passcode lock found before the chain write of the identity creation: no chain write, the pending secret is dropped, and the
	/// result is `cancelled`.
	func testAnIdentityConfirmLockedBeforeTheChainWriteIsCancelledWithNoWrite() {
		let restore = arrangeUnlocked()
		defer { restore() }
		let probe = RegistrationProbe()
		let savedRegistration = BeamioPGPIdentityCreate.registration
		BeamioPGPIdentityCreate.registration = probe
		defer { BeamioPGPIdentityCreate.registration = savedRegistration }
		let pending = BeamioChatPgpKeychain.PendingIdentity(
			privateArmor: "SYNTHETIC-PRIVATE-ARMOR", publicArmor: "SYNTHETIC-PUBLIC-ARMOR", idempotencyKey: "key-1", seen: "seen-1"
		)
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: account, pending))
		BeamioPasscodeSession.shared.lockAll()
		let outcome = BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "key-1")
		// a passcode lock is not an application-level event; the confirmation is not `cancelled` by it and goes on to its own write.
		XCTAssertEqual(outcome, .failed("write_failed"), "the confirmation reaches the chain write; the probe answers a write failure")
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(outcome), "retry_write")
		XCTAssertEqual(probe.calls, 1, "the confirmation reaches the chain write as for an unlocked account")
	}

	/// C-28 (pgp-bridge-command-vectors, the row itself): the ack `accepted` is the only answer while the read is held, then one
	/// `pgpRestoreResult` `cancelled`. Both lines are compared with the vector row, under the row's own reqId (`c3-c-28`). No local write.
	func testGroupC28AckAndResultMatchTheVectorRow() throws {
		let restore = arrangeUnlocked()
		defer { restore() }
		let row = try GroupCVector.row("C-28")
		let request = try XCTUnwrap(row["request"] as? [String: Any])
		let reqId = try XCTUnwrap(request["reqId"] as? String)
		let entered = expectation(description: "the read of the restore reached the transport")
		let release = DispatchSemaphore(value: 0)
		holdTheRead(entered: entered, release: release)
		var answers: [[String: Any]] = []
		let resulted = expectation(description: "the result arrives after the release")
		let emit: BeamioConetChatModule.WebEmit = { payload in
			guard let event = payload["event"] as? [String: Any], event["reqId"] as? String == reqId else { return }
			answers.append(event)
			if event["type"] as? String == "pgpRestoreResult" { resulted.fulfill() }
		}
		BeamioConetChatModule.handleCommand(request, emit: emit)
		wait(for: [entered], timeout: 5)
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		XCTAssertEqual(answers.map { $0["type"] as? String }, ["ack"], "the accepted ack is the only answer while the read is held")
		BeamioPasscodeSession.shared.lockAll()
		release.signal()
		wait(for: [resulted], timeout: 10)
		let differing = try GroupCVector.differences(row: row, answers: answers)
		print("GROUP-C-RUN C-28: \(differing.isEmpty ? "matches the vector" : "differs in \(differing.joined(separator: ", "))")")
		XCTAssertTrue(differing.isEmpty, "C-28: the answers differ from the vector in \(differing.joined(separator: ", "))")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "C-28: nothing is written locally")
	}

	/// a lock found right before the save writes nothing and returns `cancelled`. Without a lock, the same
	/// evaluation is written and read back.
	func testWriteLocalStopsBeforeTheSaveWhenTheAccountIsLocked() {
		let restore = arrangeUnlocked()
		defer { restore() }
		let evaluation = BeamioPGPRestoreCommands.Evaluation(
			state: "ok", failureClass: nil, code: nil, offerEntry: false, uiKey: nil,
			armor: "-----BEGIN PGP PRIVATE KEY BLOCK-----SYNTHETIC-----END PGP PRIVATE KEY BLOCK-----", chainPublicArmor: "-----BEGIN PGP PUBLIC KEY BLOCK-----SYNTHETIC-----END PGP PUBLIC KEY BLOCK-----", chainSubkeyKeyID: "SYNTHETIC-KEY-ID", restoredSubkeyKeyID: nil
		)
		let locked = BeamioPGPRestoreCommands.writeLocal(eoa: account, evaluation: evaluation, stillUnlocked: { false })
		XCTAssertEqual(locked.code, "cancelled", "a lock before the save is cancelled")
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: account), "nothing is written")
		let unlocked = BeamioPGPRestoreCommands.writeLocal(eoa: account, evaluation: evaluation, stillUnlocked: { true })
		XCTAssertEqual(unlocked.code, "ok", "without a lock the record is written and read back")
	}
}
#endif
