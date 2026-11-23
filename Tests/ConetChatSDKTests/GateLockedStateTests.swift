import XCTest
@testable import ConetChatSDK

/// The locked state of (the fourth of the five states), in the test target only. A passcode record is written for the account through
/// the vault's own record store; the session holds no unlocked bundle, so `appState` is `locked`. Nothing here is a product hook: it uses the
/// public `vault` property of the session and restores it in tearDown. Synthetic data only.
final class GateLockedStateTests: XCTestCase {
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

	private var savedVault: BeamioPasscodeVault?
	private let account = PgpMigrationTestSupport.eoa

	override func setUp() {
		super.setUp()
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPasscodeSession.shared.lockAll()
	}

	override func tearDown() {
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		super.tearDown()
	}

	private final class LockedStore: BeamioChatWalletKeyStoring {
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

	/// Sends one command and returns its answer with the reqId, after the main queue has drained.
	private func answerOf(_ body: [String: Any], reqId: Int) -> [String: Any]? {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		return events.first { $0["reqId"] as? Int == reqId }
	}

	/// step 4: with the session ready and the account locked, a known command of the table is answered `locked` at the
	/// gate, before its parameters and stubs. A name outside the table is unknown_command, a retired name is not_supported (step 3), and
	/// passcodeRun stays open, because it is the way to unlock.
	func testWithoutThePasscodeBundleEveryGatedCommandAnswersNotReadyWithItsReason() throws {
		let savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		defer {
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
		let store = LockedStore()
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		let records = MemoryRecords()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[account] = (try? JSONEncoder().encode(passcodeRecord)) ?? Data()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked)

		var reqId = 8200
		// The families of with a bridge name (N1 to N4 named in the N table): C1, C2, C3, C5, W7, N0, N1, N2, N3, N4.
		for name in ["historySign", "gossipSign", "pgpDecryptInbound", "deriveSubkeys", "ephemeralSign", "walletAddress",
		             "walletSignTypedData", "walletSignMessage", "walletSendTransaction", "walletSignUserOp"] {
			reqId += 1
			// No parameters are sent.: the answer is not `locked`; with the passcode bundle not provided it is `not_ready` with the reason
			// `passcode_not_provided` (envelope `ok:false`, no payload read), as the exemption vector v2 says.
			let answer = answerOf(["type": name, "reqId": reqId], reqId: reqId)
			XCTAssertEqual(answer?["error"] as? String, "not_ready", name)
			XCTAssertEqual(answer?["reason"] as? String, "passcode_not_provided", name)
			XCTAssertEqual(answer?["ok"] as? Bool, false, name)
		}
		// every L-LOCK case of passcode-locked-exemption-vectors.v2, one by one
		let data = try? BundledVectorFile.data(resource: "passcode-locked-exemption-vectors.v2")
		let root = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
		let cases = (root?["cases"] as? [[String: Any]] ?? []).filter { ($0["id"] as? String ?? "").hasPrefix("L-LOCK-") }
		XCTAssertFalse(cases.isEmpty, "the vector has L-LOCK cases")
		for c in cases {
			reqId += 1
			let id = c["id"] as? String ?? "?"
			let command = c["command"] as? String ?? ""
			let expect = c["expect"] as? [String: Any] ?? [:]
			let answer = answerOf(["type": command, "reqId": reqId], reqId: reqId)
			XCTAssertEqual(answer?["ok"] as? Bool, expect["ok"] as? Bool, id)
			XCTAssertEqual(answer?["error"] as? String, expect["error"] as? String, id)
			XCTAssertEqual(answer?["reason"] as? String, expect["reason"] as? String, id)
		}
		reqId += 1
		XCTAssertNotEqual(answerOf(["type": "passcodeRun", "reqId": reqId], reqId: reqId)?["error"] as? String, "locked", "passcodeRun stays open")
		reqId += 1
		let unknown = answerOf(["type": "notAListedName", "reqId": reqId], reqId: reqId)
		XCTAssertEqual(unknown?["error"] as? String, "unknown_command")
		reqId += 1
		let retired = answerOf(["type": "walletTransferOnce", "reqId": reqId], reqId: reqId)
		XCTAssertEqual(retired?["error"] as? String, "not_supported")
		reqId += 1
		XCTAssertEqual(answerOf(["type": "identity.provision", "reqId": reqId], reqId: reqId)?["error"] as? String, "unknown_command",
		               "identity.provision is a spec name, not a bridge name")
	}

	/// A passcode is set for the account and nothing is unlocked: the state is locked. An unknown name is `unknown_command`, judged before the
	/// gate and in this state too, with one answer and the reqId echoed.
	func testAnUnknownNameIsUnknownCommandWhenTheAccountIsLocked() throws {
		let records = MemoryRecords()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[account] = try JSONEncoder().encode(passcodeRecord)
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked, "a passcode is set and no bundle is unlocked")

		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "notAListedName", "reqId": 8101]) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		// The module answers on the main queue: drain it once before reading the answer.
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		XCTAssertEqual(events.count, 1, "one answer")
		XCTAssertEqual(events.first?["error"] as? String, "unknown_command")
		XCTAssertEqual(events.first?["reqId"] as? Int, 8101)
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked, "the answer does not unlock the account")
	}

	/// the C4 function does not sign while the account is locked. It refuses every purpose, because the purpose registry is empty
	/// the answer is a refusal, never a signature, and no key is read. The account has a passcode and nothing is unlocked.
	func testPgpSignDoesNotSignWhileLocked() throws {
		let records = MemoryRecords()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[account] = try JSONEncoder().encode(passcodeRecord)
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked)
		let result = BeamioNativeWallet.pgpSign(eoa: account, purposeId: "chatEnvelope", sigType: 0x00, data: Data([1]))
		if case .success = result { XCTFail("pgpSign produced a signature while the registry is empty") }
		// no `locked` return; the purpose registry is empty, so the refusal is the purpose check, and nothing is signed.
		XCTAssertEqual(result, .failure(.rejected("purpose_not_registered")))
	}

	/// 25.52Y.118: a passcode lock answers `locked` with no accountKey and no reason. The key record is readable, so the lock is the answer.
	func testWalletStatusPasscodeLockHasNoAccountKey() {
		final class Box { var events: [[String: Any]] = [] }
		let savedStore = BeamioNativeWallet.keyStore
		let store = LockedStore()
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		let records = MemoryRecords()
		let passcodeRecord = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[account] = (try? JSONEncoder().encode(passcodeRecord)) ?? Data()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		defer {
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked)
		let box = Box()
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 9301], emit: { event in
			box.events.append((event["event"] as? [String: Any]) ?? event)
		})
		let deadline = Date().addingTimeInterval(5)
		while box.events.isEmpty, Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.02))
		}
		let result = box.events.first?["result"] as? [String: Any]
		// the real state replaces the earlier `locked` answer: not_ready, the reason passcode_not_provided, retryable, no accountKey.
		XCTAssertEqual(result?["status"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "passcode_not_provided")
		XCTAssertEqual(result?["retryable"] as? Bool, true)
		XCTAssertNil(result?["accountKey"], "25.52Y.118: no accountKey")
		XCTAssertNil(result?["reason"], "the reason is notReadyReason, not reason")
	}
}
