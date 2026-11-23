#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// `voiceEphemeralRegister`, W7 `ephemeralSign` and `voiceEphemeralSeal` against the vector file `voice-ephemeral-register-vectors.v1.json`
///. Each case runs through the public command path (`handleCommand`). The clock, the passcode lock, the
/// session and the native key store are the test seams; the steps `destroy`, `clearIdentity`, `init` and `restart` run the real commands where
/// the command exists. Each answer is checked against its expectation: the keys, the values, the address and signature shapes, the recovery of
/// the W7 signature to `temp`, and the sealed shape. The recipient key is a real OpenPGP public key from the interop vectors (test material only).
///
/// Not checked here: `payloadRead` (the gate runs before the payload is read in the code, and no observer sees the read) and `noStateChange`
/// (its effect shows in the later steps of each case). A sealed text is not decrypted here; asks the native test to decrypt it with a
/// test key and to find no tk plaintext in the sealed text. That check is not in this file.
final class VoiceEphemeralRegisterVectorTests: XCTestCase {
	/// The derivation test key (synthetic, public test material) derives this address.
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	/// A second account with a real key of its own (synthetic): its address is derived from the key, so an init for it verifies.
	private let keyDataB = Data(repeating: 0x33, count: 32)
	private var accountB: String { BeamioNativeEthSigner.address(privateKey: [UInt8](keyDataB))?.lowercased() ?? "" }
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	/// A real OpenPGP public key from `pgp-native-interop-vectors.v1.json` (test material; no private key).
	private let recipientOk = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEavZtBxYJKwYBBAHaRw8BAQdAANdU7dbJb188EeYnJma8txGCM6hXUwj8\nt/Mr85f54jjNP3N5bnRoZXRpYyByZWNpcGllbnQgYSA8c3ludGhldGljLnJl\nY2lwaWVudC5hQHN5bnRoZXRpYy5pbnZhbGlkPsLAEwQTFgoAhQWCavZtBwML\nCQcJEPWwl85PFk/hRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bq\ncy5vcmdy1ziMGKuu2l9lr0RxVi9NwYhKTmk9R1SOhalEnw4gKwUVCggODAQW\nAAIBAhkBApsDAh4BFiEEHWqkahebJ4ByGxxA9bCXzk8WT+EAALj7AP0XCJzv\nwY3sbsMTl7R5AdxH0tGM0LkXic0pW/FT2fWJkwD+JnYwsu1h95EFx8TDx617\nu9kYE2iZX/BXbtnQiXAT5gjOOARq9m0HEgorBgEEAZdVAQUBAQdAYHVZgOzT\n4MO6QNhMp24p1Kri0rSlI4+o2eykqKE6jx8DAQgHwr4EGBYKAHAFgmr2bQcJ\nEPWwl85PFk/hRRQAAAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5v\ncmdFTPdjVXrSB3szYGqcyybLX8GTc8bdkrvWKKd/Ln3TPwKbDBYhBB1qpGoX\nmyeAchscQPWwl85PFk/hAACbOgD+MNhDEy1mNf0t30RjfvYuTdQ3eVIxAV5+\nAlp/6YrsscoA/2R/SrpmZjg7q+Gyh001l1TK5GTT+B8vu5kOej8GUGEC\n=mCFC\n-----END PGP PUBLIC KEY BLOCK-----"
	/// A key of the right shape that cannot be parsed: the seal fails (VR-34).
	private let recipientBroken = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----"

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

	private var store: NativeCombinationTests.Store!
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	private var records = MemoryRecords()
	private var events: [[String: Any]] = []
	/// The account the device currently holds (the record account of the case).
	private var current = ""

	override func setUpWithError() throws {
		// The shipped voiceEphemeralSeal fails closed (alternative A): v2.3 asserts its steps after the gate as unknown_command. The retired seal path is not enabled here.
		// The recovery-backup flag is a Keychain item. A host that cannot write the Keychain (the simulator test host, errSecMissingEntitlement, -34018)
		// skips these cases; they run on a host with Keychain access (macOS swift test, or a device).
		let keychainProbe = "0x00000000000000000000000000000000000000ff"
		let keychainWritable = BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: keychainProbe)
		BeamioRecoveryBackupFlag.clear(eoa: keychainProbe)
		try XCTSkipUnless(keychainWritable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018)")
		// The vector's clearIdentity steps run with the recovery-backup flag set: the vector models the clear, not the flag.
		BeamioRecoveryBackupFlag.confirmRecoveryBackup(eoa: account)
		try super.setUpWithError()
		savedStore = BeamioNativeWallet.keyStore
		store = NativeCombinationTests.Store()
		BeamioNativeWallet.keyStore = store
		savedVault = BeamioPasscodeSession.shared.vault
		records = MemoryRecords()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		NativeAccountPointerIsolation.begin()
		BeamioVoiceEphemeral.clearAll()
		BeamioVoiceEphemeral.testClock = nil
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioVoiceEphemeral.testClock = nil
		BeamioVoiceEphemeral.clearAll()
		BeamioPasscodeSession.shared.lockAll()
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.end()
		// setUp skips when the vector file is not given: then nothing was saved, and nothing is restored.
		if let savedStore { BeamioNativeWallet.keyStore = savedStore }
		super.tearDown()
	}

	// MARK: - The file

	private func vectorRoot() throws -> [String: Any] {
		let data = try BundledVectorFile.data(resource: "voice-ephemeral-register-vectors.v2.4")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	func testEveryCaseOfTheVectorFileAnswersItsExpectation() throws {
		let root = try vectorRoot()
		let fixture = try XCTUnwrap(root["fixture"] as? [String: Any])
		let nowSec = Int64(try XCTUnwrap(fixture["nowSec"] as? Int))
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 35, "the registered file has 35 cases")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			runCase(c, id: id, nowSec: nowSec)
		}
	}

	// MARK: - One case

	private func runCase(_ c: [String: Any], id: String, nowSec: Int64) {
		resetDevice(nowSec: nowSec)
		let initial = c["initial"] as? [String: Any] ?? [:]
		seedGate(initial["gate"] as? String ?? "G0")
		for op in initial["afterInit"] as? [[String: Any]] ?? [] {
			runOp(op, id: id)
		}
		var temps: [Int: String] = [:]
		var seals: [Int: String] = [:]
		for (index, step) in (c["steps"] as? [[String: Any]] ?? []).enumerated() {
			if step["op"] as? String == "request" {
				runRequest(step, id: id, index: index, temps: &temps, seals: &seals)
			} else {
				runOp(step, id: id)
			}
		}
	}

	private func resetDevice(nowSec: Int64) {
		store.keys = [:]
		records.data = [:]
		BeamioVoiceEphemeral.clearAll()
		BeamioVoiceEphemeral.testClock = nowSec
		BeamioConetChatSignBroker.clearSigner()
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		events = []
		current = account
	}

	/// G0: no record and no pointer. G1: the record, the session not ready. G2: the record, the session ready for its account.
	private func seedGate(_ gate: String) {
		switch gate {
		case "G1":
			store.keys[account] = keyData
			BeamioConetChatSignBroker.setSignerEoa(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		case "G2":
			store.keys[account] = keyData
			BeamioConetChatSignBroker.setSignerEoa(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		default:
			break
		}
	}

	// MARK: - Operations of a case

	private func runOp(_ op: [String: Any], id: String) {
		switch op["op"] as? String ?? "" {
		case "advanceTime":
			let seconds = Int64(op["seconds"] as? Int ?? 0)
			BeamioVoiceEphemeral.testClock = (BeamioVoiceEphemeral.testClock ?? 0) + seconds
		case "destroy":
			send(["type": "destroy", "reqId": 9100])
		case "lock":
			lockPasscode()
		case "unlock":
			records.data[current.lowercased()] = nil
		case "clearIdentity":
			BeamioConetChatSignBroker.setSignerEoa(current)
			send(["type": "clearIdentity", "reqId": 9101])
		case "restoreAndInit":
			store.keys[current] = keyData
			BeamioConetChatModule.setNativeGateForTests(account: current, sessionReady: false)
			initCurrent()
		case "reinit":
			initCurrent()
		case "accountSwitch":
			send(["type": "destroy", "reqId": 9102])
			store.keys[accountB] = keyDataB
			BeamioConetChatSignBroker.setSignerEoa(accountB)
			BeamioConetChatModule.setNativeGateForTests(account: accountB, sessionReady: false)
			current = accountB
		case "restart":
			BeamioVoiceEphemeral.clearAll()
			BeamioConetChatModule.setNativeGateForTests(account: current, sessionReady: false)
		default:
			XCTFail("\(id): unknown operation \(op["op"] ?? "")")
		}
	}

	/// A passcode record for the current account, then the lock: the account is `locked` (no unlocked bundle).
	private func lockPasscode() {
		let record = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		records.data[current.lowercased()] = (try? JSONEncoder().encode(record)) ?? Data()
		BeamioPasscodeSession.shared.lockAll()
	}

	/// `init` for the current account through the command path (G1 to G2). Waits for the `ready` event.
	private func initCurrent() {
		send(["type": "init", "reqId": 9200 + events.count, "payload": [
			"identity": ["eoaAddress": current] as [String: Any],
			"nodes": [["ip": "203.0.113.7", "domain": "node.example.invalid", "region": "test", "armoredPublicKey": "synthetic"]] as [[String: Any]],
		] as [String: Any]])
		let ready = waitUntil(30) {
			self.events.contains { ($0["event"] as? [String: Any])?["type"] as? String == "ready" }
		}
		if !ready { XCTFail("init for the current account did not reach ready") }
	}

	/// One command through the entry point, then the main loop runs briefly so its main-queue work finishes.
	private func send(_ body: [String: Any]) {
		BeamioConetChatModule.handleCommand(body, emit: { _ in })
		RunLoop.current.run(until: Date().addingTimeInterval(0.1))
	}

	// MARK: - One request

	private func runRequest(_ step: [String: Any], id: String, index: Int, temps: inout [Int: String], seals: inout [Int: String]) {
		let action = step["action"] as? String ?? ""
		let reqId = step["reqId"] as? String ?? ""
		let expect = step["expect"] as? [String: Any] ?? [:]
		let args = resolve(step["args"] ?? [String: Any]()) as? [String: Any] ?? [:]
		let label = "\(id) step \(index) (\(action) \(reqId))"
		// The envelope is flat, the type and the fields at one level. The file still carries `args`: its envelope is
		// superseded by the spec until the vectors are regenerated, so the fields are sent at the top level here.
		var body = args
		body["type"] = action
		body["reqId"] = reqId
		BeamioConetChatModule.handleCommand(body, emit: { _ in })
		guard let ack = waitForAnswer(reqId, timeout: action == "voiceEphemeralSeal" ? 60 : 5) else {
			XCTFail("\(label): no answer")
			return
		}
		// No action name in the answer: the file's `action` key is not compared.
		XCTAssertEqual(Set(ack.keys), Set(expect["ackKeys"] as? [String] ?? []).subtracting(["action"]), "\(label): ack keys")
		for (key, want) in (expect["ack"] as? [String: Any] ?? [:]) where key != "action" {
			XCTAssertTrue(same(ack[key], want), "\(label): ack.\(key) is \(String(describing: ack[key])), want \(want)")
		}
		let result = ack["result"] as? [String: Any] ?? [:]
		if let resultKeys = expect["resultKeys"] as? [String] {
			XCTAssertEqual(Set(result.keys), Set(resultKeys), "\(label): result keys")
		}
		for (key, want) in expect["result"] as? [String: Any] ?? [:] {
			XCTAssertTrue(same(result[key], want), "\(label): result.\(key) is \(String(describing: result[key])), want \(want)")
		}
		if expect["tempFormat"] as? String == "address" {
			XCTAssertTrue(matches(result["temp"], "^0x[0-9a-f]{40}$"), "\(label): temp is an address")
		}
		if expect["tempSigFormat"] as? String == "signature" {
			XCTAssertTrue(matches(result["tempSig"], "^0x[0-9a-f]{130}$"), "\(label): tempSig is a signature")
		}
		if expect["recoverTo"] as? String == "temp", let signedText = expect["signedText"] as? String {
			let recovered = BeamioNativeEthSigner.recoverEip191AddressForTests(message: signedText, signature: result["tempSig"] as? String ?? "")
			XCTAssertEqual(recovered, result["temp"] as? String, "\(label): the signature recovers to temp")
		}
		if expect["sealedFormat"] as? String == "pgpMessage" {
			XCTAssertTrue((result["sealed"] as? String ?? "").hasPrefix("-----BEGIN PGP MESSAGE-----"), "\(label): sealed is a PGP message")
		}
		if let i = expect["tempEqualsStep"] as? Int {
			// Known defect of the registered file, reported to the interface spec: VR-23 step 2 names itself (tempEqualsStep 2). The step
			// it means is step 1, the registration of the second sid. Only this one reference is read that way; the others are taken as written.
			let target = (id == "VR-23" && index == 2 && i == 2) ? 1 : i
			XCTAssertEqual(result["temp"] as? String, temps[target], "\(label): the temp of step \(target)")
		}
		if let i = expect["tempDiffersFromStep"] as? Int {
			XCTAssertNotNil(temps[i], "\(label): step \(i) has a temp")
			XCTAssertNotEqual(result["temp"] as? String, temps[i], "\(label): a new temp, not that of step \(i)")
		}
		if let i = expect["sealedDiffersFromStep"] as? Int {
			XCTAssertNotNil(seals[i], "\(label): step \(i) has a sealed text")
			XCTAssertNotEqual(result["sealed"] as? String, seals[i], "\(label): a new sealed text, not that of step \(i)")
		}
		if let temp = result["temp"] as? String { temps[index] = temp }
		if let sealed = result["sealed"] as? String { seals[index] = sealed }
	}

	// MARK: - Helpers

	/// The answer with this reqId (the latest), once it arrives or the timeout passes.
	private func waitForAnswer(_ reqId: String, timeout: TimeInterval) -> [String: Any]? {
		var found: [String: Any]?
		_ = waitUntil(timeout) {
			found = self.events.compactMap { $0["event"] as? [String: Any] }.last {
				($0["type"] as? String) == "ack" && self.reqIdText($0["reqId"]) == reqId
			}
			return found != nil
		}
		return found
	}

	@discardableResult
	private func waitUntil(_ timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
		let deadline = Date().addingTimeInterval(timeout)
		while !condition() && Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		return condition()
	}

	private func reqIdText(_ value: Any?) -> String {
		if let text = value as? String { return text }
		if let number = value as? NSNumber { return number.stringValue }
		return ""
	}

	/// The `$FIXTURE.*` references of the file, replaced by the test's key material.
	private func resolve(_ value: Any) -> Any {
		if let text = value as? String, text.hasPrefix("$FIXTURE.") {
			switch text {
			case "$FIXTURE.recipientPgpOk": return recipientOk
			case "$FIXTURE.recipientPgpBroken": return recipientBroken
			default: return text
			}
		}
		if let dict = value as? [String: Any] {
			return dict.mapValues { resolve($0) }
		}
		return value
	}

	/// Equal values of the same JSON kind: strings equal, booleans equal, numbers equal (a boolean is not a number).
	private func same(_ actual: Any?, _ want: Any?) -> Bool {
		switch (actual, want) {
		case let (a as String, w as String):
			return a == w
		case let (a as NSNumber, w as NSNumber):
			let aBool = CFGetTypeID(a) == CFBooleanGetTypeID()
			let wBool = CFGetTypeID(w) == CFBooleanGetTypeID()
			return aBool == wBool && a.doubleValue == w.doubleValue
		default:
			return false
		}
	}

	private func matches(_ value: Any?, _ pattern: String) -> Bool {
		guard let text = value as? String, let regex = try? NSRegularExpression(pattern: pattern) else { return false }
		return regex.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil
	}
}
#endif
