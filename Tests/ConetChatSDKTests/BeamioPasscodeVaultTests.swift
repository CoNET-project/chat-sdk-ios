import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Passcode vault (spec to): T-70 (KDF KAT), T-71 (backoff table), T-72 (state machine), and the record
/// behaviour of enable, change, disable and unlock. Vectors from PASSCODE_VECTORS (ui/passcode-vectors.v1.json).
/// Synthetic key and synthetic passcodes only.
final class BeamioPasscodeVaultTests: XCTestCase {
	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		var corruptNextWrite = false
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool {
			if corruptNextWrite {
				corruptNextWrite = false
				data[eoa.lowercased()] = Data(value.reversed())
			} else {
				data[eoa.lowercased()] = value
			}
			return true
		}
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class MemoryHardware: BeamioPasscodeHardwareKeyStoring {
		/// AES-256-GCM with a memory key: the fallback semantics, with AAD binding. Not hardware-bound.
		var keys: [String: SymmetricKey] = [:]
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { keys[eoa.lowercased()] != nil }
		func createKey(eoa: String) -> Bool {
			keys[eoa.lowercased()] = SymmetricKey(size: .bits256)
			return true
		}
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data {
			guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
			return try BeamioPasscodeWrap.seal(plain, key: k, aad: aad)
		}
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data {
			guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
			return try BeamioPasscodeWrap.open(blob, key: k, aad: aad)
		}
		func deleteKey(eoa: String) { keys[eoa.lowercased()] = nil }
	}

	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private func pc(_ digits: String) -> [UInt8] { Array(digits.utf8) }
	private let bundle = Data(repeating: 0x11, count: 32)
	private var records: MemoryRecords!
	private var hardware: MemoryHardware!
	private var clock: Double = 1_800_000_000
	private var vault: BeamioPasscodeVault!

	private func vectors() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["PASSCODE_VECTORS"], !path.isEmpty else {
			throw XCTSkip("set PASSCODE_VECTORS to interface/ui/passcode-vectors.v1.json")
		}
		return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any])
	}

	override func setUp() {
		super.setUp()
		records = MemoryRecords()
		hardware = MemoryHardware()
		_ = hardware.createKey(eoa: eoa)
		clock = 1_800_000_000
		vault = BeamioPasscodeVault(records: records, hardware: hardware, now: { Date(timeIntervalSince1970: self.clock) })
		// A device-key record (no passcode), as the wallet has today.
		let blob = try! hardware.wrap(bundle, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))
		records.data[eoa] = try! JSONEncoder().encode(BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob))
	}

	// MARK: - T-70 KDF

	func testT70KDFKnownAnswer() throws {
		let v = try vectors()
		let kdf = try XCTUnwrap(v["kdf"] as? [String: Any])
		let salt = try XCTUnwrap(kdf["saltHex"] as? String)
		let saltBytes = stride(from: 0, to: salt.count, by: 2).map { i -> UInt8 in
			let a = salt.index(salt.startIndex, offsetBy: i)
			return UInt8(salt[a ..< salt.index(a, offsetBy: 2)], radix: 16)!
		}
		let out = try XCTUnwrap(BeamioPasscodeKDF.derive(passcode: Array((try XCTUnwrap(kdf["passcode"] as? String)).utf8), salt: saltBytes,
		                                                 iterations: try XCTUnwrap(kdf["iterations"] as? Int)))
		XCTAssertEqual(out.map { String(format: "%02x", $0) }.joined(), kdf["outputHex"] as? String)
	}

	// MARK: - T-71 backoff

	func testT71BackoffMatchesTheVectorSchedule() throws {
		let v = try vectors()
		let schedule = try XCTUnwrap((v["backoff"] as? [String: Any])?["schedule"] as? [[String: Any]])
		for row in schedule {
			let f = try XCTUnwrap(row["consecutiveFailures"] as? Int)
			XCTAssertEqual(BeamioPasscodeBackoff.cooldownSeconds(consecutiveFailures: f), row["cooldownSec"] as? Int, "f = \(f)")
		}
	}

	// MARK: - T-72 state machine

	func testT72StateMachineMatchesTheVectorTable() throws {
		let v = try vectors()
		let table = try XCTUnwrap(v["stateMachine"] as? [String: Any])
		let transitions = try XCTUnwrap(table["transitions"] as? [[String: Any]])
		// 19 rows: the vector file of the 14th batch (sha256 7993ad85…). The change setup_new rows are included.
		XCTAssertEqual(transitions.count, 19)
		let allModes: [BeamioPasscodeMode] = [.enable, .change, .disable, .unlock]
		let allStates: [BeamioPasscodeFlowState] = [.setupNew, .setupConfirm, .verifyOld, .verify, .unlock, .done]
		for t in transitions {
			let event = try XCTUnwrap(BeamioPasscodeEvent(rawValue: try XCTUnwrap(t["event"] as? String)))
			let modeName = try XCTUnwrap(t["mode"] as? String)
			let fromName = try XCTUnwrap(t["from"] as? String)
			let modes = modeName == "*" ? allModes : [try XCTUnwrap(BeamioPasscodeMode(rawValue: modeName))]
			let states = fromName == "*" ? allStates : [try XCTUnwrap(BeamioPasscodeFlowState(rawValue: fromName))]
			for m in modes {
				for s in states {
					let got = BeamioPasscodeFlow.next(mode: m, from: s, event: event)
					if modeName == "*" || fromName == "*" {
						XCTAssertEqual(got?.result, t["result"] as? String, "\(m) \(s) \(event)")
						XCTAssertEqual(got?.to.rawValue, t["to"] as? String, "\(m) \(s) \(event)")
					} else {
						XCTAssertEqual(got?.to.rawValue, t["to"] as? String, "\(m) \(s) \(event)")
						XCTAssertEqual(got?.result, t["result"] as? String, "\(m) \(s) \(event)")
						XCTAssertEqual(got?.message, t["message"] as? String, "\(m) \(s) \(event)")
					}
				}
			}
		}
	}

	func testATransitionThatIsNotInTheTableIsRefused() {
		XCTAssertNil(BeamioPasscodeFlow.next(mode: .enable, from: .setupNew, event: .submitMatch))
		XCTAssertNil(BeamioPasscodeFlow.next(mode: .unlock, from: .setupNew, event: .submitMatch))
	}

	// MARK: - Records and flows

	func testEnableUnlockWrongPasscodeAndTheRecord() {
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("11111111")), .policy("all_same"))
		XCTAssertFalse(vault.isSet(eoa: eoa))
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("13572468")), .ok)
		XCTAssertTrue(vault.isSet(eoa: eoa))
		XCTAssertEqual(try? vault.unlock(eoa: eoa, passcode: pc("13572468")).get(), Array(bundle))
		XCTAssertEqual(vault.unlock(eoa: eoa, passcode: pc("24681358")).failure, .wrong)
	}

	/// rule 6: no retry count and no cooldown in the SDK. Wrong passcodes are each `wrong`, never `backoff`; the right passcode works at once
	/// whatever came before; `cooldownLeft` is always 0; and the record is not written by any attempt (its bytes are unchanged).
	func testTheVaultKeepsNoRetryCountAndNoCooldown() {
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("13572468")), .ok)
		let before = records.readRecord(eoa: eoa)
		for _ in 0 ..< 12 { XCTAssertEqual(vault.unlock(eoa: eoa, passcode: pc("24681358")).failure, .wrong) }
		XCTAssertEqual(vault.cooldownLeft(eoa: eoa), 0)
		XCTAssertEqual(records.readRecord(eoa: eoa), before, "a wrong passcode writes nothing")
		XCTAssertEqual(try? vault.unlock(eoa: eoa, passcode: pc("13572468")).get(), Array(bundle), "the right passcode works at once")
		XCTAssertEqual(records.readRecord(eoa: eoa), before, "a right passcode writes nothing either")
	}

	/// An old record that carries `failures` and `lastFailureAt` stays decodable and its bytes stay as they were: the SDK neither reads nor rewrites them,
	/// and an old cooldown in the record does not block the right passcode.
	func testAnOldRecordWithFailureFieldsStaysUnchangedAndDoesNotBlock() throws {
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("13572468")), .ok)
		var record = try JSONDecoder().decode(BeamioPasscodeRecord.self, from: try XCTUnwrap(records.readRecord(eoa: eoa)))
		record.failures = 9
		record.lastFailureAt = Date().timeIntervalSince1970
		let old = try JSONEncoder().encode(record)
		XCTAssertTrue(records.writeRecord(eoa: eoa, old))
		XCTAssertEqual(try? vault.unlock(eoa: eoa, passcode: pc("13572468")).get(), Array(bundle), "an old cooldown does not block")
		XCTAssertEqual(vault.unlock(eoa: eoa, passcode: pc("24681358")).failure, .wrong)
		XCTAssertEqual(records.readRecord(eoa: eoa), old, "the old fields and bytes are kept")
		let decoded = try JSONDecoder().decode(BeamioPasscodeRecord.self, from: try XCTUnwrap(records.readRecord(eoa: eoa)))
		XCTAssertEqual(decoded.failures, 9)
		XCTAssertNotNil(decoded.lastFailureAt)
	}

	func testChangeRequiresTheOldPasscodeAndDisableReturnsToTheDeviceKey() {
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("13572468")), .ok)
		XCTAssertEqual(vault.change(eoa: eoa, oldPasscode: pc("24681358"), newPasscode: pc("24681357")), .wrong)
		XCTAssertEqual(vault.change(eoa: eoa, oldPasscode: pc("13572468"), newPasscode: pc("24681357")), .ok)
		XCTAssertNotNil(try? vault.unlock(eoa: eoa, passcode: pc("24681357")).get())
		XCTAssertEqual(vault.unlock(eoa: eoa, passcode: pc("13572468")).failure, .wrong)
		XCTAssertEqual(vault.disable(eoa: eoa, passcode: pc("24681357")), .ok)
		XCTAssertFalse(vault.isSet(eoa: eoa))
		XCTAssertEqual(vault.unlock(eoa: eoa, passcode: pc("24681357")).failure, .noRecord)
	}

	func testAFailedReadBackKeepsTheOldRecord() {
		let before = records.data[eoa]
		records.corruptNextWrite = true
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("13572468")), .failed)
		XCTAssertEqual(records.data[eoa], before, "the old record is restored")
		XCTAssertFalse(vault.isSet(eoa: eoa))
	}

	func testARecordMovedToAnotherAccountDoesNotOpen() {
		XCTAssertEqual(vault.enable(eoa: eoa, passcode: pc("13572468")), .ok)
		let other = "0x2222222222222222222222222222222222222222"
		_ = hardware.createKey(eoa: other)
		records.data[other] = records.data[eoa]
		let moved = BeamioPasscodeVault(records: records, hardware: hardware, now: { Date(timeIntervalSince1970: self.clock) })
		XCTAssertNotEqual(try? moved.unlock(eoa: other, passcode: pc("13572468")).get(), Array(bundle), "the account is bound by the AAD")
	}
}

private extension Result {
	/// The failure value, or nil.
	var failure: Failure? {
		if case .failure(let f) = self { return f }
		return nil
	}
}
