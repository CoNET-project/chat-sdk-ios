import XCTest
@testable import ConetChatSDK

/// The shell passcode core (frozen protocol v1 §3, §7, §9): provision, uncounted unlock, change, disable, repair, over memory stores.
/// Synthetic phrase and passcodes only; no Keychain.
final class ShellPasscodeCoreTests: XCTestCase {
	final class MemRecords: BeamioPasscodeRecordStoring {
		var values: [String: Data] = [:]
		var failWrites = false
		var unavailable = false
		var corruptNextReadOf: Data?
		func readRecord(eoa: String) -> Data? { if case .present(let d) = readRecordState(eoa: eoa) { return d }; return nil }
		func readRecordState(eoa: String) -> BeamioPasscodeRecordRead {
			if unavailable { return .unavailable }
			guard let d = values[eoa.lowercased()] else { return .absent }
			return .present(d)
		}
		func writeRecord(eoa: String, _ data: Data) -> Bool {
			if failWrites { return false }
			values[eoa.lowercased()] = data
			return true
		}
		func deleteRecord(eoa: String) { values[eoa.lowercased()] = nil }
		func enumerateRecordOwners() -> [String]? { Array(values.keys) }
	}

	/// Synthetic hardware layer: a tagged copy, bound to the AAD. Not a security control.
	final class MemHardware: BeamioPasscodeHardwareKeyStoring {
		var present = Set<String>()
		var state: BeamioPasscodeHardwareKeyState?
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { present.contains(eoa.lowercased()) }
		func createKey(eoa: String) -> Bool { present.insert(eoa.lowercased()); return true }
		func keyState(eoa: String) -> BeamioPasscodeHardwareKeyState { state ?? (hasKey(eoa: eoa) ? .present : .absent) }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data {
			guard hasKey(eoa: eoa) else { throw BeamioPasscodeError.hardwareUnavailable }
			return aad + Data([0xFF]) + plain
		}
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data {
			guard hasKey(eoa: eoa) else { throw BeamioPasscodeError.hardwareUnavailable }
			guard blob.starts(with: aad + Data([0xFF])) else { throw BeamioPasscodeError.recordInvalid }
			return blob.dropFirst(aad.count + 1)
		}
		func deleteKey(eoa: String) { present.remove(eoa.lowercased()) }
	}

	private let phrase = Array("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".utf8)
	private let otherPhrase = Array("legal winner thank year wave sausage worth useful legal winner thank yellow".utf8)
	private let pass = Array("73920461".utf8)
	private let pass2 = Array("58204716".utf8)
	private var records: MemRecords!
	private var staging: MemRecords!
	private var hardware: MemHardware!
	private var vault: BeamioPasscodeVault!

	private func eoa(of phrase: [UInt8]) -> String {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) else { fatalError("bad fixture") }
		defer { BeamioNativeWallet.wipe(&key) }
		return BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
	}

	override func setUp() {
		super.setUp()
		records = MemRecords()
		staging = MemRecords()
		hardware = MemHardware()
		vault = BeamioPasscodeVault(records: records, hardware: hardware, staging: staging)
	}

	func testProvisionFromNothingWritesOneRecordThatUnlocksWithBothParts() throws {
		let a = eoa(of: phrase)
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: phrase, passcode: pass), .ok(address: a))
		XCTAssertTrue(staging.values.isEmpty, "the staging copy is cleared")
		guard case .passcode(let record) = vault.shellRecord(eoa: a) else { return XCTFail("not a passcode record") }
		XCTAssertNotNil(record.mnemonicBlob)
		XCTAssertEqual(record.failures, 0)
		let unlocked = try XCTUnwrap(try? vault.shellUnlock(eoa: a, passcode: pass).get())
		defer { unlocked.wipe() }
		XCTAssertEqual(unlocked.phrase, phrase)
		XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: unlocked.bundle)?.lowercased(), a)
	}

	func testWrongPasscodeIsNeverCountedAndWritesNothing() {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		let before = records.values
		for _ in 0 ..< 10 {
			guard case .failure(let r) = vault.shellUnlock(eoa: a, passcode: pass2) else { return XCTFail("unlocked with a wrong passcode") }
			XCTAssertEqual(r, .fail("wrong_passcode"))
		}
		XCTAssertEqual(records.values, before, "no count, no cooldown, no write")
		XCTAssertNoThrow(try vault.shellUnlock(eoa: a, passcode: pass).get().wipe(), "still opens at once: no cooldown")
	}

	func testProvisionRefusals() {
		let a = eoa(of: phrase)
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: phrase, passcode: Array("12345678".utf8)), .fail("weak_passcode", reason: "common"))
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: otherPhrase, passcode: pass), .fail("eoa_mismatch"))
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: Array("not a phrase".utf8), passcode: pass), .fail("eoa_mismatch"))
		XCTAssertTrue(records.values.isEmpty)
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: phrase, passcode: pass), .ok(address: a))
		let before = records.values
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: phrase, passcode: pass2), .fail("already_set"))
		XCTAssertEqual(records.values, before, "already_set overwrites nothing")
	}

	func testProvisionOverADeviceRecordNeedsTheSameKey() throws {
		let a = eoa(of: phrase)
		hardware.present.insert(a)
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) else { return XCTFail() }
		let blob = try hardware.wrap(Data(key), eoa: a, aad: BeamioPasscodeWrap.aadH(eoa: a))
		records.values[a] = try JSONEncoder().encode(BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob))
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: phrase, passcode: pass), .ok(address: a))
		XCTAssertTrue(vault.shellStatus(eoa: a).set)
		// a device record of another key under this account: refused, untouched
		let wrongKey = try hardware.wrap(Data(repeating: 7, count: 32), eoa: a, aad: BeamioPasscodeWrap.aadH(eoa: a))
		let device = try JSONEncoder().encode(BeamioPasscodeRecord(mode: "device", salt: nil, blob: wrongKey))
		records.values[a] = device
		XCTAssertEqual(vault.shellProvision(eoa: a, phrase: phrase, passcode: pass), .fail("address_mismatch"))
		XCTAssertEqual(records.values[a], device)
	}

	func testHardwareLayerMissingIsRecordInvalidAndUnknownIsNotReady() {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		let before = records.values
		hardware.present.removeAll()
		guard case .failure(let missing) = vault.shellUnlock(eoa: a, passcode: pass) else { return XCTFail() }
		XCTAssertEqual(missing, .fail("record_invalid"))
		hardware.state = .unknown
		guard case .failure(let unknown) = vault.shellUnlock(eoa: a, passcode: pass) else { return XCTFail() }
		XCTAssertEqual(unknown, .fail("not_ready"))
		XCTAssertEqual(records.values, before, "nothing counted, nothing written")
	}

	func testAHardwareKeyThatIsPresentButNotUsableIsNotReadyNeverRecordInvalid() {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		let before = records.values
		hardware.present.removeAll() // the layer cannot unwrap ...
		hardware.state = .present // ... but the lookup says the key is there (locked device, busy store)
		guard case .failure(let r) = vault.shellUnlock(eoa: a, passcode: pass) else { return XCTFail() }
		XCTAssertEqual(r, .fail("not_ready"))
		XCTAssertEqual(records.values, before)
	}

	func testAFailedWriteKeepsTheOldRecordAndClearsStaging() {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		let before = records.values
		records.failWrites = true
		XCTAssertEqual(vault.shellChange(eoa: a, oldPasscode: pass, newPasscode: pass2), .fail("write_failed", reason: "storage_write"))
		records.failWrites = false
		XCTAssertEqual(records.values, before)
		XCTAssertTrue(staging.values.isEmpty)
		XCTAssertNoThrow(try vault.shellUnlock(eoa: a, passcode: pass).get().wipe(), "the old passcode still opens")
		// the staging store refuses the write: the record is not touched either
		staging.failWrites = true
		XCTAssertEqual(vault.shellChange(eoa: a, oldPasscode: pass, newPasscode: pass2), .fail("write_failed", reason: "storage_write"))
		XCTAssertEqual(records.values, before)
	}

	func testAnUnreadableRecordIsNeverOverwritten() {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		let before = records.values
		records.unavailable = true
		XCTAssertEqual(vault.shellRepair(eoa: a, phrase: phrase, passcode: pass), .fail("not_ready"))
		records.unavailable = false
		XCTAssertEqual(records.values, before)
	}

	func testChangeKeepsThePhraseAndTheOldPasscodeStopsWorking() throws {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		XCTAssertEqual(vault.shellChange(eoa: a, oldPasscode: pass, newPasscode: pass2), .ok(address: a))
		let unlocked = try XCTUnwrap(try? vault.shellUnlock(eoa: a, passcode: pass2).get())
		defer { unlocked.wipe() }
		XCTAssertEqual(unlocked.phrase, phrase)
		guard case .failure(let old) = vault.shellUnlock(eoa: a, passcode: pass) else { return XCTFail() }
		XCTAssertEqual(old, .fail("wrong_passcode"))
		XCTAssertEqual(vault.shellChange(eoa: a, oldPasscode: pass, newPasscode: pass2), .fail("wrong_passcode"))
		XCTAssertEqual(vault.shellChange(eoa: a, oldPasscode: pass2, newPasscode: Array("11111111".utf8)), .fail("weak_passcode", reason: "all_same"))
	}

	func testDisableRestoresThePhraseFirstAndKeepsTheKey() throws {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		var restored: Data?
		// a failed restore changes nothing
		XCTAssertEqual(vault.shellDisable(eoa: a, passcode: pass, restorePhrase: { _ in false }), .fail("write_failed", reason: "storage_write"))
		XCTAssertTrue(vault.shellStatus(eoa: a).set)
		XCTAssertEqual(vault.shellDisable(eoa: a, passcode: pass2, restorePhrase: { _ in XCTFail("restored on a wrong passcode"); return true }), .fail("wrong_passcode"))
		XCTAssertEqual(vault.shellDisable(eoa: a, passcode: pass, restorePhrase: { restored = $0; return true }), .ok(address: a))
		XCTAssertEqual(restored, Data(phrase))
		XCTAssertFalse(vault.shellStatus(eoa: a).set)
		guard case .device(let device) = vault.shellRecord(eoa: a) else { return XCTFail("not a device record") }
		XCTAssertNil(device.mnemonicBlob)
		var key = try hardware.unwrap(device.blob, eoa: a, aad: BeamioPasscodeWrap.aadH(eoa: a))
		defer { BeamioNativeWallet.wipe(&key) }
		XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: [UInt8](key))?.lowercased(), a)
		guard case .failure(let r) = vault.shellUnlock(eoa: a, passcode: pass) else { return XCTFail() }
		XCTAssertEqual(r, .fail("not_set"))
	}

	func testRepairRebuildsFromThePhraseUnderTheSamePasscode() throws {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass2)
		// the UI knows `pass`; the native record is under another passcode (passcode_mismatch)
		guard case .failure(let r) = vault.shellUnlock(eoa: a, passcode: pass) else { return XCTFail() }
		XCTAssertEqual(r, .fail("wrong_passcode"))
		XCTAssertEqual(vault.shellRepair(eoa: a, phrase: phrase, passcode: pass), .ok(address: a))
		XCTAssertNoThrow(try vault.shellUnlock(eoa: a, passcode: pass).get().wipe())
		// the wrong account's phrase is refused and the record stays
		let before = records.values
		XCTAssertEqual(vault.shellRepair(eoa: a, phrase: otherPhrase, passcode: pass), .fail("eoa_mismatch"))
		XCTAssertEqual(records.values, before)
		// a repair with no record at all creates it (no_record)
		records.values.removeAll()
		XCTAssertEqual(vault.shellRepair(eoa: a, phrase: phrase, passcode: pass), .ok(address: a))
	}

	func testStagingReconciliation() throws {
		let a = eoa(of: phrase)
		XCTAssertEqual(vault.shellReconcileStaging(eoa: a), "clean")
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		staging.values[a] = records.values[a]
		XCTAssertEqual(vault.shellReconcileStaging(eoa: a), "clean")
		XCTAssertTrue(staging.values.isEmpty, "a stale copy beside a usable record is removed")
		// the record is gone but a staged copy is usable: neither is promoted nor deleted
		let staged = records.values[a]!
		records.values[a] = Data("garbage".utf8)
		staging.values[a] = staged
		XCTAssertEqual(vault.shellReconcileStaging(eoa: a), "rollback_pending")
		XCTAssertEqual(staging.values[a], staged)
		XCTAssertEqual(records.values[a], Data("garbage".utf8))
	}

	func testTheMnemonicAadDomainIsSeparate() throws {
		let a = eoa(of: phrase)
		_ = vault.shellProvision(eoa: a, phrase: phrase, passcode: pass)
		guard case .passcode(let record) = vault.shellRecord(eoa: a), var p = BeamioPasscodeKDF.derive(passcode: pass, salt: Array(record.salt!)) else { return XCTFail() }
		defer { BeamioNativeWallet.wipe(&p) }
		let key = SymmetricKey(data: Data(p))
		let blob = try XCTUnwrap(record.mnemonicBlob)
		XCTAssertNoThrow(try BeamioPasscodeWrap.open(blob, key: key, aad: BeamioPasscodeWrap.aadM(eoa: a)))
		XCTAssertThrowsError(try BeamioPasscodeWrap.open(blob, key: key, aad: BeamioPasscodeWrap.aadP(eoa: a)))
		XCTAssertThrowsError(try BeamioPasscodeWrap.open(blob, key: key, aad: BeamioPasscodeWrap.aadM(eoa: "0x0000000000000000000000000000000000000001")))
		XCTAssertEqual(String(decoding: BeamioPasscodeWrap.aadM(eoa: a), as: UTF8.self), "beamio-native-wallet-v1|m|\(a)|v1")
	}
}
import CryptoKit

/// The older vault unlock (the native keyboard flow) must not count a missing hardware layer as a wrong passcode.
final class VaultHardwareMissingNotCountedTests: XCTestCase {
	func testMissingHardwareLayerIsNotAFailure() throws {
		let records = ShellPasscodeCoreTests.MemRecords()
		let hardware = ShellPasscodeCoreTests.MemHardware()
		let vault = BeamioPasscodeVault(records: records, hardware: hardware, staging: ShellPasscodeCoreTests.MemRecords())
		let account = "0x1111111111111111111111111111111111111111"
		hardware.present.insert(account)
		let blob = try hardware.wrap(Data(repeating: 3, count: 32), eoa: account, aad: BeamioPasscodeWrap.aadH(eoa: account))
		records.values[account] = try JSONEncoder().encode(BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob))
		let pass = Array("73920461".utf8)
		XCTAssertEqual(vault.enable(eoa: account, passcode: pass), .ok)
		let before = records.values
		hardware.present.removeAll()
		for _ in 0 ..< 6 { XCTAssertEqual(vault.disable(eoa: account, passcode: pass), .unavailable) }
		XCTAssertEqual(records.values, before, "no failure was recorded")
		hardware.present.insert(account)
		XCTAssertEqual(vault.disable(eoa: account, passcode: pass), .ok, "no cooldown after the hardware layer returns")
	}
}
