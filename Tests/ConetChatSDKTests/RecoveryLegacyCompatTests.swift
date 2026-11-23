import CryptoKit
import Foundation
import XCTest
@testable import ConetChatSDK

/// Records made by the PWA's own libraries (noble argon2id, WebCrypto AES-GCM, ethers), with the layout of the PWA's
/// `createRecover`: `base64(JSON({stored, img}))`, `stored` = {algo, v, m, t, p, salt, hash}. The code, the PIN and the
/// name are synthetic; the phrase is the public BIP-39 test phrase, whose account is 0x9858…. Two parameter sets: the
/// PWA default (32 MiB, 3 passes, 1 lane) and another (16 MiB, 2 passes, 2 lanes). Generated once; the generator is not in the repo.
final class RecoveryLegacyCompatTests: XCTestCase {
	private let code = "Qm7ZkP2xRt9WcL4dHs6NbV"
	private let pin = "SYN-pin-legacy-2026"
	private let accountName = "syn_legacy_pwa_0003"
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let v1PathA = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiSDRqa1dnbnpNZTVYL21SWFIwbFNzZz09IiwiaGFzaCI6ImFzR0g1NGFvOG9wNXEvamJ0dG1ra3lLQzlFSi9OWWtqV0F5NU5YVWFtRnc9In0sImltZyI6IkJ3OEl5R1lwekxpRmxFM2JaN3hZN2dJTXV3byt6TUU2SzJicmZZYWNJdk5wdGdLV1hhM0pEd0JLMDQ2clYvd2kvbkVMY09ZQUo0WkZaTm9sZFRaQ0MvaFRpbE9tMTZjT0NRdmtsY2UxdG1jMVFCVUJvZ1VXSUpLcTNDTHZtL3d2SEhBeUNxZ3JyZVdseXY2cU1QSEs2OVJOOWpwQ0JDWnFTZEdPaUFnYmYveXVxNmhROFlsQjVIb01oSXlnYWpzUE1hVUNadkp2TmZRPSJ9"
	private let v1PathB = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjMyNzY4LCJ0IjozLCJwIjoxLCJzYWx0IjoiSDRqa1dnbnpNZTVYL21SWFIwbFNzZz09IiwiaGFzaCI6ImFzR0g1NGFvOG9wNXEvamJ0dG1ra3lLQzlFSi9OWWtqV0F5NU5YVWFtRnc9In0sImltZyI6IlExb1FreTgrUGk3OVhVczh4aU5QbUZJNUxSV0VjeCtMbVBWcTZTdG1nbkJXNlQwd1pGcGczVWhLVkY5RTFWRlphRWRMUEZmNEthZWtjbWNWcktjMjluSFI0M1E2ZDQrajRNNVF3d3ZaQko2NHlvaDJwL2lSQksxZDNYN0NQajFHc3cxWU9yTmpCcE05M2wxczBMemtUSFZwT1RhVXNiUnBENTNBMW1pMVlUKzBjOXplcG9aNHQzTGNkOGNheXlxRmxEakIyUDJhcFJBPSJ9"
	private let v2PathA = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjE2Mzg0LCJ0IjoyLCJwIjoyLCJzYWx0IjoiL3JXSEFDa0ZvcE1QVnQ0dEdnR0h2UT09IiwiaGFzaCI6IitLU3phblVUMW9WNSs2NXBnK3hZU2RlWWNOSllXdDdoUHQwQmVUa09vbk09In0sImltZyI6IkRvZXQ1Wk9ERnN0SlRsb254TmZVV25wTDNVUDFoSGlqQ3RxYklRWnA3UWlxSXBvWWV2SURMRU5DRXluaGN1ZVVub1V3ZGpTbWhRRlhOUE5pRGJkZzd3SGxIYjk1a1BZNVRMUWl1ZnZxL3ptYUpvVUM1Z2FlWmhJZFlGN05jNVlUMm43cVZnM2NxTVVISysxYTJBa3NUTWVFSHB5b3lBS3QyRm1TVFgvWVFqMHh6bm9pTGo5eGFjWjhGOTBlT2o4WTV2NitvanU1V1BzPSJ9"
	private let v2PathB = "eyJzdG9yZWQiOnsiYWxnbyI6ImFyZ29uMmlkIiwidiI6MTksIm0iOjE2Mzg0LCJ0IjoyLCJwIjoyLCJzYWx0IjoiL3JXSEFDa0ZvcE1QVnQ0dEdnR0h2UT09IiwiaGFzaCI6IitLU3phblVUMW9WNSs2NXBnK3hZU2RlWWNOSllXdDdoUHQwQmVUa09vbk09In0sImltZyI6ImhlRVoyWGk1Rm1zSXhraEhlekhoalFhLzZBalBUaG9ldTJIcHU2SEtiWENGYTVQR2NxZG9nWVhUbExTTDEzeTBYY0NMQTR6SCs4bnZ0WnlreDdwNWpDSmtWaG5TUzBTWDNWY1JadkZuR2ljZ2JnOVY1N25odU5Xa0h1SUN6SzhmdkxKUGYxaGRHNldtdFI5ZElJVU5vMkxuaFh3Qk9DZWM3T05tWnk5alNwemFra2MydklOamMvOEkxdGZCR1BtVGFMaCtFUk1TSElrPSJ9"

	final class LegacyRegistry: BeamioRecoveryRegistryReading {
		var byHash: [String: String] = [:]
		var byName: [String: String] = [:]
		func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
			.success(byHash[nameHash.map { String(format: "%02x", $0) }.joined()] ?? "")
		}
		func recordByAccountName(_ name: String) -> Result<String, Error> { .success(byName[name] ?? "") }
		func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .success("") }
	}

	final class LegacyKeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	final class LegacyAttempts: BeamioNativeRecovery.PinAttemptStoring {
		var failures = 0
		var last: Date?
		func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
		func save(failures: Int, lastFailure: Date?) { self.failures = failures; last = lastFailure }
	}

	private var savedRegistry: BeamioRecoveryRegistryReading?
	private var savedKDF: BeamioNativeRecovery.KeyDerivation?
	private var savedAttempts: BeamioNativeRecovery.PinAttemptStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedRegistry = BeamioNativeRecovery.registry
		savedKDF = BeamioNativeRecovery.keyDerivation
		savedAttempts = BeamioNativeRecovery.attempts
		BeamioNativeRecovery.keyDerivation = BeamioNativeRecovery.BeamioRecoveryKDF()
	}

	override func tearDown() {
		BeamioNativeRecovery.registry = savedRegistry
		BeamioNativeRecovery.keyDerivation = savedKDF
		BeamioNativeRecovery.attempts = savedAttempts ?? BeamioNativeRecovery.UserDefaultsPinAttempts()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func registry(hashRecord: String, nameRecord: String) -> LegacyRegistry {
		let r = LegacyRegistry()
		r.byHash[BeamioNativeEthSigner.keccak256(Array(code.utf8)).map { String(format: "%02x", $0) }.joined()] = hashRecord
		r.byName[accountName] = nameRecord
		return r
	}

	private func assertPathA(hashRecord: String, file: StaticString = #filePath, line: UInt = #line) {
		let store = LegacyKeyStore()
		BeamioNativeRecovery.registry = registry(hashRecord: hashRecord, nameRecord: "")
		BeamioNativeRecovery.attempts = LegacyAttempts()
		XCTAssertEqual(BeamioNativeRecovery.restore(.recoveryCode(code), store: store), .ok(eoa: account), file: file, line: line)
		XCTAssertNotNil(store.read(eoa: account), file: file, line: line)
	}

	private func assertPathB(nameRecord: String, password: String, file: StaticString = #filePath, line: UInt = #line) -> BeamioNativeRecovery.RestoreOutcome {
		let store = LegacyKeyStore()
		BeamioNativeRecovery.registry = registry(hashRecord: "", nameRecord: nameRecord)
		BeamioNativeRecovery.attempts = LegacyAttempts()
		return BeamioNativeRecovery.restore(.account(name: accountName, password: Array(password.utf8)), store: store)
	}

	/// Path A on the PWA-built records: the code opens them, the phrase derives the PWA's account.
	func testPWARecordsRestoreThePWAAccountOnPathA() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "argon2id needs the X-19 framework")
		assertPathA(hashRecord: v1PathA)
		assertPathA(hashRecord: v2PathA)
	}

	/// Path B on the same records: the PIN opens the second image; a wrong PIN is bad_pin and is counted.
	func testPWARecordsRestoreThePWAAccountOnPathBAndCountAWrongPIN() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "argon2id needs the X-19 framework")
		XCTAssertEqual(assertPathB(nameRecord: v1PathB, password: pin), .ok(eoa: account))
		XCTAssertEqual(assertPathB(nameRecord: v2PathB, password: pin), .ok(eoa: account))
		XCTAssertEqual(assertPathB(nameRecord: v1PathB, password: "SYN-wrong-pin"), .failed(.badPin))
	}
}
