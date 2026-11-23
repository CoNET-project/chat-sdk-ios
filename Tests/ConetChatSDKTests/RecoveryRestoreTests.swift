import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Path A of the native recovery (spec.3): the steps with an injected registry and a stand-in KDF. The stand-in is
/// SHA-256 and is NOT argon2id: it exists only to test the pipeline around the KDF (format, hash, decrypt, mnemonic,
/// existing record, write, read-back). The real KDF is pending the dependency decision. The mnemonic is the public test
/// phrase, whose account is 0x9858…; no real credential is used.
final class RecoveryRestoreTests: XCTestCase {
	private let code = "Ab3dE5fG7hJ9kL1mN3pQ5r"        // 22 base62 characters
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	final class MemoryKeyStore: BeamioChatWalletKeyStoring {
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

	/// Test stand-in for argon2id: SHA-256 of the password. NOT the production KDF; it only exercises the pipeline around it.
	struct StandInKDF: BeamioNativeRecovery.KeyDerivation {
		func argon2id(password: [UInt8], salt: [UInt8], m: Int, t: Int, p: Int) -> Result<[UInt8], BeamioNativeRecovery.KeyDerivationError> {
			.success(Array(SHA256.hash(data: Data(password))))
		}
	}

	/// The registry for the pipeline: one record, returned for the path A hash and for any account name (path B reads).
	struct FixedRegistry: BeamioRecoveryRegistryReading {
		var record: String
		func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> { .success(record) }
		func recordByAccountName(_ name: String) -> Result<String, Error> { .success(record) }
		func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .success("") }
	}

	private var store: MemoryKeyStore!
	private var savedRegistry: BeamioRecoveryRegistryReading?
	private var savedKDF: BeamioNativeRecovery.KeyDerivation?

	override func setUp() {
		super.setUp()
		store = MemoryKeyStore()
		savedRegistry = BeamioNativeRecovery.registry
		savedKDF = BeamioNativeRecovery.keyDerivation
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		BeamioNativeRecovery.registry = savedRegistry
		BeamioNativeRecovery.keyDerivation = savedKDF
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// The `{img, stored}` record, encrypted under the stand-in key for `code`.
	private func record(mnemonic: String = "", code: String, key: [UInt8]? = nil, tamper: Bool = false) throws -> String {
		let phraseText = mnemonic.isEmpty ? phrase : mnemonic
		let phraseBase64 = Data(phraseText.utf8).base64EncodedString()
		let k = key ?? Array(SHA256.hash(data: Data(code.utf8)))
		var sealed = try AES.GCM.seal(Data(phraseBase64.utf8), using: SymmetricKey(data: Data(k))).combined!
		if tamper { sealed[sealed.count - 1] ^= 0x01 }
		let object: [String: Any] = [
			"img": sealed.base64EncodedString(),
			"stored": ["algo": "argon2id", "v": 19, "salt": Data("salt-salt-salt!".utf8).base64EncodedString(), "hash": "synthetic", "m": 8192, "t": 1, "p": 1],
		]
		return try JSONSerialization.data(withJSONObject: object).base64EncodedString()
	}

	func testARecordFromTheRightCodeRestoresTheAccount() throws {
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(code: code))
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		let outcome = BeamioNativeRecovery.restore(recoveryCode: code, store: store)
		XCTAssertEqual(outcome, .ok(eoa: account))
		XCTAssertNotNil(store.read(eoa: account), "the key is written natively")
	}

	func testTheCodeFormatIsCheckedFirst() {
		BeamioNativeRecovery.registry = FixedRegistry(record: "")
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: "short", store: store), .failed(.invalidFormat))
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: "Ab3dE5fG7hJ9kL1mN3pQ5!", store: store), .failed(.invalidFormat))
	}

	/// Without the registry or the KDF nothing is decided: `not_supported`, never a guess.
	func testWithoutTheRegistryOrTheKDFTheAnswerIsNotSupported() throws {
		BeamioNativeRecovery.registry = nil
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.notSupported))
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(code: code))
		BeamioNativeRecovery.keyDerivation = nil
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.notSupported))
		XCTAssertNil(store.read(eoa: account))
	}

	func testAnEmptyRecordIsNotFound() {
		BeamioNativeRecovery.registry = FixedRegistry(record: "")
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.notFound))
	}

	func testATamperedRecordIsRecordInvalid() throws {
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(code: code, tamper: true))
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.recordInvalid))
		XCTAssertNil(store.read(eoa: account))
	}

	func testAPhraseThatIsNotAMnemonicIsRecordInvalid() throws {
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(mnemonic: "not a valid recovery phrase at all", code: code))
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.recordInvalid))
	}

	func testAnExistingKeyIsAlreadyExistsAndNotOverwritten() throws {
		let existing = Data(repeating: 0x55, count: 32)
		XCTAssertTrue(store.write(eoa: account, key: existing))
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(code: code))
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.alreadyExists))
		XCTAssertEqual(store.read(eoa: account), existing, "an existing record is not overwritten")
	}

	func testTheOutcomeCarriesOnlyAPublicCodeAndAddress() throws {
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(code: code))
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		let outcome = BeamioNativeRecovery.restore(recoveryCode: code, store: store)
		XCTAssertEqual(outcome.code, "ok")
		XCTAssertFalse(String(describing: outcome).contains(phrase))
		XCTAssertFalse(String(describing: outcome).contains(code))
	}
	final class MemoryAttempts: BeamioNativeRecovery.PinAttemptStoring {
		var failures = 0
		var last: Date?
		func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
		func save(failures: Int, lastFailure: Date?) {
			self.failures = failures
			last = lastFailure
		}
	}

	/// A record with the given `stored` parameters, the phrase encrypted under `key`.
	private func recordWith(m: Int, t: Int, p: Int, key: [UInt8]) throws -> String {
		let phraseBase64 = Data(phrase.utf8).base64EncodedString()
		let sealed = try AES.GCM.seal(Data(phraseBase64.utf8), using: SymmetricKey(data: Data(key))).combined!
		let object: [String: Any] = [
			"img": sealed.base64EncodedString(),
			"stored": ["algo": "argon2id", "v": 19, "salt": Data("salt-salt-salt!".utf8).base64EncodedString(),
			           "hash": "synthetic", "m": m, "t": t, "p": p],
		]
		return try JSONSerialization.data(withJSONObject: object).base64EncodedString()
	}

	/// the parameter bounds are judged on the record, before any KDF call.
	/// Counts the calls of the KDF: a record out of bounds must never reach it.
	final class CountingKDF: BeamioNativeRecovery.KeyDerivation {
		var calls = 0
		func argon2id(password: [UInt8], salt: [UInt8], m: Int, t: Int, p: Int) -> Result<[UInt8], BeamioNativeRecovery.KeyDerivationError> {
			calls += 1
			return .success(Array(SHA256.hash(data: Data(password))))
		}
	}

	/// the parameter bounds are judged on the record, before any KDF call. Out of range
	/// is record_invalid and the KDF is called zero times; in range, the KDF is called once.
	func testParameterBoundsAreJudgedBeforeTheKDF() throws {
		let kdf = CountingKDF()
		BeamioNativeRecovery.keyDerivation = kdf
		let key = Array(SHA256.hash(data: Data(code.utf8)))
		for (m, t, p) in [(65537, 1, 1), (15, 1, 2), (8191, 1, 1), (8192, 0, 1), (8192, 11, 1), (8192, 1, 5)] {
			BeamioNativeRecovery.registry = FixedRegistry(record: try recordWith(m: m, t: t, p: p, key: key))
			kdf.calls = 0
			XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .failed(.recordInvalid),
			               "m=\(m) t=\(t) p=\(p)")
			XCTAssertEqual(kdf.calls, 0, "m=\(m) t=\(t) p=\(p): the KDF is not called for an out-of-bounds record")
			XCTAssertNil(store.read(eoa: account))
		}
		// The bounds themselves are accepted: m = 8192 KB and m = 65536 KB, t = 1 and t = 10, p = 1 and p = 4.
		for (m, t, p) in [(8192, 1, 1), (65536, 10, 4)] {
			store = MemoryKeyStore()
			BeamioNativeAccountPointer.clear()
			BeamioNativeRecovery.registry = FixedRegistry(record: try recordWith(m: m, t: t, p: p, key: key))
			kdf.calls = 0
			XCTAssertEqual(BeamioNativeRecovery.restore(recoveryCode: code, store: store), .ok(eoa: account),
			               "m=\(m) t=\(t) p=\(p)")
			XCTAssertEqual(kdf.calls, 1, "m=\(m) t=\(t) p=\(p): the KDF is called once for an in-bounds record")
		}
	}

	/// only `ok` clears the PIN failure count. The other codes neither clear it nor count.
	func testOnlyOkClearsThePinFailureCount() throws {
		let attempts = MemoryAttempts()
		attempts.failures = 3
		BeamioNativeRecovery.attempts = attempts
		defer { BeamioNativeRecovery.attempts = BeamioNativeRecovery.UserDefaultsPinAttempts() }
		BeamioNativeRecovery.keyDerivation = StandInKDF()
		let password = "pw-synthetic-2026"
		let key = Array(SHA256.hash(data: Data(password.utf8)))
		// The password opens the record, but the phrase is not a mnemonic: record_invalid, and the count stays at 3.
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(mnemonic: "not a valid recovery phrase at all", code: "", key: key))
		XCTAssertEqual(BeamioNativeRecovery.restore(.account(name: "syn_name", password: Array(password.utf8)), store: store),
		               .failed(.recordInvalid))
		XCTAssertEqual(attempts.failures, 3)
		// A wrong password is bad_pin and adds one.
		XCTAssertEqual(BeamioNativeRecovery.restore(.account(name: "syn_name", password: Array("wrong".utf8)), store: store),
		               .failed(.badPin))
		XCTAssertEqual(attempts.failures, 4)
		// Only the right password with a valid record is ok, and that clears the count (4 before, 0 after).
		BeamioNativeRecovery.registry = FixedRegistry(record: try record(code: "", key: key))
		XCTAssertEqual(BeamioNativeRecovery.restore(.account(name: "syn_name", password: Array(password.utf8)), store: store),
		               .ok(eoa: account))
		XCTAssertEqual(attempts.failures, 0)
	}
}
