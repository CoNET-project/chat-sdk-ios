import CryptoKit
import Foundation
import XCTest
@testable import ConetChatSDK

/// Vector file: native-recovery-vectors.v1.json, sha256 8537389d59a99e29f901edf0a044170091fa10af00fbf8cbb479b91400ac2c28,
/// revision.
/// The 38 cases of `native-recovery-vectors.v1.json`, run against the recovery engine
/// with the real argon2id (X-19 v5). Needs NATIVE_RECOVERY_VECTORS=<path to the file>; skipped without it. Skipped also on
/// a build without the X-19 framework, where the KDF is `not_supported` and the vectors cannot be answered. The records and
/// the codes are synthetic; the phrase is the public BIP-39 test phrase.
final class NativeRecoveryVectorTests: XCTestCase {
	/// Known deviations of the registered vector. None remain: B-06, B-12 and B-15 were implementation deviations (path B queried the retired
	/// pre-migration registry), fixed so that the vector's `not_found` is asserted as written.
	static let knownVectorDeviations: [String: (observed: String, reason: String)] = [:]

	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let startTime = Date(timeIntervalSince1970: 1_800_000_000)

	final class VectorKeyStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var writeFail = false
		var readbackFail = false

		func write(eoa: String, key: Data) -> Bool {
			if writeFail { return false }
			keys[eoa.lowercased()] = key
			return true
		}

		/// With `readbackFail`, the bytes read back differ from the bytes written (step 10).
		func read(eoa: String) -> Data? {
			guard let value = keys[eoa.lowercased()] else { return nil }
			guard readbackFail, !value.isEmpty else { return value }
			var flipped = value
			flipped[flipped.count - 1] ^= 0x01
			return flipped
		}

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

	final class VectorRegistry: BeamioRecoveryRegistryReading {
		var byHash: [String: String] = [:]
		var byName: [String: String] = [:]
		var legacy: [String: String] = [:]
		var failing = false
		/// The pre-migration registry only (env `legacyRpc`).
		var legacyFailing = false

		func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> {
			if failing { return .failure(AddressPGPChain.ReadError.transport("rpc unavailable")) }
			let key = "nameHash:0x" + nameHash.map { String(format: "%02x", $0) }.joined()
			return .success(byHash[key] ?? "")
		}

		func recordByAccountName(_ name: String) -> Result<String, Error> {
			if failing { return .failure(AddressPGPChain.ReadError.transport("rpc unavailable")) }
			return .success(byName["name:" + name] ?? "")
		}

		func legacyRecordByAccountName(_ name: String) -> Result<String, Error> {
			if failing || legacyFailing { return .failure(AddressPGPChain.ReadError.transport("rpc unavailable")) }
			return .success(legacy["name:" + name] ?? "")
		}
	}

	final class VectorAttempts: BeamioNativeRecovery.PinAttemptStoring {
		var failures = 0
		var last: Date?
		func load() -> (failures: Int, lastFailure: Date?) { (failures, last) }
		func save(failures: Int, lastFailure: Date?) {
			self.failures = failures
			last = lastFailure
		}
	}

	private var store = VectorKeyStore()
	private var registry = VectorRegistry()
	private var attempts = VectorAttempts()
	private var now = Date(timeIntervalSince1970: 1_800_000_000)
	private var savedRegistry: BeamioRecoveryRegistryReading?
	private var savedKDF: BeamioNativeRecovery.KeyDerivation?
	private var savedAttempts: BeamioNativeRecovery.PinAttemptStoring?
	private var savedClock: (() -> Date)?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedRegistry = BeamioNativeRecovery.registry
		savedKDF = BeamioNativeRecovery.keyDerivation
		savedAttempts = BeamioNativeRecovery.attempts
		savedClock = BeamioNativeRecovery.clock
		BeamioNativeRecovery.keyDerivation = BeamioNativeRecovery.BeamioRecoveryKDF()
		BeamioNativeRecovery.clock = { [unowned self] in self.now }
	}

	override func tearDown() {
		BeamioNativeRecovery.registry = savedRegistry
		BeamioNativeRecovery.keyDerivation = savedKDF
		BeamioNativeRecovery.attempts = savedAttempts ?? BeamioNativeRecovery.UserDefaultsPinAttempts()
		BeamioNativeRecovery.clock = savedClock ?? { Date() }
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func vectorRoot() throws -> [String: Any] {
		// BundledVectorFile checks the registered digest (SHA256-CURRENT, native-recovery-vectors.v1.json) before the cases are used.
		let data = try BundledVectorFile.data(resource: "native-recovery-vectors.v1", env: "NATIVE_RECOVERY_VECTORS")
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	/// Fresh device state for one case: no key, no pointer, no failures, the clock at the start.
	private func resetCase() {
		store = VectorKeyStore()
		registry = VectorRegistry()
		attempts = VectorAttempts()
		now = startTime
		BeamioNativeAccountPointer.clear()
		BeamioNativeRecovery.registry = registry
		BeamioNativeRecovery.attempts = attempts
	}

	private func cooldownActive() -> Bool {
		let wait = BeamioPasscodeBackoff.cooldownSeconds(consecutiveFailures: attempts.failures)
		guard wait > 0, let last = attempts.last else { return false }
		return last.addingTimeInterval(TimeInterval(wait)) > now
	}

	func testTheThirtyEightCasesAnswerTheVectorResults() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "argon2id needs the X-19 framework (iOS builds with Vendor/X19.xcframework)")
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 38)
		let fixtures = try XCTUnwrap(root["fixtures"] as? [String: Any])
		let registryFixture = try XCTUnwrap(fixtures["registry"] as? [String: String])
		let legacyFixture = try XCTUnwrap(fixtures["legacyRegistry"] as? [String: String])
		for c in cases {
			try runCase(c, registryFixture: registryFixture, legacyFixture: legacyFixture)
		}
	}

	private func runCase(_ c: [String: Any], registryFixture: [String: String], legacyFixture: [String: String]) throws {
		let id = try XCTUnwrap(c["id"] as? String)
		resetCase()

		let env = c["env"] as? [String: Any] ?? [:]
		if let device = env["device"] as? [String: Any] {
			if device["hasKey"] as? Bool == true {
				store.keys[account] = Data(repeating: 0x11, count: 32)
				BeamioNativeAccountPointer.set(account)
			}
			store.writeFail = device["writeFail"] as? Bool == true
			store.readbackFail = device["readbackFail"] as? Bool == true
			// The PIN counter: `failures`, and `cooldownActive` puts the last failure at the start time.
			if let failures = device["failures"] as? Int {
				attempts.failures = failures
				attempts.last = device["cooldownActive"] as? Bool == true ? startTime : nil
			}
		}
		registry.failing = (env["rpc"] as? String) == "fail"
		registry.legacyFailing = (env["legacyRpc"] as? String) == "fail"
		registry.byHash = registryFixture.filter { $0.key.hasPrefix("nameHash:") }
		registry.byName = registryFixture.filter { $0.key.hasPrefix("name:") }
		registry.legacy = legacyFixture

		var results: [[String: Any]] = []
		for step in try XCTUnwrap(c["steps"] as? [[String: Any]]) {
			let op = step["op"] as? String ?? ""
			if op == "elapse" {
				// Past the cooldown of the current failure count.
				let wait = BeamioPasscodeBackoff.cooldownSeconds(consecutiveFailures: attempts.failures)
				now = now.addingTimeInterval(TimeInterval(wait + 1))
				continue
			}
			let a = try XCTUnwrap(step["a"] as? [String: Any], "\(id): attempt arguments")
			let reqId = try XCTUnwrap(a["reqId"] as? String)
			if a["cancel"] as? Bool == true {
				// The page is closed before a submit: no read, no decision.
				results.append(["reqId": reqId, "code": BeamioNativeRecovery.ResultCode.cancelled.rawValue])
				continue
			}
			let outcome: BeamioNativeRecovery.RestoreOutcome
			if a["path"] as? String == "A" {
				outcome = BeamioNativeRecovery.restore(.recoveryCode(a["code"] as? String ?? ""), store: store)
			} else {
				let password = Array((a["password"] as? String ?? "").utf8)
				outcome = BeamioNativeRecovery.restore(.account(name: a["name"] as? String ?? "", password: password), store: store)
			}
			var result: [String: Any] = ["reqId": reqId, "code": outcome.code]
			if case .ok(let eoa) = outcome { result["eoa"] = eoa }
			if case .backoff(let seconds) = outcome { result["cooldownSec"] = seconds }
			results.append(result)
		}

		let expect = try XCTUnwrap(c["expect"] as? [String: Any])
		let want = try XCTUnwrap(expect["results"] as? [[String: Any]])
		XCTAssertEqual(results.count, want.count, "\(id): number of results")
		for (got, exp) in zip(results, want) {
			XCTAssertEqual(got["reqId"] as? String, exp["reqId"] as? String, "\(id): reqId")
			XCTAssertEqual(got["code"] as? String, exp["code"] as? String, "\(id): code")
			if let eoa = exp["eoa"] as? String {
				XCTAssertEqual(got["eoa"] as? String, eoa, "\(id): eoa")
			}
			if let seconds = exp["cooldownSec"] as? Int {
				XCTAssertEqual(got["cooldownSec"] as? Int, seconds, "\(id): cooldownSec")
			}
		}
		let state = try XCTUnwrap(expect["state"] as? [String: Any])
		XCTAssertEqual(!store.keys.isEmpty, state["hasKey"] as? Bool, "\(id): hasKey")
		XCTAssertEqual(attempts.failures, state["failures"] as? Int, "\(id): failures")
		XCTAssertEqual(cooldownActive(), state["cooldownActive"] as? Bool, "\(id): cooldownActive")
	}
}
