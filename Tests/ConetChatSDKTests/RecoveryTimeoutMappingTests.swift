import XCTest
@testable import ConetChatSDK

/// The recovery source timing out (25.52Y.163 M-1, draft 3A): a timeout is unknown, so the page gets `network_error` and may retry. It is not a
/// wrong PIN: the failure counter is not written, so no cooldown follows. Synthetic values only.
final class RecoveryTimeoutMappingTests: XCTestCase {
	/// A registry whose current read times out at every endpoint.
	private final class TimeoutRegistry: BeamioRecoveryRegistryReading {
		func recordByNameHash(_ nameHash: [UInt8]) -> Result<String, Error> { .failure(URLError(.timedOut)) }
		func recordByAccountName(_ name: String) -> Result<String, Error> { .failure(URLError(.timedOut)) }
		func legacyRecordByAccountName(_ name: String) -> Result<String, Error> { .failure(LegacyRegistryRetired()) }
	}

	/// The PIN attempt store, counting the writes.
	private final class CountingAttempts: BeamioNativeRecovery.PinAttemptStoring {
		var saves = 0
		func load() -> (failures: Int, lastFailure: Date?) { (0, nil) }
		func save(failures: Int, lastFailure: Date?) { saves += 1 }
	}

	private var savedRegistry: BeamioRecoveryRegistryReading?
	private var savedAttempts: BeamioNativeRecovery.PinAttemptStoring?

	override func setUp() {
		super.setUp()
		savedRegistry = BeamioNativeRecovery.registry
		savedAttempts = BeamioNativeRecovery.attempts
		BeamioNativeRecovery.registry = TimeoutRegistry()
	}

	override func tearDown() {
		BeamioNativeRecovery.registry = savedRegistry
		BeamioNativeRecovery.attempts = savedAttempts ?? BeamioNativeRecovery.attempts
		super.tearDown()
	}

	/// Path B (account name and password) with the registry timing out: `network_error`, and the PIN counter is not written.
	func testAPathBRegistryTimeoutIsNetworkErrorAndCountsNothing() {
		let attempts = CountingAttempts()
		BeamioNativeRecovery.attempts = attempts
		let outcome = BeamioNativeRecovery.restore(.account(name: "syn_timeout_0001", password: Array("x1".utf8)),
		                                           store: MemoryNativeKeyStore())
		XCTAssertEqual(outcome.code, "network_error", "a timeout is unknown: the page may retry")
		XCTAssertEqual(attempts.saves, 0, "a timeout is not a wrong PIN: the failure counter is not written")
	}

	/// Path A (recovery code) with the same timeout: also `network_error`, nothing counted (the counter is path B only).
	func testAPathARegistryTimeoutIsNetworkErrorAndCountsNothing() {
		let attempts = CountingAttempts()
		BeamioNativeRecovery.attempts = attempts
		let outcome = BeamioNativeRecovery.restore(.recoveryCode(String(repeating: "A", count: 22)), store: MemoryNativeKeyStore())
		XCTAssertEqual(outcome.code, "network_error")
		XCTAssertEqual(attempts.saves, 0)
	}
}
