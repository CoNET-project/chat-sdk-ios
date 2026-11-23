import XCTest
@testable import ConetChatSDK

/// Isolates the device account pointer and the gate session for one test (spec). Each test gets its own
/// in-memory defaults object (no suite, no domain, no preferences file), and the defaults and the session are reset at the end, so no state leaks between tests.
enum NativeAccountPointerIsolation {
	/// The defaults in use before `begin`, restored by `end` (a test-hook build has its own process suite, not the standard defaults).
	private static var previousDefaults: BeamioDefaultsStoring?

	static func begin() {
		previousDefaults = BeamioNativeAccountPointer.defaults
		BeamioNativeAccountPointer.defaults = BeamioMemoryDefaults()   // in memory: no suite, no domain, no preferences file
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
	}

	static func end() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeAccountPointer.defaults = previousDefaults ?? BeamioMemoryDefaults()
		previousDefaults = nil
	}
}
