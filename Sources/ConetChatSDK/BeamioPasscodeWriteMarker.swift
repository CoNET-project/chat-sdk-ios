import Foundation

/// The in-process marker of a passcode write in progress, per account (interface spec v205 section 225.2). A staging record may only be taken for a leftover when no
/// write of its account is running in this process; the cleanup asks `isInProgress`. The marker is a counter: nested or concurrent writes of one account all
/// have to end. It is released on every exit of the write (the caller uses `defer`), so an early return or a failure never leaves it set.
///
/// LIMITS (read before changing the app's targets): the marker covers one storage call (`BeamioPasscodeKeychainRecords.writeRecord/deleteRecord`, the single choke point) and
/// the whole span of the two flows in which a staging copy exists (`stagedReplace`, `shellReconcileStaging`); the steps between the calls of a multi-step flow (the
/// attempt-counter update, a write check, a rollback) are not inside it. It is valid in THIS PROCESS only. Today no other process writes these records (the iOS shell has no
/// app extension and no app group or keychain access group; the Keychain items are the app's own). If an App Extension, a notification service extension or a shared app
/// group or keychain access group is ever added, the marker MUST become a cross-process one (for example a lock file in the shared container) in the same change, or the rule
/// "no staging copy is deleted while a write of its account is running" no longer holds.
enum BeamioPasscodeWriteMarker {
	private static let lock = NSLock()
	private static var counts: [String: Int] = [:]

	/// The time this process started (taken at first use, which is in the first moments of the process): a staging record older than this is not this process's write.
	static let processStart = Date()

	#if BEAMIO_TEST_HOOKS
	/// Test build only: told of every `begin` (the account), so that a test can prove a write path sets the marker.
	static var testOnBegin: ((String) -> Void)?
	#endif

	static func begin(_ eoa: String) {
		#if BEAMIO_TEST_HOOKS
		testOnBegin?(eoa.lowercased())
		#endif
		lock.lock(); defer { lock.unlock() }
		counts[eoa.lowercased(), default: 0] += 1
	}

	static func end(_ eoa: String) {
		lock.lock(); defer { lock.unlock() }
		let key = eoa.lowercased()
		let next = (counts[key] ?? 0) - 1
		if next > 0 { counts[key] = next } else { counts[key] = nil }
	}

	/// Runs `body` with the marker set for `eoa`. The marker is a re-entrant counter: nested scopes of one account (createKey calls createFallbackKey, a flow calls a
	/// store call) each add one and each take one away, so an inner scope never releases the outer one. It is released on every exit: a normal return, an early return and a throw.
	@discardableResult
	static func scoped<T>(_ eoa: String, _ body: () throws -> T) rethrows -> T {
		begin(eoa)
		defer { end(eoa) }
		return try body()
	}

	static func isInProgress(_ eoa: String) -> Bool {
		lock.lock(); defer { lock.unlock() }
		return (counts[eoa.lowercased()] ?? 0) > 0
	}
}
