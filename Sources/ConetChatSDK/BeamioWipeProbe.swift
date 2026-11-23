import Foundation

#if BEAMIO_TEST_HOOKS
/// Test build only (BEAMIO_TEST_HOOKS): records every buffer wipe (length, whether it held a non-zero byte before, whether it is all zero after),
/// so a test can prove that a session clear overwrote the key bytes in place. It holds no key bytes.
enum BeamioWipeProbe {
	struct Event: Equatable { let count: Int; let hadNonZero: Bool; let allZero: Bool; let address: UInt? }
	private static let lock = NSLock()
	private static var events: [Event] = []
	private static var on = false

	static func start() { lock.lock(); events = []; on = true; lock.unlock() }
	static func stop() -> [Event] { lock.lock(); defer { lock.unlock() }; on = false; return events }
	static func record(count: Int, hadNonZero: Bool, allZero: Bool, address: UInt?) {
		lock.lock(); defer { lock.unlock() }
		if on { events.append(Event(count: count, hadNonZero: hadNonZero, allZero: allZero, address: address)) }
	}
}
#endif
