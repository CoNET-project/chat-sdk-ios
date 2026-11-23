import Foundation

/// The key-value calls that the SDK makes on its defaults. `UserDefaults` conforms (the product); a test build uses `BeamioMemoryDefaults`, which is an independent
/// implementation that does not inherit from `UserDefaults`, so no call, covered or not, can reach the machine's real defaults domain.
public protocol BeamioDefaultsStoring: AnyObject {
	func object(forKey key: String) -> Any?
	func string(forKey key: String) -> String?
	func dictionary(forKey key: String) -> [String: Any]?
	func integer(forKey key: String) -> Int
	func double(forKey key: String) -> Double
	func bool(forKey key: String) -> Bool
	func set(_ value: Any?, forKey key: String)
	func removeObject(forKey key: String)
}

extension UserDefaults: BeamioDefaultsStoring {}

/// The defaults that the SDK's own settings use (the entry pool cache, the guardian watch's read marks, the native-recovery PIN counter, the native account pointer, the clear-pending
/// marker). The product uses the standard defaults; a test build uses an in-memory object of its own (the same principle as the isolated file roots and the in-memory Keychain stand-in).
enum BeamioDefaults {
	static var standard: BeamioDefaultsStoring {
		#if BEAMIO_TEST_HOOKS
		return memory
		#else
		return UserDefaults.standard
		#endif
	}

	#if BEAMIO_TEST_HOOKS
	static let memory = BeamioMemoryDefaults()

	/// The keys the SDK writes into its defaults, for the guard that proves a test run left the real domain as it was.
	static let knownKeys = [
		"conet.entryPool.cache.v1",
		"beamio.guardian.storageRoot", "beamio.guardian.block", "beamio.guardian.builtAt", "beamio.guardian.nodeKeysV1",
		"beamio.recovery.pinFailures.v1", "beamio.recovery.pinLastFailure.v1",
		"beamio.native.account.v1",
	]
	#endif
}

#if BEAMIO_TEST_HOOKS
/// An in-memory implementation of `BeamioDefaultsStoring`: a dictionary behind a lock. It is not a `UserDefaults`; it has no suite, no domain and no file.
final class BeamioMemoryDefaults: BeamioDefaultsStoring {
	private var values: [String: Any] = [:]
	private let lock = NSLock()

	func object(forKey key: String) -> Any? { lock.lock(); defer { lock.unlock() }; return values[key] }
	func string(forKey key: String) -> String? { object(forKey: key) as? String }
	func dictionary(forKey key: String) -> [String: Any]? { object(forKey: key) as? [String: Any] }
	func integer(forKey key: String) -> Int { (object(forKey: key) as? NSNumber)?.intValue ?? 0 }
	func double(forKey key: String) -> Double { (object(forKey: key) as? NSNumber)?.doubleValue ?? 0 }
	func bool(forKey key: String) -> Bool { (object(forKey: key) as? NSNumber)?.boolValue ?? false }
	func set(_ value: Any?, forKey key: String) {
		lock.lock(); defer { lock.unlock() }
		if let value { values[key] = value } else { values[key] = nil }
	}
	func removeObject(forKey key: String) { set(nil, forKey: key) }
}
#endif
