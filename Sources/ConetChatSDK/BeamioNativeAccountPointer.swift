import Foundation

/// The device's native account pointer (spec, gates G0 and G1): the account whose native key record is on this
/// device. The address is public. It is written when a record is written (the import,) or found at `init`, and
/// cleared when the identity is cleared. It is kept in UserDefaults, so a cold start with a record is G1, not G0.
public enum BeamioNativeAccountPointer {
	/// Test seam: tests use their own defaults. The app uses the standard defaults.
	/// A test-hook build (BEAMIO_TEST_HOOKS) defaults to an in-memory defaults object of its own, fresh for each test process, so no test writes the test host's standard defaults and no
	/// preferences file is left behind (an earlier version used a named suite per process, which left one plist in ~/Library/Preferences for every test process).
	public static var defaults: BeamioDefaultsStoring = {
		#if BEAMIO_TEST_HOOKS
		return BeamioMemoryDefaults()
		#else
		return UserDefaults.standard
		#endif
	}()
	private static let key = "beamio.native.account.v1"

	/// The lower-case account, or empty when no pointer is set.
	public static func get() -> String { (defaults.string(forKey: key) ?? "").lowercased() }

	/// The strict read of the pointer, for session decisions: `empty` (no value), `value`, or `unreadable` (a value that is not a string). `get()` cannot
	/// tell "empty" from "cannot be read"; a session is never decided from it.
	public enum Reading: Equatable {
		case empty
		case value(String)
		case unreadable
	}

	public static func read() -> Reading {
		guard let raw = defaults.object(forKey: key) else { return .empty }
		guard let text = raw as? String else { return .unreadable }
		let eoa = text.lowercased()
		return eoa.isEmpty ? .empty : .value(eoa)
	}

	/// A change of the pointer refreshes the native-key snapshot in the same critical section (25.52Y.70 第 4 項). A pointer that now names another
	/// account (or none) ends every unlocked session: the session keys of the old account are wiped (frozen protocol, session clearing).
	public static func set(_ eoa: String) {
		let old = get()
		let new = eoa.lowercased()
		BeamioNativeKeySnapshot.mutate { defaults.set(new, forKey: key) }
		if old != new { BeamioPasscodeSession.shared.lockAll(reason: .accountSwitch) }
	}

	public static func clear() {
		let old = get()
		BeamioNativeKeySnapshot.mutate { defaults.removeObject(forKey: key) }
		if !old.isEmpty { BeamioPasscodeSession.shared.lockAll(reason: .logout) }
	}

	/// The result of a pointer write that is read back (25.52Y.160, the device check before a selection is answered ok).
	/// `written`: the read-back equals the address written. `mismatch`: a value is read back, and it is another address.
	/// `unreadable`: no value can be read back (the read failed); the state after the write is unknown.
	public enum WriteCheck: Equatable {
		case written, mismatch, unreadable
	}

	/// Writes the pointer, reads it back and compares. A write that does not read back as written (`mismatch`, `unreadable`) puts the previous pointer back exactly as it
	/// was (the value, or no value), so a failed write never switches the account (MS-W2). The sessions of the old account end only after the new pointer reads back
	/// (`written`) and only when the account really changed.
	public static func writeChecked(_ eoa: String) -> WriteCheck {
		let target = eoa.lowercased()
		let before = get()
		let beforeRaw = defaults.object(forKey: key)
		BeamioNativeKeySnapshot.mutate { defaults.set(target, forKey: key) }
		guard let readBack = defaults.object(forKey: key) as? String else {
			restore(beforeRaw)
			return .unreadable
		}
		guard readBack.lowercased() == target else {
			restore(beforeRaw)
			return .mismatch
		}
		if before != target { BeamioPasscodeSession.shared.lockAll(reason: .accountSwitch) }
		return .written
	}

	/// Puts the pointer back as it was before a failed checked write: the previous value, or no value when there was none.
	private static func restore(_ previous: Any?) {
		BeamioNativeKeySnapshot.mutate {
			if let previous { defaults.set(previous, forKey: key) } else { defaults.removeObject(forKey: key) }
		}
	}
}
