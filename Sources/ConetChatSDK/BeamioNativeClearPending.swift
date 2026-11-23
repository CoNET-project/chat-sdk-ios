import Foundation

/// The device marker `clear_pending`: a clear of the identity has started and its account pointer is not yet cleared.
/// It is set when the removal starts and cleared with the account pointer. It is not secret and it does not
/// depend on the keys or the copies. It is kept in UserDefaults, so it survives a restart. It is the one basis of an interrupted clear and its redo.
public enum BeamioNativeClearPending {
	/// Test seam: tests use their own suite. The app uses the standard defaults.
	public static var defaults: BeamioDefaultsStoring = BeamioDefaults.standard
	private static let key = "beamio.native.clear_pending.v1"

	/// True while a clear has started and has not cleared its account pointer.
	public static func isSet() -> Bool { defaults.bool(forKey: key) }

	/// The strict reading: `unset` (no value, or false), `set` (true), or `unreadable` (a value that is not a Boolean). `isSet()` cannot tell "not set" from "cannot
	/// be read"; a decision that must not delete on an unknown state uses this.
	public enum Reading: Equatable { case unset, set, unreadable }

	public static func read() -> Reading {
		guard let raw = defaults.object(forKey: key) else { return .unset }
		if let number = raw as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? .set : .unset }
		if let flag = raw as? Bool { return flag ? .set : .unset }
		return .unreadable
	}

	/// The account(s) whose clear is pending: written WITH the marker and read back. A redo is only for the recorded accounts.
	private static let ownersKey = "beamio.native.clear_pending.owners.v1"

	public enum Owners: Equatable {
		/// the marker carries no owner record (an older marker, or none written)
		case missing
		/// a record that cannot be read as a list of addresses
		case unreadable
		case list([String])
	}

	public static func owners() -> Owners {
		guard let raw = defaults.object(forKey: ownersKey) else { return .missing }
		guard let list = raw as? [String], !list.isEmpty else { return .unreadable }
		return .list(Array(Set(list.map { $0.lowercased() }.filter { !$0.isEmpty })).sorted())
	}

	/// The marker with the accounts it belongs to, written together and read back. Returns false when the owner record or the marker does not read back as written; this function
	/// removes nothing itself: the caller (clearSteps) calls `clear()` on false, so no half marker is left, and starts no deletion.
	@discardableResult
	public static func set(owners: [String]) -> Bool {
		let wanted = Array(Set(owners.map { $0.lowercased() }.filter { !$0.isEmpty })).sorted()
		defaults.set(wanted, forKey: ownersKey)
		defaults.set(true, forKey: key)
		if case .list(let back) = Self.owners(), back == wanted, read() == .set || read() == .unset { return isSet() }
		return false
	}

	/// The marker without an owner record (the shape of an older marker). Kept for the tests of that case and for callers that have no account.
	public static func set() { defaults.set(true, forKey: key) }

	public static func clear() {
		defaults.removeObject(forKey: key)
		defaults.removeObject(forKey: ownersKey)
	}
}
