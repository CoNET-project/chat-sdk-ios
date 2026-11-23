import Foundation
import Security

/// The category of the last wallet-Keychain read failure (v161 section 181): a class only, never the item content or the raw error text.
/// `entitlement` (errSecMissingEntitlement, -34018) is a build configuration a retry never cures; `device_locked` (errSecInteractionNotAllowed,
/// -25308) ends at the first unlock; anything else is `other` and is not retried (a failure that cannot be classified is not a transient one).
enum BeamioKeychainFailureNote {
	static let entitlement = "entitlement"
	static let deviceLocked = "device_locked"
	static let other = "other"

	/// PREMISE (tested by testAReadFailingOnAnotherThreadDoesNotChangeTheCause): the reads of a snapshot judgement run synchronously on the thread that judges (the snapshot,
	/// the mnemonic inventory and the wallet keychain store have no DispatchQueue or async hop), so the category left on that thread is the category of those reads. If any of
	/// those reads is ever made asynchronous or moved to another thread, the category MUST be passed back as the return value of the read call (a change of the
	/// `BeamioChatWalletKeyStoring` signatures) instead of this note, in the same change.
	///
	/// The note is per thread: a snapshot judgement reads only what its own thread's reads left, never what another thread's read failed with.
	private static let key = "com.beamio.keychain-failure-note"
	private static var last: String? {
		get { Thread.current.threadDictionary[key] as? String }
		set { Thread.current.threadDictionary[key] = newValue }
	}

	static func category(of status: OSStatus) -> String {
		switch status {
		case -34018: return entitlement
		case errSecInteractionNotAllowed: return deviceLocked
		default: return other
		}
	}

	/// Called with the status of a read: a failure records its category; a success or "not found" leaves the note (it is cleared by `reset`, at the start of
	/// a snapshot judgement, which then takes the category the judgement's own reads left).
	static func note(_ status: OSStatus) {
		guard status != errSecSuccess, status != errSecItemNotFound else { return }
		last = category(of: status)
	}

	static func reset() { last = nil }

	/// The category of the last failure; `other` when a read was judged unreadable without a recorded status.
	static var current: String { last ?? other }

	static func retryable(_ cause: String) -> Bool { cause == deviceLocked }

	/// Test only.
	static func setForTests(_ cause: String?) { last = cause }
}
