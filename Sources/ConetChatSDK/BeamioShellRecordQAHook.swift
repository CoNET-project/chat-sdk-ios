#if BEAMIO_SHELL_RECORD_QA
import Foundation

/// The QA test hook of the record bridge. It exists only in a build compiled with the `BEAMIO_SHELL_RECORD_QA` condition,
/// and only the native test target calls it. It is not a page command and is not reachable through the window channel or the chat-module channel.
/// A production build contains no symbol, command name or string of it; the release gate scans the artifact for that.
enum BeamioShellRecordQAHook {
	/// Removes `privateKeyArmor` from the profile whose keyID is the account, so that a read answers `needs_native_recovery` (AK-20). Nothing else
	/// changes: not `mnemonicPhrase`, `recoveryWords`, the account pointer, the device state, L or K, and not the record's `rev`.
	/// Returns false when the record is absent or no profile whose keyID is the account holds the key.
	@discardableResult
	static func removeEOAPrivateKey(account: String, store: BeamioShellRecord.ShellRecordStore) -> Bool {
		guard case let .record(record) = store.read(account: account) else { return false }
		guard var profiles = record["profiles"] as? [[String: Any]] else { return false }
		var removed = false
		for index in profiles.indices {
			guard (profiles[index]["keyID"] as? String)?.lowercased() == account.lowercased(),
			      profiles[index]["privateKeyArmor"] != nil
			else { continue }
			profiles[index].removeValue(forKey: "privateKeyArmor")
			removed = true
		}
		guard removed else { return false }
		var next = record
		next["profiles"] = profiles
		return store.write(account: account, next)
	}
}
#endif
