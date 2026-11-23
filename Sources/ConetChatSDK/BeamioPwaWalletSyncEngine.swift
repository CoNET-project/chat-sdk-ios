import Foundation

/// The SDK entry point behind the shell's `PwaWalletSyncEngine` seam (IOS-SHELL-BRIDGE-01). The shell's trusted gate has already checked the origin,
/// the credential fields and the formats, so the origin is passed here as trusted. The engine reads the native snapshot state itself and runs the
/// rest of the decision (stale seq, same-account idempotency, the overwrite, the read-back, the preread state).
///
/// Each function returns one bare ack `{type: "ack", reqId, ok, result? | error?, reason?}`. It is never wrapped in a chatModuleEvent: the shell
/// wraps it. A reply cache for a repeated reqId and seq (spec section eleven) is not implemented: a repeated request is judged again, and the
/// same account with the same phrase answers idempotent.
public enum BeamioPwaWalletSyncEngine {
	public static func pwaWalletSync(reqId: Int, seq: Int, eoa: String, phrase: String) -> [String: Any] {
		answer([
			"type": "pwaWalletSync", "reqId": reqId, "seq": NSNumber(value: seq), "eoa": eoa, "phrase": phrase, "trustedOrigin": true,
		])
	}

	/// The passcode form of the sync (method Y): the account's v3 envelope and the six-digit passcode the page has just verified (nil: the page only mirrors the
	/// envelope and the account stays locked). The envelope is verified with the passcode in memory only and stays the native record; a correct passcode readies the
	/// session. Nothing here keeps or logs the passcode.
	public static func pwaWalletSync(reqId: Int, seq: Int, eoa: String, cipher: [String: Any], passcode: String?) -> [String: Any] {
		var body: [String: Any] = ["type": "pwaWalletSync", "reqId": reqId, "seq": NSNumber(value: seq), "eoa": eoa, "cipher": cipher, "trustedOrigin": true]
		if let passcode { body["passcode"] = passcode }
		return answer(body)
	}

	public static func nativeMnemonicPreread(reqId: Int, seq: Int) -> [String: Any] {
		answer(["type": "nativeMnemonicPreread", "reqId": reqId, "seq": NSNumber(value: seq), "trustedOrigin": true])
	}

	private static func answer(_ body: [String: Any]) -> [String: Any] {
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		let known = BeamioNativeKeySnapshot.isKnown
		let locked = BeamioNativeKeySnapshot.current()?.storageLock != nil
		return BeamioPwaWalletSync.answer(body, snapshotKnown: known, storageLocked: locked)
	}
}
