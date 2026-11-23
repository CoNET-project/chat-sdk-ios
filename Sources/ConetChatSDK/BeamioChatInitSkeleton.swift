import Foundation

/// The `chatInit` skeleton (25.52Y.163 chatInit, draft r2.5.20 v7, sha256 e1e44860…). It is not registered to the bridge: no command-table entry,
/// no allow-list entry and no table-T pin. It holds only the pure parts of the contract: the closed external status set, the internal-to-external
/// mapping, the G0/G1 gate answer, the workspace default, and the public-field whitelist of the answer. It reads no store, sends nothing and writes nothing.
enum BeamioChatInitSkeleton {
	/// The external status (draft §1, closed set). The page shows `pending_confirm` as a wait, never as a failure.
	enum Status: String, Equatable {
		case ready
		case pendingConfirm = "pending_confirm"
		case registering
		case restoreFailed = "restore_failed"
		case error
	}

	/// The internal states (draft §1, not sent to the page). Each maps to one external status.
	enum Internal: Equatable {
		case unknown
		case retryReady
		case undetermined
		case normalEvaluation
		case writing
		case ready
		case registering
		case restoreFailed
		case error
	}

	/// The registration state shown to the page (draft §1 field `registrationStatus`).
	enum RegistrationStatus: String, Equatable {
		case none, submitted, confirmed
	}

	/// The external status of an internal state. `retry_ready` is never `registering`; every wait state is `pending_confirm`.
	static func status(of state: Internal) -> Status {
		switch state {
		case .unknown, .retryReady, .undetermined, .normalEvaluation, .writing: return .pendingConfirm
		case .ready: return .ready
		case .registering: return .registering
		case .restoreFailed: return .restoreFailed
		case .error: return .error
		}
	}

	/// The answer of a call before the flow runs (draft §1A item 2): G0 and G1 answer `pending_confirm` and read nothing, write nothing, generate nothing.
	/// Only G2 runs the full flow, so this returns nil for G2.
	static func gateStatus(_ gate: BeamioConetChatModule.NativeGate) -> Status? {
		switch gate {
		case .g0, .g1: return .pendingConfirm
		case .g2: return nil
		}
	}

	/// The workspace of the request (draft §1): missing means `default`; a non-string is refused (nil).
	static func workspace(_ body: [String: Any]) -> String? {
		guard let raw = body["workspace"] else { return "default" }
		guard let text = raw as? String else { return nil }
		return text
	}

	/// The public fields of the answer, the explicit whitelist (draft §1). Nothing else is ever passed through.
	static let publicFields: Set<String> = [
		"type", "reqId", "status", "eoa", "keyId", "publicKeyArmored", "registrationStatus", "code",
	]

	/// The names that must never appear in an answer (draft §1, forbidden names).
	static let forbiddenNames: Set<String> = [
		"userPgpPrivateArmor", "privateKeyArmor", "pgpPrivateKeyArmored", "armored", "walletSignature", "backupCiphertext",
		"mnemonic", "passphrase", "pin",
	]

	/// The `chatInitResult` answer. `eoa` is lower case. `code` is present only for `error` and `restore_failed`.
	static func answer(reqId: Int, status: Status, eoa: String?, keyId: String?, publicKeyArmored: String?,
	                   registration: RegistrationStatus, code: String?) -> [String: Any] {
		var out: [String: Any] = [
			"type": "chatInitResult",
			"reqId": reqId,
			"status": status.rawValue,
			"registrationStatus": registration.rawValue,
		]
		if let eoa { out["eoa"] = eoa.lowercased() }
		if let keyId { out["keyId"] = keyId }
		if let publicKeyArmored { out["publicKeyArmored"] = publicKeyArmored }
		if status == .error || status == .restoreFailed, let code { out["code"] = code }
		return out
	}

	/// True when the answer carries only whitelisted fields and none of the forbidden names.
	static func isPublic(_ answer: [String: Any]) -> Bool {
		answer.keys.allSatisfy { publicFields.contains($0) && !forbiddenNames.contains($0) }
	}
}
