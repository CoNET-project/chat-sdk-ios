import Foundation

/// The narrow discard of private-key records (25.52Y.163 r2.4.2 第 42(4) 项; 第 33(5)、36(5) 项的判据被其取代）.
///
/// A private-key record is not an account, so it is discarded only when both sides say clearly that they hold no mnemonic: the PWA side is
/// explicitly empty AND the native side is explicitly empty. Any unknown side (a read failed, or a listing failed) discards nothing, and a side
/// that holds a valid mnemonic discards nothing either. Each side discards only its own private-key records.
///
/// The audit is written before any deletion. When the audit cannot be written, nothing is deleted.
enum BeamioNarrowDiscard {
	/// One side's reading. `readOk` false: the side is unknown. `mnemonicAccounts`: the accounts with a valid mnemonic on this side.
	/// `privateKeyRecords`: the identifiers of this side's private-key records.
	struct Side: Equatable {
		let readOk: Bool
		let mnemonicAccounts: [String]
		let privateKeyRecords: [String]

		/// Explicitly empty of mnemonics: the read succeeded and no valid mnemonic exists on this side.
		var explicitlyEmpty: Bool { readOk && mnemonicAccounts.isEmpty }
	}

	/// One audit row of the narrow discard (第 46(3) 项, 第 46(5) 项): `{entryType, count, utc}`, holding the entry type, the count and the time only.
	/// `count` 0 is an abandoned or aborted discard (第 46(5) 项): the row records it, and it deletes nothing.
	static func auditRow(entryType: String, count: Int, utc: String) -> [String: Any] {
		["entryType": entryType, "count": count, "utc": utc]
	}

	/// The private-key records each side would discard. Empty unless both sides are explicitly empty of mnemonics (第 42(4) 項).
	struct Plan: Equatable {
		let pwa: [String]
		let native: [String]

		var isEmpty: Bool { pwa.isEmpty && native.isEmpty }
	}

	enum Outcome: Equatable {
		/// Nothing was deleted: there was no private-key record to discard, or a side was unknown or held a mnemonic.
		case nothingToDiscard
		/// The audit could not be written. Nothing was deleted.
		case auditFailed
		/// The audit was written and these records were deleted (each side's own).
		case discarded(pwa: [String], native: [String])
		/// A deletion failed after the audit. The records that were not deleted are kept and reported.
		case deletionIncomplete(pwaFailed: [String], nativeFailed: [String])
	}

	/// The plan for the two readings. Pure: nothing is read, written or deleted here.
	static func plan(pwa: Side, native: Side) -> Plan {
		guard pwa.explicitlyEmpty, native.explicitlyEmpty else {
			return Plan(pwa: [], native: [])
		}
		return Plan(pwa: pwa.privateKeyRecords, native: native.privateKeyRecords)
	}

	/// Runs the plan: the audit first, then the deletions of each side. `audit` gets the plan and returns true when it is written.
	/// `deletePWA` and `deleteNative` return the identifiers they could not delete (empty when all were deleted).
	static func execute(pwa: Side, native: Side,
	                    audit: (Plan) -> Bool,
	                    deletePWA: ([String]) -> [String],
	                    deleteNative: ([String]) -> [String]) -> Outcome {
		let plan = plan(pwa: pwa, native: native)
		guard !plan.isEmpty else { return .nothingToDiscard }
		guard audit(plan) else { return .auditFailed }
		let pwaFailed = plan.pwa.isEmpty ? [] : deletePWA(plan.pwa)
		let nativeFailed = plan.native.isEmpty ? [] : deleteNative(plan.native)
		if pwaFailed.isEmpty && nativeFailed.isEmpty {
			return .discarded(pwa: plan.pwa, native: plan.native)
		}
		return .deletionIncomplete(pwaFailed: pwaFailed, nativeFailed: nativeFailed)
	}
}
