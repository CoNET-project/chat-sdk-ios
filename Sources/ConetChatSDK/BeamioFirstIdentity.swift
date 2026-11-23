import Foundation

/// The first-identity judgement (frozen protocol §13): a new chat key may be made only when this account has no old chat key on this
/// device (`legacy` ABSENT) and the chain has no registration (`chain` unregistered). Both are judged here, natively; the page's own signals do not
/// count. Nothing is read from the page, nothing is written, and the answer is not kept: it is judged again at every use.
///
/// Any source that cannot be read gives UNREADABLE / unknown, never ABSENT / unregistered.
public enum BeamioFirstIdentity {
	public enum Legacy: String, Equatable {
		case absent = "ABSENT"
		case present = "PRESENT"
		case unreadable = "UNREADABLE"
	}

	/// Replaced in tests. Production: the single-RPC chain read.
	static var chainProbe: (String) -> AddressPGPChain.ChainStatus = { AddressPGPChain.chainStatus(eoa: $0) }

	/// Whether this device holds an old chat private key of `eoa`, or something that stops a new one.
	/// PRESENT: any source confirms it. UNREADABLE: none confirms it, but one cannot be read, or the device holds PGP items that cannot be assigned to
	/// this account. ABSENT: every source confirms that there is none.
	public static func legacy(eoa rawEoa: String) -> Legacy {
		let eoa = rawEoa.lowercased()
		var unreadable = false
		switch BeamioChatPgpKeychain.recordState(eoa: eoa) {
		case .present: return .present
		case .unreadable: unreadable = true
		case .absent: break
		}
		// the plain legacy layout whose account is this one
		if let old = BeamioChatPgpKeychain.readOnlyRecord(eoa: eoa), old.hasUserPrivate { return .present }
		// the migration copy, marker or a run that failed
		if BeamioPgpMigrationImport.state(eoa: eoa) != .none { return .present }
		// a new identity in progress, or a restore that did not finish
		// (a prepared identity that holds no key yet is this very flow's own mark, not an old key)
		if let pending = BeamioChatPgpKeychain.loadPending(eoa: eoa), !pending.privateArmor.isEmpty { return .present }
		if BeamioChatPgpKeychain.restoreIncomplete(eoa: eoa) { return .present }
		if unreadable { return .unreadable }
		// items on the device that cannot be told apart from this account's: not "none"
		switch BeamioChatPgpKeychain.devicePresenceState() {
		case false?: return .absent
		case true?, nil: return .unreadable
		}
	}

	public static func chain(eoa: String) -> AddressPGPChain.ChainStatus { chainProbe(eoa.lowercased()) }

	/// `pgpIdentityCreate` may make a first identity only when both fields say so. Judged by the native layer at the prepare and again at the
	/// confirmation (a fresh single-RPC read each time), whatever the page says.
	public static func firstIdentityEligible(eoa: String) -> Bool { firstIdentityRefusal(eoa: eoa) == nil }

	/// The refusal code of a first identity, or nil when it may go on. The chain is read first: a registration seen now is `cas_conflict` (the chain
	/// is not empty any more, nothing is generated or written), an unreadable chain is `pgp_source_unavailable`. Then the device: an old chat key, or
	/// a source that cannot be read, is `not_eligible`.
	public static func firstIdentityRefusal(eoa: String) -> String? {
		switch chain(eoa: eoa) {
		case .registered: return "cas_conflict"
		case .unknown: return "pgp_source_unavailable"
		case .unregistered: break
		}
		return legacy(eoa: eoa) == .absent ? nil : "not_eligible"
	}
}
