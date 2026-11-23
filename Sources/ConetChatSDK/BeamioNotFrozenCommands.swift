import Foundation

/// Bridge commands whose spec, vectors or registry are not frozen yet. They are stubs: each is
/// judged by the gate first (G0 `no_key`, G1 `not_ready`, spec, before any payload is read), and then refused.
/// No key material, no signature, no event, no state change. They become real when the interface owner freezes the
/// vectors and registries (matrix GAP-06, GAP-07, GAP-10, GAP-11, GAP-16, GAP-15, GAP-13, GAP-14).
enum BeamioNotFrozenCommands {
	/// C1 `historySign` (spec: the protocol root is never returned by the native SDK, so there is no bridge answer;
	/// the derivation is internal, see BeamioNativeWallet.historyMaster), and the N1 to N4 signing commands (; registry drafts, not frozen).
	/// W5 `signMessage` is not a bridge name, so it is not listed. C5 `deriveSubkeys` and W7 `ephemeralSign` are built
	/// and are not listed here.
	static let names: Set<String> = [
		"historySign",
		"walletSignTypedData", "walletSignMessage", "walletSendTransaction", "walletTransfer", "walletSignUserOp",
	]

	/// Value-moving commands (G-3). Each needs a native confirmation panel, which the SDK does not have: the
	/// shell draws it, and a confirmation from the page is refused (`confirmation_not_native`, as in C-21).
	static let valueMoving: Set<String> = ["walletSignTypedData", "walletSendTransaction", "walletTransfer", "walletSignUserOp"]

	/// The refusal code for an unfrozen command. Only the code is returned.
	static func refusal(type: String, body: [String: Any]) -> String {
		if valueMoving.contains(type), body["confirm"] != nil { return "confirmation_not_native" }
		return "not_supported"
	}
}
