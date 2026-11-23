import Foundation

/// The window-channel entries of the wallet commands `walletEoaAddress` and `walletCredential`. They are not in the
/// chat command table: the shell calls them from the injected window object, with the same boundary as `shellRecordRead` on iOS.
///
/// `trust` is the shell's verdict of the call: the origin, the main frame, and the package hash (the shell checks the hash against the
/// frozen manifest). The SDK does not require a capability bit here. Envelope errors (`origin_refused`, `bad_request`, `key_over_bridge_refused`)
/// are `ok: false` with `error`, not a `result.code`. `emit` receives the one ack of the call.
///
/// Shell call (iOS): `BeamioWindowWallet.walletEoaAddress(reqId: reqId, trusted: trusted) { ack in... }`, with `ack` the dictionary to pass back
/// to the page. The same for `walletCredential`.
/// The shell's trust verdict of a window call (spec §25.52Y.44 第 4 项, Y.49 第 2 项 (a)). `originRefused`: the origin or the frame does not match;
/// the envelope is `origin_refused`, once. `notTrusted`: the origin is allowed, but the package verification or a capability bit is not met.
public enum WindowTrust: Equatable {
	case trusted
	case originRefused
	case notTrusted

}

public enum BeamioWindowWallet {
	/// `walletEoaAddress`: `{type, reqId, ok: true, result: {eoa}}`. Only the public address.
	public static func walletEoaAddress(reqId: Any?, trust: WindowTrust, emit: ([String: Any]) -> Void) {
		answer(reqId: reqId, trust: trust, emit: emit) { BeamioConetChatModule.walletEoaAddressOutcome() }
	}

	/// `walletCredential`: `{type, reqId, ok: true, result: {eoa, credentialKind: "mnemonic", mnemonic}}`. An `eoa_key` account answers
	/// `ok: false` with `unavailable`; no private key is returned by any path.
	/// The capability bit `wallet.credential.v1`. This build declares it only when the frozen manifest carries it.
	/// No manifest carries it yet, so `walletCredential` answers `not_trusted` in every build.
	public static let walletCredentialCapability = "wallet.credential.v1"

	/// Whether this SDK build declares the capability (the SDK's own list, `BeamioConetChatProtocol.capabilities`).
	static func walletCredentialDeclared() -> Bool {
		#if BEAMIO_TEST_HOOKS
		if let declaredOverride { return declaredOverride }
		#endif
		return BeamioConetChatProtocol.capabilities.contains(walletCredentialCapability)
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only: declares or withholds the capability without a QA build (the QA list is compiled only under BEAMIO_QA_BUILD).
	static var declaredOverride: Bool? = nil
	#endif

	/// `walletCredential`. `body` is the request: `{type, reqId}` for the phrase with its blob, or
	/// `{type, reqId, mode: "unseal", blob}` to open a blob. Checks in the order of; nothing is read before the check that refuses it.
	public static func walletCredential(_ body: [String: Any], trust: WindowTrust, emit: ([String: Any]) -> Void) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		// 0: the shell's trust gate. An origin or frame mismatch is origin_refused (once); a package or capability failure is not_trusted (Y.44 第 4 项).
		if trust == .originRefused { emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "origin_refused")); return }
		guard trust == .trusted else { emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_trusted")); return }
		// 2: the SDK declares the capability `wallet.credential.v1`. Without it, no Keychain is read.
		guard walletCredentialDeclared() else { emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_trusted")); return }
		// 3: a key-shaped field name is refused, and only its name is logged.
		if body.keys.contains(where: isKeyShapedName) {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "key_over_bridge_refused"))
			return
		}
		// 4: any other field, a mode other than "unseal", a mode without a blob (or the reverse), or a blob that is not a string.
		let allowed: Set<String> = ["type", "reqId", "mode", "blob"]
		guard body.keys.allSatisfy({ allowed.contains($0) }) else {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request"))
			return
		}
		let hasMode = body["mode"] != nil
		let hasBlob = body["blob"] != nil
		guard hasMode == hasBlob else {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request"))
			return
		}
		let outcome: (ok: Bool, result: [String: Any]?, error: String?)
		if hasMode {
			guard body["mode"] as? String == "unseal", let blob = body["blob"] as? String else {
				emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request"))
				return
			}
			outcome = BeamioConetChatModule.walletCredentialUnsealOutcome(blob: blob)
		} else {
			outcome = BeamioConetChatModule.walletCredentialBlobOutcome()
		}
		emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: outcome.ok ? outcome.result : nil,
		                                         error: outcome.ok ? nil : (outcome.error ?? "unavailable")))
	}

	/// Field names that carry key material (第 4 項): the shell record's key-shaped names and prefixes, plus `eoaPrivateKey`.
	static func isKeyShapedName(_ name: String) -> Bool {
		name == "eoaPrivateKey" || BeamioShellRecord.keyShapeNames.contains(name)
			|| BeamioShellRecord.keyShapePrefixes.contains { name.hasPrefix($0) }
	}

	/// `shellRecordRead` through the window object `BeamioShellRecord`. `trusted` is the
	/// shell's judgement of the call; the SDK does not judge the origin itself. The answer split of: the envelope failures (`origin_refused`,
	/// `bad_request`, `key_over_bridge_refused`) are `ok: false` with `error`; the state and storage answers are `ok: true` with `result.code`.
	public static func shellRecordRead(_ body: [String: Any], trust: WindowTrust, emit: ([String: Any]) -> Void) {
		shellRecordEntry("shellRecordRead", body, trust: trust, emit: emit)
	}

	/// `shellRecordWrite` through the window object `BeamioShellRecord`. The same trust and answer rules as `shellRecordRead`.
	public static func shellRecordWrite(_ body: [String: Any], trust: WindowTrust, emit: ([String: Any]) -> Void) {
		shellRecordEntry("shellRecordWrite", body, trust: trust, emit: emit)
	}

	private static func shellRecordEntry(_ type: String, _ body: [String: Any], trust: WindowTrust, emit: ([String: Any]) -> Void) {
		var command = body
		command["type"] = type
		let reqId: Any = body["reqId"] ?? NSNull()
		if trust == .originRefused {
			emit(BeamioShellRecord.ackEnvelope(for: ["code": "origin_refused", "reqId": reqId]))
			return
		}
		// v163 section 183: the record commands answer origin_refused for every untrusted source, a package or capability failure included;
		// not_trusted is the walletCredential code, and untrusted_source stays with the old commands only.
		guard trust == .trusted else {
			emit(BeamioShellRecord.ackEnvelope(for: ["code": "origin_refused", "reqId": reqId]))
			return
		}
		guard let answer = BeamioConetChatModule.shellRecordWindowAnswer(command) else {
			emit(BeamioShellRecord.ackEnvelope(for: ["code": "bad_request", "reqId": reqId]))
			return
		}
		emit(BeamioShellRecord.ackEnvelope(for: answer))
	}

	private static func answer(reqId: Any?, trust: WindowTrust, emit: ([String: Any]) -> Void,
	                           outcome: () -> (ok: Bool, result: [String: Any]?, error: String?)) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(reqId) else {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		if trust == .originRefused {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "origin_refused"))
			return
		}
		guard trust == .trusted else {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_trusted"))
			return
		}
		let result = outcome()
		emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: result.ok ? result.result : nil,
		                                         error: result.ok ? nil : (result.error ?? "unavailable")))
	}
}
