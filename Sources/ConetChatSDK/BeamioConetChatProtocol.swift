import Foundation

/// ChatDaemon protocol v1, iOS side. The spec lives in `@conet.project/chat-sdk`
/// (`src/protocol.ts`, `spec/chat-daemon-protocol.v1.schema.json`); this file
/// follows it. Shared conformance vectors: `Tests/ConetChatSDKTests/Resources/chat-daemon-vectors.v1.json`
/// (a copy of the spec's file, see `scripts/sync-protocol-vectors.sh`).
public enum BeamioConetChatProtocol {
	/// Newest protocol version this module speaks.
	public static let protocolVersion = 1
	/// Oldest protocol version this module still speaks.
	public static let minProtocolVersion = 1
	/// The formal version of this package (incremented from 0.2.2, the qa suffix dropped; project rule for Release, 2026-11-16).
	static let formalVersion = "0.2.3"
#if BEAMIO_QA_BUILD
	/// Version of this package. A QA candidate keeps a qa suffix so it cannot be mistaken for a formal build.
	public static let sdkVersion = "0.2.3-qa.1"
#else
	/// Version of this package. A Release build carries the formal version, with no qa suffix.
	public static let sdkVersion = formalVersion
#endif

	/// Capabilities this module implements (names from the spec's `CHAT_DAEMON_CAPABILITIES`).
	/// The order is the shared vector's. `history.local.v1`, `history.page.v1` and
	/// `layout.cache.v1` are the capabilities the `ready` event already announces, and the module serves their commands.
	public static let capabilities: [String] = [
		"identity.provision",
		"signing.local",
		"lifecycle.daemon",
		"inbound.deferAck",
		// this shell supports `inboundGeneration`, so the page waits for its event before it sends.
		"inbound.generation.v1",
		"history.v2",
		"call.control",
		"voice.delegated",
		"presence.query",
		"mailbox.command",
		"send.mailboxWrap",
		"history.local.v1",
		"history.page.v1",
		"layout.cache.v1",
		// 25.52Y.93 第 2 条, 25.52Y.121 第 1 条: the native key pair is declared together, kpresent first, in every build (Release included).
		"identity.kpresent.v1",
		"identity.native-keys.v1",
		// The shell passcode protocol (PROTOCOL-shell-passcode-v1, frozen SHA-256 adb8b71a…, §1.5): declared in every build, Release and QA alike.
		// A build without it fails closed on the page (a release blocker), so it is never moved to `qaCapabilities`. Declared only because the
		// six commands (BeamioShellPasscodeCommands) are implemented and tested.
		BeamioConetChatProtocol.passcodeCapability,
		// Native delivery receipts: declared only because setRoutes validation and answers, the eoa check,
		// the whitelist, the (from, sendId) and armorHash dedupe, the two in-flight places, the 128 / 10-minute queue, the locks and the clear
		// are all implemented and tested (DeliveryReceiptTests, DR-01..18). Never remove one of them without removing this name.
		BeamioConetChatProtocol.deliveryReceiptCapability,
	] + qaCapabilities

	/// The capability of the shell passcode protocol. Not `identity.native-keys.v1`, which only says that the native layer holds the keys.
	public static let passcodeCapability = "wallet.passcode.v1"

	/// The capability of the native delivery receipt. The page sends `setRoutes` and skips its own receipt only when hello declares it.
	public static let deliveryReceiptCapability = "receipt.delivery.v1"

	// The native key pair (`identity.kpresent.v1`, `identity.native-keys.v1`) is in `capabilities` above, in the shipped list. It is not a QA
	// switch: a Release build declares it (project requirement; 25.52Y.119 to Y.121). Its prerequisites are in place: kPresent on the G0
	// identityPublic answer (25.52Y.90), and the import page's nativeImportResult with the public eoa (25.52Y.95, Y.97).

	/// The static declaration of the QA candidate. Compiled only in the QA configuration, which defines
	/// BEAMIO_QA_BUILD. Release and Store builds do not contain these names in the hello list. Not a runtime switch.
#if BEAMIO_QA_BUILD
	static let qaCapabilities: [String] = ["identity.route-register.native.v1", "wallet.credential.v1", "identity.first.status.v1"]
#else
	static let qaCapabilities: [String] = []
#endif

#if BEAMIO_QA_BUILD
	/// The QA-only marker literal. Compiled only in the QA configuration, so a store build never contains it. A store export may refuse any binary that contains this text.
	/// The text occurs only inside the QA conditional block and its tests (git grep).
	public static let qaBuildMarker = "beamio-sdk-qa-only-marker"
#endif

	/// The native app that is installed and running (project owner, 2026-11-21; interface spec v158 section 178, which replaces v157 section 177): `hello`
	/// reports `nativeApp: {platform: "ios", version, build}`, read at run time in the host process from the HOST app's main bundle
	/// (`Bundle.main`: `CFBundleShortVersionString` and `CFBundleVersion`). Never the SDK's own bundle, never a compile-time constant, never the SDK
	/// version. `version` must match `^\d+(\.\d+){1,3}\z` and `build` `^\d+\z` (`\z`: the end of the text, so a trailing newline does not pass); a missing key, a value that is not a string, an empty one or one of another form
	/// gives no `nativeApp` field (nothing is invented, and the page reads a missing field as unknown). The shell does not write this field as well.
	public static func nativeApp() -> [String: String]? {
		guard let info = hostInfo(),
		      let version = info["CFBundleShortVersionString"] as? String, matches(version, #"^\d+(\.\d+){1,3}\z"#),
		      let build = info["CFBundleVersion"] as? String, matches(build, #"^\d+\z"#)
		else { return nil }
		return ["platform": "ios", "version": version, "build": build]
	}

	private static func matches(_ text: String, _ pattern: String) -> Bool {
		text.range(of: pattern, options: .regularExpression) != nil
	}

	/// The Info dictionary of the host app: `Bundle.main`, the process's main bundle, which is the app that embeds the SDK. Only a test build can replace
	/// it (`hostInfoOverride`); a release build has no such seam.
	private static func hostInfo() -> [String: Any]? {
		#if BEAMIO_TEST_HOOKS
		if let override = hostInfoOverride { return override() }
		#endif
		return Bundle.main.infoDictionary
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook only: stands in for the host Info dictionary. nil restores the real one.
	static var hostInfoOverride: (() -> [String: Any]?)?
	#endif

	/// `hello` answer (`ack.result`).
	public static func helloResult() -> [String: Any] {
		var result: [String: Any] = [
			"protocolVersion": protocolVersion,
			"minProtocolVersion": minProtocolVersion,
			"sdkVersion": sdkVersion,
			"implementation": "ios",
			"capabilities": capabilities,
		]
		if let app = nativeApp() { result["nativeApp"] = app }
		return result
	}
}

/// Plaintext shapes on the wire (before PGP encryption). Same objects as the
/// spec's `src/wire.ts` and Android `BeamioConetChatWire`.
public enum BeamioConetChatWire {
	/// Outer chat envelope; `signMessage` = EIP-191(`text`), only inside the user-PGP layer.
	public static func chatEnvelope(timestamp: Int, text: String, from: String, signMessage: String) -> [String: Any] {
		["timestamp": timestamp, "text": text, "from": from, "signMessage": signMessage]
	}

	/// The signed middle row `{ sendId, from: "me", text, createdAt }`.
	public static func pendingRow(sendId: String, text: String, createdAt: Int) -> [String: Any] {
		["sendId": sendId, "from": "me", "text": text, "createdAt": createdAt]
	}

	/// `gossip_delivery_ack` to the own mailbox. `timestamp` in seconds.
	public static func deliveryAckCommand(eoa: String, armorHash: String, timestamp: Int) -> [String: Any] {
		["command": "gossip_delivery_ack", "walletAddress": eoa, "armorHash": armorHash, "timestamp": timestamp]
	}

	/// Receipt sent back to the sender as a NoPush chat message. `deliveredAt` in ms.
	public static func deliveryReceipt(sendId: String, armorHash: String, deliveredAt: Int, eoa: String) -> [String: Any] {
		["type": "beamio_chat_delivery_receipt_v1", "sendId": sendId, "armorHash": armorHash, "deliveredAt": deliveredAt, "from": eoa]
	}

	/// Mailbox work packet; `NoPush` only when true.
	public static func mailboxWork(data: String, noPush: Bool) -> [String: Any] {
		noPush ? ["data": data, "NoPush": true] : ["data": data]
	}
}
