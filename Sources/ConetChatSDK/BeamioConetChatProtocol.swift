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
	/// Version of this package.
	public static let sdkVersion = "0.1.8"

	/// Capabilities this module implements (names from the spec's `CHAT_DAEMON_CAPABILITIES`).
	public static let capabilities: [String] = [
		"identity.provision",
		"signing.local",
		"lifecycle.daemon",
		"inbound.deferAck",
		"history.v2",
		"call.control",
		"voice.delegated",
		"presence.query",
		"mailbox.command",
	]

	/// `hello` answer (`ack.result`).
	public static func helloResult() -> [String: Any] {
		[
			"protocolVersion": protocolVersion,
			"minProtocolVersion": minProtocolVersion,
			"sdkVersion": sdkVersion,
			"implementation": "ios",
			"capabilities": capabilities,
		]
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
