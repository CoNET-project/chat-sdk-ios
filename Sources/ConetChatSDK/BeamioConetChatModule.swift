import CryptoKit
import Foundation
import Network

/// Native Conet Chat Module — WorkerCommand / WorkerOutbound parity; 1B signing via PWA.
public enum BeamioConetChatModule {
	public typealias WebEmit = (_ payload: [String: Any]) -> Void

	/// Entry / mailbox node with optional route PGP (from PWA setNodes).
	public struct Node {
		public var ip: String
		public var domain: String
		public var region: String
		public var armoredPublicKey: String
		public init(ip: String, domain: String, region: String, armoredPublicKey: String) {
			self.ip = ip
			self.domain = domain
			self.region = region
			self.armoredPublicKey = armoredPublicKey
		}

		public func asKeychainNode() -> BeamioChatPgpKeychain.SiNode {
			BeamioChatPgpKeychain.SiNode(ip: ip, domain: domain, region: region, armoredPublicKey: armoredPublicKey)
		}
	}

	/// The API base of the init payload: the page's `apiBaseUrl` wins when it is given; without it, or when it is empty or blank, the current value stays. The default is `https://beamio.ca/api`.
	static func resolvedApiBaseUrl(payload: [String: Any], current: String) -> String {
		let given = (payload["apiBaseUrl"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
		// An empty or blank value keeps the current one, as the Android side does (ifBlank); it never becomes a relative request base.
		return given.isEmpty ? current : given
	}

	public final class Session {
		public init() {}
		/// Set when `init` completes for `eoa` (spec, G2).
		public var ready = false
		public var eoa: String = ""
		public var pgpPublicKeyArmored: String = ""
		public var ownRouteArmoredPublicKey: String = ""
		public var mailboxIp: String = ""
		/// Route key ID the running listen sent its last `mailbox_listen` to (log + handoff check).
		public var listenRouteKeyId: String = ""
		public var nodes: [Node] = []
		/// The peers' routes the page handed over by `setRoutes` (memory only). Read and written under `routesLock`.
		public var routes: [[String: Any]] {
			get { routesLock.lock(); defer { routesLock.unlock() }; return routesStorage }
			set { routesLock.lock(); routesStorage = newValue; routesLock.unlock() }
		}
		private var routesStorage: [[String: Any]] = []
		private let routesLock = NSLock()
		/// Receipts that waited for a route (from, sendId, armorHash, queued at, generation); and the armorHashes already receipted or queued.
		/// Memory only, no plaintext. Guarded by `receiptLock`.
		var receiptQueue: [(from: String, sendId: String, armorHash: String, at: Date, generation: Int)] = []
		var receiptedHashes: [String] = []
		/// (from, sendId) already receipted or queued, oldest first; at most 1024.
		var receiptedKeys: [String] = []
		/// Receipts ready to post but waiting for one of the two in-flight places (shares the 128 limit with `receiptQueue`).
		var receiptOutbox: [(route: [String: Any], sendId: String, armorHash: String)] = []
		var receiptInFlight = 0
		let receiptLock = NSLock()
		/// Drops the routes and the queued receipts (identity clear, account switch, session end, init rebuild).
		func clearReceiptState() {
			routes = []
			receiptLock.lock()
			receiptQueue = []
			receiptedHashes = []
			receiptedKeys = []
			receiptOutbox = []
			receiptInFlight = 0
			receiptLock.unlock()
		}
		public var conetRpcUrl: String = "https://rpc1.conet.network"
		public var ipfsBaseUrl: String = "https://ipfs.conet.network/api"
		public var ipfsWriteBaseUrl: String = ""
		public var apiBaseUrl: String = "https://beamio.ca/api"
		public var chatIndexRegistryAddress: String = "0x1511Caa71081C84d8a591490D1b83879088EED72"
		public var chainId: Int = 224422
		public var history: BeamioConetChatHistoryStore?
		/// Local chat library (spec v1.0). Unlocked with the history master; locked on destroy.
		public var localStore: BeamioConetChatLocalStore?
		public var destroyed = false
		/// The app confirms each inbound message with `ackInbound` after it has
		/// stored it. Until then the mailbox keeps its offline copy, so a message
		/// is not lost when the page is starting, suspended or killed.
		public var deferAck = false
		/// armorHash → message waiting for the app's `ackInbound`. Guarded by `pendingLock`.
		var pendingAcks: [String: (plaintext: String, from: String, at: Date)] = [:]
		let pendingLock = NSLock()

		/// a send by its sendId, in this session. In flight: the answers of the retries that wait on it. Done: the answer
		/// it got, kept so that a retry is answered from it and never posted again.
		enum SendState {
			case inFlight([(Bool, [String: Any]?, String?) -> Void])
			case done(Bool, [String: Any]?, String?)
		}

		/// What a send with a sendId finds: it starts, it joins a send in flight, or it is answered from the stored result.
		enum SendJoin {
			case started
			case joined
			case replayed(Bool, [String: Any]?, String?)
		}

		private var sendStates: [String: SendState] = [:]
		private let sendLock = NSLock()

		func joinSend(_ sendId: String, answer: @escaping (Bool, [String: Any]?, String?) -> Void) -> SendJoin {
			sendLock.lock()
			defer { sendLock.unlock() }
			switch sendStates[sendId] {
			case nil:
				sendStates[sendId] = .inFlight([])
				return .started
			case .inFlight(let waiters)?:
				sendStates[sendId] = .inFlight(waiters + [answer])
				return .joined
			case .done(let ok, let result, let error)?:
				return .replayed(ok, result, error)
			}
		}

		/// The request has its answer. `posted`: its POST was made, so the result is kept for the retries. The requests waiting on it get the
		/// same answer, once each.
		func finishSend(_ sendId: String, ok: Bool, result: [String: Any]?, error: String?, posted: Bool) {
			sendLock.lock()
			var waiters: [(Bool, [String: Any]?, String?) -> Void] = []
			if case .inFlight(let w)? = sendStates[sendId] {
				waiters = w
			}
			sendStates[sendId] = posted ? .done(ok, result, error) : nil
			sendLock.unlock()
			for waiter in waiters {
				waiter(ok, result, error)
			}
		}

		/// The request ended silently before any POST (its generation expired): nothing is kept, and a retry starts again.
		func forgetSend(_ sendId: String) {
			sendLock.lock()
			defer { sendLock.unlock() }
			sendStates[sendId] = nil
		}
	}


	private static let lock = NSLock()
	private static var session: Session?
	private static var emit: WebEmit?
	private static let listen = BeamioConetChatListenSession()
	private static var voiceSessions = Set<String>()

	/// Shell hook: sees every module event (messages included) even when no
	/// page is attached, so the shell can act on a caller's cancel natively.
	/// Called on the main queue.
	public static var nativeObserver: WebEmit?

	/// Shell hook: `true` while a call rings or is up. The page's `pause` is
	/// then deferred: the mailbox listen stays connected until the call ends.
	/// Called on the main queue.
	public static var keepListenWhile: (() -> Bool)?

	/// Shell call layer: a verified peer call-control message arrived over Chat
	/// (type, callId, sessionId, recovered signer). Called on the main queue.
	public static var callControlObserver: ((_ type: String, _ callId: String, _ sessionId: String, _ from: String) -> Void)? {
		didSet {
			// a layer that registers after a signal arrived gets the signals that waited, once each.
			if callControlObserver != nil { flushPendingCallSignals() }
		}
	}

	/// A pause is owed once `keepListenWhile` turns false. Main queue only.
	private static var pauseOwed = false
	/// Last listen status was `listening` (connected).
	private static var listenConnected = false
	private static var idleCheckPosted = false
	private static let idleCheckInterval: TimeInterval = 10

	/// The bridge entry of the page: `chatModuleCommand`, dispatched on `cmd.type`.
	/// Every module event comes back through `emit` as `{event: payload}`; the shell wraps it as `{action: "chatModuleEvent", event}`.
	/// The chat channel does not receive the origin, and the SDK does not judge it. The shell verifies the sender of the page before it
	/// calls this entry, and answers `origin_refused` itself when the sender is not allowed.
	public static func chatModuleCommand(_ cmd: [String: Any], emit: @escaping WebEmit) {
		handleCommand(cmd, emit: emit)
	}

	/// Names answered `not_supported` before the no-key gate (spec).
	static let retiredCommands: Set<String> = ["walletTransferOnce", "walletTransferSwitched", "walletTransferStatus"]

	/// Test hook (T-IU5): every name the bridge table knows, for the audit that no command deletes a record or an intent.
	static var commandNamesForAudit: Set<String> { dispatchedCommands.union(retiredCommands) }

	/// The command table of the bridge: every name `handleCommand` dispatches, the retired names, the not-frozen names and the
	/// PGP restore names. A name outside it is `unknown_command`, judged before the gate.
	static let dispatchedCommands: Set<String> = [
		"ackInbound", "clearIdentity", "deriveSubkeys", "destroy", "ephemeralSign", "gossipSign", "hello", "historyAppend",
		"historyClearCache", "historyDeleteConversation", "historyDeleteMessage", "historyFullSync", "historyImportBatch",
		"historyListConversations", "historyLoad", "historyLoadOlder", "historyOpenConversation", "historyRead",
		"historyReportLayout", "historyVerifyImport", "identityPublic", "init", "issueGroupRoster", "issueGroupTombstone",
		"mailboxCommand", "nativeAccountCreateOpen", "nativeRecoveryOpen", "nodesResponse", "ownMailboxCommand",
		"passcodeRun", "passcodeStatus", "pause", "pgpDecryptInbound", "pgpMigrate", "provisionIdentity", "queryNativeWake",
		"queryPresence", "resume", "send", "sendGroup", "setNodes", "setRoutes", "shellRecordRead", "shellRecordWrite", "voiceFrame",
		"voiceListen", "voiceUnlisten", "walletAddress", "walletStatus", "walletTransferStatus",
		"walletTransferSwitched", "chatRouteRegister",
		"voiceEphemeralRegister", "voiceEphemeralSeal", "voiceEphemeralPrepare", "voiceEphemeralForget",
		"passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide",
		"nativeIdentityCheck", "accountCleanupOld", "accountCreateRegister",
	]

	/// The reference table T: the bridge names that the command table knows. Not the spec names
	/// (identity.provision is a spec name). A name in this table is refused by the gate, not as unknown.
	static let noKeyCommandTable: Set<String> = [
		"ackInbound", "chatRouteRegister", "clearIdentity", "deriveSubkeys", "destroy", "ephemeralSign", "gossipSign",
		"hello", "historyAppend", "historyClearCache", "historyDeleteConversation", "historyDeleteMessage", "historyFullSync",
		"historyImportBatch", "historyListConversations", "historyLoad", "historyLoadOlder", "historyOpenConversation", "historyRead",
		"historyReportLayout", "historySign", "historyVerifyImport", "identityPublic", "init", "issueGroupRoster",
		"issueGroupTombstone", "mailboxCommand", "nativeAccountCreateOpen", "nativeRecoveryOpen", "nodesResponse",
		"ownMailboxCommand", "passcodeRun", "passcodeStatus", "pause", "pgpDecryptInbound", "pgpIdentityCreate",
		"pgpMigrate", "pgpRestore", "pgpRestoreEvaluate", "provisionIdentity", "queryNativeWake", "queryPresence",
		"resume", "send", "sendGroup", "setNodes", "setRoutes", "shellRecordRead", "shellRecordWrite", "voiceFrame",
		"voiceListen", "voiceUnlisten", "walletAddress", "walletSendTransaction", "walletSignMessage", "walletSignTypedData",
		"walletSignUserOp", "walletStatus", "walletTransfer", "walletTransferStatus", "walletTransferSwitched",
		"voiceEphemeralRegister", "voiceEphemeralSeal", "voiceEphemeralPrepare", "voiceEphemeralForget",
		"passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide",
		"nativeIdentityCheck",
	]

	/// True when the name is in the command table: dispatched here, in the no-key table, retired, not frozen, or a PGP restore name.
	static func knownBridgeCommand(_ type: String) -> Bool {
		dispatchedCommands.contains(type) || noKeyCommandTable.contains(type) || retiredCommands.contains(type)
			|| BeamioNotFrozenCommands.names.contains(type) || BeamioPGPRestoreCommands.names.contains(type)
			|| statusCommands.contains(type) || historyDeleteCommands.contains(type) || shellGatedCommands.contains(type)
	}

	/// The shell-layer names that the gate state vector gates (`gate-state-vectors.v1.json`, `shellGated`): G0 `no_key`, G1 `not_ready`. They are
	/// known names, so they are not `unknown_command` (step 3).
	/// `saveRecoveryQrToPhotos`, `scanRecoveryQr` and `startPhysicalCardBind` are outer actions (H), not inner commands, and
	/// `cacheCallerAvatars`, `notifyVoiceMicReady`, `queryIncomingCallOutcome` and `startNativeVoiceMic` are Android shell actions that iOS does not
	/// dispatch. None of these names is in this table on iOS: each one is `unknown_command`, exactly once, before the gate.
	/// the 13 outer gated names are not inner commands on iOS either. The inner layer answers `unknown_command`, once, before the
	/// gate, in G0, G1 and G2. The outer shell still answers them (`no_key`, `not_ready`); that is the shell's layer. The set is therefore empty here.
	static let shellGatedCommands: Set<String> = []

	/// The CRED names: 16 names. The single source of the refusal of a
	/// credential field, both in the command check (`credentialFieldNames`) and in the payload check (`identityForbiddenKeys`). They apply to
	/// the identity and PGP commands only.
	static let credentialFieldNames: Set<String> = pageCredentialFields.union([
		"privateKeyArmor", "privateKeyArmorWrap", "encrypKeyArmored", "mnemonicPhrase", "recoveryWords",
		// the bare `passphrase` (the PGP passphrase is typed on the native page).
		"passphrase",
	])

	/// The commands whose credential fields are refused before the gate (step 2; adds pgpMigrate).
	static let credentialCommands: Set<String> = [
		"init", "provisionIdentity", "identity.provision", "pgpRestore", "pgpRestoreEvaluate", "pgpDecryptInbound", "pgpIdentityCreate", "pgpMigrate",
	]

	/// The credential refusal of a command: the leaf paths of the credential fields, in UTF-8 order, and the first field name.
	/// Only the names are returned, never a value. nil when the command has no credential field.
	static func credentialFieldHit(type: String, body: [String: Any]) -> (field: String, paths: [String])? {
		guard credentialCommands.contains(type) else { return nil }
		var paths: [String] = []
		func walk(_ value: Any, _ prefix: String) {
			if let dict = value as? [String: Any] {
				for (key, item) in dict {
					let path = prefix.isEmpty ? key : prefix + "." + key
					if credentialFieldNames.contains(key) { paths.append(path) }
					walk(item, path)
				}
			} else if let array = value as? [Any] {
				for item in array { walk(item, prefix + "[*]") }
			}
		}
		walk(body.filter { $0.key != "type" && $0.key != "reqId" }, "")
		guard !paths.isEmpty else { return nil }
		let sorted = paths.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
		let field = String(sorted[0].split(separator: ".").last ?? "")
		return (field, sorted)
	}

	/// Commands answered in every gate state (spec, step 2): the lifecycle commands. The two
	/// status queries are answered by their own handlers in every state (table D).
	/// `pgpMigrate` judges its own gate, after the key-field refusal (R-02 is answered at G0 too).
	static let gateExemptCommands: Set<String> = [
		"hello", "pause", "resume", "destroy", "nativeRecoveryOpen", "nativeAccountCreateOpen", "pgpMigrate",
		// the shell passcode commands (frozen protocol §12): reachable at G0 and while locked.
		"passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide",
		// the record commands are judged in BeamioShellRecord, for both channels: not_ready at G1, and at G0 the imported
		// copy decides. Other commands keep the gate of.
		"shellRecordRead", "shellRecordWrite",
		// the silent cleanup judges its own gate (v196 section 216, CU-06): a gate that is not passed (no key, not ready, locked) answers not_ready and deletes nothing.
		"accountCleanupOld",
		// accountCreateRegister runs right after nativeAccountCreateOpen, when the device has a native account
		// and no chat session yet (G1). The gate must not answer no_key (G0) or not_ready (G1) for it; the command judges the record account itself and answers
		// not_ready when there is none.
		"accountCreateRegister",
	]
	/// The family commands that a storage-derived Locked answers `not_ready` at G2: C1 to C5, W7, N0 to N4, the PGP decrypt and
	/// the PGP restore and create commands. `chatRouteRegister` (W5 by bridge name) is judged in its own answer path.
	/// E4: an unsettled overwrite marker (rollback_pending) or discard intent (DISCARD_PENDING) is answered like a storage-derived lock: the family
	/// commands answer not_ready once and walletStatus answers not_ready / unreadable. Reads only.
	static func settlementLockPending() -> Bool {
		guard let raw = BeamioNativeWallet.keyStore as? BeamioChatRawItemStoring else { return false }
		return BeamioPwaPhraseOverwrite.settlementLockPending(store: raw)
	}
	static let storageLockedFamilies: Set<String> = [
		"historySign", "gossipSign", "pgpDecryptInbound", "deriveSubkeys", "ephemeralSign", "walletAddress", "walletSignTypedData",
		"walletSignMessage", "walletSendTransaction", "walletTransfer", "walletSignUserOp", "pgpRestoreEvaluate", "pgpRestore", "pgpIdentityCreate",
	]
	static let statusCommands: Set<String> = ["walletStatus", "passcodeStatus"]
	/// The native deletions. They need the session (G2) like `historyOpenConversation`, and a refused origin is not processed.
	static let historyDeleteCommands: Set<String> = ["historyDeleteMessage", "historyDeleteConversation"]
	/// The history reads that a storage-derived Locked answers as a business result: ok, `source` not_ready, no data.
	static let historyReadCommands: Set<String> = ["historyRead", "historyLoad", "historyLoadOlder", "historyListConversations", "historyOpenConversation"]

	/// The gate state of the device (spec). G0: no native key record on the device. G1: a record, and this session
	/// has not completed `init` for the record's account. G2: `init` completed for that account.
	public enum NativeGate: Equatable {
		case g0
		case g1
		case g2
	}

	/// The account whose native record is on this device, when that record is present (the device pointer).
	static func recordAccount() -> String? {
		let account = BeamioNativeAccountPointer.get()
		// The record account is the account of an existing mnemonic record, readable or not (hasRecord reads the mnemonic items only). A private key or
		// an address alone is not a record here: with none, the gate is G0 (no_key), 2026-11-17 startup classification.
		guard !account.isEmpty, BeamioNativeWallet.hasRecord(eoa: account) else { return nil }
		return account
	}

	/// The gate state, read-only (spec). The shell uses this, and nothing of its own, to judge the gate. G2 needs
	/// the session to be ready for the record's account; a session that is not ready, or has been destroyed, is G1.
	public static func nativeGate() -> NativeGate {
		gate(forRecordAccount: recordAccount())
	}

	/// The gate for a record account (nil: no record, G0), with the session's readiness. The snapshot reads this with the account it holds
	/// (25.52Y.70 第 4 項), so the judgement needs no key record read.
	static func gate(forRecordAccount account: String?) -> NativeGate {
		guard let account else { return .g0 }
		if let s = currentSession(), s.ready, s.eoa.lowercased() == account { return .g2 }
		return .g1
	}

	/// `init` in G1 (spec, step 4): the payload EOA must equal the record. A private-key field is left to `init`
	/// itself, which refuses it, so the field check is not repeated here.
	/// The EOA rules of `init` at G1 and G2, before any key is read. nil when the request names the record's account.
	/// A forbidden key is not judged here: handleInit refuses it first. Public fields at the top of the payload, with no identity
	/// object, are missing_identity. An identity object without an EOA, or a payload with no EOA at all, is address_mismatch. An EOA
	/// that is not the canonical lower-case form is bad_identity, and is not compared. Another account is address_mismatch.
	static func initGateRefusal(_ body: [String: Any], account: String) -> String? {
		let payload = (body["payload"] as? [String: Any]) ?? [:]
		if identityForbiddenField(in: payload) != nil { return nil }
		guard let identity = payload["identity"] as? [String: Any] else {
			let topLevel = ["eoa", "eoaAddress", "pgpPublicKeyArmored", "ownRouteArmoredPublicKey"]
			return topLevel.contains(where: { payload[$0] != nil }) ? "missing_identity" : "address_mismatch"
		}
		guard let raw = (identity["eoa"] as? String) ?? (identity["eoaAddress"] as? String) else {
			return "address_mismatch"
		}
		guard let canonical = identityEoa(raw) else { return "bad_identity" }
		return canonical == account ? nil : "address_mismatch"
	}


	/// The gate refusal of a command before dispatch (spec, steps 2 to 4): `no_key` at G0, and `not_ready` at G1 for every command but
	/// `init`. nil when the command goes on to its own checks. The retired, exempt and status sets are never refused here. The record commands are not
	/// exempt: BeamioShellRecord judges them. The answer of a refusal is `{type: "ack", reqId, ok: false, error}`, nothing else.
	static func gateRefusal(type: String, gate: NativeGate) -> String? {
		guard !retiredCommands.contains(type), !gateExemptCommands.contains(type), !statusCommands.contains(type) else { return nil }
		// 第 3a 项 (fallback (a)): with the marker clear_pending set, the G0 clearIdentity is the redo of an interrupted clear.
		// The primary path (automatic redo at process start, (c)) is not implemented yet, so this fallback is the only redo route for now.
		// The vectors G0-CLR-PENDING and G1-CLR-PENDING answer ok: with the marker set, clearIdentity is the redo at G0 and G1.
		if gate == .g0 || gate == .g1, type == "clearIdentity", BeamioNativeClearPending.isSet() { return nil }
		if gate == .g0 { return "no_key" }
		// walletCredential is available at G1 and G2 (第 4 項 (d);): its own checks answer the rest.
		if gate == .g1, type != "init", type != "walletCredential" { return "not_ready" }
		return nil
	}

	/// The gate answers echo any valid reqId, a string too (the vectors of use string ids). An invalid one
	/// is not answered, as before.
	/// `not_ready` for a command that the gate would have answered no_key, because the key store could not be read: `notReadyReason` unreadable, the cause as a
	/// category only, and `retryable` by cause (only device_locked can end by itself).
	private static func unreadableNotReadyAck(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		let cause = BeamioNativeKeySnapshot.current()?.unreadableCause ?? BeamioKeychainFailureNote.other
		var ack = BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready")
		ack["notReadyReason"] = BeamioShellRecord.notReadyUnreadable
		ack["unreadableCause"] = cause
		ack["retryable"] = BeamioKeychainFailureNote.retryable(cause)
		emitEvent(ack)
	}

	private static func gateAck(_ body: [String: Any], error: String, reason: String? = nil) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		var envelope = BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: error)
		if let reason { envelope["reason"] = reason }
		emitEvent(envelope)
	}

	/// The P-IMP-PGP commands, see BeamioPGPRestoreCommands. Checks first (key fields, observedVersion, the
	/// account, the lock), then the evaluation, which reads the chain on a background queue. An invalid reqId is `bad_request`.
	private static func pgpRestoreCommand(_ body: [String: Any], type: String) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		let refused = BeamioPGPRestoreCommands.refusal(type: type, body: body)
		if refused != "not_supported" {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: refused))
			return
		}
		let account = recordAccount() ?? ""
		guard !account.isEmpty, (body["accountKey"] as? String)?.lowercased() == account + ":default" else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "account_mismatch"))
			return
		}
		// The request shape comes first: without an idempotency key the command is bad_request, whatever the local state.
		if type == "pgpIdentityCreate", !((body["idempotencyKey"] as? String) ?? "").isEmpty,
		   BeamioPGPRestoreCommands.isClass4LocalState(eoa: account) {
			// spec: the explicit replacement of class 4 is not implemented on iOS. Nothing is prepared, written or deleted.
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_supported"))
			return
		}
		if type == "pgpIdentityCreate" {
			// Prepare reads the chain once; the ack carries the mode only. The confirmation is native (userConfirmed).
			let key = body["idempotencyKey"] as? String ?? ""
			// a repeat of the key in the in-flight window is answered without prepare, and nothing else changes.
			if case .inFlightDuplicate(let mode)? = BeamioPGPIdentityCreate.inFlightAnswer(eoa: account, idempotencyKey: key) {
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["accepted": true, "mode": mode.rawValue], error: nil))
				emitEvent(["type": "pgpIdentityCreateResult", "reqId": echo, "code": "idempotent"])
				return
			}
			// item 4: while the device marker is set, the creation ends before any key is generated: one result event,
			// `not_ready` with state `undetermined`, terminal. Nothing is prepared, generated or written, and the identity-create slot is not taken.
			if BeamioShellRecord.productionDevice.load().legacyUnreadable {
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["accepted": false], error: nil))
				emitEvent(["type": "pgpIdentityCreateResult", "reqId": echo, "code": "not_ready", "state": "undetermined"])
				return
			}
			DispatchQueue.global(qos: .userInitiated).async {
				let outcome = BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: key)
				DispatchQueue.main.async {
					switch outcome {
					case .ready(let mode):
						identityCreateReqId = echo
						emitEvent(BeamioChatRouteRegister.ackEnvelope(
							reqId: echo, result: ["accepted": true, "mode": mode.rawValue], error: nil
						))
					case .inFlightDuplicate(let mode):
						// the first confirmation is still open. The repeat is accepted with the first mode and gets one `idempotent`
						// result under its own reqId. The identity-create reqId slot is not touched, and no panel is shown for the repeat.
						emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["accepted": true, "mode": mode.rawValue], error: nil))
						emitEvent(["type": "pgpIdentityCreateResult", "reqId": echo, "code": "idempotent"])
					case .failed(let code):
						emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: code))
					}
				}
			}
			return
		}
		if type == "pgpRestore" {
			// the ack `accepted` once the gate and the parameters have passed and execution starts, before the chain read and
			// before any local write. It is sent exactly once and never earlier. A lock after it gives one `cancelled` result.
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["accepted": true], error: nil))
		}
		DispatchQueue.global(qos: .userInitiated).async {
			// One read of the configured endpoint serves the evaluation and the `chain` field (frozen protocol §13).
			var chainField: AddressPGPChain.ChainStatus = .unknown
			let evaluation: BeamioPGPRestoreCommands.Evaluation
			if case .success(let snapshot) = AddressPGPChain.read(eoa: account) {
				evaluation = BeamioPGPRestoreCommands.evaluate(eoa: account, snapshot: snapshot)
				chainField = AddressPGPChain.chainStatus(from: snapshot)
			} else {
				evaluation = BeamioPGPRestoreCommands.retry()
			}
			if type == "pgpRestoreEvaluate" {
				// `legacy` and `chain` (frozen protocol §13): judged natively, an unreadable source is never ABSENT / unregistered.
				var result = BeamioPGPRestoreCommands.evaluationResult(evaluation)
				result["legacy"] = BeamioFirstIdentity.legacy(eoa: account).rawValue
				result["chain"] = chainField.rawValue
				DispatchQueue.main.async {
					emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: result, error: nil))
				}
				return
			}
			// a lock found after `accepted` and before anything is written: one result `cancelled`, no data, nothing written (vector C-28)
			if BeamioPasscodeSession.shared.isLocked(eoa: account) {
				DispatchQueue.main.async { emitEvent(["type": "pgpRestoreResult", "reqId": echo, "code": "cancelled"]) }
				return
			}
			// no record and no backup. `accepted` was already sent, so the answer is the result event
			// (`no_identity_yet`, state and code alike), not an ack.
			if evaluation.state == "first_identity" {
				DispatchQueue.main.async { emitEvent(["type": "pgpRestoreResult", "reqId": echo, "code": "no_identity_yet", "state": "no_identity_yet"]) }
				return
			}
			let outcome: (code: String, state: String)
			if evaluation.state == "ok" {
				// the lock is judged again right before the save, inside writeLocal.
				outcome = BeamioPGPRestoreCommands.writeLocal(
					eoa: account, evaluation: evaluation, stillUnlocked: { !BeamioPasscodeSession.shared.isLocked(eoa: account) }
				)
			} else {
				outcome = (evaluation.code ?? "pgp_source_unavailable", evaluation.state)
			}
			if outcome.code == "cancelled" {
				// a lock before the local write: one result event, `cancelled`, no data (the same shape as the vector row C-28).
				DispatchQueue.main.async { emitEvent(["type": "pgpRestoreResult", "reqId": echo, "code": "cancelled"]) }
				return
			}
			var event: [String: Any] = ["type": "pgpRestoreResult", "reqId": echo, "code": outcome.code, "state": outcome.state]
			if outcome.state != "ok" {
				event["failureClass"] = evaluation.failureClass ?? NSNull()
				event["uiKey"] = evaluation.uiKey ?? NSNull()
			}
			// `accepted` was sent before the read. The result is the only event here.
			DispatchQueue.main.async { emitEvent(event) }
		}
	}

	/// Entry for the page commands `shellRecordRead` and `shellRecordWrite`. The shell calls it after its own origin
	/// check (main frame, embedded page). The answer is one `shellRecordResult` event.
	/// `rawByteCount` is the size of the request as the shell received it; without it the size is taken from the
	/// re-serialized request.
	public static func handleShellRecordCommand(_ body: [String: Any], originAllowed: Bool, rawByteCount: Int? = nil) {
		// a refused origin is not processed and gets no reply.
		guard let answer = BeamioShellRecord.handle(body, originAllowed: originAllowed, rawByteCount: rawByteCount) else { return }
		emitShellRecord(answer)
	}


	/// Emits a shell-record answer. The WebView receives the full answer, W-class fields included. The native observer
	/// receives the answer without them, and nothing about them is logged.
	/// The shell-record answer for the window entry. The origin is the shell's judgement, passed in as trusted by the caller: the
	/// record boundary runs with `originAllowed: true` here. nil when the boundary gives no answer.
	static func shellRecordWindowAnswer(_ body: [String: Any]) -> [String: Any]? {
		BeamioShellRecord.handle(body, originAllowed: true)
	}

	private static func emitShellRecord(_ answer: [String: Any]) {
		let event = BeamioShellRecord.ackEnvelope(for: answer)
		let full: [String: Any] = ["action": "chatModuleEvent", "event": event]
		let observed: [String: Any] = ["action": "chatModuleEvent", "event": BeamioShellRecord.observerEnvelope(event)]
		DispatchQueue.main.async {
			nativeObserver?(observed)
			emit?(full)
		}
	}

	#if DEBUG
	/// Test seam: replaces the production environment of `pgpMigrate`. A Release build has no such
	/// variable, so nothing in the shipped binary can replace the environment.
	static var pgpMigrationEnvironmentOverride: BeamioPgpMigrationImport.Environment?
	#endif

	/// `pgpMigrate`: the native PGP migration import of the device account. The request carries only `type` and
	/// `reqId`. Refusals come first (reqId, key fields, unknown fields), then the gate, the lock and the run. The run is native and
	/// on a background queue, and it answers with one `pgpMigrateResult` event. Nothing about the key leaves here.
	private static func pgpMigrateCommand(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		let fields = Set(body.keys)
		let forbidden = fields.intersection(BeamioPgpMigrationImport.forbiddenRequestFields)
		if !forbidden.isEmpty {
			// Field names only, never values.
			NSLog("[BeamioConetChat] pgpMigrate refused: private material in fields %@", forbidden.sorted().joined(separator: ","))
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "key_over_bridge_refused"))
			return
		}
		guard fields.isSubset(of: BeamioPgpMigrationImport.allowedRequestFields) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request"))
			return
		}
		switch nativeGate() {
		case .g0:
			// an unreadable key store is not "no key"
			if BeamioNativeKeySnapshot.current()?.unreadable == true { unreadableNotReadyAck(body); return }
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "no_key"))
			return
		case .g1:
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
			return
		case .g2:
			break
		}
		guard let account = recordAccount() else {
			// beyond the G0 ruling, on the safe side: at G2 with no record account the store may be unreadable; no_key would say "no key" falsely
			if BeamioNativeKeySnapshot.current()?.unreadable == true { unreadableNotReadyAck(body); return }
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "no_key"))
			return
		}
		#if DEBUG
		let environment = pgpMigrationEnvironmentOverride ?? BeamioPgpMigrationImport.production
		#else
		let environment = BeamioPgpMigrationImport.production
		#endif
		DispatchQueue.global(qos: .userInitiated).async {
			let outcome = BeamioPgpMigrationImport.runInternal(
				eoa: account, workspace: BeamioChatPgpKeychain.defaultWorkspace, env: environment
			)
			DispatchQueue.main.async {
				if outcome.code == "busy" {
					emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "busy"))
					return
				}
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["accepted": true], error: nil))
				guard !outcome.interrupted else { return }
				var event: [String: Any] = ["type": "pgpMigrateResult", "reqId": echo, "code": outcome.code]
				event["fp"] = outcome.fp ?? NSNull()
				emitEvent(event)
			}
		}
	}

	/// The reqId of the pgpIdentityCreate command that is prepared (events carry it). Set on a ready prepare.
	static var identityCreateReqId: Any?

	private static let createRegisterLock = NSLock()
	private static var createRegisterRunning: Set<String> = []

	/// `accountCreateRegister {type, reqId, tag, password}` (new-account registration protocol v1): the registration payload of a new account (the BeamioTag and the recover
	/// records), signed and sealed here; the page only forwards it to /addUser. The answer is `result {accountName, wallet, signMessage, recover, recoverCodeBase58}`, or an error code
	/// of the table: bad_request, bad_tag, bad_password, tag_taken, sign_failed, seal_failed, not_ready, in_flight, not_available. The password stays in memory for this call, and the
	/// request is never logged beyond its lengths.
	private static func createRegisterRefuse(_ echo: Any, _ code: String) {
		emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: code))
	}

	private static func accountCreateRegister(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		// not enabled in this build: nothing else is looked at
		guard BeamioNewAccountFeature.registerEnabled else { return createRegisterRefuse(echo, "not_available") }
		guard Set(body.keys) == ["type", "reqId", "tag", "password"], let tag = body["tag"] as? String, let password = body["password"] as? String else { return createRegisterRefuse(echo, "bad_request") }
		// The account is the device's native record account (the one nativeAccountCreateOpen made), not the chat session's signer: the session does not exist yet
		// at this step (G1). With no record account nothing is read and nothing is made: not_ready.
		guard let recordAccount = recordAccount() else { return createRegisterRefuse(echo, "not_ready") }
		let account = recordAccount.lowercased()
		guard !BeamioPasscodeSession.shared.isLocked(eoa: account) else { return createRegisterRefuse(echo, "not_ready") }
		createRegisterLock.lock()
		let started = createRegisterRunning.insert(account).inserted
		createRegisterLock.unlock()
		guard started else { return createRegisterRefuse(echo, "in_flight") }
		DispatchQueue.global(qos: .userInitiated).async {
			let outcome = BeamioAccountRegisterPayload.make(tag: tag, password: password, eoa: account)
			createRegisterLock.lock(); createRegisterRunning.remove(account); createRegisterLock.unlock()
			DispatchQueue.main.async {
				switch outcome {
				case .success(let result): emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: result, error: nil))
				case .failure(let failure):
					// The failure code goes to the page as it is. `already_registered` is in the code table: the registry names this account as the owner
					// of the tag, so the page does not call addUser and shows no recover code; it is not `tag_taken` (another owner) and not `not_ready` (a registry that could not be read).
					emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: failure.code))
				}
			}
		}
	}

	/// The state of the first-identity registration (`firstIdentityStatus`, new-account registration protocol v1): `state` of registering, registered, retry_later, identity_pending,
	/// failed; the optional `reason` of no_record_confirmed, read_unavailable, submit_5xx, submit_4xx, conflict_other_key, readback_timeout; the optional `attempt` and `retryAfterMs`.
	/// Only these five keys, and nothing about a key, an armor, a fingerprint, a signature, a tag or a password. QA build only.
	static func emitFirstIdentityStatus(state: String, reason: String? = nil, attempt: Int? = nil, retryAfterMs: Int? = nil) {
		var event: [String: Any] = ["type": "firstIdentityStatus", "state": state]
		if let reason { event["reason"] = reason }
		if let attempt { event["attempt"] = attempt }
		if let retryAfterMs { event["retryAfterMs"] = retryAfterMs }
		#if BEAMIO_QA_BUILD
		emitEvent(event)
		#endif
		#if BEAMIO_TEST_HOOKS
		firstIdentityStatusForTests.append(event)
		#endif
	}

	#if BEAMIO_TEST_HOOKS
	static var firstIdentityStatusForTests: [[String: Any]] = []
	#endif

	/// The one `pgpIdentityCreateResult` for the prepared command. Nil code: no event.
	static func emitIdentityCreateResult(code: String?) {
		guard let code, let reqId = identityCreateReqId else { return }
		identityCreateReqId = nil
		var event: [String: Any] = ["type": "pgpIdentityCreateResult", "reqId": reqId, "code": code]
		if let state = identityCreateResultState(code: code) { event["state"] = state }
		emitEvent(event)
	}

	/// The state that a `pgpIdentityCreateResult` carries: only the codes that the spec names (already_exists is `ok`, not_ready is `undetermined`,
	/// no_identity_yet). Every other code carries none (retry_write and write_reverted included).
	static func identityCreateResultState(code: String) -> String? {
		switch code {
		case "already_exists": return "ok"
		case "not_ready": return "undetermined"
		case "no_identity_yet": return "no_identity_yet"
		default: return nil
		}
	}

	/// `pgpDecryptInbound`: the native decrypt of an inbound line. An invalid reqId is answered with `null`.
	private static func pgpDecryptInbound(_ body: [String: Any]) {
		// an invalid reqId is refused with bad_request and a null reqId, before anything else is read.
		guard let validEcho = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		let echo: Any = validEcho
		let account = recordAccount() ?? ""
		var subkey: String?
		if !account.isEmpty, let kc = BeamioChatPgpKeychain.load(eoa: account), kc.hasUserPrivate, !kc.publicKeyArmor.isEmpty {
			subkey = BeamioPGPBackup.keyIdentity(armor: kc.publicKeyArmor)?.subkeyKeyID
		}
		let context = BeamioPGPInbound.Context(
			unlockedAccountKey: account.isEmpty ? nil : account + ":default",
			locked: false,
			subkeyKeyID: subkey,
			nativeAvailable: BeamioPGPNative.linked,
			decrypt: { data in BeamioNativeWallet.pgpDecrypt(eoa: account, message: data) }
		)
		switch BeamioPGPInbound.run(body, context: context) {
		case .ok(let plaintext, let signal, _):
			let sig: Any = signal.map { $0 as [String: Any] } ?? NSNull()
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["plaintext": plaintext, "signal": sig], error: nil))
		case .error(let code):
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: code))
		}
	}

	/// Test hook only (not called by the app): sets the device record account and whether this session has completed `init`.
	static func setNativeGateForTests(account: String?, sessionReady: Bool) {
		accountCreateLock.lock()
		finishedAccountCreateKeys.removeAll()
		accountCreateLock.unlock()
		if let account { BeamioNativeAccountPointer.set(account) } else { BeamioNativeAccountPointer.clear() }
		lock.lock()
		if let account, sessionReady {
			let s = Session()
			s.eoa = account.lowercased()
			s.ready = true
			session = s
		} else {
			session = nil
		}
		lock.unlock()
	}

	/// The shell calls this when it starts (第 42(2) 项): the native store is read on a background queue, and the PWA's preread answers
	/// `unknown` until that read is published. A write moves the epoch on, so an older read is dropped (第 49(2) 项).
	public static func startPrereadAtShellStart() {
		BeamioPwaPreread.startAsync(snapshotKnown: BeamioNativeKeySnapshot.isKnown,
		                            storageLocked: BeamioNativeKeySnapshot.current()?.storageLock != nil,
		                            store: BeamioNativeWallet.keyStore)
	}

	public static func handleCommand(_ body: [String: Any], emit: @escaping WebEmit) {
		self.emit = emit
		// 25.52Y.70 第 4 項 (takeover item 1): the session start establishes the native-key snapshot if it is unknown. With it unknown, the command
		// is answered here: nothing is read from the store, nothing is written, and the startup steps below do not run.
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		let snapshotUnknown = !BeamioNativeKeySnapshot.isKnown
		// r2.5.17 (step 3, 第 48(5) 项, 第 58 项): the PWA sync commands and the preread are answered on their own lifecycle route, before the gate.
		if BeamioPwaWalletSync.commands.contains(String(body["type"] as? String ?? "")) {
			let known = BeamioNativeKeySnapshot.isKnown
			let locked = BeamioNativeKeySnapshot.current()?.storageLock != nil
			// iOS review 2026-11-17, condition 1: a pwaEmptySignal's discard gate receives the seq of the native reading taken now. A reading that cannot be
			// taken gives nil, and the discard is refused.
			let isEmptySignal = String(body["type"] as? String ?? "") == BeamioPwaWalletSync.emptySignalCommand
			let readSeq = isEmptySignal
				? BeamioPwaWalletSync.snapshotReadSeq(body: body, snapshotKnown: known, storageLocked: locked, store: BeamioNativeWallet.keyStore)
				: nil
			let syncAnswer = BeamioPwaWalletSync.answer(body, snapshotKnown: known, storageLocked: locked, nativeReadSeq: readSeq)
#if BEAMIO_QA_BUILD
			if String(body["type"] as? String ?? "") == BeamioPwaWalletSync.prereadCommand {
				let line = qaPrereadLine(reqId: BeamioShellRecord.echoedReqId(body), snapshotKnown: known, storageLocked: locked, envelope: syncAnswer)
				NSLog("[BeamioQAPreread] %@", line)
				qaStateSink?("\(ISO8601DateFormatter().string(from: Date())) [BeamioQAPreread] \(line)")
			}
#endif
			emitEvent(syncAnswer)
			return
		}
		// The shell passcode commands (frozen protocol §12) are answered on their own route: no gate, no key-state refusal, and the account lock
		// does not stop them (they are the way to unlock, to set and to repair). Their own field set and reqId range are checked inside.
		if BeamioShellPasscodeCommands.names.contains(String(body["type"] as? String ?? "")) {
			// Reachable at G0 and while locked only. At G1 (a session start in progress, the account not established) the five commands answer not_ready;
			// passcodeStatus keeps its read-only answer at G1 (frozen protocol §12; vector G1-NK-S2).
			if nativeGate() == .g1 {
				let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) ?? NSNull()
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
				return
			}
			BeamioShellPasscodeCommands.handle(body) { emitEvent($0) }
			return
		}
		// 25.52Y.70, Y.75, Y.83 and Y.88 (takeover): with the snapshot unknown or a storage-derived lock, each command is answered by its class.
		// E5.1-1: a PHRASE_ONLY residue (pointer set, key record absent, phrase readable) answers the family commands not_ready, once. walletStatus keeps its
		// own answer (locked with phrase_only in a ready session, G1 form otherwise).
		if storageLockedFamilies.contains(String(body["type"] as? String ?? "")), BeamioPwaWalletSync.phraseOnlyResidueEOA(store: BeamioNativeWallet.keyStore) != nil,
		   let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
			return
		}
		if snapshotUnknown || BeamioNativeKeySnapshot.current()?.storageLock != nil || settlementLockPending() {
			if answerKeyStateRefusal(body, snapshotUnknown: snapshotUnknown) { return }
		}
		// §25.52PY.8 第 7 項: the startup redo runs once, before the first command, when an interrupted clear left copies behind.
		runStartupClearRedoOnce()
		if clearRedoBlocks(type: String(body["type"] as? String ?? "")), let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
			return
		}
		// (c): the start-up reconciliation of the import intents runs before any command reads a record (once per process).
		BeamioNativeKeyImport.reconcileOnceAtStart()
		// 第 59(3)(e)(7) 项: a marker of an interrupted PWA overwrite is settled once per process, before any record is read.
		BeamioPwaPhraseOverwrite.settleOnceAtStart()
		let type = String(body["type"] as? String ?? "")
		if type == "chatRouteRegister" {
			// Own answer path: the reqId may be a string, and the gate is judged inside.
			chatRouteRegister(body)
			return
		}
		if type.hasPrefix("shellRecord") {
			// (iOS fallback),,: the shell has verified the sender before this call. shellRecordRead and shellRecordWrite are
			// answered by the record, with no gate and no envelope of this module. Any other shellRecord* name falls through to the
			// unknown-name answer below.
			if type == "shellRecordRead" || type == "shellRecordWrite" {
				handleShellRecordCommand(body, originAllowed: true)
				return
			}
		}
		// The order of judgment: the envelope, then the credential fields, then the command name, then the gate, then the
		// parameters, then execution. A missing or invalid reqId is answered bad_request with reqId null (T-179); the integer 0 is valid.
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		if let stray = BeamioShellPasscodeCommands.strayCredentialField(type: type, body: body) {
			// only the six passcode commands may carry phrase / passcode / oldPasscode / newPasscode (frozen protocol §1.6). Names only.
			emitEvent(["type": "ack", "reqId": echo, "ok": false, "error": "key_over_bridge_refused", "field": stray])
			return
		}
		if let hit = credentialFieldHit(type: type, body: body) {
			// the names sit in the ack's result (leaf paths). `field` is kept at the top for the identity vectors.
			NSLog("[BeamioConetChat] %@ refused: a credential field came over the bridge", type)
			emitEvent([
				"type": "ack", "reqId": echo, "ok": false, "error": "key_over_bridge_refused",
				"field": hit.field, "result": ["names": hit.paths],
			])
			return
		}
		// A name outside the command table is unknown_command in every gate state, before the gate.
		guard knownBridgeCommand(type) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "unknown_command"))
			return
		}
		if !retiredCommands.contains(type), !gateExemptCommands.contains(type), !statusCommands.contains(type) {
			// A private-key-only account (no phrase) cannot clear its identity or log out on this device: recognised BEFORE the gate and before clear_pending, so the answer is the
			// one the spec wants, `{ok:false, error:unregister_refused, reason:key_only}`, not the gate's no_key (project owner's requirement, spec 25.52PY.14 item 4 (c);
			// Android does the same). Nothing is deleted, shown or exported. The other commands keep their gate behaviour.
			// The key-only precheck depends on clear_pending, read strictly and bound to its accounts: not set, or set for another account -> a new clear of a key-only
			// account is refused; set for this account -> the redo of the clear that began goes on (a half-cleared account must never be trapped); set with no readable owner record or
			// a marker that cannot be read -> nothing is redone and nothing is deleted.
			if type == "clearIdentity" {
				switch BeamioNativeClearPending.read() {
				case .unreadable:
					gateAck(body, error: "unregister_refused")
					return
				case .set:
					guard case .list(let recorded) = BeamioNativeClearPending.owners() else {
						gateAck(body, error: "clear_incomplete")
						return
					}
					let current = clearOwners(signer: BeamioConetChatSignBroker.currentSignerEoa())
					if !current.allSatisfy({ recorded.contains($0) }), clearIdentityIsKeyOnly() {
						gateAck(body, error: "unregister_refused", reason: "key_only")
						return
					}
				case .unset:
					// P3 (G0 plan B GB-P3b; Android keyOnlyClearRefusedAt): the one state where the gate already answers no_key and nothing could be deleted is not refused as key-only:
					// no current account, no clear_pending marker (read strictly above), the identity_cleared marker strictly read as set AND nothing on the device but the published key-only copies that\n					// marker still ignores (no account wallet, no locked wallet, no readable-failure copy). Any other state, an unreadable marker included, is refused or not_ready.
					let noCurrentAccount = clearOwners(signer: BeamioConetChatSignBroker.currentSignerEoa()).isEmpty
					let clearedStrict = BeamioIdentityCleared.p3ExemptionHolds(store: BeamioNativeWallet.keyStore)
					if clearIdentityIsKeyOnly(), !(noCurrentAccount && clearedStrict) {
						gateAck(body, error: "unregister_refused", reason: "key_only")
						return
					}
				}
			}
			// spec: judged before dispatch and before the payload is read (T-155, T-160).
			let gate = nativeGate()
			// 25.52Y.90: the G0 answer of identityPublic carries kPresent when the capability pair is declared.
			// (1): a key store that cannot be read is not "no key". At G0, with a snapshot that judged the store unreadable
			// (-34018, -25308, an enumeration that failed), a command that would answer no_key answers not_ready instead, with the reason and whether a retry can help.
			// method Y: the account behind a v3 envelope answers its own address (or `not_ready` while it is locked), never the gate's `no_key`
			if type == "walletAddress", cipherAccountOfDevice() != nil {
				walletAddress(body)
				return
			}
			if gate == .g0, BeamioNativeKeySnapshot.current()?.unreadable == true, gateRefusal(type: type, gate: gate) == "no_key" {
				unreadableNotReadyAck(body)
				return
			}
			if gate == .g0, type == "identityPublic" {
				if let answer = identityPublicNoKeyAnswer(body) { emitEvent(answer) }
				return
			}
			if let refusal = gateRefusal(type: type, gate: gate) {
				gateAck(body, error: refusal)
				return
			}
			// the SDK keeps no application-level lock and no UI-lock rule: a valid command of the trusted UI is not refused `locked` and not
			// held back by a UI lock or by "never unlocked in this cold start". The one real state left is that the account's passcode record has no
			// bundle in memory (the passcode was not provided): nothing that needs the key can succeed, and the answer says so, as `not_ready` with the reason
			// `passcode_not_provided` (retryable once the UI provides the passcode), never as `locked` or no key. A record that cannot be read at all is
			// `unknown` in `appState` and is reported by the command's own check.
			if gate == .g2, let account = recordAccount(), BeamioPasscodeSession.shared.appState(eoa: account) == .locked {
				gateAck(body, error: "not_ready", reason: "passcode_not_provided")
				return
			}
			// at G2 the family commands answer not_ready, once, when the key record exists and cannot be read (before the parameters).
			if gate == .g2, storageLockedFamilies.contains(type), let account = recordAccount(),
			   BeamioNativeWallet.keyStore.keyRecordState(eoa: account) == .unreadable {
				gateAck(body, error: "not_ready")
				return
			}
			// at G2 a storage-derived Locked answers each history read `{ok:true, result:{source:"not_ready"}}`, once, with no
			// data and before the parameters. The page reads `source`, not `ok`.
			if gate == .g2, historyReadCommands.contains(type), let account = recordAccount(),
			   BeamioNativeWallet.keyStore.keyRecordState(eoa: account) == .unreadable {
				if let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) {
					emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["source": "not_ready"], error: nil))
				}
				return
			}
			// init at G1 and G2 is judged on its EOA before any key is read.
			// A stored record that cannot be read answers not_ready at G2 (the storage-derived Locked state).
			if type == "init", gate == .g1 || gate == .g2, let account = recordAccount() {
				if gate == .g2, BeamioNativeWallet.storageDerivedLocked(eoa: account) {
					gateAck(body, error: "not_ready")
					return
				}
				if let refusal = initGateRefusal(body, account: account) {
					gateAck(body, error: refusal)
					return
				}
			}
		}
		switch type {
		case "hello":
			// the first moment of a start: an owed erase of a temporary key is tried again (r2x s3)
			BeamioPGPIdentityCreate.retryCleanupAtStart()
			// Protocol v1: version + capabilities (see BeamioConetChatProtocol).
			ack(body["reqId"] as? Int ?? 0, ok: true, result: BeamioConetChatProtocol.helloResult())
		case "init":
			BeamioOpenPgpHost.shared.prewarm()
			BeamioPGPIdentityCreate.retryCleanupAtStart()
			handleInit(body, capabilities: BeamioConetChatProtocol.capabilities)
		case "setRoutes":
			handleSetRoutes(body)
		case "setNodes":
			handleSetNodes(body)
		case "nodesResponse":
			break
		case "send":
			handleSend(body)
		case "sendGroup":
			handleSendGroup(body)
		case "issueGroupRoster":
			handleIssueGroupRoster(body)
		case "issueGroupTombstone":
			handleIssueGroupTombstone(body)
		case "queryPresence":
			handleQueryPresence(body)
		case "queryNativeWake":
			handleQueryNativeWake(body)
		case "historyLoad":
			handleHistoryLoad(body)
		case "historyRead":
			handleHistoryRead(body)
		case "historyAppend":
			handleHistoryAppend(body)
		case "historyOpenConversation":
			handleHistoryOpenConversation(body)
		case "historyListConversations":
			handleHistoryListConversations(body)
		case "historyLoadOlder":
			handleHistoryLoadOlder(body)
		case "historyReportLayout":
			handleHistoryReportLayout(body)
		case "historyClearCache":
			handleHistoryClearCache(body)
		case "historyFullSync":
			handleHistoryFullSync(body)
		case "historyImportBatch":
			handleHistoryImportBatch(body)
		case "historyVerifyImport":
			handleHistoryVerifyImport(body)
		case "mailboxCommand":
			handleMailboxCommand(body)
		case "ownMailboxCommand":
			handleOwnMailboxCommand(body)
		case "voiceFrame":
			handleVoiceFrame(body)
		case "voiceListen":
			handleVoiceListen(body)
		case "voiceUnlisten":
			handleVoiceUnlisten(body)
		case "pause":
			DispatchQueue.main.async { requestPause() }
		case "ackInbound":
			handleAckInbound(body)
		case "resume":
			DispatchQueue.main.async {
				// The shell reported the app in the background: the page (or a
				// wake event it got) does not reopen the listen there.
				guard BeamioListenPolicy.pageResumeApplies(
					lifecycleKnown: lifecycleKnown,
					inForeground: appInForeground,
					callInProgress: keepListenWhile?() == true
				) else {
					NSLog("[BeamioConetChat] page resume ignored: app in the background")
					return
				}
				pauseOwed = false
				resumeListen()
			}
		case "destroy":
			destroy()
		case "clearIdentity":
			clearIdentity(reqId: body["reqId"] as? Int ?? -1)
		case "walletTransferOnce", "walletTransferSwitched", "walletTransferStatus":
			// X-21 is retired (spec): not_supported, no state change, no bytes.
			x21Retired(body)
		case "nativeAccountCreateOpen":
			nativeAccountCreateOpen(body)
		case "nativeRecoveryOpen":
			nativeRecoveryOpen(body)
		case "nativeIdentityCheck":
			// 2.6, v41 s45.5: judged by the gate like any other command (locked answers `locked`), then a yes or no
			BeamioShellPasscodeCommands.handle(body) { emitEvent($0) }
		case "walletStatus":
			walletStatus(body)
		case "walletAddress":
			walletAddress(body)
		// `walletCredential` is not in the command table. The handler is kept for
		// the tests of W-L5 and W-L6 (`walletCredentialForTests`), and is not reachable from the bridge.
		case "gossipSign":
			gossipSign(body)
		case "pgpDecryptInbound":
			pgpDecryptInbound(body)
		case "pgpMigrate":
			pgpMigrateCommand(body)
		case "pgpUpgradeRetry":
			pgpUpgradeRetry(body)
		case "historyDeleteMessage":
			historyDeleteMessage(body)
		case "historyDeleteConversation":
			historyDeleteConversation(body)
		case _ where BeamioPGPRestoreCommands.names.contains(type):
			pgpRestoreCommand(body, type: type)
		case "accountCleanupOld":
			accountCleanupOld(body)
		case "accountCreateRegister":
			accountCreateRegister(body)
		case "passcodeStatus":
			passcodeStatus(body)
		case "passcodeRun":
			passcodeRun(body)
		case "provisionIdentity":
			provisionIdentity(body)
		case "identityPublic":
			identityPublic(body)
		case "deriveSubkeys":
			deriveSubkeys(body)
		case "ephemeralSign":
			ephemeralSign(body)
		case "voiceEphemeralRegister":
			voiceEphemeralRegister(body)
		case "voiceEphemeralSeal":
			voiceEphemeralSeal(body)
		case "voiceEphemeralPrepare":
			voiceEphemeralPrepare(body)
		case "voiceEphemeralForget":
			voiceEphemeralForget(body)
		case _ where BeamioNotFrozenCommands.names.contains(type):
			// Stubs for commands whose spec or registry is not frozen. Gate first, then refusal.
			ack(body["reqId"] as? Int ?? -1, ok: false, error: BeamioNotFrozenCommands.refusal(type: type, body: body))
		default:
			NSLog("[BeamioConetChat] unknown command %@", type)
			// Protocol v1: a command that expects an answer gets one.
			if let reqId = body["reqId"] as? Int, reqId > 0 {
				ack(reqId, ok: false, error: "unknown_command")
			}
		}
	}

	// MARK: - Init / routes / nodes

#if BEAMIO_TEST_HOOKS
	/// Test hook only: `init` with a given hello list. Not compiled into a release or store build.
	static func testHandleInit(_ body: [String: Any], capabilities: [String]) {
		handleInit(body, capabilities: capabilities)
	}
#endif

	/// The nodes already stored in the Keychain for this account: the account's record, else the device roster.
	private static func keychainSiNodes(owner: String) -> [Node] {
		let record = BeamioChatPgpKeychain.load(eoa: owner)?.siNodes ?? []
		let roster = record.isEmpty ? BeamioChatPgpKeychain.loadSiNodes() : record
		return roster.map { Node(ip: $0.ip, domain: $0.domain, region: $0.region, armoredPublicKey: $0.armoredPublicKey) }
	}

	/// `init`. The hello list is the shipped list (`BeamioConetChatProtocol.capabilities`). A test runs the capability
	/// branch with another list through `testHandleInit`.
	private static func handleInit(_ body: [String: Any], capabilities: [String]) {
		let reqId = body["reqId"] as? Int ?? 0
		let initStarted = Date()
		initStageLog(reqId, "start", "entered")
		guard let payload = body["payload"] as? [String: Any] else {
			initStageLog(reqId, "payload", "exit=missing_payload")
			initAnswerLog(reqId, ok: false, code: "missing_payload", since: initStarted)
			ack(reqId, ok: false, error: "missing_payload")
			return
		}
		// With identity.native-keys.v1 declared (spec), `init` is checked like `provisionIdentity`: a
		// private-key field anywhere is refused, and the public identity must sit under payload.identity. Without the
		// capability the legacy payload is kept and the native side behaves as before.
		// S-1 (spec, T-144): no bridge command takes a private key, with or without the capability. Refused before
		// anything else reads the payload. The field name is logged; the value never is.
		if let field = identityForbiddenField(in: payload) {
			NSLog("[BeamioConetChat] init refused: a private key field came over the bridge")
			initStageLog(reqId, "forbiddenField", "exit=key_over_bridge_refused")
			initAnswerLog(reqId, ok: false, code: "key_over_bridge_refused", since: initStarted)
			ackFailure(reqId, error: "key_over_bridge_refused", extra: ["field": field])
			return
		}
		var capabilityAccount: String?
		if capabilities.contains(identityNativeKeysCapability) {
			let outcome = identityProvisionOutcome(
				payload: payload, route: .initNested, readyFor: { _ in false }, capabilities: capabilities
			)
			if outcome["ok"] as? Bool != true {
				let error = outcome["error"] as? String ?? "error"
				initStageLog(reqId, "identityProvision", "exit=\(error)")
				if error == "key_over_bridge_refused" {
					NSLog("[BeamioConetChat] init refused: a private key field came over the bridge")
				}
				initAnswerLog(reqId, ok: false, code: error, since: initStarted)
				ackFailure(reqId, error: error, extra: outcome.filter { $0.key == "field" })
				return
			}
			capabilityAccount = (outcome["eoa"] as? String) ?? ""
			initStageLog(reqId, "identityProvision", "result=ok")
		}
		let identityRaw = payload["identity"] as? [String: Any]
		let idEoa = normalizeAddress(String(identityRaw?["eoaAddress"] as? String ?? identityRaw?["eoa"] as? String ?? ""))
		// at G2 an init for the session's own account is idempotent. It answers the ready event once and
		// changes nothing: no key is read, no session is replaced and no listen is restarted.
		if let running = currentSession(), running.ready, !idEoa.isEmpty, running.eoa == idEoa {
			initStageLog(reqId, "idempotentReady", "exit=ready")
			initAnswerLog(reqId, ok: true, code: "ok", since: initStarted)
			emitEvent(["type": "ready", "reqId": reqId, "result": readyResult()])
			return
		}
		// ready = true only when the native store holds this account's key and it derives the account (read-back). Refused before any
		// session is replaced. The record state decides the error: absent is no_key, unreadable is not_ready.:
		// `record_mismatch` is not an init answer (it belongs to the retired X-21 path). A stored key that derives another address for an account
		// whose EOA matches is not_ready: nothing is written, deleted or transferred, the gate stays G1, and a diagnostic line is logged without
		// any key, armor or passphrase.
		// Y.163 第 4 至 8 項: several native keys and no account pointer are chosen silently here, the first by creation time, and the pointer is
		// written and read back. A choice that cannot be decided is not_ready, unreadable; nothing is written, deleted or created.
		switch BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore) {
		case .unreadable:
			initStageLog(reqId, "silentSelect", "exit=unreadable")
			initAnswerLog(reqId, ok: false, code: "not_ready", since: initStarted)
			ackFailure(reqId, error: "not_ready")
			return
		case .selected:
			initStageLog(reqId, "silentSelect", "result=selected")
		case .none, .single, .pointerKept:
			break
		}
		if let account = capabilityAccount {
			let keyCheck = identityKeyCheck(eoa: account)
			initStageLog(reqId, "keyCheck", "result=\(keyCheck)")
			switch keyCheck {
			case .ready: break
			case .absent:
				initStageLog(reqId, "keyCheck", "exit=no_key")
				initAnswerLog(reqId, ok: false, code: "no_key", since: initStarted)
				ackFailure(reqId, error: "no_key"); return
			case .unreadable:
				initStageLog(reqId, "keyCheck", "exit=not_ready")
				initAnswerLog(reqId, ok: false, code: "not_ready", since: initStarted)
				// method Y: the account behind a v3 envelope needs its passcode (the page sends it with the envelope); this is not a damaged record
				if BeamioCipherUnlock.cipherAccount(store: BeamioNativeWallet.keyStore) == account.lowercased(), !BeamioCipherUnlock.isUnlocked(eoa: account) {
					ackFailure(reqId, error: "not_ready", extra: ["reason": "passcode_not_provided"]); return
				}
				ackFailure(reqId, error: "not_ready"); return
			case .mismatch:
				NSLog("[BeamioConetChat] init: the stored key does not derive the account; nothing changed, the gate stays G1")
				initStageLog(reqId, "keyCheck", "exit=not_ready")
				initAnswerLog(reqId, ok: false, code: "not_ready", since: initStarted)
				ackFailure(reqId, error: "not_ready")
				return
			}
		}
		// and, at G1, after the account checks above and before anything else:
		// - a `nodes` value that is not a list of node objects (null, a string, a string list) is bad_request;
		// - an empty list is nodes_unavailable, with no Keychain fallback;
		// - a missing key falls back to the nodes stored in the Keychain; with none stored it is nodes_unavailable.
		// No ready and no session change in any refusal.
		if !(currentSession()?.ready ?? false) {
			if payload.keys.contains("nodes") {
				guard let suppliedList = payload["nodes"] as? [[String: Any]] else {
					initStageLog(reqId, "nodesCheck", "exit=bad_request source=supplied")
					initAnswerLog(reqId, ok: false, code: "bad_request", since: initStarted)
					ackFailure(reqId, error: "bad_request")
					return
				}
				if suppliedList.isEmpty {
					initStageLog(reqId, "nodesCheck", "exit=nodes_unavailable source=supplied count=0")
					initAnswerLog(reqId, ok: false, code: "nodes_unavailable", since: initStarted)
					ackFailure(reqId, error: "nodes_unavailable")
					return
				}
				initStageLog(reqId, "nodesCheck", "result=ok source=supplied count=\(suppliedList.count)")
			} else {
				let owner = idEoa.isEmpty ? BeamioNativeAccountPointer.get() : idEoa
				let keychainNodes = keychainSiNodes(owner: owner)
				if keychainNodes.isEmpty {
					initStageLog(reqId, "nodesCheck", "exit=nodes_unavailable source=keychain count=0")
					initAnswerLog(reqId, ok: false, code: "nodes_unavailable", since: initStarted)
					ackFailure(reqId, error: "nodes_unavailable")
					return
				}
				initStageLog(reqId, "nodesCheck", "result=ok source=keychain count=\(keychainNodes.count)")
			}
		}
		// A listen started without the page (VoIP push) for this wallet: the page
		// takes it over as it is. No reconnect; the messages it holds unconfirmed
		// are handed to the page below.
		let running = currentSession()
		let attach = running != nil && !idEoa.isEmpty && running?.eoa == idEoa && listen.isRunning()
		let s: Session
		if attach, let running {
			s = running
		} else {
			lock.lock()
			listen.stop()
			session?.history?.destroy()
			session?.history = nil
			session?.localStore?.lock()
			s = Session()
			BeamioVoiceEphemeral.clearAll()
			session = s
			lock.unlock()
		}
		DispatchQueue.main.async { pauseOwed = false }

		if let identity = payload["identity"] as? [String: Any] {
			s.eoa = normalizeAddress(String(identity["eoaAddress"] as? String ?? identity["eoa"] as? String ?? ""))
			s.pgpPublicKeyArmored = String(identity["pgpPublicKeyArmored"] as? String ?? "")
			s.ownRouteArmoredPublicKey = String(identity["ownRouteArmoredPublicKey"] as? String
				?? identity["routePublicKeyArmored"] as? String ?? "")
			s.mailboxIp = String(identity["mailboxIp"] as? String ?? "")
		}
		// The PGP record of the account this identity names; before an EOA is known, the native account pointer's.
		let pgpOwner = s.eoa.isEmpty ? BeamioNativeAccountPointer.get() : normalizeAddress(s.eoa)
		if s.ownRouteArmoredPublicKey.isEmpty {
			if let kc = BeamioChatPgpKeychain.load(eoa: pgpOwner) {
				if s.pgpPublicKeyArmored.isEmpty { s.pgpPublicKeyArmored = kc.publicKeyArmor }
				if s.ownRouteArmoredPublicKey.isEmpty { s.ownRouteArmoredPublicKey = kc.routePublicKeyArmor }
				if s.mailboxIp.isEmpty { s.mailboxIp = kc.mailboxIp }
				if s.eoa.isEmpty { s.eoa = normalizeAddress(kc.eoa) }
			}
		}
		// (1): the account is entered first. A switch that cannot clear the old inbox closes the chat module for this account.
		if !enterIdentity(s.eoa) {
			initStageLog(reqId, "enterIdentity", "exit=clear_failed")
			initAnswerLog(reqId, ok: false, code: "clear_failed", since: initStarted)
			ack(reqId, ok: false, error: "clear_failed")
			return
		}
		// (6): an isolated inbox row is reported with its error code; the inbox keeps running.
		for code in BeamioConetChatInboxStore.quarantineCodes() {
			emitEvent(["type": "event:log", "level": "warn", "message": "inbox row isolated: \(code)"])
		}
		s.conetRpcUrl = String(payload["conetRpcUrl"] as? String ?? s.conetRpcUrl)
		s.ipfsBaseUrl = String(payload["ipfsBaseUrl"] as? String ?? s.ipfsBaseUrl)
		s.ipfsWriteBaseUrl = String(payload["ipfsWriteBaseUrl"] as? String ?? "")
		s.apiBaseUrl = resolvedApiBaseUrl(payload: payload, current: s.apiBaseUrl)
		s.chatIndexRegistryAddress = String(payload["chatIndexRegistryAddress"] as? String ?? s.chatIndexRegistryAddress)
		// only the page's own init declaration decides. Neither the attach nor the earlier state does.
		s.deferAck = (payload["deferAck"] as? Bool) == true
		if let cid = payload["chainId"] as? Int { s.chainId = cid }
		else if let cid = payload["chainId"] as? NSNumber { s.chainId = cid.intValue }

		// (option B(1)): the AddressPGP source comes from this init payload, and only a usable configuration is set.
		configureAddressPGPChain(from: payload)
		// (option B(2)): an empty node list is "not provided", and it never replaces a list the session already has.
		let suppliedNodes = (payload["nodes"] as? [[String: Any]]).map { parseNodes($0) } ?? []
		s.nodes = resolvedNodes(supplied: suppliedNodes, current: s.nodes) {
			keychainSiNodes(owner: pgpOwner)
		}
		// delivery receipts: init takes no routes; the page sends them with setRoutes after init. A rebuild starts empty.
		s.clearReceiptState()

		guard !s.eoa.isEmpty else {
			initStageLog(reqId, "identity", "exit=missing_identity")
			initAnswerLog(reqId, ok: false, code: "missing_identity", since: initStarted)
			ack(reqId, ok: false, error: "missing_identity")
			return
		}
		if !s.nodes.isEmpty, BeamioChatPgpKeychain.loadSiNodes().isEmpty {
			_ = BeamioChatPgpKeychain.storeChainRoster(
				nodes: s.nodes.map { $0.asKeychainNode() },
				mailboxIp: s.mailboxIp.isEmpty ? nil : s.mailboxIp
			)
		}

		persistEntryKeys(s.nodes)

		// r3: the wallet key is read from the native store only. Without it the library stays locked. S-1:
		// the X-21 one-time transfer is retired, so no request is opened and no key is asked for over the bridge.
		// 10633 key-level check: a native key that is not the page copy's account is refused here. No signer, no pointer, nothing created,
		// deleted or changed. The page gets the native recovery answer.
		if let refusal = BeamioNativeWallet.sessionStartRefusal(eoa: s.eoa, place: "session start") {
			initStageLog(reqId, "sessionStart", "exit=\(refusal)")
			BeamioConetChatSignBroker.clearSigner()
			initAnswerLog(reqId, ok: false, code: refusal, since: initStarted)
			ack(reqId, ok: false, error: refusal)
			return
		}
		initStageLog(reqId, "sessionStart", "result=pass")
		BeamioConetChatSignBroker.setSignerEoa(s.eoa)
		// Y.163 第 32 項 行 9: keyPresent is true when and only when a valid mnemonic of this account exists. A private-key record alone is not present.
		let keyPresent = BeamioConetChatSignBroker.keyStore.mnemonicAccountState(owner: s.eoa) == .valid
		initStageLog(reqId, "keyPresent", "result=\(keyPresent)")
		if keyPresent {
			// init writes the pointer only when it is empty, the native enumeration holds exactly one valid key, and that key is the init EOA.
			if BeamioShellRecord.initMayWritePointer(eoa: s.eoa) { BeamioNativeAccountPointer.set(s.eoa) }
		} else {
			emitEvent(["type": "event:log", "level": "warn", "message": "wallet key missing: library stays locked"])
		}
		let ensureStarted = Date()
		initStageLog(reqId, "ensureReady", "phase=start")
		BeamioOpenPgpHost.shared.ensureReady { ok in
			let elapsedMs = Int(Date().timeIntervalSince(ensureStarted) * 1000)
			guard ok else {
				initStageLog(reqId, "ensureReady", "phase=failed elapsedMs=\(elapsedMs) exit=openpgp_not_ready")
				// The session is not ready, so the signer must not count as this account: nativeGate says G1.
				if let cur = currentSession(), !cur.ready { BeamioConetChatSignBroker.clearSigner() }
				initAnswerLog(reqId, ok: false, code: "openpgp_not_ready", since: initStarted)
				ack(reqId, ok: false, error: "openpgp_not_ready")
				return
			}
			initStageLog(reqId, "ensureReady", "phase=ok elapsedMs=\(elapsedMs)")
			finishInit(reqId: reqId, session: s, attach: attach, since: initStarted)
		}
	}


	/// The launch id of this process: random, made once on first use. It ties the ack lines of one launch together. It carries no device or account value.
	static let initLaunchId: String = String(UUID().uuidString.prefix(8))

	/// The detail of the init ack line: `ok=<bool> code=<code> elapsedMs=<n>` (the stage name is `ack`; `launch=` follows every stage line).
	static func initAckDetail(ok: Bool, code: String, elapsedMs: Int) -> String {
		"ok=\(ok) code=\(code) elapsedMs=\(elapsedMs)"
	}

	/// The one ack line of an init request, logged where its answer is sent. The elapsed time runs from the start of init.
	static func initAnswerLog(_ reqId: Int, ok: Bool, code: String, since: Date) {
		initStageLog(reqId, "ack", initAckDetail(ok: ok, code: code, elapsedMs: Int(Date().timeIntervalSince(since) * 1000)))
	}

	/// The QA state line (25.52Y.159 diagnostic). Only counts, booleans, enum names and exit codes. Built from the values given: no address,
	/// no part of an account name, no key name and no key value.
	static func qaStateLine(keychainWalletEntries: Int?, pointerSet: Bool, keyState: String, snapshotKnown: Bool, gate: String,
	                        walletExit: String, shellExit: String) -> String {
		"keychainWalletEntries=\(keychainWalletEntries.map(String.init) ?? "unknown") pointerSet=\(pointerSet) keyState=\(keyState) "
			+ "snapshotKnown=\(snapshotKnown) gate=\(gate) walletStatusExit=\(walletExit) shellReadExit=\(shellExit)"
	}

#if BEAMIO_QA_BUILD || BEAMIO_TEST_HOOKS
	/// The closed vocabularies of the QA lines below. A word outside its set is written as `?`: nothing else can enter a line.
	private static let qaCodes: Set<String> = ["ok", "absent", "migrating", "not_ready", "error", "conflict", "write_failed", "too_large", "bad_request",
	                                           "origin_refused", "pgp_private_in_payload", "key_shaped_content", "wallet_copy_not_approved", "wallet_fields_missing"]
	private static let qaSubs: Set<String> = ["account_mismatch", "account_record_missing", "import_not_done", "legacy_store_unreadable",
	                                          "needs_native_recovery", "not_ready_persistent", "record_unreadable", "storage_locked"]
	private static let qaReasons: Set<String> = ["storage_locked", "g1_uninitialized", "ambiguous_accounts", "unreadable", "passcode_not_provided"]
	private static let qaCauses: Set<String> = ["entitlement", "device_locked", "other"]
	private static let qaPrereadStates: Set<String> = ["ok", "confirmed_missing", "read_error"]
	private static let qaPrereadErrors: Set<String> = ["untrusted_source", "key_over_bridge_refused", "bad_request", "stale_seq"]

	private static func qaWord(_ value: Any?, in set: Set<String>) -> String {
		guard let text = value as? String, !text.isEmpty else { return "-" }
		return set.contains(text) ? text : "?"
	}

	/// The QA line of one shellRecordRead answer (25.52Y.159 diagnostic): the reqId (an integer), the code, the sub, the not_ready reason, whether a
	/// retry can help, and the class of an unreadable cause. Each name must be in its closed set; anything else is written as `?`. No address, no
	/// account name, no key name, no record and no value can enter the line.
	static func qaShellReadLine(reqId: Int?, answer: [String: Any]) -> String {
		let body = (answer["result"] as? [String: Any]) ?? answer
		let retryable = (body["retryable"] as? Bool).map { $0 ? "true" : "false" } ?? "-"
		return "reqId=\(reqId.map(String.init) ?? "-") code=\(qaWord(body["code"], in: qaCodes)) sub=\(qaWord(body["sub"], in: qaSubs)) "
			+ "reason=\(qaWord(body["notReadyReason"], in: qaReasons)) retryable=\(retryable) cause=\(qaWord(body["unreadableCause"], in: qaCauses))"
	}

	/// The QA line of one nativeMnemonicPreread answer: the reqId (an integer), the snapshot and storage-lock flags, and the state word (valid, absent,
	/// unknown) or the envelope error word, each from its closed set. Never the account, the phrase or the seq.
	static func qaPrereadLine(reqId: Int?, snapshotKnown: Bool, storageLocked: Bool, envelope: [String: Any]) -> String {
		let result = envelope["result"] as? [String: Any]
		return "reqId=\(reqId.map(String.init) ?? "-") snapshotKnown=\(snapshotKnown) storageLocked=\(storageLocked) "
			+ "state=\(qaWord(result?["code"], in: qaPrereadStates)) error=\(qaWord(envelope["error"], in: qaPrereadErrors))"
	}
#endif

	/// The exit label of a walletStatus answer (Y.163 第 14 項): not_ready/<reason>, no_key, or ok for an unlocked account.
	static func qaStatusLabel(_ answer: [String: Any]) -> String {
		let status = answer["status"] as? String ?? "?"
		if status == "unlocked" { return "ok" }
		guard let reason = answer["notReadyReason"] as? String else { return status }
		return "\(status)/\(reason)"
	}

#if BEAMIO_QA_BUILD
	/// QA builds only: the shell may set this to keep the QA state lines in its own QA log. Release builds have no sink and write nothing.
	public static var qaStateSink: ((String) -> Void)?
	private static var qaLastShellExit = "none"
	private static var qaLastStateLine = ""
	private static let qaStateLock = NSLock()

	/// Emits one QA state line when the state changes (not every poll). Reads the keychain entry count, the pointer flag and the snapshot.
	/// `walletExit` is the walletStatus answer of this call (nil: no answer this time, written as none). It is never carried over.
	static func qaStateDiagnose(walletExit: String?, shellExit: String?) {
		qaStateLock.lock()
		if let shellExit { qaLastShellExit = shellExit }
		let judgement = BeamioShellRecord.nativeJudgement()
		let line = qaStateLine(
			keychainWalletEntries: BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).validCount,
			pointerSet: !BeamioNativeAccountPointer.get().isEmpty,
			keyState: "\(judgement.keyState)",
			snapshotKnown: BeamioNativeKeySnapshot.isKnown,
			gate: "\(nativeGate())",
			walletExit: walletExit ?? "none",
			shellExit: qaLastShellExit
		)
		let changed = line != qaLastStateLine
		qaLastStateLine = line
		qaStateLock.unlock()
		guard changed else { return }
		NSLog("[BeamioQAState] %@", line)
		qaStateSink?("\(ISO8601DateFormatter().string(from: Date())) [BeamioQAState] \(line)")
	}
#endif

	/// init diagnostics (真机取证). One line per stage: the reqId, the stage name and a code. The NSLog line goes to the system log.
	/// Never an address, a key, a phrase or a record: the detail is a reason code or a count.
#if BEAMIO_QA_BUILD || BEAMIO_TEST_HOOKS
	/// QA builds only (BEAMIO_QA_BUILD; the test-hook build for the tests). The shell may set a sink to keep these lines in its own QA log.
	/// The sink receives `initStageLine`. A release build has no sink: its only output is the NSLog line.
	public static var initQASink: ((String) -> Void)?
#endif
	static func initStageLog(_ reqId: Int, _ stage: String, _ detail: String) {
		NSLog("[BeamioConetChatInit] reqId=%ld stage=%@ %@ launch=%@", reqId, stage, detail, initLaunchId)
#if BEAMIO_QA_BUILD || BEAMIO_TEST_HOOKS
		if let sink = initQASink {
			sink(initStageLine(reqId, stage, detail, at: Date()))
		}
#endif
	}

	/// The QA line: an ISO 8601 time with fractional seconds, then the NSLog text. Built from a reqId, a stage name and a code or a count only.
	static func initStageLine(_ reqId: Int, _ stage: String, _ detail: String, at date: Date) -> String {
		let formatter = ISO8601DateFormatter()
		formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
		return "\(formatter.string(from: date)) [BeamioConetChatInit] reqId=\(reqId) stage=\(stage) \(detail) launch=\(initLaunchId)"
	}

	/// The `ready` answer of `init`: the page reads it from the event.
	static func readyResult() -> [String: Any] {
		["historyApi": 2, "localApi": 1,
		 "capabilities": ["history.local.v1", "history.page.v1", "layout.cache.v1", "media.manifest.v1", "history.import.v1"]]
	}

	private static func finishInit(reqId: Int, session s: Session, attach: Bool, since: Date) {
		initStageLog(reqId, "finishInit", "phase=start attach=\(attach)")
		do {
			let host = BeamioOpenPgpHost.shared
			s.history?.destroy()
			s.localStore?.lock()
			if s.localStore == nil, let root = BeamioConetChatLocalStore.defaultRootDirectory() {
				let local = BeamioConetChatLocalStore(rootDirectory: root)
				// Spec 21.2: the bridge sets the media parser (capability media.manifest.v1).
				local.mediaManifestParser = BeamioChatMediaBody.parse
				_ = local.subscribe { ev in
					emitEvent(["type": "event:historyChange", "payload": changePayload(ev)])
				}
				s.localStore = local
			}
			s.history = BeamioConetChatHistoryStore(
				eoa: s.eoa,
				chainId: s.chainId,
				conetRpcUrl: s.conetRpcUrl,
				ipfsBaseUrl: s.ipfsBaseUrl,
				ipfsWriteBaseUrl: s.ipfsWriteBaseUrl.isEmpty ? nil : s.ipfsWriteBaseUrl,
				apiBaseUrl: s.apiBaseUrl,
				registryAddress: s.chatIndexRegistryAddress,
				openPgp: host,
				log: { level, msg in
					emitEvent(["type": "event:log", "level": level, "message": msg])
				}
			)
			s.history?.localTsProvSink = { [weak s] peer, sendKey, tsProv in
				s?.localStore?.recordLocalTsProv(convKey: peer, sendKey: sendKey, tsProv: tsProv)
			}
			// Listen first: it must not wait on the (sign-dependent) history key derivation.
			// `historyApi: 2` = streamed `event:historyBuffer`, array `historyRead`, sendId-idempotent append.
			// `localApi: 1` = historyOpenConversation / LoadOlder / ReportLayout / ClearCache / FullSync.
			s.ready = true
			initAnswerLog(reqId, ok: true, code: "ok", since: since)
			emitEvent(["type": "ready", "reqId": reqId, "result": readyResult()])
			initStageLog(reqId, "ready", "emitted=true attach=\(attach)")
			// the account is unlocked and ready: a first identity is made and registered in the background when the chain shows none
			BeamioFirstIdentityScheduler.kick(eoa: s.eoa)
			announceInboundGeneration()
			if attach {
				s.pendingLock.lock()
				let pending = s.pendingAcks
				s.pendingLock.unlock()
				NSLog("[BeamioConetChat] page attached to the running listen pending=%d", pending.count)
				if listen.isListening() {
					emitEvent(["type": "event:status", "payload": ["status": "listening", "detail": "attached"]])
				} else {
					resumeListen()
				}
				checkOwnRoute(session: s, reason: "page attach")
				for (hash, p) in pending {
					emitEvent([
						"type": "event:message",
						"payload": ["line": p.plaintext, "from": p.from, "armorHash": hash, "viaDomain": "", "plain": false],
					])
				}
				settleReceiptsForOldPage(s)
			} else {
				startListen(session: s)
			}
			// only a page that calls ackInbound (deferAck) has unconfirmed messages to get again on attach.
			if s.deferAck { replayInbox(session: s) }
			s.history?.prepare { ok in
				if ok { unlockLocalLibrary(session: s) }
			}
		}
	}

	/// Unlocks the local library with the history master (spec 6.4). Logs only the outcome code.
	private static func unlockLocalLibrary(session s: Session) {
		guard let local = s.localStore else { return }
		// accountKey = eoa + ":" + workspace; iOS uses the `default` workspace (spec D5).
		let eoa = s.eoa.lowercased()
		// R_db comes from the wallet key already held in the keychain (existing path, no new bridge parameter).
		// The private key is only used inside this call and zeroed afterwards.
		guard let root = BeamioChatWalletBoundary.localRoot(eoa: eoa, store: BeamioConetChatSignBroker.keyStore) else {
			emitEvent(["type": "event:log", "level": "warn", "message": "local library locked: no_key"])
			return
		}
		do {
			try local.unlock(accountKey: eoa + ":default", localRoot: root)
		} catch {
			emitEvent(["type": "event:log", "level": "warn", "message": "local library locked: \(error)"])
		}
	}

	// MARK: - No-page start (VoIP push)

	/// Open the mailbox listen from the stored identity, without the page: a
	/// VoIP push woke the app. Messages go to `nativeObserver` and stay
	/// unconfirmed (no mailbox ACK) until the page starts and stores them. An
	/// existing session is only resumed. Returns false when no stored identity
	/// can listen (no wallet key, PGP key, route key or roster).
	@discardableResult
	public static func startFromStore(reason: String) -> Bool {
		// under a storage-derived Locked, no page-less listen is started or resumed.
		if BeamioNativeWallet.storageDerivedLocked(eoa: BeamioNativeAccountPointer.get()) { return false }
		if let existing = currentSession() {
			if BeamioNativeWallet.storageDerivedLocked(eoa: existing.eoa) { return false }
			if listen.isListening() && !listenConnected {
				// Reconnecting (the app was suspended): retry now instead of
				// waiting out the backoff.
				NSLog("[BeamioConetChat] listen not connected; retrying now for %@", reason)
				startListen(session: existing)
			} else if !listen.isListening() {
				NSLog("[BeamioConetChat] listen resumed for %@", reason)
				DispatchQueue.main.async {
					pauseOwed = true
					postIdleCheck()
				}
				let resumeGeneration = BeamioInboxIO.generation
				listen.resume(
					session: existing,
					onStatus: { status, detail in emitStatus(status, detail) },
					onInbound: { p, h, v, a in
						guard listenFrameIsCurrent(existing, generation: resumeGeneration) else { return }
						handleInbound(plaintext: p, armorHash: h, viaDomain: v, armor: a)
					}
				)
			}
			return true
		}
		guard let pgp = BeamioChatPgpKeychain.load(eoa: BeamioNativeAccountPointer.get()), pgp.hasUserPrivate,
		      pgp.routePublicKeyArmor.contains("BEGIN PGP PUBLIC KEY"),
		      !pgp.eoa.isEmpty,
		      BeamioChatWalletKeychain.hasKey(eoa: normalizeAddress(pgp.eoa), store: BeamioConetChatSignBroker.keyStore)
		else {
			NSLog("[BeamioConetChat] no stored identity for a no-page listen (%@)", reason)
			return false
		}
		let nodes = pgp.siNodes.isEmpty ? BeamioChatPgpKeychain.loadSiNodes() : pgp.siNodes
		guard !nodes.isEmpty else {
			NSLog("[BeamioConetChat] no stored roster for a no-page listen (%@)", reason)
			return false
		}
		let s = Session()
		s.eoa = normalizeAddress(pgp.eoa)
		if BeamioNativeWallet.sessionStartRefusal(eoa: s.eoa, place: "no-page listen") != nil {
			// A refused listen leaves no signer behind from an earlier session.
			BeamioConetChatSignBroker.clearSigner()
			return false
		}
		BeamioConetChatSignBroker.setSignerEoa(s.eoa)
		guard enterIdentity(s.eoa) else { return false }
		s.pgpPublicKeyArmored = pgp.publicKeyArmor
		s.ownRouteArmoredPublicKey = pgp.routePublicKeyArmor
		s.mailboxIp = pgp.mailboxIp
		s.nodes = nodes.map { Node(ip: $0.ip, domain: $0.domain, region: $0.region, armoredPublicKey: $0.armoredPublicKey) }
		// No page runs on this path, so no init declares anything here. A frame that no page displayed gets no receipt at display:
		// receipts wait for a page's ackInbound (deferAck). A page's init replaces this value.
		s.deferAck = true
		lock.lock()
		if session != nil {
			lock.unlock()
			return true
		}
		session = s
		lock.unlock()
		NSLog("[BeamioConetChat] no-page listen starting for %@", reason)
		BeamioOpenPgpHost.shared.ensureReady { ok in
			guard ok, currentSession() === s else { return }
			startListen(session: s)
		}
		DispatchQueue.main.async {
			pauseOwed = true
			postIdleCheck()
		}
		return true
	}

	// MARK: - Background pause vs. calls

	/// Main queue.
	private static func requestPause() {
		if keepListenWhile?() == true {
			NSLog("[BeamioConetChat] pause deferred: call in progress")
			pauseOwed = true
			postIdleCheck()
			return
		}
		guard BeamioListenPolicy.pauseApplies(lifecycleKnown: lifecycleKnown, inForeground: appInForeground, callInProgress: false) else {
			// The app is in the foreground: it keeps its listen.
			NSLog("[BeamioConetChat] pause skipped: app in the foreground")
			pauseOwed = false
			return
		}
		pauseOwed = false
		listen.pause()
		emitEvent(["type": "event:status", "payload": ["status": "idle", "detail": "paused"]])
	}

	/// Main queue.
	private static func postIdleCheck() {
		guard !idleCheckPosted else { return }
		idleCheckPosted = true
		DispatchQueue.main.asyncAfter(deadline: .now() + idleCheckInterval) {
			idleCheckPosted = false
			guard pauseOwed else { return }
			if keepListenWhile?() == true {
				postIdleCheck()
			} else {
				NSLog("[BeamioConetChat] call over; owed pause applied")
				requestPause()
			}
		}
	}

	// MARK: - App foreground / background (shell)

	/// The shell reports the app state (`appWillEnterForeground` / `appDidEnterBackground`). Main queue.
	private static var lifecycleKnown = false
	private static var appInForeground = true

	/// Shell: the app went to the background. The app does not run there: the
	/// listen is paused after a short grace (a call push or dial may be
	/// starting), or when the call that rings / is up ends. Nothing retries
	/// while paused. Main queue.
	public static func appDidEnterBackground(reason: String = "background") {
		lifecycleKnown = true
		guard appInForeground else { return }
		appInForeground = false
		guard currentSession() != nil else { return }
		NSLog("[BeamioConetChat] app in the background (%@); listen pauses in %.0fs unless a call needs it", reason, idleCheckInterval)
		pauseOwed = true
		postIdleCheck()
	}

	/// Shell: the app came to the foreground. Reconnect now: resume a paused
	/// listen, cut a retry wait short, or reopen a listen the mailbox has been
	/// quiet on for 45 s (it may have died while the app was suspended). Main queue.
	public static func appWillEnterForeground(reason: String = "foreground") {
		lifecycleKnown = true
		appInForeground = true
		pauseOwed = false
		retryUnconfirmedGossipAcksNow()
		guard currentSession() != nil else { return }
		ensureNetworkWatch()
		if !listen.isListening() {
			NSLog("[BeamioConetChat] app in the foreground (%@); listen resumed", reason)
			resumeListen()
		} else if !listenConnected {
			NSLog("[BeamioConetChat] app in the foreground (%@); retrying the listen now", reason)
			listen.retryNow()
		} else {
			resumeListen()
		}
	}

	private static var networkMonitor: NWPathMonitor?

	/// Retry at once when a network comes up, instead of waiting out the
	/// backoff. Has an effect only while the listen runs and is not connected
	/// (never while paused in the background).
	private static func ensureNetworkWatch() {
		guard networkMonitor == nil else { return }
		let monitor = NWPathMonitor()
		monitor.pathUpdateHandler = { path in
			DispatchQueue.main.async {
				guard path.status == .satisfied else { return }
				if listen.isListening(), !listenConnected {
					NSLog("[BeamioConetChat] network available; retrying the listen now")
					listen.retryNow()
				}
				kickOwnRouteCheck()
			}
		}
		monitor.start(queue: DispatchQueue.global(qos: .utility))
		networkMonitor = monitor
	}

	/// (1) and (1, 2): an account import or switch clears the old account's inbox before the new account starts. The owner of the
	/// stored inbox is kept in a marker file. The answer is synchronous: the caller needs it before the chat module starts for the account.
	/// - The marker names this account: nothing to do.
	/// - No marker, and no data anywhere (inbox and call ledger): the marker is written for this account.
	/// - No marker but data present ((2)), a marker that names another account, or an unreadable marker: the owner is unknown, so the
	/// inbox is cleared first, and the marker is written for this account only after the clear succeeded.
	/// False when the clear or the marker write fails. `enterIdentity` then closes the chat module for this account ((1)).
	@discardableResult
	static func claimInboundOwner(_ eoa: String) -> Bool {
		let account = eoa.lowercased()
		guard !account.isEmpty else { return true }
		switch BeamioInboxOwner.read() {
		case .account(let owner) where owner == account:
			return true
		case .absent:
			if !BeamioConetChatInboxStore.holdsAnyRow() && !BeamioConetChatCallLedger.hasAnyRow() {
				return BeamioInboxOwner.write(account)
			}
			return clearAndMark(account)
		case .account, .unknown:
			return clearAndMark(account)
		}
	}

	/// Enters the account for the chat module ((1)). When the old inbox cannot be cleared for it, the module does not start for it: the
	/// session is dropped and the signer cleared. The caller then answers `clear_failed`, and the page may retry.
	static func enterIdentity(_ eoa: String) -> Bool {
		guard claimInboundOwner(eoa) else {
			NSLog("[BeamioConetChat] the inbound clear for an account switch did not complete; the chat module does not start")
			destroy()
			return false
		}
		return true
	}

	/// The clear for an account switch, run now: the generation advances, the retries go, and the wipe completes before this returns. The
	/// marker moves to the account only after the wipe succeeded.
	private static func clearAndMark(_ account: String) -> Bool {
		gossipRetry.clear()
		currentSession()?.clearReceiptState()
		let wiped = BeamioInboxIO.wipeNow {
			let inbox = BeamioConetChatInboxStore.clear()
			let ledger = BeamioConetChatCallLedger.clear()
			return inbox && ledger
		}
		announceInboundGeneration()
		guard wiped else { return false }
		return BeamioInboxOwner.write(account)
	}

	/// the native side tells the page the current inbound generation, on init success and on every advance (a clear, an account
	/// switch, a failed clear). The page keeps the latest value and never derives it.
	static func announceInboundGeneration() {
		emitEvent(["type": "inboundGeneration", "generation": BeamioInboxIO.generation])
	}

	/// a valid `inboundGeneration` is a JSON integer from 0 to 2^53-1. A boolean, a string, a decimal or a value out of range is not.
	static func parseInboundGeneration(_ value: Any?) -> Int? {
		BeamioChatRouteRegister.bridgeInteger(value)
	}

	/// The user cleared the identity: the inbox goes, with the armor the page has not confirmed and the dedupe records; so do
	/// the call-signal delivery states and the retry timers. The mailbox was acked for these frames, so none is sent again, and none is
	/// re-signed with the new identity. The frames stay on the server.
	///
	/// Every clear runs `destroy` first. `destroy` clears the session's pending acks on the session object itself and then drops the
	/// session (F1). This function forgets the retry timers on the main queue and queues the wipe on the inbox IO queue behind every job
	/// already queued. `done` runs on the main queue after the wipe, with its result: the reply to the clear waits for it (F4, F5).
	static func clearInboundState(then done: @escaping (Bool) -> Void) {
		gossipRetry.clear()
		BeamioInboxIO.wipe({
			let inbox = BeamioConetChatInboxStore.clear()
			let ledger = BeamioConetChatCallLedger.clear()
			let owner = BeamioInboxOwner.remove()
			return inbox && ledger && owner
		}, then: done)
		announceInboundGeneration()
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: adds a pending ack to the current session, as a stored frame does before the page confirms it.
	static func testAddPendingAck(_ armorHash: String) {
		guard let s = currentSession() else { return }
		s.pendingLock.lock()
		s.pendingAcks[armorHash] = (plaintext: "", from: "0x0000000000000000000000000000000000000009", at: Date())
		s.pendingLock.unlock()
	}

	/// Test build only: stages a displayed message awaiting the page's ackInbound, with its real plaintext (delivery-receipt cases).
	static func testStagePending(armorHash: String, plaintext: String, from: String) {
		guard let s = currentSession() else { return }
		s.pendingLock.lock()
		s.pendingAcks[armorHash] = (plaintext: plaintext, from: from, at: Date())
		s.pendingLock.unlock()
	}

	/// Test build only: the queued receipts and the flush with a given clock.
	static func testReceiptQueueCount() -> Int {
		guard let s = currentSession() else { return 0 }
		s.receiptLock.lock(); defer { s.receiptLock.unlock() }
		return s.receiptQueue.count
	}
	static func testFlushReceipts(now: Date) {
		guard let s = currentSession() else { return }
		flushQueuedReceipts(session: s, now: now)
	}
	static func testAgeReceiptQueue(by seconds: TimeInterval) {
		guard let s = currentSession() else { return }
		s.receiptLock.lock(); defer { s.receiptLock.unlock() }
		s.receiptQueue = s.receiptQueue.map { ($0.from, $0.sendId, $0.armorHash, $0.at.addingTimeInterval(-seconds), $0.generation) }
	}
	static func testDestroySession() { destroy() }

	/// Test build only: the pending acks of the current session.
	static func testPendingAckCount() -> Int {
		guard let s = currentSession() else { return 0 }
		s.pendingLock.lock(); defer { s.pendingLock.unlock() }
		return s.pendingAcks.count
	}
#endif


#if BEAMIO_TEST_HOOKS
	/// Test build only: the session the product currently holds, for the tests that hold it across a clear.
#if BEAMIO_TEST_HOOKS
	/// Test build only: how many POSTs were attempted, and an action run at each attempt, before its answer.
	static var testPostAttempts = 0
	static var testOnPostAttempt: (() -> Void)? = nil
#endif

	static func testCurrentSession() -> Session? { currentSession() }

	/// Test build only: the order of a clear: `destroy` first, then the wipe; `done` gets the wipe's result. The key and migration
	/// steps of `clearIdentity` are not run here.
	static func testClearOrder(then done: @escaping (Bool) -> Void) {
		destroy()
		clearInboundState(then: done)
	}

	/// Test build only: the page's `ackInbound` for these hashes (E-29, E-30).
	static func testAckInbound(_ hashes: [String]) {
		handleAckInbound(["armorHashes": hashes])
	}

	/// Test build only: lets the next immediate retry run again (the 5 s throttle, D2).
	static func testClearImmediateRetryThrottle() {
		lastImmediateRetry = nil
	}

	/// Test build only: the page's gossipSign command, as the page sends it ((4)).
	static func testGossipSign(_ body: [String: Any]) {
		gossipSign(body)
	}

	/// Test build only: the page's mailbox command, as the page sends it.
	static func testMailboxCommand(_ body: [String: Any]) {
		handleMailboxCommand(body)
	}

	/// Test build only: the page's single and group sends, as the page sends them.
	static func testSend(_ body: [String: Any]) {
		handleSend(body)
	}

	static func testSendGroup(_ body: [String: Any]) {
		handleSendGroup(body)
	}

	/// Test build only: the page's event callback of an earlier command is dropped, so a test does not reach another test's callback.
	static func testDetachPageEmit() {
		lock.lock()
		emit = nil
		lock.unlock()
	}

	/// Test build only: how long an in-flight send, ack or signature may wait.
	static func testSetInFlightTimeout(_ seconds: TimeInterval) {
		inFlightTimeout = seconds
	}

	/// Test build only: a failed ack from a flow of generation `gen` tries to register its retry (F3).
	static func testRecordGossipFailure(session: Session, armorHash: String, generation gen: Int) {
		scheduleGossipRetry(session: session, armorHash: armorHash, advance: true, generation: gen)
	}
#endif

#if BEAMIO_TEST_HOOKS
	/// Test build only: the steps of a clear, in the order they run, while a test records them. nil: nothing is recorded.
	static var testClearTrace: [String]? = nil
	private static func traceClear(_ step: String) { testClearTrace?.append(step) }
#else
	private static func traceClear(_ step: String) {}
#endif

	/// The removal steps of a clear after every check has passed (§25.52PY.8 第 3–7 項): the marker, the copies, the signer, the wallet items, the
	/// inbox wipe, the pointer. `finish` is called once with the outcome: (true, nil) for ok, or (false, code). Used by clearIdentity and by the
	/// synchronous startup redo.
	private static func clearSteps(owners: [String], finish: @escaping (Bool, String?) -> Void) {
		// item 1: the device marker `clear_pending` is set when the removal starts, after every owner has passed its check. A refusal
		// changes nothing, so it sets no marker. It is cleared with the account pointer (below). It is the basis of an interrupted clear and its redo.
		// the marker is bound to the accounts of this clear; a marker that does not read back as written is a failed start: nothing has been removed yet
		guard BeamioNativeClearPending.set(owners: owners) else {
			BeamioNativeClearPending.clear()
			finish(false, "clear_incomplete")
			return
		}
		traceClear("pending")
		// Only when every owner passed: the copies (M, N) of each owner are removed. L is never removed here.
		for owner in owners {
			// The check passed above, so a failure here is a failed deletion step (PY.8 第 2 项): clear_incomplete, not the migration's code.
			let code = BeamioPgpMigrationImport.unregister(eoa: owner).code
			if code != "ok" {
				finish(false, "clear_incomplete")
				return
			}
		}
		traceClear("copies")
		// A,: only after every unregistration is ok, the session is destroyed, the signer and the wallet keys go, and the inbox is wiped.
		// ((a)): the account pointer is the last step. The wallet key of every owner goes with the copies, before the
		// pointer; the pointer goes after the wipe; the reply goes last. An interruption before the pointer leaves the window that the reads and
		// walletState answer fail-closed, and a clear run again completes it.
		destroy()
		BeamioConetChatSignBroker.clearSigner()
		// /: the wallet items go (mnemonic record, K, EOA key); the scoped PGP record L is kept. Every owner is tried. Any failure
		// fails the clear as a whole: the pointer and the marker clear_pending stay, the page gets the code only, and a redo completes it.
		var walletCleared = true
		for owner in owners {
			if let walletStore = BeamioConetChatSignBroker.keyStore as? BeamioChatWalletKeychainStore {
				if !walletStore.clearWalletItems(eoa: owner) { walletCleared = false }
			} else {
				BeamioConetChatSignBroker.keyStore.delete(eoa: owner)
			}
		}
		if !walletCleared {
			traceClear("keys-incomplete")
			finish(false, "clear_incomplete")
			return
		}
		// the flag goes with the W items, once every step has succeeded.
		for owner in owners { BeamioRecoveryBackupFlag.clear(eoa: owner) }
		traceClear("keys")
		clearInboundState { wiped in
			traceClear("wipe")
			// A failed wipe keeps the pointer and the marker clear_pending, and the reply is clear_incomplete; the redo completes the clear. A successful wipe clears the pointer (the last step), then the marker.
			var marked = true
			if wiped {
				// the clear keeps every stored account, so it writes the `identity_cleared` marker (no secret, nothing deleted) before the pointer goes. A marker that
				// does not read back keeps the pointer and clear_pending, and the redo completes the clear.
				marked = BeamioIdentityCleared.record(accounts: BeamioIdentityCleared.accountsOnDevice(store: BeamioNativeWallet.keyStore, owners: owners), store: BeamioNativeWallet.keyStore)
				if marked {
					traceClear("marker")
					// the pointer goes only when it names an account of this clear (a redo of X never clears the pointer of another account Y)
					let pointerNow = BeamioNativeAccountPointer.get()
					if pointerNow.isEmpty || owners.contains(pointerNow) { BeamioNativeAccountPointer.clear() }
					traceClear("pointer")
					BeamioNativeClearPending.clear()
				}
			}
			// F4, F5: the reply goes after the wipe has finished, and says whether the wipe did.
			NSLog("[BeamioConetChat] identity cleared, inbound wipe ok: %d", wiped ? 1 : 0)
			// an inbox wipe failure is one failed step of the clear; the answer is clear_incomplete (code only).
			if !wiped || !marked {
				finish(false, "clear_incomplete")
			} else {
				finish(true, nil)
			}
		}
	}

	private static func clearIdentity(reqId: Int) {
		// the signer and the account pointer are read first. destroy clears the signer, so nothing is destroyed or cleared
		// before every owner is judged.
		let eoa = BeamioConetChatSignBroker.currentSignerEoa()
		let owners = clearOwners(signer: eoa)
		// A,,: the recovery source of every owner is checked before any removal. A
		// refusal, a busy account or a bad request answers its own code and changes nothing: the session is not destroyed, the wallet key, the account
		// pointer, the inbox, the dedupe records and the call signals stay as they are.
		// (§25.52PY.8 第 1 项 (6)): with no account known, a residual PGP copy (N or M) is a check failure: unregister_refused, nothing removed.
		// §25.52PY.8 第 2 項, 第 5 項: a redo (clear_pending already set) goes from step (3); the checks (1a)–(1c) are not run again.
		// clear_pending is bound to the accounts of the clear that began. Only the recorded accounts are redone; for any other current account
		// the marker does not exist (the checks run as usual). A marker with no readable owner record is never a redo and never deletes: clear_incomplete.
		var isRedo = false
		var otherAccountPending = false
		var clearOwnersList = owners
		if BeamioNativeClearPending.isSet() {
			guard case .list(let recorded) = BeamioNativeClearPending.owners() else {
				ack(reqId, ok: false, error: "clear_incomplete")
				return
			}
			// (owner, G0 plan B): with no current account (G0, `owners` is empty) a manual clearIdentity does not continue the clear of the recorded X: it answers
			// clear_incomplete and deletes and writes nothing; X is finished by the startup redo (when it is safe) or by a clearIdentity once the current account is X again.
			if owners.isEmpty {
				ack(reqId, ok: false, error: "clear_incomplete")
				return
			}
			if owners.allSatisfy({ recorded.contains($0) }) {
				// The current accounts are the recorded ones (the current account is X). Only the RECORDED accounts X are redone, and only what can be attributed to X
				// exactly is removed (the redo never reads the current pointer or signer to choose what to delete).
				isRedo = true
				clearOwnersList = recorded
			} else {
				// The marker belongs to X and the current account is Y: Y's own checks run first (below); a refusal is answered as it is. When Y passes, the answer is
				// still only clear_incomplete: nothing is deleted or written, X and Y stay as they are, because the marker has a single slot and X's clear must end before Y's begins.
				// X is finished only by the startup redo, or by a clearIdentity when the current account really is X.
				otherAccountPending = true
			}
		}
		if !isRedo, owners.isEmpty, BeamioPgpMigrationImport.KeychainStore.residualCopiesPresent() {
			ack(reqId, ok: false, error: "unregister_refused")
			return
		}
		if !isRedo {
		for owner in owners {
			var code = clearCheck(owner)
			// the closed set of the additional field `reason` of unregister_refused: key_only, backup_unconfirmed (the other refusals carry none)
			var reason: String?
			// (1b),: with W items present, the recovery-backup flag must be set. A missing or unreadable flag is not set.
			// PY.14 (c): a private-key-only account fails closed; nothing is cleared. This is the project owner's requirement (spec §25.52PY.14 item 4 (c),
			// ): an account that accepts a private key cannot clear its identity or log out on this device.
			if code == "ok", BeamioBackupDisplay.isKeyOnlyAccount(eoa: owner) { code = "unregister_refused"; reason = "key_only" }
			if code == "ok", BeamioRecoveryBackupFlag.hasWalletItems(eoa: owner, store: BeamioConetChatSignBroker.keyStore),
			   !BeamioRecoveryBackupFlag.isRecoveryBackupConfirmed(eoa: owner) {
				code = "unregister_refused"
				reason = "backup_unconfirmed"
			}
			if code != "ok" {
				ack(reqId, ok: false, error: code, reason: reason)
				return
			}
		}
		}
		if otherAccountPending {
			ack(reqId, ok: false, error: "clear_incomplete")
			return
		}
		clearSteps(owners: clearOwnersList) { ok, code in
			if ok { ack(reqId, ok: true, result: ["ok": true]) } else { ack(reqId, ok: false, error: code ?? "clear_incomplete") }
		}
	}

	/// The accounts whose records a clear removes: the signer and the native account pointer, each once.
	private static let startupRedoLock = NSLock()
	private static var startupRedoRan = false

	/// The once-per-process startup redo (§25.52PY.8 第 7 項): an account with copies that is not the active one and has no W item is judged by C.3
	/// (L, P, or a chain backup) and cleared in the order M, N, lastCode when it passes. Nothing else is touched.
	static func runStartupClearRedoOnce() {
		startupRedoLock.lock()
		let first = !startupRedoRan
		startupRedoRan = true
		startupRedoLock.unlock()
		guard first else { return }
		// §25.52PY.8 第 5 項: an interrupted clear (clear_pending set) is redone before the first command, locally, from step (3). Until it
		// completes, the wallet and identity commands answer not_ready (see `clearRedoBlocks`). The redo never queries the chain.
		if BeamioNativeClearPending.isSet() {
			startupRedoLock.lock(); clearRedoFailed = true; startupRedoLock.unlock()
			// PY.8 第 5 項: with clear_pending set and W items still present, the automatic redo does not run; the wallet and identity commands
			// stay not_ready until the user completes the redo through clearIdentity.
			if BeamioPgpMigrationImport.walletItemsToClearMayExist() { return }
			// the accounts of the redo are the RECORDED ones, never the current pointer's; with no readable record nothing is redone and nothing is deleted
			guard case .list(let owners) = BeamioNativeClearPending.owners() else { return }
			// (owner, G0 plan B): the automatic finish is for the recorded account X only when it is safe: the marker and its owner record read, and no other account's
			// wallet or chat entry exists on the device (every read succeeded). Otherwise nothing is deleted or written, the marker stays, and the next start judges again.
			guard startupRedoIsSafe(recorded: owners) else { return }
			clearSteps(owners: owners) { ok, _ in
				startupRedoLock.lock(); clearRedoFailed = !ok; startupRedoLock.unlock()
			}
		}
		// §25.52PY.8 第 7 項: the residual scan is background work. It does not block the start, the first command, or an offline start.
		DispatchQueue.global(qos: .utility).async {
			BeamioPgpMigrationImport.redoResidualCopiesAtStart(activeAccount: BeamioNativeAccountPointer.get()) { owner in
				BeamioRecoveryBackupFlag.hasWalletItems(eoa: owner, store: BeamioConetChatSignBroker.keyStore)
			}
		}
	}

	/// Whether the startup redo of the recorded accounts is safe to run. Reads only; nothing is written.
	/// All of these must hold, or the redo does not run and the marker stays:
	/// - the marker reads as set and the owner record is a non-empty list (the caller has read it);
	/// - the native key owners and the mnemonic accounts can be enumerated, and every one is a recorded account;
	/// - every account with PGP copies (N, M, last code) is a recorded account;
	/// - the account pointer is empty or names a recorded account.
	/// An enumeration that cannot be read (nil) is a failed read, so the answer is not safe. A clear never deletes the wallet key (walletKey), so the recorded accounts' own keys stay.
	static func startupRedoIsSafe(recorded: [String]) -> Bool {
		guard !recorded.isEmpty, BeamioNativeClearPending.read() == .set else { return false }
		let known = Set(recorded.map { $0.lowercased() })
		let store = BeamioNativeWallet.keyStore
		guard let keyOwners = store.enumerateKeyOwners(), let mnemonics = store.enumerateMnemonicCreations() else { return false }
		guard keyOwners.allSatisfy({ known.contains($0.lowercased()) }),
		      mnemonics.allSatisfy({ known.contains($0.owner.lowercased()) }) else { return false }
		guard let copyOwners = BeamioPgpMigrationImport.KeychainStore.accountsWithCopiesChecked(), copyOwners.allSatisfy({ known.contains($0.lowercased()) }) else { return false }
		let pointer = BeamioNativeAccountPointer.get().lowercased()
		return pointer.isEmpty || known.contains(pointer)
	}

	/// True while an interrupted clear is not complete: the wallet and identity commands answer not_ready (§25.52PY.8 第 5 項).
	static func clearRedoBlocks(type: String) -> Bool {
		// the block follows clear_pending alone; it lifts only when the marker is cleared.
		guard BeamioNativeClearPending.isSet() else { return false }
		// 25.52Y.96 第 3 项, 25.22.4: a retired name answers not_supported before the lock, so the block does not apply to it.
		guard !retiredCommands.contains(type) else { return false }
		return type.hasPrefix("wallet") || ["init", "provisionIdentity", "identity.provision"].contains(type)
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: forgets that the startup redo ran, so a test can run it again.
	static func resetStartupRedoForTests() {
		startupRedoLock.lock()
		startupRedoRan = false
		clearRedoFailed = false
		startupRedoLock.unlock()
	}
#endif

	private static var clearRedoFailed = false

	/// True when the identity to clear is a private-key-only account: the signer or the pointer's account holds a key record and no mnemonic (BeamioBackupDisplay.isKeyOnlyAccount);
	/// with neither known, true when the device holds key records and no account has a mnemonic. Reads only; nothing is written.
	static func clearIdentityIsKeyOnly() -> Bool {
		let owners = clearOwners(signer: BeamioConetChatSignBroker.currentSignerEoa())
		if !owners.isEmpty { return owners.contains { BeamioBackupDisplay.isKeyOnlyAccount(eoa: $0) } }
		let store = BeamioNativeWallet.keyStore
		guard let keyOwners = store.enumerateKeyOwners(), !keyOwners.isEmpty else { return false }
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		return inventory.enumerated && !inventory.readFailed && inventory.accounts.isEmpty
	}

	private static func clearOwners(signer: String) -> [String] {
		var owners: [String] = []
		for candidate in [signer, BeamioNativeAccountPointer.get()] {
			let account = candidate.lowercased()
			guard !account.isEmpty, !owners.contains(account) else { continue }
			owners.append(account)
		}
		return owners
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: the check that clearIdentity makes for an owner. nil: the production check.
	static var testUnregisterCheck: ((String) -> BeamioPgpMigrationImport.Outcome)? = nil

	/// Test build only: runs clearIdentity without the command gate, so a test can hold an account pointer that differs from the signer.
	static func testClearIdentity(reqId: Int) {
		clearIdentity(reqId: reqId)
	}
#endif

	/// The check of one unregistration, as clearIdentity makes it before any removal. Returns the answer code.
	private static func clearCheck(_ owner: String) -> String {
#if BEAMIO_TEST_HOOKS
		if let override = testUnregisterCheck { return override(owner).code }
#endif
		return BeamioPgpMigrationImport.unregisterCheck(eoa: owner).code
	}

	/// Hand the page what the inbox store holds and the page has not been given
	/// in this session (received while it was not running, or never confirmed).
	private static func replayInbox(session s: Session) {
		let gen = BeamioInboxIO.generation
		BeamioInboxIO.perform(generation: gen, { BeamioConetChatInboxStore.list() }) { stored in
			s.pendingLock.lock()
			let given = Set(s.pendingAcks.keys)
			s.pendingLock.unlock()
			let rest = stored.filter { !given.contains($0.armorHash) }
			guard !rest.isEmpty else { return }
			NSLog("[BeamioConetChat] inbox replay count=%d", rest.count)
			for e in rest {
				BeamioConetChatListenSession.decryptArmor(session: s, armored: e.armor) { line, hash in
					handOverStored(plaintext: line, armorHash: hash, viaDomain: e.viaDomain)
				}
			}
		}
	}

	/// `chatRouteRegister`. The reqId is checked first. Then the gate state (judged
	/// before the payload is read), the native lock, the capability, and the shape (BeamioChatRouteRegister). A well-formed
	/// request with the capability signs the registration. The capability is not declared in this build, so every request
	/// answers native_unavailable.
	private static func chatRouteRegister(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		let account = recordAccount() ?? ""
		// the passcode bundle not provided is `not_ready` with the reason `passcode_not_provided`, never `locked` (the stage keeps no lock word in production).
		if nativeGate() == .g2, !account.isEmpty, BeamioPasscodeSession.shared.appState(eoa: account) == .locked {
			var envelope = BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready")
			envelope["reason"] = "passcode_not_provided"
			emitEvent(envelope)
			return
		}
		let locked = false
		let storageUnreadable = !account.isEmpty && BeamioNativeWallet.keyStore.keyRecordState(eoa: account) == .unreadable
		switch BeamioChatRouteRegister.stage(body: body, gate: nativeGate(), locked: locked, storageUnreadable: storageUnreadable) {
		case .answer(let code):
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: code))
		case .proceed(let request):
			// (3): the registration is for the signer's account only; another account is refused with signer_mismatch, before any record is read.
			if let refusal = routeRegisterSignerRefusal(account: account) {
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: refusal))
				return
			}
			let outcome = BeamioChatRouteRegister.register(
				account: account, request: request, secrets: routeRegisterSecrets(account: account),
				timestamp: Int64(Date().timeIntervalSince1970 * 1000),
				iv: BeamioChatRouteRegister.randomBytes(12), nonce: BeamioChatRouteRegister.randomBytes(16)
			)
			switch outcome {
			case .success(let result):
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: result, error: nil))
			case .failure(let refusal):
				emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: refusal.code))
			}
		}
	}

	/// Capability that switches `identity.provision` to the public-material answer (spec).
	static let identityNativeKeysCapability = "identity.native-keys.v1"

	/// `provisionIdentity` (r3, spec rule 1): no key may come over the bridge. A payload that carries any
	/// private-key or passphrase field is refused. With `identity.native-keys.v1` declared, the answer is `{ready, eoa}`;
	/// without it, the legacy answer is kept.
	private static func provisionIdentity(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		let p = (body["payload"] as? [String: Any]) ?? body
		let outcome = identityProvisionOutcome(
			payload: p, readyFor: identityKeyReady, capabilities: BeamioConetChatProtocol.capabilities
		)
		if outcome["ok"] as? Bool == true {
			var result = outcome
			result.removeValue(forKey: "ok")
			ack(reqId, ok: true, result: result)
			return
		}
		let error = outcome["error"] as? String ?? "error"
		if error == "key_over_bridge_refused" {
			NSLog("[BeamioConetChat] provisionIdentity refused: a private key field came over the bridge")
		}
		ackFailure(reqId, error: error, extra: outcome.filter { $0.key == "field" })
	}

	/// Private-key fields refused by `identity.provision` (identity-native-keys-vectors.v1, 17th batch). Key names are
	/// compared case-insensitively, at any depth.
	/// The CRED set of `provisionIdentity` and `init`: the same 16 names as `credentialFieldNames`, sorted.
	/// Matched case-insensitively over the whole payload (T-103). The identity vector checks a subset of it.
	static let identityForbiddenKeys: [String] = credentialFieldNames.sorted()
	private static let identityForbiddenKeysLowercased = Set(identityForbiddenKeys.map { $0.lowercased() })

	/// The two places the public identity sits. `provisionIdentity` is flat; `init` nests it under `payload.identity`
	/// (spec, fieldPlacement). A top-level public field in `init` is not an identity (missing_identity).
	enum IdentityRoute {
		case provision
		case initNested
	}

	/// The `identity.provision` / `init` answer with the shipped hello list (the production path).
	static func identityProvisionOutcome(payload p: [String: Any], route: IdentityRoute = .provision, readyFor: (String) -> Bool) -> [String: Any] {
		identityProvisionOutcome(payload: p, route: route, readyFor: readyFor, capabilities: BeamioConetChatProtocol.capabilities)
	}

#if BEAMIO_TEST_HOOKS
	/// Test hook only: the answer with a given hello list. Not compiled into a release or store build.
	static func testIdentityProvisionOutcome(payload p: [String: Any], route: IdentityRoute = .provision, readyFor: (String) -> Bool,
	                                         capabilities: [String]) -> [String: Any] {
		identityProvisionOutcome(payload: p, route: route, readyFor: readyFor, capabilities: capabilities)
	}
#endif

	/// The `identity.provision` / `init` answer as a pure function: refusal and error codes are the vector codes. Only
	/// `readyFor` reads the store, and it is not called for a refused or malformed request.
	private static func identityProvisionOutcome(
		payload p: [String: Any],
		route: IdentityRoute = .provision,
		readyFor: (String) -> Bool,
		capabilities: [String]
	) -> [String: Any] {
		if let field = identityForbiddenField(in: p) {
			return ["ok": false, "error": "key_over_bridge_refused", "field": field]
		}
		// Rule 0a runs after the three detections above (notice 30): a non-canonical key name is bad_identity, with the field.
		if let field = identityNonCanonicalKeyField(in: p) {
			return ["ok": false, "error": "bad_identity", "field": field]
		}
		let source: [String: Any]
		switch route {
		case .provision:
			source = p
		case .initNested:
			guard let nested = p["identity"] as? [String: Any] else {
				return ["ok": false, "error": "missing_identity"]
			}
			source = nested
		}
		guard source["eoa"] != nil || source["eoaAddress"] != nil else {
			return ["ok": false, "error": "missing_identity"]
		}
		guard let raw = (source["eoa"] as? String) ?? (source["eoaAddress"] as? String), let eoa = identityEoa(raw) else {
			return ["ok": false, "error": "bad_identity"]
		}
		if let pub = source["pgpPublicKeyArmored"] {
			guard let armor = pub as? String, identityPGPPublicArmorAccepted(armor) else {
				return ["ok": false, "error": "bad_identity"]
			}
		}
		// The route public key may be omitted: the key is then absent, never an empty string.
		// When it is present it must be a PGP public armor, as the PGP public key is.
		if let route = source["ownRouteArmoredPublicKey"] {
			guard let armor = route as? String, identityPGPPublicArmorAccepted(armor) else {
				return ["ok": false, "error": "bad_identity"]
			}
		}
		switch identityProvisionAnswer(eoa: eoa, ready: readyFor(eoa), capabilities: capabilities) {
		case .ready(let ready, let account):
			return ["ok": true, "ready": ready, "eoa": account]
		case .legacyPresent:
			return ["ok": true, "present": true]
		case .legacyMissing:
			return ["ok": false, "error": "no_key"]
		}
	}

	/// The first refused field in the payload, checked in the vector's order (valueShapeRules 5): key names
	/// (case-insensitive, whole payload), then a string holding "PRIVATE KEY BLOCK" (whole payload), then a string that is
	/// exactly 64 hex digits with an optional 0x (every position except the exact path `payload.nodes`). Only the field
	/// name is returned, never the value.
	static func identityForbiddenField(in value: Any) -> String? {
		if let field = identityForbiddenKeyField(in: value) { return field }
		guard let root = value as? [String: Any] else { return nil }
		if let field = identityValueField(in: root, rule: .privateKeyBlock) { return field }
		return identityValueField(in: root, rule: .hex64)
	}

	static func identityForbiddenKeyField(in value: Any) -> String? {
		if let dict = value as? [String: Any] {
			for key in dict.keys.sorted() where identityForbiddenKeysLowercased.contains(where: { forbidden in
				identityScalarsEqual(Array(identityNormalized(key).lowercased().unicodeScalars), Array(forbidden.unicodeScalars))
			}) {
				return key
			}
			for key in dict.keys.sorted() {
				if let nested = dict[key], let field = identityForbiddenKeyField(in: nested) { return field }
			}
		} else if let list = value as? [Any] {
			for nested in list {
				if let field = identityForbiddenKeyField(in: nested) { return field }
			}
		}
		return nil
	}

	enum IdentityValueRule {
		case privateKeyBlock
		case hex64
	}

	/// Walks the payload's values. Only the top-level key `nodes` (the exact path `payload.nodes`) is exempt from the 64-hex
	/// rule, with its whole subtree. Nested `nodes` keys (payload.identity.nodes, payload.extra.nodes) are not exempt.
	static func identityValueField(in root: [String: Any], rule: IdentityValueRule) -> String? {
		for name in root.keys.sorted() {
			if let nested = root[name],
			   let field = identityValueField(in: nested, key: name, rule: rule, inNodes: name == "nodes") {
				return field
			}
		}
		return nil
	}

	static func identityValueField(in value: Any, key: String?, rule: IdentityValueRule, inNodes: Bool) -> String? {
		if let text = value as? String {
			return identityValueRefused(text, rule: rule, inNodes: inNodes) ? (key ?? "") : nil
		}
		if let dict = value as? [String: Any] {
			for name in dict.keys.sorted() {
				if let nested = dict[name], let field = identityValueField(in: nested, key: name, rule: rule, inNodes: inNodes) {
					return field
				}
			}
		} else if let list = value as? [Any] {
			for nested in list {
				if let field = identityValueField(in: nested, key: key, rule: rule, inNodes: inNodes) { return field }
			}
		}
		return nil
	}

	static func identityValueRefused(_ text: String, rule: IdentityValueRule, inNodes: Bool) -> Bool {
		switch rule {
		case .privateKeyBlock:
			return identityValueHasPrivateKeyBlock(text)
		case .hex64:
			// Rule 2 applies to the normalised value. Rule 3 (notice 26): a multi-line string stays a long string after
			// normalisation, so it does not match the whole-value pattern (for example a PGP public key block).
			if inNodes { return false }
			return identityValueIsHex64(text)
		}
	}

	/// A string that carries key material: a PGP private key block, or exactly 64 hex digits with an optional 0x.
	static func identityValueLooksLikeKeyMaterial(_ text: String) -> Bool {
		identityValueHasPrivateKeyBlock(text) || identityValueIsHex64(text)
	}

	/// Set S of notice 26: Unicode White_Space, plus U+FEFF, U+200B–U+200D, U+2060 and U+00AD. Every character of S is
	/// deleted before a comparison (key names and values alike). This does not use the platform trim.
	static func identityStripsCharacter(_ scalar: Unicode.Scalar) -> Bool {
		switch scalar.value {
		case 0x0009...0x000D, 0x0020, 0x0085, 0x00A0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
			return true
		case 0xFEFF, 0x200B, 0x200C, 0x200D, 0x2060, 0x00AD:
			return true
		default:
			return false
		}
	}

	/// Normalisation N (rule 0, notice 30): Unicode NFKD first (decomposes, so a combining mark separates from its base
	/// character; full-width and compatibility characters map to ASCII), then every character of S is deleted, then every
	/// character of general category Mn, Me or Cf. Used for detection only; the original value is not rewritten. No trim.
	static func identityNormalized(_ text: String) -> String {
		let nfkd = (text as NSString).decomposedStringWithCompatibilityMapping
		var view = String.UnicodeScalarView()
		view.append(contentsOf: nfkd.unicodeScalars.filter { !identityStripsCharacter($0) && !identityIsMarkOrFormat($0) })
		return String(view)
	}

	/// Unicode general category Mn (nonspacing mark), Me (enclosing mark) or Cf (format).
	static func identityIsMarkOrFormat(_ scalar: Unicode.Scalar) -> Bool {
		switch scalar.properties.generalCategory {
		case .nonspacingMark, .enclosingMark, .format:
			return true
		default:
			return false
		}
	}

	/// Key name whitelist (notice 30, rule 0a): the original key equals its normalisation, and after normalisation it holds
	/// only ASCII letters, digits and underscore. Applies at every level, payload.nodes included.
	static func identityKeyIsCanonical(_ key: String) -> Bool {
		let scalars = Array(key.unicodeScalars)
		guard !scalars.isEmpty, identityScalarsEqual(scalars, Array(identityNormalized(key).unicodeScalars)) else { return false }
		return scalars.allSatisfy { s in
			(0x30 ... 0x39).contains(s.value) || (0x41 ... 0x5A).contains(s.value) || (0x61 ... 0x7A).contains(s.value) || s.value == 0x5F
		}
	}

	/// The first key in the payload (depth-first, sorted per object) that is not canonical, or nil.
	static func identityNonCanonicalKeyField(in value: Any) -> String? {
		if let dict = value as? [String: Any] {
			for key in dict.keys.sorted() where !identityKeyIsCanonical(key) {
				return key
			}
			for key in dict.keys.sorted() {
				if let nested = dict[key], let field = identityNonCanonicalKeyField(in: nested) { return field }
			}
		} else if let list = value as? [Any] {
			for nested in list {
				if let field = identityNonCanonicalKeyField(in: nested) { return field }
			}
		}
		return nil
	}

	/// Rule 1: PRIVATEKEYBLOCK (PRIVATE KEY BLOCK with every character of S deleted), in any key or position.
	static func identityValueHasPrivateKeyBlock(_ text: String) -> Bool {
		identityScalarsContain(identityNormalized(text).uppercased(), "PRIVATEKEYBLOCK")
	}

	/// Rule 2: the normalised whole value is 64 hex digits with an optional 0x or 0X (regex ^(0[xX])?[0-9a-fA-F]{64}$).
	static func identityValueIsHex64(_ text: String) -> Bool {
		var body = Array(identityNormalized(text).unicodeScalars)
		if body.count >= 2, body[0] == "0", body[1] == "x" || body[1] == "X" { body.removeFirst(2) }
		return body.count == 64 && body.allSatisfy { isHexScalar($0) }
	}

	/// Account format for `identity.provision` (vectors reject-bad-eoa-*): `0x` + 40 hex digits, all lower-case or EIP-55
	/// checksummed. An all-upper-case hex body is refused. Returns the lower-case form.
	static func identityEoa(_ raw: String) -> String? {
		// Canonical form only (notice 23), checked per Unicode scalar (review 29): the value equals its normalisation, and
		// is exactly 0x followed by 40 ASCII lower-case hex digits. Any extra scalar (a combining mark included), a BOM,
		// NBSP, full-width form, 0X prefix, upper-case digit or an EIP-55 checksum is bad_identity.
		let scalars = Array(raw.unicodeScalars)
		guard identityScalarsEqual(scalars, Array(identityNormalized(raw).unicodeScalars)) else { return nil }
		guard scalars.count == 42, scalars[0] == "0", scalars[1] == "x" else { return nil }
		guard scalars.dropFirst(2).allSatisfy({ isLowerHexScalar($0) }) else { return nil }
		return raw
	}

	/// Scalar-exact equality and substring search. Swift's String comparison and contains work on Characters and
	/// canonical equivalence, so a combining mark could hide a character from them (review 29). These do not.
	static func identityScalarsEqual(_ a: [Unicode.Scalar], _ b: [Unicode.Scalar]) -> Bool {
		guard a.count == b.count else { return false }
		for i in 0 ..< a.count where a[i] != b[i] { return false }
		return true
	}

	static func identityScalarsContain(_ haystack: String, _ needle: String) -> Bool {
		let h = Array(haystack.unicodeScalars)
		let n = Array(needle.unicodeScalars)
		guard !n.isEmpty, h.count >= n.count else { return false }
		for start in 0 ... (h.count - n.count) where identityScalarsEqual(Array(h[start ..< start + n.count]), n) {
			return true
		}
		return false
	}

	static func isLowerHexScalar(_ s: Unicode.Scalar) -> Bool {
		(0x30 ... 0x39).contains(s.value) || (0x61 ... 0x66).contains(s.value)
	}

	static func isHexScalar(_ s: Unicode.Scalar) -> Bool {
		(0x30 ... 0x39).contains(s.value) || (0x61 ... 0x66).contains(s.value) || (0x41 ... 0x46).contains(s.value)
	}

	/// The PGP public key block (23rd batch): the header is detected on the normalised text (BEGINPGPPUBLICKEYBLOCK).
	/// The value itself is not rewritten; it may not carry a character of S other than space, tab, CR or LF.
	static func identityPGPPublicArmorAccepted(_ raw: String) -> Bool {
		for scalar in raw.unicodeScalars where identityStripsCharacter(scalar) {
			if ![0x20, 0x09, 0x0D, 0x0A].contains(scalar.value) { return false }
		}
		return identityScalarsContain(identityNormalized(raw), "BEGINPGPPUBLICKEYBLOCK")
	}

	private static func eip55Checksum(_ lower: String) -> String {
		let body = String(lower.dropFirst(2))
		let hash = BeamioNativeEthSigner.keccak256(Array(body.utf8)).map { String(format: "%02x", $0) }.joined()
		var out = "0x"
		for (c, d) in zip(body, hash) {
			if c.isLetter, let v = Int(String(d), radix: 16), v >= 8 {
				out.append(Character(c.uppercased()))
			} else {
				out.append(c)
			}
		}
		return out
	}

	/// A failure answer that carries one extra field (the vector's `field` for a refused private-key key).
	private static func ackFailure(_ reqId: Int, error: String, extra: [String: Any] = [:]) {
		if reqId < 0 { return }
		var payload: [String: Any] = ["type": "ack", "reqId": reqId, "ok": false, "error": error]
		for (key, value) in extra { payload[key] = value }
		// a credential refusal names its field in the ack's result as well as at the top (the identity vectors read the top).
		if error == "key_over_bridge_refused", let field = extra["field"] as? String {
			payload["result"] = ["names": [field]]
		}
		emitEvent(payload)
	}

	/// The answer shape of `identity.provision` (spec). A pure function, so both capability states can be
	/// tested. Only a declared `identity.native-keys.v1` switches to `{ready, eoa}`.
	enum IdentityProvisionAnswer: Equatable {
		/// Capability declared: `{ready, eoa}`.
		case ready(Bool, eoa: String)
		/// Capability absent and the key is there: the legacy `{present: true}`.
		case legacyPresent
		/// Capability absent and the key is missing: the legacy error.
		case legacyMissing
	}

#if BEAMIO_TEST_HOOKS
	/// Test hook only: the answer for a given hello list. Not compiled into a release or store build.
	static func testIdentityProvisionAnswer(eoa: String, ready: Bool, capabilities: [String]) -> IdentityProvisionAnswer {
		identityProvisionAnswer(eoa: eoa, ready: ready, capabilities: capabilities)
	}
#endif

	private static func identityProvisionAnswer(eoa: String, ready: Bool, capabilities: [String]) -> IdentityProvisionAnswer {
		if capabilities.contains(identityNativeKeysCapability) { return .ready(ready, eoa: eoa) }
		return ready ? .legacyPresent : .legacyMissing
	}

	/// `ready` (spec, T-104): true only when the native store holds a key for `eoa` and that key derives `eoa`
	/// (read-back check). The key is copied to bytes, wiped, and never returned.
	static func identityKeyReady(eoa: String) -> Bool {
		identityKeyCheck(eoa: eoa) == .ready
	}

	/// The answer of the read-back of an account's key. `absent`, `unreadable` and `mismatch` are the three refusals of the record.
	enum IdentityKeyCheck: Equatable {
		case ready, absent, unreadable, mismatch
	}

	/// The record state first: absent has no key, unreadable is not ready. A present key is read once, wiped, and must derive `eoa`.
	static func identityKeyCheck(eoa: String) -> IdentityKeyCheck {
		let store = BeamioConetChatSignBroker.keyStore
		// Y.163 第 31、32 項: the account is its valid mnemonic. No mnemonic is no key; one that cannot be judged, or is invalid, is unreadable.
		// A valid mnemonic whose key record is missing is an inconsistent store, not "no key": unreadable.
		switch store.mnemonicAccountState(owner: eoa) {
		case .absent: return .absent
		case .unreadable, .invalid: return .unreadable
		case .valid: break
		}
		switch store.keyRecordState(eoa: eoa) {
		case .absent, .unreadable: return .unreadable
		case .present: break
		}
		guard var stored = store.read(eoa: eoa) else { return .unreadable }
		var key = [UInt8](stored)
		BeamioNativeWallet.wipe(&stored)
		defer { BeamioNativeEthSigner.wipe(&key) }
		return BeamioNativeEthSigner.address(privateKey: key)?.lowercased() == eoa.lowercased() ? .ready : .mismatch
	}

	/// `walletAddress` (spec, vectors U-1 to U-5): the account of the native record. No record: `no_key`, with no
	/// data and no signature. The address is public.
	private static func walletAddress(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		// method Y: the account of a v3 envelope answers its address once unlocked and `not_ready` before (never `no_key`)
		if let cipher = cipherAccountOfDevice() {
			if BeamioCipherUnlock.isUnlocked(eoa: cipher) { ack(reqId, ok: true, result: ["address": cipher]) } else { ack(reqId, ok: false, error: "not_ready") }
			return
		}
		let eoa = BeamioConetChatSignBroker.currentSignerEoa().lowercased()
		guard !eoa.isEmpty, BeamioNativeWallet.hasKey(eoa: eoa) else {
			ack(reqId, ok: false, error: "no_key")
			return
		}
		ack(reqId, ok: true, result: ["address": eoa])
	}

	/// C5 `deriveSubkeys` (spec, 25.3): the subkeys kId, kIdx, dek and kcv of the account, lowercase hex, workspace
	/// `default` (D5). R_db, R_proto and P are never returned. The gate is judged before this (G2 only).
	private static func deriveSubkeys(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		let account = BeamioConetChatSignBroker.currentSignerEoa().lowercased()
		if let claimed = body["eoa"] as? String, claimed.lowercased() != account {
			ack(reqId, ok: false, error: "address_mismatch")
			return
		}
		guard !account.isEmpty,
		      var root = BeamioChatWalletBoundary.localRoot(eoa: account, store: BeamioConetChatSignBroker.keyStore)
		else {
			// A key record that exists but gives no key now (unreadable, or a passcode record whose bundle has not been provided) is not "no key".
			let state = account.isEmpty ? BeamioChatWalletKeyRecordState.absent : BeamioConetChatSignBroker.keyStore.keyRecordState(eoa: account)
			ack(reqId, ok: false, error: state == .absent ? "no_key" : "not_ready")
			return
		}
		defer { BeamioNativeWallet.wipe(&root) }
		let dek = BeamioChatLocalCrypto.dek(localRoot: root, eoa: account, workspace: "default")
		let idKey = BeamioChatLocalCrypto.idKey(localRoot: root)
		let idxKey = BeamioChatLocalCrypto.idxKey(localRoot: root)
		let kcv = BeamioChatLocalCrypto.kcv(dek: dek)
		ack(reqId, ok: true, result: [
			"kId": symmetricHex(idKey),
			"kIdx": symmetricHex(idxKey),
			"dek": symmetricHex(dek),
			"kcv": kcv,
		])
	}

	/// The account a W-command is bound to (25.3): the signer, and `eoa` when given must be that account. Returns the error
	/// code to answer with, or nil when the command may run. A locked account is `locked` (25.3: needs unlocked).
	private static func boundAccountRefusal(_ body: [String: Any]) -> (account: String, error: String?) {
		let account = BeamioConetChatSignBroker.currentSignerEoa().lowercased()
		if let claimed = body["eoa"] as? String, claimed.lowercased() != account { return (account, "address_mismatch") }
		if account.isEmpty { return (account, "no_key") }
		return (account, nil)
	}

	/// W2 in-process: the local subkeys {DEK, K_idx, K_id}, lower-case hex, workspace `default`.
	/// Not a bridge command: no PWA caller, and withdraws a bridge exposure. No R_db, R_proto or P is returned.
	/// nil when the account has no native key.
	static func localSubkeys(account: String) -> [String: String]? {
		// nothing in G0 or G1; the value only in G2 for this account.
		guard BeamioNativeWallet.answersValues(eoa: account) else { return nil }
		guard var root = BeamioChatWalletBoundary.localRoot(eoa: account, store: BeamioConetChatSignBroker.keyStore) else {
			return nil
		}
		defer { BeamioNativeWallet.wipe(&root) }
		let dek = BeamioChatLocalCrypto.dek(localRoot: root, eoa: account, workspace: "default")
		let idKey = BeamioChatLocalCrypto.idKey(localRoot: root)
		let idxKey = BeamioChatLocalCrypto.idxKey(localRoot: root)
		return ["DEK": symmetricHex(dek), "K_idx": symmetricHex(idxKey), "K_id": symmetricHex(idKey)]
	}

	/// W3 in-process: {indexEncKey (lower-case hex), genesisCid ("0x" + 64 hex)}, for the
	/// CONET chain 224422. Not a bridge command. R_proto stays in the SDK process and is not returned. nil without a key.
	/// (3): the code a route registration gets when its account is not the signer's (`signer_mismatch`, the code both platforms use).
	static func routeRegisterSignerRefusal(account: String) -> String? {
		BeamioConetChatSignBroker.currentSignerEoa() == account.lowercased() ? nil : "signer_mismatch"
	}

	/// (F3): a route registration signs with the PGP record of its own account only. For another account the record is not read, so the
	/// registration is refused (`no_pgp_key`) before any signature is made.
	static func routeRegisterSecrets(account: String) -> BeamioChatPgpKeychain.Secrets? {
		guard BeamioConetChatSignBroker.currentSignerEoa() == account.lowercased() else { return nil }
		return BeamioChatPgpKeychain.load(eoa: account)
	}

	static func protocolValues(account: String) -> [String: String]? {
		// nothing in G0 or G1; the value only in G2 for this account.
		// (F3): the history master is signed for this account, so only the signer's account gets the values.
		guard BeamioConetChatSignBroker.currentSignerEoa() == account.lowercased() else { return nil }
		guard BeamioNativeWallet.answersValues(eoa: account) else { return nil }
		guard let rProto = BeamioNativeWallet.historyMaster(eoa: account, chainId: 224422) else { return nil }
		let indexEncKey = BeamioConetChatHistoryStore.hkdf(master: rProto, info: "index-enc", length: 32)
		let genesis = BeamioConetChatHistoryStore.hkdf(master: rProto, info: "frag-genesis", length: 32)
		return ["indexEncKey": BeamioChatLocalCrypto.hex(indexEncKey), "genesisCid": "0x" + BeamioChatLocalCrypto.hex(genesis)]
	}

	private static func symmetricHex(_ key: SymmetricKey) -> String {
		key.withUnsafeBytes { BeamioChatLocalCrypto.hex(Data($0)) }
	}

	/// W7 `ephemeralSign` (spec): the voiceListen signature by the channel key T, nothing else. `voicePay` is not
	/// signed here (W5 kind `voice`). `bad_request` for a malformed input, `unknown_channel` for an unknown `sid`.
	/// The answer of a W7 or voice ephemeral command: `{type: "ack", reqId, ok, result | error}`. The reqId is echoed as it was sent. No action
	/// name is returned.
	private static func ephemeralAnswer(reqId: Any, result: [String: Any]?, error: String?) {
		emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: result, error: error))
	}

	/// An integer JSON number: not a boolean, not a string, not fractional.
	private static func wholeNumber(_ value: Any?) -> Int64? {
		guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
		let double = number.doubleValue
		guard double == double.rounded(), abs(double) < 9e15 else { return nil }
		return number.int64Value
	}

	/// `ephemeralSign` (W7): the listen signature of a live registration. The arguments are `args` when present, else the top level.
	private static func ephemeralSign(_ body: [String: Any]) {
		let reqId: Any = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) ?? -1
		let args = body
		if let kind = body["kind"], (kind as? String) != "voiceListen" {
			ephemeralAnswer(reqId: reqId, result: nil, error: "bad_request")
			return
		}
		guard let sid = args["sid"] as? String, BeamioVoiceEphemeral.isSid(sid),
		      let wk = args["wk"] as? String, BeamioVoiceEphemeral.isWk(wk),
		      let relayKeyId = args["relayKeyId"] as? String, !relayKeyId.isEmpty,
		      let timestamp = wholeNumber(args["timestamp"]).map({ Int($0) })
		else {
			ephemeralAnswer(reqId: reqId, result: nil, error: "bad_request")
			return
		}
		switch BeamioVoiceEphemeral.sign(sid: sid, wk: wk, relayKeyId: relayKeyId, timestamp: timestamp) {
		case .success(let out):
			ephemeralAnswer(reqId: reqId, result: ["temp": out.temp, "tempSig": out.tempSig], error: nil)
		case .failure(.badRequest):
			ephemeralAnswer(reqId: reqId, result: nil, error: "bad_request")
		case .failure(.unknownChannel):
			ephemeralAnswer(reqId: reqId, result: nil, error: "unknown_channel")
		}
	}

	/// `voiceEphemeralRegister` (to): the channel key T is made natively and registered for `sid` until `expiresAt`. The gate
	/// (no_key, not_ready, locked) is judged before this. The answer holds only the public address of T.
	private static func voiceEphemeralRegister(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		let args = body
		guard let sid = args["sid"] as? String, BeamioVoiceEphemeral.isSid(sid), let expiresAt = wholeNumber(args["expiresAt"]) else {
			ephemeralAnswer(reqId: echo, result: nil, error: "bad_request")
			return
		}
		let current = BeamioVoiceEphemeral.now()
		guard expiresAt > current, expiresAt <= current + BeamioVoiceEphemeral.maxTTLSeconds else {
			ephemeralAnswer(reqId: echo, result: nil, error: "bad_request")
			return
		}
		switch BeamioVoiceEphemeral.enroll(sid: sid, expiresAt: expiresAt) {
		case .registered(let temp):
			ephemeralAnswer(reqId: echo, result: ["sid": sid, "temp": temp, "expiresAt": expiresAt], error: nil)
		case .sidExists:
			ephemeralAnswer(reqId: echo, result: nil, error: "sid_exists")
		case .failed:
			// (interface ruling): register_failed, when a failure happens while the registration executes, after the gate and the
			// arguments pass. No address or material is returned, nothing is stored, no event is emitted, and an existing registration is not changed.
			ephemeralAnswer(reqId: echo, result: nil, error: "register_failed")
		}
	}

	/// `voiceEphemeralPrepare {role, sid, needPgp}` (v109 section 119, project owner's requirement): the temporary wallet key, the channel keys and,
	/// with `needPgp`, the temporary OpenPGP key are made natively; the answer carries public fields only. A failure never falls back to a page key or to the
	/// long-term chat PGP: `not_ready`, `keygen_failed`, `bad_request`. The gate (no_key, not_ready, locked) is judged before this.
	private static func voiceEphemeralPrepare(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		guard let role = body["role"] as? String, let sid = body["sid"] as? String,
		      let needPgp = (body["needPgp"] as? NSNumber), CFGetTypeID(needPgp as CFTypeRef) == CFBooleanGetTypeID()
		else {
			ephemeralAnswer(reqId: echo, result: nil, error: "bad_request")
			return
		}
		switch BeamioVoiceEphemeral.prepare(role: role, sid: sid, needPgp: needPgp.boolValue) {
		case .success(let channel):
			var out: [String: Any] = ["sid": channel.sid, "key": channel.key, "wk": channel.wk, "temp": channel.temp, "tempPgpFpr": channel.tempPgpFpr]
			if let armor = channel.tempPgpArmor { out["tempPgpArmor"] = armor }
			ephemeralAnswer(reqId: echo, result: ["channel": out], error: nil)
		case .failure(let code):
			ephemeralAnswer(reqId: echo, result: nil, error: code.rawValue)
		}
	}

	/// `voiceEphemeralForget {sid}`: every private key held for the `sid` is overwritten and removed. Idempotent: a `sid` that holds nothing answers ok.
	private static func voiceEphemeralForget(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		guard let sid = body["sid"] as? String, BeamioVoiceEphemeral.isSid(sid) else {
			ephemeralAnswer(reqId: echo, result: nil, error: "bad_request")
			return
		}
		BeamioVoiceEphemeral.forget(sid: sid)
		ephemeralAnswer(reqId: echo, result: [:], error: nil)
	}

	/// `voiceEphemeralSeal`: T is sealed to the recipient's OpenPGP key. The arguments are checked first, then the registration.
	/// Only the armored message leaves the native layer. Each call seals afresh.
	private static func voiceEphemeralSeal(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		// Project owner's alternative A (2026-11-21): no message may carry the temporary private key, not even sealed to the peer's long-term OpenPGP
		// key; only the temporary address is exchanged, and the peer signs an authorization. The command fails closed: nothing is read out of T, nothing
		// is sealed, nothing leaves. (The legacy body below exists only in a test build, for the conformance cases of the retired path.)
		#if BEAMIO_TEST_HOOKS
		if legacySealForTests { legacyVoiceEphemeralSeal(echo: echo, body: body); return }
		#endif
		ephemeralAnswer(reqId: echo, result: nil, error: "unknown_command")
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook only: runs the retired seal path (T sealed to the recipient's OpenPGP key) for the conformance tests that still cover it.
	static var legacySealForTests = false

	private static func legacyVoiceEphemeralSeal(echo: Any, body: [String: Any]) {
		let args = body
		guard let sid = args["sid"] as? String, BeamioVoiceEphemeral.isSid(sid),
		      let raw = args["recipientPgpPublicArmored"] as? String
		else {
			ephemeralAnswer(reqId: echo, result: nil, error: "bad_request")
			return
		}
		let recipient = raw.trimmingCharacters(in: .whitespacesAndNewlines)
		guard recipient.hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK-----") else {
			ephemeralAnswer(reqId: echo, result: nil, error: "bad_request")
			return
		}
		switch BeamioVoiceEphemeral.acceptText(sid: sid) {
		case .failure:
			ephemeralAnswer(reqId: echo, result: nil, error: "unknown_channel")
		case .success(let plaintext):
			BeamioOpenPgpHost.shared.encrypt(plaintext: plaintext, publicKeyArmor: recipient) { outcome in
				if case .success(let armor) = outcome, armor.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("-----BEGIN PGP MESSAGE-----") {
					ephemeralAnswer(reqId: echo, result: ["sid": sid, "sealed": armor.trimmingCharacters(in: .whitespacesAndNewlines)], error: nil)
				} else {
					ephemeralAnswer(reqId: echo, result: nil, error: "seal_failed")
				}
			}
		}
	}
	#endif

	/// `identityPublic` at G0 (25.52Y.90): `no_key`. The boolean `kPresent` is added only when the capability pair `identity.kpresent.v1` is
	/// declared (25.52Y.90 第 4 項), and only when the device's PGP and K records can be read. A read that fails omits the field, which the page
	/// reads as unknown (25.52Y.108 第 2 項). Presence only: no key is read here. nil when the reqId is invalid (no answer).
	static func identityPublicNoKeyAnswer(_ body: [String: Any],
	                                      declared: Bool = BeamioConetChatProtocol.capabilities.contains("identity.kpresent.v1")) -> [String: Any]? {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return nil }
		var answer = BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "no_key")
		if declared, let present = BeamioChatPgpKeychain.devicePresenceState() { answer["kPresent"] = present }
		return answer
	}

	/// `identityPublic {reqId}` (spec): the public material of the account, read natively. G2 only; the gate is judged
	/// before this (G0 `no_key`, G1 `not_ready`). Read only: no state change, no signature, no unlock, so the passcode lock
	/// does not matter. The result never carries a key, a passphrase, a recovery code, a mnemonic, a backup or a hash.
	private static func identityPublic(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		// Credential and key fields first. Only the field names are logged, never the values.
		let refused = body.keys.filter { identityCredentialFields.contains($0) }.sorted()
		if !refused.isEmpty {
			NSLog("[BeamioConetChat] identityPublic refused fields: %@", refused.joined(separator: ","))
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "key_over_bridge_refused"))
			return
		}
		if body.keys.contains(where: { $0 != "type" && $0 != "reqId" }) {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request"))
			return
		}
		let account = BeamioConetChatSignBroker.currentSignerEoa().lowercased()
		guard !account.isEmpty else {
			// Unreachable past the gate (G2 has an account). Not `no_key`: that answer belongs to the gate alone.
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
			return
		}
		var result: [String: Any] = ["eoa": account, "accountKey": account + ":default"]
		// pgpReady: the record holds pgpKeyID, the PGP public key and the route public key together.
		let record = BeamioChatPgpKeychain.publicRecord(eoa: account)
		let ready = record.map { !$0.pgpKeyId.isEmpty && !$0.publicKeyArmor.isEmpty && !$0.routePublicKeyArmor.isEmpty } ?? false
		result["pgpReady"] = ready
		if ready, let record {
			result["pgpKeyID"] = record.pgpKeyId
			result["pgpPublicKeyArmored"] = record.publicKeyArmor
			result["ownRouteArmoredPublicKey"] = record.routePublicKeyArmor
		}
		emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: result, error: nil))
	}

	/// The family commands (§25.22.4 as the storage-derived lock lists them) and the key-setup names: each answers not_ready once under a storage-derived
	/// lock. Each would otherwise answer no_key at G0 (25.52Y.83). Bridge names of C1–C5 and N0–N4 follow the existing family set.
	static let storageLockedNames: Set<String> = storageLockedFamilies.union([
		"init", "walletCredential", "walletEoaAddress", "nativeAccountCreateOpen", "nativeRecoveryOpen", "pgpMigrate",
		"chatRouteRegister", "pgpUpgradeRetry",
	])

	/// Y.88 A (takeover): the lifecycle and status commands keep their answer under an unknown snapshot or a storage-derived lock.
	static let lifecycleAndStatusNames: Set<String> = ["hello", "pause", "resume", "destroy", "passcodeStatus"]

	/// Y.88 B, C and E, with 25.52Y.83 (takeover): these names answer not_ready once under a storage-derived lock. Under an unknown snapshot
	/// every known name that is not in class A answers not_ready once. The page opens (B), the families and identityPublic (C), and the names
	/// that need the key store (E) are listed here.
	static let keyStateAnsweredNames: Set<String> = storageLockedNames.union([
		"provisionIdentity", "identityPublic", "pgpUpgradeRetry",
		"send", "sendGroup", "ackInbound", "mailboxCommand", "ownMailboxCommand", "issueGroupRoster", "issueGroupTombstone",
		"voiceListen", "voiceUnlisten", "voiceFrame", "voiceEphemeralRegister", "voiceEphemeralSeal", "voiceEphemeralPrepare", "voiceEphemeralForget",
		"queryPresence", "queryNativeWake", "clearIdentity",
	])

	/// Y.88 (takeover, 2026-11-15): with the native-key snapshot unknown, or a storage-derived lock, each command is answered by its class.
	/// A (`lifecycleAndStatusNames`) keeps the normal path. The record commands are answered by BeamioShellRecord. walletStatus answers not_ready with
	/// `notReadyReason: "unreadable"`. D (the history reads) answers ok with `source` not_ready (25.52DL). B, C and E answer not_ready once. With the
	/// snapshot unknown, every other known name answers not_ready once; under the storage lock, the other names keep the normal path.
	/// Nothing is read from the store or written by these answers. The envelope and the credential check keep their order.
	/// Returns true when it answered.
	private static func answerKeyStateRefusal(_ body: [String: Any], snapshotUnknown: Bool) -> Bool {
		let type = String(body["type"] as? String ?? "")
		if type == "shellRecordRead" || type == "shellRecordWrite" {
			handleShellRecordCommand(body, originAllowed: true)
			return true
		}
		if lifecycleAndStatusNames.contains(type) { return false }
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return true
		}
		if let hit = credentialFieldHit(type: type, body: body) {
			NSLog("[BeamioConetChat] %@ refused: a credential field came over the bridge", type)
			emitEvent([
				"type": "ack", "reqId": echo, "ok": false, "error": "key_over_bridge_refused",
				"field": hit.field, "result": ["names": hit.paths],
			])
			return true
		}
		guard knownBridgeCommand(type) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "unknown_command"))
			return true
		}
		if type == "walletStatus" {
			// E4 settlement lock yields to walletStatus (E9.10.3-3): an unsettled overwrite marker blocks the write path only.
			// With the snapshot known and no storage lock, walletStatus is judged by its own rules (no_key when the mnemonic reads empty and nothing
			// is unreadable; not_ready/unreadable on a read failure). The snapshot-unknown and storage-lock answers stay.
			if !snapshotUnknown, BeamioNativeKeySnapshot.current()?.storageLock == nil { return false }
			ack(body["reqId"] as? Int ?? -1, ok: true, result: ["status": "not_ready", "notReadyReason": "unreadable"])
			return true
		}
		if retiredCommands.contains(type) {
			// 25.52BZ.3: the retired names answer not_supported in every state.
			x21Retired(body)
			return true
		}
		if historyReadCommands.contains(type) {
			// 25.52DL: a history read answers ok with source not_ready and no data.
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["source": "not_ready"], error: nil))
			return true
		}
		guard snapshotUnknown || keyStateAnsweredNames.contains(type) else { return false }
		emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
		return true
	}

	/// 25.52Y.117 (TS-07; Y.106, Y.107 第 1 項): G0 with the pointer set and no key record, whose mnemonic residue is readable, is `has`,
	/// never `no_key`. A session ready for the pointer's account answers `locked` with the accountKey and `reason: phrase_only`; otherwise the
	/// G1 form, `not_ready` with `g1_uninitialized`. Both are `has` on the page. A mnemonic or mark that cannot be read answers `unreadable`
	/// (unknown on the page). Residue without a mnemonic (a commit or an intent only) is not changed here: nil, so the caller answers `no_key`
	/// (Y.107 第 3 項, TS-08). Only the item states are read: nothing is returned, written or deleted. nil: no residue to report.
	static func phraseResidueStatus() -> [String: Any]? {
		let pointer = BeamioNativeAccountPointer.get()
		guard !pointer.isEmpty, let items = BeamioNativeWallet.keyStore as? BeamioChatMnemonicKeyStoring else { return nil }
		let mnemonic = items.itemState(.mnemonic, eoa: pointer)
		let commit = items.itemState(.commit, eoa: pointer)
		let intent = items.itemState(.intent, eoa: pointer)
		if [mnemonic, commit, intent].contains(.unreadable) || BeamioNativeKeyImport.isIntentUnavailable(eoa: pointer) {
			return ["status": "not_ready", "notReadyReason": "unreadable"]
		}
		guard mnemonic == .present else { return nil }
		return phraseOnlyAnswer(eoa: pointer)
	}

	/// The answer for a pointer account that holds a mnemonic and no key record (v227 section 247.1, requirement): the residue phrase must be readable and verified (the read
	/// succeeds, the BIP-39 checksum passes, it derives the account). Verified: a ready session answers `locked` with the accountKey and `reason: phrase_only`, otherwise `not_ready` with
	/// `g1_uninitialized`. Readable but not verified, or not readable: `not_ready` with `unreadable`. None of them is `no_key`. Only the item is read; nothing is returned or written.
	static func phraseOnlyAnswer(eoa: String) -> [String: Any] {
		switch BeamioNativeWallet.keyStore.mnemonicAccountState(owner: eoa) {
		case .valid:
			if let s = currentSession(), s.ready, s.eoa.lowercased() == eoa.lowercased() {
				return ["status": "locked", "accountKey": eoa + ":default", "reason": "phrase_only"]
			}
			return ["status": "not_ready", "notReadyReason": "g1_uninitialized"]
		case .invalid, .unreadable, .absent:
			return ["status": "not_ready", "notReadyReason": "unreadable"]
		}
	}

	/// The exit of the G1 branch of `walletStatus` (Y.163, draft §23.1, §24.2 P2): `unreadable` when the shell record cannot be read, its markers
	/// cannot be read, or the snapshot judged it unreadable; otherwise `g1_uninitialized`. Pure, so the rule is tested without a store.
	static func walletStatusG1Exit(recordState: BeamioChatWalletKeyRecordState?, markersUnreadable: Bool, snapshotUnreadable: Bool) -> String {
		if recordState == .unreadable || markersUnreadable || snapshotUnreadable { return "unreadable" }
		return "g1_uninitialized"
	}

	/// The label of a record state for the diagnostic line: the three states, or `none` when the device has no record account.
	static func stateLabel(_ state: BeamioChatWalletKeyRecordState?) -> String {
		switch state {
		case .absent?: return "absent"
		case .present?: return "present"
		case .unreadable?: return "unreadable"
		case nil: return "none"
		}
	}

	/// `walletStatus` (W1, spec 表 D): the status only. With no native key it is `no_key`, and no account key is
	/// returned, except the residue of 25.52Y.117 (`phraseResidueStatus`). With a key it is `unlocked` with the account key (eoa + ":default", D5), or
	/// `locked` without one (a passcode lock, 25.52Y.118).
	private static func walletStatus(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		// Y.163 第 14 項: the QA state line carries the answer of this call, and of no other.
		func reply(_ answer: [String: Any]) {
			ack(reqId, ok: true, result: answer)
			#if BEAMIO_QA_BUILD
			qaStateDiagnose(walletExit: qaStatusLabel(answer), shellExit: nil)
			#endif
		}
		// method Y: the native record is the account's v3 envelope. The account exists and needs its passcode (never `no_key`); after the page's
		// pwaWalletSync with the correct passcode the session holds its key and the account is unlocked.
		if let cipher = cipherAccountOfDevice() {
			reply(BeamioCipherUnlock.isUnlocked(eoa: cipher) ? ["status": "unlocked", "accountKey": cipher + ":default"]
			                                                 : ["status": "not_ready", "notReadyReason": "passcode_not_provided", "retryable": true])
			return
		}
		// (k): the marks of the account (intent, commit, mnemonic) and the storage-derived unreadable record answer
		// `not_ready` with `notReadyReason: "unreadable"`, before the passcode lock. Nothing is deleted.
		let unreadable: [String: Any] = ["status": "not_ready", "notReadyReason": "unreadable"]
		switch nativeGate() {
		case .g0:
			// 25.52Y.159 (A): several native keys and no account pointer (the snapshot's ambiguous state) answer not_ready, unreadable.
			// Nothing is chosen, written or deleted; never no_key. (Y.163: the walletStatus stays read-only; the init chooses.)
			// 25.52Y.160 (AS-02, AS-04): keys that cannot be read are not_ready, unreadable; one key is the account (G1, not_ready
			// with g1_uninitialized) when no pointer names it; otherwise the residue answer or no_key.
			let judgement = BeamioShellRecord.nativeJudgement()
			let answer: [String: Any]
			if judgement.keyState == .ambiguous || accountSelectEntries() == nil {
				answer = unreadable
			} else if let residue = phraseResidueStatus() {
				answer = residue
			} else if judgement.keyState == .normal, judgement.account != nil, BeamioNativeAccountPointer.get().isEmpty {
				answer = ["status": "not_ready", "notReadyReason": "g1_uninitialized"]
			} else if BeamioNativeAccountPointer.get().isEmpty {
				// 25.52Y.162: with no pointer, the residue probe decides. A residue, or a probe that fails, is not_ready/unreadable;
				// only a successful probe with no residue may answer no_key.
				switch BeamioResidueProbe.probe(ignoringIntents: true) {
				case .absent: answer = ["status": "no_key"]
				case .present, .failed: answer = unreadable
				}
			} else {
				answer = ["status": "no_key"]
			}
			reply(answer)
		case .g1:
			// Y.163 (2026-11-17, draft §23.1, §24.2 P2): the shell record is judged for readability first. A record that exists and cannot be read is
			// `not_ready` with `unreadable`, never `g1_uninitialized`. The judgement is logged as labels only (no key material, no account).
			let account = recordAccount()
			let recordState = account.map { BeamioNativeWallet.keyStore.keyRecordState(eoa: $0) }
			let markersUnreadable = account.map { BeamioNativeKeyImport.walletMarkersUnreadable(eoa: $0) } ?? false
			// 25.52Y.39 第 9 項 (b): a damaged or unreadable key record answers `unreadable`. The snapshot judged it at the last event.
			let snapshotUnreadable = BeamioNativeKeySnapshot.current()?.unreadable == true
			let exit = walletStatusG1Exit(recordState: recordState, markersUnreadable: markersUnreadable, snapshotUnreadable: snapshotUnreadable)
			NSLog("[BeamioConetChat] walletStatus g1 record=%@ markers=%@ snapshot=%@ exit=%@", stateLabel(recordState),
			      markersUnreadable ? "unreadable" : "ok", snapshotUnreadable ? "unreadable" : "ok", exit)
			// 25.52Y.117 / Y.118: the G1 form of `not_ready` names its reason, `g1_uninitialized` (no init has completed yet). A mnemonic that is readable but not verified, or not readable,
			// is `unreadable` (v227 section 247.1).
			let mnemonicVerified = account.map { BeamioNativeWallet.keyStore.mnemonicAccountState(owner: $0) == .valid } ?? true
			reply(exit == "unreadable" || !mnemonicVerified ? unreadable : ["status": "not_ready", "notReadyReason": "g1_uninitialized"])
		case .g2:
			guard let eoa = recordAccount() else {
				reply(["status": "no_key"])
				return
			}
			if BeamioNativeKeyImport.walletMarkersUnreadable(eoa: eoa) {
				reply(unreadable)
				return
			}
			// the record exists and cannot be read: not_ready, without accountKey. A read failure is never reported as locked (25.52Y.107 第 2 項),
			// so this check comes before the passcode lock answer.
			if BeamioNativeWallet.keyStore.keyRecordState(eoa: eoa) == .unreadable {
				reply(unreadable)
				return
			}
			// 25.52Y.117: the pointer's account holds a mnemonic and has no key record (a phrase-only residue): `locked` with `phrase_only` when the phrase is verified, `unreadable` when it is not;
			// never `unlocked` and never `no_key` (v227 section 247.1).
			if BeamioNativeWallet.keyStore.keyRecordState(eoa: eoa) == .absent {
				reply(phraseOnlyAnswer(eoa: eoa))
				return
			}
			// 25.52Y.118: `unlocked` always carries accountKey.: a passcode record whose bundle has not been provided is a real storage
			// state, not an application lock: `not_ready` with the reason `passcode_not_provided`, retryable, and no accountKey.
			let bundleMissing = BeamioPasscodeSession.shared.appState(eoa: eoa) == .locked
			if bundleMissing {
				reply(["status": "not_ready", "notReadyReason": "passcode_not_provided", "retryable": true])
			} else {
				reply(["status": "unlocked", "accountKey": eoa + ":default"])
			}
		}
	}

	/// `walletCredential`. The answer is the mnemonic of an account that
	/// has a mnemonic record, checked against the stored key and address. An account with no mnemonic record (an `eoa_key` account) answers
	/// `unavailable`: no private key is returned, and no `{eoa}` either (W-L5). An unreadable record or mark answers `unavailable`.
	static func walletCredentialForTests(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		let answer = walletCredentialOutcome()
		if answer.ok {
			ack(reqId, ok: true, result: answer.result)
		} else {
			ack(reqId, ok: false, error: answer.error ?? "unavailable")
		}
	}

	/// True when the key store holds a key record of any account, or cannot say (fail closed): a key with no mnemonic. walletCredential answers `unavailable` then, never `no_key`.
	private static func keyRecordsMayExist() -> Bool {
		let keys = BeamioNativeWallet.keyStore
		if keys.hasAnyKeyRecord() { return true }
		guard let owners = keys.enumerateKeyOwners() else { return true }
		return !owners.isEmpty
	}

	/// The answer of walletCredential for the record account. Shared by the window entry
	/// and the tests. Only the mnemonic path exists: no private key is returned, and an `eoa_key` account answers `unavailable`.
	static func walletCredentialOutcome() -> (ok: Bool, result: [String: Any]?, error: String?) {
		guard let eoa = recordAccount(), let items = BeamioNativeWallet.keyStore as? BeamioChatMnemonicKeyStoring else {
			// A key record with no mnemonic (a key-only account) answers `unavailable`: `no_key` is the walletStatus word (requirement, item 2). No key is returned either way.
			return (false, nil, keyRecordsMayExist() ? "unavailable" : "no_key")
		}
		if BeamioNativeKeyImport.walletMarkersUnreadable(eoa: eoa) { return (false, nil, "unavailable") }
		switch items.itemState(.mnemonic, eoa: eoa) {
		case .absent, .unreadable:
			return (false, nil, "unavailable")
		case .present:
			guard var phrase = items.readItem(.mnemonic, eoa: eoa), var stored = items.readItem(.key, eoa: eoa) else {
				return (false, nil, "unavailable")
			}
			defer { BeamioNativeWallet.wipe(&phrase); BeamioNativeWallet.wipe(&stored) }
			var derived: [UInt8] = []
			if case .key(let k) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) { derived = k }
			defer { BeamioNativeWallet.wipe(&derived) }
			guard !derived.isEmpty, derived == [UInt8](stored),
			      BeamioNativeEthSigner.address(privateKey: derived)?.lowercased() == eoa
			else { return (false, nil, "unavailable") }
			return (true, ["eoa": eoa, "credentialKind": "mnemonic", "mnemonic": String(decoding: phrase, as: UTF8.self)], nil)
		}
	}

	/// The get answer of walletCredential: the phrase outcome plus its blob. The blob is always carried. The phrase is a `String`
	/// (the platform keeps it; it cannot be zeroed, note); the byte buffers handed to the blob are wiped by the blob code.
	static func walletCredentialBlobOutcome() -> (ok: Bool, result: [String: Any]?, error: String?) {
		guard let account = recordAccount() else {
			return (false, nil, keyRecordsMayExist() ? "unavailable" : "no_key")
		}
		let base = walletCredentialOutcome()
		guard base.ok, var result = base.result, let phrase = result["mnemonic"] as? String else { return base }
		// (upgrade path): an account without K gets it now, after its mnemonic was read in this call. An existing K is kept.
		guard BeamioWalletCredentialBlob.createIfMissing(eoa: account) else { return (false, nil, "unavailable") }
		guard let blob = BeamioWalletCredentialBlob.seal(phrase: Data(phrase.utf8), eoa: account) else {
			return (false, nil, "unavailable")
		}
		result["blob"] = blob
		return (true, result, nil)
	}

	/// The unseal answer of walletCredential: the blob opens with the account's key, and the phrase derives the current account.
	/// Any failure is `unavailable`; a passcode lock is `locked`, and nothing is opened past it.
	static func walletCredentialUnsealOutcome(blob: String) -> (ok: Bool, result: [String: Any]?, error: String?) {
		guard let account = recordAccount() else { return (false, nil, "no_key") }
		guard var phrase = BeamioWalletCredentialBlob.open(hex: blob, eoa: account) else { return (false, nil, "unavailable") }
		defer { BeamioNativeWallet.wipe(&phrase) }
		let text = String(decoding: phrase, as: UTF8.self)
		guard case .key(var derived) = BeamioMnemonicDerivation.derive(phrase: text) else { return (false, nil, "unavailable") }
		defer { BeamioNativeWallet.wipe(&derived) }
		guard BeamioNativeEthSigner.address(privateKey: derived)?.lowercased() == account else { return (false, nil, "unavailable") }
		return (true, ["eoa": account, "credentialKind": "mnemonic", "mnemonic": text], nil)
	}

	/// The answer of walletEoaAddress ((c), (d)): the public address of the record account, at G1 and G2. It is checked
	/// against the key the native store holds (derived address = record EOA) before it is returned. The key itself is never returned.
	static func walletEoaAddressOutcome() -> (ok: Bool, result: [String: Any]?, error: String?) {
		switch nativeGate() {
		case .g0: return (false, nil, "no_key")
		case .g1, .g2: break
		}
		guard let eoa = recordAccount(), BeamioNativeWallet.keyAccountGate(eoa: eoa) == nil,
		      let key = BeamioNativeWallet.keyStore.read(eoa: eoa) else {
			return (false, nil, "unavailable")
		}
		let derived = BeamioNativeEthSigner.address(privateKey: [UInt8](key))?.lowercased()
		guard derived == eoa else { return (false, nil, "unavailable") }
		return (true, ["eoa": eoa], nil)
	}

	/// Fields that never reach the bridge with the two page commands. A hit answers `key_over_bridge_refused`.
	static let pageCredentialFields: Set<String> = [
		"privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
		"recoveryCode", "pin", "password", "accountPassword",
	]

	/// The fields `identityPublic` refuses (spec): the list of, plus privateKeyArmor and encrypKeyArmored.
	static let identityCredentialFields: Set<String> = pageCredentialFields.union(["privateKeyArmor", "encrypKeyArmored"])

	/// The reqId and field checks of the two page commands. Returns the error code, or nil when the command may
	/// run. The order: reqId (answered with null when invalid), credential fields, then any other field.
	private static func pageOpenRefusal(_ body: [String: Any]) -> String? {
		if body.keys.contains(where: { pageCredentialFields.contains($0) }) { return "key_over_bridge_refused" }
		if body.keys.contains(where: { $0 != "type" && $0 != "reqId" }) { return "bad_request" }
		return nil
	}

	/// `pgpUpgradeRetry {type, reqId, accountKey}` (25.52Y.63 第 2 条): the ack, then the `pgpUpgradeState` event. The rules are in
	/// BeamioPGPUpgradeRetry. Never answers `unknown_command` (25.52Y.96 第 3 条).
	private static func pgpUpgradeRetry(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		let account = BeamioConetChatSignBroker.currentSignerEoa().lowercased()
		if let refused = BeamioPGPUpgradeRetry.refusal(body, account: account) {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: refused))
			return
		}
		emitEvent(["type": "ack", "reqId": echo, "ok": true, "accepted": true])
		emitEvent(["type": "pgpUpgradeState", "code": BeamioPGPUpgradeRetry.decide(eoa: account).rawValue])
	}

	private static let accountCreateLock = NSLock()
	private static var pendingAccountCreateReqId: Any?
	/// Whether the open page has sent a result: a failure keeps the page open, and a close then sends nothing.
	private static var accountCreateResultSent = false
	/// The reqIds whose page has closed or ended with `ok`. Opening one of them again is `not_available`, and the set is kept for the
	/// process lifetime: a new page does not clear it. Only the current page's pointer is cleared when a page closes. The test gate helper clears it.
	private static var finishedAccountCreateKeys = Set<String>()
	/// The id of the binding query of `nativeAccountCreateOpen` that is pending; nil when none is. Cleared by the first answer.
	private static var lookupQueryId: Int?
	private static var queryCounter = 0
	/// The watchdog of a pending query: at the 10-second total, an unanswered query is answered `lookup_unavailable`.
	/// Tests shorten it.
	static var queryWatchdog: TimeInterval = BeamioAccountBindingLookup.totalBudget

	/// A reqId as a record key: a string and an integer never match.
	private static func accountCreateKey(_ id: Any) -> String {
		if let text = id as? String { return "s:" + text }
		if let number = id as? Int { return "i:\(number)" }
		return "?"
	}

	/// `nativeAccountCreateOpen {reqId, account}` (spec to): G0 only, and only after the binding lookup
	/// has found no binding. G1 and G2 answer `not_available` and open nothing.
	/// No host: `not_supported`. `ok` only when the host reports that the page is open. The page sends its one result through
	/// `BeamioNativeAccountCreate.create(store:)` (the generation and the write), which sends the result through `finishAccountCreate`.
	private static func nativeAccountCreateOpen(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		// The account input is the one field this command takes beyond type and reqId. It is checked as a field of its own.
		var rest = body
		rest.removeValue(forKey: "account")
		if let refused = pageOpenRefusal(rest) {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: refused))
			return
		}
		guard let account = BeamioAccountBindingLookup.parse(body["account"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "bad_request"))
			return
		}
		// The host is judged first (N-21, N-25): no host is not_supported in any state. G1 and G2 then answer not_available
		// without calling the host.
		guard let host = BeamioNativeAccountCreate.onCreateRequired else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_supported"))
			return
		}
		// one page at a time. While the page is open, the same reqId is answered again without showing the page, and another
		// reqId is refused. The reqId of the last page that closed or ended with `ok` is refused until another page opens.
		accountCreateLock.lock()
		let openedReqId = pendingAccountCreateReqId
		let finishedKeys = finishedAccountCreateKeys
		accountCreateLock.unlock()
		if let openedReqId {
			if sameReqId(openedReqId, echo) { emitAccountCreateAck(echo, page: "opened") } else { emitPageAck(echo, opened: false) }
			return
		}
		if finishedKeys.contains(accountCreateKey(echo)) {
			emitPageAck(echo, opened: false)
			return
		}
		// M-1: while a binding query is pending, every open is refused, the same reqId included. No second query starts.
		accountCreateLock.lock()
		let queryPending = lookupQueryId != nil
		accountCreateLock.unlock()
		if queryPending {
			emitPageAck(echo, opened: false)
			return
		}
		guard nativeGate() == .g0 else {
			emitPageAck(echo, opened: false)
			return
		}
		// step 0: the binding lookup runs before the first screen. The creation step (the host and, after it, the
		// generation) runs only on no binding, and the gate is judged again at that point.
		// the query is answered once: by the lookup, or by the watchdog at the 10-second total, whichever comes first.
		// A later answer of the same query changes nothing.
		accountCreateLock.lock()
		queryCounter += 1
		let queryId = queryCounter
		lookupQueryId = queryId
		accountCreateLock.unlock()
		let answer: (BeamioAccountBindingLookup.Outcome) -> Void = { outcome in
			accountCreateLock.lock()
			let current = lookupQueryId == queryId
			if current { lookupQueryId = nil }
			accountCreateLock.unlock()
			guard current else { return }
			switch outcome {
			case .noBinding:
				guard nativeGate() == .g0 else {
					emitPageAck(echo, opened: false)
					return
				}
				// PY.18: the creation page opens only when the admission holds: (a) legacy confirmed empty, (b) pointer empty, (c) no native
				// key, (d) no page copy, (e) no write failure latched. The binding answers (already_bound, the recovery page) are not creation and
				// are not refused by it. A refusal here is not_available with no page and no creation result; the reason is internal only.
				if BeamioShellRecord.creationRefusal(device: BeamioShellRecord.productionDevice.load(), store: BeamioShellRecord.EncryptedShellRecordStore.production) != nil {
					emitPageAck(echo, opened: false)
					return
				}
				// A page that opened while the lookup ran holds the one page: the same reqId is answered again, another is refused.
				accountCreateLock.lock()
				let openedMeanwhile = pendingAccountCreateReqId
				accountCreateLock.unlock()
				if let openedMeanwhile {
					if sameReqId(openedMeanwhile, echo) { emitAccountCreateAck(echo, page: "opened") } else { emitPageAck(echo, opened: false) }
					return
				}
				let opened = host()
				if opened {
					accountCreateLock.lock()
					pendingAccountCreateReqId = echo
					accountCreateResultSent = false
					// a new page does not clear the set of finished reqIds.
					accountCreateLock.unlock()
					emitAccountCreateAck(echo, page: "opened")
				} else {
					emitPageAck(echo, opened: false)
				}
			case .alreadyBound:
				// No creation page and no EOA. The open is answered `ok:true` with `page: none`: the outcome is the result
				// event's code, which tells the page to open the recovery page (step 4).
				emitAccountCreateAck(echo, page: "none")
				emitResultEvent(accountCreateResultEvent(reqId: echo, code: "already_bound"))
			case .unavailable:
				// Nothing is generated and no first screen is shown; the page retries (step 3). Answered `ok:true`, `page: none`.
				emitAccountCreateAck(echo, page: "none")
				emitResultEvent(accountCreateResultEvent(reqId: echo, code: "lookup_unavailable"))
			}
		}
		DispatchQueue.main.asyncAfter(deadline: .now() + queryWatchdog) {
			answer(.unavailable("timeout"))
		}
		BeamioAccountBindingLookup.run(account, completion: answer)
	}

	/// Whether a creation page is open for `nativeAccountCreateOpen`. Nothing is generated without one.
	static func accountCreatePageOpen() -> Bool {
		accountCreateLock.lock()
		defer { accountCreateLock.unlock() }
		return pendingAccountCreateReqId != nil
	}

	/// The page's `nativeAccountCreateResult` (25.52Y.137 第 6 项, 25.52Y.138 第 1 项): `{type, reqId, ok, result: {code, eoa?, cleanupPending?}}`.
	/// `ok` is true only for code `ok`. `cleanupPending` appears only with `ok` (false: no pending mark). `eoa` appears only with `ok` and `already_exists`.
	static func accountCreateResultEvent(reqId: Any, code: String, eoa: String? = nil) -> [String: Any] {
		var result: [String: Any] = ["code": code]
		if code == "ok" { result["cleanupPending"] = false }
		if let eoa, code == "ok" || code == "already_exists" { result["eoa"] = eoa }
		return ["type": "nativeAccountCreateResult", "reqId": reqId, "ok": code == "ok", "result": result]
	}

	/// What the intake did with one native result (group A). `forwarded` is true only when the event went to the
	/// page; a drop carries its reason code and, for `field_not_allowed`, the names of the fields (never their values).
	struct AccountCreateDelivery: Equatable {
		let forwarded: Bool
		let reason: String?
		let fields: [String]

		static let forward = AccountCreateDelivery(forwarded: true, reason: nil, fields: [])
		static func drop(_ reason: String, fields: [String] = []) -> AccountCreateDelivery {
			AccountCreateDelivery(forwarded: false, reason: reason, fields: fields)
		}
	}

	private static let accountCreateFields: Set<String> = ["type", "reqId", "code", "eoa"]
	/// The result codes of the creation page (Y.163 第 12 項 adds not_ready).
	private static let accountCreateCodes: Set<String> = [
		"ok", "cancelled", "already_exists", "write_failed", "readback_failed", "already_bound", "lookup_unavailable", "not_ready", "bad_request",
	]

	/// The native layer's one result for the open creation page. Every result that carries the page's
	/// reqId counts as a result of the page, forwarded or dropped (NC-16). A failure keeps the page open for a retry;
	/// `ok` (and `cancelled`) close it. A result with another reqId is dropped and changes nothing.
	@discardableResult
	static func deliverAccountCreateResult(_ raw: [String: Any]) -> AccountCreateDelivery {
		accountCreateLock.lock()
		guard let reqId = pendingAccountCreateReqId else {
			accountCreateLock.unlock()
			return .drop("no_page")
		}
		guard let given = raw["reqId"], sameReqId(given, reqId) else {
			accountCreateLock.unlock()
			return .drop("reqid_mismatch")
		}
		accountCreateResultSent = true
		// step 1: a field outside the base set is refused as a whole. The W fields (privateKeyArmor, mnemonicPhrase, recoveryWords) are outside it: they never reach the page (25.52Y.148).
		let extra = raw.keys.filter { !accountCreateFields.contains($0) }.sorted()
		if !extra.isEmpty {
			accountCreateLock.unlock()
			return .drop("field_not_allowed", fields: extra)
		}
		guard raw["type"] as? String == "nativeAccountCreateResult" else {
			accountCreateLock.unlock()
			return .drop("unknown_type")
		}
		guard let code = raw["code"] as? String, accountCreateCodes.contains(code) else {
			accountCreateLock.unlock()
			return .drop("unknown_code")
		}
		var eoaOut: String?
		if code == "ok" {
			guard let eoa = raw["eoa"] as? String, isCanonicalAddress(eoa), eoa == eoa.lowercased() else {
				accountCreateLock.unlock()
				return .drop("eoa_invalid")
			}
			eoaOut = eoa
			finishedAccountCreateKeys.insert(accountCreateKey(reqId))
			pendingAccountCreateReqId = nil
		} else {
			// 25.52X.4: `already_exists` may carry the public eoa (lower case, canonical); no other failure may.
			if let carried = raw["eoa"] {
				guard code == "already_exists", let text = carried as? String, isCanonicalAddress(text), text == text.lowercased() else {
					accountCreateLock.unlock()
					return .drop("eoa_not_allowed")
				}
				eoaOut = text
			}
			if code == "cancelled" {
				finishedAccountCreateKeys.insert(accountCreateKey(reqId))
				pendingAccountCreateReqId = nil
			}
		}
		accountCreateLock.unlock()
		let event = accountCreateResultEvent(reqId: reqId, code: code, eoa: eoaOut)
		emitResultEvent(event)
		return .forward
	}

	/// The same reqId in either form the bridge uses (an integer or a string); a different type never matches.
	private static func sameReqId(_ a: Any, _ b: Any) -> Bool {
		if let x = a as? String, let y = b as? String { return x == y }
		if let x = a as? Int, let y = b as? Int { return x == y }
		return false
	}

	/// The SDK's own result for the open page: built here and checked by the same intake as a native result.
	@discardableResult
	static func finishAccountCreate(code: String, eoa: String?) -> Bool {
		accountCreateLock.lock()
		let reqId = pendingAccountCreateReqId
		accountCreateLock.unlock()
		guard let reqId else { return false }
		var raw: [String: Any] = ["type": "nativeAccountCreateResult", "reqId": reqId, "code": code]
		if let eoa { raw["eoa"] = eoa }
		return deliverAccountCreateResult(raw).forwarded
	}

	/// The page is closed by the user: `cancelled` when no result was produced for this page, nothing when one was.
	@discardableResult
	static func closeAccountCreatePage() -> Bool {
		accountCreateLock.lock()
		guard let reqId = pendingAccountCreateReqId else {
			accountCreateLock.unlock()
			return false
		}
		let sent = accountCreateResultSent
		finishedAccountCreateKeys.insert(accountCreateKey(reqId))
		pendingAccountCreateReqId = nil
		accountCreateResultSent = false
		accountCreateLock.unlock()
		if !sent { emitEvent(accountCreateResultEvent(reqId: reqId, code: "cancelled")) }
		return true
	}

	/// The ack of an account-create open: `ok: true` with `page` ("opened" when the creation page is open, "none" when no page
	/// is opened and the outcome is a result event). A refusal has no `page` (see `emitPageAck`).
	private static func emitAccountCreateAck(_ echo: Any, page: String) {
		emitEvent(["type": "ack", "reqId": echo, "ok": true, "page": page])
	}

	/// The ack of a page command: `{type, reqId, ok: true}` when the page is open, `not_available` otherwise.
	private static func emitPageAck(_ echo: Any, opened: Bool) {
		var ack: [String: Any] = ["type": "ack", "reqId": echo, "ok": opened]
		if !opened { ack["error"] = "not_available" }
		emitEvent(ack)
	}

	/// The reqId of the recovery page that is open and has not reported yet (one result per opened page).
	private static var pendingRecoveryReqId: Any?
	/// Whether the open recovery page has produced a result: a failure keeps the page open, and a close then sends nothing.
	private static var recoveryResultSent = false
	private static let recoveryLock = NSLock()

	/// `nativeRecoveryOpen {reqId}` (spec,.2): opens the native recovery page. The page sends one
	/// `nativeRecoveryResult` for this reqId through `finishRecovery`. A second open while one is pending: `not_available`.
	private static func nativeRecoveryOpen(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		if let refused = pageOpenRefusal(body) {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: refused))
			return
		}
		guard let host = BeamioNativeRecovery.onRecoveryRequired else {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_supported"))
			return
		}
		recoveryLock.lock()
		let busy = pendingRecoveryReqId != nil
		recoveryLock.unlock()
		if busy {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_available"))
			return
		}
		let opened = host(BeamioConetChatSignBroker.currentSignerEoa().lowercased())
		if opened {
			recoveryLock.lock()
			pendingRecoveryReqId = echo
			recoveryResultSent = false
			recoveryLock.unlock()
		}
		emitPageAck(echo, opened: opened)
	}

	/// The one `nativeRecoveryResult` of the open recovery page. Returns false when no page is pending. The codes
	/// are the page codes; `eoa` only with `ok` (a lower-case address), `cooldownSec` only with `backoff`.
	@discardableResult
	static func finishRecovery(code: String, eoa: String?, cooldownSec: Int?) -> Bool {
		recoveryLock.lock()
		guard let reqId = pendingRecoveryReqId else {
			recoveryLock.unlock()
			return false
		}
		// One result per confirmation: a failure keeps the page open for a retry; `ok` and `cancelled` close it.
		recoveryResultSent = true
		if code == "ok" || code == "cancelled" { pendingRecoveryReqId = nil }
		recoveryLock.unlock()
		var event: [String: Any] = ["type": "nativeRecoveryResult", "reqId": reqId, "code": code]
		// 25.52Y.152: the ok answer is flat {type, reqId, code, eoa}. No key, phrase, recovery words or PGP field is carried by any answer.
		if code == "ok", let eoa, isCanonicalAddress(eoa) {
			event["eoa"] = eoa.lowercased()
		}
		// 25.52X.4: already_exists carries the public account, when the native layer derived and persisted it. No other answer carries it.
		if code == "already_exists", let eoa, isCanonicalAddress(eoa) {
			event["eoa"] = eoa.lowercased()
		}
		if code == "backoff", let cooldownSec {
			event["cooldownSec"] = cooldownSec
		}
		emitResultEvent(event)
		return true
	}

	/// Whether a recovery page is open and has not closed. A failure result leaves it open.
	static func recoveryPageOpen() -> Bool {
		recoveryLock.lock()
		defer { recoveryLock.unlock() }
		return pendingRecoveryReqId != nil
	}

	/// The recovery page is closed by the user: `cancelled` when no result was produced for this page, nothing when one was.
	@discardableResult
	static func closeRecoveryPage() -> Bool {
		recoveryLock.lock()
		guard let reqId = pendingRecoveryReqId else {
			recoveryLock.unlock()
			return false
		}
		let sent = recoveryResultSent
		pendingRecoveryReqId = nil
		recoveryResultSent = false
		recoveryLock.unlock()
		if !sent { emitEvent(["type": "nativeRecoveryResult", "reqId": reqId, "code": "cancelled"]) }
		return true
	}

	private static func isCanonicalAddress(_ text: String) -> Bool {
		text.count == 42 && text.hasPrefix("0x") && text.dropFirst(2).allSatisfy { $0.isHexDigit }
	}

	/// `gossipSign {reqId, kind, message}` (spec, C2). `kind` defaults to `gossip`. The answer is the signature only;
	/// a refused string gets its vector code and no signature.
	/// an optional top-level `sendId` must be a non-empty string.,: an envelope or group request of a new page
	/// (init declared deferAck) carries `inboundGeneration`; missing, or of the wrong type, it is bad_request. An old page may omit it: its
	/// request takes the generation at arrival. A value of the wrong type is bad_request for any page. None of these fields enters the
	/// signed bytes, which cover `message` only.
	private static func gossipSign(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		let kind = body["kind"] as? String ?? "gossip"
		let message = body["message"] as? String ?? ""
		if let raw = body["sendId"] {
			guard let id = raw as? String, !id.isEmpty else {
				ack(reqId, ok: false, error: "bad_request")
				return
			}
		}
		// the session's account must be the signer. A request of a generation that is no longer current is dropped.
		if ["envelope", "group"].contains(kind) {
			let presented = body["inboundGeneration"] != nil
			let requested = parseInboundGeneration(body["inboundGeneration"])
			if presented, requested == nil {
				ack(reqId, ok: false, error: "bad_request")
				return
			}
			guard let s = currentSession() else {
				ack(reqId, ok: false, error: "not_ready")
				return
			}
			if s.deferAck, requested == nil {
				ack(reqId, ok: false, error: "bad_request")
				return
			}
			let signer = BeamioConetChatSignBroker.currentSignerEoa()
			guard !signer.isEmpty, signer == s.eoa.lowercased() else {
				ack(reqId, ok: false, error: "signer_mismatch")
				return
			}
			if s.deferAck, let requested, requested != BeamioInboxIO.generation { return }
		}
		switch BeamioGossipSign.sign(kind: kind, message: message, eoa: BeamioConetChatSignBroker.currentSignerEoa()) {
		case .success(let signature): ack(reqId, ok: true, result: ["signature": signature])
		case .failure(let code): ack(reqId, ok: false, error: code.rawValue)
		}
	}

	/// X-21 is retired (spec): `walletTransferOnce`, `walletTransferStatus` and `walletTransferSwitched` answer
	/// `not_supported` for any argument. No event, no bytes, no state change.
	private static func x21Retired(_ body: [String: Any]) {
		ack(body["reqId"] as? Int ?? -1, ok: false, error: "not_supported")
	}

	/// `passcodeStatus`: `set`, `locked` and `hasKey`, and `walletState` (additive). No record: the three are false.
	/// `hasKey` is device-level: false in G0, true in G1 and G2. `set` and `locked` follow the record's account.
	/// The public addresses of the keys held: lower case, unique, sorted. nil when any key is unreadable or the enumeration fails (fail closed).
	private static func accountSelectEntries() -> [String]? {
		// Y.163 第 31、32、34(3) 項: the accounts are the valid mnemonics. An invalid or unreadable mnemonic, or a failed listing, is nil.
		let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
		// The same judgement as the snapshot (requirement): a confirmed invalid mnemonic is no credential and is not a failure; an unconfirmed or
		// unreadable one is a read failure (nil).
		guard inventory.enumerated, !inventory.readFailed else { return nil }
		return inventory.valid.map { $0.eoa }.sorted()
	}

	/// method Y: the account whose native record is a v3 envelope, when it is the account of this device (no pointer yet, or the pointer names it).
	private static func cipherAccountOfDevice() -> String? {
		guard let eoa = BeamioCipherUnlock.cipherAccount(store: BeamioNativeWallet.keyStore) else { return nil }
		let pointer = BeamioNativeAccountPointer.get().lowercased()
		return pointer.isEmpty || pointer == eoa ? eoa : nil
	}

	private static func passcodeStatus(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		// method Y: the account of a v3 envelope is present and locked until the page sends the passcode with its envelope; a restart locks it again.
		if let cipher = cipherAccountOfDevice() {
			if let asked = body["eoa"] {
				guard let text = asked as? String, let normalized = BeamioShellPasscodeCommands.normalizedEoa(text) else {
					ack(reqId, ok: false, error: "bad_request")
					return
				}
				guard normalized == cipher else {
					ack(reqId, ok: false, error: "account_mismatch")
					return
				}
			}
			let unlocked = BeamioCipherUnlock.isUnlocked(eoa: cipher)
			ack(reqId, ok: true, result: ["set": true, "locked": !unlocked, "hasKey": true, "walletState": BeamioNativeWalletStateResolver.current().state.rawValue,
			                              "nativeLocked": !unlocked])
			return
		}
		let account = recordAccount() ?? ""
		// v45 s50: an optional `eoa` names the account the page asks about; another account than the current native one is `account_mismatch`
		// (a value that is not an address is `bad_request`).
		if let asked = body["eoa"] {
			guard let text = asked as? String, let normalized = BeamioShellPasscodeCommands.normalizedEoa(text) else {
				ack(reqId, ok: false, error: "bad_request")
				return
			}
			guard normalized == account.lowercased() else {
				ack(reqId, ok: false, error: "account_mismatch")
				return
			}
		}
		let state = account.isEmpty ? BeamioPasscodeAppState.noPasscode : BeamioPasscodeSession.shared.appState(eoa: account)
		guard state != .unknown else {
			ack(reqId, ok: false, error: "unavailable")
			return
		}
		// (additive): the state of the native store, from the pointer and the enumeration. The state only, never material.
		let walletState = BeamioNativeWalletStateResolver.current().state.rawValue
		// v43 s47: `nativeLocked` is the one field the page reads for "the native session is unlocked" (only `false` means unlocked). `locked` keeps its
		// meaning. A locked passcode session is locked; an unlocked one is not; no passcode set is unlocked only when the key record is readable.
		let nativeLocked: Bool
		switch state {
		case .unlocked: nativeLocked = nativeGate() == .g1
		// v45 s50: while the session start is not complete (G1) it is locked, fail closed; the readable record decides only outside G1
		case .noPasscode: nativeLocked = account.isEmpty || nativeGate() == .g1 || BeamioNativeWallet.keyStore.keyRecordState(eoa: account) != .present
		default: nativeLocked = true
		}
		ack(reqId, ok: true, result: ["set": state != .noPasscode, "locked": state == .locked, "hasKey": !account.isEmpty, "walletState": walletState,
		                              "nativeLocked": nativeLocked])
	}

	/// `passcodeRun {mode, copy}`: the shell's overlay runs the flow. The answer is the result code only.
	/// The cleanup environment of the command. The product's own; a test replaces it with an in-memory one.
	nonisolated(unsafe) static var accountCleanupEnvironment: () -> BeamioAccountCleanup.Environment = { BeamioAccountCleanupProduction.environment() }
	/// Repeated callbacks run one after another: a second run starts only when the first has finished, and then finds what is left (idempotent by what it finds).
	private static let accountCleanupLock = NSLock()

	/// `accountCleanupOld {accountKey, idempotencyKey}` (v196 section 216). The page sends it once both sides read back the same address. The answer is the
	/// accountCleanupAck of `BeamioAccountCleanup.Answer.ack`; the bridge envelope has already refused a body without a reqId (bad_request, null reqId) before this runs. Not a key over the bridge: only an address and a name.
	private static func accountCleanupOld(_ body: [String: Any]) {
		let key = body["accountKey"] as? String ?? ""
		let idem = body["idempotencyKey"] as? String ?? ""
		accountCleanupLock.lock()
		let answer = BeamioAccountCleanup.run(accountKey: key, idempotencyKey: idem, env: accountCleanupEnvironment())
		accountCleanupLock.unlock()
		NSLog("[BeamioConetChat] accountCleanupOld ok=%d error=%@ pending=%d kept=%d deleted=%d", answer.ok ? 1 : 0, answer.error ?? "-", answer.cleanupPending ? 1 : 0, answer.keptUnattributed, answer.deleted)
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else { return }
		emitEvent(answer.ack(reqId: echo))
	}

	private static func passcodeRun(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		guard let mode = BeamioPasscodeMode(rawValue: body["mode"] as? String ?? "") else {
			ack(reqId, ok: false, error: "bad_mode")
			return
		}
		guard let present = BeamioPasscodePresenter.present else {
			ack(reqId, ok: true, result: ["code": BeamioPasscodeRunResult.error.code])
			return
		}
		let eoa = BeamioConetChatSignBroker.currentSignerEoa()
		let copy = body["copy"] as? [String: Any] ?? [:]
		present(mode, eoa, copy) { result in
			var payload: [String: Any] = ["code": result.code]
			if case .backoff(let seconds) = result { payload["cooldownSec"] = seconds }
			ack(reqId, ok: true, result: payload)
			emitEvent(BeamioPasscodeSession.shared.statePayload(eoa: eoa, reason: nil))
		}
	}

	// MARK: - Call layer entry (no page involved)

	/// Native call layer: a VoIP push arrived, a call rings or is up, or the app
	/// came to the foreground. Opens / resumes the mailbox listen from the stored
	/// identity. Same as `startFromStore`.
	@discardableResult
	public static func wake(reason: String) -> Bool {
		// the first moment of a wake: the OpenPGP page boots now, so that the offer that arrives next does not wait for a cold boot
		BeamioOpenPgpHost.shared.prewarm()
		return startFromStore(reason: reason)
	}

	/// Native call layer: the call is over. Applies an owed background pause now.
	public static func release(reason: String) {
		DispatchQueue.main.async {
			if pauseOwed, keepListenWhile?() != true {
				NSLog("[BeamioConetChat] released (%@); owed pause applied", reason)
				requestPause()
			}
		}
	}

	/// Every listen path reports its status here. A listen handshake sends the unconfirmed acks again now.
	private static func noteListenStatus(_ status: String, _ detail: String?) {
		listenConnected = status == "listening"
		if status == "listening", detail == "handshake" { retryUnconfirmedGossipAcksNow() }
	}

	private static func emitStatus(_ status: String, _ detail: String?) {
		noteListenStatus(status, detail)
		var payload: [String: Any] = ["status": status]
		if let detail { payload["detail"] = detail }
		emitEvent(["type": "event:status", "payload": payload])
	}

	static let setRoutesMaxEntries = 256
	static let setRoutesMaxArmorBytes = 32 * 1024
	static let receiptQueueMax = 128
	static let receiptQueueTTL: TimeInterval = 600

	/// `setRoutes`: a full replacement of the peers' routes. `eoa` is required and must be the session's account.
	/// More than 256 entries, an armor over 32 KB or a non-array answers `bad_request` and changes nothing; an unusable entry is dropped alone.
	/// Memory only; the log keeps counts. Internal for the tests.
	static func handleSetRoutes(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? -1
		func reply(_ ok: Bool, _ error: String? = nil, _ result: [String: Any]? = nil) {
			if reqId >= 0 { ack(reqId, ok: ok, result: result, error: error) }
		}
		guard let s = currentSession() else { reply(false, "not_ready"); return }
		guard let eoaRaw = body["eoa"] as? String, !eoaRaw.isEmpty else { reply(false, "bad_request"); return }
		guard !s.eoa.isEmpty, normalizeAddress(eoaRaw) == normalizeAddress(s.eoa) else {
			reply(false, "signer_mismatch")
			return
		}
		guard let raw = body["routes"] as? [Any], raw.count <= setRoutesMaxEntries else { reply(false, "bad_request"); return }
		var byEoa: [String: [String: Any]] = [:]
		var order: [String] = []
		var dropped = 0
		for item in raw {
			guard let entry = item as? [String: Any] else { dropped += 1; continue }
			let userPgp = entry["userPublicKeyArmored"] as? String ?? ""
			let routerPgp = entry["routerArmoredPublicKey"] as? String ?? ""
			if userPgp.utf8.count > setRoutesMaxArmorBytes || routerPgp.utf8.count > setRoutesMaxArmorBytes {
				reply(false, "bad_request")
				return
			}
			let eoa = normalizeAddress(String(entry["eoaAddress"] as? String ?? entry["eoa"] as? String ?? ""))
			guard isEvmAddress(eoa), userPgp.contains("BEGIN PGP PUBLIC KEY"), routerPgp.contains("BEGIN PGP PUBLIC KEY") else {
				dropped += 1
				continue
			}
			if byEoa[eoa] == nil { order.append(eoa) }
			byEoa[eoa] = ["eoaAddress": eoa, "userPublicKeyArmored": userPgp, "routerArmoredPublicKey": routerPgp]
		}
		s.routes = order.compactMap { byEoa[$0] }
		emitEvent(["type": "event:log", "level": "info", "message": "setRoutes kept=\(order.count) dropped=\(dropped)"])
		reply(true, nil, ["accepted": order.count, "dropped": dropped])
		flushQueuedReceipts(session: s)
	}

	private static func isEvmAddress(_ a: String) -> Bool {
		a.count == 42 && a.hasPrefix("0x") && a.dropFirst(2).allSatisfy { $0.isHexDigit }
	}

	private static func handleSetNodes(_ body: [String: Any]) {
		guard let s = currentSession() else { return }
		if let nodes = body["nodes"] as? [[String: Any]] {
			s.nodes = parseNodes(nodes)
			persistEntryKeys(s.nodes)
		}
	}

	/// Keeps an entry's PGP key in the device roster, so a background listen and a later send have it without the page.
	/// Only fills a node whose stored key is empty: the chain roster stays the source, and no node is added or removed.
	static func persistEntryKeys(_ nodes: [Node]) {
		let keyed = nodes.filter { !$0.armoredPublicKey.isEmpty }
		guard !keyed.isEmpty else { return }
		var roster = BeamioChatPgpKeychain.loadSiNodes()
		guard !roster.isEmpty else { return }
		var changed = false
		for n in keyed {
			guard let ip = BeamioSiCipherPost.normalizeIp(n.ip) else { continue }
			for i in roster.indices where roster[i].ip == ip && roster[i].armoredPublicKey.isEmpty {
				roster[i].armoredPublicKey = n.armoredPublicKey
				changed = true
			}
		}
		if changed { _ = BeamioChatPgpKeychain.storeChainRoster(nodes: roster, mailboxIp: nil) }
	}

	// MARK: - Send

	/// the generation a page request was initiated in. A new page (its init declared deferAck) sends `inboundGeneration`
	/// at the top level; a missing or invalid value gives nil, and the request is bad_request. An old page does not send it: the generation at
	/// arrival is taken.
	static func initiationGeneration(_ s: Session, body: [String: Any]) -> Int? {
		// (audit of 03b56bf): a field present with the wrong type is bad_request from any page, a new page or an old one.
		if body["inboundGeneration"] != nil, parseInboundGeneration(body["inboundGeneration"]) == nil {
			return nil
		}
		guard s.deferAck else { return BeamioInboxIO.generation }
		return parseInboundGeneration(body["inboundGeneration"])
	}

	/// a single send. Every answer goes through `reply`, which answers only while the request's generation (`initiated`)
	/// is still current. The generation is checked before signing, before the POST, and before each answer; an expired request is silent.
	/// A valid request still in flight after `inFlightTimeout` answers send_timeout, once.
	private static func handleSend(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		// v109 section 122: the chat mailbox carries no audio, video or channel control. Judged before the session, the sendId and anything else.
		if BeamioVoiceMailboxGuard.refusesChatText(String(body["payload"] as? String ?? "")) {
			ack(reqId, ok: false, error: "not_supported")
			return
		}
		guard let s = currentSession(),
		      let to = body["to"] as? [String: Any]
		else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		guard let initiated = initiationGeneration(s, body: body) else {
			(body["_receiptDone"] as? () -> Void)?()
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		let receiptDone = body["_receiptDone"] as? () -> Void
		let reply = BeamioInFlightReply(timeout: inFlightTimeout, isCurrent: { BeamioInboxIO.generation == initiated }) { ok, result, error in
			ack(reqId, ok: ok, result: result, error: error)
			receiptDone?()
		}
		let payload = String(body["payload"] as? String ?? "")
		let sendId = String(body["sendId"] as? String ?? UUID().uuidString)
		let noPush = (body["beamioNoPush"] as? Bool) ?? false
		let userPgp = String(to["userPublicKeyArmored"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
		let mailboxRoute = String(to["routerArmoredPublicKey"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
		// a sendId this session has sent, or has in flight, is not posted again. A retry joins the send in flight, or is
		// answered from the stored result; each request is answered once.
		switch s.joinSend(sendId, answer: { ok, result, error in reply.send(ok: ok, result: result, error: error) }) {
		case .started:
			break
		case .joined:
			return
		case .replayed(let ok, let result, let error):
			reply.send(ok: ok, result: result, error: error)
			return
		}
		// The answer of this request. `posted`: its POST was made, so the sendId keeps the result for its retries.
		func answer(_ ok: Bool, _ result: [String: Any]?, _ error: String?, posted: Bool) {
			s.finishSend(sendId, ok: ok, result: result, error: error, posted: posted)
			reply.send(ok: ok, result: result, error: error)
		}
		guard userPgp.contains("BEGIN PGP PUBLIC KEY") else {
			answer(false, nil, "missing_recipient_pgp", posted: false)
			return
		}
		// Every send is wrapped to the recipient's mailbox route key, so the entry
		// never sees the recipient key ID. Without that route: not sent.
		guard mailboxRoute.contains("BEGIN PGP PUBLIC KEY") else {
			answer(false, nil, "recipient_mailbox_unknown", posted: false)
			return
		}
		let host = BeamioOpenPgpHost.shared
		// before signing.
		guard BeamioInboxIO.generation == initiated else {
			receiptDone?()
			s.forgetSend(sendId)
			return
		}
		requestSessionSignature(s, message: payload) { signResult in
			switch signResult {
			case .failure(let err):
				answer(false, nil, signFailureCode(err), posted: false)
			case .success(let signature):
				let envelope: [String: Any] = [
					"timestamp": Int(Date().timeIntervalSince1970 * 1000),
					"text": payload,
					"from": s.eoa,
					"signMessage": signature,
				]
				host.encryptUtf8JsonBase64(jsonObject: envelope, recipientPublicArmor: userPgp) { encResult in
					switch encResult {
					case .failure:
						answer(false, nil, "encrypt_failed", posted: false)
					case .success(let armor):
						func postInner(_ finalArmor: String) {
							// /: before the POST.
							guard BeamioInboxIO.generation == initiated else {
								receiptDone?()
								s.forgetSend(sendId)
								return
							}
							DispatchQueue.global(qos: .userInitiated).async {
								let ok = postToEntriesSync(armor: finalArmor, mailboxRoute: mailboxRoute, session: s)
								DispatchQueue.main.async {
									answer(true, ["sent": ok, "sendId": sendId], nil, posted: true)
								}
							}
						}
						host.wrapArmorToMailboxWork(
							innerArmor: armor,
							mailboxRoutePublicArmor: mailboxRoute,
							noPush: noPush
						) { wrapResult in
							switch wrapResult {
							case .failure:
								answer(false, nil, "wrap_failed", posted: false)
							case .success(let wrapped):
								postInner(wrapped)
							}
						}
					}
				}
			}
		}
	}

	// MARK: - Group

	/// to: a group text, with the same stages as a single send. Each member's POST is checked before it goes out.
	private static func handleSendGroup(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		if let request = body["request"] as? [String: Any],
		   BeamioVoiceMailboxGuard.refusesChatText(String(request["body"] as? String ?? request["text"] as? String ?? "")) {
			ack(reqId, ok: false, error: "not_supported")
			return
		}
		guard let s = currentSession(),
		      let request = body["request"] as? [String: Any],
		      let roster = request["roster"] as? [String: Any],
		      let members = roster["members"] as? [[String: Any]]
		else {
			ack(reqId, ok: false, error: "bad_group_request")
			return
		}
		guard let initiated = initiationGeneration(s, body: body) else {
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		let reply = BeamioInFlightReply(timeout: inFlightTimeout, isCurrent: { BeamioInboxIO.generation == initiated }) { ok, result, error in
			ack(reqId, ok: ok, result: result, error: error)
		}
		let bodyText = String(request["body"] as? String ?? request["text"] as? String ?? "")
		let host = BeamioOpenPgpHost.shared
		// before signing.
		guard BeamioInboxIO.generation == initiated else { return }
		requestSessionSignature(s, message: bodyText) { signResult in
			guard case .success(let signature) = signResult else {
				if case .failure(let err) = signResult {
					reply.send(ok: false, error: signFailureCode(err, fallback: "group_sign_failed"))
				}
				return
			}
			let envelope: [String: Any] = [
				"timestamp": Int(Date().timeIntervalSince1970 * 1000),
				"text": bodyText,
				"from": s.eoa,
				"signMessage": signature,
				"groupId": String(request["groupId"] as? String ?? roster["groupId"] as? String ?? ""),
			]
			DispatchQueue.global(qos: .userInitiated).async {
				var delivered = 0
				let group = DispatchGroup()
				let deliverLock = NSLock()
				for member in members {
					let pgp = String(member["userPublicKeyArmored"] as? String
						?? member["pgpPublicKeyArmored"] as? String ?? "")
					let route = String(member["routerArmoredPublicKey"] as? String ?? "")
					// Wrapped to the member's mailbox: no route, no delivery.
					guard pgp.contains("BEGIN PGP PUBLIC KEY"), route.contains("BEGIN PGP PUBLIC KEY") else { continue }
					group.enter()
					host.encryptUtf8JsonBase64(jsonObject: envelope, recipientPublicArmor: pgp) { enc in
						guard case .success(let userArmor) = enc else { group.leave(); return }
						host.wrapArmorToMailboxWork(innerArmor: userArmor, mailboxRoutePublicArmor: route, noPush: false) { wrap in
							defer { group.leave() }
							guard case .success(let armor) = wrap else { return }
							// /: before each member's POST.
							guard BeamioInboxIO.generation == initiated else { return }
							let ok = postToEntriesSync(armor: armor, mailboxRoute: route, session: s)
							if ok {
								deliverLock.lock()
								delivered += 1
								deliverLock.unlock()
							}
						}
					}
				}
				group.wait()
				DispatchQueue.main.async {
					reply.send(ok: true, result: ["delivered": delivered, "members": members.count])
				}
			}
		}
	}

	private static func handleIssueGroupRoster(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		if let request = body["request"] as? [String: Any],
		   let members = (request["roster"] as? [String: Any])?["members"] as? [[String: Any]],
		   !members.isEmpty {
			handleSendGroup(body)
			return
		}
		ack(reqId, ok: true, result: ["ok": true])
	}

	private static func handleIssueGroupTombstone(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		if body["request"] != nil {
			handleSendGroup(body)
			return
		}
		ack(reqId, ok: true, result: ["ok": true])
	}

	// MARK: - Presence / native wake

	private static func handleQueryPresence(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession() else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let target = normalizeAddress(String(body["targetWallet"] as? String ?? body["wallet"] as? String ?? ""))
		let routeKey = String(body["routerArmoredPublicKey"] as? String
			?? (body["route"] as? [String: Any])?["routerArmoredPublicKey"] as? String ?? "")
		guard !target.isEmpty, routeKey.contains("BEGIN PGP PUBLIC KEY") else {
			ack(reqId, ok: false, error: "bad_presence")
			return
		}
		postSignedMailboxCommand(
			session: s,
			routerArmoredPublicKey: routeKey,
			command: [
				"command": "wallet_online_query",
				"walletAddress": s.eoa,
				"targetWallet": target,
				"timestamp": Int(Date().timeIntervalSince1970),
			]
		) { ok, _ in
			ack(reqId, ok: true, result: ["ok": ok, "online": false, "wallet": target])
			if ok {
				emitEvent([
					"type": "event:presence",
					"payload": ["wallet": target, "online": true, "ok": true],
				])
			}
		}
	}

	private static func handleQueryNativeWake(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession() else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let target = normalizeAddress(String(body["targetWallet"] as? String ?? body["wallet"] as? String ?? ""))
		let routeKey = String(body["routerArmoredPublicKey"] as? String
			?? (body["route"] as? [String: Any])?["routerArmoredPublicKey"] as? String ?? "")
		guard !target.isEmpty, routeKey.contains("BEGIN PGP PUBLIC KEY") else {
			ack(reqId, ok: false, error: "bad_native_wake")
			return
		}
		postSignedMailboxCommand(
			session: s,
			routerArmoredPublicKey: routeKey,
			command: [
				"command": "wallet_native_wake_query",
				"walletAddress": s.eoa,
				"targetWallet": target,
				"timestamp": Int(Date().timeIntervalSince1970),
			]
		) { ok, _ in
			ack(reqId, ok: true, result: ["ok": ok, "nativeWakeable": false, "wallet": target])
			if ok {
				emitEvent([
					"type": "event:nativeWake",
					"payload": ["wallet": target, "nativeWakeable": true, "ok": true],
				])
			}
		}
	}

	// MARK: - History

	/// `historyDeleteMessage`: one message, by (convKey, messageId = sendKey). Exactly one ack. The page record is not written.
	private static func historyDeleteMessage(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(["type": "ack", "reqId": NSNull(), "ok": false, "error": "bad_request"])
			return
		}
		// the key record exists and cannot be read at G2: not_ready, once, nothing deleted (not busy).
		if historyKeyUnreadable() {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
			return
		}
		let convKey = body["convKey"] as? String ?? ""
		guard isDeleteConvKey(convKey) else { return deleteAck(echo, ["code": "bad_request", "names": ["convKey"]]) }
		let messageId = body["messageId"] as? String ?? ""
		guard isDeleteMessageId(messageId) else { return deleteAck(echo, ["code": "bad_request", "names": ["messageId"]]) }
		guard let store = currentSession()?.localStore, let deleted = store.deleteMessage(convKey: convKey, sendKey: messageId) else {
			return deleteAck(echo, ["code": "busy"])
		}
		deleteAck(echo, ["code": "ok", "deleted": deleted])
	}

	/// `historyDeleteConversation`: one conversation, by convKey. Exactly one ack. The page record is not written.
	private static func historyDeleteConversation(_ body: [String: Any]) {
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emitEvent(["type": "ack", "reqId": NSNull(), "ok": false, "error": "bad_request"])
			return
		}
		// the key record exists and cannot be read at G2: not_ready, once, nothing deleted (not busy).
		if historyKeyUnreadable() {
			emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: "not_ready"))
			return
		}
		let convKey = body["convKey"] as? String ?? ""
		guard isDeleteConvKey(convKey) else { return deleteAck(echo, ["code": "bad_request", "names": ["convKey"]]) }
		guard let store = currentSession()?.localStore, let deleted = store.deleteConversation(convKey: convKey) else {
			return deleteAck(echo, ["code": "busy"])
		}
		deleteAck(echo, ["code": "ok", "deleted": deleted])
	}

	/// The ack of a deletion: one `ack` envelope, the result in `result`.
	/// the current session's account has a key record that cannot be read (a storage-derived Locked, not the passcode lock).
	private static func historyKeyUnreadable() -> Bool {
		let account = currentSession()?.eoa ?? ""
		return !account.isEmpty && BeamioNativeWallet.keyStore.keyRecordState(eoa: account) == .unreadable
	}

	private static func deleteAck(_ reqId: Any, _ result: [String: Any]) {
		emitEvent(BeamioChatRouteRegister.ackEnvelope(reqId: reqId, result: result, error: nil))
	}

	/// a conversation address, `0x` and 40 lowercase hexadecimal digits.
	static func isDeleteConvKey(_ value: String) -> Bool {
		value.count == 42 && value.hasPrefix("0x")
			&& value.dropFirst(2).allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
	}

	/// a message identifier, 1 to 128 visible ASCII characters.
	static func isDeleteMessageId(_ value: String) -> Bool {
		(1...128).contains(value.utf8.count) && value.utf8.allSatisfy { (0x21...0x7e).contains($0) }
	}

	private static func handleHistoryLoad(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let hist = currentSession()?.history, hist.isReady() else {
			// History key derivation (two PWA signatures) may still be in flight: not an error.
			ack(reqId, ok: true)
			return
		}
		hist.load(
			options: body["options"] as? [String: Any],
			emitBuffer: { peer, entries, isTail in
				emitEvent([
					"type": "event:historyBuffer",
					"payload": ["peer": peer, "entries": entries.map(\.json), "isTail": isTail],
				])
			},
			done: { ack(reqId, ok: true) }
		)
	}

	/// Callers already reported as unbounded in this process (spec 12.2: each logged once).
	private static var unboundedCallers = Set<String>()

	private static func handleHistoryRead(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		// Spec 12.2 stage one: a call without `limit` keeps its full result and is counted, not refused.
		let options = body["options"] as? [String: Any]
		if BeamioConetChatHistoryStore.intValue(options?["limit"]) == nil {
			let caller = String((options?["caller"] as? String) ?? "unknown").prefix(64).description
			lock.lock()
			let first = unboundedCallers.insert(caller).inserted
			lock.unlock()
			NSLog("historyRead.unbounded caller=%@", caller)
			if first {
				emitEvent(["type": "event:log", "level": "info", "message": "historyRead.unbounded caller=\(caller)"])
			}
		}
		guard let hist = currentSession()?.history, hist.isReady() else {
			ack(reqId, ok: true, result: [[String: Any]]())
			return
		}
		hist.read(options: body["options"] as? [String: Any]) { entries in
			ack(reqId, ok: true, result: entries.map(\.json))
		}
	}

	private static func handleHistoryAppend(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let hist = currentSession()?.history, hist.isReady(),
		      let entry = body["entry"] as? [String: Any]
		else {
			ack(reqId, ok: false, error: "history_not_ready")
			return
		}
		hist.append(entry: entry) { ok in
			ack(reqId, ok: ok, result: ["ok": ok], error: ok ? nil : "append_failed")
		}
	}

	// MARK: - Local chat library (spec 6.2, 12)

	/// `historyListConversations` (spec 6.7): session list, newest first. Empty while locked.
	private static func handleHistoryListConversations(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let local = currentSession()?.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		do {
			let page = try local.listConversations(limit: body["limit"] as? Int ?? 100, cursor: body["cursor"] as? String)
			let rows: [[String: Any]] = page.rows.map { row in
				["convKey": row.convKey, "lastSortTs": row.lastSortTs, "lastStableId": row.lastStableId,
				 "lastPreview": row.lastPreview, "pendingCount": row.pendingCount]
			}
			let next: Any = page.nextCursor ?? NSNull()
			ack(reqId, ok: true, result: ["conversations": rows, "nextCursor": next])
		} catch {
			ack(reqId, ok: false, error: "cursor_invalid")
		}
	}

	private static func handleHistoryOpenConversation(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let local = currentSession()?.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		guard let conv = (body["convKey"] as? String)?.lowercased(), !conv.isEmpty,
		      let vp = parseViewport(body["viewport"])
		else {
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		ack(reqId, ok: true, result: pageJSON(local.openConversation(convKey: conv, viewport: vp)))
	}

	private static func handleHistoryLoadOlder(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let local = currentSession()?.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		guard let conv = (body["convKey"] as? String)?.lowercased(), !conv.isEmpty,
		      let cursor = body["cursor"] as? String, !cursor.isEmpty,
		      let vp = parseViewport(body["viewport"])
		else {
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		do {
			ack(reqId, ok: true, result: pageJSON(try local.loadOlder(convKey: conv, cursor: cursor, viewport: vp)))
		} catch {
			ack(reqId, ok: false, error: "\(error)" == "cursorInvalid" ? "cursor_invalid" : "load_failed")
		}
	}

	private static func handleHistoryReportLayout(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let local = currentSession()?.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		guard let conv = (body["convKey"] as? String)?.lowercased(), !conv.isEmpty,
		      let sid = body["stableId"] as? String, !sid.isEmpty,
		      let vp = parseViewport(body["viewport"]),
		      let w = (body["wPt"] as? NSNumber)?.doubleValue, let h = (body["hPt"] as? NSNumber)?.doubleValue,
		      w > 0, h > 0
		else {
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		let written = local.reportLayout(convKey: conv, stableId: sid, viewport: vp, wPt: w, hPt: h)
		ack(reqId, ok: true, result: ["written": written])
	}

	private static func handleHistoryClearCache(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let local = currentSession()?.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let conv = (body["convKey"] as? String)?.lowercased()
		do {
			let result = try local.clearLocalCache(convKey: (conv?.isEmpty == false) ? conv : nil)
			ack(reqId, ok: true, result: ["pendingKept": result.pendingKept])
		} catch {
			ack(reqId, ok: false, error: "clear_failed")
		}
	}

	/// Starts the full-history sync in the background. The ack returns at once (spec 9.3).
	private static func handleHistoryFullSync(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession(), let local = s.localStore, let src = s.history?.localSyncSource(),
		      s.history?.isReady() == true
		else {
			ack(reqId, ok: false, error: "history_not_ready")
			return
		}
		ack(reqId, ok: true, result: ["started": true])
		DispatchQueue.global(qos: .utility).async {
			let report = local.syncIndex(records: src.records, historyMaster: src.master, fetchCipher: src.fetch)
			NSLog("[BeamioConetChat] local sync records=%d fetched=%d failed=%d locked=%d",
			      report.records, report.fetched, report.failed, report.locked ? 1 : 0)
		}
	}

	/// Native error codes for the local library (6.6, 11.2).
	private static func localErrorCode(_ error: Error) -> String {
		switch error as? BeamioChatLocalError {
		case .accountMismatch?: return "account_mismatch"
		case .batchTooLarge?: return "batch_too_large"
		case .badRow?: return "bad_row"
		case .locked?: return "locked"
		case .crypto?: return "crypto_error"
		default: return "import_failed"
		}
	}

	/// D8 migration, M2 (11.2): at most 200 rows. Native code derives sendKey and stable_id, de-duplicates, encrypts.
	private static func handleHistoryImportBatch(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession(), let local = s.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let account = ((body["accountKey"] as? String) ?? (s.eoa + ":default")).lowercased()
		guard let raw = body["rows"] as? [[String: Any]] else {
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		guard raw.count <= BeamioConetChatLocalStore.importBatchLimit else {
			ack(reqId, ok: false, error: "batch_too_large")
			return
		}
		var rows: [BeamioChatImportRow] = []
		for r in raw {
			guard let conv = r["convKey"] as? String, let dir = r["dir"] as? String, let text = r["body"] as? String else {
				ack(reqId, ok: false, error: "bad_row")
				return
			}
			rows.append(BeamioChatImportRow(
				convKey: conv, dir: dir, ts: (r["ts"] as? NSNumber)?.int64Value,
				sendId: r["sendId"] as? String, body: text, pending: (r["pending"] as? Bool) ?? false
			))
		}
		do {
			let res = try local.importBatch(accountKey: account, rows: rows)
			ack(reqId, ok: true, result: ["imported": res.imported, "duplicates": res.duplicates,
			                              "sendKeyConflict": res.sendKeyConflict])
		} catch {
			ack(reqId, ok: false, error: localErrorCode(error))
		}
	}

	/// D8 migration, M3 (11.1): row count and digest for the comparison with the old side.
	private static func handleHistoryVerifyImport(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession(), let local = s.localStore else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let account = ((body["accountKey"] as? String) ?? (s.eoa + ":default")).lowercased()
		do {
			let v = try local.verifyImport(accountKey: account)
			ack(reqId, ok: true, result: ["rows": v.rows, "digest": v.digest])
		} catch {
			ack(reqId, ok: false, error: localErrorCode(error))
		}
	}

	private static func parseViewport(_ raw: Any?) -> BeamioChatViewport? {
		guard let o = raw as? [String: Any],
		      let w = (o["widthPt"] as? NSNumber)?.doubleValue, let h = (o["heightPt"] as? NSNumber)?.doubleValue,
		      w > 0, h > 0,
		      let orientation = (o["orientation"] as? String).flatMap(BeamioChatOrientation.init(rawValue:))
		else { return nil }
		let fs = (o["fontScale"] as? NSNumber)?.doubleValue ?? 1.0
		let lv = (o["layoutVersion"] as? NSNumber)?.intValue ?? 1
		return BeamioChatViewport(widthPt: w, heightPt: h, orientation: orientation, fontScale: fs, layoutVersion: lv)
	}

	private static func itemJSON(_ i: BeamioChatItem) -> [String: Any] {
		var o: [String: Any] = [
			"stableId": i.stableId, "sortTs": NSNumber(value: i.sortTs), "dir": i.dir,
			"kind": i.kind.rawValue, "revision": NSNumber(value: i.revision),
			"layout": ["wPt": i.layout.wPt, "hPt": i.layout.hPt, "measured": i.layout.measured],
		]
		if let b = i.body { o["body"] = b }
		if let m = i.media {
			var mo: [String: Any] = ["mime": m.mime, "state": m.state]
			if let w = m.widthPx { mo["widthPx"] = w }
			if let h = m.heightPx { mo["heightPx"] = h }
			o["media"] = mo
		}
		return o
	}

	private static func pageJSON(_ p: BeamioChatPage) -> [String: Any] {
		var o: [String: Any] = [
			"items": p.items.map(itemJSON), "olderState": p.olderState.rawValue,
			"scanExhausted": p.scanExhausted, "syncState": p.syncState.rawValue,
			"source": p.source.rawValue, "short": p.short, "capped": p.capped,
		]
		o["olderCursor"] = p.olderCursor ?? NSNull()
		return o
	}

	private static func changePayload(_ ev: BeamioChatEvent) -> [String: Any] {
		switch ev {
		case .inserted(let conv, let items, let position):
			return ["kind": "inserted", "convKey": conv, "position": position, "items": items.map(itemJSON)]
		case .updated(let conv, let sid, let rev):
			return ["kind": "updated", "convKey": conv, "stableId": sid, "revision": NSNumber(value: rev)]
		case .deleted(let conv, let sid):
			return ["kind": "deleted", "convKey": conv, "stableId": sid]
		case .cleared(let scope, let conv, let kept):
			return ["kind": "cleared", "scope": scope, "convKey": conv ?? NSNull(), "pendingKept": kept]
		case .syncProgress(_, let done, let total, let state):
			return ["kind": "syncProgress", "doneRows": done, "totalRows": total, "state": state]
		case .locked:
			return ["kind": "locked"]
		case .olderAvailable(let conv):
			return ["kind": "olderAvailable", "convKey": conv]
		}
	}

	// MARK: - Mailbox commands

	/// to: a page's mailbox command. The signed command takes the generation of the request; the voice command, which is not
	/// signed, is checked before its POST. An expired request is silent; a valid one still in flight after `inFlightTimeout` answers send_timeout.
	private static func handleMailboxCommand(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		// v109 section 122: a router command has no voice name and no media field; the voice_ route that used to be open is closed.
		if let command = body["command"] as? [String: Any], BeamioVoiceMailboxGuard.refusesCommand(command) {
			ack(reqId, ok: false, error: "not_supported")
			return
		}
		guard let s = currentSession() else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		guard let initiated = initiationGeneration(s, body: body) else {
			ack(reqId, ok: false, error: "bad_request")
			return
		}
		let reply = BeamioInFlightReply(timeout: inFlightTimeout, isCurrent: { BeamioInboxIO.generation == initiated }) { ok, result, error in
			ack(reqId, ok: ok, result: result, error: error)
		}
		let routeKey = String(body["routerArmoredPublicKey"] as? String ?? "")
		guard let command = body["command"] as? [String: Any],
		      routeKey.contains("BEGIN PGP PUBLIC KEY")
		else {
			reply.send(ok: false, error: "bad_mailbox_command")
			return
		}
		// The signed command has its own stage checks (before signing, before the POST, after the signature); its answer is the reply's.
		postSignedMailboxCommand(
			session: s, routerArmoredPublicKey: routeKey, command: command, generation: initiated, timeout: .infinity
		) { ok, _ in
			reply.send(ok: true, result: ["ok": ok])
		}
	}

	private static func handleOwnMailboxCommand(_ body: [String: Any]) {
		var next = body
		if let s = currentSession() {
			next["routerArmoredPublicKey"] = s.ownRouteArmoredPublicKey
		}
		handleMailboxCommand(next)
	}

	// MARK: - Voice (delegate to BeamioNativeVoiceSignaling)

	private static func handleVoiceListen(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		let sessionId = String(body["sessionId"] as? String ?? "")
		lock.lock()
		voiceSessions.insert(sessionId)
		lock.unlock()
		// BeamioNativeVoiceSignaling owns CallKit / voice SSE — avoid dual listen.
		ack(reqId, ok: true, result: ["ok": true, "delegated": true, "sessionId": sessionId])
	}

	private static func handleVoiceUnlisten(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		let sessionId = String(body["sessionId"] as? String ?? "")
		lock.lock()
		voiceSessions.remove(sessionId)
		lock.unlock()
		ack(reqId, ok: true, result: ["ok": true])
	}

	/// `voiceFrame` (v99 section 106, interface spec 2026-11-21): the chat mailbox carries no audio or video. The command no longer posts a `voice_uplink`
	/// to the entries; it is refused with `not_supported` until the four-channel relay path is specified, and the SDK adds no command. The answer
	/// does not depend on the session or on the frame, so nothing is built, encrypted or sent. (A source guard test keeps a mailbox post out of here.)
	private static func handleVoiceFrame(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		ack(reqId, ok: false, error: "not_supported")
	}

	// MARK: - Listen lifecycle

	/// C, D (review of d2055d7): a frame the listen decrypted is handled only while the session it was started for is still the current one,
	/// and the identity has not been cleared since. Otherwise it is dropped: nothing is written, shown, acked or delivered.
	static func listenFrameIsCurrent(_ session: Session, generation: Int) -> Bool {
		currentSession() === session && BeamioInboxIO.generation == generation
	}

	private static func startListen(session: Session) {
		// under a storage-derived Locked nothing is signed and no listen is started.
		if BeamioNativeWallet.storageDerivedLocked(eoa: session.eoa) {
			NSLog("[BeamioConetChat] listen not started: the key record cannot be read")
			return
		}
		// r3: the mailbox listen decrypts with the native OpenPGP layer, which is not approved (X-19). Until then the
		// listen does not start, and the status says why (no armor reaches the WebView).
		guard BeamioPGPNative.available else {
			emitStatus("blocked", BeamioPGPNative.pendingCode)
			return
		}
		DispatchQueue.main.async {
			ensureNetworkWatch()
			// Started while the app is in the background (page reload, call
			// push): it pauses again unless a call needs it.
			if lifecycleKnown, !appInForeground {
				pauseOwed = true
				postIdleCheck()
			}
		}
		let listenGeneration = BeamioInboxIO.generation
		listen.start(
			session: session,
			onStatus: { status, detail in
				noteListenStatus(status, detail)
				var payload: [String: Any] = ["status": status]
				if let detail { payload["detail"] = detail }
				emitEvent(["type": "event:status", "payload": payload])
			},
			onInbound: { plaintext, armorHash, viaDomain, armor in
				guard listenFrameIsCurrent(session, generation: listenGeneration) else { return }
				handleInbound(plaintext: plaintext, armorHash: armorHash, viaDomain: viaDomain, armor: armor)
			}
		)
		checkOwnRoute(session: session, reason: "listen start")
	}

	// MARK: - Own route vs chain (see BeamioOwnRouteCheck)

	private static let routeCheckSignal = NSCondition()
	private static var routeCheckGen = 0

	/// Network back: a check waiting to retry reads the chain now.
	private static func kickOwnRouteCheck() {
		routeCheckSignal.lock()
		routeCheckSignal.broadcast()
		routeCheckSignal.unlock()
	}

	/// Check the session's route against the chain record. A failed read retries
	/// with backoff and never changes the route; a different chain route wins and
	/// the listen reopens on it. One check runs at a time; a newer one ends it.
	private static func checkOwnRoute(session s: Session, reason: String) {
		routeCheckSignal.lock()
		routeCheckGen += 1
		let gen = routeCheckGen
		routeCheckSignal.broadcast()
		routeCheckSignal.unlock()
		DispatchQueue.global(qos: .utility).async {
			let alive: () -> Bool = {
				routeCheckSignal.lock()
				let current = routeCheckGen == gen
				routeCheckSignal.unlock()
				return current && currentSession() === s && !s.destroyed
			}
			// Page handoff: a running listen on another route than the session's reopens now.
			let inUse = s.listenRouteKeyId
			let wanted = BeamioOwnRouteCheck.routeKeyId(s.ownRouteArmoredPublicKey)
			if !inUse.isEmpty, !wanted.isEmpty, inUse != wanted {
				NSLog("[BeamioConetChat] own route: listen on %@, session route %@ (%@); reopening", inUse, wanted, reason)
				DispatchQueue.main.async { if alive(), listen.isListening() { reopenListen(session: s) } }
			}
			let verdict = BeamioOwnRouteCheck.reconcile(
				listenArmor: { s.ownRouteArmoredPublicKey },
				read: { BeamioOwnRouteCheck.readChainRoute(rpcUrl: s.conetRpcUrl, eoa: s.eoa) },
				sleep: { seconds in
					routeCheckSignal.lock()
					_ = routeCheckSignal.wait(until: Date().addingTimeInterval(seconds))
					routeCheckSignal.unlock()
					return alive()
				},
				onRetry: { why, seconds in
					NSLog("[BeamioConetChat] own route check: chain read failed (%@); keeping route=%@; retry in %.0fs", why, wanted, seconds)
				}
			)
			guard alive() else { return }
			switch verdict {
			case .match:
				NSLog("[BeamioConetChat] own route check: route=%@ matches chain (%@)", wanted, reason)
			case .noRoute:
				NSLog("[BeamioConetChat] own route check: chain has no route; keeping route=%@", wanted)
			case .switchTo(let chainId, let chainArmor):
				NSLog("[BeamioConetChat] own route mismatch: route=%@ chain=%@ (%@); reconnecting on the chain route", wanted, chainId, reason)
				DispatchQueue.main.async {
					if alive() { applyChainRoute(session: s, routeKeyId: chainId, routeArmor: chainArmor) }
				}
			case .retry:
				break
			}
		}
	}

	/// Main thread. The chain route replaces the session's and the stored one.
	private static func applyChainRoute(session s: Session, routeKeyId: String, routeArmor: String) {
		s.ownRouteArmoredPublicKey = routeArmor
		let mailboxIp = s.nodes.first { $0.domain.caseInsensitiveCompare(routeKeyId) == .orderedSame }?.ip ?? ""
		s.mailboxIp = mailboxIp
		BeamioChatPgpKeychain.upsert(eoa: s.eoa, fromWeb: [
			"routePublicKeyArmor": routeArmor,
		])
		let roster = BeamioChatPgpKeychain.loadSiNodes()
		if !mailboxIp.isEmpty, !roster.isEmpty {
			_ = BeamioChatPgpKeychain.storeChainRoster(nodes: roster, mailboxIp: mailboxIp)
		}
		emitEvent(["type": "event:log", "level": "warn", "message": "own route switched to the chain route \(routeKeyId)"])
		// A paused listen picks the new route up when it resumes.
		if listen.isListening() { reopenListen(session: s) }
	}

	private static func reopenListen(session: Session) {
		let listenGeneration = BeamioInboxIO.generation
		listen.start(
			session: session,
			onStatus: { status, detail in
				noteListenStatus(status, detail)
				var payload: [String: Any] = ["status": status]
				if let detail { payload["detail"] = detail }
				emitEvent(["type": "event:status", "payload": payload])
			},
			onInbound: { plaintext, armorHash, viaDomain, armor in
				guard listenFrameIsCurrent(session, generation: listenGeneration) else { return }
				handleInbound(plaintext: plaintext, armorHash: armorHash, viaDomain: viaDomain, armor: armor)
			}
		)
	}

	/// Back in the foreground with no word from the mailbox for this long: reopen
	/// the listen. A stream that died while the app was suspended is not always
	/// reported, and only a new listen makes the mailbox send what it holds.
	private static let resumeStaleSeconds: TimeInterval = 45

	private static func resumeListen() {
		guard let s = currentSession() else { return }
		// under a storage-derived Locked no listen is resumed.
		if BeamioNativeWallet.storageDerivedLocked(eoa: s.eoa) { return }
		if listen.isListening() {
			// Connected (or reconnecting by itself) and recently heard: keep it.
			let quiet = listen.secondsSinceLastMailboxFrame()
			if quiet < resumeStaleSeconds { return }
			NSLog("[BeamioConetChat] resume: mailbox quiet %.0fs; reopening the listen", quiet)
		}
		listen.resume(
			session: s,
			onStatus: { status, detail in
				noteListenStatus(status, detail)
				var payload: [String: Any] = ["status": status]
				if let detail { payload["detail"] = detail }
				emitEvent(["type": "event:status", "payload": payload])
			},
			onInbound: { plaintext, armorHash, viaDomain, armor in
				handleInbound(plaintext: plaintext, armorHash: armorHash, viaDomain: viaDomain, armor: armor)
			}
		)
	}

	/// (c): the passcode lock ends a running listen loop, so no mailbox connection stays open while the account is locked.
	/// Asynchronous: the caller (the passcode lock) may hold its own lock. The status says why (`idle`, detail `locked`).
	/// A session lock wipes the keys that were derived from the wallet key and live in memory: the local library's DEK, id and index keys and local root,
	/// and the history store's master and index key. Called by `BeamioPasscodeSession.lockAll`, outside the module lock.
	static func lockDerivedKeys() {
		lock.lock()
		let current = session
		lock.unlock()
		current?.localStore?.lock()
		current?.history?.lockKeys()
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook: attaches the derived-key holders to the current test session.
	static func attachStoresForTests(local: BeamioConetChatLocalStore?, history: BeamioConetChatHistoryStore?) {
		lock.lock()
		session?.localStore = local
		session?.history = history
		lock.unlock()
	}
	#endif

	/// Sends a `passcodeState` payload that the session built (carrying `reason` when a session ended).
	/// The output that is current when the session ends is the one that gets the event: it is captured here, not looked up when the main queue runs, so an
	/// event of a session end never lands in the output of a command that is sent later.
	static func emitPasscodeStateEvent(_ payload: [String: Any]) {
		let out: [String: Any] = ["action": "chatModuleEvent", "event": payload]
		let target = emit
		DispatchQueue.main.async {
			nativeObserver?(out)
			target?(out)
		}
	}

	static func stopListenForLock() {
		DispatchQueue.main.async {
			guard listen.isRunning() else { return }
			listen.stop()
			listenConnected = false
			emitEvent(["type": "event:status", "payload": ["status": "idle", "detail": "locked"]])
		}
	}

	private static func destroy() {
		listen.stop()
		lock.lock()
		session?.destroyed = true
		// F1: the pending acks belong to this session and go with it. They are cleared here, while the object is reachable.
		session?.pendingLock.lock()
		session?.pendingAcks = [:]
		session?.pendingLock.unlock()
		session?.clearReceiptState()
		session?.history?.destroy()
		session?.history = nil
		session = nil
		voiceSessions.removeAll()
		BeamioVoiceEphemeral.clearAll()
		lock.unlock()
		// A destroyed session signs nothing and counts as no account: the signer goes with it.
		BeamioConetChatSignBroker.clearSigner()
		// the OpenPGP page goes with the session (asynchronous; the lock above is already released).
		BeamioOpenPgpHost.shared.tearDown(reason: "session destroyed")
		emitEvent(["type": "event:status", "payload": ["status": "destroyed"]])
	}

	// MARK: - Inbound

	/// A frame the listen decrypted. The call-control signal goes first, and never depends on the store. Then the store, on
	/// the inbox IO queue, one read and at most one write. A new frame is shown once stored, then acked. A copy
	/// of a stored frame is acked, not shown. The ack is confirmed only by a 200 with ok:true.
	private static func handleInbound(plaintext: String, armorHash: String, viaDomain: String, armor: String) {
		guard let s = currentSession() else { return }
		// the flow carries the generation it started in. An identity clear after this point makes the flow stale.
		let gen = BeamioInboxIO.generation
		// a decrypted row that is not valid JSON is a dropped frame. It cannot be verified, so it is not shown and
		// keeps no armor; its marker is committed first, and the ack follows that commit.
		// valid JSON that is not an object has no signature to check. It is a signature failure: nothing is
		// written, acked or delivered.
		switch inboundShape(plaintext) {
		case .notJSON:
			emitEvent(["type": "event:log", "level": "warn", "message": "inbound not json — drop"])
			acceptUnparsedInbound(session: s, armorHash: armorHash, generation: gen)
			return
		case .notObject:
			emitEvent(["type": "event:log", "level": "warn", "message": "inbound json not an object — drop"])
			return
		case .object:
			break
		}
		// Decrypt completes on the main thread and `host.verifyMessage` needs the main thread too. Never block on it with a semaphore
		// (that deadlocked for 8 s and every inbound message was dropped as "verify failed").
		verifyEnvelope(plaintext: plaintext, host: BeamioOpenPgpHost.shared) { from in
			// F2: a verification that completes after a clear is discarded before anything is written, delivered, acked or re-signed.
			guard gen == BeamioInboxIO.generation else { return }
			// Not verified: nothing is shown, written, acked or handed over. The frame stays on the server.
			guard let from, !from.isEmpty else {
				emitEvent(["type": "event:log", "level": "warn", "message": "inbound verify failed — drop"])
				return
			}
			acceptVerifiedInbound(
				session: s, plaintext: plaintext, from: from, armorHash: armorHash, armor: armor, viaDomain: viaDomain, generation: gen
			)
		}
	}

	/// A verified frame: the call signal first, then the store, then the display, then the ack (to). Each step is checked
	/// against the generation the flow started in: store and ledger work is queued only while it is current, and a completion runs only
	/// while it still is. Internal for the tests.
	static func acceptVerifiedInbound(
		session s: Session,
		plaintext: String,
		from: String,
		armorHash: String,
		armor: String,
		viaDomain: String,
		generation gen: Int
	) {
		guard gen == BeamioInboxIO.generation else { return }
		deliverCallSignal(plaintext: plaintext, from: from, generation: gen) { recorded in
			// The call signal could not be recorded: nothing is stored, shown or acked, so the mailbox sends the frame again.
			guard recorded else { return }
			BeamioInboxIO.perform(generation: gen, {
				BeamioConetChatInboxStore.admit(armorHash: armorHash, armor: armor, viaDomain: viaDomain)
			}) { admission in
				var input = InboundFrameRule.Input()
				input.inboxRead = admission.readable ? .ok : .readFailed
				input.dedupeKnown = admission.known
				input.persist = (admission.known || !admission.readable || admission.stored) ? .ok : .fail
				let outcome = InboundFrameRule.decide(armorHash: armorHash, input)
				guard outcome.displayed == 1 else {
					// A copy of a stored frame is acked: its copy is durable. A frame that was not stored is not.
					if !outcome.ackSent.isEmpty {
						postGossipAck(session: s, armorHash: armorHash, generation: gen, retryOnFailure: !admission.serverAcked)
					}
					return
				}
				// Stored: shown now, then acked. The armor stays until the page's ackInbound.
				emitInboundMessage(plaintext: plaintext, from: from, armorHash: armorHash, viaDomain: viaDomain)
				postGossipAck(session: s, armorHash: armorHash, generation: gen)
				let now = Date()
				if s.deferAck {
					// a message waits for the page's ackInbound however long that takes. Nothing here expires by time.
					s.pendingLock.lock()
					s.pendingAcks[armorHash] = (plaintext, from, now)
					s.pendingLock.unlock()
				} else {
					// (an old page, init without deferAck, never sends ackInbound): its sender receipt goes out at display.
					sendSenderReceipt(session: s, plaintext: plaintext, armorHash: armorHash, from: from)
				}
			}
		}
	}

	/// a row that is not JSON is a dropped frame. Its marker (the armorHash only) is committed first;
	/// the ack follows only that commit. Nothing is shown and no armor is kept. Internal for the tests.
	static func acceptUnparsedInbound(session s: Session, armorHash: String, generation gen: Int) {
		guard gen == BeamioInboxIO.generation else { return }
		BeamioInboxIO.perform(generation: gen, {
			BeamioConetChatInboxStore.admitMarker(armorHash: armorHash)
		}) { admission in
			var input = InboundFrameRule.Input()
			input.parse = .fail
			input.inboxRead = admission.readable ? .ok : .readFailed
			input.dedupeKnown = admission.known
			input.persist = (admission.known || !admission.readable || admission.stored) ? .ok : .fail
			let outcome = InboundFrameRule.decide(armorHash: armorHash, input)
			guard !outcome.ackSent.isEmpty else { return }
			postGossipAck(session: s, armorHash: armorHash, generation: gen, retryOnFailure: !admission.serverAcked)
		}
	}

	/// The shape of a decrypted row: not JSON, valid JSON that is not an object, or a JSON object. Only an object can verify
	/// (see `verifyEnvelope`).
	enum InboundShape: Equatable {
		case notJSON
		case notObject
		case object
	}

	static func inboundShape(_ plaintext: String) -> InboundShape {
		guard let data = plaintext.data(using: .utf8),
		      let root = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
		else { return .notJSON }
		return root is [String: Any] ? .object : .notObject
	}

	/// A stored frame handed to the page again on attach (the page has not confirmed it). Not a new arrival: nothing is written and nothing
	/// is acked. Its call-control signal is handed over if its key was not. Nothing of an earlier generation is handed over.
	private static func handOverStored(plaintext: String, armorHash: String, viaDomain: String) {
		guard let s = currentSession() else { return }
		let gen = BeamioInboxIO.generation
		verifyEnvelope(plaintext: plaintext, host: BeamioOpenPgpHost.shared) { from in
			guard gen == BeamioInboxIO.generation else { return }
			guard let from, !from.isEmpty else { return }
			handOverVerified(session: s, plaintext: plaintext, from: from, armorHash: armorHash, viaDomain: viaDomain, generation: gen)
		}
	}

	/// A verified stored frame on attach. Its call signal is recorded first. If the record cannot be written, the frame is
	/// neither shown nor staged, so the next attach hands it over again. Internal for the tests.
	static func handOverVerified(
		session s: Session, plaintext: String, from: String, armorHash: String, viaDomain: String, generation gen: Int
	) {
		guard gen == BeamioInboxIO.generation else { return }
		// A stored frame handed to the page again is history, not a new arrival (v68 section 75.2): it is shown and staged, and never hands a call
		// signal to the shell. The signal of its first arrival was handed over (or kept as pending) then.
		emitInboundMessage(plaintext: plaintext, from: from, armorHash: armorHash, viaDomain: viaDomain)
		let now = Date()
		s.pendingLock.lock()
		s.pendingAcks[armorHash] = (plaintext, from, now)
		s.pendingLock.unlock()
	}

	/// (2): a page that did not declare deferAck displays what it is given at attach, so the sender receipts of those messages go out
	/// now. A page that declared deferAck keeps them until its ackInbound. Internal for the tests.
	static func settleReceiptsForOldPage(_ s: Session) {
		guard !s.deferAck else { return }
		s.pendingLock.lock()
		let shown = s.pendingAcks
		s.pendingAcks = [:]
		s.pendingLock.unlock()
		for (hash, p) in shown {
			sendSenderReceipt(session: s, plaintext: p.plaintext, armorHash: hash, from: p.from)
		}
	}

	/// (review B1, D5, D6): a call-control signal (end, timeout) of a verified frame, once per (callId, sessionId).
	/// Handed to the call layer when one is registered; otherwise kept as pending in the ledger. `then(recorded)`: false means the signal
	/// could not be recorded, and the caller must then neither store, show nor ack the frame. The hand-over is a claim (D5), so two
	/// paths cannot both hand the same key over at once. Every step runs only while `gen` is current.
	private static func deliverCallSignal(plaintext: String, from: String, generation gen: Int, then: @escaping (Bool) -> Void) {
		// The gate (v54 section 61, v68 section 75): only an envelope whose outer signer, envelope from and inner from are the same address is a call
		// signal. A message that is not one, or that fails the gate, is an ordinary line: nothing is handed over and no state changes.
		guard case .deliver(let kind, let callId, let sessionId, let sender) = BeamioConetChatCallControl.admit(plaintext: plaintext, signer: from) else {
			then(true)
			return
		}
		let sig = BeamioConetChatCallControl.Signal(type: kind, callId: callId, sessionId: sessionId, from: sender)
		let from = sender
		let key = BeamioConetChatCallLedger.key(callId: sig.callId, sessionId: sig.sessionId)
		let waiting = BeamioConetChatCallLedger.Pending(
			key: key, type: sig.type, callId: sig.callId, sessionId: sig.sessionId, from: from
		)
		BeamioInboxIO.perform(generation: gen, { BeamioConetChatCallLedger.claimOutcome(waiting) }) { outcome in
			switch outcome {
			case .delivered:
				// Recorded already: the signal went out before.
				then(true)
				return
			case .held:
				// Another path holds this key and has not recorded it. Nothing is stored, shown or acked.
				then(false)
				return
			case .claimed:
				break
			}
			let observer = callControlObserver
			let handOver = CallSignalRule.shouldHandOver(
				isCallControl: true, delivered: false, observerRegistered: observer != nil
			)
			if handOver, let observer {
				observer(sig.type, sig.callId, sig.sessionId, from)
				BeamioInboxIO.perform(generation: gen, { BeamioConetChatCallLedger.markDelivered(key) }) { ok in then(ok) }
			} else {
				BeamioInboxIO.perform(generation: gen, {
					let ok = BeamioConetChatCallLedger.markPending(waiting)
					BeamioConetChatCallLedger.release(key)
					return ok
				}) { ok in then(ok) }
			}
		}
	}

	/// a call layer registered. The signals that waited are claimed and handed over now, once each (the generation as of the call).
	private static func flushPendingCallSignals() {
		let gen = BeamioInboxIO.generation
		BeamioInboxIO.perform(generation: gen, { BeamioConetChatCallLedger.pendingSignals() }) { waiting in
			for p in waiting {
				BeamioInboxIO.perform(generation: gen, { BeamioConetChatCallLedger.claim(p) }) { claimed in
					guard claimed else { return }
					guard let observer = callControlObserver else {
						BeamioInboxIO.perform(generation: gen, { BeamioConetChatCallLedger.release(p.key) }) { _ in }
						return
					}
					observer(p.type, p.callId, p.sessionId, p.from)
					BeamioInboxIO.perform(generation: gen, { BeamioConetChatCallLedger.markDelivered(p.key) }) { _ in }
				}
			}
		}
	}

	private static func emitInboundMessage(plaintext: String, from: String, armorHash: String, viaDomain: String) {
		emitEvent([
			"type": "event:message",
			"payload": [
				"line": plaintext,
				"from": from,
				"armorHash": armorHash,
				"viaDomain": viaDomain,
				"plain": false,
			],
		])
	}

	/// The page has stored these messages (ackInbound). Their armor leaves the inbox; their record stays (dedupe). The sender gets the
	/// delivery receipt. This sends no gossip_delivery_ack: the mailbox was acked when each frame was stored.
	private static func handleAckInbound(_ body: [String: Any]) {
		guard let s = currentSession() else { return }
		let gen = BeamioInboxIO.generation
		var hashes = (body["armorHashes"] as? [String]) ?? []
		if let one = body["armorHash"] as? String, !one.isEmpty { hashes.append(one) }
		BeamioInboxIO.perform(generation: gen, { BeamioConetChatInboxStore.confirm(hashes) }) { _ in }
		for hash in hashes where !hash.isEmpty {
			s.pendingLock.lock()
			let pending = s.pendingAcks.removeValue(forKey: hash)
			s.pendingLock.unlock()
			guard let pending else { continue }
			// F2: a receipt is a send, and it is not made after an identity clear.
			guard gen == BeamioInboxIO.generation else { return }
			sendSenderReceipt(session: s, plaintext: pending.plaintext, armorHash: hash, from: pending.from)
		}
	}

	/// The mailbox ack for one stored frame (`gossip_delivery_ack`). Recorded as acked only on an HTTP 200 with ok:true, from an entry that
	/// answered so; the entries are tried in turn until one does (review D4). An unconfirmed ack is sent again: after 30 s,
	/// doubling, at most 600 s; at once on a listen handshake and on the return to the foreground, which does not move the interval sequence
	///; no limit until confirmed. Every send is re-signed with the current time.
	/// After an identity clear an ack of an earlier generation is not sent, not re-signed, and its answer changes
	/// nothing: no confirmation, no store write and no retry.
	/// the armorHashes whose `gossip_delivery_ack` is in flight. A copy of the frame that arrives meanwhile does not POST again:
	/// the ack in flight answers for it. Once that ack has ended, a copy is acked again (IA-05).
	private static let gossipAckLock = NSLock()
	private static var gossipAckInFlight: Set<String> = []

	/// False when the ack of this armorHash is already in flight.
	static func beginGossipAck(_ armorHash: String) -> Bool {
		gossipAckLock.lock()
		defer { gossipAckLock.unlock() }
		return gossipAckInFlight.insert(armorHash).inserted
	}

	/// The ack of this armorHash has ended, by an answer or by its timeout. Called on every end, also after a clear.
	static func endGossipAck(_ armorHash: String) {
		gossipAckLock.lock()
		defer { gossipAckLock.unlock() }
		gossipAckInFlight.remove(armorHash)
	}

	private static func postGossipAck(
		session: Session, armorHash: String, immediate: Bool = false, generation gen: Int, retryOnFailure: Bool = true
	) {
		guard gen == BeamioInboxIO.generation else { return }
		guard session.ownRouteArmoredPublicKey.contains("BEGIN PGP PUBLIC KEY") else {
			// No route key: the ack cannot be sent now. It is unconfirmed, so it is retried (review D3).
			if retryOnFailure { scheduleGossipRetry(session: session, armorHash: armorHash, advance: !immediate, generation: gen) }
			return
		}
		// an ack of this armorHash already in flight answers for this copy; no second POST.
		guard beginGossipAck(armorHash) else { return }
		postSignedMailboxCommand(
			session: session,
			routerArmoredPublicKey: session.ownRouteArmoredPublicKey,
			command: [
				"command": "gossip_delivery_ack",
				"walletAddress": session.eoa,
				"armorHash": armorHash,
				"timestamp": Int(Date().timeIntervalSince1970),
			],
			generation: gen,
			accept: { result in InboundFrameRule.isConfirmed(status: result.status, body: jsonBody(result.body)) }
		) { ok, body in
			endGossipAck(armorHash)
			// F2, F3: an answer that comes after a clear changes nothing: no confirmation, no store write and no retry.
			guard gen == BeamioInboxIO.generation else { return }
			// `body` is set only for an HTTP 200 answer (postSignedMailboxCommand).
			if ok, InboundFrameRule.isConfirmed(status: 200, body: body) {
				gossipRetry.confirm(armorHash)
				BeamioInboxIO.perform(generation: gen, { BeamioConetChatInboxStore.markServerAcked([armorHash]) }) { _ in }
			} else {
				if retryOnFailure { scheduleGossipRetry(session: session, armorHash: armorHash, advance: !immediate, generation: gen) }
			}
		}
	}

	private static func jsonBody(_ text: String) -> Any? {
		try? JSONSerialization.jsonObject(with: Data(text.utf8))
	}

	/// The unconfirmed acks and their timers (main queue only). Cleared with the identity. A failure of an earlier generation
	/// registers nothing (F3), so no ack is retried after a clear.
	static var gossipRetry = BeamioGossipRetryBook()

	private static func scheduleGossipRetry(session: Session, armorHash: String, advance: Bool, generation gen: Int) {
		guard gen == BeamioInboxIO.generation else { return }
		let (failures, token) = gossipRetry.recordFailure(armorHash, advance: advance)
		DispatchQueue.main.asyncAfter(deadline: .now() + GossipRetrySchedule.delay(failures: failures - 1)) {
			guard gen == BeamioInboxIO.generation, gossipRetry.isDue(armorHash, token: token),
                  let s = currentSession(), s.eoa == session.eoa else { return }
			gossipRetry.fired(armorHash)
			postGossipAck(session: s, armorHash: armorHash, generation: gen)
		}
	}

	/// The listen handshake, or the return to the foreground: every unconfirmed ack goes again now, once. Its timer is cancelled. A
	/// repeat within `immediateRetryMinInterval` is skipped. After a clear nothing goes.
	static func retryUnconfirmedGossipAcksNow() {
		let gen = BeamioInboxIO.generation
		DispatchQueue.main.async {
			guard gen == BeamioInboxIO.generation, let s = currentSession() else { return }
			let now = Date()
			if let last = lastImmediateRetry, now.timeIntervalSince(last) < immediateRetryMinInterval { return }
			lastImmediateRetry = now
			for hash in gossipRetry.pendingHashes {
				gossipRetry.cancelTimer(hash)
				postGossipAck(session: s, armorHash: hash, immediate: true, generation: gen)
			}
		}
	}

	/// how long an in-flight send, ack or signature may wait for its callback before it is answered as failed (the ack then goes
	/// back to pending retry; a page command answers `send_timeout`).
	static var inFlightTimeout: TimeInterval = 30

	private static var lastImmediateRetry: Date?
	private static let immediateRetryMinInterval: TimeInterval = 5

	/// Recover the EIP-191 signer: the recovered address is the only trusted
	/// sender identity. A differing claimed `from` is passed on for the app to flag.
	/// Internal for the tests: a JSON object without `text` or `signMessage` completes with nil, so the frame is dropped.
	static func verifyEnvelope(
		plaintext: String,
		host: BeamioOpenPgpHost,
		completion: @escaping (String?) -> Void
	) {
		guard let data = plaintext.data(using: .utf8),
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else {
			completion(nil)
			return
		}
		let text: String
		if let t = obj["text"] as? String {
			text = t
		} else if let inner = obj["message"] as? String {
			text = inner
		} else {
			completion(nil)
			return
		}
		let sig = String(obj["signMessage"] as? String ?? "")
		guard !sig.isEmpty else {
			completion(nil)
			return
		}
		// The recovered signer is the sender. A claimed `from` that differs is not
		// dropped here: the app keeps the message under the signer and shows a
		// warning for the false claim.
		host.verifyMessage(text: text, signature: sig) { result in
			guard case .success(let recovered) = result else {
				completion(nil)
				return
			}
			completion(recovered)
		}
	}

	/// The sendId of an ordinary one-to-one chat message that earns a delivery receipt, or nil. The envelope is
	/// unwrapped like the page's extractInboundSendId: at most 6 layers, a string is parsed as JSON, an object with a string `text` is unwrapped
	/// further. Every layer's top-level fields are checked: `type`, `groupId`, `reply` or `callRecord` (receipt, call control, group, reaction,
	/// payment request controls, call record) earn no receipt; neither does a failed unwrap, an unknown shape, a depth over 6 or a missing
	/// sendId. Text, quote, voiceMessage, fileMessage (image, video, PDF, archive) and paymentCard do. A `type` nested inside a manifest
	/// (voiceMessage.type, fileMessage.type) is not a top-level field and does not exclude. Internal for the tests.
	static func receiptEligibleSendId(plaintext: String) -> String? {
		if BeamioConetChatCallControl.parse(plaintext) != nil { return nil }
		let maxLayers = 6
		let excluded = ["type", "groupId", "reply", "callRecord"]
		var current = plaintext
		var layers = 0
		var sendId: String?
		var first = true
		while true {
			guard let data = current.trimmingCharacters(in: .whitespacesAndNewlines).data(using: .utf8),
			      let parsed = try? JSONSerialization.jsonObject(with: data)
			else {
				// the first value must be a JSON object; a deeper value that is not an object is the user's text (a leaf) and ends the unwrap
				if first { return nil }
				break
			}
			guard let obj = parsed as? [String: Any] else {
				if first { return nil }
				break
			}
			for key in excluded {
				if let v = obj[key], !(v is NSNull) { return nil }
			}
			// the signed envelope the listen decrypted ({timestamp, text, from, signMessage}) is not a layer: layer 1 is the payload in its `text`
			// It is still checked for the excluded fields above.
			let isEnvelope = first && obj["signMessage"] != nil
			first = false
			if !isEnvelope {
				layers += 1
				if layers > maxLayers { return nil }
				if layers == 1 {
					// layer 1 must carry a non-empty sendId
					guard let id = obj["sendId"] as? String, !id.isEmpty else { return nil }
					sendId = id
				}
			}
			guard let text = obj["text"] as? String else { break }
			current = text
		}
		return sendId
	}

	/// The delivery receipt of a displayed message. Once per armorHash. Without a route for the sender it waits in a
	/// memory queue (128, 10 minutes, no plaintext) until a `setRoutes` brings one.
	static func sendSenderReceipt(session: Session, plaintext: String, armorHash: String, from: String) {
		guard let sendId = receiptEligibleSendId(plaintext: plaintext) else { return }
		let gen = BeamioInboxIO.generation
		session.receiptLock.lock()
		if session.receiptedHashes.contains(armorHash) {
			session.receiptLock.unlock()
			return
		}
		let pairKey = from.lowercased() + "|" + sendId
		if session.receiptedKeys.contains(pairKey) {
			session.receiptLock.unlock()
			return
		}
		session.receiptedHashes.append(armorHash)
		if session.receiptedHashes.count > 1024 { session.receiptedHashes.removeFirst(session.receiptedHashes.count - 1024) }
		session.receiptedKeys.append(pairKey)
		if session.receiptedKeys.count > 1024 { session.receiptedKeys.removeFirst(session.receiptedKeys.count - 1024) }
		session.receiptLock.unlock()
		if let route = receiptRoute(session: session, from: from) {
			postReceipt(session: session, route: route, sendId: sendId, armorHash: armorHash)
			return
		}
		session.receiptLock.lock()
		session.receiptQueue.append((from.lowercased(), sendId, armorHash, Date(), gen))
		if session.receiptQueue.count > receiptQueueMax { session.receiptQueue.removeFirst(session.receiptQueue.count - receiptQueueMax) }
		session.receiptLock.unlock()
	}

	private static func receiptRoute(session: Session, from: String) -> [String: Any]? {
		let key = from.lowercased()
		return session.routes.first(where: {
			normalizeAddress(String($0["eoaAddress"] as? String ?? $0["eoa"] as? String ?? "")) == key
		})
	}

	/// After a `setRoutes`: the queued receipts whose sender now has a route go out; the expired and the stale ones are dropped.
	static func flushQueuedReceipts(session: Session, now: Date = Date()) {
		let gen = BeamioInboxIO.generation
		session.receiptLock.lock()
		let queued = session.receiptQueue
		session.receiptQueue = []
		session.receiptLock.unlock()
		var keep: [(from: String, sendId: String, armorHash: String, at: Date, generation: Int)] = []
		for item in queued {
			if now.timeIntervalSince(item.at) > receiptQueueTTL || item.generation != gen { continue }
			if let route = receiptRoute(session: session, from: item.from) {
				postReceipt(session: session, route: route, sendId: item.sendId, armorHash: item.armorHash)
			} else {
				keep.append(item)
			}
		}
		if !keep.isEmpty {
			session.receiptLock.lock()
			session.receiptQueue = keep + session.receiptQueue
			session.receiptLock.unlock()
		}
	}

	static let receiptMaxInFlight = 2

	/// A receipt waits for one of two in-flight places, so a batch ackInbound cannot occupy the signer and the OpenPGP page; the outbox shares the
	/// 128 limit with the route queue (the oldest is dropped). A user's own send does not go through here.
	static func postReceipt(session: Session, route: [String: Any], sendId: String, armorHash: String) {
		session.receiptLock.lock()
		session.receiptOutbox.append((route, sendId, armorHash))
		if session.receiptOutbox.count > receiptQueueMax { session.receiptOutbox.removeFirst(session.receiptOutbox.count - receiptQueueMax) }
		session.receiptLock.unlock()
		pumpReceipts(session: session)
	}

	private static func pumpReceipts(session: Session) {
		while true {
			session.receiptLock.lock()
			guard session.receiptInFlight < receiptMaxInFlight, !session.receiptOutbox.isEmpty, !session.destroyed else {
				session.receiptLock.unlock()
				return
			}
			let item = session.receiptOutbox.removeFirst()
			session.receiptInFlight += 1
			session.receiptLock.unlock()
			let once = NSLock()
			var released = false
			let release: () -> Void = {
				once.lock()
				if released { once.unlock(); return }
				released = true
				once.unlock()
				session.receiptLock.lock()
				if session.receiptInFlight > 0 { session.receiptInFlight -= 1 }
				session.receiptLock.unlock()
				pumpReceipts(session: session)
			}
			sendReceiptNow(session: session, item: item, release: release)
		}
	}

	/// The wire format is unchanged: outer {sendId, from:"me", text, createdAt}; inner {type, sendId, armorHash, deliveredAt, from}.
	private static func sendReceiptNow(
		session: Session, item: (route: [String: Any], sendId: String, armorHash: String), release: @escaping () -> Void
	) {
		let receiptInner: [String: Any] = [
			"type": "beamio_chat_delivery_receipt_v1",
			"sendId": item.sendId,
			"armorHash": item.armorHash,
			"deliveredAt": Int(Date().timeIntervalSince1970 * 1000),
			"from": session.eoa,
		]
		guard let receiptData = try? JSONSerialization.data(withJSONObject: receiptInner),
		      let receiptJson = String(data: receiptData, encoding: .utf8)
		else { release(); return }
		let pending: [String: Any] = [
			"sendId": UUID().uuidString,
			"from": "me",
			"text": receiptJson,
			"createdAt": Int(Date().timeIntervalSince1970 * 1000),
		]
		guard let pendingData = try? JSONSerialization.data(withJSONObject: pending),
		      let pendingJson = String(data: pendingData, encoding: .utf8)
		else { release(); return }
		// A deferAck page's session takes a send only with the generation it was started in (`initiationGeneration`); a receipt that carried none
		// was answered bad_request on reqId -1, which is not delivered, so the receipt never left. The receipt is started now, in the current generation.
		let body: [String: Any] = [
			"reqId": -1,
			"to": item.route,
			"payload": pendingJson,
			"sendId": UUID().uuidString,
			"beamioNoPush": true,
			"inboundGeneration": BeamioInboxIO.generation,
		]
		if let hook = receiptSendHook {
			hook(body, release)
			return
		}
		// a watchdog frees the place if the send never answers.
		DispatchQueue.main.asyncAfter(deadline: .now() + 60) { release() }
		var withDone = body
		withDone["_receiptDone"] = release
		handleSend(withDone)
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: replaces the network send; the hook must call its `release` when the pretend send ends.
	static var receiptSendHook: (([String: Any], @escaping () -> Void) -> Void)?
#else
	static let receiptSendHook: (([String: Any], @escaping () -> Void) -> Void)? = nil
#endif

	/// (3): the error a page command answers with when a signature was refused. A signer that is not the session's account gives
	/// `signer_mismatch`; any other failure keeps its own message (or `fallback`).
	static func signFailureCode(_ error: Error, fallback: String? = nil) -> String {
		if let signError = error as? BeamioConetChatSignBroker.SignError, signError == .signerChanged {
			return "signer_mismatch"
		}
		return fallback ?? error.localizedDescription
	}

	/// A chat signature is made for the session's account only: the signer must be that account, and the broker refuses any other
	/// account at the moment it signs.
	static func requestSessionSignature(_ s: Session, message: String, completion: @escaping (Result<String, Error>) -> Void) {
		let signer = BeamioConetChatSignBroker.currentSignerEoa()
		guard !signer.isEmpty, signer == s.eoa.lowercased() else {
			completion(.failure(BeamioConetChatSignBroker.SignError.signerChanged))
			return
		}
		BeamioConetChatSignBroker.requestEip191(message: message, expectedEoa: signer, completion: completion)
	}

	// MARK: - Shared helpers

	/// `generation`: the generation of an inbound flow; nil for the other commands. A command of an earlier generation is not signed,
	/// posted or completed with a body. The session's account must be the signer (F3): the broker signs for that account only, and refuses any other.
	static func postSignedMailboxCommand(
		session: Session,
		routerArmoredPublicKey: String,
		command: [String: Any],
		generation gen: Int? = nil,
		timeout: TimeInterval = BeamioConetChatModule.inFlightTimeout,
		accept: @escaping (BeamioSiCipherPost.Result) -> Bool = { $0.ok },
		completion: @escaping (_ ok: Bool, _ json: [String: Any]?) -> Void
	) {
		// the shared entry of every signed mailbox command: no voice name and no media field, whoever the caller is (v109 section 122.2).
		if BeamioVoiceMailboxGuard.refusesCommand(command) {
			completion(false, nil)
			return
		}
		// the answer is one-shot; a callback that never comes times out to a failure (the ack then retries).
		let finish = BeamioInFlightOnce<(Bool, [String: Any]?)>(
			timeout: timeout, timeoutValue: (false, nil)
		) { result in completion(result.0, result.1) }
		if let gen, gen != BeamioInboxIO.generation {
			finish((false, nil))
			return
		}
		var cmd = command
		if cmd["walletAddress"] == nil { cmd["walletAddress"] = session.eoa }
		if cmd["timestamp"] == nil { cmd["timestamp"] = Int(Date().timeIntervalSince1970) }
		guard let data = try? JSONSerialization.data(withJSONObject: cmd),
              let message = String(data: data, encoding: .utf8)
		else {
			finish((false, nil))
			return
		}
		// F3: the session's account must be the signer, checked before anything is signed. The broker checks the same account again,
		// at the moment it signs, and signs only for it.
		let signer = BeamioConetChatSignBroker.currentSignerEoa()
		guard !signer.isEmpty, signer == session.eoa.lowercased() else {
			finish((false, nil))
			return
		}
		let host = BeamioOpenPgpHost.shared
		BeamioConetChatSignBroker.requestEip191(message: message, expectedEoa: signer) { signResult in
			guard case .success(let signature) = signResult else {
				finish((false, nil))
				return
			}
			// A clear during the signature: the signed command is not sent.
			if let gen, gen != BeamioInboxIO.generation {
				finish((false, nil))
				return
			}
			host.encryptSignedRouteCommand(
				message: message,
				signMessage: signature,
				routePublicArmor: routerArmoredPublicKey
			) { encResult in
				guard case .success(let armor) = encResult else {
					finish((false, nil))
					return
				}
				if let gen, gen != BeamioInboxIO.generation {
					finish((false, nil))
					return
				}
				DispatchQueue.global(qos: .userInitiated).async {
					let answer = postToEntriesAnswer(armor: armor, mailboxRoute: routerArmoredPublicKey, session: session, accept: accept)
					var body: [String: Any]?
					if let answer, answer.status == 200 {
						body = (try? JSONSerialization.jsonObject(with: Data(answer.body.utf8))) as? [String: Any]
					}
					DispatchQueue.main.async { finish((answer != nil, body)) }
				}
			}
		}
	}

	/// Sync POST via entry ≠ B. Optionally wrap to entry route PGP when available.
	@discardableResult
	private static func postToEntriesSync(armor: String, mailboxRoute: String, session: Session) -> Bool {
		postToEntriesAnswer(armor: armor, mailboxRoute: mailboxRoute, session: session) != nil
	}

	/// The answer of the entry that took the POST (status and body), or nil when none did.
	private static func postToEntriesAnswer(
		armor: String, mailboxRoute: String, session: Session, accept: (BeamioSiCipherPost.Result) -> Bool = { $0.ok }
	) -> BeamioSiCipherPost.Result? {
		#if BEAMIO_TEST_HOOKS
		testPostAttempts += 1
		testOnPostAttempt?()
		#endif
		var exclude = Set<String>()
		if let m = BeamioSiCipherPost.normalizeIp(session.mailboxIp) {
			exclude.insert(m)
		}
		for n in session.nodes {
			guard mailboxRoute.contains("BEGIN PGP"),
			      !n.armoredPublicKey.isEmpty,
			      normalizeArmorFingerprint(n.armoredPublicKey) == normalizeArmorFingerprint(mailboxRoute),
			      let ip = BeamioSiCipherPost.normalizeIp(n.ip)
			else { continue }
			exclude.insert(ip)
		}

		let host = BeamioOpenPgpHost.shared
		// The session's node list, or the keychain roster while the session has none yet. Both carry each entry's PGP key.
		let source: [BeamioChatPgpKeychain.SiNode] = session.nodes.isEmpty
			? BeamioChatPgpKeychain.loadSiNodes()
			: session.nodes.map { $0.asKeychainNode() }
		let entryCandidates = source.filter { n in
			guard let ip = BeamioSiCipherPost.normalizeIp(n.ip) else { return false }
			return !exclude.contains(ip)
		}.shuffled()

		// One entry at a time; the next only after a clear failure (connection
		// error or reset, non-2xx, `ok:false`, or no answer in 8 s). A timed-out
		// POST may have arrived: the mailbox keeps one copy per ciphertext and
		// the recipient dedupes by sendId. At most 4 entries, about 25 s.
		// Every POST goes out wrapped to the entry's PGP key. An entry without a key is skipped. A wrap that fails or does
		// not answer in 8 s also skips the entry. The armor is never posted unwrapped, and there is no bare POST to the
		// roster.
		let started = Date()
		for entry in entryCandidates.prefix(4) {
			if Date().timeIntervalSince(started) > 25 { break }
			guard entry.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") else { continue }
			let sem = DispatchSemaphore(value: 0)
			var wrapped: String?
			host.wrapArmorToEntryRoute(innerArmor: armor, entryRoutePublicArmor: entry.armoredPublicKey) { r in
				if case .success(let a) = r { wrapped = a }
				sem.signal()
			}
			guard sem.wait(timeout: .now() + 8) == .success, let postArmor = wrapped else { continue }
			let result = BeamioSiCipherPost.post(
				armor: postArmor,
				nodes: [entry],
				excludeIps: exclude,
				maxAttempts: 1,
				timeout: 8
			)
			// An answer the caller does not accept (an empty 2xx, for a gossip ack) does not end the search: the next entry may answer (D4).
			if accept(result) { return result }
		}
		return nil
	}

	private static func currentSession() -> Session? {
		lock.lock(); defer { lock.unlock() }
		guard let s = session, !s.destroyed else { return nil }
		return s
	}

	/// A result event. The WebView gets it whole; the native observer gets it without the W fields.
	private static func emitResultEvent(_ payload: [String: Any]) {
		var observed = payload
		observed.removeValue(forKey: "privateKeyArmor")
		observed.removeValue(forKey: "mnemonicPhrase")
		observed.removeValue(forKey: "recoveryWords")
		let full: [String: Any] = ["action": "chatModuleEvent", "event": payload]
		let copy: [String: Any] = ["action": "chatModuleEvent", "event": observed]
		DispatchQueue.main.async {
			nativeObserver?(copy)
			emit?(full)
		}
	}

	private static func emitEvent(_ payload: [String: Any]) {
		let out: [String: Any] = ["action": "chatModuleEvent", "event": payload]
		DispatchQueue.main.async {
			nativeObserver?(out)
			emit?(out)
		}
	}

	private static func ack(_ reqId: Int, ok: Bool, result: Any? = nil, error: String? = nil, reason: String? = nil) {
		if reqId < 0 { return }
		var payload: [String: Any] = ["type": "ack", "reqId": reqId, "ok": ok]
		if ok, let result { payload["result"] = result }
		if !ok { payload["error"] = error ?? "error" }
		// an additional field, never a replacement of the error code (protocol unregister-refused-reason-field): only a failed answer carries it
		if !ok, let reason { payload["reason"] = reason }
		emitEvent(payload)
	}

	/// (option B(1)): the AddressPGP source. The contract (`addressPgpContractAddress`) and the chain (`chainId`) come from the init payload; the RPC
	/// comes only from the shell's native build configuration (`AddressPGPChain.shellEndpoint`), never from the payload.
	/// Without the shell endpoint, or with an unusable configuration, the source is left as it was. Keeping an earlier source is intentional: a later init
	/// that lacks the fields does not clear a source already set from the same shell configuration (N-3, confirmed 2026-11-16). Returns whether it was set.
	@discardableResult
	static func configureAddressPGPChain(from payload: [String: Any]) -> Bool {
		guard let contract = payload["addressPgpContractAddress"] as? String,
		      let chainId = (payload["chainId"] as? Int) ?? (payload["chainId"] as? NSNumber)?.intValue,
		      let rpc = AddressPGPChain.shellEndpoint
		else { return false }
		let candidate = AddressPGPChain.Configuration(contract: contract, chainId: chainId, rpcURL: rpc)
		guard candidate.isUsable else { return false }
		// the account registry (the owner of a BeamioTag), when the page's init declares it: an unusable value does not replace an earlier one
		if let registry = (payload["accountRegistryAddress"] as? String) ?? (payload["beamioAccountRegistryAddress"] as? String),
		   registry.hasPrefix("0x"), registry.count == 42, registry.dropFirst(2).allSatisfy({ $0.isHexDigit }) {
			AddressPGPChain.registryContract = registry
		}
		AddressPGPChain.configuration = candidate
		return true
	}

	/// (option B(2)): the node list of a session. An empty list is "not provided": it never replaces a list the session already has,
	/// and the SI list of the keychain fills a session that has none. Only a non-empty supplied list replaces the session's list.
	static func resolvedNodes(supplied: [Node], current: [Node], keychain: () -> [Node]) -> [Node] {
		if !supplied.isEmpty { return supplied }
		if !current.isEmpty { return current }
		return keychain()
	}

	private static func parseNodes(_ raw: [[String: Any]]) -> [Node] {
		// The PWA `nodeInfo` carries `ip_addr`, native roster rows carry `ip`.
		// A row with only a domain is resolved through the chain roster in the
		// keychain; without an IP an entry can never be reached over HTTP.
		var rosterIpByDomain: [String: String] = [:]
		var rosterKeyByIp: [String: String] = [:]
		let roster = BeamioChatPgpKeychain.loadSiNodes()
		for kn in roster where !kn.domain.isEmpty {
			rosterIpByDomain[kn.domain.uppercased()] = kn.ip
		}
		for kn in roster where !kn.armoredPublicKey.isEmpty {
			rosterKeyByIp[kn.ip] = kn.armoredPublicKey
		}
		return raw.compactMap { n in
			var ip = String(n["ip"] as? String ?? n["ip_addr"] as? String ?? "")
			let domain = String(n["domain"] as? String ?? "")
			if BeamioSiCipherPost.normalizeIp(ip) == nil, !domain.isEmpty,
			   let known = rosterIpByDomain[domain.uppercased()] {
				ip = known
			}
			guard !ip.isEmpty || !domain.isEmpty else { return nil }
			var key = String(n["armoredPublicKey"] as? String ?? n["pgpPublicKeyArmored"] as? String ?? "")
			// A payload row without its key keeps the key the chain roster holds for the same node.
			if key.isEmpty, let norm = BeamioSiCipherPost.normalizeIp(ip), let known = rosterKeyByIp[norm] {
				key = known
			}
			return Node(
				ip: ip,
				domain: domain,
				region: String(n["region"] as? String ?? ""),
				armoredPublicKey: key
			)
		}
	}

	private static func normalizeAddress(_ raw: String) -> String {
		let t = raw.trimmingCharacters(in: .whitespacesAndNewlines)
		guard t.hasPrefix("0x"), t.count == 42 else { return t.lowercased() }
		return t.lowercased()
	}

	private static func normalizeArmorFingerprint(_ armor: String) -> String {
		armor
			.replacingOccurrences(of: "\r", with: "")
			.components(separatedBy: .whitespacesAndNewlines)
			.joined()
			.uppercased()
	}

	private static func extractSendId(from plaintext: String) -> String? {
		guard let data = plaintext.data(using: .utf8),
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else { return nil }
		if let id = obj["sendId"] as? String { return id }
		if let text = obj["text"] as? String,
		   let innerData = text.data(using: .utf8),
		   let inner = try? JSONSerialization.jsonObject(with: innerData) as? [String: Any],
		   let id = inner["sendId"] as? String {
			return id
		}
		return nil
	}
}
