import Foundation

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
			BeamioChatPgpKeychain.SiNode(ip: ip, domain: domain, region: region)
		}
	}

	public final class Session {
		public init() {}
		public var eoa: String = ""
		public var pgpPrivateKeyArmored: String = ""
		public var pgpPublicKeyArmored: String = ""
		public var ownRouteArmoredPublicKey: String = ""
		public var mailboxIp: String = ""
		public var nodes: [Node] = []
		public var routes: [[String: Any]] = []
		public var conetRpcUrl: String = "https://rpc1.conet.network"
		public var ipfsBaseUrl: String = "https://ipfs.conet.network/api"
		public var ipfsWriteBaseUrl: String = ""
		public var apiBaseUrl: String = "https://beamio.app/api"
		public var chatIndexRegistryAddress: String = "0x1511Caa71081C84d8a591490D1b83879088EED72"
		public var chainId: Int = 224422
		public var history: BeamioConetChatHistoryStore?
		public var destroyed = false
		/// The app confirms each inbound message with `ackInbound` after it has
		/// stored it. Until then the mailbox keeps its offline copy, so a message
		/// is not lost when the page is starting, suspended or killed.
		public var deferAck = false
		/// armorHash → message waiting for the app's `ackInbound`. Guarded by `pendingLock`.
		var pendingAcks: [String: (plaintext: String, from: String, at: Date)] = [:]
		let pendingLock = NSLock()
	}

	/// Unconfirmed for this long: forget it without ACK; the mailbox redelivers it later.
	private static let pendingAckTTL: TimeInterval = 600

	private static let lock = NSLock()
	private static var session: Session?
	private static var emit: WebEmit?
	private static let listen = BeamioConetChatListenSession()
	private static var voiceSessions = Set<String>()

	public static func handleCommand(_ body: [String: Any], emit: @escaping WebEmit) {
		self.emit = emit
		BeamioConetChatSignBroker.setWebEmit(emit)
		let type = String(body["type"] as? String ?? "")
		switch type {
		case "init":
			handleInit(body)
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
			listen.pause()
			emitEvent(["type": "event:status", "payload": ["status": "idle", "detail": "paused"]])
		case "ackInbound":
			handleAckInbound(body)
		case "resume":
			resumeListen()
		case "destroy":
			destroy()
		default:
			NSLog("[BeamioConetChat] unknown command %@", type)
		}
	}

	// MARK: - Init / routes / nodes

	private static func handleInit(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let payload = body["payload"] as? [String: Any] else {
			ack(reqId, ok: false, error: "missing_payload")
			return
		}
		lock.lock()
		listen.stop()
		session?.history?.destroy()
		session?.history = nil
		let s = Session()
		session = s
		lock.unlock()

		if let identity = payload["identity"] as? [String: Any] {
			s.eoa = normalizeAddress(String(identity["eoaAddress"] as? String ?? identity["eoa"] as? String ?? ""))
			s.pgpPrivateKeyArmored = String(identity["pgpPrivateKeyArmored"] as? String ?? "")
			s.pgpPublicKeyArmored = String(identity["pgpPublicKeyArmored"] as? String ?? "")
			s.ownRouteArmoredPublicKey = String(identity["ownRouteArmoredPublicKey"] as? String
				?? identity["routePublicKeyArmored"] as? String ?? "")
			s.mailboxIp = String(identity["mailboxIp"] as? String ?? "")
		}
		if s.pgpPrivateKeyArmored.isEmpty || s.ownRouteArmoredPublicKey.isEmpty {
			if let kc = BeamioChatPgpKeychain.load() {
				if s.pgpPrivateKeyArmored.isEmpty { s.pgpPrivateKeyArmored = kc.privateKeyArmor }
				if s.pgpPublicKeyArmored.isEmpty { s.pgpPublicKeyArmored = kc.publicKeyArmor }
				if s.ownRouteArmoredPublicKey.isEmpty { s.ownRouteArmoredPublicKey = kc.routePublicKeyArmor }
				if s.mailboxIp.isEmpty { s.mailboxIp = kc.mailboxIp }
				if s.eoa.isEmpty { s.eoa = normalizeAddress(kc.eoa) }
			}
		}
		s.conetRpcUrl = String(payload["conetRpcUrl"] as? String ?? s.conetRpcUrl)
		s.ipfsBaseUrl = String(payload["ipfsBaseUrl"] as? String ?? s.ipfsBaseUrl)
		s.ipfsWriteBaseUrl = String(payload["ipfsWriteBaseUrl"] as? String ?? "")
		s.apiBaseUrl = String(payload["apiBaseUrl"] as? String ?? s.apiBaseUrl)
		s.chatIndexRegistryAddress = String(payload["chatIndexRegistryAddress"] as? String ?? s.chatIndexRegistryAddress)
		s.deferAck = (payload["deferAck"] as? Bool) == true
		if let cid = payload["chainId"] as? Int { s.chainId = cid }
		else if let cid = payload["chainId"] as? NSNumber { s.chainId = cid.intValue }

		if let nodesRaw = payload["nodes"] as? [[String: Any]] {
			s.nodes = parseNodes(nodesRaw)
		} else if let kc = BeamioChatPgpKeychain.load(), !kc.siNodes.isEmpty {
			s.nodes = kc.siNodes.map { Node(ip: $0.ip, domain: $0.domain, region: $0.region, armoredPublicKey: "") }
		}
		if let routesRaw = payload["routes"] as? [[String: Any]] {
			s.routes = routesRaw
		}

		guard !s.eoa.isEmpty, s.pgpPrivateKeyArmored.contains("BEGIN PGP PRIVATE KEY") else {
			ack(reqId, ok: false, error: "missing_identity")
			return
		}

		BeamioOpenPgpHost.shared.ensureReady { ok in
			guard ok else {
				ack(reqId, ok: false, error: "openpgp_not_ready")
				return
			}
			let host = BeamioOpenPgpHost.shared
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
			// Listen first: it must not wait on the (sign-dependent) history key derivation.
			// `historyApi: 2` = streamed `event:historyBuffer`, array `historyRead`, sendId-idempotent append.
			emitEvent(["type": "ready", "reqId": reqId, "result": ["historyApi": 2]])
			startListen(session: s)
			s.history?.prepare { _ in }
		}
	}

	private static func handleSetRoutes(_ body: [String: Any]) {
		guard let s = currentSession() else { return }
		if let routes = body["routes"] as? [[String: Any]] {
			s.routes = routes
		}
	}

	private static func handleSetNodes(_ body: [String: Any]) {
		guard let s = currentSession() else { return }
		if let nodes = body["nodes"] as? [[String: Any]] {
			s.nodes = parseNodes(nodes)
		}
	}

	// MARK: - Send

	private static func handleSend(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession(),
		      let to = body["to"] as? [String: Any]
		else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let payload = String(body["payload"] as? String ?? "")
		let sendId = String(body["sendId"] as? String ?? UUID().uuidString)
		let noPush = (body["beamioNoPush"] as? Bool) ?? false
		let userPgp = String(to["userPublicKeyArmored"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
		let mailboxRoute = String(to["routerArmoredPublicKey"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
		guard userPgp.contains("BEGIN PGP PUBLIC KEY") else {
			ack(reqId, ok: false, error: "missing_recipient_pgp")
			return
		}
		let host = BeamioOpenPgpHost.shared
		BeamioConetChatSignBroker.requestEip191(message: payload) { signResult in
			switch signResult {
			case .failure(let err):
				ack(reqId, ok: false, error: err.localizedDescription)
			case .success(let signature):
				let envelope: [String: Any] = [
					"timestamp": Int(Date().timeIntervalSince1970 * 1000),
					"text": payload,
					"from": s.eoa,
					"signMessage": signature,
				]
				host.encryptUtf8JsonBase64(jsonObject: envelope, recipientPublicArmor: userPgp) { encResult in
					switch encResult {
					case .failure(let err):
						ack(reqId, ok: false, error: err.localizedDescription)
					case .success(let armor):
						func postInner(_ finalArmor: String) {
							DispatchQueue.global(qos: .userInitiated).async {
								let ok = postToEntriesSync(armor: finalArmor, mailboxRoute: mailboxRoute, session: s)
								DispatchQueue.main.async {
									ack(reqId, ok: true, result: ["sent": ok, "sendId": sendId])
								}
							}
						}
						if noPush {
							guard mailboxRoute.contains("BEGIN PGP PUBLIC KEY") else {
								ack(reqId, ok: false, error: "NoPush requires recipient mailbox routerArmoredPublicKey")
								return
							}
							host.wrapArmorToMailboxWork(
								innerArmor: armor,
								mailboxRoutePublicArmor: mailboxRoute,
								noPush: true
							) { wrapResult in
								switch wrapResult {
								case .failure(let err):
									ack(reqId, ok: false, error: err.localizedDescription)
								case .success(let wrapped):
									postInner(wrapped)
								}
							}
						} else {
							postInner(armor)
						}
					}
				}
			}
		}
	}

	// MARK: - Group

	private static func handleSendGroup(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession(),
		      let request = body["request"] as? [String: Any],
		      let roster = request["roster"] as? [String: Any],
		      let members = roster["members"] as? [[String: Any]]
		else {
			ack(reqId, ok: false, error: "bad_group_request")
			return
		}
		let bodyText = String(request["body"] as? String ?? request["text"] as? String ?? "")
		let host = BeamioOpenPgpHost.shared
		BeamioConetChatSignBroker.requestEip191(message: bodyText) { signResult in
			guard case .success(let signature) = signResult else {
				ack(reqId, ok: false, error: "group_sign_failed")
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
					guard pgp.contains("BEGIN PGP PUBLIC KEY") else { continue }
					group.enter()
					host.encryptUtf8JsonBase64(jsonObject: envelope, recipientPublicArmor: pgp) { enc in
						defer { group.leave() }
						guard case .success(let armor) = enc else { return }
						let ok = postToEntriesSync(armor: armor, mailboxRoute: route, session: s)
						if ok {
							deliverLock.lock()
							delivered += 1
							deliverLock.unlock()
						}
					}
				}
				group.wait()
				DispatchQueue.main.async {
					ack(reqId, ok: true, result: ["delivered": delivered, "members": members.count])
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

	private static func handleHistoryRead(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
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

	// MARK: - Mailbox commands

	private static func handleMailboxCommand(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession() else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let routeKey = String(body["routerArmoredPublicKey"] as? String ?? "")
		guard let command = body["command"] as? [String: Any],
		      routeKey.contains("BEGIN PGP PUBLIC KEY")
		else {
			ack(reqId, ok: false, error: "bad_mailbox_command")
			return
		}
		postSignedMailboxCommand(session: s, routerArmoredPublicKey: routeKey, command: command) { ok, _ in
			ack(reqId, ok: true, result: ["ok": ok])
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

	private static func handleVoiceFrame(_ body: [String: Any]) {
		let reqId = body["reqId"] as? Int ?? 0
		guard let s = currentSession() else {
			ack(reqId, ok: false, error: "not_ready")
			return
		}
		let routeKey = String(body["routerArmoredPublicKey"] as? String ?? "")
		guard let frame = body["frame"] as? [String: Any],
		      routeKey.contains("BEGIN PGP PUBLIC KEY")
		else {
			ack(reqId, ok: false, error: "bad_voice_frame")
			return
		}
		postSignedMailboxCommand(session: s, routerArmoredPublicKey: routeKey, command: frame) { ok, _ in
			ack(reqId, ok: true, result: ["sent": ok])
		}
	}

	// MARK: - Listen lifecycle

	private static func startListen(session: Session) {
		listen.start(
			session: session,
			onStatus: { status, detail in
				var payload: [String: Any] = ["status": status]
				if let detail { payload["detail"] = detail }
				emitEvent(["type": "event:status", "payload": payload])
			},
			onInbound: { plaintext, armorHash, viaDomain in
				handleInbound(plaintext: plaintext, armorHash: armorHash, viaDomain: viaDomain)
			}
		)
	}

	private static func resumeListen() {
		guard let s = currentSession() else { return }
		listen.resume(
			session: s,
			onStatus: { status, detail in
				var payload: [String: Any] = ["status": status]
				if let detail { payload["detail"] = detail }
				emitEvent(["type": "event:status", "payload": payload])
			},
			onInbound: { plaintext, armorHash, viaDomain in
				handleInbound(plaintext: plaintext, armorHash: armorHash, viaDomain: viaDomain)
			}
		)
	}

	private static func destroy() {
		listen.stop()
		BeamioConetChatSignBroker.cancelAll(reason: "destroyed")
		lock.lock()
		session?.destroyed = true
		session?.history?.destroy()
		session?.history = nil
		session = nil
		voiceSessions.removeAll()
		lock.unlock()
		emitEvent(["type": "event:status", "payload": ["status": "destroyed"]])
	}

	// MARK: - Inbound + dual receipts

	private static func handleInbound(plaintext: String, armorHash: String, viaDomain: String) {
		guard let s = currentSession() else { return }
		let host = BeamioOpenPgpHost.shared
		// Decrypt completes on the main thread and `host.verifyMessage` needs the
		// main thread too. Never block on it with a semaphore (that deadlocked for
		// 8 s and every inbound message was dropped as "verify failed").
		verifyEnvelope(plaintext: plaintext, host: host) { from in
			guard let from, !from.isEmpty else {
				emitEvent(["type": "event:log", "level": "warn", "message": "inbound verify failed — drop"])
				return
			}
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
			if s.deferAck, !armorHash.isEmpty {
				let now = Date()
				s.pendingLock.lock()
				s.pendingAcks = s.pendingAcks.filter { now.timeIntervalSince($0.value.at) < pendingAckTTL }
				s.pendingAcks[armorHash] = (plaintext, from, now)
				s.pendingLock.unlock()
			} else {
				emitDualReceipts(session: s, plaintext: plaintext, armorHash: armorHash, from: from)
			}
		}
	}

	/// The app stored these messages: now send the mailbox ACK (deletes the
	/// offline copy) and the sender's delivery receipt.
	private static func handleAckInbound(_ body: [String: Any]) {
		guard let s = currentSession() else { return }
		var hashes = (body["armorHashes"] as? [String]) ?? []
		if let one = body["armorHash"] as? String, !one.isEmpty { hashes.append(one) }
		for hash in hashes where !hash.isEmpty {
			s.pendingLock.lock()
			let pending = s.pendingAcks.removeValue(forKey: hash)
			s.pendingLock.unlock()
			guard let pending else { continue }
			emitDualReceipts(session: s, plaintext: pending.plaintext, armorHash: hash, from: pending.from)
		}
	}

	/// Recover the EIP-191 signer: the recovered address is the only trusted
	/// sender identity. A differing claimed `from` is passed on for the app to flag.
	private static func verifyEnvelope(
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

	private static func emitDualReceipts(session: Session, plaintext: String, armorHash: String, from: String) {
		if session.ownRouteArmoredPublicKey.contains("BEGIN PGP PUBLIC KEY") {
			postSignedMailboxCommand(
				session: session,
				routerArmoredPublicKey: session.ownRouteArmoredPublicKey,
				command: [
					"command": "gossip_delivery_ack",
					"walletAddress": session.eoa,
					"armorHash": armorHash,
					"timestamp": Int(Date().timeIntervalSince1970),
				]
			) { _, _ in }
		}
		guard let route = session.routes.first(where: {
			normalizeAddress(String($0["eoaAddress"] as? String ?? $0["eoa"] as? String ?? "")) == from.lowercased()
		}),
		let userPgp = route["userPublicKeyArmored"] as? String,
		userPgp.contains("BEGIN PGP PUBLIC KEY")
		else { return }

		let sendId = extractSendId(from: plaintext) ?? ""
		let receiptInner: [String: Any] = [
			"type": "beamio_chat_delivery_receipt_v1",
			"sendId": sendId,
			"armorHash": armorHash,
			"deliveredAt": Int(Date().timeIntervalSince1970 * 1000),
			"from": session.eoa,
		]
		guard let receiptData = try? JSONSerialization.data(withJSONObject: receiptInner),
		      let receiptJson = String(data: receiptData, encoding: .utf8)
		else { return }
		let pending: [String: Any] = [
			"sendId": UUID().uuidString,
			"from": "me",
			"text": receiptJson,
			"createdAt": Int(Date().timeIntervalSince1970 * 1000),
		]
		guard let pendingData = try? JSONSerialization.data(withJSONObject: pending),
		      let pendingJson = String(data: pendingData, encoding: .utf8)
		else { return }
		handleSend([
			"reqId": -1,
			"to": route,
			"payload": pendingJson,
			"sendId": UUID().uuidString,
			"beamioNoPush": true,
		])
	}

	// MARK: - Shared helpers

	private static func postSignedMailboxCommand(
		session: Session,
		routerArmoredPublicKey: String,
		command: [String: Any],
		completion: @escaping (_ ok: Bool, _ json: [String: Any]?) -> Void
	) {
		var cmd = command
		if cmd["walletAddress"] == nil { cmd["walletAddress"] = session.eoa }
		if cmd["timestamp"] == nil { cmd["timestamp"] = Int(Date().timeIntervalSince1970) }
		guard let data = try? JSONSerialization.data(withJSONObject: cmd),
		      let message = String(data: data, encoding: .utf8)
		else {
			completion(false, nil)
			return
		}
		let host = BeamioOpenPgpHost.shared
		BeamioConetChatSignBroker.requestEip191(message: message) { signResult in
			guard case .success(let signature) = signResult else {
				completion(false, nil)
				return
			}
			host.encryptSignedRouteCommand(
				message: message,
				signMessage: signature,
				routePublicArmor: routerArmoredPublicKey
			) { encResult in
				guard case .success(let armor) = encResult else {
					completion(false, nil)
					return
				}
				DispatchQueue.global(qos: .userInitiated).async {
					let ok = postToEntriesSync(armor: armor, mailboxRoute: routerArmoredPublicKey, session: session)
					DispatchQueue.main.async { completion(ok, nil) }
				}
			}
		}
	}

	/// Sync POST via entry ≠ B. Optionally wrap to entry route PGP when available.
	@discardableResult
	private static func postToEntriesSync(armor: String, mailboxRoute: String, session: Session) -> Bool {
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
		let entryCandidates = session.nodes.filter { n in
			guard let ip = BeamioSiCipherPost.normalizeIp(n.ip) else { return false }
			return !exclude.contains(ip)
		}.shuffled()

		for entry in entryCandidates.prefix(4) {
			var postArmor = armor
			if entry.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") {
				let sem = DispatchSemaphore(value: 0)
				host.wrapArmorToEntryRoute(innerArmor: armor, entryRoutePublicArmor: entry.armoredPublicKey) { r in
					if case .success(let a) = r { postArmor = a }
					sem.signal()
				}
				_ = sem.wait(timeout: .now() + 8)
			}
			let result = BeamioSiCipherPost.post(
				armor: postArmor,
				nodes: [entry.asKeychainNode()],
				excludeIps: exclude,
				maxAttempts: 1
			)
			if result.ok { return true }
		}

		// Fallback: any roster node excluding mailbox.
		let roster = session.nodes.map { $0.asKeychainNode() }
		if roster.isEmpty, let kc = BeamioChatPgpKeychain.load() {
			let result = BeamioSiCipherPost.post(armor: armor, nodes: kc.siNodes, excludeIps: exclude)
			return result.ok
		}
		let result = BeamioSiCipherPost.post(armor: armor, nodes: roster, excludeIps: exclude)
		return result.ok
	}

	private static func currentSession() -> Session? {
		lock.lock(); defer { lock.unlock() }
		guard let s = session, !s.destroyed else { return nil }
		return s
	}

	private static func emitEvent(_ payload: [String: Any]) {
		let out: [String: Any] = ["action": "chatModuleEvent", "event": payload]
		DispatchQueue.main.async {
			emit?(out)
		}
	}

	private static func ack(_ reqId: Int, ok: Bool, result: Any? = nil, error: String? = nil) {
		if reqId < 0 { return }
		var payload: [String: Any] = ["type": "ack", "reqId": reqId, "ok": ok]
		if ok, let result { payload["result"] = result }
		if !ok { payload["error"] = error ?? "error" }
		emitEvent(payload)
	}

	private static func parseNodes(_ raw: [[String: Any]]) -> [Node] {
		// The PWA `nodeInfo` carries `ip_addr`, native roster rows carry `ip`.
		// A row with only a domain is resolved through the chain roster in the
		// keychain; without an IP an entry can never be reached over HTTP.
		var rosterIpByDomain: [String: String] = [:]
		for kn in BeamioChatPgpKeychain.loadSiNodes() where !kn.domain.isEmpty {
			rosterIpByDomain[kn.domain.uppercased()] = kn.ip
		}
		return raw.compactMap { n in
			var ip = String(n["ip"] as? String ?? n["ip_addr"] as? String ?? "")
			let domain = String(n["domain"] as? String ?? "")
			if BeamioSiCipherPost.normalizeIp(ip) == nil, !domain.isEmpty,
			   let known = rosterIpByDomain[domain.uppercased()] {
				ip = known
			}
			guard !ip.isEmpty || !domain.isEmpty else { return nil }
			return Node(
				ip: ip,
				domain: domain,
				region: String(n["region"] as? String ?? ""),
				armoredPublicKey: String(n["armoredPublicKey"] as? String
					?? n["pgpPublicKeyArmored"] as? String ?? "")
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
