import Foundation

/// The registration of a new chat identity on the chain: the signed eight-line message (`BeamioChatRouteRegister.signedRegistration`), the POST to the Beamio API
/// (`/api/regiestChatRoute`, which the Cluster verifies and the Master writes with addPublicPGPByAdmin), and the read back from the chain.
///
/// The POST is not the proof: the server may answer before the chain write is final. The registration counts only when the agreed read of the two endpoints (one block, one
/// hash, the same answers) shows this very key. A 4xx other than 409 is refused and not sent again at once; 409, 5xx and no answer go to the read back.
public enum BeamioPGPRegistrar {
	/// The origin of the Beamio API (https), set once from the shell's native build configuration, never from a page payload. Nil: nothing is sent.
	public static var apiBase: URL?

	/// The product registration is available when the API origin and both chain endpoints and the chain configuration are set.
	static var isConfigured: Bool {
		guard BeamioNewAccountFeature.enabled, let apiBase, apiBase.scheme?.lowercased() == "https", let configuration = AddressPGPChain.configuration, configuration.isUsable,
		      let second = AddressPGPChain.shellEndpointSecond, second.scheme?.lowercased() == "https" else { return false }
		return true
	}

	public enum PostOutcome: Equatable {
		case accepted
		case conflict
		case refused(Int)
		case server(Int)
		case network
	}

	/// POSTs one JSON body. Replaced in tests. The status, or nil when there was no answer.
	static var post: (URL, Data) -> Int? = defaultPost

	static let postTimeoutSeconds: TimeInterval = 15

	static func defaultPost(_ url: URL, _ body: Data) -> Int? {
		guard url.scheme?.lowercased() == "https" else { return nil }
		var request = URLRequest(url: url, timeoutInterval: postTimeoutSeconds)
		request.httpMethod = "POST"
		request.setValue("application/json", forHTTPHeaderField: "Content-Type")
		request.httpBody = body
		let done = DispatchSemaphore(value: 0)
		var status: Int?
		URLSession.shared.dataTask(with: request) { _, response, _ in
			status = (response as? HTTPURLResponse)?.statusCode
			done.signal()
		}.resume()
		if done.wait(timeout: .now() + postTimeoutSeconds + 1) == .timedOut { return nil }
		return status
	}

	static func classify(_ status: Int?) -> PostOutcome {
		guard let status else { return .network }
		if (200 ..< 300).contains(status) { return .accepted }
		if status == 409 { return .conflict }
		if (400 ..< 500).contains(status) { return .refused(status) }
		if (500 ..< 600).contains(status) { return .server(status) }
		return .network
	}

	/// The read back schedule after a POST: seconds to wait before each agreed read (2, 4, 8, 16, 32: about a minute in all, plus the reads).
	static var pollDelays: [TimeInterval] = [2, 4, 8, 16, 32]
	/// The wait. Replaced in tests.
	static var sleep: (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }
	/// The agreed read. Replaced in tests.
	static var readAgreed: (String) -> Result<AddressPGPChain.Agreed, Error> = { AddressPGPChain.readAgreed(eoa: $0) }
	/// The identity of an armored key: primary fingerprint and subkey key ID. Replaced in tests (the OpenPGP wrapper is linked on iOS builds only).
	static var identityOf: (String) -> (fingerprint: String, subkeyKeyID: String)? = { BeamioPGPBackup.keyIdentity(armor: $0) }
	/// The signing stage. Replaced in tests.
	static var sign: (String, String, BeamioChatRouteRegister.Request, Int64, [UInt8], [UInt8]) -> Result<[String: Any], BeamioChatRouteRegister.RouteRegisterRefusal> = {
		BeamioChatRouteRegister.signedRegistration(account: $0, privateArmor: $1, request: $2, timestamp: $3, iv: $4, nonce: $5)
	}
	/// The choice of the mailbox route. Replaced in tests.
	static var chooseRoute: () -> (routeKeyID: String, armor: String)? = defaultChooseRoute

	/// A node of the roster that has a domain and a route public key, taken at random. Nil when the roster has none.
	static func defaultChooseRoute() -> (routeKeyID: String, armor: String)? {
		let usable = BeamioChatPgpKeychain.loadSiNodes().filter { !$0.domain.isEmpty && $0.armoredPublicKey.contains("BEGIN PGP PUBLIC KEY") }
		guard !usable.isEmpty else { return nil }
		let pick = usable[Int.random(in: 0 ..< usable.count)]
		return (pick.domain, pick.armoredPublicKey)
	}

	/// Whether two armored public keys are the same key: by primary fingerprint when the OpenPGP wrapper is linked, else by the normalized text.
	static func sameKey(_ a: String, _ b: String) -> Bool {
		if let x = identityOf(a), let y = identityOf(b) {
			return x.fingerprint == y.fingerprint && x.subkeyKeyID == y.subkeyKeyID
		}
		return BeamioChatRouteRegister.normalizedArmor(a) == BeamioChatRouteRegister.normalizedArmor(b)
	}

	/// What the registration of one pending identity came to.
	public enum Outcome: Equatable {
		/// The chain shows this key; the route it was sent with.
		case verified(routeArmor: String)
		/// The chain shows another key for the account: nothing more is sent, the pending key stays.
		case conflict
		/// The server refused the request (4xx but 409): not sent again at once.
		case refused(Int)
		/// No registration is visible after the read back window: the pending key stays, a later call signs again (new nonce, same key). The reason: `submit_5xx` (the server failed
		/// or did not answer) or `readback_timeout`.
		case retryLater(String)
		case locked
		/// A step before the chain: no route, no API, the signature, the chain endpoints.
		case notReady(String)
	}

	/// The route chosen for the pending identity: the one it already has, else a new choice, kept with the pending identity.
	static func routeFor(eoa: String, pending: inout BeamioChatPgpKeychain.PendingIdentity) -> (routeKeyID: String, armor: String)? {
		if !pending.routeKeyID.isEmpty, !pending.routeArmor.isEmpty { return (pending.routeKeyID, pending.routeArmor) }
		guard let route = chooseRoute() else { return nil }
		pending.routeKeyID = route.routeKeyID
		pending.routeArmor = route.armor
		_ = BeamioChatPgpKeychain.savePending(eoa: eoa, pending)
		return route
	}

	/// Signs, posts and reads back the registration of `pending` (the private key is never sent: only the backup under the account key goes out). Single flight is the caller's.
	static func submitAndVerify(eoa rawEoa: String, pending startPending: BeamioChatPgpKeychain.PendingIdentity, sendTransaction: Bool = true) -> Outcome {
		let eoa = rawEoa.lowercased()
		var pending = startPending
		guard !BeamioFirstIdentityCoordinator.isLocked(eoa) else { return .locked }
		guard let apiBase, apiBase.scheme?.lowercased() == "https" else { return .notReady("api") }
		guard let route = routeFor(eoa: eoa, pending: &pending) else { return .notReady("route") }
		guard let identity = identityOf(pending.publicArmor) else { return .notReady("openpgp") }
		let request = BeamioChatRouteRegister.Request(
			keyID: identity.subkeyKeyID.uppercased(), publicKeyArmored: Data(pending.publicArmor.utf8).base64EncodedString(), routeKeyID: route.routeKeyID
		)
		// the lock is judged again right before the signature, which is the last step before the network
		guard !BeamioFirstIdentityCoordinator.isLocked(eoa) else { return .locked }
		let signed = sign(
			eoa, pending.privateArmor, request, Int64(Date().timeIntervalSince1970 * 1000),
			BeamioChatRouteRegister.randomBytes(12), BeamioChatRouteRegister.randomBytes(16)
		)
		let fields: [String: Any]
		switch signed {
		case .failure(let refusal):
			return refusal.code == "locked" ? .locked : .notReady("sign_" + refusal.code)
		case .success(let value): fields = value
		}
		guard let body = try? JSONSerialization.data(withJSONObject: fields) else { return .notReady("body") }
		let outcome = classify(post(apiBase.appendingPathComponent("api/regiestChatRoute"), body))
		if case .refused(let status) = outcome { return .refused(status) }
		// accepted, conflict, a server failure or no answer: the chain decides
		var serverFailed = false
		switch outcome {
		case .server, .network: serverFailed = true
		default: break
		}
		return readBack(eoa: eoa, pending: pending, route: route, reasonIfNotVisible: serverFailed ? "submit_5xx" : "readback_timeout")
	}

	/// The read back: the agreed read at each step of the schedule. The key must be the pending key (primary fingerprint and subkey key ID), with a backup in place.
	static func readBack(eoa: String, pending: BeamioChatPgpKeychain.PendingIdentity, route: (routeKeyID: String, armor: String), reasonIfNotVisible: String = "readback_timeout") -> Outcome {
		for delay in pollDelays {
			sleep(delay)
			guard case .success(let agreed) = readAgreed(eoa) else { continue }
			let chain = agreed.snapshot
			if chain.exists, !chain.publicArmor.isEmpty {
				return sameKey(chain.publicArmor, pending.publicArmor) && !chain.backupBase64.isEmpty ? .verified(routeArmor: route.armor) : .conflict
			}
		}
		return .retryLater(reasonIfNotVisible)
	}

	/// The product `Registering` of `BeamioPGPIdentityCreate.confirm`: the pending key of the account is signed, posted and read back.
	static let production = ProductRegistration()

	final class ProductRegistration: BeamioPGPIdentityCreate.Registering {
		private let lock = NSLock()
		private var routes: [String: String] = [:]

		func register(eoa rawEoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error> {
			let eoa = rawEoa.lowercased()
			guard let pending = BeamioChatPgpKeychain.loadPending(eoa: eoa), pending.idempotencyKey == idempotencyKey, !pending.privateArmor.isEmpty else {
				return .failure(RegisterError.notPrepared)
			}
			switch submitAndVerify(eoa: eoa, pending: pending) {
			case .verified(let armor):
				lock.lock(); routes[eoa] = armor; lock.unlock()
				return .success(())
			case .conflict: return .failure(RegisterError.conflict)
			case .refused: return .failure(RegisterError.refused)
			case .retryLater, .locked, .notReady: return .failure(RegisterError.notVerified)
			}
		}

		func routeArmor(registered eoa: String) -> String {
			lock.lock(); defer { lock.unlock() }
			return routes[eoa.lowercased()] ?? ""
		}
	}

	enum RegisterError: Error, Equatable { case notPrepared, conflict, refused, notVerified }
}

/// The first identity of a new account, made by the SDK on its own once the account is unlocked (G2), when the agreed read of the chain shows nothing registered:
/// S0 the local state, S1 the agreed read, S2 generate and keep the pending key, S3 read again before the submission, S4 sign and post, S5 read back, S6 activate.
/// A pending key is never regenerated; every step can be run again. Single flight per account.
public enum BeamioFirstIdentityCoordinator {
	/// The rule that allows the silent first identity: a confirmed absence on the chain, read by two endpoints that agree.
	static let approval = "confirmed-no-record"

	public enum Outcome: Equatable {
		/// The account has its identity: registered on the chain with the local key.
		case active
		/// The chain holds a registration of the account (or a backup): the restore flow owns that, nothing is made here.
		case registeredElsewhere
		/// The device holds an old chat key or something that cannot be assigned to this account: not a first identity.
		case notFirst
		case conflict
		case refused(Int)
		case retryLater(String)
		case locked
		case notReady(String)
	}

	/// The lock of the account. Replaced in tests.
	static var isLocked: (String) -> Bool = { BeamioPasscodeSession.shared.isLocked(eoa: $0) }
	/// The agreed read. Replaced in tests.
	static var readAgreed: (String) -> Result<AddressPGPChain.Agreed, Error> = { AddressPGPChain.readAgreed(eoa: $0) }
	/// Whether this device holds an old chat key. Replaced in tests.
	static var legacy: (String) -> BeamioFirstIdentity.Legacy = { BeamioFirstIdentity.legacy(eoa: $0) }

	private static func isRegistered(_ chain: AddressPGPChain.Snapshot) -> Bool {
		chain.exists || !chain.backupBase64.isEmpty || !chain.publicArmor.isEmpty
	}

	@discardableResult
	public static func run(eoa rawEoa: String) -> Outcome {
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty else { return .notReady("eoa") }
		guard BeamioPGPIdentityCreate.beginWrite(eoa: eoa) else { return .retryLater("busy") }
		defer { BeamioPGPIdentityCreate.endWrite(eoa: eoa) }
		guard !isLocked(eoa) else { return .locked }
		// an erase that was left behind comes first
		guard BeamioChatPgpKeychain.retryCleanup(eoa: eoa) else { return .retryLater("cleanup") }

		// S0: the local state
		let record = BeamioChatPgpKeychain.load(eoa: eoa)
		var pending = BeamioChatPgpKeychain.loadPending(eoa: eoa)
		if let held = pending, held.privateArmor.isEmpty {
			// a prepared identity of the confirmation flow with no key: not ours
			pending = nil
		}
		if let record, record.hasUserPrivate {
			guard case .success(let agreed) = readAgreed(eoa) else { return .retryLater("chain_read") }
			let chain = agreed.snapshot
			if chain.exists, !chain.publicArmor.isEmpty {
				// registered: the same key keeps the identity; another key is the restore flow's
				return BeamioPGPRegistrar.sameKey(chain.publicArmor, record.publicKeyArmor) ? .active : .registeredElsewhere
			}
			if isRegistered(chain) { return .registeredElsewhere }
			// a local key that was never registered: only a record without a route is discarded and made again (a record with a route is not touched)
			guard !record.hasRoutePublic else { return .retryLater("record_unregistered") }
			guard BeamioChatPgpKeychain.removeRecord(eoa: eoa) else { return .retryLater("record_remove") }
		}

		if pending == nil {
			// S1: the agreed read, and the device judgement
			guard case .success(let agreed) = readAgreed(eoa) else { return .retryLater("chain_read") }
			let chain = agreed.snapshot
			if isRegistered(chain) { return .registeredElsewhere }
			guard legacy(eoa) == .absent else { return .notFirst }
			// S2: generate, keep as pending with its meta, read back
			guard !isLocked(eoa) else { return .locked }
			guard case .success(let pair) = BeamioPGPIdentityCreate.generateKeyPair(eoa) else { return .notReady("generation") }
			let created = BeamioChatPgpKeychain.PendingIdentity(
				privateArmor: pair.privateArmor, publicArmor: pair.publicArmor, idempotencyKey: UUID().uuidString,
				seen: BeamioPGPIdentityCreate.seenToken(chain) + "|block=" + agreed.block, mode: BeamioPGPIdentityCreate.Mode.first.rawValue
			)
			guard BeamioChatPgpKeychain.savePending(eoa: eoa, created), let back = BeamioChatPgpKeychain.loadPending(eoa: eoa), back == created else {
				_ = BeamioChatPgpKeychain.clearPending(eoa: eoa)
				return .notReady("pending_write")
			}
			pending = created
		}
		guard let held = pending else { return .notReady("pending") }

		// S3: read again before the submission (a lock stops it first: nothing is read for, signed or sent by a locked account)
		guard !isLocked(eoa) else { return .locked }
		guard case .success(let again) = readAgreed(eoa) else { return .retryLater("chain_read") }
		let before = again.snapshot
		var route = (routeKeyID: held.routeKeyID, armor: held.routeArmor)
		if before.exists || !before.publicArmor.isEmpty {
			if BeamioPGPRegistrar.sameKey(before.publicArmor, held.publicArmor) {
				// the registration of this very key is already there (an earlier submission): go to the activation
				return activate(eoa: eoa, pending: held, routeArmor: route.armor)
			}
			return .conflict
		}
		if isRegistered(before) { return .conflict }

		// S4 and S5: sign, post, read back
		switch BeamioPGPRegistrar.submitAndVerify(eoa: eoa, pending: held) {
		case .verified(let armor):
			route.armor = armor
			return activate(eoa: eoa, pending: BeamioChatPgpKeychain.loadPending(eoa: eoa) ?? held, routeArmor: armor)
		case .conflict: return .conflict
		case .refused(let status): return .refused(status)
		case .retryLater(let why): return .retryLater(why)
		case .locked: return .locked
		case .notReady(let why): return .notReady(why)
		}
	}

	/// S6: the registered key becomes the local record with the route it was registered with.
	private static func activate(eoa: String, pending: BeamioChatPgpKeychain.PendingIdentity, routeArmor: String) -> Outcome {
		// a route that was never chosen (the key was found on the chain after a restart without it) is not guessed
		guard !routeArmor.isEmpty else { return .retryLater("route_unknown") }
		switch BeamioPGPIdentityCreate.activate(eoa: eoa, pending: pending, routeArmor: routeArmor) {
		case .ok: return .active
		default: return .retryLater("activate")
		}
	}
}

/// Runs the first identity in the background after an init: the first run at once, then again after 30 s, 60 s, 120 s and 300 s while the run says `retry_later`. One schedule per account.
/// It does nothing unless the registration is configured (the Beamio API origin and the two chain endpoints from the shell's build configuration).
enum BeamioFirstIdentityScheduler {
	static var delays: [TimeInterval] = [0, 30, 60, 120, 300]
	static var sleep: (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }
	/// Runs the schedule where it is called, instead of on a queue. Tests only.
	static var synchronous = false

	private static let lock = NSLock()
	private static var running: Set<String> = []
	private static let queue = DispatchQueue(label: "beamio.first-identity", qos: .utility)

	static func kick(eoa rawEoa: String) {
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty, BeamioPGPRegistrar.isConfigured else { return }
		lock.lock()
		let started = running.insert(eoa).inserted
		lock.unlock()
		guard started else { return }
		let work = { runSchedule(eoa: eoa) }
		if synchronous { work() } else { queue.async(execute: work) }
	}

	static func runSchedule(eoa: String) {
		defer { lock.lock(); running.remove(eoa); lock.unlock() }
		var submitted = false
		for (index, delay) in delays.enumerated() {
			if delay > 0 { sleep(delay) }
			// the account must still be the unlocked account of the session
			guard BeamioConetChatModule.nativeGate() == .g2, !BeamioPasscodeSession.shared.isLocked(eoa: eoa) else { return }
			BeamioConetChatModule.emitFirstIdentityStatus(state: "registering", reason: index == 0 ? "no_record_confirmed" : nil, attempt: index + 1)
			switch BeamioFirstIdentityCoordinator.run(eoa: eoa) {
			case .active:
				BeamioConetChatModule.emitFirstIdentityStatus(state: "registered"); return
			case .registeredElsewhere, .notFirst, .locked:
				// not this flow's: the restore flow owns a registration that is there, and a locked account is left alone (no event)
				return
			case .conflict:
				BeamioConetChatModule.emitFirstIdentityStatus(state: "failed", reason: "conflict_other_key"); return
			case .refused:
				BeamioConetChatModule.emitFirstIdentityStatus(state: "failed", reason: "submit_4xx"); return
			case .notReady:
				BeamioConetChatModule.emitFirstIdentityStatus(state: "failed"); return
			case .retryLater(let why):
				submitted = why == "submit_5xx" || why == "readback_timeout"
				let reason = why == "chain_read" ? "read_unavailable" : (submitted ? why : nil)
				let next = index + 1 < delays.count ? Int(delays[index + 1] * 1000) : nil
				BeamioConetChatModule.emitFirstIdentityStatus(state: "retry_later", reason: reason, attempt: index + 1, retryAfterMs: next)
			}
		}
		// the schedule is used up: a registration that was submitted and is not read back yet stays pending; nothing is made again
		if submitted { BeamioConetChatModule.emitFirstIdentityStatus(state: "identity_pending", reason: "readback_timeout") }
	}
}
