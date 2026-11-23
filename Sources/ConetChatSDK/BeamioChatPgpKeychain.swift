import Foundation
import Security

/// Permanent storage for the user PGP record and the device SI roster.
///
/// The PGP record (private armor, public armor, key ID, route public key, entry domains, EOA) is kept per account
/// (spec D5): `accountKey = eoa.lowercased + ":" + workspace`, workspace `default`. Reads, saves and deletes name one
/// account, so a second account never overwrites the first, and deleting one account leaves the others in place.
/// The SI roster (`siNodes`, `mailboxIp`) is chain data shared by the device and stays under fixed item names.
/// Host apps should refresh SI node IPs from chain (`getAllNodes`) and call `storeChainRoster`. Web roster payloads must
/// not overwrite `siNodes` / `mailboxIp`. Ciphertext POST uses `http://{ip}/post`.
///
/// Never stores the EOA mnemonic. Accessibility: AfterFirstUnlockThisDeviceOnly.
public enum BeamioChatPgpKeychain {
	private static let service = "com.beamio.beamio.chat-pgp"
	/// Fields of one account's record. The keychain account name is `<accountKey>|<field>`. Before per-account storage the
	/// same names were used without the prefix; `adoptLegacyRecord` moves that single record into its own account.
	private static let fieldPrivate = "userPgpPrivateArmor"
	private static let fieldPublic = "userPgpPublicArmor"
	private static let fieldKeyId = "userPgpKeyId"
	private static let fieldRoute = "mailboxRoutePublicArmor"
	private static let fieldEntries = "entryDomainsJson"
	private static let fieldEoa = "recipientEoa"
	/// The private armor is copied last, so that its presence means that the copy is complete.
	private static let recordFields = [fieldPublic, fieldKeyId, fieldRoute, fieldEntries, fieldEoa, fieldPrivate, fieldRestoreIncomplete]
	/// The marker of a restore whose rollback did not complete (spec (ii),): the scoped record may be mixed. While it is present,
	/// no reader returns the scoped record and no restore writes over it. Only the record clear removes it.
	private static let fieldRestoreIncomplete = "userPgpRestoreIncomplete"
	/// Device roster, shared by all accounts on this device.
	private static let accountSiNodes = "siNodesJson"
	private static let accountMailboxIp = "mailboxIp"

	/// The Keychain service of the K records (25.52Y.77 第 2 条). It differs from the L service above.
	private static let kService = "com.beamio.beamio.chat-pgp-k"
	/// The account-name prefix of every K record: `K.v1|<eoa lower>|<workspace>`.
	private static let kPrefix = "K.v1|"
	/// The three key fields. They are held in the K item; before it, they were scoped items (read only, removed after a verified K write).
	private static let keyFields = [fieldPrivate, fieldPublic, fieldKeyId]

	/// The workspace of the device's chat (spec D5). The only workspace in this build.
	public static let defaultWorkspace = "default"

	public struct SiNode: Equatable {
		public var ip: String
		public var domain: String
		public var region: String
		/// The entry node's PGP public key (armor). Empty when the roster row carries none. Such a node cannot be an
		/// entry (the entry-route wrap needs the key), so the senders skip it and never post its armor unwrapped.
		public var armoredPublicKey: String
		public init(ip: String, domain: String = "", region: String = "", armoredPublicKey: String = "") {
			self.ip = ip
			self.domain = domain
			self.region = region
			self.armoredPublicKey = armoredPublicKey
		}
	}

	public struct Secrets: Equatable {
		public var privateKeyArmor: String
		public var publicKeyArmor: String
		public var pgpKeyId: String
		public var routePublicKeyArmor: String
		public var entryDomains: [String]
		public var siNodes: [SiNode]
		public var mailboxIp: String
		public var eoa: String

		public var hasUserPrivate: Bool {
			privateKeyArmor.contains("BEGIN PGP PRIVATE KEY")
		}

		public var hasRoutePublic: Bool {
			routePublicKeyArmor.contains("BEGIN PGP PUBLIC KEY")
		}
	}

	/// spec D5 `accountKey`: the lower-case EOA and the workspace, joined by ":". Empty when the EOA is empty.
	public static func accountKey(eoa: String, workspace: String = defaultWorkspace) -> String {
		let owner = normalized(eoa)
		guard !owner.isEmpty else { return "" }
		return owner + ":" + workspace
	}

	/// The public part of one account's PGP record, for `identityPublic` (spec). Read only: it does not adopt a legacy
	/// record (no write), and it never returns the private armor. nil when the account has no PGP private key on this device.
	public struct PublicRecord: Equatable {
		public var pgpKeyId: String
		public var publicKeyArmor: String
		public var routePublicKeyArmor: String
	}

	public static func publicRecord(eoa rawEoa: String) -> PublicRecord? {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, !restoreIncomplete(eoa: eoa),
		      let privateArmor = keyValue(fieldPrivate, eoa),
		      privateArmor.contains("BEGIN PGP PRIVATE KEY")
		else { return nil }
		return PublicRecord(
			pgpKeyId: keyValue(fieldKeyId, eoa) ?? "",
			publicKeyArmor: keyValue(fieldPublic, eoa) ?? "",
			routePublicKeyArmor: read(account: scoped(fieldRoute, eoa)) ?? ""
		)
	}

	/// The record of one account, or nil when that account has no PGP private key on this device.
	public static func load(eoa rawEoa: String) -> Secrets? {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, !restoreIncomplete(eoa: eoa) else { return nil }
		adoptLegacyRecord(eoa: eoa)
		guard let privateArmor = keyValue(fieldPrivate, eoa),
		      privateArmor.contains("BEGIN PGP PRIVATE KEY")
		else { return nil }
		let domainsJson = read(account: scoped(fieldEntries, eoa)) ?? "[]"
		let domains = (try? JSONDecoder().decode([String].self, from: Data(domainsJson.utf8))) ?? []
		return Secrets(
			privateKeyArmor: privateArmor,
			publicKeyArmor: keyValue(fieldPublic, eoa) ?? "",
			pgpKeyId: keyValue(fieldKeyId, eoa) ?? "",
			routePublicKeyArmor: read(account: scoped(fieldRoute, eoa)) ?? "",
			entryDomains: domains,
			siNodes: loadSiNodes(),
			mailboxIp: read(account: accountMailboxIp) ?? "",
			eoa: eoa
		)
	}

	/// The record of one account, read only (`LegacyRecord.read`): nothing is adopted and nothing is written. A record in
	/// the pre-D5 layout is read only when its EOA is `eoa`. The EOA is returned as stored, so a caller can refuse a record that
	/// names another account. nil when the account has no PGP private key on this device.
	public static func readOnlyRecord(eoa rawEoa: String) -> Secrets? {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return nil }
		if !restoreIncomplete(eoa: eoa), let privateArmor = keyValue(fieldPrivate, eoa), privateArmor.contains("BEGIN PGP PRIVATE KEY") {
			return Secrets(
				privateKeyArmor: privateArmor,
				publicKeyArmor: keyValue(fieldPublic, eoa) ?? "",
				pgpKeyId: keyValue(fieldKeyId, eoa) ?? "",
				routePublicKeyArmor: "",
				entryDomains: [],
				siNodes: [],
				mailboxIp: "",
				eoa: read(account: scoped(fieldEoa, eoa)) ?? ""
			)
		}
		guard read(account: fieldEoa).map({ normalized($0) }) == eoa,
		      let privateArmor = read(account: fieldPrivate), privateArmor.contains("BEGIN PGP PRIVATE KEY")
		else { return nil }
		return Secrets(
			privateKeyArmor: privateArmor,
			publicKeyArmor: read(account: fieldPublic) ?? "",
			pgpKeyId: read(account: fieldKeyId) ?? "",
			routePublicKeyArmor: "",
			entryDomains: [],
			siNodes: [],
			mailboxIp: "",
			eoa: eoa
		)
	}

	/// Writes the record under the account named by `secrets.eoa`. A record without an EOA has no account and is refused.
	@discardableResult
	public static func save(_ secrets: Secrets) -> Bool {
		let eoa = normalized(secrets.eoa)
		guard secrets.hasUserPrivate, !eoa.isEmpty else { return false }
		var fields: [String: String] = ["privateKeyArmor": secrets.privateKeyArmor]
		if !secrets.publicKeyArmor.isEmpty { fields["publicKeyArmor"] = secrets.publicKeyArmor }
		if !secrets.pgpKeyId.isEmpty { fields["keyId"] = secrets.pgpKeyId }
		// The key fields are one K item (25.52Y.77 第 2 条). Its scoped copies are removed only after it reads back.
		var ok = writeK(eoa: eoa, fields: fields, replace: false)
		if secrets.hasRoutePublic {
			ok = write(account: scoped(fieldRoute, eoa), value: secrets.routePublicKeyArmor) && ok
		}
		if let data = try? JSONEncoder().encode(secrets.entryDomains),
		   let json = String(data: data, encoding: .utf8)
		{
			ok = write(account: scoped(fieldEntries, eoa), value: json) && ok
		}
		ok = write(account: scoped(fieldEoa, eoa), value: eoa) && ok
		NSLog(
			"[BeamioChatPgp] saved keyId=%@ route=%@ entries=%ld siNodes=%ld eoa=%@",
			secrets.pgpKeyId.isEmpty ? "-" : String(secrets.pgpKeyId.prefix(12)),
			secrets.hasRoutePublic ? "yes" : "no",
			secrets.entryDomains.count,
			secrets.siNodes.count,
			String(eoa.prefix(10))
		)
		return ok
	}

	/// The private-material field refused in a bridge payload, as a one-element list (or empty). S-1 (spec): the
	/// same rule as `provisionIdentity` and `init` (`BeamioConetChatModule.identityForbiddenField`), so one implementation
	/// decides every bridge path. Names only, never values. A forbidden field is refused even when it is empty, as in the
	/// identity vectors.
	public static func refusedPrivateFields(in body: [String: Any]) -> [String] {
		if let field = BeamioConetChatModule.identityForbiddenField(in: body) { return [field] }
		return []
	}

	/// Merge a partial PWA payload (routes, public keys, domains) into the record of `eoa`. Never takes private material.
	/// A payload that names another EOA is refused, so it cannot write into a different account.
	@discardableResult
	public static func upsert(eoa rawEoa: String, fromWeb body: [String: Any]) -> Bool {
		// S-1: refuse before anything is read or written. Only field names are logged, never values.
		let refused = refusedPrivateFields(in: body)
		guard refused.isEmpty else {
			NSLog("[BeamioChatPgp] upsert refused: private material in fields %@", refused.joined(separator: ","))
			return false
		}
		let eoa = normalized(rawEoa)
		if let named = body["eoa"] as? String, !named.isEmpty, normalized(named) != eoa { return false }
		// The private armor never comes from the bridge. Only the stored one is kept; nothing is written without it.
		guard !eoa.isEmpty, let prev = load(eoa: eoa), prev.hasUserPrivate else { return false }
		var domains: [String] = prev.entryDomains
		if let arr = body["entryDomains"] as? [String] {
			domains = arr.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
		} else if let arr = body["entryDomains"] as? [Any] {
			domains = arr.compactMap { ($0 as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
		}
		let secrets = Secrets(
			privateKeyArmor: prev.privateKeyArmor,
			publicKeyArmor: (body["publicKeyArmor"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev.publicKeyArmor,
			pgpKeyId: (body["pgpKeyId"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev.pgpKeyId,
			routePublicKeyArmor: (body["routePublicKeyArmor"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev.routePublicKeyArmor,
			entryDomains: domains,
			siNodes: prev.siNodes,
			mailboxIp: prev.mailboxIp,
			eoa: eoa
		)
		return save(secrets)
	}

	/// Optional host hook when PWA sends a roster payload.
	/// The host app may refresh Guardian nodes (e.g. chain `getAllNodes`); the SDK never POSTs SI from Web-named URLs.
	public static var onRosterUpsertFromWeb: (() -> Void)?

	/// PWA roster payloads do not overwrite Keychain SI nodes. Invokes `onRosterUpsertFromWeb` if set.
	@discardableResult
	public static func upsertRoster(fromWeb body: [String: Any]) -> Bool {
		_ = body
		onRosterUpsertFromWeb?()
		return true
	}

	/// The device roster (shared by all accounts).
	public static func loadSiNodes() -> [SiNode] {
		loadRoster().nodes
	}

	// MARK: Roster file (Application Support, not the Keychain)

	/// Why the last roster read did not use the file: nil when it did (or the roster is simply absent). Diagnostic only, no roster content.
	public private(set) static var rosterDiagnostic: String?

	/// A test build with the in-memory Keychain uses its own file name (per process), never the product's file: a parallel suite or a developer's real roster is untouched.
	private static var rosterFileName: String {
		#if BEAMIO_TEST_HOOKS
		if memory != nil { return "si_roster_v1.test-\(ProcessInfo.processInfo.processIdentifier).json" }
		#endif
		return "si_roster_v1.json"
	}

	private static var rosterFileURL: URL? { BeamioInboxFile.folder?.appendingPathComponent(rosterFileName) }

	/// The roster: the file first, then the old Keychain item. A file that cannot be read or decoded never becomes an empty roster:
	/// the Keychain item answers and `rosterDiagnostic` says why. A roster found only in the Keychain is moved to the file
	/// (write, read back identical, only then delete the Keychain item); any failed step keeps the Keychain item for the next read.
	static func loadRoster() -> (nodes: [SiNode], fromFile: Bool) {
		var diagnostic: String?
		if let url = rosterFileURL {
			switch BeamioInboxFile.read(url) {
			case .data(let data):
				let nodes = decodeSiNodes(String(data: data, encoding: .utf8))
				if !nodes.isEmpty {
					rosterDiagnostic = nil
					// `BeamioInboxFile.read` has set the protection class again; a failure to do so stays visible
					if BeamioInboxFile.protectionRetryPending(url) { rosterDiagnostic = "roster_protection_pending" }
					// A file is the newer source: an old Keychain item left by a failed delete is retried here.
					if read(account: accountSiNodes) != nil { _ = delete(account: accountSiNodes) }
					return (nodes, true)
				}
				diagnostic = "roster_file_corrupt"
			case .unreadable:
				diagnostic = "roster_file_unreadable"
			case .missing:
				break
			}
		} else {
			diagnostic = "roster_folder_unavailable"
		}
		guard let json = read(account: accountSiNodes) else {
			rosterDiagnostic = diagnostic
			return ([], false)
		}
		let nodes = decodeSiNodes(json)
		if nodes.isEmpty {
			rosterDiagnostic = diagnostic ?? "roster_keychain_undecodable"
			return ([], false)
		}
		if diagnostic == nil, !moveRosterToFile(json: json, nodes: nodes) { diagnostic = "roster_migration_pending" }
		rosterDiagnostic = diagnostic
		return (nodes, false)
	}

	/// Writes `json` to the roster file, reads it back, and only when the bytes and the decoded roster are identical removes the Keychain item.
	private static func moveRosterToFile(json: String, nodes: [SiNode]) -> Bool {
		guard writeRosterFile(json: json, nodes: nodes) else { return false }
		return delete(account: accountSiNodes)
	}

	private static func writeRosterFile(json: String, nodes: [SiNode]) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if testFailRosterWrite { return false }
		#endif
		guard let url = rosterFileURL, let data = json.data(using: .utf8),
		      BeamioInboxFile.replace(url, with: data),
		      case .data(let back) = BeamioInboxFile.read(url), back == data,
		      decodeSiNodes(String(data: back, encoding: .utf8)) == nodes
		else { return false }
		return true
	}

	/// The device roster's mailbox IP (shared by all accounts).
	public static func loadMailboxIp() -> String {
		read(account: accountMailboxIp) ?? ""
	}

	/// The route public armor of one account.
	public static func loadRoutePublicArmor(eoa rawEoa: String) -> String {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, !restoreIncomplete(eoa: eoa) else { return "" }
		adoptLegacyRecord(eoa: eoa)
		return read(account: scoped(fieldRoute, eoa)) ?? ""
	}

	/// Chain refresh writer. Does not require a user PGP private key.
	/// `mailboxIp == nil` leaves the stored mailbox IP unchanged.
	@discardableResult
	public static func storeChainRoster(nodes: [SiNode], mailboxIp: String?) -> Bool {
		guard !nodes.isEmpty, let json = encodeSiNodes(nodes) else { return false }
		var ok = storeRosterJson(json, nodes: nodes)
		if let mailboxIp, !mailboxIp.isEmpty {
			ok = write(account: accountMailboxIp, value: mailboxIp) && ok
		}
		return ok
	}

	/// File first; the Keychain item goes only after the file is read back identical. When the file cannot be written,
	/// the Keychain keeps the roster, unless an older file exists (it would shadow the Keychain): then nothing changes and false is returned.
	private static func storeRosterJson(_ json: String, nodes: [SiNode]) -> Bool {
		let reread = decodeSiNodes(json)
		if writeRosterFile(json: json, nodes: reread.isEmpty ? nodes : reread) {
			rosterDiagnostic = nil
			if let url = rosterFileURL, BeamioInboxFile.protectionRetryPending(url) { rosterDiagnostic = "roster_protection_pending" }
			if !delete(account: accountSiNodes) { rosterDiagnostic = "roster_keychain_delete_pending" }
			return true
		}
		if let url = rosterFileURL, case .missing = BeamioInboxFile.read(url) {
			rosterDiagnostic = "roster_file_write_failed"
			return write(account: accountSiNodes, value: json)
		}
		rosterDiagnostic = "roster_file_write_failed_kept_old"
		return false
	}

	public static func parseSiNodes(_ raw: Any?) -> [SiNode] {
		let rows: [Any]
		if let arr = raw as? [Any] {
			rows = arr
		} else if let s = raw as? String, let data = s.data(using: .utf8),
		          let arr = try? JSONSerialization.jsonObject(with: data) as? [Any] {
			rows = arr
		} else {
			return []
		}
		var out: [SiNode] = []
		for row in rows {
			if let ip = row as? String, let norm = BeamioSiCipherPost.normalizeIp(ip) {
				out.append(SiNode(ip: norm, domain: "", region: ""))
				continue
			}
			guard let dict = row as? [String: Any] else { continue }
			let ipRaw = (dict["ip"] as? String) ?? (dict["ip_addr"] as? String) ?? ""
			guard let ip = BeamioSiCipherPost.normalizeIp(ipRaw) else { continue }
			let domain = (dict["domain"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
			let region = (dict["region"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
			let armor = (dict["armoredPublicKey"] as? String) ?? (dict["pgpPublicKeyArmored"] as? String) ?? ""
			out.append(SiNode(ip: ip, domain: domain, region: region, armoredPublicKey: armor))
		}
		return out
	}

	private static func decodeSiNodes(_ json: String?) -> [SiNode] {
		guard let json, let data = json.data(using: .utf8),
		      let arr = try? JSONSerialization.jsonObject(with: data)
		else { return [] }
		return parseSiNodes(arr)
	}

	private static func encodeSiNodes(_ nodes: [SiNode]) -> String? {
		let rows: [[String: String]] = nodes.map {
			["ip": $0.ip, "domain": $0.domain, "region": $0.region, "armoredPublicKey": $0.armoredPublicKey]
		}
		guard let data = try? JSONSerialization.data(withJSONObject: rows) else { return nil }
		return String(data: data, encoding: .utf8)
	}

	/// A new identity in progress (pgpIdentityCreate, spec and). `privateArmor` and `publicArmor` are empty
	/// while the user has not confirmed yet ("prepared"). `seen` is the on-chain state the user saw (S_seen), kept natively.
	/// This is not a record: a restored or created identity is written to the record fields only when it is complete.
	public struct PendingIdentity: Equatable {
		public var privateArmor: String
		public var publicArmor: String
		public var idempotencyKey: String
		public var seen: String
		/// The mode the user was shown: `replace` or `first`. Kept with the pending identity so a repeated command can answer it (C-15).
		public var mode: String
		public init(privateArmor: String, publicArmor: String, idempotencyKey: String, seen: String, mode: String = "replace") {
			self.privateArmor = privateArmor
			self.publicArmor = publicArmor
			self.idempotencyKey = idempotencyKey
			self.seen = seen
			self.mode = mode
		}
	}

	private static let fieldPendingPrivate = "pendingPgpPrivateArmor"
	private static let fieldPendingPublic = "pendingPgpPublicArmor"
	private static let fieldPendingMeta = "pendingPgpMetaJson"
	private static let pendingFields = [fieldPendingPrivate, fieldPendingPublic, fieldPendingMeta]

	/// Stores the pending identity of `eoa`. The meta item (idempotency key and S_seen) is written last.
	@discardableResult
	public static func savePending(eoa rawEoa: String, _ pending: PendingIdentity) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		let meta: [String: String] = ["idempotencyKey": pending.idempotencyKey, "seen": pending.seen, "mode": pending.mode]
		guard let data = try? JSONSerialization.data(withJSONObject: meta), let json = String(data: data, encoding: .utf8) else {
			return false
		}
		var ok = write(account: scoped(fieldPendingPrivate, eoa), value: pending.privateArmor)
		ok = write(account: scoped(fieldPendingPublic, eoa), value: pending.publicArmor) && ok
		ok = write(account: scoped(fieldPendingMeta, eoa), value: json) && ok
		return ok
	}

	/// The pending identity of `eoa`, or nil.
	public static func loadPending(eoa rawEoa: String) -> PendingIdentity? {
		let eoa = normalized(rawEoa)
		// a pending identity whose erase is owed is not read for anything (r2x s2)
		guard !eoa.isEmpty, !cleanupPending(eoa: eoa), let json = read(account: scoped(fieldPendingMeta, eoa)),
		      let data = json.data(using: .utf8),
		      let meta = try? JSONSerialization.jsonObject(with: data) as? [String: String]
		else { return nil }
		return PendingIdentity(
			privateArmor: read(account: scoped(fieldPendingPrivate, eoa)) ?? "",
			publicArmor: read(account: scoped(fieldPendingPublic, eoa)) ?? "",
			idempotencyKey: meta["idempotencyKey"] ?? "",
			seen: meta["seen"] ?? "",
			mode: meta["mode"] ?? "replace"
		)
	}

	/// Forgets the pending identity of `eoa` (cancel, a CAS conflict, or a completed registration).
	/// Erases the pending identity. True only when every field is gone (a failed erase is reported, never ignored: the key may still be there).
	@discardableResult
	public static func clearPending(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return true }
		var ok = true
		for field in pendingFields where !delete(account: scoped(field, eoa)) { ok = false }
		return ok
	}

	// MARK: cleanup marker (a flag only; no key, no identity)

	private static let fieldCleanupPending = "userPgpCleanupPending"

	/// A pending identity that could not be erased outside the create flow (a cancel, a success path): the next start tries again.
	@discardableResult
	static func markCleanupPending(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		return write(account: scoped(fieldCleanupPending, eoa), value: "1")
	}

	/// Whether the pending identity of `eoa` is blocked (r2x s2): the marker is there, or it cannot be read. A marker that cannot be read counts as pending
	/// (fail closed): the temporary key is not used for anything until the erase is done.
	static func cleanupPending(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		let account = scoped(fieldCleanupPending, eoa)
		if !itemReadable(field: fieldCleanupPending, account: account) { return true }
		return read(account: account) != nil
	}

	/// Retries the erase that was left behind; the marker goes only when the erase worked. Returns true when nothing is left to do.
	@discardableResult
	static func retryCleanup(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, cleanupPending(eoa: eoa) else { return true }
		guard clearPending(eoa: eoa) else { return false }
		return delete(account: scoped(fieldCleanupPending, eoa))
	}

	/// Removes only the record fields of `eoa` (used to revert a write that did not read back). The pending identity stays.
	@discardableResult
	public static func removeRecord(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return true }
		var ok = true
		for field in recordFields where !delete(account: scoped(field, eoa)) { ok = false }
		if !delete(account: kAccount(eoa: eoa), service: kService) { ok = false }
		return ok
	}

	/// The stored values of the scoped record of `eoa` (every record field that is set). Kept before a write, so a write that does not
	/// read back can put the account's previous record back exactly. Storage values only; never returned over the bridge.
	static func scopedSnapshot(eoa rawEoa: String) -> [String: String] {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return [:] }
		var values: [String: String] = [:]
		for field in recordFields {
			let value = keyFields.contains(field) ? keyValue(field, eoa) : read(account: scoped(field, eoa))
			if let value { values[field] = value }
		}
		return values
	}

	/// Puts the scoped record of `eoa` back to `snapshot`: a field in the snapshot gets its stored value, a field that is not in it is
	/// removed. The plain legacy items are never touched. Returns false when a write fails.
	static func restoreScoped(eoa rawEoa: String, snapshot: [String: String]) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		var ok = true
		let keys = keyFields.filter { snapshot[$0] != nil }
		if keys.isEmpty {
			// No key before the snapshot: the K item and the scoped copies go.
			delete(account: kAccount(eoa: eoa), service: kService)
			for field in keyFields { delete(account: scoped(field, eoa)) }
		} else {
			var fields: [String: String] = [:]
			for field in keys { fields[jsonName(field)] = snapshot[field] ?? "" }
			ok = writeK(eoa: eoa, fields: fields, replace: true) && ok
		}
		for field in recordFields where !keyFields.contains(field) {
			let account = scoped(field, eoa)
			if let value = snapshot[field] {
				ok = write(account: account, value: value) && ok
			} else {
				delete(account: account)
			}
		}
		return ok
	}

	/// Whether the scoped record of `eoa` holds the same key as the candidate: the same identity: the primary fingerprint when both public keys can be read, else the key ID. The account must match.
	/// nil when the scoped record has no private armor, so there is nothing to compare. Storage values only; nothing is written.
	static func scopedRecordSameKey(eoa rawEoa: String, privateArmor: String, publicArmor: String, keyId: String) -> Bool? {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty, let stored = keyValue(fieldPrivate, eoa), stored.contains("BEGIN PGP PRIVATE KEY") else { return nil }
				// The account must match ((ii)). The same key is then judged by identity, not by the armor text.
		guard (read(account: scoped(fieldEoa, eoa)) ?? "").lowercased() == eoa else { return false }
		return sameIdentity(storedPublic: keyValue(fieldPublic, eoa) ?? "", candidatePublic: publicArmor,
		                    storedKeyId: keyValue(fieldKeyId, eoa) ?? "", candidateKeyId: keyId)
	}

	/// The identity of a stored and a candidate key: the primary fingerprint, when both public armors can be read; otherwise the key
	/// ID, when it is set. The armor text is not compared, so a line-ending difference never changes the identity.
	static func sameIdentity(storedPublic: String, candidatePublic: String, storedKeyId: String, candidateKeyId: String) -> Bool {
		if let stored = BeamioPGPBackup.keyIdentity(armor: storedPublic)?.fingerprint,
		   let candidate = BeamioPGPBackup.keyIdentity(armor: candidatePublic)?.fingerprint {
			return stored.uppercased() == candidate.uppercased()
		}
		return !storedKeyId.isEmpty && storedKeyId == candidateKeyId
	}

	/// Whether the scoped record of `eoa` carries the marker of an incomplete restore ((ii)).
	static func restoreIncomplete(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		return read(account: scoped(fieldRestoreIncomplete, eoa)) != nil
	}

	/// Marks the scoped record of `eoa` as an incomplete restore: its rollback did not complete. The mark is one more scoped item; nothing else of the
	/// record is changed. False when the mark cannot be written.
	static func markRestoreIncomplete(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		return write(account: scoped(fieldRestoreIncomplete, eoa), value: "1")
	}

	/// Whether every item of the scoped record of `eoa` can be read. An item that is not stored is readable
	/// (absent). An item that the Keychain cannot return, for any reason but "not found", is not readable: the write is then refused.
	static func scopedItemsReadable(eoa rawEoa: String) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return true }
		for field in recordFields where !itemReadable(field: field, account: scoped(field, eoa)) {
			return false
		}
		if case .unreadable = readK(eoa: eoa) { return false }
		return true
	}

	private static func itemReadable(field: String, account: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if memory != nil { return !testUnreadableFields.contains(field) }
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		if status == errSecItemNotFound { return true }
		guard status == errSecSuccess, let data = item as? Data else { return false }
		return String(data: data, encoding: .utf8) != nil
	}

	/// The state of the PGP record of `eoa`: the PGP counterpart of the wallet record state of, which is a different thing.
	/// `absent`: no record (no scoped private key and no scoped copy of it). `present`: the scoped private key can be read and holds a PGP private key.
	/// `unreadable`: the record exists and does not open: an item cannot be read, or the private item holds no PGP private key. Only `absent` allows a write
	/// without a comparison; `unreadable` is `not_ready` and nothing is written.
	public enum RecordState: Equatable {
		case absent
		case present
		case unreadable
	}

	public static func recordState(eoa rawEoa: String) -> RecordState {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return .absent }
		guard scopedItemsReadable(eoa: eoa) else { return .unreadable }
		guard let privateArmor = keyValue(fieldPrivate, eoa) else {
			// Scoped items without a private key are not a record: the restore may write over them, and a rollback keeps them.
			return .absent
		}
		return privateArmor.contains("BEGIN PGP PRIVATE KEY") ? .present : .unreadable
	}

	/// Whether this device holds any PGP private-key item, of any account or the legacy one. Presence only: it is never
	/// a positive answer, and it reads no key. An item that cannot be enumerated counts as present (fail closed, like `unreadable`).
	public static func deviceHasPrivateRecord() -> Bool {
		guard let kAccounts = enumerateKAccounts() else { return true }
		if !kAccounts.isEmpty { return true }
		#if BEAMIO_TEST_HOOKS
		if let memory {
			return memory.values.keys.contains { $0 == fieldPrivate || $0.hasSuffix("|" + fieldPrivate) }
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return false }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return true }
		return rows.contains { row in
			guard let account = row[kSecAttrAccount as String] as? String else { return false }
			return account == fieldPrivate || account.hasSuffix("|" + fieldPrivate)
		}
	}

	/// kPresent (25.52Y.90, 25.52Y.107 第 4 項): whether this device holds any PGP or K record, of any account. Presence only; no key is read.
	/// Three answers: true, false, or nil when the records cannot be enumerated or named. nil is not false: the caller omits the field,
	/// which the page reads as unknown (25.52Y.108 第 2 項). Unlike `deviceHasPrivateRecord`, an enumeration failure is not reported as true.
	static func devicePresenceState() -> Bool? {
		guard let kAccounts = enumerateKAccounts() else { return nil }
		if !kAccounts.isEmpty { return true }
		#if BEAMIO_TEST_HOOKS
		if let memory {
			return memory.values.keys.contains { $0 == fieldPrivate || $0.hasSuffix("|" + fieldPrivate) }
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return false }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var present = false
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			if account == fieldPrivate || account.hasSuffix("|" + fieldPrivate) { present = true }
		}
		return present
	}

	/// The route armor and the entry domains of the scoped record of `eoa`, as stored. A write that has neither keeps them, so a
	/// write never blanks a route or an entry list that the account already has.
	static func keptRouteAndEntries(eoa rawEoa: String) -> (route: String, entryDomains: [String]) {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return ("", []) }
		let route = read(account: scoped(fieldRoute, eoa)) ?? ""
		var domains: [String] = []
		if let json = read(account: scoped(fieldEntries, eoa)), let data = json.data(using: .utf8),
		   let decoded = try? JSONDecoder().decode([String].self, from: data) {
			domains = decoded
		}
		return (route, domains)
	}

	/// Logout / wallet removed or switched: forget only this account's PGP record (and a legacy record that names it).
	/// The device roster and the other accounts' records are not touched.
	public static func clear(eoa rawEoa: String) {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return }
		for field in pendingFields { delete(account: scoped(field, eoa)) }
		for field in recordFields { delete(account: scoped(field, eoa)) }
		delete(account: kAccount(eoa: eoa), service: kService)
		if read(account: fieldEoa).map({ normalized($0) }) == eoa {
			for field in recordFields { delete(account: field) }
		}
	}

	/// Copy of the single record kept before per-account storage (plain item names) into the account it names. A read path never deletes
	/// the plain items stay, and the copy is made once, because the scoped record exists after it. Only a record whose EOA
	/// matches is copied. A record with no EOA, or another EOA, is left where it is and never read for this account. A failed copy is retried
	/// by the next load. The plain items are removed only by the explicit clear (`clear(eoa:)`) or the whole-store clear for a switch.
	private static func adoptLegacyRecord(eoa: String) {
		guard read(account: fieldEoa).map({ normalized($0) }) == eoa,
		      read(account: fieldPrivate)?.contains("BEGIN PGP PRIVATE KEY") == true,
		      keyValue(fieldPrivate, eoa) == nil
		else { return }
		var ok = true
		for field in recordFields {
			guard let value = read(account: field) else { continue }
			ok = write(account: scoped(field, eoa), value: value) && ok
		}
		guard ok else {
			NSLog("[BeamioChatPgp] legacy record not copied: a copy failed")
			return
		}
		NSLog("[BeamioChatPgp] legacy record copied to its account %@", String(eoa.prefix(10)))
	}

	#if BEAMIO_TEST_HOOKS
	/// Test seam: when set, the PGP record is kept in memory. The iOS simulator test host has no Keychain entitlement
	/// (errSecMissingEntitlement, -34018), so Keychain writes fail there. The app always uses the Keychain. Compiled only with the test hooks
	/// a Release or QA build has no such symbol.
	final class MemoryRecords {
		var values: [String: String] = [:]
	}

	static var memory: MemoryRecords? {
		willSet { if memory != nil, let url = BeamioInboxFile.folder?.appendingPathComponent(rosterFileName) { BeamioInboxFile.remove(url) } }
		didSet { if memory != nil, let url = BeamioInboxFile.folder?.appendingPathComponent(rosterFileName) { BeamioInboxFile.remove(url) } }
	}
	/// Test seam: the roster file cannot be written.
	static var testFailRosterWrite = false
		/// Test seam: scoped fields that the Keychain cannot return, by field name (a storage-derived lock).
		static var testUnreadableFields: Set<String> = []
		/// Test seam: the number of writes that succeed before every later write fails. nil: no injection.
		static var testWriteBudget: Int?
		/// Test seam: fields that the write budget does not count, so a marker can be written after a failed rollback.
		static var testWriteBudgetExemptFields: Set<String> = []
	#endif

	// MARK: - K record (25.52Y.77 第 2 条, 25.52Z.3 第 7 项)

	/// What one K item reads as. `record` is returned only for an item that holds a PGP private key.
	enum KRead: Equatable {
		case absent
		case record([String: String])
		case unreadable
	}

	/// The Keychain account name of the K record of `eoa` in `workspace`: `K.v1|<eoa lower>|<workspace>`.
	static func kAccount(eoa rawEoa: String, workspace: String = defaultWorkspace) -> String {
		kPrefix + normalized(rawEoa) + "|" + workspace
	}

	/// The K record of `eoa` in `workspace`. Read only.
	static func readK(eoa rawEoa: String, workspace: String = defaultWorkspace) -> KRead {
		readKAccount(kAccount(eoa: rawEoa, workspace: workspace))
	}

	private static func readKAccount(_ account: String) -> KRead {
		#if BEAMIO_TEST_HOOKS
		if let memory {
			guard let raw = memory.values[account] else { return .absent }
			return decodeK(raw)
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: kService,
			kSecAttrAccount as String: account,
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		if status == errSecItemNotFound { return .absent }
		guard status == errSecSuccess, let data = item as? Data, let text = String(data: data, encoding: .utf8) else {
			return .unreadable
		}
		return decodeK(text)
	}

	/// The UTF-8 JSON of a K item. An item without a PGP private key does not open.
	private static func decodeK(_ text: String) -> KRead {
		guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: String],
		      (object["privateKeyArmor"] ?? "").contains("BEGIN PGP PRIVATE KEY")
		else { return .unreadable }
		return .record(object)
	}

	/// The JSON name of a key field in the K item.
	private static func jsonName(_ field: String) -> String {
		switch field {
		case fieldPrivate: return "privateKeyArmor"
		case fieldPublic: return "publicKeyArmor"
		default: return "keyId"
		}
	}

	/// One key field of `eoa`. The K item decides when it can be read (nil when it lacks the field); an unreadable K item gives nil.
	/// Without a K item, the scoped item of the layout before K is read (never removed on a read).
	private static func keyValue(_ field: String, _ eoa: String) -> String? {
		switch readK(eoa: eoa) {
		case .record(let record): return record[jsonName(field)]
		case .unreadable: return nil
		case .absent: return read(account: scoped(field, eoa))
		}
	}

	/// Writes the K item of `eoa` in the default workspace. `replace` false merges `fields` into the key fields already read for the account;
	/// `replace` true makes `fields` the whole key content. The item is read back and must match before the scoped copies of the key fields are
	/// removed (25.52Y.80 第 3 项, 25.52Y.109 第 1 条: the old key is removed only after the new one is verified). An unreadable K item is not overwritten.
	@discardableResult
	/// `retireScoped`: whether the scoped copies of the key fields are removed after the K item reads back. The migration writers remove them;
	/// the upgrade from L keeps them (25.52Y.62 `upgraded_from_L`: L is kept).
	private static func writeK(eoa rawEoa: String, fields: [String: String], replace: Bool, retireScoped: Bool = true) -> Bool {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return false }
		let account = kAccount(eoa: eoa)
		var createdAt = ""
		switch readKAccount(account) {
		case .unreadable: return false
		case .record(let current): createdAt = current["createdAt"] ?? ""
		case .absent: break
		}
		var record: [String: String] = [:]
		if !replace {
			for field in keyFields {
				if let value = keyValue(field, eoa) { record[jsonName(field)] = value }
			}
		}
		for (key, value) in fields { record[key] = value }
		record["eoa"] = eoa
		record["workspace"] = defaultWorkspace
		record["createdAt"] = createdAt.isEmpty ? ISO8601DateFormatter().string(from: Date()) : createdAt
		guard let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]),
		      let json = String(data: data, encoding: .utf8),
		      write(account: account, value: json, service: kService)
		else { return false }
		guard case .record(let back) = readKAccount(account), back == record else { return false }
		if retireScoped {
			for field in keyFields { delete(account: scoped(field, eoa)) }
		}
		return true
	}

	/// The K write of the upgrade from L (25.52Y.59 第 3 项, 25.52Y.62 `upgraded_from_L`). It writes the K item and reads it back. The scoped
	/// legacy items (L) are kept. True only when the K item reads back with the same private armor, public armor and key ID.
	static func upgradeKFromLegacy(eoa rawEoa: String, privateArmor: String, publicArmor: String, keyId: String) -> Bool {
		guard !privateArmor.isEmpty, !publicArmor.isEmpty, !keyId.isEmpty else { return false }
		// The K field names are the record's own names (jsonName), so the fields are written and read back by the same names.
		let fields = [jsonName(fieldPrivate): privateArmor, jsonName(fieldPublic): publicArmor, jsonName(fieldKeyId): keyId]
		guard writeK(eoa: rawEoa, fields: fields, replace: false, retireScoped: false) else { return false }
		guard case .record(let back) = readK(eoa: rawEoa),
		      back[jsonName(fieldPrivate)] == privateArmor, back[jsonName(fieldPublic)] == publicArmor, back[jsonName(fieldKeyId)] == keyId
		else { return false }
		return true
	}

	/// The account names of every K item on this device, of any account. nil when they cannot be enumerated: an error other than "not found".
	static func enumerateKAccounts() -> [String]? {
		#if BEAMIO_TEST_HOOKS
		if let memory { return memory.values.keys.filter { $0.hasPrefix(kPrefix) }.sorted() }
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: kService,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var accounts: [String] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			if account.hasPrefix(kPrefix) { accounts.append(account) }
		}
		return accounts
	}

	/// The state of the K records of `eoa` in workspaces other than the default one (25.52Z.3 第 7 项). `present` when one of them holds a PGP
	/// private key; `unreadable` when one does not open or the items cannot be enumerated; otherwise `absent`.
	static func otherWorkspaceState(eoa rawEoa: String) -> RecordState {
		let eoa = normalized(rawEoa)
		guard !eoa.isEmpty else { return .absent }
		guard let accounts = enumerateKAccounts() else { return .unreadable }
		let prefix = kPrefix + eoa + "|"
		let active = kAccount(eoa: eoa)
		var state = RecordState.absent
		for account in accounts where account.hasPrefix(prefix) && account != active {
			switch readKAccount(account) {
			case .absent: continue
			case .unreadable: return .unreadable
			case .record: state = .present
			}
		}
		return state
	}

	/// The state the EOA path of the binding lookup reads (25.52Y.77 第 1 条, Z.3 第 7 项(b)): the ACTIVE K record or a K record of another workspace.
	/// `present` when either holds a PGP private key; `unreadable` when either cannot be read; otherwise `absent`.
	public static func bindingRecordState(eoa rawEoa: String) -> RecordState {
		let active = recordState(eoa: rawEoa)
		let other = otherWorkspaceState(eoa: rawEoa)
		if active == .present || other == .present { return .present }
		if active == .unreadable || other == .unreadable { return .unreadable }
		return .absent
	}

	private static func normalized(_ eoa: String) -> String {
		eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
	}

	/// Keychain account name of one field of one account's record.
	private static func scoped(_ field: String, _ eoa: String) -> String {
		accountKey(eoa: eoa) + "|" + field
	}

	private static func read(account: String, service: String = BeamioChatPgpKeychain.service) -> String? {
		#if BEAMIO_TEST_HOOKS
		if let memory { return memory.values[account] }
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
			kSecReturnData as String: true,
			kSecMatchLimit as String: kSecMatchLimitOne,
		]
		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		guard status == errSecSuccess, let data = item as? Data,
		      let s = String(data: data, encoding: .utf8), !s.isEmpty
		else { return nil }
		return s
	}

	@discardableResult
	private static func write(account: String, value: String, service: String = BeamioChatPgpKeychain.service) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if let memory {
			if let budget = testWriteBudget, !testWriteBudgetExemptFields.contains(where: { account.hasSuffix("|" + $0) }) {
				guard budget > 0 else { return false }
				testWriteBudget = budget - 1
			}
			memory.values[account] = value
			return true
		}
		#endif
		guard let data = value.data(using: .utf8) else { return false }
		let base: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
		]
		SecItemDelete(base as CFDictionary)
		var add = base
		add[kSecValueData as String] = data
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		let status = SecItemAdd(add as CFDictionary, nil)
		return status == errSecSuccess
	}

	#if BEAMIO_TEST_HOOKS
	/// Test seam: account names (full scoped names) whose erase fails.
	static var testFailDeleteContains: [String] = []
	#endif

	/// True when the item is gone (erased, or it was not there). A Keychain error other than "not found" is a failed erase.
	@discardableResult
	private static func delete(account: String, service: String = BeamioChatPgpKeychain.service) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if testFailDeleteContains.contains(where: { account.contains($0) }) { return false }
		if let memory {
			memory.values[account] = nil
			return true
		}
		#endif
		let base: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
		]
		let status = SecItemDelete(base as CFDictionary)
		return status == errSecSuccess || status == errSecItemNotFound
	}
}
#if BEAMIO_TEST_HOOKS
// Test build only: this file's Keychain calls are answered from the test store (BeamioTestKeychainStore), never the real Keychain.
fileprivate func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.copyMatching(query, result)
}
fileprivate func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.add(attributes, result)
}
fileprivate func SecItemDelete(_ query: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.delete(query)
}
#endif
