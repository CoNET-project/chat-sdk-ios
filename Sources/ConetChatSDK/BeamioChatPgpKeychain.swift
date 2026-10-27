import Foundation
import Security

/// Permanent storage for recipient **user PGP** and mailbox route public key.
/// Host apps should refresh SI node IPs from chain (`getAllNodes`) and call
/// `storeChainRoster`. Web roster payloads must not overwrite `siNodes` / `mailboxIp`.
/// Ciphertext POST uses `http://{ip}/post`.
///
/// Never stores the EOA mnemonic. Accessibility: AfterFirstUnlockThisDeviceOnly.
public enum BeamioChatPgpKeychain {
	private static let service = "com.beamio.beamio.chat-pgp"
	private static let accountPrivate = "userPgpPrivateArmor"
	private static let accountPublic = "userPgpPublicArmor"
	private static let accountKeyId = "userPgpKeyId"
	private static let accountRoute = "mailboxRoutePublicArmor"
	private static let accountEntries = "entryDomainsJson"
	private static let accountSiNodes = "siNodesJson"
	private static let accountMailboxIp = "mailboxIp"
	private static let accountEoa = "recipientEoa"

	public struct SiNode: Equatable {
		public var ip: String
		public var domain: String
		public var region: String
		public init(ip: String, domain: String = "", region: String = "") {
			self.ip = ip
			self.domain = domain
			self.region = region
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

	public static func load() -> Secrets? {
		guard let privateArmor = read(account: accountPrivate),
		      privateArmor.contains("BEGIN PGP PRIVATE KEY")
		else { return nil }
		let domainsJson = read(account: accountEntries) ?? "[]"
		let domains = (try? JSONDecoder().decode([String].self, from: Data(domainsJson.utf8))) ?? []
		return Secrets(
			privateKeyArmor: privateArmor,
			publicKeyArmor: read(account: accountPublic) ?? "",
			pgpKeyId: read(account: accountKeyId) ?? "",
			routePublicKeyArmor: read(account: accountRoute) ?? "",
			entryDomains: domains,
			siNodes: decodeSiNodes(read(account: accountSiNodes)),
			mailboxIp: read(account: accountMailboxIp) ?? "",
			eoa: read(account: accountEoa) ?? ""
		)
	}

@discardableResult
	public static func save(_ secrets: Secrets) -> Bool {
		guard secrets.hasUserPrivate else { return false }
		var ok = write(account: accountPrivate, value: secrets.privateKeyArmor)
		if !secrets.publicKeyArmor.isEmpty {
			ok = write(account: accountPublic, value: secrets.publicKeyArmor) && ok
		}
		if !secrets.pgpKeyId.isEmpty {
			ok = write(account: accountKeyId, value: secrets.pgpKeyId) && ok
		}
		if secrets.hasRoutePublic {
			ok = write(account: accountRoute, value: secrets.routePublicKeyArmor) && ok
		}
		if let data = try? JSONEncoder().encode(secrets.entryDomains),
		   let json = String(data: data, encoding: .utf8)
		{
			ok = write(account: accountEntries, value: json) && ok
		}
		if !secrets.eoa.isEmpty {
			ok = write(account: accountEoa, value: secrets.eoa) && ok
		}
		NSLog(
			"[BeamioChatPgp] saved keyId=%@ route=%@ entries=%ld siNodes=%ld eoa=%@",
			secrets.pgpKeyId.isEmpty ? "-" : String(secrets.pgpKeyId.prefix(12)),
			secrets.hasRoutePublic ? "yes" : "no",
			secrets.entryDomains.count,
			secrets.siNodes.count,
			secrets.eoa.isEmpty ? "-" : String(secrets.eoa.prefix(10))
		)
		return ok
	}

	/// Merge partial PWA payload into existing Keychain (private required).
@discardableResult
	public static func upsert(fromWeb body: [String: Any]) -> Bool {
		let privateArmor = (body["privateKeyArmor"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
		guard privateArmor.contains("BEGIN PGP PRIVATE KEY") else { return false }
		let prev = load()
		var domains: [String] = prev?.entryDomains ?? []
		if let arr = body["entryDomains"] as? [String] {
			domains = arr.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
		} else if let arr = body["entryDomains"] as? [Any] {
			domains = arr.compactMap { ($0 as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
		}
		let secrets = Secrets(
			privateKeyArmor: privateArmor,
			publicKeyArmor: (body["publicKeyArmor"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev?.publicKeyArmor ?? "",
			pgpKeyId: (body["pgpKeyId"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev?.pgpKeyId ?? "",
			routePublicKeyArmor: (body["routePublicKeyArmor"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev?.routePublicKeyArmor ?? "",
			entryDomains: domains,
			siNodes: prev?.siNodes ?? loadSiNodes(),
			mailboxIp: prev?.mailboxIp ?? loadMailboxIp(),
			eoa: (body["eoa"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
				?? prev?.eoa ?? ""
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

	public static func loadSiNodes() -> [SiNode] {
		decodeSiNodes(read(account: accountSiNodes))
	}

	public static func loadMailboxIp() -> String {
		read(account: accountMailboxIp) ?? ""
	}

	public static func loadRoutePublicArmor() -> String {
		read(account: accountRoute) ?? ""
	}

	/// Chain refresh writer. Does not require a user PGP private key.
	/// `mailboxIp == nil` leaves the stored mailbox IP unchanged.
@discardableResult
	public static func storeChainRoster(nodes: [SiNode], mailboxIp: String?) -> Bool {
		guard !nodes.isEmpty, let json = encodeSiNodes(nodes) else { return false }
		var ok = write(account: accountSiNodes, value: json)
		if let mailboxIp, !mailboxIp.isEmpty {
			ok = write(account: accountMailboxIp, value: mailboxIp) && ok
		}
		return ok
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
			out.append(SiNode(ip: ip, domain: domain, region: region))
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
		let rows: [[String: String]] = nodes.map { ["ip": $0.ip, "domain": $0.domain, "region": $0.region] }
		guard let data = try? JSONSerialization.data(withJSONObject: rows) else { return nil }
		return String(data: data, encoding: .utf8)
	}

	private static func read(account: String) -> String? {
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
	private static func write(account: String, value: String) -> Bool {
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
}
