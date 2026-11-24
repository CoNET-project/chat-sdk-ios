import CryptoKit
import Foundation
import Security

/// Storage of the account wallet private key. The key is kept only here, in the native
/// wallet layer:
/// - one Keychain item per account, `AfterFirstUnlockThisDeviceOnly`, not synchronised;
/// - when a Secure Enclave P-256 key is available, the key bytes are wrapped with it (ECIES) and only the ciphertext
/// is stored; otherwise the bytes are stored in the Keychain item itself (mode "keychain");
/// - the key is read as `Data` and never returned as a hex string. Callers zero it after use.
/// No key ever leaves this type through the bridge or a log line.
/// X-21 migration phase for one account on one device: none, running, complete, switched.
/// `running` is written before the key, `complete` only after the read-back (and the address check) has passed,
/// `switched` after the PWA copy has been cleared (the PWA confirms it by the bridge).
public enum BeamioChatMigrationPhase: String, Equatable {
	case none
	case running
	case complete
	case switched
}

public protocol BeamioChatWalletKeyStoring {
	func write(eoa: String, key: Data) -> Bool
	func read(eoa: String) -> Data?
	func delete(eoa: String)
	/// One-time migration marker for this account on this device.
	func migrationMarkerExists(eoa: String) -> Bool
	func setMigrationMarker(eoa: String) -> Bool
	/// Migration phase (see `BeamioChatMigrationPhase`). Stores that persist phases override these.
	func migrationPhase(eoa: String) -> BeamioChatMigrationPhase
	func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool
	/// What the store knows about the key of the account: absent, present, or unreadable. Only `absent` means that there is no key.
	func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState
	/// Whether any account on this device has a key record here, readable or not. A store that cannot enumerate its records answers
	/// true (fail closed): an unreadable store is not "no key".
	func hasAnyKeyRecord() -> Bool
	/// Each key record this store holds, for the walletState enumeration. nil: the store cannot enumerate, which is not "no key"
	/// (fail closed).
	func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]?
	/// The account names of the key records, read from the record attributes only (PV.2 第 2 项): no record content, no key is read,
	/// no Secure Enclave unwrap. nil when a record cannot be named from its attributes (fail closed).
	func enumerateKeyOwners() -> [String]?
	/// The creation time of each key record, from the record attributes only (Y.163 第 5 項): no record content, no key is read. nil when the
	/// store cannot list its records (fail closed). A record whose creation time cannot be read is listed with `created` nil.
	func enumerateKeyCreations() -> [BeamioChatKeyCreation]?
	/// The judgement of one account's mnemonic (Y.163 r8 第 34(1) 項): `valid`, `invalid`, `unreadable`, or `absent`. The account is judged by its
	/// mnemonic only; a private-key record is not counted here (第 31、32 項). A store without mnemonic items answers `unreadable` (fail closed).
	func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState
	/// The creation time of each mnemonic item of this store (attributes only, Y.163 第 5 項). nil when the store cannot list them (fail closed).
	func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]?
}

extension BeamioChatWalletKeyStoring {
	/// Stores with mnemonic items answer from them; any other store has no mnemonic to judge, so the answer is `unreadable`.
	public func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState {
		guard let items = self as? BeamioChatMnemonicKeyStoring else { return .unreadable }
		return items.itemsAccountState(owner: owner)
	}

	/// Stores with mnemonic items list them; any other store cannot list its mnemonics, so the answer is nil (fail closed).
	public func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? {
		(self as? BeamioChatMnemonicKeyStoring)?.mnemonicRecordCreations()
	}
}

/// One key record's creation time, for the silent selection of `init` (Y.163 第 5 至 7 項). `created` is nil when the time cannot be read.
public struct BeamioChatKeyCreation: Equatable {
	public let owner: String
	public let created: Date?

	public init(owner: String, created: Date?) {
		self.owner = owner
		self.created = created
	}
}

/// The state of the wallet key record of an account. `absent`: there is no record. `present`: the record can be read. `unreadable`:
/// there is a record, or the store cannot be reached, and it cannot be read now. An unreadable record is not "no key".
public enum BeamioChatWalletKeyRecordState: Equatable {
	case absent
	case present
	case unreadable
}

/// The check of one key record that the enumeration found. `valid`: the record can be read, and the key it holds derives the address
/// of the account it is stored under. `locked`: a passcode record whose passcode is locked, so it cannot be judged now. `corrupt`: the record cannot be
/// decoded, or its key is not the key of its account. `unavailable`: the record is listed but cannot be read now (retryable).
public enum BeamioChatKeyEntryCheck: Equatable {
	case valid(eoa: String)
	case locked(eoa: String)
	case corrupt
	case unavailable
}

extension BeamioChatWalletKeyStoring {
	/// A store that cannot enumerate its records answers nil (fail closed). The product stores override it.
	public func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { nil }
	public func enumerateKeyOwners() -> [String]? { nil }
	public func enumerateKeyCreations() -> [BeamioChatKeyCreation]? { nil }
}

extension BeamioChatWalletKeyStoring {
	/// A store without a state of its own answers from `read`: nil is absent. Stores that can fail to read override this.
	public func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState {
		guard var key = read(eoa: eoa) else { return .absent }
		BeamioNativeWallet.wipe(&key)
		return .present
	}

	/// A store with no records of its own (a test store, or a store that keeps nothing on the device). The two stores of the product override it.
	public func hasAnyKeyRecord() -> Bool { false }
}

extension BeamioChatWalletKeyStoring {
	/// Default for stores without persisted phases: the marker means `complete`.
	public func migrationPhase(eoa: String) -> BeamioChatMigrationPhase {
		migrationMarkerExists(eoa: eoa) ? .complete : .none
	}

	/// Default for stores without persisted phases: `complete` sets the marker; the transient phases are no-ops.
	public func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
		switch phase {
		case .complete: return setMigrationMarker(eoa: eoa)
		case .running, .switched: return true
		case .none: return false
		}
	}
}

public struct BeamioChatWalletKeychainStore: BeamioChatWalletKeyStoring {
	public static let standard = BeamioChatWalletKeychainStore(service: "com.beamio.beamio.chat-wallet")
	private let service: String

	public init(service: String) {
		self.service = service
	}

	private static func owner(_ eoa: String) -> String {
		eoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
	}

	/// Keychain account name of one EOA's wallet key: one item per account, the EOA lower-cased.
	static func walletKeyAccount(_ eoa: String) -> String {
		"walletKey:" + owner(eoa)
	}

	private func baseQuery(account: String) -> [String: Any] {
		[
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecAttrAccount as String: account,
		]
	}

	/// A key write and its snapshot refresh run in one critical section (25.52Y.70 第 4 項 (c)).
	public func write(eoa: String, key: Data) -> Bool {
		BeamioNativeKeySnapshot.mutate { clearLegacyRetireRecord(owner: Self.owner(eoa)) && writeUnsnapped(eoa: eoa, key: key) }
	}

	func writeUnsnapped(eoa: String, key: Data) -> Bool {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty, key.count == 32 else { return false }
		var mode = "keychain"
		var blob = key
		if let wrapped = SecureEnclaveWrap.wrap(key) {
			mode = "se"
			blob = wrapped
		}
		let record: [String: Any] = ["v": 2, "eoa": owner, "mode": mode, "blob": blob.base64EncodedString()]
		guard let data = try? JSONSerialization.data(withJSONObject: record) else { return false }
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.put(service, Self.walletKeyAccount(owner), data)
			return true
		}
		#endif
		// An existing item is updated in place: a delete and add would reset its creation time, which orders the silent selection (Y.163 第 5 項).
		let query = baseQuery(account: Self.walletKeyAccount(owner))
		let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
		if update == errSecSuccess { return true }
		guard update == errSecItemNotFound else { return false }
		var add = query
		add[kSecValueData as String] = data
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		add[kSecAttrSynchronizable as String] = kCFBooleanFalse
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
	}

	/// The Keychain state of the record. Absent only when the Keychain has no item for the owner. An item that cannot be read (for example
	/// while the device is locked) is unreadable. The key is wiped at once, and it is never returned.
	public func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return .absent }
		// the older wallet key record of an account that the passcode state has taken over is not returned (see `legacyAwareItem`)
		switch BeamioMnemonicSets.legacyView(store: self, eoa: owner) {
		case .live: break
		case .retired: return .absent
		case .retiredUnverified, .unknown: return .unreadable
		}
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			guard BeamioChatWalletTestMemory.get(service, Self.walletKeyAccount(owner)) != nil else { return .absent }
			guard var key = readWithoutUI(eoa: eoa) else { return .unreadable }
			BeamioNativeWallet.wipe(&key)
			return .present
		}
		#endif
		// Y.163 (iOS review 2026-11-17, condition b): the production probe and the value read both suppress the authentication UI. A protected item
		// answers unreadable and never prompts. The probe's mapping is `probeAnswer`, the query is `stateProbeQuery`; both are tested without the Keychain.
		var item: CFTypeRef?
		let status = SecItemCopyMatching(stateProbeQuery(account: Self.walletKeyAccount(owner)) as CFDictionary, &item)
		BeamioKeychainFailureNote.note(status)
		if let answer = Self.probeAnswer(status) { return answer }
		guard var key = readWithoutUI(eoa: eoa) else { return .unreadable }
		BeamioNativeWallet.wipe(&key)
		return .present
	}

	/// The Keychain query that probes a record's state: attributes only (never the value), at most one item, with the authentication UI suppressed.
	func stateProbeQuery(account: String) -> [String: Any] {
		var query = baseQuery(account: account)
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		query[kSecReturnAttributes as String] = true
		query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
		return query
	}

	/// The probe's answer (pure). No item is absent. A probe that finds the item goes on to the value read (nil). Any other status, for example
	/// errSecInteractionNotAllowed while the device is locked, or a missing entitlement, is unreadable: never absent and never a prompt.
	static func probeAnswer(_ status: OSStatus) -> BeamioChatWalletKeyRecordState? {
		switch status {
		case errSecSuccess: return nil
		case errSecItemNotFound: return .absent
		default: return .unreadable
		}
	}

	/// Any wallet key item of this service, for any account. Only the account names are read, never a value. An enumeration that
	/// fails for any reason other than "no item" answers true: the store cannot say that it holds no key.
	public func hasAnyKeyRecord() -> Bool {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			return BeamioChatWalletTestMemory.accounts(service).contains { $0.hasPrefix("walletKey:") && !isRetiredLegacy(String($0.dropFirst("walletKey:".count))) }
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		BeamioKeychainFailureNote.note(status)
		if status == errSecItemNotFound { return false }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return true }
		return rows.contains { row in
			guard let account = row[kSecAttrAccount as String] as? String, account.hasPrefix("walletKey:") else { return false }
			return !isRetiredLegacy(String(account.dropFirst("walletKey:".count)))
		}
	}

	/// Keychain account of the legacy single item (store build 100 to 104): JSON `{eoa, key}`, `key` 64 lower-case hex digits.
	private static let legacyAccount = "walletKey"
	private static let perAccountPrefix = "walletKey:"

	/// The key records of this service: one item per account, and the legacy single item. The names are listed first, then each item is
	/// checked. nil when the listing fails (fail closed).
	/// Attributes only: the account name of each record. The per-account item names its owner; the legacy single item does not, so it
	/// is nil (fail closed) rather than decrypted to find its owner.
	public func enumerateKeyOwners() -> [String]? {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			var owners: [String] = []
			for account in BeamioChatWalletTestMemory.accounts(service) {
				if account == Self.legacyAccount { return nil }
				guard account.hasPrefix(Self.perAccountPrefix) else { continue }
				let owner = String(account.dropFirst(Self.perAccountPrefix.count))
				if !isRetiredLegacy(owner) { owners.append(owner) }
			}
			return owners
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		BeamioKeychainFailureNote.note(status)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var owners: [String] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			// 25.52Y.105 第 1 項: a row of another kind (mnemonic, phase, intent, commit) is skipped; it does not fail the enumeration.
			if account == Self.legacyAccount { return nil }
			guard account.hasPrefix(Self.perAccountPrefix) else { continue }
			let owner = String(account.dropFirst(Self.perAccountPrefix.count))
			if !isRetiredLegacy(owner) { owners.append(owner) }
		}
		return owners
	}

	/// The creation time of each per-account item (attributes only). The legacy single item has no owner in its attributes, so a store that
	/// holds it cannot name its creation times: nil (fail closed).
	public func enumerateKeyCreations() -> [BeamioChatKeyCreation]? {
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			var out: [BeamioChatKeyCreation] = []
			for account in BeamioChatWalletTestMemory.accounts(service) {
				if account == Self.legacyAccount { return nil }
				guard account.hasPrefix(Self.perAccountPrefix) else { continue }
				let owner = String(account.dropFirst(Self.perAccountPrefix.count))
				if isRetiredLegacy(owner) { continue }
				out.append(BeamioChatKeyCreation(owner: owner, created: BeamioChatWalletTestMemory.created(service, account)))
			}
			return out
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var out: [BeamioChatKeyCreation] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			if account == Self.legacyAccount { return nil }
			guard account.hasPrefix(Self.perAccountPrefix) else { continue }
			let owner = String(account.dropFirst(Self.perAccountPrefix.count))
			if isRetiredLegacy(owner) { continue }
			out.append(BeamioChatKeyCreation(owner: owner, created: row[kSecAttrCreationDate as String] as? Date))
		}
		return out
	}

	public func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? {
		#if BEAMIO_TEST_HOOKS
		BeamioKeychainCounters.entryEnumerations += 1
		#endif
		#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			var out: [BeamioChatKeyEntryCheck] = []
			for account in BeamioChatWalletTestMemory.accounts(service) {
				if account == Self.legacyAccount {
					out.append(.unavailable)
				} else if account.hasPrefix(Self.perAccountPrefix) {
					let owner = String(account.dropFirst(Self.perAccountPrefix.count))
					if !isRetiredLegacy(owner) { out.append(checkPerAccountItem(owner: owner)) }
				}
			}
			return out
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var out: [BeamioChatKeyEntryCheck] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			if account == Self.legacyAccount {
				out.append(.unavailable)
			} else if account.hasPrefix(Self.perAccountPrefix) {
				let owner = String(account.dropFirst(Self.perAccountPrefix.count))
				if !isRetiredLegacy(owner) { out.append(checkPerAccountItem(owner: owner)) }
			}
		}
		return out
	}

	/// One item per account. The record must name its owner, and the key it holds must derive the address.
	private func checkPerAccountItem(owner: String) -> BeamioChatKeyEntryCheck {
		#if BEAMIO_TEST_HOOKS
		BeamioKeychainCounters.entryChecks += 1
		#endif
		guard let raw = copyItemData(account: Self.walletKeyAccount(owner)) else { return .unavailable }
		guard let obj = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
			  obj["eoa"] as? String == owner,
			  let mode = obj["mode"] as? String,
			  let blobText = obj["blob"] as? String,
			  let blob = Data(base64Encoded: blobText)
		else { return .corrupt }
		var key: Data
		switch mode {
		case "se":
			guard let unwrapped = SecureEnclaveWrap.unwrap(blob) else { return .unavailable }
			key = unwrapped
		case "keychain":
			key = blob
		default:
			return .corrupt
		}
		defer { BeamioNativeWallet.wipe(&key) }
		guard key.count == 32 else { return .corrupt }
		return Self.check(privateKey: key, owner: owner)
	}

	/// `.valid` when the key derives the address, otherwise `.corrupt`.
	private static func check(privateKey key: Data, owner: String) -> BeamioChatKeyEntryCheck {
		guard let address = BeamioNativeEthSigner.address(privateKey: [UInt8](key)) else { return .corrupt }
		return address.lowercased() == owner.lowercased() ? .valid(eoa: owner.lowercased()) : .corrupt
	}

	/// The 32 key bytes of a legacy `key` field: 64 hex digits, with an optional 0x (the rule of the store, 4042c16). nil otherwise.
	static func legacyKeyBytes(_ raw: String?) -> [UInt8]? {
		var text = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		if text.hasPrefix("0x") { text.removeFirst(2) }
		guard text.count == 64, text.allSatisfy({ $0.isHexDigit }) else { return nil }
		var bytes: [UInt8] = []
		bytes.reserveCapacity(32)
		var index = text.startIndex
		while index < text.endIndex {
			let next = text.index(index, offsetBy: 2)
			guard let byte = UInt8(text[index..<next], radix: 16) else { return nil }
			bytes.append(byte)
			index = next
		}
		return bytes
	}

	private func copyItemData(account: String) -> Data? {
		BeamioKeyJudgementDiagnostics.note(.keyRecordReads)
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on { return BeamioChatWalletTestMemory.get(service, account) }
		#endif
		var query = baseQuery(account: account)
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
		return item as? Data
	}

	public func read(eoa: String) -> Data? {
		readKey(eoa: eoa, suppressUI: false)
	}

	/// The record bytes for a state read: the same item and the same decoding as `read(eoa:)`, with the Keychain's authentication UI suppressed
	/// (a protected item is unreadable and never prompts). Used by `keyRecordState` only (Y.163, iOS review 2026-11-17, condition b).
	func readWithoutUI(eoa: String) -> Data? {
		readKey(eoa: eoa, suppressUI: true)
	}

	private func readKey(eoa: String, suppressUI: Bool) -> Data? {
		if case .live = BeamioMnemonicSets.legacyView(store: self, eoa: Self.owner(eoa)) {} else { return nil }
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			let owner = Self.owner(eoa)
			guard !owner.isEmpty, let stored = BeamioChatWalletTestMemory.get(service, Self.walletKeyAccount(owner)) else { return nil }
			return BeamioChatWalletTestMemory.keyOf(record: stored, owner: owner)
		}
		#endif
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return nil }
		var query = baseQuery(account: Self.walletKeyAccount(owner))
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		if suppressUI { query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail }
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
		      let data = item as? Data,
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
		      obj["eoa"] as? String == owner,
		      let blobText = obj["blob"] as? String,
		      let blob = Data(base64Encoded: blobText)
		else { return nil }
		let key: Data?
		switch obj["mode"] as? String {
		case "se": key = SecureEnclaveWrap.unwrap(blob)
		case "keychain": key = blob
		default: key = nil
		}
		guard let key, key.count == 32 else { return nil }
		return key
	}

	/// Removes the EOA key item only: the rollback of a key write (import, migration). It never touches the mnemonic, K, or L.
	/// Whether any wallet item of this store exists (an EOA key copy, a mnemonic record, or K), by item name only. An enumeration that fails is true
	/// (fail closed). No value is read.
	public func hasAnyWalletItemOrUnreadable() -> Bool {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			return BeamioChatWalletTestMemory.accounts(service).contains { $0.hasPrefix("walletKey:") || $0.hasPrefix("mnemonic:") || $0.hasPrefix("blobKey:") }
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return false }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return true }
		return rows.contains { row in
			guard let account = row[kSecAttrAccount as String] as? String else { return true }
			return account.hasPrefix("walletKey:") || account.hasPrefix("mnemonic:") || account.hasPrefix("blobKey:")
		}
	}

	public func delete(eoa: String) {
		BeamioNativeKeySnapshot.mutate { deleteUnsnapped(eoa: eoa) }
	}

	func deleteUnsnapped(eoa: String) {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return }
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.remove(service, Self.walletKeyAccount(owner))
			return
		}
		#endif
		SecItemDelete(baseQuery(account: Self.walletKeyAccount(owner)) as CFDictionary)
	}

	/// Clearing identity or unregistering: removes the wallet items W (the mnemonic record, then K, then
	/// the EOA key item). L, the scoped PGP record, is not touched. Each step is reported: false when any step fails, with no value logged.
	#if BEAMIO_TEST_HOOKS
	/// Test build only: makes one named step ("mnemonic", "blobKey" or "key") of clearWalletItems fail, so the failure is shown to be reported.
	static var clearFailStepForTests: String? = nil
	#endif

	@discardableResult
	private func clearFailName(_ name: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		return Self.clearFailStepForTests == name
		#else
		return false
		#endif
	}

	@discardableResult
	public func clearWalletItems(eoa: String) -> Bool {
		BeamioNativeKeySnapshot.mutate { clearWalletItemsUnsnapped(eoa: eoa) }
	}

	@discardableResult
	func clearWalletItemsUnsnapped(eoa: String) -> Bool {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return false }
		let steps: [(String, () -> Bool)] = [
			("mnemonic", { self.deleteItem(.mnemonic, eoa: owner) }),
			("blobKey", { BeamioWalletCredentialBlob.delete(eoa: owner) }),
			// The published `walletKey:<eoa>` item is never deleted here: this step is gone, so a clear of the identity keeps it, byte for byte.
		]
		var allDone = true
		for (name, step) in steps where !(clearFailName(name) ? false : step()) {
			NSLog("[BeamioChatWalletKeychain] account delete: the %@ item was not removed; retry the delete", name)
			allDone = false
		}
		return allDone
	}

	/// Storage mode of the record ("se" or "keychain"), for diagnostics. Never returns key material.
	public func storageMode(eoa: String) -> String? {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			guard let stored = BeamioChatWalletTestMemory.get(service, Self.walletKeyAccount(Self.owner(eoa))),
			      let obj = try? JSONSerialization.jsonObject(with: stored) as? [String: Any] else { return nil }
			return obj["mode"] as? String
		}
		#endif
		let owner = Self.owner(eoa)
		var query = baseQuery(account: Self.walletKeyAccount(owner))
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
		      let data = item as? Data,
		      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
		else { return nil }
		return obj["mode"] as? String
	}

	public func migrationMarkerExists(eoa: String) -> Bool {
		let phase = migrationPhase(eoa: eoa)
		return phase == .complete || phase == .switched
	}

	public func setMigrationMarker(eoa: String) -> Bool {
		setMigrationPhase(eoa: eoa, .complete)
	}

	/// Persisted phase in its own item. Accounts migrated before phases existed carry the old `migrated:` marker,
	/// which reads as `complete`.
	public func migrationPhase(eoa: String) -> BeamioChatMigrationPhase {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			if let stored = BeamioChatWalletTestMemory.get(service, "phase:" + Self.owner(eoa)), let raw = String(data: stored, encoding: .utf8),
			   let phase = BeamioChatMigrationPhase(rawValue: raw) {
				return phase
			}
			return BeamioChatWalletTestMemory.get(service, "migrated:" + Self.owner(eoa)) != nil ? .complete : .none
		}
		#endif
		var query = baseQuery(account: "phase:" + Self.owner(eoa))
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		var item: CFTypeRef?
		if SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
		   let data = item as? Data, let raw = String(data: data, encoding: .utf8),
		   let phase = BeamioChatMigrationPhase(rawValue: raw) {
			return phase
		}
		var legacy = baseQuery(account: "migrated:" + Self.owner(eoa))
		legacy[kSecReturnData as String] = true
		legacy[kSecMatchLimit as String] = kSecMatchLimitOne
		var legacyItem: CFTypeRef?
		return SecItemCopyMatching(legacy as CFDictionary, &legacyItem) == errSecSuccess ? .complete : .none
	}

	public func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			let key = "phase:" + Self.owner(eoa)
			BeamioChatWalletTestMemory.remove(service, key)
			if phase == .none { return true }
			BeamioChatWalletTestMemory.put(service, key, Data(phase.rawValue.utf8))
			return true
		}
		#endif
		let query = baseQuery(account: "phase:" + Self.owner(eoa))
		SecItemDelete(query as CFDictionary)
		if phase == .none { return true }
		var add = query
		add[kSecValueData as String] = Data(phase.rawValue.utf8)
		add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
		add[kSecAttrSynchronizable as String] = kCFBooleanFalse
		return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
	}
}

/// Secure Enclave wrap of the wallet key bytes (D21). Returns nil when no Secure Enclave key can be created or used,
/// in which case the caller stores the bytes in the Keychain item (mode "keychain"). Not verified on a device here.
enum SecureEnclaveWrap {
	private static let tag = Data("com.beamio.chat-wallet.se-wrap.v1".utf8)
	private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

	private static func existingKey() -> SecKey? {
		let query: [String: Any] = [
			kSecClass as String: kSecClassKey,
			kSecAttrApplicationTag as String: tag,
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecReturnRef as String: true,
		]
		var item: CFTypeRef?
		guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
		return (item as! SecKey)
	}

	private static func createKey() -> SecKey? {
		var error: Unmanaged<CFError>?
		guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &error) else {
			return nil
		}
		let attributes: [String: Any] = [
			kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
			kSecAttrKeySizeInBits as String: 256,
			kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
			kSecPrivateKeyAttrs as String: [
				kSecAttrIsPermanent as String: true,
				kSecAttrApplicationTag as String: tag,
				kSecAttrAccessControl as String: acl,
			],
		]
		return SecKeyCreateRandomKey(attributes as CFDictionary, &error)
	}

	static func wrap(_ data: Data) -> Data? {
#if BEAMIO_TEST_HOOKS
		// Test build only: the memory items keep the keys in "keychain" mode, so a test run creates no Secure Enclave key.
		if BeamioChatWalletTestMemory.on { return nil }
	#endif
		guard let priv = existingKey() ?? createKey(), let pub = SecKeyCopyPublicKey(priv) else { return nil }
		guard SecKeyIsAlgorithmSupported(pub, .encrypt, algorithm) else { return nil }
		var error: Unmanaged<CFError>?
		return SecKeyCreateEncryptedData(pub, algorithm, data as CFData, &error) as Data?
	}

	static func unwrap(_ blob: Data) -> Data? {
		BeamioKeyJudgementDiagnostics.noteUnlock()
		guard let priv = existingKey() else { return nil }
		var error: Unmanaged<CFError>?
		return SecKeyCreateDecryptedData(priv, algorithm, blob as CFData, &error) as Data?
	}
}

/// Helpers the module uses. The static API keeps no key in memory.
public enum BeamioChatWalletKeychain {
	/// 64 lower-case hex chars without 0x; empty when not a private key.
	public static func normalizeKey(_ raw: String?) -> String {
		var t = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		if t.hasPrefix("0x") { t.removeFirst(2) }
		guard t.count == 64, t.allSatisfy({ $0.isHexDigit }) else { return "" }
		return t
	}

	public static func hasKey(eoa: String, store: BeamioChatWalletKeyStoring = BeamioChatWalletKeychainStore.standard) -> Bool {
		guard let k = store.read(eoa: eoa) else { return false }
		var copy = k
		BeamioNativeWallet.wipe(&copy)
		return true
	}
}

// MARK: - Mnemonic, intent and commit items

/// The Keychain items of one account that the import and creation keep beside the key (第 3、4 项).
/// `key` is the existing private key record (`walletKey:<eoa>`). `mnemonic` is `mnemonic:<eoa>`, the BIP-39 phrase, wrapped like the key
/// record. `intent` and `commit` are `intent:<eoa>` and `commit:<eoa>`: plain UTF-8 JSON with no secret in them ((h)).
public enum BeamioChatWalletItemKind: String, CaseIterable {
	case key
	case mnemonic
	case intent
	case commit
}

/// The state of one item ((i)): absent, present, or present but unreadable (no data is returned here).
public enum BeamioChatItemState: Equatable {
	case absent
	case present
	case unreadable
}

/// The write, read and delete of the four items of an account, and the enumeration of the intent items for the start-up
/// reconciliation ((c)). Only the intent item names its account: the enumeration returns the of the intent items.
public protocol BeamioChatMnemonicKeyStoring: BeamioChatWalletKeyStoring {
	func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState
	/// `value` is the phrase bytes for `mnemonic`, and the record bytes (the same JSON as the key record) for `key`; `intent` and `commit`
	/// store the given JSON as is.
	func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool
	/// The decoded value (the phrase bytes or the key bytes, or the stored JSON). nil when absent or unreadable.
	func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data?
	/// True when the item is gone after the call (an absent item counts as deleted).
	func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool
	/// The accounts that have an intent item, or nil when the enumeration failed.
	func intentOwners() -> [String]?
	/// The mnemonic items with their creation times (attributes only). nil when the enumeration failed (Y.163 第 5、34(1) 項).
	func mnemonicRecordCreations() -> [BeamioChatKeyCreation]?
	/// Whether a failed read of this owner's mnemonic item is transient (a locked keychain, before the first unlock, or another non-deterministic error),
	/// as opposed to deterministic (the item is absent or does not decode). A transient failure is never a reason to ignore the item (E9.1-1, 2026-11-17).
	/// A store that cannot tell answers true (fail closed).
	func mnemonicReadFailureIsTransient(owner: String) -> Bool
}

extension BeamioChatMnemonicKeyStoring {
	/// A store with no mnemonic enumeration answers nil (fail closed). The product stores override it.
	public func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? { nil }
	/// Default: transient (fail closed).
	public func mnemonicReadFailureIsTransient(owner: String) -> Bool { true }
}

extension BeamioChatWalletKeychainStore: BeamioChatMnemonicKeyStoring {
	static func itemAccount(_ kind: BeamioChatWalletItemKind, owner: String) -> String {
		switch kind {
		case .key: return walletKeyAccount(owner)
		case .mnemonic: return "mnemonic:" + owner
		case .intent: return "intent:" + owner
		case .commit: return "commit:" + owner
		}
	}

	/// Removes the retirement record of the older copies of `owner` before an older-format item is written for it. True when no record is left.
	private func clearLegacyRetireRecord(owner: String) -> Bool {
		guard !owner.isEmpty else { return true }
		switch rawRead(account: BeamioMnemonicSets.legacyRetireName(owner)) {
		case .absent: return true
		case .unreadable: return false
		case .present: return rawDelete(account: BeamioMnemonicSets.legacyRetireName(owner))
		}
	}

	/// True when the older copies of this owner are retired and the v3 record is verified: the owner is no longer listed by the key and mnemonic enumerations.
	private func isRetiredLegacy(_ owner: String) -> Bool {
		BeamioMnemonicSets.legacyView(store: self, eoa: owner) == .retired
	}

	/// The item of a kind as the readers see it: the older device copies (`mnemonic:`, `walletKey:`) of an account that the passcode state has taken over are not returned. Retired and verified: not
	/// found (the account is judged by its v3 record). Retired but the v3 record does not read back, or the pointer cannot be read: an item that cannot be read, never absent and never the copy.
	private func legacyAwareItem(_ kind: BeamioChatWalletItemKind, owner: String) -> (status: OSStatus, data: Data?) {
		let account = Self.itemAccount(kind, owner: owner)
		guard kind == .mnemonic || kind == .key else { return rawItem(account: account) }
		switch BeamioMnemonicSets.legacyView(store: self, eoa: owner) {
		case .live: return rawItem(account: account)
		case .retired: return (errSecItemNotFound, nil)
		case .retiredUnverified, .unknown: return (errSecInteractionNotAllowed, nil)
		}
	}

	private func rawItem(account: String) -> (status: OSStatus, data: Data?) {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			if let stored = BeamioChatWalletTestMemory.get(service, account) { return (errSecSuccess, stored) }
			return (errSecItemNotFound, nil)
		}
		#endif
		var query = baseQuery(account: account)
		query[kSecReturnData as String] = true
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		// Y.163 (iOS review 2026-11-17, condition b): a state read never raises a Keychain authentication prompt. A protected item answers as unreadable.
		query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		return (status, item as? Data)
	}

	/// The status of the mnemonic item's read: a deterministic failure is an absent item or one that does not decode (errSecDecode); any other status
	/// (a locked keychain, errSecInteractionNotAllowed, or an unknown error) is transient. The test memory has no keychain status: deterministic.
	public func mnemonicReadFailureIsTransient(owner rawOwner: String) -> Bool {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on { return false }
#endif
		let owner = Self.owner(rawOwner)
		guard !owner.isEmpty else { return true }
		let got = legacyAwareItem(.mnemonic, owner: owner)
		switch got.status {
		case errSecItemNotFound, errSecDecode: return false
		case errSecSuccess:
			// The item is there. A record that is not the stored shape is deterministic (format, E9.1.2-1 (a)). A well-formed record whose blob does not
			// unwrap is NOT classified deterministic here: an authentication failure and a locked Secure Enclave look the same at this layer, so it is
			// transient (unknown, fail closed) until a keystore-availability probe separates them (E9.1.2 open item, reported 2026-11-17).
			guard let data = got.data,
			      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
			      obj["eoa"] as? String == owner, obj["blob"] is String, obj["mode"] is String
			else { return false }
			return true
		default: return true
		}
	}

	public func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return .unreadable }
		let got = legacyAwareItem(kind, owner: owner)
		if got.status == errSecItemNotFound {
			// no `mnemonic:<eoa>` item: the no-passcode set of the same owner is the mnemonic of the account
			if kind == .mnemonic {
				switch BeamioMnemonicSets.readSet(store: self, eoa: owner) {
				case .absent:
					// method Y: the account whose current record is a v3 envelope has its mnemonic item in that envelope
					if case .cipher(let held, _) = BeamioMnemonicSets.current(store: self), held == owner { return .present }
					return .absent
				case .unreadable: return .unreadable
				case .damaged, .phrase: return .present
				}
			}
			return .absent
		}
		return got.status == errSecSuccess && got.data != nil ? .present : .unreadable
	}

	public func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
		BeamioNativeKeySnapshot.mutate { writeItemUnsnapped(kind, eoa: eoa, value: value) }
	}

	func writeItemUnsnapped(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty, !value.isEmpty else { return false }
		// an older-format item written again for an account whose copies were retired is a new choice of that item: the retirement record no longer applies
		if kind == .mnemonic || kind == .key, !clearLegacyRetireRecord(owner: owner) { return false }
		let payload: Data
		switch kind {
		case .intent, .commit:
			payload = value
		case .key, .mnemonic:
			var mode = "keychain"
			var blob = value
			if let wrapped = SecureEnclaveWrap.wrap(value) {
				mode = "se"
				blob = wrapped
			}
			let record: [String: Any] = ["v": 2, "eoa": owner, "mode": mode, "blob": blob.base64EncodedString()]
			guard let data = try? JSONSerialization.data(withJSONObject: record) else { return false }
			payload = data
		}
		// (order step 2): for a mnemonic, the blob key K is created and read back first. If K cannot be made, the mnemonic is not written.
		// K created here is removed again when the mnemonic write fails, so no K is left without a mnemonic record.
		let keyExisted = kind == .mnemonic && BeamioWalletCredentialBlob.hasRecord(eoa: owner)
		if kind == .mnemonic, !BeamioWalletCredentialBlob.createIfMissing(eoa: owner) { return false }
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.put(service, Self.itemAccount(kind, owner: owner), payload)
			return true
		}
		#endif
		let query = baseQuery(account: Self.itemAccount(kind, owner: owner))
		// Y.163 第 5a 項: an existing item is updated in place, never deleted and added again, so its creation time (which orders the
		// silent selection) is kept. A new item is added only when there is nothing to update.
		let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: payload] as CFDictionary)
		var written = update == errSecSuccess
		if !written, update == errSecItemNotFound {
			var add = query
			add[kSecValueData as String] = payload
			add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
			add[kSecAttrSynchronizable as String] = kCFBooleanFalse
			written = SecItemAdd(add as CFDictionary, nil) == errSecSuccess
		}
		if !written, kind == .mnemonic, !keyExisted { _ = BeamioWalletCredentialBlob.delete(eoa: owner) }
		return written
	}

	public func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return nil }
		let found = legacyAwareItem(kind, owner: owner)
		guard let data = found.data else {
			if kind == .mnemonic, found.status == errSecItemNotFound, case .phrase(let phrase) = BeamioMnemonicSets.readSet(store: self, eoa: owner) { return phrase }
			return nil
		}
		switch kind {
		case .intent, .commit:
			return data
		case .key, .mnemonic:
			guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
			      obj["eoa"] as? String == owner,
			      let blobText = obj["blob"] as? String,
			      let blob = Data(base64Encoded: blobText)
			else { return nil }
			switch obj["mode"] as? String {
			case "se": return SecureEnclaveWrap.unwrap(blob)
			case "keychain": return blob
			default: return nil
			}
		}
	}

	public func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
		BeamioNativeKeySnapshot.mutate { deleteItemUnsnapped(kind, eoa: eoa) }
	}

	func deleteItemUnsnapped(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
		let owner = Self.owner(eoa)
		guard !owner.isEmpty else { return false }
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			BeamioChatWalletTestMemory.remove(service, Self.itemAccount(kind, owner: owner))
			if kind == .mnemonic, !BeamioWalletCredentialBlob.delete(eoa: owner) { return false }
			return true
		}
		#endif
		let status = SecItemDelete(baseQuery(account: Self.itemAccount(kind, owner: owner)) as CFDictionary)
		// /: K goes with the mnemonic record; a failed K deletion keeps the item failed.
		if kind == .mnemonic, !BeamioWalletCredentialBlob.delete(eoa: owner) { return false }
		return status == errSecSuccess || status == errSecItemNotFound
	}

	/// The mnemonic items of this service with their creation times, and (method Y) the account whose current record is a v3 envelope.
	public func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? {
		guard var rows = mnemonicItemCreations() else { return nil }
		if case .cipher(let eoa, _) = BeamioMnemonicSets.current(store: self), !rows.contains(where: { $0.owner.lowercased() == eoa }) {
			rows.append(BeamioChatKeyCreation(owner: eoa, created: nil))
		}
		return rows
	}

	/// The mnemonic items of this service with their creation times. Attributes only: no value is read, no secure element is used.
	private func mnemonicItemCreations() -> [BeamioChatKeyCreation]? {
		let prefix = "mnemonic:"
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			return BeamioChatWalletTestMemory.accounts(service).compactMap { account -> BeamioChatKeyCreation? in
				if let setOwner = BeamioMnemonicSets.setOwner(inAccount: account) {
					return BeamioChatKeyCreation(owner: setOwner, created: BeamioChatWalletTestMemory.created(service, account))
				}
				guard account.hasPrefix(prefix) else { return nil }
				return BeamioChatKeyCreation(owner: String(account.dropFirst(prefix.count)),
				                             created: BeamioChatWalletTestMemory.created(service, account))
			}
		}
		#endif
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var out: [BeamioChatKeyCreation] = []
		for row in rows {
			guard let account = row[kSecAttrAccount as String] as? String else { return nil }
			if let setOwner = BeamioMnemonicSets.setOwner(inAccount: account) {
				out.append(BeamioChatKeyCreation(owner: setOwner, created: row[kSecAttrCreationDate as String] as? Date))
				continue
			}
			guard account.hasPrefix(prefix) else { continue }
			out.append(BeamioChatKeyCreation(owner: String(account.dropFirst(prefix.count)),
			                                 created: row[kSecAttrCreationDate as String] as? Date))
		}
		return out
	}

	public func intentOwners() -> [String]? {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on {
			return BeamioChatWalletTestMemory.accounts(service).compactMap { $0.hasPrefix("intent:") ? String($0.dropFirst("intent:".count)) : nil }
		}
		#endif
		var query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		return rows.compactMap { row -> String? in
			guard let account = row[kSecAttrAccount as String] as? String, account.hasPrefix("intent:") else { return nil }
			return String(account.dropFirst("intent:".count))
		}
	}
}

#if BEAMIO_TEST_HOOKS
/// Test build only: counts the key-record reads of the entry checks, so a test can assert that a judgement does not reach them.
enum BeamioKeychainCounters {
	static var entryEnumerations = 0
	static var entryChecks = 0
	static func reset() { entryEnumerations = 0; entryChecks = 0 }
}
#endif
#if BEAMIO_TEST_HOOKS
/// Test build only: the wallet service's Keychain items, held in memory. The simulator test host has no Keychain entitlement (-34018), and a test
/// run must not write the real Keychain. The items are the store items (key, mnemonic, intent, commit, phase), the K records and the recovery-backup
/// flags, all in the one service. In a test-hook build `items` is held in memory from the start (`[:]`), so every test answers from memory and no
/// test writes the real Keychain; a test may still set `[:]` in setUp and restore the saved value in tearDown. Each item is keyed by its service
/// and account. The Security calls of the other files are answered from these items too (see BeamioTestKeychainStore). The product code paths
/// are not changed.
enum BeamioChatWalletTestMemory {
	static var items: [String: Data]? = [:]

	static var on: Bool { items != nil }

	private static func slot(_ service: String, _ account: String) -> String { service + "\u{1}" + account }

	static func get(_ service: String, _ account: String) -> Data? { items?[slot(service, account)] }

	/// The creation time of each item, as the Keychain keeps it: set when the item is added, kept by a change of its value.
	static var createdAt: [String: Date] = [:]

	static func put(_ service: String, _ account: String, _ data: Data) {
		if items == nil { items = [:] }   // never "off": a write with no items creates them, it does not go to the real Keychain
		if items?[slot(service, account)] == nil { createdAt[slot(service, account)] = Date() }
		items?[slot(service, account)] = data
	}

	static func remove(_ service: String, _ account: String) {
		items?[slot(service, account)] = nil
		createdAt[slot(service, account)] = nil
	}

	static func created(_ service: String, _ account: String) -> Date? { createdAt[slot(service, account)] }

	/// Test only: sets the creation time of an item already in memory (the ordering of the silent selection needs known times).
	static func setCreated(_ service: String, _ account: String, _ date: Date?) { createdAt[slot(service, account)] = date }

	/// The account names of one service, sorted.
	static func accounts(_ service: String) -> [String] {
		let prefix = service + "\u{1}"
		return (items ?? [:]).keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }.sorted()
	}

	/// The key of a keystore record held in "keychain" mode for its owner. nil for any other record.
	static func keyOf(record data: Data, owner: String) -> Data? {
		guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
		      obj["eoa"] as? String == owner, obj["mode"] as? String == "keychain",
		      let blobText = obj["blob"] as? String, let blob = Data(base64Encoded: blobText), blob.count == 32
		else { return nil }
		return blob
	}
}
#endif
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
fileprivate func SecItemUpdate(_ query: CFDictionary, _ attributesToUpdate: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.update(query, attributesToUpdate)
}
fileprivate func SecKeyCreateRandomKey(_ parameters: CFDictionary, _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?) -> SecKey? {
	// A test build never creates a Secure Enclave key, whatever `BeamioChatWalletTestMemory.items` holds (nil or not): this answers nil, so the creation of an SE key FAILS.
	// `BeamioPasscodeKeychainHardware.createKey` then takes its Keychain fallback (SecItemAdd, also answered from the in-memory items, which a first write creates), so `createKey`
	// still SUCCEEDS in a test build, by the fallback, with nothing written to the real Keychain.
	BeamioTestKeychainStore.createRandomKey(parameters, error)
}
#endif

/// The residue probe of 25.52Y.162. An attribute-only, non-interactive enumeration of the keychain services that hold the residues: the
/// chat-wallet service by prefix (`mnemonic:`, `commit:`, `intent:`, `walletKey:`), and the chat-pgp and chat-pgp-k services as a whole. No
/// value is read (kSecReturnData is false), nothing is deleted, and no authentication UI is shown. The answer is `present` when a residue
/// exists, `absent` when the enumerations succeeded and found none, and `failed` for any other outcome (error, incomplete, refused).
public enum BeamioResidueProbe {
	public enum Result: Equatable {
		case absent, present, failed
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only: an answer given by the test in place of the enumeration (the failure cases).
	public static var overrideForTests: (() -> Result)?
	#endif

	static let walletService = "com.beamio.beamio.chat-wallet"
	/// Y.163 r8 第 32 項 行 4: a residue is a mnemonic-channel item only. A private-key record (`walletKey:`) and the PGP services are not residue.
	static let walletPrefixes = ["mnemonic:", "commit:", "intent:"]
	static let pgpServices = ["com.beamio.beamio.chat-pgp", "com.beamio.beamio.chat-pgp-k"]

	/// Whether a list of account names holds a residue: an item of the mnemonic channel (one of the prefixes), or an orphan v3 cipher version item
	/// (`mnemonic.set.<eoa>.c.<digest>`, the pointer `mnemonic.current` is missing). The version is written before the pointer, so a refused pointer write leaves an orphan: a
	/// recorded account that no inventory lists, and a creation must not go ahead beside it. The condition is the one of the preread (`BeamioPwaWalletSync.reading`).
	/// With a pointer the versions are named and the account is judged by its own state. The versions of an identity that was cleared on purpose are ignored with it; an
	/// unreadable marker blocks (unknown).
	static func hasResidue(in names: [String], prefixes: [String]) -> Bool {
		if names.contains(where: { name in prefixes.contains { name.hasPrefix($0) } }) { return true }
		if names.contains(BeamioMnemonicSets.currentName) { return false }
		let owners = Set(names.compactMap { BeamioMnemonicSets.cipherVersionOwner(inAccount: $0)?.lowercased() })
		return BeamioMnemonicSets.orphanVersionsBlock(owners: owners, cleared: BeamioIdentityCleared.read(store: BeamioNativeWallet.keyStore))
	}

	/// The account names of one service, from the attributes only. nil when the enumeration fails or any row has no account name.
	static func accounts(service: String) -> [String]? {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
			kSecReturnAttributes as String: true,
			kSecReturnData as String: false,
			kSecMatchLimit as String: kSecMatchLimitAll,
			kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var items: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &items)
		if status == errSecItemNotFound { return [] }
		guard status == errSecSuccess, let rows = items as? [[String: Any]] else { return nil }
		var names: [String] = []
		for row in rows {
			guard let name = row[kSecAttrAccount as String] as? String else { return nil }
			names.append(name)
		}
		return names
	}

	/// The probe itself. The chat-wallet service is checked first, then the two PGP services.
	/// The probe for the walletStatus G0 residue (E9.11-3, 2026-11-17): an intent item is not residue when the current mnemonic decides the answer, so the
	/// caller passes `ignoringIntents: true`. The intent and the residue themselves are kept.
	public static func probe(ignoringIntents: Bool) -> Result {
		if !ignoringIntents { return probe() }
		#if BEAMIO_TEST_HOOKS
		if overrideForTests != nil { return probe() }
		if BeamioChatWalletTestMemory.on {
			let walletAccounts = BeamioChatWalletTestMemory.accounts(walletService)
			return hasResidue(in: walletAccounts, prefixes: ["mnemonic:", "commit:"]) ? .present : .absent
		}
		#endif
		guard let walletAccounts = accounts(service: walletService) else { return .failed }
		if hasResidue(in: walletAccounts, prefixes: ["mnemonic:", "commit:"]) { return .present }
		for service in pgpServices {
			guard accounts(service: service) != nil else { return .failed }
		}
		return .absent
	}

	public static func probe() -> Result {
		#if BEAMIO_TEST_HOOKS
		if let overrideForTests { return overrideForTests() }
		// Test build: the chat-wallet memory answers the probe, so no test asks the real Keychain (the simulator refuses the query, which
		// would read as a failed probe). The PGP services are not in that memory and are absent here.
		if BeamioChatWalletTestMemory.on {
			let walletAccounts = BeamioChatWalletTestMemory.accounts(walletService)
			return hasResidue(in: walletAccounts, prefixes: walletPrefixes) ? .present : .absent
		}
		#endif
		guard let walletAccounts = accounts(service: walletService) else { return .failed }
		if hasResidue(in: walletAccounts, prefixes: walletPrefixes) { return .present }
		// The PGP services are listed so that a failed listing still fails closed, but their items are not residue (Y.163 第 32 項 行 4).
		for service in pgpServices {
			guard accounts(service: service) != nil else { return .failed }
		}
		return .absent
	}
}

// MARK: - Raw payloads for the PWA overwrite (25.52Y.163 r2.5.19 第 59(3)(e))

/// The raw state of one stored account: its payload bytes exactly as stored (wrapped for the key and mnemonic records), absent, or unreadable.
public enum BeamioChatRawItem: Equatable {
	case absent
	case present(Data)
	case unreadable
}

/// Raw access to the stored payloads of the wallet items. The overwrite isolates a record by copying its payload bytes and restores it by writing
/// the same bytes back: nothing is unwrapped or re-wrapped, so an isolated record restores byte for byte.
public protocol BeamioChatRawItemStoring: BeamioChatMnemonicKeyStoring {
	/// The account name one item of an owner is kept under.
	func accountName(_ kind: BeamioChatWalletItemKind, eoa: String) -> String
	func rawRead(account: String) -> BeamioChatRawItem
	/// Writes the bytes as they are. False when the write fails; the account is then unchanged.
	func rawWrite(account: String, bytes: Data) -> Bool
	/// True when the account is absent after the call.
	func rawDelete(account: String) -> Bool
	/// Judges the payload of a copy of one mnemonic item (the bytes `rawRead` gives for it) for `owner`: `valid` with the phrase, `invalid`, or
	/// `unreadable`. Nothing is written or deleted, and no key is returned. A store that cannot judge a payload answers `unreadable` (fail closed).
	func judgeMnemonicPayload(_ bytes: Data, owner: String) -> (state: BeamioMnemonicAccountState, phrase: Data?)
	/// Deletes the plaintext mnemonic set of `eoa` (`mnemonic.set.<eoa>`, never a v3 version and never the pointer). Only the cleanup of a retired set calls it. True when the item is absent after the call.
	func deleteRetiredPlainSet(eoa: String) -> Bool
	/// Deletes the older device copies of `eoa` once the passcode state holds the account: the wrapped mnemonic item `mnemonic:<eoa>` (with the credential key that goes with it) and the wallet key
	/// record `walletKey:<eoa>`. Only the cleanup of a retired account calls it. True when the store did the deletions; the caller checks that the items are gone.
	func deleteRetiredLegacyItems(eoa: String) -> Bool
	/// Every account name of the raw items of this store, from the attributes only. nil: the store cannot list its items (fail closed: the caller reads that as unknown).
	func rawAccountNames() -> [String]?
}

extension BeamioChatRawItemStoring {
	/// A store that cannot list its items says so; the callers treat that as an unknown state, never as "no items".
	public func rawAccountNames() -> [String]? { nil }

	/// The plain deletion of the one plaintext set item. A store that guards its set items overrides it.
	public func deleteRetiredPlainSet(eoa: String) -> Bool { rawDelete(account: BeamioMnemonicSets.setName(eoa)) }

	/// A store that guards its items overrides it; the plain store deletes the two items and the credential key.
	public func deleteRetiredLegacyItems(eoa: String) -> Bool {
		let mnemonic = deleteItem(.mnemonic, eoa: eoa)
		delete(eoa: eoa)
		return mnemonic
	}

	public func judgeMnemonicPayload(_ bytes: Data, owner: String) -> (state: BeamioMnemonicAccountState, phrase: Data?) {
		(.unreadable, nil)
	}
}

extension BeamioChatWalletKeychainStore: BeamioChatRawItemStoring {
	public func rawAccountNames() -> [String]? {
#if BEAMIO_TEST_HOOKS
		if BeamioChatWalletTestMemory.on { return BeamioChatWalletTestMemory.accounts(service) }
		#endif
		return BeamioResidueProbe.accounts(service: service)
	}

	public func accountName(_ kind: BeamioChatWalletItemKind, eoa: String) -> String {
		Self.itemAccount(kind, owner: Self.owner(eoa))
	}

	public func rawRead(account: String) -> BeamioChatRawItem {
		let got = rawItem(account: account)
		if got.status == errSecItemNotFound { return .absent }
		guard got.status == errSecSuccess, let data = got.data else { return .unreadable }
		return .present(data)
	}

	public func rawWrite(account: String, bytes: Data) -> Bool {
		BeamioNativeKeySnapshot.mutate { () -> Bool in
			guard !bytes.isEmpty else { return false }
#if BEAMIO_TEST_HOOKS
			if BeamioChatWalletTestMemory.on {
				BeamioChatWalletTestMemory.put(service, account, bytes)
				return true
			}
#endif
			let query = baseQuery(account: account)
			let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: bytes] as CFDictionary)
			if update == errSecSuccess { return true }
			guard update == errSecItemNotFound else { return false }
			var add = query
			add[kSecValueData as String] = bytes
			add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
			add[kSecAttrSynchronizable as String] = kCFBooleanFalse
			return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
		}
	}

	public func rawDelete(account: String) -> Bool {
		BeamioNativeKeySnapshot.mutate { () -> Bool in
#if BEAMIO_TEST_HOOKS
			if BeamioChatWalletTestMemory.on {
				BeamioChatWalletTestMemory.remove(service, account)
				return true
			}
#endif
			let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
			return status == errSecSuccess || status == errSecItemNotFound
		}
	}

	/// The stored mnemonic record (the same JSON as `writeItem` makes) is judged as `readItem` judges it: the owner must match, the blob is unwrapped,
	/// the phrase must pass the BIP-39 check and derive the owner. The phrase is returned only for `valid`.
	public func judgeMnemonicPayload(_ bytes: Data, owner rawOwner: String) -> (state: BeamioMnemonicAccountState, phrase: Data?) {
		let owner = Self.owner(rawOwner)
		guard !owner.isEmpty,
		      let obj = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
		      obj["eoa"] as? String == owner,
		      let blobText = obj["blob"] as? String,
		      let blob = Data(base64Encoded: blobText)
		else { return (.unreadable, nil) }
		let plain: Data?
		switch obj["mode"] as? String {
		case "se": plain = SecureEnclaveWrap.unwrap(blob)
		case "keychain": plain = blob
		default: return (.unreadable, nil)
		}
		guard var phrase = plain else { return (.unreadable, nil) }
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) else {
			BeamioNativeWallet.wipe(&phrase)
			return (.invalid, nil)
		}
		defer { BeamioNativeWallet.wipe(&key) }
		guard let derived = BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), derived == owner else {
			BeamioNativeWallet.wipe(&phrase)
			return (.invalid, nil)
		}
		return (.valid, phrase)
	}
}
