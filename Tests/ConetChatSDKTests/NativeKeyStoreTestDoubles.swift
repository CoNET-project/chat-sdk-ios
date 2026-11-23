import Foundation
@testable import ConetChatSDK

/// A memory native key store for tests. A device with no native key is the default of these tests. The product store cannot be read in the
/// simulator (no Keychain entitlement), so a test that relies on "no native key" must not use it: its records would be unreadable, and the shell
/// answers an unreadable record as a record that exists (fail closed).
final class MemoryNativeKeyStore: BeamioChatMnemonicKeyStoring {
	/// A change of the keys is a key-store write: the native-key snapshot is judged again at the next session start (25.52Y.70 第 4 項).
	var keys: [String: Data] = [:] {
		didSet { BeamioNativeKeySnapshot.mutate { } }
	}

	/// The mnemonic, intent and commit items (TestMnemonicItems). A key record alone is not an account (第 31、32 項): with no mnemonic item
	/// the account is `absent`, and the enumeration of the mnemonics is an empty list.
	var mnemonic = TestMnemonicItems() {
		didSet { BeamioNativeKeySnapshot.mutate { } }
	}

	/// Raw accounts that are not wallet items: the isolation copies, the marker and the audit of the PWA overwrite (r2.5.19 第 59(3)(e)).
	var rawAccounts: [String: Data] = [:]

	/// Test seam: raw accounts whose read fails (the marker of E9.10.3 G1-NK-S1, a read failure of MARK).
	var failRawReadAccounts: Set<String> = []
	/// The store cannot list its raw items (rawAccountNames answers nil).
	var rawNamesUnavailable = false

	/// Test seam: mnemonic items whose failed read is transient (a locked keychain). Default: every failure is deterministic.
	var transientReadOwners: Set<String> = []

	/// Test seam (SS-32-u): a scripted sequence of mnemonic states per owner; each read consumes one entry. Empty: the store's own state.
	var mnemonicStateScript: [String: [BeamioMnemonicAccountState]] = [:]

	/// Test seam (SS-32-u, bytes): the stored bytes returned with each scripted state (consumed together with the state).
	var mnemonicBytesScript: [String: [Data]] = [:]
	private var scriptedBytes: [String: Data] = [:]

	func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState {
		let key = owner.lowercased()
		if var script = mnemonicStateScript[key], !script.isEmpty {
			let next = script.removeFirst()
			mnemonicStateScript[key] = script
			if var bytes = mnemonicBytesScript[key], !bytes.isEmpty {
				scriptedBytes[key] = bytes.removeFirst()
				mnemonicBytesScript[key] = bytes
			}
			return next
		}
		return itemsAccountState(owner: owner)
	}

	func mnemonicReadFailureIsTransient(owner: String) -> Bool { transientReadOwners.contains(owner.lowercased()) }

	/// Test seam: the n-th mutating call (a write or a delete, item or raw) fails and changes nothing. nil: no call fails.
	var failMutationAt: Int?
	private(set) var mutationCount = 0

	/// Counts one mutating call and says whether it is the one that fails.
	func mutationFails() -> Bool {
		mutationCount += 1
		return failMutationAt == mutationCount
	}

	/// Test seams for the PWA overwrite (r2.5.21 synthetic cases). Names are account names as `accountName` and the raw calls give them.
	/// A write to a name here returns false and changes nothing.
	var failWriteAccounts: Set<String> = []
	/// A write to a name here reports success and stores nothing (a read-back then finds no record).
	var dropWriteAccounts: Set<String> = []
	/// A raw write to a name with one of these prefixes stores the bytes with the first byte flipped (a copy that does not match its digest).
	var corruptWritePrefixes: [String] = []
	/// A raw write whose bytes contain this text fails and changes nothing.
	var failRawWriteContaining: String?

	func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
		kind == .key ? (keys[eoa.lowercased()] == nil ? .absent : .present) : mnemonic.itemState(kind, eoa: eoa)
	}

	func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
		if mutationFails() { return false }
		let name = accountName(kind, eoa: eoa)
		if failWriteAccounts.contains(name) { return false }
		if dropWriteAccounts.contains(name) { return true }
		if kind == .key { return write(eoa: eoa, key: value) }
		return mnemonic.writeItem(kind, eoa: eoa, value: value)
	}

	func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? {
		if kind == .mnemonic, let bytes = scriptedBytes[eoa.lowercased()] { return bytes }
		return kind == .key ? read(eoa: eoa) : mnemonic.readItem(kind, eoa: eoa)
	}

	func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
		if mutationFails() { return false }
		if kind == .key { delete(eoa: eoa); return keys[eoa.lowercased()] == nil }
		return mnemonic.deleteItem(kind, eoa: eoa)
	}

	func intentOwners() -> [String]? { mnemonic.intentOwners() }

	func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? { mnemonic.mnemonicRecordCreations() }

	func write(eoa: String, key: Data) -> Bool {
		keys[eoa.lowercased()] = key
		return true
	}

	func read(eoa: String) -> Data? { keys[eoa.lowercased()] }

	/// Test seam (E9.10.3 WK-29a, G1-NK-S1): the key record (REC = walletKey:<eoa>) of these owners cannot be read (aead_failed in the vectors).
	var failKeyReadOwners: Set<String> = []

	func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState {
		if failKeyReadOwners.contains(eoa.lowercased()) { return .unreadable }
		return keys[eoa.lowercased()] == nil ? .absent : .present
	}

	func delete(eoa: String) { keys[eoa.lowercased()] = nil }

	func migrationMarkerExists(eoa: String) -> Bool { false }

	func setMigrationMarker(eoa: String) -> Bool { true }

	/// A key is present when a record is written, for any account.
	func hasAnyKeyRecord() -> Bool { !keys.isEmpty }

	/// The owners of the keys held, from the records only (no key is read).
	func enumerateKeyOwners() -> [String]? { keys.keys.map { $0 } }

	/// Each key held, checked as the product store checks one: the key must derive the account it is stored under.
	func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? {
		keys.map { (pair) -> BeamioChatKeyEntryCheck in
			let (eoa, key) = pair
			guard let address = BeamioNativeEthSigner.address(privateKey: [UInt8](key)), address.lowercased() == eoa else { return .corrupt }
			return .valid(eoa: eoa)
		}
	}
}

// MARK: - Raw payloads (25.52Y.163 r2.5.19 第 59(3)(e))

extension MemoryNativeKeyStore: BeamioChatRawItemStoring {
	func rawAccountNames() -> [String]? { rawNamesUnavailable ? nil : Array(rawAccounts.keys) }

	/// This double keeps a copy of a mnemonic as its phrase bytes (what `rawRead` gives for a live mnemonic item), so the copy is judged as a phrase.
	func judgeMnemonicPayload(_ bytes: Data, owner: String) -> (state: BeamioMnemonicAccountState, phrase: Data?) {
		// Test seam: a payload of this text is a copy that cannot be read (the product store reports a failed unwrap the same way).
		if bytes == Data("unreadable-copy".utf8) { return (.unreadable, nil) }
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: bytes, as: UTF8.self)) else { return (.invalid, nil) }
		defer { BeamioNativeEthSigner.wipe(&key) }
		guard BeamioNativeEthSigner.address(privateKey: key)?.lowercased() == owner.lowercased() else { return (.invalid, nil) }
		return (.valid, bytes)
	}

	func accountName(_ kind: BeamioChatWalletItemKind, eoa: String) -> String {
		let owner = eoa.lowercased()
		switch kind {
		case .key: return "walletKey:" + owner
		case .mnemonic: return "mnemonic:" + owner
		case .intent: return "intent:" + owner
		case .commit: return "commit:" + owner
		}
	}

	/// The kind and owner of a wallet item account. nil for any other account name.
	private func walletItem(of account: String) -> (kind: BeamioChatWalletItemKind, owner: String)? {
		let prefixes: [(String, BeamioChatWalletItemKind)] = [("walletKey:", .key), ("mnemonic:", .mnemonic), ("intent:", .intent), ("commit:", .commit)]
		for (prefix, kind) in prefixes where account.hasPrefix(prefix) {
			return (kind, String(account.dropFirst(prefix.count)))
		}
		return nil
	}

	func rawRead(account: String) -> BeamioChatRawItem {
		// Test seam (E9.10.3 G1-NK-S1, MARK read failure): a raw account in this set cannot be read.
		if failRawReadAccounts.contains(account) { return .unreadable }
		guard let item = walletItem(of: account) else {
			return rawAccounts[account].map { .present($0) } ?? .absent
		}
		switch itemState(item.kind, eoa: item.owner) {
		case .absent: return .absent
		case .unreadable: return .unreadable
		case .present: return readItem(item.kind, eoa: item.owner).map { .present($0) } ?? .unreadable
		}
	}

	func rawWrite(account: String, bytes: Data) -> Bool {
		if mutationFails() { return false }
		if failWriteAccounts.contains(account) { return false }
		if dropWriteAccounts.contains(account) { return true }
		if let text = failRawWriteContaining, String(data: bytes, encoding: .utf8)?.contains(text) == true { return false }
		var stored = bytes
		if !stored.isEmpty, corruptWritePrefixes.contains(where: { account.hasPrefix($0) }) {
			stored[stored.startIndex] ^= 0xff
		}
		guard let item = walletItem(of: account) else {
			rawAccounts[account] = stored
			return true
		}
		return item.kind == .key ? write(eoa: item.owner, key: stored) : mnemonic.writeItem(item.kind, eoa: item.owner, value: stored)
	}

	func rawDelete(account: String) -> Bool {
		if mutationFails() { return false }
		guard let item = walletItem(of: account) else {
			rawAccounts[account] = nil
			return true
		}
		if item.kind == .key {
			delete(eoa: item.owner)
			return keys[item.owner] == nil
		}
		return mnemonic.deleteItem(item.kind, eoa: item.owner)
	}
}
