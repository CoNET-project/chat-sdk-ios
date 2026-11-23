import Foundation

/// The production wiring of the account cleanup's deletion set (v198 section 218, v199 219, v200 220, v201 221, v210 230; passcode items are in `productionPasscodeItems`).
/// Every item of an old account is found by recomputing its exact name or file from the old address; nothing is deleted by pattern. A read that fails is unknown: the
/// listing answers nil and the cleanup reports clear_incomplete, deleting nothing more. Nothing here is reachable while `accountCleanupOld` is not registered.
///
/// Item kinds (the `name` of an `Item`): `wallet|<raw account>` (a chat-wallet Keychain item of the old address), `pgp` (the old account's PGP record), `page` (its page copy
/// file and key), `chat` (its local chat library file). The device-level files `owner_v1.txt`, `inbox_v1.json` and `call_signals_v1.json` are NOT deleted:
/// they are neither listed, counted nor deleted. Whole-file
/// deletion by owner match is suspended until the owner write and the generation advance are serialized and it is explicitly enabled.
enum BeamioAccountCleanupProduction {
	/// The owner of the items that are kept on purpose (not any account's): the cleanup counts them as keptUnattributed and deletes none.
	static let deviceLevelOwner = "<device-level>"

	struct Stores {
		var walletRaw: BeamioChatRawItemStoring
		/// The raw account names of the chat-wallet service; nil when they cannot be listed.
		var walletNames: () -> [String]?
		var pageCopies: BeamioShellRecord.EncryptedShellRecordStore
		var chat: BeamioConetChatLocalStore?
		/// Whether a library file exists: true or false when the file system answered, nil when it could not (a permission or I/O error): unknown, never "absent".
		var fileExists: (String) -> Bool? = { BeamioShellRecord.fileExistence(at: $0) }
		/// The account names of the PGP K records (`K.v1|<address>|<workspace>`) and of the page-copy keys (`<address>`); nil when they cannot be listed.
		var pgpKAccounts: () -> [String]? = { BeamioChatPgpKeychain.enumerateKAccounts() }
		var pageKeyAccounts: () -> [String]? = { BeamioResidueProbe.accounts(service: BeamioShellRecord.KeychainKeyStorage.service) }
		/// The addresses named by the Secure Enclave tags and the fallback items of H (identification only; the Secure Enclave key is kept); nil when they cannot be listed.
		var hardwareAccounts: () -> [String]? = { BeamioPasscodeKeychainHardware.standard.enumerateAccounts() }
		var pgpState: (String) -> BeamioChatPgpKeychain.RecordState
		var pgpClear: (String) -> Void
		var ownerRead: () -> BeamioInboxOwner.Owner
		var ownerRemove: () -> Bool
		var inboxFileExists: () -> Bool?
		var inboxClear: () -> Bool
		var signalsFileExists: () -> Bool?
		var signalsClear: () -> Bool

		static var standard: Stores {
			Stores(
				walletRaw: BeamioChatWalletKeychainStore.standard,
				walletNames: { BeamioResidueProbe.accounts(service: BeamioResidueProbe.walletService) },
				pageCopies: BeamioShellRecord.EncryptedShellRecordStore.production,
				chat: BeamioConetChatLocalStore.defaultRootDirectory().map { BeamioConetChatLocalStore(rootDirectory: $0) },
				pgpState: { BeamioChatPgpKeychain.recordState(eoa: $0) },
				pgpClear: { BeamioChatPgpKeychain.clear(eoa: $0) },
				ownerRead: { BeamioInboxOwner.read() },
				ownerRemove: { BeamioInboxOwner.remove() },
				inboxFileExists: { BeamioInboxFile.folder.map { FileManager.default.fileExists(atPath: $0.appendingPathComponent("inbox_v1.json").path) } },
				inboxClear: { BeamioConetChatInboxStore.clear() },
				signalsFileExists: { BeamioInboxFile.folder.map { FileManager.default.fileExists(atPath: $0.appendingPathComponent("call_signals_v1.json").path) } },
				signalsClear: { BeamioConetChatCallLedger.clear() }
			)
		}
	}

	/// The items of the old account that exist now; nil when any of them cannot be listed (the cleanup then stops with clear_incomplete).
	static func items(of rawOld: String, stores: Stores) -> [BeamioAccountCleanup.Item]? {
		let old = rawOld.lowercased()
		var out: [BeamioAccountCleanup.Item] = []
		// the chat-wallet Keychain items: exact names rebuilt in full from the address
		guard let names = stores.walletNames() else { return nil }
		for name in BeamioAccountCleanup.attributableWalletItemNames(oldEoa: old, listed: names) {
			// A mnemonic residue that is readable but cannot be verified (the checksum fails, it derives no key, or it does not derive this account) does not prove its account: the name and the
			// envelope's eoa field are not an exact attribution (v230 section 250, requirement). It is kept, counted in keptUnattributed, and is not pending; the account's other
			// exactly attributable items go as usual. One that cannot be read is unknown (retry), never a verdict.
			if name == "mnemonic:" + old {
				switch stores.walletRaw.mnemonicAccountState(owner: old) {
				case .valid, .absent: break
				case .invalid:
					out.append(.init(owner: Self.deviceLevelOwner, name: "unverifiable-mnemonic|" + old))
					continue
				case .unreadable: return nil
				}
			}
			out.append(.init(owner: old, name: "wallet|" + name))
		}
		switch stores.pgpState(old) {
		case .absent: break
		// chat-pgp is a published format: never cleared (reconcile); kept and counted
		case .present: out.append(.init(owner: Self.deviceLevelOwner, name: "kept-pgp|" + old))
		case .unreadable: return nil
		}
		guard let pageExists = stores.pageCopies.pageCopyExists(account: old) else { return nil }
		if pageExists { out.append(.init(owner: old, name: "page")) }
		if let chat = stores.chat {
			let path = chat.databasePath(for: old)
			// the library is listed when its main file or any side file remains (a side file can outlive the main one); a probe that failed is unknown: the cleanup stops with
			// clear_incomplete, it never reads a failed probe as "no library"
			var remains = false
			for suffix in ["", "-wal", "-shm", "-journal"] {
				guard let present = stores.fileExists(path + suffix) else { return nil }
				if present { remains = true }
			}
			if remains {
				// a library with unsent messages is kept in this version and counted (requirement, item 3): it is not pending and blocks nothing. A probe that fails is unknown.
				let unsent: Int
				do { unsent = try chat.unsentMessageCount(accountKey: old) } catch { return nil }
				// The chat library (chat-local-v1-<tag>.sqlite) is an unpublished format (added after the published SDK a4be9d17).
				// The file of the old account is listed by its exact name rebuilt from the address; one with unsent messages is kept and counted, and the active and the new account's
				// libraries are never the old account's (the run walks old accounts only).
				if unsent > 0 { out.append(.init(owner: Self.deviceLevelOwner, name: "chat-unsent|" + old)) } else { out.append(.init(owner: old, name: "chat")) }
			}
		}
		// owner_v1.txt, inbox_v1.json and call_signals_v1.json are NOT in the deletion set: between the wipe and the owner write of a switch,
		// rows of the new generation can already sit in the files while the owner is still the old account, so a whole-file delete could take them. Since the project lead decision of
		// 2026-11-21 (S-13 and resume, item 4) they are not counted in keptUnattributed either: all three ends leave them alone and silent.
		return out
	}

	/// Deletes one item and says whether it is gone afterwards (read back).
	static func delete(_ item: BeamioAccountCleanup.Item, stores: Stores) -> Bool {
		let old = item.owner.lowercased()
		if item.name.hasPrefix("wallet|") {
			let account = String(item.name.dropFirst("wallet|".count))
			// the published walletKey is never deleted, whatever listed it: a defense in depth that only removes a deletion path
			guard !account.hasPrefix("walletKey:") else { return false }
			guard stores.walletRaw.rawDelete(account: account) else { return false }
			if case .absent = stores.walletRaw.rawRead(account: account) { return true }
			return false
		}
		switch item.name {
		case "pgp":
			// never deleted here (reconcile): chat-pgp is a published format
			return false
		case "chat":
			guard let chat = stores.chat else { return false }
			do { try chat.deleteLocalData(accountKey: old, force: false) } catch { return false }
			// gone means the file system said "no such file"; a probe that fails is not gone
			let path = chat.databasePath(for: old)
			return ["", "-wal", "-shm", "-journal"].allSatisfy { stores.fileExists(path + $0) == false }
		case "page":
			return stores.pageCopies.deletePageCopy(account: old)
		case "owner", "inbox", "signals":
			// never deleted: the three device-level files are kept until the owner write and the generation are serialized and it is explicitly enabled
			return false
		default:
			return false
		}
	}

	/// The cleanup environment of the product over `stores`: the gate (G2 and not locked), the read-back sources, the listing of the accounts the device holds (a union
	/// of the mnemonic, key and passcode owners; nil when any of them cannot be listed), the items and the deletion of this file, and the passcode items.
	static func environment(stores: Stores = .standard, passcode: BeamioAccountCleanup.PasscodeItems = BeamioAccountCleanup.productionPasscodeItems()) -> BeamioAccountCleanup.Environment {
		let keyStore = BeamioNativeWallet.keyStore
		// One reading of the pointer and the address derived from that same value, so that an account switch between two reads cannot split them. The derived address is nil when the
		// pointer is empty, the key record of that account is not readable as present, or the key cannot be read.
		func snapshot() -> (pointer: String, derived: String?) {
			let pointer = BeamioNativeAccountPointer.get()
			guard !pointer.isEmpty, keyStore.keyRecordState(eoa: pointer) == .present,
			      case .success(let address) = BeamioNativeWallet.withAccountKeyUnchecked(eoa: pointer, { BeamioNativeEthSigner.address(privateKey: $0) }) else { return (pointer, nil) }
			return (pointer, address)
		}
		return BeamioAccountCleanup.Environment(
			gatePassed: {
				guard BeamioConetChatModule.nativeGate() == .g2, BeamioConetChatModule.recordAccount() != nil else { return false }
				return true
			},
			activeSnapshot: { snapshot() },
			mnemonicState: { keyStore.mnemonicAccountState(owner: $0) },
			keyRecordState: { keyStore.keyRecordState(eoa: $0) },
			accounts: { discoveredAccounts(stores: stores, keyStore: keyStore) },
			itemsOfOldAccount: { items(of: $0, stores: stores) },
			delete: { delete($0, stores: stores) },
			passcode: passcode,
			unattributedKept: { keptResidue(stores: stores, keyStore: keyStore, activeAccount: $0) }
		)
	}

	/// The prefixes of the account-keyed names in the chat-wallet service; the address follows exactly (the same set as `attributableWalletItemNames`).
	private static let walletAccountPrefixes = ["walletKey:", "mnemonic:", "intent:", "commit:", "phase:", "migrated:", "recoveryBackupConfirmed:", "blobKey:", "wallet.restore.unconfirmed."]

	private static func isExactAddress(_ s: String) -> Bool {
		s.count == 42 && s.hasPrefix("0x") && s.dropFirst(2).allSatisfy { $0.isHexDigit && !$0.isUppercase }
	}

	/// Every account the device holds an item for, found by a name that carries the address: the mnemonic, key and passcode owners, the PGP K records, the page-copy keys, the account-keyed
	/// items of the wallet service (walletKey, mnemonic, intent, commit, phase, migrated, recovery-backup flag, credential K, unconfirmed restore) and the Secure Enclave tags and H fallback
	/// items. A name of one of those stores that is not exactly an address (lower-case 0x and 40 hex digits) names no account: it is kept and counted as residue (v4 EA-03, EA-14).
	/// nil when any listing fails.
	static func scanAccountNames(stores: Stores, keyStore: BeamioChatWalletKeyStoring) -> (accounts: [String], residue: [String])? {
		guard let mnemonics = keyStore.enumerateMnemonicCreations(), let keys = keyStore.enumerateKeyOwners() else { return nil }
		var all = Set(mnemonics.map { $0.owner.lowercased() })
		all.formUnion(keys.map { $0.lowercased() })
		guard let records = BeamioPasscodeKeychainRecords.standard.enumerateRecordOwners() else { return nil }
		all.formUnion(records.map { $0.lowercased() })
		guard let pgp = stores.pgpKAccounts(), let pages = stores.pageKeyAccounts(), let walletNames = stores.walletNames(), let hardware = stores.hardwareAccounts() else { return nil }
		var residue: [String] = []
		for name in pgp where name.hasPrefix("K.v1|") {
			let parts = name.split(separator: "|", omittingEmptySubsequences: false)
			if parts.count >= 2, isExactAddress(String(parts[1])) { all.insert(String(parts[1])) } else { residue.append("pgp|" + name) }
		}
		for name in walletNames {
			for prefix in walletAccountPrefixes where name.hasPrefix(prefix) {
				let tail = String(name.dropFirst(prefix.count))
				if isExactAddress(tail) { all.insert(tail) } else { residue.append("wallet|" + name) }
				break
			}
		}
		for a in hardware { if isExactAddress(a) { all.insert(a) } else { residue.append("hardware|" + a) } }
		for name in pages {
			let head = String(name.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false).first ?? "")
			if isExactAddress(head) { all.insert(head) } else { residue.append("page|" + name) }
		}
		return (all.sorted(), residue.sorted())
	}

	static func discoveredAccounts(stores: Stores, keyStore: BeamioChatWalletKeyStoring) -> [String]? {
		scanAccountNames(stores: stores, keyStore: keyStore)?.accounts
	}

	/// What the cleanup keeps and cannot attribute to one account: the chat libraries of `orphanLibraries`, the account-keyed names of the stores that are not exactly an address (`scanAccountNames`) and the isolated copies of an overwrite in the wallet service (`wallet.iso.`: their
	/// tag cannot be recomputed from an address, so a copy cannot be proved one account's alone). Each is counted once in keptUnattributed. The device-level items (the overwrite marker, the audits)
	/// are not counted. nil when a listing fails.
	static func keptResidue(stores: Stores, keyStore: BeamioChatWalletKeyStoring, activeAccount: String) -> [String]? {
		guard let libraries = orphanLibraries(stores: stores, keyStore: keyStore, activeAccount: activeAccount), let walletNames = stores.walletNames(), let scan = scanAccountNames(stores: stores, keyStore: keyStore) else { return nil }
		return libraries + scan.residue + walletNames.filter { $0.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) }.sorted().map { "isolated|" + $0 }
	}

	/// The chat libraries whose file-name tag matches no account the device knows (the new one included): their account cannot be told from the name, so they are kept and counted.
	static func orphanLibraries(stores: Stores, keyStore: BeamioChatWalletKeyStoring, activeAccount: String) -> [String]? {
		guard let chat = stores.chat else { return [] }
		guard let tags = chat.libraryTagsOnDisk(), var known = discoveredAccounts(stores: stores, keyStore: keyStore) else { return nil }
		if !activeAccount.isEmpty { known.append(activeAccount.lowercased()) }   // the verified active account, from the caller: the pointer is not read again here
		let knownTags = Set(known.map { chat.libraryTag(for: $0) })
		return tags.filter { !knownTags.contains($0) }.map { "chatfile|" + $0 }
	}
}
