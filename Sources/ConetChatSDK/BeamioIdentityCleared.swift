import Foundation

/// The `identity_cleared` marker: a clear of the identity keeps every published and every stored account on
/// the device (nothing is deleted for it), so the clear writes this marker instead. It holds no secret: the public addresses of the accounts that were on the device
/// when the identity was cleared, the format version and the UTC time. While an address is in the marker, the account list, the snapshot's `.present` judgement
/// and the silent selection ignore that account: it is not adopted again and no pointer is written for it. The ignore of one account ends only when the user explicitly
/// restores, imports, creates or syncs that account again (`lift`). Nothing is deleted at any step.
///
/// The marker is one item (`identity.cleared`) of the chat-wallet service. A marker that cannot be read is unknown: the account list is then not enumerated (fail closed),
/// never "nothing ignored".
enum BeamioIdentityCleared {
	static let itemName = "identity.cleared"
	static let formatVersion = 1

	enum Reading: Equatable {
		case ok(Set<String>)
		case unreadable
	}

	/// The raw item store behind a key store: the passcode store's wallet layer, or a store that is itself raw. nil: the store cannot hold the marker.
	static func rawStore(of store: BeamioChatWalletKeyStoring) -> BeamioChatRawItemStoring? {
		if let passcode = store as? BeamioPasscodeWalletStore { return passcode.rawLegacyStoreForShell }
		return store as? BeamioChatRawItemStoring
	}

	static func read(store: BeamioChatWalletKeyStoring) -> Reading {
		guard let raw = rawStore(of: store) else { return .ok([]) }
		switch raw.rawRead(account: itemName) {
		case .absent: return .ok([])
		case .unreadable: return .unreadable
		case .present(let bytes):
			guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], object["v"] as? Int == formatVersion,
			      let list = object["ignored"] as? [String]
			else { return .unreadable }
			return .ok(Set(list.map { $0.lowercased() }))
		}
	}

	/// True only when the marker item is present and valid. A marker that is absent, unreadable or malformed is false (never an exemption): the strict reading of the P3 gate.
	static func isSetStrict(store: BeamioChatWalletKeyStoring) -> Bool {
		guard let raw = rawStore(of: store), case .present(let bytes) = raw.rawRead(account: itemName),
		      let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], object["v"] as? Int == formatVersion,
		      object["ignored"] is [String]
		else { return false }
		return true
	}

	/// The P3 exemption: the device holds nothing but the published key-only copies that the completed clear left behind, so a clearIdentity at G0 may go on to the
	/// gate (no_key) instead of being refused as key-only. All of these must hold; any read that fails is "not exempt":
	/// - the marker is present and valid (`isSetStrict`) and lists its ignored accounts;
	/// - the store can list its key records, mnemonic items and intent items, and there are no mnemonic accounts and no intent items (no account wallet, locked or not);
	/// - every key record is still an ignored account of the marker (the clear's published copy; an account that was restored, imported, created or synced was lifted from the
	/// marker, and the marker item itself stays present afterwards, so "set" alone proves nothing), is readable, and has no commit item.
	static func p3ExemptionHolds(store: BeamioChatWalletKeyStoring) -> Bool {
		guard isSetStrict(store: store), case .ok(let ignored) = read(store: store),
		      let items = store as? BeamioChatMnemonicKeyStoring,
		      let owners = store.enumerateKeyOwners(),
		      let mnemonics = items.mnemonicRecordCreations(), mnemonics.isEmpty,
		      let intents = items.intentOwners(), intents.isEmpty
		else { return false }
		for owner in owners {
			let eoa = owner.lowercased()
			guard ignored.contains(eoa), store.keyRecordState(eoa: eoa) == .present, items.itemState(.commit, eoa: eoa) == .absent else { return false }
		}
		return true
	}

	private static func write(_ accounts: Set<String>, raw: BeamioChatRawItemStoring) -> Bool {
		let record: [String: Any] = ["v": formatVersion, "ignored": accounts.sorted(), "utc": BeamioNativeKeyImport.utcSeconds(Date())]
		guard let bytes = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]) else { return false }
		guard raw.rawWrite(account: itemName, bytes: bytes), case .present(let back) = raw.rawRead(account: itemName), back == bytes else { return false }
		return true
	}

	/// The identity was cleared: the accounts in `accounts` (the ones on the device, plus the owners of the clear) are ignored from now on. Added to what is already
	/// marked, written and read back. True when the marker reads back as written. A store that cannot hold the marker answers true (nothing can be ignored there).
	static func record(accounts: Set<String>, store: BeamioChatWalletKeyStoring) -> Bool {
		guard let raw = rawStore(of: store) else { return true }
		guard case .ok(let existing) = read(store: store) else { return false }
		return write(existing.union(accounts.map { $0.lowercased() }), raw: raw)
	}

	/// The user explicitly restored, imported, created or synced `eoa`: the ignore of that account ends. Best effort: a marker that cannot be read or written leaves the
	/// account ignored (never adopted by mistake). True when `eoa` is not ignored afterwards.
	@discardableResult
	static func lift(_ eoa: String, store: BeamioChatWalletKeyStoring) -> Bool {
		guard let raw = rawStore(of: store) else { return true }
		guard case .ok(let existing) = read(store: store) else { return false }
		let owner = eoa.lowercased()
		guard existing.contains(owner) else { return true }
		return write(existing.subtracting([owner]), raw: raw)
	}

	/// Every account the device holds, whatever its state (the mnemonic and set owners and the key owners), for the marker of a clear.
	static func accountsOnDevice(store: BeamioChatWalletKeyStoring, owners: [String]) -> Set<String> {
		var all = Set(owners.map { $0.lowercased() }.filter { !$0.isEmpty })
		all.formUnion(BeamioNativeMnemonicInventory.readUnfiltered(store: store).accounts.map(\.eoa))
		for owner in store.enumerateKeyOwners() ?? [] { all.insert(owner.lowercased()) }
		return all
	}
}
