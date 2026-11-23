import Foundation
import CryptoKit

/// The accounts of this device, judged by their mnemonic items only (25.52Y.163 r8, 第 31、32、34 項; 1423). A private-key record, a legacy
/// record and an orphan key are not accounts: they are not listed here, not counted, and not read (第 32 項 裁定 A).
///
/// Every judgement that counted key records (the silent selection, the makeAccount guard, the snapshot, the pointer, the residue, the owners)
/// reads this value instead. The entries it gives (`entries`) use the record vocabulary of `BeamioNativeWalletStateResolver`, so that resolver
/// is unchanged: a valid mnemonic is `valid`, an invalid one is `corrupt`, an unreadable one is `unavailable`.
struct BeamioNativeMnemonicInventory: Equatable {
	struct Account: Equatable {
		let eoa: String
		/// Never `absent`: an owner is listed only when its mnemonic item exists.
		let state: BeamioMnemonicAccountState
		/// Whole UTC seconds of the mnemonic item's creation. nil when the time cannot be read.
		let created: Int?
	}

	/// false: the listing of the mnemonic items failed, or a row could not be named (fail closed).
	let enumerated: Bool
	/// One account per owner, in the order the store listed them.
	let accounts: [Account]

	static let notEnumerated = BeamioNativeMnemonicInventory(enumerated: false, accounts: [])

	/// The accounts whose mnemonic is valid (第 31 項 (1)).
	var valid: [Account] { accounts.filter { $0.state == .valid } }

	/// A read failed (the listing, or an item): the judgement is unknown, never "no account" (第 20g 項).
	var readFailed: Bool { !enumerated || accounts.contains { $0.state == .unreadable } }

	/// The snapshot is damaged: a read failed, or a mnemonic is readable but fails the check (第 20g(b) 项, 第 32 项).
	var damaged: Bool { readFailed || accounts.contains { $0.state == .invalid } }

	/// True when a valid account exists, or a mnemonic cannot be read or listed (fail closed).
	var holdsRecord: Bool { !enumerated || accounts.contains { $0.state == .valid || $0.state == .unreadable } }

	/// The number of valid accounts, or nil when the listing failed.
	var validCount: Int? { enumerated ? valid.count : nil }

	/// The state of one account: `valid`, `invalid` or `unreadable`; `absent` when no mnemonic item exists; `unreadable` when the listing failed.
	func state(of eoa: String) -> BeamioMnemonicAccountState {
		guard enumerated else { return .unreadable }
		let owner = eoa.lowercased()
		return accounts.first { $0.eoa == owner }?.state ?? .absent
	}

	/// The pointer as the judgement uses it (第 34(3) 項): the pointer when its account has a mnemonic item of any state, and "" otherwise
	/// (no pointer, an absent account, or a private-key record only). A pointer with no usable target chooses no account.
	func usablePointer(_ pointer: String) -> String {
		let owner = pointer.lowercased()
		guard !owner.isEmpty, state(of: owner) != .absent else { return "" }
		return owner
	}

	/// The record vocabulary of the resolver. nil when the listing failed (the resolver answers not_ready).
	var entries: [BeamioChatKeyEntryCheck]? {
		guard enumerated else { return nil }
		return accounts.map { account in
			switch account.state {
			case .valid: return .valid(eoa: account.eoa)
			case .invalid: return .corrupt
			case .unreadable, .absent: return .unavailable
			}
		}
	}

	/// Reads the mnemonic items of a store: the owners and their creation times from the attributes, then each owner's state. Nothing is written
	/// or deleted, and no key is returned. A store that cannot list its mnemonics is not enumerated.
	/// The one judgement of the current mnemonics (requirement, WK26 / E9.1-4): a valid mnemonic is `valid`; a mnemonic that reads invalid is
	/// `invalid` only when a second read of the same store also finds it invalid (confirmed: no credential, the data kept); an invalid reading that is not
	/// confirmed, or a read failure, is `unreadable` (unknown, retry). Nothing is written or deleted.
	static func read(store: BeamioChatWalletKeyStoring) -> BeamioNativeMnemonicInventory {
		let all = readUnfiltered(store: store)
		// the accounts that an identity clear marked `identity_cleared` are ignored (not adopted, not selected) until the user brings one back explicitly; an unreadable
		// marker is unknown, never "nothing ignored"
		switch BeamioIdentityCleared.read(store: store) {
		case .unreadable: return notEnumerated
		case .ok(let ignored):
			if ignored.isEmpty || !all.enumerated { return all }
			return BeamioNativeMnemonicInventory(enumerated: true, accounts: all.accounts.filter { !ignored.contains($0.eoa) })
		}
	}

	/// The accounts as the store lists them, whatever the `identity_cleared` marker says (for the marker itself and for the clear).
	static func readUnfiltered(store: BeamioChatWalletKeyStoring) -> BeamioNativeMnemonicInventory {
		let first = readOnce(store: store)
		guard first.enumerated, first.accounts.contains(where: { $0.state == .invalid }) else { return first }
		// The digest of each invalid reading is taken from the same read (in memory only; nothing is logged or stored).
		// A store that exposes no bytes (a state-only store) confirms on the two states alone.
		let bytesStore = store as? BeamioChatMnemonicKeyStoring
		let firstDigests = invalidDigests(first, store: store)
		let second = readOnce(store: store)
		let secondDigests = invalidDigests(second, store: store)
		let accounts = first.accounts.map { account -> Account in
			guard account.state == .invalid else { return account }
			let again = second.accounts.first { $0.eoa == account.eoa }?.state
			// Confirmed only when both reads find it invalid AND, on a byte store, the stored bytes are the same (requirement, E9.11.24 SS-32-u / SS-32-c).
			let sameBytes: Bool
			if bytesStore == nil {
				sameBytes = true
			} else {
				sameBytes = firstDigests[account.eoa] != nil && firstDigests[account.eoa] == secondDigests[account.eoa]
			}
			return again == .invalid && sameBytes ? account : Account(eoa: account.eoa, state: .unreadable, created: account.created)
		}
		return BeamioNativeMnemonicInventory(enumerated: second.enumerated, accounts: accounts)
	}

	/// The SHA-256 digest of the stored mnemonic bytes of each invalid account of a reading. A bytes read that fails gives no digest.
	private static func invalidDigests(_ inventory: BeamioNativeMnemonicInventory, store: BeamioChatWalletKeyStoring) -> [String: Data] {
		guard let items = store as? BeamioChatMnemonicKeyStoring else { return [:] }
		var out: [String: Data] = [:]
		for account in inventory.accounts where account.state == .invalid {
			guard var bytes = items.readItem(.mnemonic, eoa: account.eoa) else { continue }
			out[account.eoa] = Data(SHA256.hash(data: bytes))
			BeamioNativeWallet.wipe(&bytes)
		}
		return out
	}

	/// The credential entries for the walletStatus judgement: a confirmed invalid mnemonic is no credential, so it is not listed (as an absent one).
	var credentialEntries: [BeamioChatKeyEntryCheck]? {
		guard enumerated else { return nil }
		return accounts.compactMap { account -> BeamioChatKeyEntryCheck? in
			switch account.state {
			case .valid: return .valid(eoa: account.eoa)
			case .invalid: return nil
			case .unreadable, .absent: return .unavailable
			}
		}
	}

	private static func readOnce(store: BeamioChatWalletKeyStoring) -> BeamioNativeMnemonicInventory {
		guard let rows = store.enumerateMnemonicCreations() else { return notEnumerated }
		var order: [String] = []
		var times: [String: [Int?]] = [:]
		for row in rows {
			let owner = row.owner.lowercased()
			if times[owner] == nil { order.append(owner) }
			times[owner, default: []].append(row.created.map { Int(floor($0.timeIntervalSince1970)) })
		}
		let raw = store as? BeamioChatRawItemStoring
		let accounts = order.map { owner -> Account in
			let known = (times[owner] ?? []).compactMap { $0 }
			let allKnown = known.count == (times[owner] ?? []).count
			// 第 28(d)2 (project ruling): an unconfirmed restored entry is never judged valid. It stays unreadable until a verified read-back clears its mark,
			// so the start-up does not select it silently.
			let unconfirmed = raw.map { BeamioNativeRestore.isUnconfirmed(eoa: owner, store: $0) } ?? false
			let state = unconfirmed ? BeamioMnemonicAccountState.unreadable : store.mnemonicAccountState(owner: owner)
			return Account(eoa: owner, state: state, created: allKnown ? known.min() : nil)
		}
		return BeamioNativeMnemonicInventory(enumerated: true, accounts: accounts)
	}
}
