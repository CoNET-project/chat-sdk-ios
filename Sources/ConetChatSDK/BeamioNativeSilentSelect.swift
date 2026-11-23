import Foundation

/// Y.163 (r8): the silent selection of `init` (several accounts and no usable pointer) and the native guard of `makeAccount`.
///
/// Every account is a valid mnemonic (第 31、32 項): private-key records are not accounts and are never ranked, counted or refused on. The
/// decisions are pure: the caller reads the inventory (`BeamioNativeMnemonicInventory`) and the pointer, so the rules are tested without the
/// Keychain. The vectors are account-select-vectors.v2.json. There is no account picker: the first account by creation time is chosen, and
/// only when it judges valid. Any other state is `unreadable` (not_ready), and nothing is written, deleted or created.
enum BeamioNativeSilentSelect {
	enum Decision: Equatable {
		/// No mnemonic account and no usable pointer: nothing is chosen here, and `init` goes on as it always did.
		case none
		/// One valid account and no usable pointer: the single-account rule of 25.52Y.159 (G1). Nothing is written.
		case single(String)
		/// The pointer names a valid account: the pointer is used as it is (Y.163 第 9 項). Nothing is written.
		case pointerKept(String)
		/// Several accounts and no usable pointer: the first by (creation time, lower-case address) is chosen. The pointer must still be written and read back.
		case selected(String)
		/// Not decidable: not_ready with notReadyReason unreadable. Nothing is written.
		case unreadable
	}

	/// The decision from the inventory. `pointerReadOk` is false when the pointer cannot be read back. `probeFailed` is true when the residue probe
	/// failed (Y.163 第 20g(d); SS-33). A read that failed, and an unreadable pointer target, are unreadable.
	///
	/// Ranking (第 5 至 7 項, 第 20b 項): every readable mnemonic account is ranked, valid or not, by its creation time and then by its lower-case
	/// address. The first ranked account must judge valid; if it does not, the whole choice is unreadable and no later account is tried (SS-11, SS-12).
	/// A single account must be valid (SS-05, SS-06). Several accounts need every creation time (SS-13).
	static func decide(inventory: BeamioNativeMnemonicInventory, pointer: String, pointerReadOk: Bool, probeFailed: Bool, current: String? = nil) -> Decision {
		guard pointerReadOk, !probeFailed, !inventory.readFailed else { return .unreadable }
		let named = pointer.lowercased()
		// 第 34(3) 項: a pointer that names a valid account is kept; one that names an invalid or unreadable account is unreadable (SS-19, PT-03).
		// A pointer that names no mnemonic account (absent, or a private-key record only) is no usable pointer: the choice below decides (PK-04, PT-01).
		if !named.isEmpty, let target = inventory.accounts.first(where: { $0.eoa == named }) {
			return target.state == .valid ? .pointerKept(named) : .unreadable
		}
		let all = inventory.accounts
		guard !all.isEmpty else { return .none }
		// method Y: with no usable pointer the device's current record decides, whatever the other accounts' creation times are: the first-entry rule below
		// does not apply while a current record names an account of the inventory. A current that is not valid is unreadable; nothing else is selected.
		if let followed = current?.lowercased(), !followed.isEmpty, let target = all.first(where: { $0.eoa == followed }) {
			return target.state == .valid ? .selected(followed) : .unreadable
		}
		if all.count == 1 {
			return all[0].state == .valid ? .single(all[0].eoa) : .unreadable
		}
		// 第 7 項: every account needs its creation time; nothing is ranked on an address or on the enumeration order.
		guard all.allSatisfy({ $0.created != nil }) else { return .unreadable }
		let ranked = all.sorted { a, b in
			let x = a.created ?? 0, y = b.created ?? 0
			return x != y ? x < y : a.eoa < b.eoa
		}
		guard let first = ranked.first, first.state == .valid else { return .unreadable }
		return .selected(first.eoa)
	}

	/// The live decision for `init`: reads the inventory, the pointer and the residue probe, decides, and for a selection writes the pointer and
	/// reads it back (Y.163 第 8 項). A failed or mismatched write is unreadable; the pointer is then not known to be set, and the next `init`
	/// decides again from the same accounts.
	static func run(store: BeamioChatWalletKeyStoring,
	                writePointer: (String) -> BeamioNativeAccountPointer.WriteCheck = { BeamioNativeAccountPointer.writeChecked($0) }) -> Decision {
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		var followed: String?
		if let raw = store as? BeamioChatRawItemStoring {
			switch BeamioMnemonicSets.current(store: raw) {
			case .ok(let eoa, _), .cipher(let eoa, _): followed = eoa
			default: break
			}
		}
		let decision = decide(inventory: inventory, pointer: BeamioNativeAccountPointer.get(), pointerReadOk: true,
		                      probeFailed: BeamioResidueProbe.probe() == .failed, current: followed)
		guard case .selected(let eoa) = decision else { return decision }
		switch writePointer(eoa) {
		case .written: return .selected(eoa)
		case .mismatch, .unreadable: return .unreadable
		}
	}

	/// The outcome of the makeAccount guard (r7 第 12、27、29 項). A creation is the page's explicit command (`userExplicit`) and only appends:
	/// accounts already held do not refuse it. An unreadable listing or account is `unreadable`; an unlocked session (G2), or an address that
	/// collides with a valid account, is `alreadyExists`, and nothing is overwritten.
	enum CreateGuard: Equatable {
		case mayCreate
		case alreadyExists
		case unreadable
		case badRequest
	}

	/// The collision of a new address with the accounts (Y.163 第 12 項 (b)(4), 第 35(6) 項): a valid account of that address is already_exists;
	/// any other mnemonic item of that address is kept, never overwritten, so the creation is not_ready (the item is named by its address).
	enum Collision: Equatable {
		case free
		case alreadyExists
		case keptNotOverwritten
	}

	static func collision(eoa: String, inventory: BeamioNativeMnemonicInventory) -> Collision {
		let owner = eoa.lowercased()
		if inventory.valid.contains(where: { $0.eoa == owner }) { return .alreadyExists }
		if inventory.accounts.contains(where: { $0.eoa == owner }) { return .keptNotOverwritten }
		return .free
	}

	/// `g1WithoutKeys`: the session is G1 and no account is held (r6 第 12 項): not_ready, unreadable.
	static func createGuard(userExplicit: Bool, enumerated: Bool, sessionIsG2: Bool, g1WithoutKeys: Bool = false,
	                        residue: Bool, probeFailed: Bool) -> CreateGuard {
		guard userExplicit else { return .badRequest }
		guard enumerated else { return .unreadable }
		guard !sessionIsG2 else { return .alreadyExists }
		guard !g1WithoutKeys else { return .unreadable }
		guard !probeFailed, !residue else { return .unreadable }
		return .mayCreate
	}
}
