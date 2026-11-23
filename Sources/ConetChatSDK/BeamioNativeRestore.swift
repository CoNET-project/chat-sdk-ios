import Foundation

/// The explicit restore of an account from its recovery phrase (25.52Y.163 r2.5.19, 第 28、29 项). Two internal operations of the native recovery
/// paths. They are not bridge commands: table-T has no restore names, and the page never calls them directly.
///
/// `restoreWrite` appends the restored account as a new entry. It never deletes, overwrites or rewrites an entry, and it never changes the
/// account pointer (第 28(c), 第 28(d)1–2). `restoreConfirm` points the account at the restored EOA after the user has confirmed it, with a checked
/// write and a read-back (第 28(d)3–4). Both need the user's explicit mark (第 29(c)).
///
/// 第 28(d)2 (project ruling): when the read-back of a written entry fails, the entry is kept, not rolled back, and it is marked unconfirmed. An
/// unconfirmed entry is never judged valid (see `BeamioNativeMnemonicInventory`), so the start-up never selects it silently. The mark is cleared only
/// by a verified read-back: by `restoreConfirm` with the user's mark, or by a retry of the restore that finds the entry verified.
enum BeamioNativeRestore {
	enum Answer: Equatable {
		/// The restored account is written (restoreWrite), or the pointer names it (restoreConfirm).
		case ok(eoa: String)
		/// The name is already held, or the session is unlocked. Nothing is written (第 28(c), 第 28(e)).
		case alreadyExists(eoa: String?)
		/// The state cannot be judged, or a read-back failed: `not_ready` with reason `unreadable` (第 28(a), 第 28(d)2, 第 28(d)4).
		case notReady
		/// The restore material is not valid, or the write failed (第 28(b)).
		case importFailed
		/// No user-explicit mark (第 29(c)).
		case badRequest
	}

	/// The raw account of the unconfirmed mark of one restored entry.
	static func unconfirmedAccount(_ eoa: String) -> String {
		"wallet.restore.unconfirmed." + eoa.lowercased()
	}

	/// True when the entry carries the unconfirmed mark. A mark that cannot be read counts as marked (fail closed).
	static func isUnconfirmed(eoa: String, store: BeamioChatRawItemStoring) -> Bool {
		if case .absent = store.rawRead(account: unconfirmedAccount(eoa)) { return false }
		return true
	}

	/// Writes the unconfirmed mark and reads it back: true only when the mark holds the bytes just written (第 28(d)2, 残留裁定). It holds the account,
	/// the UTC time and the reason, and no key or phrase material.
	static func markUnconfirmedVerified(eoa: String, utc: String, store: BeamioChatRawItemStoring) -> Bool {
		let object: [String: Any] = ["v": 1, "eoa": eoa.lowercased(), "utc": utc, "reason": "readback_failed"]
		guard let bytes = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return false }
		guard store.rawWrite(account: unconfirmedAccount(eoa), bytes: bytes) else { return false }
		return store.rawRead(account: unconfirmedAccount(eoa)) == .present(bytes)
	}

	/// Removes the unconfirmed mark. True when no mark remains.
	static func clearUnconfirmed(eoa: String, store: BeamioChatRawItemStoring) -> Bool {
		store.rawDelete(account: unconfirmedAccount(eoa))
	}

	/// The read-back of an entry: complete and consistent, with the key, the mnemonic and the commit (BeamioPwaPhraseOverwrite.readBack).
	static func verified(eoa: String, store: BeamioChatRawItemStoring) -> Bool {
		BeamioPwaPhraseOverwrite.readBack(eoa: eoa, store: store) != nil
	}

	/// 第 28 項 (a) to (c), (e), 第 28(d)2 (project ruling): the explicit restore writes one entry. The mnemonic is the restored object (第 28 項, 1423).
	/// The pointer is not touched. An unconfirmed entry of the same account is verified first: a verified entry is confirmed by this retry, and
	/// nothing else is written.
	static func restoreWrite(phrase: String, userExplicit: Bool, sessionIsG2: Bool, store: BeamioChatRawItemStoring) -> Answer {
		// 第 29(c): without the explicit mark nothing is read for a write and nothing is written.
		guard userExplicit else { return .badRequest }
		if let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase), isUnconfirmed(eoa: derived.eoa, store: store) {
			guard verified(eoa: derived.eoa, store: store), clearUnconfirmed(eoa: derived.eoa, store: store) else { return .notReady }
			return .alreadyExists(eoa: derived.eoa)
		}
		// 第 28(a): an unreadable enumeration or mnemonic is not_ready, and nothing is written.
		if BeamioNativeMnemonicInventory.read(store: store).readFailed { return .notReady }
		// 第 28(e): a session that is already unlocked answers already_exists and writes nothing.
		if sessionIsG2 { return .alreadyExists(eoa: nil) }
		// 第 28(b): material that is not a valid mnemonic is import_failed.
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let eoa = BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
		else { return .importFailed }
		var words = Array(BeamioPwaWalletSync.normalized(phrase))
		defer { BeamioNativeWallet.wipe(&words) }
		// 第 28(c), 第 28(d)1–2: the shared import tail appends the entry (an existing entry of the same name is already_exists, with its eoa) and
		// reads it back. A failed read-back keeps the entry (no rollback), and the entry is marked unconfirmed below.
		switch BeamioNativeKeyImport.storeDerivedKey(&key, expectedEoa: eoa, store: store, mnemonic: words, setPointer: false,
		                                             keepOnReadBackFailure: true) {
		case .imported: return .ok(eoa: eoa)
		case .alreadyPresent: return .alreadyExists(eoa: eoa)
		case .invalidFormat, .invalidMnemonic, .invalidKey, .addressMismatch, .writeFailed: return .importFailed
		case .readBackFailed, .rollbackPending:
			// 第 28(d)2 (project ruling, 残留裁定): the entry is kept. storeDerivedKey writes the mark before it removes the intent, and a failed mark keeps
			// the intent for the next start. Nothing is rolled back. The answer is not_ready (unreadable), and the pointer is unchanged.
			return .notReady
		case .unavailable, .cancelled: return .notReady
		}
	}

	/// 第 28 項 (d)3–4: after the user confirms the restored public address, the pointer is set to it with a checked write and a read-back.
	/// An unconfirmed entry is confirmed only after its read-back verifies, and its mark is cleared then (project ruling). The pointer is unchanged when
	/// the write or the read-back fails.
	static func restoreConfirm(eoa rawEoa: String, userExplicit: Bool, store: BeamioChatRawItemStoring) -> Answer {
		// 第 29(c): an unconfirmed restoreConfirm answers bad_request and writes nothing.
		guard userExplicit else { return .badRequest }
		let eoa = rawEoa.lowercased()
		// the user explicitly confirmed this restored account: its `identity_cleared` ignore ends first (the list must show it to be judged); a failed confirm puts the ignore back
		let wasIgnored: Bool = { if case .ok(let ignored) = BeamioIdentityCleared.read(store: store) { return ignored.contains(eoa) }; return false }()
		BeamioIdentityCleared.lift(eoa, store: store)
		func answer(_ a: Answer) -> Answer {
			if wasIgnored, case .ok = a {} else if wasIgnored { _ = BeamioIdentityCleared.record(accounts: [eoa], store: store) }
			return a
		}
		if isUnconfirmed(eoa: eoa, store: store) {
			guard verified(eoa: eoa, store: store), clearUnconfirmed(eoa: eoa, store: store) else { return answer(.notReady) }
		}
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		if inventory.readFailed { return answer(.notReady) }
		guard inventory.state(of: eoa) == .valid else { return answer(.notReady) }
		switch BeamioNativeAccountPointer.writeChecked(eoa) {
		case .written: return answer(.ok(eoa: eoa))
		case .mismatch, .unreadable: return answer(.notReady)
		}
	}
}
