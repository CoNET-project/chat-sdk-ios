import CryptoKit
import Foundation

/// The no-passcode state of the mnemonic (the finalized section 1): the validated mnemonic that the PWA hands over through the trusted
/// bridge is kept per mnemonic, as one set, and a `current` pointer names the set in use.
///
/// - One set per mnemonic, named by the address the mnemonic derives (`mnemonic.set.<eoa>`). A set holds the version, the mode `keychain`, the address, the
/// normalized phrase and the UTC time. The mode is `keychain`: the item is a keychain item (`AfterFirstUnlockThisDeviceOnly`, not synced), under the base
/// isolation of the operating system and the app container. No Secure Enclave key, no device-protection key and no extra unlock step is used (
/// rule 1, item 4).
/// - `mnemonic.current` holds the address of the set in use. It is written only after the set is written and read back identical; a mnemonic that differs from
/// the current one is written and read back first, then `current` moves, and the old sets stay (nothing is deleted: the delete path stays disabled).
/// - The names do not touch the published items (`walletKey`, the PGP items) or the `mnemonic:<eoa>` items of the withdrawn formats.
/// - The phrase never goes to a log. Its Data copies are wiped after use; a Swift String cannot be zeroed (an accepted limit).
enum BeamioMnemonicSets {
	static let setPrefix = "mnemonic.set."
	static let currentName = "mnemonic.current"
	static let formatVersion = 1

	/// The state of `current` as the cold-start answer reads it. Only `confirmedMissing` is a confirmed absence; every other failure keeps the data.
	enum Current: Equatable {
		case ok(eoa: String, phrase: String)
		/// The current record of the passcode state: the stored v3 envelope as canonical JSON, returned as it is (never decrypted here).
		case cipher(eoa: String, envelope: Data)
		case confirmedMissing
		case readError
		case unknown
		case verifyFailed
	}

	enum Save: Equatable {
		case updated
		case idempotent
		case badRequest
		/// `reason` is one of the closed wire words `storage_write` and `internal_state`.
		case failed(String)
	}

	static func setName(_ eoa: String) -> String { setPrefix + eoa.lowercased() }

	/// The set of one owner as the key store reads it (account judgement, phrase read, key derivation). The set is read by its own name, whatever `current` says.
	enum SetRead {
		case absent
		case unreadable
		/// The record is there but is not a set record of this owner (version, mode, address or phrase field wrong).
		case damaged
		case phrase(Data)
	}

	static func readSet(store: BeamioChatRawItemStoring, eoa rawEoa: String) -> SetRead {
		let eoa = rawEoa.lowercased()
		// a plaintext set that the passcode state has replaced is never read again (see `plainRetirement`): it reads as absent whether or not its cleanup finished
		switch plainRetirement(store: store, eoa: eoa) {
		case .yes: return .absent
		case .unknown: return .unreadable
		case .no: break
		}
		switch store.rawRead(account: setName(eoa)) {
		case .absent: return .absent
		case .unreadable: return .unreadable
		case .present(var bytes):
			defer { BeamioNativeWallet.wipe(&bytes) }
			guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
			      object["v"] as? Int == formatVersion, object["mode"] as? String == "keychain",
			      (object["eoa"] as? String)?.lowercased() == eoa, let text = object["phrase"] as? String
			else { return .damaged }
			return .phrase(Data(text.utf8))
		}
	}

	/// The key a set derives, in memory only, and only when it derives the owner's own address. nil for an absent, unreadable, damaged or mismatching set.
	/// The caller wipes the returned bytes. Nothing is written.
	static func derivedKey(store: BeamioChatRawItemStoring, eoa rawEoa: String) -> Data? {
		let eoa = rawEoa.lowercased()
		guard case .phrase(var phrase) = readSet(store: store, eoa: eoa) else { return nil }
		defer { BeamioNativeWallet.wipe(&phrase) }
		guard var derived = BeamioPwaWalletSync.derivedAccount(phrase: String(decoding: phrase, as: UTF8.self)), derived.eoa == eoa else { return nil }
		defer { BeamioNativeWallet.wipe(&derived.key) }
		return Data(derived.key)
	}

	/// The owners of the plaintext sets in a list of account names (cipher versions `mnemonic.set.<eoa>.c.<digest>` are not accounts of this judgement).
	static func setOwner(inAccount account: String) -> String? {
		guard account.hasPrefix(setPrefix) else { return nil }
		let owner = String(account.dropFirst(setPrefix.count))
		return owner.isEmpty || owner.contains(".") ? nil : owner
	}

	/// The owner of a v3 cipher version item name `mnemonic.set.<eoa>.c.<digest>`; nil for any other name (including the plaintext sets).
	static func cipherVersionOwner(inAccount account: String) -> String? {
		guard account.hasPrefix(setPrefix) else { return nil }
		let rest = account.dropFirst(setPrefix.count)
		guard let marker = rest.range(of: ".c.") else { return nil }
		let owner = String(rest[rest.startIndex ..< marker.lowerBound])
		let digest = rest[marker.upperBound...]
		return owner.isEmpty || owner.contains(".") || digest.isEmpty ? nil : owner
	}

	/// Whether the orphan v3 cipher versions (no pointer names them) block: any version of an identity that was not cleared. A version of an identity that was
	/// cleared on purpose is ignored with that identity (the marker), as its account is. An unreadable marker is unknown: it blocks.
	static func orphanVersionsBlock(owners: Set<String>, cleared: BeamioIdentityCleared.Reading) -> Bool {
		if owners.isEmpty { return false }
		switch cleared {
		case .unreadable: return true
		case .ok(let ignored): return !owners.isSubset(of: ignored)
		}
	}

	/// For a store whose pointer is confirmed missing: true when orphan versions block, false when there is none to count, nil when the items cannot be listed
	/// (unknown: the caller reads it as a read failure, never as "none").
	static func orphanVersionsBlock(store: BeamioChatWalletKeyStoring) -> Bool? {
		guard let raw = store as? BeamioChatRawItemStoring else { return false }
		guard let names = raw.rawAccountNames() else { return nil }
		let owners = Set(names.compactMap { cipherVersionOwner(inAccount: $0)?.lowercased() })
		return orphanVersionsBlock(owners: owners, cleared: BeamioIdentityCleared.read(store: store))
	}

	// MARK: - Retiring the plaintext set once the passcode state holds the account

	/// The cleanup record of one account: `mnemonic.retire.<eoa>`. It holds no secret: the version, the address and the state (`pending`, then `done`). It is written before the
	/// plaintext set is deleted and stays as the tombstone, so a restart can finish the cleanup and the plaintext is never read in between.
	static let retirePrefix = "mnemonic.retire."

	static func retireName(_ eoa: String) -> String { retirePrefix + eoa.lowercased() }

	private static func retireBytes(eoa: String, state: String) -> Data? {
		try? JSONSerialization.data(withJSONObject: ["v": formatVersion, "eoa": eoa.lowercased(), "state": state], options: [.sortedKeys])
	}

	enum Retirement: Equatable {
		case yes, no, unknown
	}

	/// What `mnemonic.current` names, for the retirement rule.
	private enum PointerKind: Equatable {
		case cipher(String)
		case plain(String)
		case other
		case unreadable
	}

	private static func pointerKind(store: BeamioChatRawItemStoring) -> PointerKind {
		switch store.rawRead(account: currentName) {
		case .unreadable: return .unreadable
		case .absent: return .other
		case .present(let bytes):
			guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], let eoa = (object["eoa"] as? String)?.lowercased(), !eoa.isEmpty else { return .other }
			return object["kind"] as? String == "cipher" ? .cipher(eoa) : .plain(eoa)
		}
	}

	/// Whether the plaintext set of `eoa` is retired: the passcode state replaced it, so it is never read again, never returned and never a key source. It is decided by the pointer, not by
	/// whether the plaintext item is still there: a pointer that names this account's v3 record retires it (the cleanup may not have run, or may have been interrupted); a pointer that names
	/// this very plaintext set keeps it (a native import chose it again); with any other pointer the cleanup record decides. An unreadable pointer or record is unknown (never "retired" and
	/// never "kept"): the caller reads it as a read failure.
	static func plainRetirement(store: BeamioChatRawItemStoring, eoa rawEoa: String) -> Retirement {
		let eoa = rawEoa.lowercased()
		switch pointerKind(store: store) {
		case .cipher(let named) where named == eoa: return .yes
		case .plain(let named) where named == eoa: return .no
		case .unreadable: return .unknown
		default:
			switch store.rawRead(account: retireName(eoa)) {
			case .present(let bytes): return retireState(bytes) == reselectedState ? .no : .yes
			case .absent: return .no
			case .unreadable: return .unknown
			}
		}
	}

	/// How the older device copies of an account (`mnemonic:<eoa>` and `walletKey:<eoa>`) are seen once the passcode state may hold the account. `retired`: the v3 record is verified, the copies
	/// read as absent whether or not their deletion finished. `retiredUnverified`: the pointer retires them but the v3 record does not read back, so they are neither returned nor called absent
	/// (an unreadable item, never "no account"). `unknown`: the pointer or the cleanup record cannot be read (also unreadable). `live`: every other account, unchanged.
	enum LegacyView: Equatable {
		case live, retired, retiredUnverified, unknown
	}

	static func legacyView(store: BeamioChatRawItemStoring, eoa rawEoa: String) -> LegacyView {
		let eoa = rawEoa.lowercased()
		// the older copies are retired only by their own record, written once the v3 record was unlocked and its key derived this very address (`retireLegacy`). A v3 record that only
		// came in without a passcode proves nothing, so it retires nothing.
		switch store.rawRead(account: legacyRetireName(eoa)) {
		case .absent: return .live
		case .unreadable: return .unknown
		case .present: return cipherVerified(store: store, eoa: eoa) ? .retired : .retiredUnverified
		}
	}

	/// The cleanup record of the older device copies of one account: `mnemonic.legacyretire.<eoa>`. No secret: the version, the address and the state (`pending`, then `done`). It is written only
	/// after the unlock of the v3 record proved the address, and it stays as the tombstone.
	static let legacyRetirePrefix = "mnemonic.legacyretire."

	static func legacyRetireName(_ eoa: String) -> String { legacyRetirePrefix + eoa.lowercased() }

	/// Retires the older device copies of `eoa`: the wrapped mnemonic item (with its credential key) and the wallet key record. It needs all of: the v3 record reads back (`cipherVerified`), and
	/// either the account is unlocked now with a held key that derives this very address, or the cleanup record already exists (an earlier unlock proved it). Then, in order: the cleanup record,
	/// the deletions, the `done` mark. Any failure leaves the record and the copies, hidden (see `legacyView`), and the next call continues. True when the copies are gone.
	@discardableResult
	static func retireLegacy(eoa rawEoa: String, store: BeamioChatRawItemStoring) -> Bool {
		let eoa = rawEoa.lowercased()
		let record = store.rawRead(account: legacyRetireName(eoa))
		if case .unreadable = record { return false }
		var haveRecord = false
		if case .present = record { haveRecord = true }
		guard cipherVerified(store: store, eoa: eoa) else { return false }
		if !haveRecord {
			// first time: the proof of the address comes from the unlocked session
			guard var held = BeamioCipherUnlock.key(eoa: eoa) else { return false }
			defer { BeamioNativeWallet.wipe(&held) }
			guard BeamioNativeEthSigner.address(privateKey: [UInt8](held))?.lowercased() == eoa else { return false }
			// nothing to retire and no record to keep when the account has no older copies
			let names = ["mnemonic:" + eoa, "walletKey:" + eoa]
			var any = false
			for name in names {
				switch store.rawRead(account: name) {
				case .unreadable: return false
				case .present: any = true
				case .absent: break
				}
			}
			guard any else { return true }
			if retireFault("intent") { return false }
			guard let pending = retireBytes(eoa: eoa, state: "pending"), store.rawWrite(account: legacyRetireName(eoa), bytes: pending),
			      case .present(let back) = store.rawRead(account: legacyRetireName(eoa)), back == pending else { return false }
		}
		if retireFault("delete") { return false }
		if retireFault("deleteCall") { return false }
		guard store.deleteRetiredLegacyItems(eoa: eoa) else { return false }
		for name in ["mnemonic:" + eoa, "walletKey:" + eoa] { guard case .absent = store.rawRead(account: name) else { return false } }
		if retireFault("done") { return false }
		if let done = retireBytes(eoa: eoa, state: "done") { _ = store.rawWrite(account: legacyRetireName(eoa), bytes: done) }
		return true
	}

	/// The state word of a cleanup record. `reselected`: the plaintext set was chosen again by a native import, so the record no longer retires it.
	static let reselectedState = "reselected"

	private static func retireState(_ bytes: Data) -> String? {
		(try? JSONSerialization.jsonObject(with: bytes) as? [String: Any])?["state"] as? String
	}

	/// The v3 record of `eoa` is there and good: the pointer names it and `current` reads it back (the version item present, its format and address valid), or, with another pointer,
	/// at least one version item of the account reads back and passes the format check. Nothing is written. A deletion of the plaintext needs this, never only the pointer.
	private static func cipherVerified(store: BeamioChatRawItemStoring, eoa: String) -> Bool {
		if case .cipher(let named, _) = current(store: store), named == eoa { return true }
		if case .cipher(let named) = pointerKind(store: store), named == eoa { return false }   // the pointer names this account's v3 record and it does not read back
		guard let names = store.rawAccountNames() else { return false }
		let prefix = setName(eoa) + ".c."
		for name in names where name.hasPrefix(prefix) {
			guard case .present(let bytes) = store.rawRead(account: name),
			      let record = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], record["v"] as? Int == formatVersion,
			      record["mode"] as? String == "cipher", (record["eoa"] as? String)?.lowercased() == eoa,
			      let envelope = record["envelope"] as? [String: Any], let parsed = BeamioMnemonicCipherV3.parse(envelope), parsed.eoa == eoa,
			      name == cipherItemName(parsed) else { continue }
			return true
		}
		return false
	}

	#if BEAMIO_TEST_HOOKS
	/// Test only: a failure injected at one step of the cleanup. The step does not run and the cleanup reports failure; nothing else changes. `reselectMarkFails` fails the deletion of the
	/// old record and the mark that replaces it.
	enum RetireFault: Equatable {
		case beforeIntent, beforeDelete, deleteFails, beforeDoneMark, reselectDeleteFails, reselectMarkFails
	}
	static var retireFaultForTests: RetireFault?
	#endif

	private static func retireFault(_ stage: String) -> Bool {
		#if BEAMIO_TEST_HOOKS
		switch (retireFaultForTests, stage) {
		case (.beforeIntent?, "intent"), (.beforeDelete?, "delete"), (.deleteFails?, "deleteCall"), (.beforeDoneMark?, "done"),
		     (.reselectDeleteFails?, "reselectDelete"), (.reselectMarkFails?, "reselectDelete"), (.reselectMarkFails?, "reselectMark"): return true
		default: return false
		}
		#else
		return false
		#endif
	}

	/// Deletes the plaintext set of `eoa` after the passcode state holds the account: the cleanup record first (no secret), then the plaintext item, then the `done` mark. True when the
	/// plaintext is gone. Any failure leaves the record, so the next call (a repeated sync, or the next start) continues; nothing here moves the pointer, writes a phrase or returns one.
	/// Runs only while the pointer names this account's v3 record, or the cleanup record already exists and the pointer does not name the plaintext set.
	@discardableResult
	static func retirePlain(eoa rawEoa: String, store: BeamioChatRawItemStoring) -> Bool {
		let eoa = rawEoa.lowercased()
		switch pointerKind(store: store) {
		case .cipher(let named) where named == eoa: break
		case .plain(let named) where named == eoa: return false
		case .unreadable: return false
		default:
			guard case .present(let bytes) = store.rawRead(account: retireName(eoa)), retireState(bytes) != reselectedState else { return false }
		}
		// the ciphertext is verified before anything is written or deleted: without a v3 record that reads back, the plaintext stays (it is still never read, see `plainRetirement`)
		// and the cleanup is tried again later
		guard cipherVerified(store: store, eoa: eoa) else { return false }
		// the record of the intent (a record left as `reselected` becomes `pending` again)
		switch store.rawRead(account: retireName(eoa)) {
		case .unreadable: return false
		case .present(let bytes):
			if retireState(bytes) == reselectedState {
				guard let pending = retireBytes(eoa: eoa, state: "pending"), store.rawWrite(account: retireName(eoa), bytes: pending),
				      case .present(let back) = store.rawRead(account: retireName(eoa)), back == pending else { return false }
			}
		case .absent:
			if retireFault("intent") { return false }
			guard let pending = retireBytes(eoa: eoa, state: "pending"), store.rawWrite(account: retireName(eoa), bytes: pending),
			      case .present(let back) = store.rawRead(account: retireName(eoa)), back == pending else { return false }
		}
		// the plaintext item
		switch store.rawRead(account: setName(eoa)) {
		case .unreadable: return false
		case .absent: break
		case .present(var bytes):
			bytes.removeAll()
			if retireFault("delete") { return false }
			if retireFault("deleteCall") { return false }
			guard store.deleteRetiredPlainSet(eoa: eoa), case .absent = store.rawRead(account: setName(eoa)) else { return false }
		}
		if retireFault("done") { return false }
		if let done = retireBytes(eoa: eoa, state: "done") { _ = store.rawWrite(account: retireName(eoa), bytes: done) }
		return true
	}

	/// Finishes every cleanup that a restart or a failure left: for each plaintext set that is retired, run the cleanup again. Reads only names and the pointer unless a set is retired.
	static func resumeRetire(store: BeamioChatRawItemStoring) {
		guard let names = store.rawAccountNames() else { return }
		var owners = Set(names.compactMap { setOwner(inAccount: $0) })
		for name in names {
			for prefix in ["mnemonic:", "walletKey:"] where name.hasPrefix(prefix) { owners.insert(String(name.dropFirst(prefix.count)).lowercased()) }
		}
		for owner in owners.sorted() where plainRetirement(store: store, eoa: owner) == .yes {
			retirePlain(eoa: owner, store: store)
		}
		// the older copies: only where their own record exists, or the account is unlocked now
		var legacyOwners = Set(names.compactMap { name -> String? in name.hasPrefix(legacyRetirePrefix) ? String(name.dropFirst(legacyRetirePrefix.count)).lowercased() : nil })
		for name in names {
			for prefix in ["mnemonic:", "walletKey:"] where name.hasPrefix(prefix) {
				let owner = String(name.dropFirst(prefix.count)).lowercased()
				if BeamioCipherUnlock.isUnlocked(eoa: owner) { legacyOwners.insert(owner) }
			}
		}
		for owner in legacyOwners.sorted() { retireLegacy(eoa: owner, store: store) }
	}

	private static func setBytes(eoa: String, phrase: Data, utc: String) -> Data? {
		guard let text = String(data: phrase, encoding: .utf8) else { return nil }
		let record: [String: Any] = ["v": formatVersion, "mode": "keychain", "eoa": eoa, "phrase": text, "utc": utc]
		return try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
	}

	private static func currentBytes(eoa: String) -> Data? {
		try? JSONSerialization.data(withJSONObject: ["v": formatVersion, "eoa": eoa], options: [.sortedKeys])
	}

	/// The phrase of a set record that is valid for `eoa`: version and mode as written, the address equal, and the phrase deriving that address.
	private static func phrase(ofSet bytes: Data, eoa: String) -> (state: Current, phrase: String?) {
		guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
		      object["v"] as? Int == formatVersion, object["mode"] as? String == "keychain",
		      let recordEoa = (object["eoa"] as? String)?.lowercased(), recordEoa == eoa,
		      let text = object["phrase"] as? String
		else { return (.verifyFailed, nil) }
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: text), derived.eoa == eoa else { return (.verifyFailed, nil) }
		return (.ok(eoa: eoa, phrase: text), text)
	}

	/// The cold-start reading of `current`.
	static func current(store: BeamioChatRawItemStoring) -> Current {
		switch store.rawRead(account: currentName) {
		case .absent:
			return .confirmedMissing
		case .unreadable:
			return .readError
		case .present(let pointer):
			guard let object = try? JSONSerialization.jsonObject(with: pointer) as? [String: Any],
			      object["v"] as? Int == formatVersion, let eoa = (object["eoa"] as? String)?.lowercased(), !eoa.isEmpty
			else { return .unknown }
			if object["kind"] as? String == "cipher" {
				guard let item = object["item"] as? String, item.hasPrefix(setName(eoa) + ".c.") else { return .unknown }
				switch store.rawRead(account: item) {
				case .absent: return .unknown
				case .unreadable: return .readError
				case .present(let bytes):
					guard let record = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], record["v"] as? Int == formatVersion,
					      record["mode"] as? String == "cipher", (record["eoa"] as? String)?.lowercased() == eoa,
					      let envelope = record["envelope"] as? [String: Any], let parsed = BeamioMnemonicCipherV3.parse(envelope), parsed.eoa == eoa
					else { return .verifyFailed }
					return .cipher(eoa: eoa, envelope: parsed.canonical)
				}
			}
			switch store.rawRead(account: setName(eoa)) {
			case .absent:
				return .unknown
			case .unreadable:
				return .readError
			case .present(var bytes):
				defer { BeamioNativeWallet.wipe(&bytes) }
				return phrase(ofSet: bytes, eoa: eoa).state
			}
		}
	}

	/// The write of a v3 envelope (the passcode state). The envelope goes in as the PWA sent it, without decryption. A new version is written and read back before `current`
	/// moves; an older version, plaintext or cipher, stays. The same bytes are idempotent. A different envelope for the same address (a changed passcode) is a new version.
	static func saveCipher(envelope: BeamioMnemonicCipherV3.Envelope, store: BeamioChatRawItemStoring, utc: String) -> Save {
		let saved = saveCipherCore(envelope: envelope, store: store, utc: utc)
		// a successful pwaWalletSync commit (written and read back) ends this account's `identity_cleared` ignore
		if saved == .updated || saved == .idempotent {
			BeamioIdentityCleared.lift(envelope.eoa, store: store)
			// the v3 record is written, read back and named by the pointer: the old plaintext set of the account is retired and deleted silently. A failure of the cleanup is not a failure of the
			// save: the plaintext is already out of use (`plainRetirement`), and the next sync or start finishes the deletion.
			retirePlain(eoa: envelope.eoa, store: store)
		}
		return saved
	}

	/// The item name of one v3 version: the account's set name, `.c.`, and the first 16 hex digits of the SHA-256 of the canonical envelope.
	static func cipherItemName(_ envelope: BeamioMnemonicCipherV3.Envelope) -> String {
		setName(envelope.eoa) + ".c." + String(SHA256.hash(data: envelope.canonical).map { String(format: "%02x", $0) }.joined().prefix(16))
	}

	private static func saveCipherCore(envelope: BeamioMnemonicCipherV3.Envelope, store: BeamioChatRawItemStoring, utc: String) -> Save {
		let eoa = envelope.eoa
		let digest = SHA256.hash(data: envelope.canonical).map { String(format: "%02x", $0) }.joined()
		let item = setName(eoa) + ".c." + String(digest.prefix(16))
		guard let envelopeObject = try? JSONSerialization.jsonObject(with: envelope.canonical),
		      let wanted = try? JSONSerialization.data(withJSONObject: ["v": formatVersion, "mode": "cipher", "eoa": eoa, "envelope": envelopeObject, "utc": utc] as [String: Any], options: [.sortedKeys])
		else { return .failed("internal_state") }
		// MS-R1: the pointer is read first; when it cannot be read, nothing is written
		if case .unreadable = store.rawRead(account: currentName) { return .failed("internal_state") }
		var itemExisted = false
		switch store.rawRead(account: item) {
		case .unreadable:
			return .failed("internal_state")
		case .present(let existing):
			guard let record = try? JSONSerialization.jsonObject(with: existing) as? [String: Any], record["mode"] as? String == "cipher",
			      let stored = record["envelope"] as? [String: Any], let parsed = BeamioMnemonicCipherV3.parse(stored), parsed.canonical == envelope.canonical
			else { return .failed("internal_state") }
			itemExisted = true
		case .absent:
			break
		}
		if !itemExisted {
			guard store.rawWrite(account: item, bytes: wanted) else { return .failed("storage_write") }
			// the read-back does not equal what was written: the state cannot be confirmed (a refused write is storage_write, above)
			guard case .present(let back) = store.rawRead(account: item), back == wanted else { return .failed("internal_state") }
		}
		var previous: Data?
		switch store.rawRead(account: currentName) {
		case .unreadable:
			return .failed("internal_state")
		case .present(let bytes):
			previous = bytes
			if let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], object["kind"] as? String == "cipher", object["item"] as? String == item {
				return itemExisted ? .idempotent : .updated
			}
		case .absent:
			break
		}
		guard let pointer = try? JSONSerialization.data(withJSONObject: ["v": formatVersion, "eoa": eoa, "kind": "cipher", "item": item] as [String: Any], options: [.sortedKeys]) else {
			return .failed("internal_state")
		}
		guard store.rawWrite(account: currentName, bytes: pointer) else { return .failed("storage_write") }
		guard case .present(let back) = store.rawRead(account: currentName), back == pointer else {
			if let previous { _ = store.rawWrite(account: currentName, bytes: previous) }
			return .failed("internal_state")
		}
		return .updated
	}

	/// The write of a validated mnemonic: the set first (written and read back identical), then `current` (written and read back identical). A failure at any
	/// step leaves `current` as it was and removes nothing.
	static func save(phrase text: String, store: BeamioChatRawItemStoring, utc: String) -> Save {
		let saved = saveCore(phrase: text, store: store, utc: utc)
		// a successful pwaWalletSync commit (the set written and read back) ends this account's `identity_cleared` ignore; a failure leaves it ignored
		if saved == .updated || saved == .idempotent, var derived = BeamioPwaWalletSync.derivedAccount(phrase: text) {
			BeamioNativeWallet.wipe(&derived.key)
			BeamioIdentityCleared.lift(derived.eoa, store: store)
			// the pointer names this plaintext set again: an older cleanup record of the account no longer applies. It is deleted, or, when it cannot be, marked `reselected`, so the cleanup
			// rule skips it. If neither works the save is not complete (the same save again retries it).
			let name = retireName(derived.eoa)
			var cleared = !retireFault("reselectDelete") && store.rawDelete(account: name)
			if !cleared, let mark = retireBytes(eoa: derived.eoa, state: reselectedState), !retireFault("reselectMark"), store.rawWrite(account: name, bytes: mark),
			   case .present(let back) = store.rawRead(account: name), back == mark { cleared = true }
			if !cleared { return .failed("internal_state") }
		}
		return saved
	}

	private static func saveCore(phrase text: String, store: BeamioChatRawItemStoring, utc: String) -> Save {
		var normalized = BeamioPwaWalletSync.normalized(text)
		defer { BeamioNativeWallet.wipe(&normalized) }
		guard var derived = BeamioPwaWalletSync.derivedAccount(phrase: text) else { return .badRequest }
		defer { BeamioNativeWallet.wipe(&derived.key) }
		let eoa = derived.eoa
		// MS-R1: a read fault writes nothing. The pointer is read first; when it cannot be read, no set is written (never a new set beside an unreadable pointer).
		if case .unreadable = store.rawRead(account: currentName) { return .failed("internal_state") }
		let name = setName(eoa)
		guard var wanted = setBytes(eoa: eoa, phrase: normalized, utc: utc) else { return .failed("internal_state") }
		defer { BeamioNativeWallet.wipe(&wanted) }
		var setExisted = false
		switch store.rawRead(account: name) {
		case .unreadable:
			return .failed("internal_state")
		case .present(var existing):
			defer { BeamioNativeWallet.wipe(&existing) }
			// the set of this address exists: it must hold this very mnemonic; a different or damaged record is not overwritten
			guard let object = try? JSONSerialization.jsonObject(with: existing) as? [String: Any],
			      (object["phrase"] as? String).map({ BeamioPwaWalletSync.normalized($0) }) == normalized
			else { return .failed("internal_state") }
			setExisted = true
		case .absent:
			break
		}
		if !setExisted {
			guard store.rawWrite(account: name, bytes: wanted) else { return .failed("storage_write") }
			guard case .present(var back) = store.rawRead(account: name), back == wanted else { return .failed("internal_state") }
			BeamioNativeWallet.wipe(&back)
		}
		// the pointer: nothing to do when it already names this set
		var previous: Data?
		switch store.rawRead(account: currentName) {
		case .unreadable:
			return .failed("internal_state")
		case .present(let bytes):
			previous = bytes
			// already current only when the pointer names this plaintext set (a pointer of kind cipher names a cipher version, not this set)
			if let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], (object["eoa"] as? String)?.lowercased() == eoa, object["kind"] == nil {
				return setExisted ? .idempotent : .updated
			}
		case .absent:
			break
		}
		guard let pointer = currentBytes(eoa: eoa) else { return .failed("internal_state") }
		guard store.rawWrite(account: currentName, bytes: pointer) else { return .failed("storage_write") }
		guard case .present(let back) = store.rawRead(account: currentName), back == pointer else {
			// put the previous pointer back; the new set stays (nothing is deleted)
			if let previous { _ = store.rawWrite(account: currentName, bytes: previous) }
			return .failed("internal_state")
		}
		return .updated
	}
}
