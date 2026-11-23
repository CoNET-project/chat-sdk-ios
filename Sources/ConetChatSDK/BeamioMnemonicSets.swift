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
		if saved == .updated || saved == .idempotent { BeamioIdentityCleared.lift(envelope.eoa, store: store) }
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
