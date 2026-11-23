import Foundation

/// Native key import. A private key or a BIP-39 recovery phrase typed into the native secure
/// field goes straight to the native key store. It never passes through the WebView or the bridge.
///
/// Steps: parse the text strictly (64 hex, optional 0x/0X, outer ASCII whitespace only; or a recovery
/// phrase), check the key is in range (0 < k < n), derive the account, refuse a mismatch with the expected account
/// when there is one, refuse to overwrite an existing record, write, read back and compare, and wipe every byte copy. A
/// failed read-back deletes the write. Both forms share the same tail (`storeDerivedKey`).
public enum BeamioNativeKeyImport {
	public enum Outcome: Equatable {
		case imported
		/// A record already exists for the account. Nothing is changed (code `already_exists`).
		case alreadyPresent
		/// Not 64 hex digits after the outer whitespace and the optional prefix (code `invalid_format`).
		case invalidFormat
		/// A recovery phrase that is not 12/15/18/21/24 listed words with a valid checksum (code `invalid_mnemonic`).
		case invalidMnemonic
		/// Zero, or not below the curve order (code `invalid_key`).
		case invalidKey
		case addressMismatch
		case writeFailed
		case readBackFailed
		/// The user left the screen (code `cancelled`). No message, no record.
		case cancelled
		/// A record of the account is unreadable, or the store cannot keep the mnemonic and the intent ((i)). Nothing is
		/// written and nothing is deleted (code `unavailable`).
		case unavailable
		/// A rollback could not delete what the import registered ((e)). The intent stays; the account is
		/// `unavailable` until the next start-up reconciliation (code `rollback_pending`).
		case rollbackPending

		/// The one-line wire code of `nativeImportResult` (25.52Y.95 第 2 条, 25.52Y.97 第 1 至 2 条). Only five codes leave the SDK.
		/// `unavailable` is not named by the spec's mapping; it is sent as `import_failed` (nothing was written) and listed for the integrator.
		public var wireCode: String {
			switch self {
			case .imported: return "ok"
			case .alreadyPresent: return "already_exists"
			case .invalidFormat, .invalidMnemonic, .invalidKey: return "bad_request"
			case .addressMismatch, .writeFailed, .readBackFailed, .rollbackPending, .unavailable: return "import_failed"
			case .cancelled: return "cancelled"
			}
		}

		/// The result code of spec and import-upgrade-vectors.v1.
		public var code: String {
			switch self {
			case .imported: return "ok"
			case .alreadyPresent: return "already_exists"
			case .invalidFormat: return "invalid_format"
			case .invalidMnemonic: return "invalid_mnemonic"
			case .invalidKey: return "invalid_key"
			case .addressMismatch: return "address_mismatch"
			case .writeFailed: return "write_failed"
			case .readBackFailed: return "readback_failed"
			case .cancelled: return "cancelled"
			case .unavailable: return "unavailable"
			case .rollbackPending: return "rollback_pending"
			}
		}
	}

	/// The import result code table (spec table, (c), (e); added `rollback_pending`). Each code is listed with its copy key
	/// (`imp.err.*`, a draft until P-IMP-COPY). The Android SDK must list the same codes with the same strings (the iOS code
	/// is the reference of the table). `ok`, `cancelled` and `unavailable` are not rows of the table: `ok` is the success, `cancelled` has no text,
	/// `unavailable` is the state of an account, not an import result.
	public static let codeTable: [(code: String, copyKey: String)] = [
		("invalid_format", "imp.err.format"),
		("invalid_key", "imp.err.range"),
		("invalid_mnemonic", "imp.err.mnemonic"),
		("address_mismatch", "imp.err.mismatch"),
		("already_exists", "imp.err.exists"),
		("write_failed", "imp.err.write"),
		("readback_failed", "imp.err.readback"),
		("rollback_pending", "imp.err.rollback"),
	]

	/// The text shown for each outcome. The native screen and the tests read the same text. nil: no message (cancelled).
	/// The texts are drafts until P-IMP-COPY is decided (spec).
	public static func userMessage(for outcome: Outcome) -> String? {
		switch outcome {
		case .imported: return "已导入"
		case .alreadyPresent: return "该账号已有密钥，未做更改"
		case .invalidFormat: return "格式不正确"
		case .invalidMnemonic: return "助记词格式不正确"
		case .invalidKey: return "密钥不在有效范围内"
		case .addressMismatch: return "该密钥与当前账号不符"
		case .writeFailed, .readBackFailed: return "保存失败，请重试"
		case .cancelled: return nil
		case .unavailable: return "钱包暂时无法读取，请重试"
		case .rollbackPending: return "钱包需要清理，请稍后重试"
		}
	}

	/// Imports one private key. `expectedEoa` may be empty (no account context): the account is then whatever the key derives.
	public static func importPrivateKey(text: String, expectedEoa: String,
	                                    store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> Outcome {
		importPrivateKeyReport(text: text, expectedEoa: expectedEoa, store: store).outcome
	}

	/// The same import as `importPrivateKey`, with the account the page may report (25.52Y.95 第 2 条).
	public static func importPrivateKeyReport(text: String, expectedEoa: String,
	                                          store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> Report {
		guard var key = parseHexKey(text) else { return Report(outcome: .invalidFormat, eoa: nil) }
		return storeDerivedKeyReport(&key, expectedEoa: expectedEoa, store: store)
	}

	/// Imports the account of a BIP-39 recovery phrase (P-MNEMONIC, spec): English list, no passphrase, path
	/// m/44'/60'/0'/0/0, account index 0. The same codes, mismatch, existing-record and read-back rules as a private key.
	/// A wrong word count, a word outside the list, or a bad checksum is `invalid_mnemonic`. The phrase is never
	/// logged and never stored: only the derived 32-byte key is written.
	static func importRecoveryPhrase(text: String, expectedEoa: String,
	                                        store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> Outcome {
		importRecoveryPhraseReport(text: text, expectedEoa: expectedEoa, store: store).outcome
	}

	/// The same import as `importRecoveryPhrase`, with the account the page may report (25.52Y.95 第 2 条).
	static func importRecoveryPhraseReport(text: String, expectedEoa: String,
	                                              store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> Report {
		switch BeamioMnemonicDerivation.derive(phrase: text) {
		case .invalidMnemonic: return Report(outcome: .invalidMnemonic, eoa: nil)
		case .invalidKey: return Report(outcome: .invalidKey, eoa: nil)
		case .key(var key):
			let normalized = text.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ").lowercased()
			var phrase = Array(normalized.utf8)
			defer { BeamioNativeWallet.wipe(&phrase) }
			return storeDerivedKeyReport(&key, expectedEoa: expectedEoa, store: store, mnemonic: phrase)
		}
	}

	/// One import as the page reports it: the outcome, and the lower-case EOA when the wire rules allow one. The EOA is set only for
	/// `ok` and `already_exists` (25.52Y.95 第 2 条, 25.52X.4), and only when the derivation of the key succeeded. The key is never in a report.
	public struct Report: Equatable {
		public let outcome: Outcome
		public let eoa: String?

		public init(outcome: Outcome, eoa: String?) {
			self.outcome = outcome
			self.eoa = eoa
		}
	}

	/// Derives the account of `key` for the report, then runs the import. `eoa` is the derived account for `ok` and `already_exists` only.
	static func storeDerivedKeyReport(_ key: inout [UInt8], expectedEoa: String, store: BeamioChatWalletKeyStoring,
	                                  mnemonic: [UInt8]? = nil) -> Report {
		let derived = BeamioNativeEthSigner.isValidKey(key) ? BeamioNativeEthSigner.address(privateKey: key)?.lowercased() : nil
		let outcome = storeDerivedKey(&key, expectedEoa: expectedEoa, store: store, mnemonic: mnemonic)
		let carriesAccount = outcome == .imported || outcome == .alreadyPresent
		return Report(outcome: outcome, eoa: carriesAccount ? derived : nil)
	}

	/// The `nativeImportResult` event of one report (25.52Y.95 第 2 条): `{type, reqId, code}`, with `eoa` only for `ok` and `already_exists`.
	public static func resultEvent(reqId: Any, report: Report) -> [String: Any] {
		let code = report.outcome.wireCode
		var event: [String: Any] = ["type": "nativeImportResult", "reqId": reqId, "code": code]
		if code == "ok" || code == "already_exists", let eoa = report.eoa {
			event["eoa"] = eoa
		}
		return event
	}

	/// The shared tail of both import forms ((a) to (e)): the range, the derivation, the expected-account check, the
	/// existence check of the four items, the intent, the key, the mnemonic when given, the commit marker last, then the intent is removed.
	/// Any failure rolls back only the items this import registered, then the intent. Wipes `key` before returning.
	/// `keepOnReadBackFailure` (第 28(d)2 项, project ruling): a failed read-back keeps the records written so far, and only the intent is removed, so no
	/// start-up rollback runs. The caller marks the entry unconfirmed. The default rolls back what this import wrote.
	static func storeDerivedKey(_ key: inout [UInt8], expectedEoa: String, store: BeamioChatWalletKeyStoring,
	                            mnemonic: [UInt8]? = nil, setPointer: Bool = true, keepOnReadBackFailure: Bool = false) -> Outcome {
		let derivedEoa = BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
		let outcome = storeDerivedKeyCore(&key, expectedEoa: expectedEoa, store: store, mnemonic: mnemonic, setPointer: setPointer, keepOnReadBackFailure: keepOnReadBackFailure)
		// the user's explicit import or creation of this account, once stored (or already held), ends its `identity_cleared` ignore; a failure leaves it ignored
		if let derivedEoa, outcome == .imported || outcome == .alreadyPresent { BeamioIdentityCleared.lift(derivedEoa, store: store) }
		return outcome
	}

	private static func storeDerivedKeyCore(_ key: inout [UInt8], expectedEoa: String, store: BeamioChatWalletKeyStoring,
	                                        mnemonic: [UInt8]?, setPointer: Bool, keepOnReadBackFailure: Bool) -> Outcome {
		defer { BeamioNativeWallet.wipe(&key) }
		guard BeamioNativeEthSigner.isValidKey(key),
		      let derived = BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
		else { return .invalidKey }
		let expected = expectedEoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		if !expected.isEmpty, expected != derived { return .addressMismatch }
		let eoa = derived
		// A store that cannot keep the intent and the mnemonic items (only the test doubles) takes the key-only write of. The
		// production store (`BeamioChatWalletKeychainStore`) always takes the full path below.
		guard let items = store as? BeamioChatMnemonicKeyStoring else {
			return storeKeyOnly(&key, eoa: eoa, store: store)
		}
		// (i): the four items are checked before any write. Any of them present is already_exists; any unreadable is unavailable.
		for kind in BeamioChatWalletItemKind.allCases {
			switch items.itemState(kind, eoa: eoa) {
			case .absent: continue
			case .present: return .alreadyPresent
			case .unreadable: return .unavailable
			}
		}
		// A new or imported account that brings its mnemonic is stored as a no-passcode set: the set is written and read back, then `current`
		// moves. No key record is written (the key is derived in memory from the set) and no intent or commit item is needed: the set is one record, written
		// and read back before `current` points at it, and nothing is deleted on a failure. A private key without a mnemonic is not an account (第 32 項 裁定 A)
		// and stays unwritable.
		if let phrase = mnemonic, let rawStore = setStore(of: store) {
			var phraseBytes = phrase
			defer { BeamioNativeWallet.wipe(&phraseBytes) }
			guard case .key(var rederived) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phraseBytes, as: UTF8.self)), rederived == key else {
				return .readBackFailed
			}
			BeamioNativeWallet.wipe(&rederived)
			switch BeamioMnemonicSets.save(phrase: String(decoding: phraseBytes, as: UTF8.self), store: rawStore, utc: utcSeconds(Date())) {
			case .updated: break
			case .idempotent: return .alreadyPresent
			case .badRequest: return .invalidKey
			case .failed: return .writeFailed
			}
			if setPointer { BeamioNativeAccountPointer.set(eoa) }
			return .imported
		}
		// (a): the intent, written first, once the check has passed.
		let intent: [String: Any] = [
			"v": 1, "eoa": eoa, "mnemonicPlanned": mnemonic != nil, "blobKeyPlanned": mnemonic != nil,
			"startedAt": utcSeconds(Date()), "phase": "begun", "keep": keepOnReadBackFailure,
		]
		guard let intentData = try? JSONSerialization.data(withJSONObject: intent, options: [.sortedKeys]) else { return .writeFailed }
		var attempted: [BeamioChatWalletItemKind] = []
		guard items.writeItem(.intent, eoa: eoa, value: intentData) else {
			return rollback(items, eoa: eoa, attempted: attempted) ? .writeFailed : .rollbackPending
		}
		// (b) (1): the private key, with a read-back.
		var data = Data(key)
		defer { BeamioNativeWallet.wipe(&data) }
		attempted.append(.key)
		guard items.writeItem(.key, eoa: eoa, value: data) else {
			return rollback(items, eoa: eoa, attempted: attempted) ? .writeFailed : .rollbackPending
		}
		guard let back = items.readItem(.key, eoa: eoa), back == data else {
			return keepOnReadBackFailure ? keepUnverified(items, store: store, eoa: eoa) : (rollback(items, eoa: eoa, attempted: attempted) ? .readBackFailed : .rollbackPending)
		}
		// (b) (2): the mnemonic when planned. Write, then read back: it derives this key and this address (§25.25.3).
		if var phrase = mnemonic {
			defer { BeamioNativeWallet.wipe(&phrase) }
			attempted.append(.mnemonic)
			// §25.25.3: a write the store refuses is write_failed; a read-back that does not match is readback_failed.
			guard items.writeItem(.mnemonic, eoa: eoa, value: Data(phrase)) else {
				return rollback(items, eoa: eoa, attempted: attempted) ? .writeFailed : .rollbackPending
			}
			let storedOK = items.readItem(.mnemonic, eoa: eoa) == Data(phrase)
			var derivedMatches = false
			if case .key(let rederived) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) {
				derivedMatches = rederived == key
			}
			guard storedOK, derivedMatches else {
				return keepOnReadBackFailure ? keepUnverified(items, store: store, eoa: eoa) : (rollback(items, eoa: eoa, attempted: attempted) ? .readBackFailed : .rollbackPending)
			}
		}
		// (b) (3): the commit marker, last. Writing it is the commit.
		let commit: [String: Any] = ["v": 1, "eoa": eoa, "committedAt": utcSeconds(Date())]
		guard let commitData = try? JSONSerialization.data(withJSONObject: commit, options: [.sortedKeys]) else {
			return rollback(items, eoa: eoa, attempted: attempted) ? .writeFailed : .rollbackPending
		}
		guard items.writeItem(.commit, eoa: eoa, value: commitData) else {
			return rollback(items, eoa: eoa, attempted: attempted) ? .writeFailed : .rollbackPending
		}
		// After the commit the intent is removed. A failed removal is not an import failure: the reconciliation finds the commit and removes it.
		_ = items.deleteItem(.intent, eoa: eoa)
		// The creation passes setPointer false and writes the pointer with the checked write and read-back (25.52Y.163 第 12(d) 項).
		if setPointer { BeamioNativeAccountPointer.set(eoa) }
		return .imported
	}

	/// The raw store that holds the sets: the production stores only (the passcode store's legacy layer, or the keychain store itself).
	static func setStore(of store: BeamioChatWalletKeyStoring) -> BeamioChatRawItemStoring? {
		if let passcode = store as? BeamioPasscodeWalletStore { return passcode.rawLegacyStoreForShell }
		return store as? BeamioChatWalletKeychainStore
	}

	/// A failed read-back that keeps its records (第 28(d)2 项, 残留裁定). The mark is written and read back first; only then is the intent removed.
	/// A failed mark keeps the intent and answers `rollbackPending`, and nothing is rolled back: the next start retries the mark.
	static func keepUnverified(_ items: BeamioChatMnemonicKeyStoring, store: BeamioChatWalletKeyStoring, eoa: String) -> Outcome {
		guard let raw = store as? BeamioChatRawItemStoring,
		      BeamioNativeRestore.markUnconfirmedVerified(eoa: eoa, utc: utcSeconds(Date()), store: raw)
		else { return .rollbackPending }
		// A failed removal leaves the intent beside the mark; the start-up keeps it marked (第 28(d)2, 残留裁定).
		_ = items.deleteItem(.intent, eoa: eoa)
		return .readBackFailed
	}

	/// The start-up of a kept restore entry (第 28(d)2, 残留裁定): the mark is ensured and read back, and only then the intent is removed.
	/// A failed mark keeps the intent for the next start. Nothing is rolled back.
	static func keepRestoreEntry(_ items: BeamioChatMnemonicKeyStoring, store: BeamioChatWalletKeyStoring, owner: String) {
		guard let raw = store as? BeamioChatRawItemStoring,
		      BeamioNativeRestore.markUnconfirmedVerified(eoa: owner, utc: utcSeconds(Date()), store: raw)
		else { return }
		_ = items.deleteItem(.intent, eoa: owner)
	}

	/// The key-only write of for a store without the intent items. Only the test doubles reach it.
	static func storeKeyOnly(_ key: inout [UInt8], eoa: String, store: BeamioChatWalletKeyStoring) -> Outcome {
		if store.read(eoa: eoa) != nil { return .alreadyPresent }
		var data = Data(key)
		defer { BeamioNativeWallet.wipe(&data) }
		guard store.write(eoa: eoa, key: data) else {
			store.delete(eoa: eoa)
			return .writeFailed
		}
		guard var back = store.read(eoa: eoa), back == data else {
			store.delete(eoa: eoa)
			return .readBackFailed
		}
		BeamioNativeWallet.wipe(&back)
		BeamioNativeAccountPointer.set(eoa)
		return .imported
	}

	/// (e): deletes only what this import registered (`attempted`, in reverse), then the intent. True when all of it is gone.
	/// A failed deletion returns false; the intent is then kept, so the start-up reconciliation can see the attempt.
	static func rollback(_ items: BeamioChatMnemonicKeyStoring, eoa: String, attempted: [BeamioChatWalletItemKind]) -> Bool {
		for kind in attempted.reversed() where !items.deleteItem(kind, eoa: eoa) {
			return false
		}
		return items.deleteItem(.intent, eoa: eoa)
	}

	static func utcSeconds(_ date: Date) -> String {
		let formatter = ISO8601DateFormatter()
		formatter.formatOptions = [.withInternetDateTime]
		formatter.timeZone = TimeZone(identifier: "UTC")
		return formatter.string(from: date)
	}

	// MARK: - Start-up reconciliation of the import intents ((c), (f), (k);)

	private static let intentLock = NSLock()
	private static var unavailableOwners = Set<String>()
	private static var reconciledOnce = false

	/// True when the account has an intent that cannot be read or judged ((c), (k);): this account is `unavailable`.
	/// Nothing is deleted for it. Other accounts are not affected.
	public static func isIntentUnavailable(eoa rawEoa: String) -> Bool {
		intentLock.lock()
		defer { intentLock.unlock() }
		return unavailableOwners.contains(rawEoa.lowercased())
	}

	/// The start-up reconciliation ((c)). It looks only at the intent items. An intent with a commit is removed. An intent without a
	/// commit has its registered records removed (the key, and the mnemonic when planned), then the intent. An intent that cannot be read, or
	/// whose fields are not valid, deletes nothing and marks its account unavailable. Records with no intent are never touched.
	/// Returns the accounts that were marked unavailable.
	@discardableResult
	public static func reconcileIntents(store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> [String] {
		guard let items = store as? BeamioChatMnemonicKeyStoring, let owners = items.intentOwners() else { return [] }
		var marked: [String] = []
		for owner in owners.map({ $0.lowercased() }) {
			let unavailable = { () -> Bool in
				intentLock.lock()
				unavailableOwners.insert(owner)
				intentLock.unlock()
				marked.append(owner)
				return true
			}
			guard let raw = items.readItem(.intent, eoa: owner),
			      let obj = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
			      obj["v"] as? Int == 1, obj["eoa"] as? String == owner, obj["phase"] as? String == "begun",
			      let planned = obj["mnemonicPlanned"] as? Bool
			else { _ = unavailable(); continue }
			// 第 28(d)2 (残留裁定): a kept restore entry is never rolled back; its mark is ensured, and only then its intent is removed.
			if obj["keep"] as? Bool == true, items.itemState(.commit, eoa: owner) == .absent {
				keepRestoreEntry(items, store: store, owner: owner)
				continue
			}
			switch items.itemState(.commit, eoa: owner) {
			case .present:
				// Committed: the intent is only leftover. Nothing else is removed.
				if !items.deleteItem(.intent, eoa: owner) { _ = unavailable() }
			case .unreadable:
				_ = unavailable()
			case .absent:
				var registered: [BeamioChatWalletItemKind] = [.key]
				if planned { registered.append(.mnemonic) }
				if rollback(items, eoa: owner, attempted: registered) { continue }
				_ = unavailable()
			}
		}
		return marked
	}

	/// Runs the reconciliation once per process, before the first command reads any record ((c)). `handleCommand` calls it first.
	public static func reconcileOnceAtStart(store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) {
		intentLock.lock()
		let first = !reconciledOnce
		reconciledOnce = true
		intentLock.unlock()
		if first { reconcileIntents(store: store) }
	}

	/// (k)(1)–(4): true when the marks of the account make it unreadable, so walletStatus answers `not_ready` with
	/// `notReadyReason: "unreadable"`. The cases: an intent that was marked unavailable by the reconciliation; an intent or a commit or a
	/// mnemonic that cannot be read; a mnemonic with neither a commit nor an intent (a corruption). Nothing is deleted for any of them.
	public static func walletMarkersUnreadable(eoa rawEoa: String, store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> Bool {
		let eoa = rawEoa.lowercased()
		if isIntentUnavailable(eoa: eoa) {
			// E9.11-1 (requirement): with an unsettled intent the classification looks only at the current mnemonic. A readable mnemonic (valid or
			// not) is judged by its own rules; only an unreadable one is unreadable here.
			guard let items = store as? BeamioChatMnemonicKeyStoring else { return true }
			return items.itemsAccountState(owner: eoa) == .unreadable
		}
		guard let items = store as? BeamioChatMnemonicKeyStoring else { return false }
		let mnemonic = items.itemState(.mnemonic, eoa: eoa)
		let commit = items.itemState(.commit, eoa: eoa)
		let intent = items.itemState(.intent, eoa: eoa)
		if [mnemonic, commit, intent].contains(.unreadable) { return true }
		// the single-judgement classification, item 2: COMMIT removed while the current mnemonic is valid is Ready, not
		// unreadable. Only a present mnemonic that does not read as a valid account keeps the unreadable mark here.
		guard mnemonic == .present && commit == .absent && intent == .absent else { return false }
		return items.itemsAccountState(owner: eoa) != .valid
	}

	/// Test hook: forgets that the start-up reconciliation ran, and the unavailable marks.
	static func resetStartupForTests() {
		intentLock.lock()
		reconciledOnce = false
		unavailableOwners.removeAll()
		intentLock.unlock()
	}

	/// Test hook: clears the unavailable marks (the marks live for the process).
	static func clearIntentMarksForTests() {
		intentLock.lock()
		unavailableOwners.removeAll()
		intentLock.unlock()
	}

	/// 64 hex digits, optionally prefixed by `0x` or `0X`, with only ASCII whitespace stripped from the two ends. Works on
	/// Unicode scalars, so a combining mark or a non-ASCII digit never passes. nil for anything else.
	static func parseHexKey(_ text: String) -> [UInt8]? {
		var scalars = Array(text.unicodeScalars)
		let asciiWhitespace: Set<UInt32> = [0x20, 0x09, 0x0A, 0x0C, 0x0D]
		while let first = scalars.first, asciiWhitespace.contains(first.value) { scalars.removeFirst() }
		while let last = scalars.last, asciiWhitespace.contains(last.value) { scalars.removeLast() }
		if scalars.count >= 2, scalars[0] == "0", scalars[1] == "x" || scalars[1] == "X" {
			scalars.removeFirst(2)
		}
		guard scalars.count == 64 else { return nil }
		var out = [UInt8]()
		out.reserveCapacity(32)
		var high: UInt8?
		for s in scalars {
			guard let nibble = hexNibble(s) else { return nil }
			if let h = high {
				out.append(h << 4 | nibble)
				high = nil
			} else {
				high = nibble
			}
		}
		return out
	}

	private static func hexNibble(_ s: Unicode.Scalar) -> UInt8? {
		switch s.value {
		case 0x30...0x39: return UInt8(s.value - 0x30)
		case 0x41...0x46: return UInt8(s.value - 0x41 + 10)
		case 0x61...0x66: return UInt8(s.value - 0x61 + 10)
		default: return nil
		}
	}
}
