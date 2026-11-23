import CryptoKit
import Foundation
#if canImport(X19)
import X19
#endif

/// The native recovery page and the recovery engine.
///
/// - The shell presents the page through `onRecoveryRequired`, which returns whether the page is open. The page
/// sends its result with `finish`: a failure keeps the page open for a retry, `ok` ends it.
/// - `restore` is the SDK engine for both paths. The credentials come from the native page and are used only
/// here: they are not returned, logged, persisted or sent to a WebView. The bridge gets a code and, with `ok`,
/// the public address and the W fields of the result.
/// - Reads are `eth_call` only, to the account registry. No write method and no Beamio HTTP endpoint.
/// - Without the registry, the KDF or the X-19 framework the answer is `not_supported`, never a guess.
///
/// Limit: the recovery code and the account name are Swift strings, which cannot be zeroized. The byte buffers
/// made from them, the derived key, the plaintext and the phrase are wiped. The caller wipes its own password buffer.
public enum BeamioNativeRecovery {
	/// Set by the shell. Presents the native recovery page for the account. Returns true when the page is open.
	public static var onRecoveryRequired: ((String) -> Bool)?

	/// The codes of the page result. `notSupported` is not a page result; it is the answer when the capability is
	/// not available.
	public enum ResultCode: String, Equatable {
		case ok, cancelled, invalidFormat = "invalid_format", badPin = "bad_pin", backoff, notFound = "not_found"
		case networkError = "network_error", alreadyExists = "already_exists", recordInvalid = "record_invalid"
		case writeFailed = "write_failed", readbackFailed = "readback_failed", legacyRecord = "legacy_record"
		case notSupported = "not_supported"
	}

	/// The credentials of one attempt. Path A: the recovery code. Path B: the account name and the password.
	public enum Credential {
		case recoveryCode(String)
		case account(name: String, password: [UInt8])
	}

	/// Outcome of `restore`. `ok` carries the public address only; `backoff` the seconds left.
	public enum RestoreOutcome: Equatable {
		case ok(eoa: String)
		case backoff(cooldownSec: Int)
		case failed(ResultCode)

		public var code: String {
			switch self {
			case .ok: return ResultCode.ok.rawValue
			case .backoff: return ResultCode.backoff.rawValue
			case .failed(let c): return c.rawValue
			}
		}
	}

	/// The one result of the open recovery page. The shell calls it with the outcome of each attempt, or with
	/// `cancelled` when the user closes the page before any result. Returns false when no page is pending.
	@discardableResult
	public static func finish(_ code: ResultCode, eoa: String? = nil, cooldownSec: Int? = nil) -> Bool {
		guard code != .notSupported else { return false }
		// 25.52X.4: already_exists carries the public account of the key on this device, derived and persisted here. A value from the shell is not used.
		let account = code == .alreadyExists ? existingKeyAccount() : eoa
		return BeamioConetChatModule.finishRecovery(code: code.rawValue, eoa: account, cooldownSec: cooldownSec)
	}

	/// 25.52X.4: the public account of the key already on this device, derived and persisted natively. nil unless the key reads, derives the
	/// account it is kept under, and the account pointer reads back the same. With no pointer, the account is named only when exactly one account has a key.
	/// The key itself never leaves this function.
	static func existingKeyAccount(store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> String? {
		var account = BeamioNativeAccountPointer.get()
		if account.isEmpty {
			// Y.163 第 31、32 項: the one account is the one valid mnemonic; a private-key record is not an account.
			let inventory = BeamioNativeMnemonicInventory.read(store: store)
			guard inventory.enumerated, !inventory.readFailed, inventory.valid.count == 1 else { return nil }
			account = inventory.valid[0].eoa
		}
		guard var key = store.read(eoa: account) else { return nil }
		defer { BeamioNativeWallet.wipe(&key) }
		guard key.count == 32, BeamioNativeEthSigner.isValidKey([UInt8](key)),
		      let derived = BeamioNativeEthSigner.address(privateKey: [UInt8](key))?.lowercased(), derived == account
		else { return nil }
		BeamioNativeAccountPointer.set(derived)
		guard BeamioNativeAccountPointer.get() == derived else { return nil }
		return derived
	}

	// MARK: - Dependencies

	/// The registry read. Nil: the restore answers `not_supported` before any read.
	public static var registry: BeamioRecoveryRegistryReading? = BeamioRecoveryRegistry()

	public enum KeyDerivationError: Error, Equatable {
		/// The primitive is not in this build (the X-19 framework is not linked).
		case unavailable
		/// The parameters or the salt are out of the accepted range: the record is invalid.
		case parameters
	}

	/// argon2id, version 19, 32-byte output (step 6). The parameters come from the record.
	public protocol KeyDerivation {
		func argon2id(password: [UInt8], salt: [UInt8], m: Int, t: Int, p: Int) -> Result<[UInt8], KeyDerivationError>
	}

	/// The argon2id primitive: the X-19 wrapper.
	public static var keyDerivation: KeyDerivation? = BeamioRecoveryKDF()

	/// The failed-PIN count and the time of the last failure, kept on this device.
	public protocol PinAttemptStoring {
		func load() -> (failures: Int, lastFailure: Date?)
		func save(failures: Int, lastFailure: Date?)
	}

	public static var attempts: PinAttemptStoring = UserDefaultsPinAttempts()

	/// The clock of the cooldown. Tests replace it.
	public static var clock: () -> Date = { Date() }

	public struct BeamioRecoveryKDF: KeyDerivation {
		public init() {}

		public func argon2id(password: [UInt8], salt: [UInt8], m: Int, t: Int, p: Int) -> Result<[UInt8], KeyDerivationError> {
			#if canImport(X19)
			var failure: NSError?
			let out = X19Argon2IDKey(Data(password), Data(salt), m, t, p, 32, &failure)
			if failure != nil { return .failure(.parameters) }
			guard let out, out.count == 32 else { return .failure(.parameters) }
			return .success(Array(out))
			#else
			_ = (password, salt, m, t, p)
			return .failure(.unavailable)
			#endif
		}
	}

	public struct UserDefaultsPinAttempts: PinAttemptStoring {
		static let failuresKey = "beamio.recovery.pinFailures.v1"
		static let lastFailureKey = "beamio.recovery.pinLastFailure.v1"

		public init() {}

		public func load() -> (failures: Int, lastFailure: Date?) {
			let defaults = BeamioDefaults.standard
			return (defaults.integer(forKey: Self.failuresKey), defaults.object(forKey: Self.lastFailureKey) as? Date)
		}

		public func save(failures: Int, lastFailure: Date?) {
			let defaults = BeamioDefaults.standard
			defaults.set(failures, forKey: Self.failuresKey)
			if let lastFailure {
				defaults.set(lastFailure, forKey: Self.lastFailureKey)
			} else {
				defaults.removeObject(forKey: Self.lastFailureKey)
			}
		}
	}

	// MARK: - Engine

	private enum Path {
		case code(String)
		case account(String)
	}

	/// The recovery engine, both paths. The steps in order; the first failure ends the flow with its code.
	/// `store` is the native key store. The key is written only by the shared import path, after the checks.
	public static func restore(_ credential: Credential, store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> RestoreOutcome {
		// Step 1: a native key is on the device already. Nothing is read, nothing is overwritten.
		if hasNativeKey(store: store) { return .failed(.alreadyExists) }

		// Step 2: input. The KDF password is the UTF-8 code on path A (the PIN is empty), the password on path B.
		let path: Path
		var password: [UInt8]
		switch credential {
		case .recoveryCode(let raw):
			let text = asciiTrimmed(raw)
			guard isUUID62(text) else { return .failed(.invalidFormat) }
			path = .code(text)
			password = Array(text.utf8)
		case .account(let rawName, let rawPassword):
			let name = accountNameKey(rawName)
			guard !name.isEmpty, !rawPassword.isEmpty else { return .failed(.invalidFormat) }
			path = .account(name)
			password = rawPassword
		}
		defer { BeamioNativeWallet.wipe(&password) }

		// Path B, before any read: the cooldown after repeated bad PINs. Nothing is read or decrypted.
		if case .account = path {
			let state = attempts.load()
			let wait = BeamioPasscodeBackoff.cooldownSeconds(consecutiveFailures: state.failures)
			if wait > 0, let last = state.lastFailure {
				let remaining = last.addingTimeInterval(TimeInterval(wait)).timeIntervalSince(clock())
				if remaining > 0 { return .backoff(cooldownSec: Int(remaining.rounded(.up))) }
			}
		}

		// Steps 3 and 4: the one read. Only `eth_call`.
		guard let registry else { return .failed(.notSupported) }
		let current: Result<String, Error>
		switch path {
		case .code(let text):
			current = registry.recordByNameHash(BeamioNativeEthSigner.keccak256(Array(text.utf8)))
		case .account(let name):
			current = registry.recordByAccountName(name)
		}
		let base64: String
		switch current {
		case .failure: return .failed(.networkError)
		case .success(let value): base64 = value
		}
		if base64.isEmpty {
			// No record in the current registry is `not_found` on both paths. The pre-migration registry is retired and is not queried by path B
			// Its answer, and its failures, do not reach the page.
			return .failed(.notFound)
		}

		// Step 5: the record must decode, with the argon2id parameters and a non-empty `img`.
		guard let record = Record(base64JSON: base64) else { return .failed(.recordInvalid) }

		// Step 6: argon2id, then AES-256-GCM. Without the primitive nothing can be decided: `not_supported`.
		guard let kdf = keyDerivation else { return .failed(.notSupported) }
		var key: [UInt8]
		switch kdf.argon2id(password: password, salt: record.salt, m: record.m, t: record.t, p: record.p) {
		case .failure(.unavailable): return .failed(.notSupported)
		case .failure(.parameters): return .failed(.recordInvalid)
		case .success(let value): key = value
		}
		defer { BeamioNativeWallet.wipe(&key) }
		guard key.count == 32, let plain = open(record.combined, key: key) else {
			switch path {
			case .code:
				// The code locates the record by its hash, so a record that does not open is an invalid record.
				return .failed(.recordInvalid)
			case .account:
				let state = attempts.load()
				attempts.save(failures: state.failures + 1, lastFailure: clock())
				return .failed(.badPin)
			}
		}

		// Step 7: the plaintext is base64 of the phrase (UTF-8). It must be a valid BIP-39 phrase.
		guard let phraseBase64 = String(data: plain, encoding: .utf8),
		      let phraseData = Data(base64Encoded: phraseBase64),
		      let phrase = String(data: phraseData, encoding: .utf8)
		else { return .failed(.recordInvalid) }

		// Steps 8 to 10: derivation, the existing-key check, write and read-back, in the shared import path.
		switch BeamioNativeKeyImport.importRecoveryPhrase(text: phrase, expectedEoa: "", store: store) {
		case .imported:
			// Only `ok` clears the PIN failure count.
			if case .account = path { attempts.save(failures: 0, lastFailure: nil) }
			let account = BeamioNativeAccountPointer.get()
			return .ok(eoa: account)
		case .alreadyPresent: return .failed(.alreadyExists)
		case .invalidMnemonic, .invalidKey, .invalidFormat, .addressMismatch, .cancelled: return .failed(.recordInvalid)
		case .writeFailed: return .failed(.writeFailed)
		case .readBackFailed: return .failed(.readbackFailed)
		case .unavailable: return .failed(.writeFailed)
		case .rollbackPending: return .failed(.writeFailed)
		}
	}

	/// Restore by a recovery code only (path A). Kept for the page that has no account name.
	public static func restore(recoveryCode: String, store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> RestoreOutcome {
		restore(.recoveryCode(recoveryCode), store: store)
	}

	/// True when the device holds a native key: the account pointer names an account whose key is stored (step 1).
	static func hasNativeKey(store: BeamioChatWalletKeyStoring) -> Bool {
		let account = BeamioNativeAccountPointer.get()
		return !account.isEmpty && store.read(eoa: account) != nil
	}

	/// A uuid62 value: 22 characters of `[0-9A-Za-z]`, the form of `uuid62.v4`.
	static func isUUID62(_ text: String) -> Bool {
		text.count == 22 && text.unicodeScalars.allSatisfy { s in
			(0x30 ... 0x39).contains(s.value) || (0x41 ... 0x5A).contains(s.value) || (0x61 ... 0x7A).contains(s.value)
		}
	}

	/// The query key of a username (path B), the same normalisation as the PWA creation side (normalizeBeamioTagInput): every `@` removed, trimmed,
	/// NFKC, then the zero-width characters U+200B to U+200D and U+FEFF removed. Case is kept: the username is case-sensitive (requirement),
	/// so `Alice` and `alice` are different keys.
	static func accountNameKey(_ raw: String) -> String {
		let noAt = raw.replacingOccurrences(of: "@", with: "")
		let trimmed = asciiTrimmed(noAt)
		let normalised = trimmed.precomposedStringWithCompatibilityMapping
		var out = ""
		out.unicodeScalars.append(contentsOf: normalised.unicodeScalars.filter { scalar in
			!((0x200B ... 0x200D).contains(scalar.value) || scalar.value == 0xFEFF)
		})
		return out
	}

	/// Strips ASCII whitespace from both ends only.
	static func asciiTrimmed(_ text: String) -> String {
		let whitespace: Set<UInt32> = [0x20, 0x09, 0x0A, 0x0C, 0x0D]
		var scalars = Array(text.unicodeScalars)
		while let first = scalars.first, whitespace.contains(first.value) { scalars.removeFirst() }
		while let last = scalars.last, whitespace.contains(last.value) { scalars.removeLast() }
		var out = ""
		out.unicodeScalars.append(contentsOf: scalars)
		return out
	}

	/// The `{img, stored}` record (step 5,; the parameter bounds of as revised by: 8192 ≤ m ≤ 65536 KB,
	/// 1 ≤ t ≤ 10, 1 ≤ p ≤ 4, m ≥ 8p; and `v` = 19 by). A record outside the bounds is record_invalid before the KDF.: `img` is base64(iv ‖ ciphertext ‖ tag); `stored` holds
	/// `algo` = "argon2id", `v` = 19, the salt (base64), the cost parameters and the PIN hash (not used on this path).
	struct Record {
		var combined: Data
		var salt: [UInt8]
		var m: Int
		var t: Int
		var p: Int

		init?(base64JSON text: String) {
			guard let data = Data(base64Encoded: text),
			      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
			      let img = object["img"] as? String, let combined = Data(base64Encoded: img),
			      let stored = object["stored"] as? [String: Any],
			      stored["algo"] as? String == "argon2id",
			      stored["v"] as? Int == 19,
			      stored["hash"] is String,
			      let saltText = stored["salt"] as? String, let salt = Data(base64Encoded: saltText),
			      let m = stored["m"] as? Int, let t = stored["t"] as? Int, let p = stored["p"] as? Int,
			      combined.count >= 12 + 16,
			      (8192 ... 65536).contains(m), (1 ... 10).contains(t), (1 ... 4).contains(p), m >= 8 * p
			else { return nil }
			self.combined = combined
			self.salt = Array(salt)
			self.m = m
			self.t = t
			self.p = p
		}
	}

	/// AES-256-GCM: a 12-byte IV in front, a 16-byte tag at the end (the WebCrypto layout of the PWA). nil: not opened.
	static func open(_ combined: Data, key: [UInt8]) -> Data? {
		guard combined.count >= 12 + 16 else { return nil }
		do {
			let box = try AES.GCM.SealedBox(
				nonce: AES.GCM.Nonce(data: combined.prefix(12)),
				ciphertext: combined.dropFirst(12).dropLast(16),
				tag: combined.suffix(16)
			)
			return try AES.GCM.open(box, using: SymmetricKey(data: Data(key)))
		} catch {
			return nil
		}
	}
}
