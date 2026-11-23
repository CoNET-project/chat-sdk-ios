import Foundation

/// W7 `ephemeralSign`, the voice listen signature by the channel's random key, and the
/// registration of that key by `voiceEphemeralRegister` and its sealing by `voiceEphemeralSeal`.
///
/// - T is a random secp256k1 key made in the wallet layer for one voice channel and kept under its `sid` with its expiry (unix seconds).
/// It is never returned, never logged, and it is dropped when the session ends (`destroy`), when the passcode locks, when the wallet is
/// cleared, when a new session starts (account switch, re-init) and when the process restarts (memory only). Expired keys are not revived.
/// - The signature is used for one purpose only: `voiceListen`. The text is fixed by the engine: `conet.voice.sse.listen.v3|sid|wk|upper(relayKeyId)|
/// timestamp` (W-01). `voicePay` is signed by the account under W5 kind `voice`, never here (N-02).
/// - `voiceEphemeralSeal` returns T sealed to the recipient's OpenPGP key. The plaintext is the accept-text form `0x` + hex of T, the form the
/// page carries in `tk`; the sealed text is the only thing that leaves the native layer.
/// - Answers: `bad_request` for a malformed input, `unknown_channel` for a `sid` with no live key.
public enum BeamioVoiceEphemeral {
	enum Failure: Error, Equatable {
		case badRequest
		case unknownChannel
	}

	/// The outcome of `enroll`.
	enum EnrollOutcome: Equatable {
		case registered(temp: String)
		case sidExists
		case failed
	}

	/// One channel key. A key without an expiry (the test seams below) has `Int64.max`.
	private struct Entry {
		var key: Data
		let expiresAt: Int64
		/// The temporary PGP private key (armor, UTF-8 bytes) of a prepared channel with `needPgp`; nil otherwise. Memory only, wiped with the entry.
		var pgpPrivate: Data? = nil
	}

	/// The keys by `sid`. Memory only (X-15): a key lives until its channel ends, its expiry, or a clearing event.
	private static var keys: [String: Entry] = [:]
	private static let lock = NSLock()

	/// The longest life of a registration: expiresAt is at most now plus 24 hours.
	static let maxTTLSeconds: Int64 = 86400

	#if BEAMIO_TEST_HOOKS
	/// Test hook only: makes the key generation of a registration fail.
	static var testFailKeyGeneration = false

	/// Test hook only: the clock of the registration and of the expiry checks. nil reads the system clock.
	static var testClock: Int64?
	#endif

	/// Must run under `lock`: overwrites every secret of the entry with zeros and removes it.
	private static func dropLocked(_ sid: String) {
		guard keys[sid] != nil else { return }
		BeamioNativeWallet.wipe(&keys[sid]!.key)
		if keys[sid]!.pgpPrivate != nil { BeamioNativeWallet.wipe(&keys[sid]!.pgpPrivate!) }
		keys[sid] = nil
	}

	/// Must run under `lock`. Every key whose life has ended is overwritten with zeros and removed (a key that expires is not kept in memory until the
	/// channel set is cleared). A key with no expiry (the test seams) is never pruned here.
	private static func pruneExpiredLocked() {
		let current = now()
		for sid in Array(keys.keys) where keys[sid]!.expiresAt <= current { dropLocked(sid) }
	}

	/// The current unix time in seconds, for the expiry rules.
	static func now() -> Int64 {
		#if BEAMIO_TEST_HOOKS
		if let testClock { return testClock }
		#endif
		return Int64(Date().timeIntervalSince1970)
	}

	/// The fixed text of the voiceListen signature. `relayKeyId` is upper-cased; the rest is as given.
	static func listenText(sid: String, wk: String, relayKeyId: String, timestamp: Int) -> String {
		"conet.voice.sse.listen.v3|" + sid + "|" + wk + "|" + relayKeyId.uppercased() + "|" + String(timestamp)
	}

	/// The `sid` format: 32 lowercase hex characters.
	static func isSid(_ text: String) -> Bool {
		text.count == 32 && text.unicodeScalars.allSatisfy { (0x30 ... 0x39).contains($0.value) || (0x61 ... 0x66).contains($0.value) }
	}

	/// A canonical base64 string of 32 bytes (`wk`,).
	static func isWk(_ text: String) -> Bool {
		guard let data = Data(base64Encoded: text), data.count == 32 else { return false }
		return data.base64EncodedString() == text
	}

	/// Makes a new random channel key for `sid` in the wallet layer, with no expiry. Returns its address, or nil when `sid` is malformed.
	@discardableResult
	static func create(sid: String) -> String? {
		guard isSid(sid) else { return nil }
		guard var key = newKey() else { return nil }
		defer { BeamioNativeEthSigner.wipe(&key) }
		guard let address = BeamioNativeEthSigner.address(privateKey: key)?.lowercased() else { return nil }
		lock.lock()
		keys[sid] = Entry(key: Data(key), expiresAt: Int64.max)
		lock.unlock()
		return address
	}

	/// The registration of `sid`. A live registration with the same `expiresAt` answers its own address (idempotent). Another
	/// live registration answers `sidExists` and is kept. An expired one is replaced by a new key, never revived. The caller has validated
	/// `sid` and `expiresAt`.
	static func enroll(sid: String, expiresAt: Int64) -> EnrollOutcome {
		guard isSid(sid) else { return .failed }
		let current = now()
		lock.lock()
		pruneExpiredLocked()
		let existing = keys[sid]
		lock.unlock()
		if let existing, existing.expiresAt > current {
			guard existing.expiresAt == expiresAt else { return .sidExists }
			var key = [UInt8](existing.key)
			defer { BeamioNativeEthSigner.wipe(&key) }
			guard let temp = BeamioNativeEthSigner.address(privateKey: key)?.lowercased() else { return .failed }
			return .registered(temp: temp)
		}
		guard var key = newKey() else { return .failed }
		defer { BeamioNativeEthSigner.wipe(&key) }
		guard let temp = BeamioNativeEthSigner.address(privateKey: key)?.lowercased() else { return .failed }
		lock.lock()
		keys[sid] = Entry(key: Data(key), expiresAt: expiresAt)
		lock.unlock()
		return .registered(temp: temp)
	}

	#if BEAMIO_TEST_HOOKS
	/// Sets the key of `sid` with no expiry (the test seams). The key must be a valid secp256k1 key.
	@discardableResult
	static func register(sid: String, privateKey: [UInt8]) -> Bool {
		guard isSid(sid), BeamioNativeEthSigner.isValidKey(privateKey) else { return false }
		lock.lock()
		dropLocked(sid)
		keys[sid] = Entry(key: Data(privateKey), expiresAt: Int64.max)
		lock.unlock()
		return true
	}
	#endif

	/// The channel ended: its key bytes are overwritten with zeros and the key is dropped. A `sid` with no key is a no-op.
	///
	/// Calling convention for the shell (public, native, not a bridge command): when a call ends (ActiveCall ends, for any reason), call
	/// `BeamioVoiceEphemeral.clear(sid:)` once for every channel `sid` that the call holds. The key is used for the one call only; nothing is kept or
	/// restored afterwards.
	public static func clear(sid: String) {
		lock.lock()
		dropLocked(sid)
		lock.unlock()
	}

	/// The shell's call-end hook (public, native, not a bridge command; idempotent): the call that ended held these channel `sid`s; each key is overwritten
	/// with zeros and removed. A `sid` with no key, or a malformed one, is ignored. Use this when an ActiveCall ends, for any reason.
	public static func clearCall(sids: [String]) {
		for sid in sids { clear(sid: sid) }
	}

	/// Every registration is dropped: the session ended, the passcode locked, the wallet was cleared, or a new session started.
	static func clearAll() {
		lock.lock()
		for sid in Array(keys.keys) { dropLocked(sid) }
		lock.unlock()
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook only: how many channel keys are held in memory.
	static var heldCountForTests: Int { lock.lock(); defer { lock.unlock() }; return keys.count }
	#endif

	/// The voiceListen signature for `sid`: `{temp, tempSig}` with `temp` the lowercase address of T. An expired key is not used.
	static func sign(sid: String, wk: String, relayKeyId: String, timestamp: Int) -> Result<(temp: String, tempSig: String), Failure> {
		guard isSid(sid), isWk(wk), !relayKeyId.isEmpty, timestamp >= 0 else { return .failure(.badRequest) }
		guard var key = liveKey(sid: sid) else { return .failure(.unknownChannel) }
		defer { BeamioNativeEthSigner.wipe(&key) }
		guard let temp = BeamioNativeEthSigner.address(privateKey: key)?.lowercased(),
		      let signature = BeamioNativeEthSigner.signEip191(
		          privateKey: key, message: listenText(sid: sid, wk: wk, relayKeyId: relayKeyId, timestamp: timestamp))
		else { return .failure(.badRequest) }
		return .success((temp, signature))
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook only (project owner's alternative A, 2026-11-21): no release code can read T out; the accept text of T stays for the legacy seal tests.
	/// The accept-text form of T (`0x` + hex) for `voiceEphemeralSeal`, for a live registration. The caller seals it at once.
	static func acceptText(sid: String) -> Result<String, Failure> {
		guard var key = liveKey(sid: sid) else { return .failure(.unknownChannel) }
		defer { BeamioNativeEthSigner.wipe(&key) }
		return .success("0x" + key.map { String(format: "%02x", $0) }.joined())
	}
	#endif

	// MARK: - Per-call channel keys (v109 section 119)

	/// The codes of the per-call entries (v109 section 119.3). None of them falls back to a page key or to the long-term chat PGP key.
	public enum EphemeralError: String, Error, Equatable {
		case notReady = "not_ready"
		case keygenFailed = "keygen_failed"
		case badRequest = "bad_request"
		case unknownSid = "unknown_sid"
		case decryptFailed = "decrypt_failed"
	}

	/// The public part of a prepared channel. `key` and `wk` are the 32-byte channel keys (canonical base64) that the call packs into its offer or accept;
	/// `temp` is the lower-case address of the temporary wallet; `tempPgpFpr` is the OpenPGP v4 primary fingerprint (40 lower-case hex, empty without
	/// a temporary PGP) and `tempPgpArmor` its public key. No private key is in it.
	public struct Channel: Equatable {
		public let sid: String
		public let key: String
		public let wk: String
		public let temp: String
		public let tempPgpFpr: String
		public let tempPgpArmor: String?
	}

	/// `voiceEphemeralPrepare`: makes, in memory and from the system CSPRNG, the temporary wallet key and, with `needPgp`, a temporary OpenPGP key
	/// (v4, curve25519, no passphrase, through X-19) for `sid`, and the two 32-byte channel keys. Nothing is derived from the mnemonic, the wallet, or the
	/// long-term chat PGP. A `sid` that already holds a key is refused (`bad_request`): a key is never replaced silently. The private keys stay here.
	public static func prepare(role: String, sid: String, needPgp: Bool) -> Result<Channel, EphemeralError> {
		guard role == "caller" || role == "callee", isSid(sid) else { return .failure(.badRequest) }
		lock.lock()
		pruneExpiredLocked()
		let taken = keys[sid] != nil
		lock.unlock()
		if taken { return .failure(.badRequest) }
		guard var wallet = newKey(), var aes = randomBytes(32), var wk = randomBytes(32) else { return .failure(.keygenFailed) }
		defer { BeamioNativeEthSigner.wipe(&wallet); BeamioNativeEthSigner.wipe(&aes); BeamioNativeEthSigner.wipe(&wk) }
		guard let temp = BeamioNativeEthSigner.address(privateKey: wallet)?.lowercased() else { return .failure(.keygenFailed) }
		var pgpPrivate: Data?
		var fingerprint = ""
		var publicArmor: String?
		if needPgp {
			#if BEAMIO_TEST_HOOKS
			if testFailKeyGeneration { return .failure(.keygenFailed) }
			#endif
			guard BeamioPGPNative.available, case .success(let pair) = BeamioPGPNative.generateKeyPair(name: "beamio-call-" + sid.prefix(8)),
			      let identity = BeamioPGPBackup.keyIdentity(armor: pair.publicArmor)
			else { return .failure(.keygenFailed) }
			pgpPrivate = Data(pair.privateArmor.utf8)
			// the fingerprint is computed here (RFC 4880) and must agree with X-19's, or the channel is not offered
			guard let own = BeamioPGPFingerprint.fingerprint(armor: pair.publicArmor), own == identity.fingerprint.lowercased() else { return .failure(.keygenFailed) }
			fingerprint = own
			publicArmor = pair.publicArmor.trimmingCharacters(in: .whitespacesAndNewlines)
			guard fingerprint.count == 40 else {
				if pgpPrivate != nil { BeamioNativeWallet.wipe(&pgpPrivate!) }
				return .failure(.keygenFailed)
			}
		}
		let expires = now() + maxTTLSeconds
		lock.lock()
		if keys[sid] != nil { // a concurrent prepare for the same sid won: this one gives up and wipes what it made
			lock.unlock()
			if pgpPrivate != nil { BeamioNativeWallet.wipe(&pgpPrivate!) }
			return .failure(.badRequest)
		}
		keys[sid] = Entry(key: Data(wallet), expiresAt: expires, pgpPrivate: pgpPrivate)
		lock.unlock()
		return .success(Channel(sid: sid, key: Data(aes).base64EncodedString(), wk: Data(wk).base64EncodedString(), temp: temp,
		                        tempPgpFpr: fingerprint, tempPgpArmor: publicArmor))
	}

	/// `voiceEphemeralForget`: overwrites and removes every private key held for `sid`. Idempotent: a `sid` that holds nothing, or a malformed one, is `ok`.
	public static func forget(sid: String) { clear(sid: sid) }

	/// The EIP-191 signature of `text` by the temporary wallet key of `sid` (the voice_listen `tempSig`; the text is the shell's, the SDK does not read it).
	public static func tempSig(sid: String, text: String) -> Result<String, EphemeralError> {
		guard isSid(sid), !text.isEmpty else { return .failure(.badRequest) }
		guard var key = liveKey(sid: sid) else { return .failure(.unknownSid) }
		defer { BeamioNativeEthSigner.wipe(&key) }
		guard let signature = BeamioNativeEthSigner.signEip191(privateKey: key, message: text) else { return .failure(.keygenFailed) }
		return .success(signature)
	}

	/// The plaintext of an inner-layer message for the temporary OpenPGP key of `sid` (nothing is interpreted). `unknown_sid`: no key for `sid` (never
	/// prepared with `needPgp`, forgotten, or expired); `decrypt_failed`: this message does not open with that key (the caller drops the packet and counts nothing).
	public static func decryptInner(sid: String, armor: String) -> Result<String, EphemeralError> {
		guard isSid(sid), armor.contains("BEGIN PGP MESSAGE") else { return .failure(.badRequest) }
		lock.lock()
		pruneExpiredLocked()
		let held = keys[sid]?.pgpPrivate.map { [UInt8]($0) }
		lock.unlock()
		guard var bytes = held else { return .failure(.unknownSid) }
		defer { BeamioNativeEthSigner.wipe(&bytes) }
		guard BeamioPGPNative.available else { return .failure(.notReady) }
		// the private armor reaches X-19 as a string for the length of the call; the string cannot be overwritten (residual, as for the long-term key)
		switch BeamioPGPNative.decryptArmoredText(privateArmor: String(decoding: bytes, as: UTF8.self), armoredMessage: armor) {
		case .plain(let data): return .success(String(decoding: data, as: UTF8.self))
		case .notUTF8, .failed: return .failure(.decryptFailed)
		}
	}

	/// The OpenPGP v4 fingerprint of an armored public key, 40 lower-case hex characters (RFC 4880 section 12.2: SHA-1 of `0x99 || 2-byte length || the
	/// primary public-key packet body`; the primary key, not a subkey). nil for anything that is not an armored v4 public key. No X-19 needed. The shell
	/// uses it to check the `tempPgpFpr` of a peer's channel (section 108.7) against the armor that came with it.
	public static func fingerprint(armor: String) -> String? { BeamioPGPFingerprint.fingerprint(armor: armor) }

	/// `count` random bytes from the system CSPRNG, or nil when it fails (no other source).
	private static func randomBytes(_ count: Int) -> [UInt8]? {
		var bytes = [UInt8](repeating: 0, count: count)
		guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { return nil }
		return bytes
	}

	/// The key of a live registration: present, and not expired at the current time.
	private static func liveKey(sid: String) -> [UInt8]? {
		let current = now()
		lock.lock()
		pruneExpiredLocked()
		let entry = keys[sid]
		lock.unlock()
		guard let entry, entry.expiresAt > current else { return nil }
		return [UInt8](entry.key)
	}

	/// A new random valid key. The caller wipes it.
	private static func newKey() -> [UInt8]? {
		#if BEAMIO_TEST_HOOKS
		if testFailKeyGeneration { return nil }
		#endif
		var key = [UInt8](repeating: 0, count: 32)
		repeat {
			guard SecRandomCopyBytes(kSecRandomDefault, key.count, &key) == errSecSuccess else { return nil }
		} while !BeamioNativeEthSigner.isValidKey(key)
		return key
	}
}
