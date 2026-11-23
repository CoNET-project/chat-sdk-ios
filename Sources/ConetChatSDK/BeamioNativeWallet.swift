import Foundation

/// The native wallet module: the one place in the SDK that holds an account's EOA private key.
///
/// - The key is read from the key store as Data, copied to [UInt8], and wiped (memset_s) when the call returns.
/// No key is ever a String, and nothing here writes to disk or to a log.
/// - Only the commands below exist. Each one checks that the stored key derives the requested account
///. Outputs are signatures, the protocol master (in memory only),
/// or the local root in process. Nothing returns a private key.
/// - PGP: C4 refuses every purpose (REGISTERED_PURPOSES is empty). C3 and the signing step wait for the
/// native OpenPGP library (BeamioPGPNative).
public enum BeamioNativeWallet {
	public enum Failure: Error, Equatable {
		case walletKeyMissing
		/// A passcode is set and the account is not unlocked (T-77).
		case locked
		/// Shape or whitelist check failed, or the key does not belong to the account. The payload is not echoed.
		case rejected(String)
		case signFailed
		/// The native capability is not built or approved yet.
		case pending(String)
		/// The key record exists and cannot be read. Not "no key".
		case storageUnreadable

		/// The fixed refusal code of the C4 function: a passcode lock is `pgp_locked`; an unreadable key record is `not_ready`.
		/// nil for the other failures, which carry no code of their own.
		public var refusalCode: String? {
			if case .locked = self { return "pgp_locked" }
			if case .storageUnreadable = self { return "not_ready" }
			return nil
		}
	}

	/// Key store: the Keychain in production, a memory store in tests.
	/// A swap of the store invalidates the native-key snapshot: the next session start judges the new store (25.52Y.70 第 4 項).
	public static var keyStore: BeamioChatWalletKeyStoring = BeamioPasscodeWalletStore.standard {
		didSet { BeamioNativeKeySnapshot.invalidate() }
	}

	/// ChatIndexRegistry EIP-712 domain chainId (PWA `REGISTRY_CHAIN_ID`); also the history EIP-191 domain chainId.
	public static let registryChainId = 224422

	// MARK: - W1 status

	public static func hasKey(eoa: String) -> Bool {
		BeamioChatWalletKeychain.hasKey(eoa: eoa, store: keyStore)
	}

	/// True when the account has a mnemonic record, whether or not it can be read now (Y.163 第 31、32 項). The gate uses this for the account of the
	/// record: a record that cannot be read is not "no record", so the gate is G1 or G2, never G0 (no_key). A private-key record alone is no record.
	public static func hasRecord(eoa: String) -> Bool {
		keyStore.mnemonicAccountState(owner: eoa) != .absent
	}

	/// True when this device holds a valid mnemonic account, or a mnemonic record that cannot be read or listed (fail closed). A private-key
	/// record alone does not count (Y.163 第 6 項 行 6, 第 31、32 項). An account pointer is not needed.
	public static func hasAnyRecord() -> Bool {
		BeamioNativeMnemonicInventory.read(store: keyStore).holdsRecord
	}

	// MARK: - C2 EIP-191 (gossip, envelope, selfAuth, chatRouteRegister, group, voice texts)

	public static func signEip191(eoa: String, message: String) -> Result<String, Failure> {
		withPrivateKey(eoa: eoa) { BeamioNativeEthSigner.signEip191(privateKey: $0, message: message) }
	}

	// MARK: - pointerEip712: SetPointer over the ChatIndexRegistry domain (the only typed-data command)

	/// `owner` must be the account; `indexHash` is 32 bytes; `ts` and `seq` are uint64 decimals; `nonce` is a uint256
	/// decimal. Returns the 65-byte signature as `0x` hex, v = 27/28.
	public static func signSetPointer(eoa: String, registry: String, indexHash: String,
	                                  ts: String, seq: String, nonce: String) -> Result<String, Failure> {
		guard let owner = BeamioNativeEip712.bytes(hex: eoa, count: 20),
		      let verifying = BeamioNativeEip712.bytes(hex: registry, count: 20),
		      let hash = BeamioNativeEip712.bytes(hex: indexHash, count: 32),
		      let tsValue = UInt64(ts), let seqValue = UInt64(seq),
		      let nonceValue = BeamioNativeEip712.uint256(decimal: nonce)
		else { return .failure(.rejected("set_pointer_shape")) }
		let digest = BeamioNativeEip712.setPointerDigest(
			chainId: registryChainId, verifyingContract: verifying, owner: owner, indexHash: hash,
			ts: tsValue, seq: seqValue, nonce: nonceValue
		)
		return withPrivateKey(eoa: eoa) { BeamioNativeEthSigner.signDigest(privateKey: $0, digest: digest) }
	}

	// MARK: - C1 protocol master (native memory only; the caller zeroes it on lock or logout)

	/// `master = keccak256(utf8(EIP-191 signature of "beamio.chat.history.v1|chainId|eoa"))`.
	/// `eoa` is used exactly as the caller spells it, because the domain string must match the other devices.
	public static func historyMaster(eoa rawEoa: String, chainId: Int) -> Data? {
		// The domain uses the lower-case account; a mixed-case account would give another root.
		let eoa = rawEoa.lowercased()
		// no master in G0 or G1 (the signature below would be refused anyway; this states the rule).
		guard answersValues(eoa: eoa) else { return nil }
		guard case .success(let domainSignature) = signEip191(
			eoa: eoa, message: "beamio.chat.history.v1|\(chainId)|\(eoa)"
		) else { return nil }
		return Keccak256.hash(Data(domainSignature.utf8))
	}

	// MARK: - C5 local root, in process only (the local library derives its subkeys from it)

	public static func localRoot(eoa: String) -> Data? {
		guard answersValues(eoa: eoa) else { return nil }
		return BeamioChatWalletBoundary.localRoot(eoa: eoa, store: keyStore)
	}

	// MARK: - PGP (pending: native OpenPGP library not approved)

	/// C4: refused for every purpose while REGISTERED_PURPOSES is empty. The signature type and the purpose
	/// are checked first, and no key is read. The caller never supplies the domain tag.
	public static func pgpSign(eoa: String, purposeId: String, sigType: UInt8, data: Data) -> Result<Data, Failure> {
		_ = data
		// the key record exists and cannot be read: not_ready, never no_key.
		if keyStore.keyRecordState(eoa: eoa) == .unreadable { return .failure(.storageUnreadable) }
		if let refusal = BeamioPGPPurpose.refusal(purposeId: purposeId, sigType: sigType) {
			return .failure(.rejected(refusal.rawValue))
		}
		// Unreachable while REGISTERED_PURPOSES is empty (step 3): the native domain tag and the signature go here.
		return .failure(.pending(BeamioPGPNative.pendingCode))
	}

	/// C3: only an OpenPGP message is accepted, never arbitrary text (refused before anything else). It works while the account is locked (the offer of
	/// a ringing call is opened; the PGP key is not under the wallet passcode). X-19 is approved for message decrypt, call-offer identity included (project owner, 2026-11-20). Failure classes:
	/// shape -> `rejected(pgp_message_shape)`; X-19 not linked -> `pending` (the caller never falls back to the WebView);
	/// PGP record present but unreadable -> `storageUnreadable` (not_ready, never "missing"); no record or another account -> `rejected(no_pgp_key)`;
	/// X-19 refuses the message or the key is corrupt -> `rejected(decrypt_failed)`. The key stays in this SDK and never reaches a log or the bridge.
	public static func pgpDecrypt(eoa rawEoa: String, message: Data) -> Result<Data, Failure> {
		guard isOpenPGPMessage(message) else { return .failure(.rejected("pgp_message_shape")) }
		// The PGP key is not protected by the wallet passcode, and a call that rings while the account is locked needs its offer opened (project owner,
		//): this decrypt does not refuse a locked account. Everything that uses the wallet key (signEip191, pgpSign, the payer
		// signature, the phrase) is still refused while locked.
		guard BeamioPGPNative.linked else { return .failure(.pending(BeamioPGPNative.pendingCode)) }
		// A record that exists and does not open is not "no key": it is not_ready (storageUnreadable). Only an absent record is no_pgp_key.
		if BeamioChatPgpKeychain.recordState(eoa: rawEoa) == .unreadable { return .failure(.storageUnreadable) }
		// The PGP private key is the one stored for this account in the Keychain. A different account is refused.
		guard let secrets = BeamioChatPgpKeychain.load(eoa: rawEoa), secrets.hasUserPrivate,
		      secrets.eoa.lowercased() == rawEoa.lowercased() else {
			return .failure(.rejected("no_pgp_key"))
		}
		guard let armored = String(data: message, encoding: .utf8) else {
			return .failure(.rejected("decrypt_failed"))
		}
		switch BeamioPGPNative.decryptArmoredText(privateArmor: secrets.privateKeyArmor, armoredMessage: armored) {
		case .plain(let plain): return .success(plain)
		case .notUTF8: return .failure(.rejected("plaintext_not_utf8"))
		case .failed: return .failure(.rejected("decrypt_failed"))
		}
	}

	/// The OpenPGP ASCII armour of a message: the only input C3 accepts.
	static func isOpenPGPMessage(_ data: Data) -> Bool {
		guard let text = String(data: data, encoding: .utf8) else { return false }
		let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
		return trimmed.hasPrefix("-----BEGIN PGP MESSAGE-----") && trimmed.hasSuffix("-----END PGP MESSAGE-----")
	}

	// MARK: - Memory hygiene

	/// Overwrites a byte array with zeros (memset_s, not optimised away).
	public static func wipe(_ bytes: inout [UInt8]) {
		BeamioNativeEthSigner.wipe(&bytes)
	}

	/// Overwrites a Data buffer with zeros. Copy-on-write makes this safe for shared storage.
	public static func wipe(_ data: inout Data) {
		#if BEAMIO_TEST_HOOKS
		let before = data.contains { $0 != 0 }
		#endif
		data.withUnsafeMutableBytes { buf in
			guard let base = buf.baseAddress, buf.count > 0 else { return }
			_ = memset_s(base, buf.count, 0, buf.count)
		}
		#if BEAMIO_TEST_HOOKS
		BeamioWipeProbe.record(count: data.count, hadNonZero: before, allZero: !data.contains { $0 != 0 }, address: nil)
		#endif
	}

	// MARK: - Private

	/// Loads the key for `eoa`, checks that it derives `eoa`, runs `body`, and wipes every copy before returning.
	private static func withPrivateKey(eoa rawEoa: String, _ body: ([UInt8]) -> String?) -> Result<String, Failure> {
		withAccountKey(eoa: rawEoa, body)
	}

	/// the wallet functions answer a value only in G2 for this account, that is, the session is ready and the record account is `eoa`.
	/// In G0 and G1 they answer nothing: no key material and no signature. The reply code is the gate's (`gateRefusal`: no_key in G0, not_ready in G1).
	static func answersValues(eoa rawEoa: String) -> Bool {
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty, BeamioConetChatModule.nativeGate() == .g2, BeamioConetChatModule.recordAccount() == eoa else { return false }
		return true
	}

	/// Runs `body` with the account's key, checked to derive the account, and wipes every copy before returning. Refused
	/// while locked. Used by the signing commands and by the route registration backup: the key bytes stay here.
	/// In G0 and G1 nothing is returned: the failure is `walletKeyMissing`, which carries no value.
	static func withAccountKey<T>(eoa rawEoa: String, _ body: ([UInt8]) -> T?) -> Result<T, Failure> {
		let eoa = rawEoa.lowercased()
		// G0 and G1 answer nothing. In G2 an account other than the session's is refused as before (account_mismatch), with no value.
		guard BeamioConetChatModule.nativeGate() == .g2 else { return .failure(.walletKeyMissing) }
		guard answersValues(eoa: eoa) else { return .failure(.rejected("account_mismatch")) }
		if let refusal = keyAccountGate(eoa: eoa) { return .failure(refusal) }
		return withAccountKeyUnchecked(eoa: eoa, body)
	}

	/// The key-level check (10633). The native key, the account the keychain names for the key record (attributes only) and the page copy's
	/// EOA must be one account. `matched`: they agree. `noKey`: no key record on this device. `mismatch`: they disagree, so the caller refuses
	/// (nothing signed, created, deleted or changed). `unknown`: the check cannot be made now, which fails closed.
	enum KeyAccountVerdict: Equatable {
		case matched
		case noKey
		case mismatch
		case unknown
	}

	/// With the account pointer set (25.52Y.14 第 6 项 (a)–(c); VR-19 requirement, 25.52Y.114 第 5 项 (§6(a) 方案 2)), the pointer's account
	/// decides, and other accounts' keys may sit on the device. Those keys are named, never read, used, deleted or overwritten here. The pointer's
	/// own key must be named and must read and derive the account: a missing key is a mismatch, an unreadable one is unknown (both fail closed).
	/// With the pointer empty, one key must be the account (10633); several keys are unknown, so init answers not_ready and writes no pointer (GZ.3).
	static func verifyKeyAccount(eoa rawEoa: String) -> KeyAccountVerdict {
		verifyKeyAccountWithReason(eoa: rawEoa).verdict
	}

	/// `verifyKeyAccount` with the reason code of its verdict (init diagnostics). A code only: never a key, an address or a record.
	/// The verdict is the same as before; only the reason is added.
	static func verifyKeyAccountWithReason(eoa rawEoa: String) -> (verdict: KeyAccountVerdict, reason: String) {
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty else { return (.unknown, "empty_account") }
		// Y.163 第 31、32 項: the owners are the valid mnemonic accounts; a private-key record is not an owner.
		let inventory = BeamioNativeMnemonicInventory.read(store: keyStore)
		guard inventory.enumerated else { return (.unknown, "enumerate_nil") }
		guard !inventory.readFailed else { return (.unknown, "key_read_failed") }
		let owners = inventory.valid.map { $0.eoa }
		if owners.isEmpty { return (.noKey, "no_owners") }
		let named = Set(owners.map { $0.lowercased() })
		if !BeamioNativeAccountPointer.get().isEmpty {
			guard BeamioNativeAccountPointer.get() == eoa else { return (.mismatch, "pointer_differs") }
			guard named.contains(eoa) else { return (.mismatch, "pointer_key_unnamed") }
		} else {
			if named.count > 1 { return (.unknown, "multi_key_no_pointer") }
			guard named == [eoa] else { return (.mismatch, "named_other") }
		}
		switch withAccountKeyUnchecked(eoa: eoa, { _ in true }) {
		case .success: return (.matched, "matched")
		case .failure(.rejected("account_mismatch")): return (.mismatch, "account_mismatch")
		case .failure(.storageUnreadable): return (.unknown, "key_read_failed")
		case .failure(.walletKeyMissing): return (.unknown, "key_read_nil")
		case .failure: return (.unknown, "key_other")
		}
	}

	/// The refusal of a signing that the key-level check does not pass: a mismatch refuses with `key_account_mismatch`, an unknown check fails
	/// closed. nil when the caller may go on. Only the code is logged.
	static func keyAccountGate(eoa: String) -> Failure? {
		switch verifyKeyAccount(eoa: eoa) {
		case .matched, .noKey: return nil
		case .mismatch:
			refuseKeyAccountMismatch(where: "signing")
			return .rejected("key_account_mismatch")
		case .unknown: return .storageUnreadable
		}
	}

	/// The refusal of a session start (init, no-page listen) by the key-level check, fail closed: nil only when the key matches or there is no key.
	/// `mismatch` answers needs_native_recovery; `unknown` answers not_ready. Nothing is created, deleted or changed.
	static func sessionStartRefusal(eoa: String, place: String) -> String? {
		let (verdict, reason) = verifyKeyAccountWithReason(eoa: eoa)
		switch verdict {
		case .matched, .noKey:
			NSLog("[BeamioNativeWallet] sessionStartRefusal place=%@ verdict=%@ reason=%@ answer=pass", place, "\(verdict)", reason)
			return nil
		case .mismatch:
			refuseKeyAccountMismatch(where: place)
			NSLog("[BeamioNativeWallet] sessionStartRefusal place=%@ verdict=%@ reason=%@ answer=needs_native_recovery", place, "\(verdict)", reason)
			return "needs_native_recovery"
		case .unknown:
			NSLog("[BeamioNativeWallet] sessionStartRefusal place=%@ verdict=%@ reason=%@ answer=not_ready", place, "\(verdict)", reason)
			return "not_ready"
		}
	}

	/// Records a key_account_mismatch refusal: a counter and the code. Never the account, the key or the record.
	static func refuseKeyAccountMismatch(where place: String) {
		BeamioKeyJudgementDiagnostics.note(.keyAccountMismatches)
		NSLog("[BeamioNativeWallet] key_account_mismatch at %@", place)
	}

	/// the storage-derived Locked state of an account: its key record exists and cannot be read. In this state nothing is installed,
	/// signed, or listened to.
	static func storageDerivedLocked(eoa rawEoa: String) -> Bool {
		keyStore.keyRecordState(eoa: rawEoa.lowercased()) == .unreadable
	}

	/// the listen authentication of the background path, for the listen session's own account. It is not a wallet function for the page:
	/// only the listen session calls it, never the bridge, and nothing is returned to the page. It needs a readable key record and no passcode lock; it does
	/// not need the session to be ready (G2).
	static func signListenAuth(eoa rawEoa: String, message: String) -> Result<String, Failure> {
		let eoa = rawEoa.lowercased()
		guard !eoa.isEmpty else { return .failure(.walletKeyMissing) }
		if let refusal = keyAccountGate(eoa: eoa) { return .failure(refusal) }
		switch keyStore.keyRecordState(eoa: eoa) {
		case .absent: return .failure(.walletKeyMissing)
		case .unreadable: return .failure(.storageUnreadable)
		case .present: break
		}
		return withAccountKeyUnchecked(eoa: eoa) { BeamioNativeEthSigner.signEip191(privateKey: $0, message: message) }
	}

	/// The key of `eoa`, read, checked to derive the account, passed to `body`, and wiped. No gate and no lock check: the callers judge those.
	static func withAccountKeyUnchecked<T>(eoa rawEoa: String, _ body: ([UInt8]) -> T?) -> Result<T, Failure> {
		let eoa = rawEoa.lowercased()
		guard var stored = keyStore.read(eoa: eoa) else {
			// A record that exists but gives no key now (unreadable, or a passcode record whose bundle has not been provided) is never "no key".
			return .failure(keyStore.keyRecordState(eoa: eoa) == .absent ? .walletKeyMissing : .storageUnreadable)
		}
		var key = [UInt8](stored)
		wipe(&stored)
		defer { wipe(&key) }
		guard BeamioNativeEthSigner.address(privateKey: key)?.lowercased() == eoa else {
			return .failure(.rejected("account_mismatch"))
		}
		guard let out = body(key) else { return .failure(.signFailed) }
		return .success(out)
	}
}
