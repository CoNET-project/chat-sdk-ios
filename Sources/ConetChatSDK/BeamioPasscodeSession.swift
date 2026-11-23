import CryptoKit
import Foundation

/// App state for the passcode. Unknown storage state must never be treated as NO_PASSCODE.
///
/// The unlocked bundle (the EOA key) is held here, in memory only. It is wiped when the account is locked. A cold start
/// starts with nothing unlocked, so the state is LOCKED for an account that has a passcode.
public enum BeamioPasscodeAppState: String, Equatable {
	case noPasscode = "NO_PASSCODE"
	case locked = "LOCKED"
	case unlocked = "UNLOCKED"
	case unknown = "UNKNOWN"
}

public final class BeamioPasscodeSession {
	public static let shared = BeamioPasscodeSession()

	private let lock = NSLock()
	private var bundles: [String: [UInt8]] = [:]
	/// The P key of an unlocked passcode record, kept in memory with the bundle and wiped with it, so the phrase can be read again without
	/// asking for the passcode (frozen protocol §7).
	private var mnemonicKeys: [String: [UInt8]] = [:]
	/// A monotonic count per account: an unlock does not move it; a lock, a logout and an account switch do, inside the same critical section that wipes
	/// the keys. A signature that was prepared under generation g0 is made only while the count is still g0 (checked by the caller before signing).
	private var generations: [String: Int] = [:]

	/// The vault that tells whether a passcode is set. Production: the standard vault.
	public var vault: BeamioPasscodeVault? = BeamioPasscodeVault.standard

	public init() {}

	public func appState(eoa rawEoa: String) -> BeamioPasscodeAppState {
		let eoa = rawEoa.lowercased()
		guard let vault else { return .unknown }
		switch vault.protectionState(eoa: eoa) {
		case .absent, .device:
			return .noPasscode
		case .unavailable:
			return .unknown
		case .passcode:
			break
		}
		lock.lock()
		defer { lock.unlock() }
		return bundles[eoa] == nil ? .locked : .unlocked
	}

	/// True when a passcode is set and the account is not unlocked. Wallet and chat commands are refused then (T-77).
	public func isLocked(eoa rawEoa: String) -> Bool {
		switch appState(eoa: rawEoa) {
		case .locked, .unknown: return true
		case .noPasscode, .unlocked: return false
		}
	}

	/// Keeps an unlocked bundle for the account. The caller has its own copy, which it wipes.
	public func install(eoa rawEoa: String, bundle: [UInt8], mnemonicKey: [UInt8]? = nil) {
		// an unlock refreshes the native-key snapshot (25.52Y.70 第 4 項): the refresh runs after this lock is released.
		BeamioNativeKeySnapshot.mutate {
			let eoa = rawEoa.lowercased()
			lock.lock()
			defer { lock.unlock() }
			BeamioNativeWallet.wipe(&bundles[eoa, default: []])
			// the session holds its own storage (never the caller's buffer), so a later wipe overwrites these very bytes and not a copy
			bundles[eoa] = Self.ownedCopy(bundle)
			BeamioNativeWallet.wipe(&mnemonicKeys[eoa, default: []])
			mnemonicKeys[eoa] = mnemonicKey.map { Self.ownedCopy($0) }
		}
	}

	/// A byte array in storage that nothing else references.
	private static func ownedCopy(_ bytes: [UInt8]) -> [UInt8] {
		[UInt8](unsafeUninitializedCapacity: bytes.count) { buffer, count in
			bytes.withUnsafeBufferPointer { source in
				if let from = source.baseAddress, let to = buffer.baseAddress { to.update(from: from, count: bytes.count) }
			}
			count = bytes.count
		}
	}

	// MARK: - Incoming calls (addenda 13, 14): the call the shell fulfilled, per account and generation. The shell calls these natively; they are not bridge commands.

	private var incomingCalls: [String: (eoa: String, gen: Int)] = [:]
	/// Accounts whose UI is locked (the native session is not). Set by `uiLock()`, cleared by a passcode unlock of that account.
	private var uiLocked: Set<String> = []
	/// Calls whose UI lock was opened by a `passcodeUnlock` that carried the call (supplement 2.3 B iii).
	private var callUiUnlocked: Set<String> = []

	/// The shell fulfilled an incoming call for `eoa`: the call is remembered with the generation of that moment.
	/// Returns false, and registers nothing, for a call id outside 8 to 128 characters of `[A-Za-z0-9_-]` (addendum 25) or an account that is not an
	/// address: the shell ends that call as `cancelled`, so a registered call is never one that an unlock would discard for its format.
	public func bindIncomingCall(callId: String, eoa rawEoa: String) -> Bool {
		guard BeamioShellPasscodeCommands.validCallId(callId) != nil, let eoa = BeamioShellPasscodeCommands.normalizedEoa(rawEoa) else { return false }
		lock.lock(); defer { lock.unlock() }
		incomingCalls[callId] = (eoa, generations[eoa, default: 0])
		return true
	}

	/// The call ended or reached a terminal code: forgotten. An unknown call is a no-op.
	public func unbindIncomingCall(callId: String) {
		lock.lock(); defer { lock.unlock() }
		incomingCalls[callId] = nil
		callUiUnlocked.remove(callId)
	}

	public enum AnswerAuthorization: String { case allow, deny }

	/// Native, not a bridge command (addendum 22): the shell asks before it signs the answer of an incoming call.: the SDK keeps no
	/// UI lock, no unlock mark and no generation rule. `allow` only when the call is still bound and the current native account is the bound account;
	/// anything else, an unreadable pointer included, is `deny`. Whether the UI may answer is the UI's own rule.
	public func incomingCallAuthorizeAnswer(callId: String) -> AnswerAuthorization {
		lock.lock()
		let bound = incomingCalls[callId]
		lock.unlock()
		guard let bound, case .value(let pointed) = BeamioNativeAccountPointer.read(), pointed == bound.eoa else { return .deny }
		return .allow
	}

	/// Kept for the shell's calls only.: the SDK keeps no UI lock; this does nothing and sends no event.
	public func uiLock() {}

	/// Kept for the callers of an unlock only; nothing is recorded.
	func markUiUnlocked(eoa rawEoa: String, callId: String?) {}

	/// The SDK keeps no UI lock.
	func isUiLocked(eoa: String) -> Bool { false }

	/// The account and generation a call was bound with, or nil when the call is not bound.
	public func incomingCall(callId: String) -> (eoa: String, gen: Int)? {
		lock.lock(); defer { lock.unlock() }
		return incomingCalls[callId]
	}

	#if BEAMIO_TEST_HOOKS
	/// Test hook: the storage addresses of the held bundle and mnemonic key.
	func storedAddressesForTests(eoa: String) -> (bundle: UInt?, mnemonicKey: UInt?) {
		lock.lock(); defer { lock.unlock() }
		func address(_ b: [UInt8]?) -> UInt? { b?.withUnsafeBufferPointer { $0.baseAddress.map { UInt(bitPattern: $0) } } }
		return (address(bundles[eoa.lowercased()]), address(mnemonicKeys[eoa.lowercased()]))
	}
	#endif

	/// A copy of the unlocked bundle, or nil while locked. The caller wipes the copy after use.
	public func bundle(eoa rawEoa: String) -> Data? {
		lock.lock()
		defer { lock.unlock() }
		guard let b = bundles[rawEoa.lowercased()] else { return nil }
		return Data(b)
	}

	/// The generation of an account (0 until its first lock, logout or switch).
	public func generation(eoa rawEoa: String) -> Int {
		lock.lock()
		defer { lock.unlock() }
		return generations[rawEoa.lowercased(), default: 0]
	}

	/// A copy of the P key of an unlocked passcode record, or nil. The caller wipes the copy.
	func mnemonicKey(eoa rawEoa: String) -> Data? {
		lock.lock()
		defer { lock.unlock() }
		guard let k = mnemonicKeys[rawEoa.lowercased()] else { return nil }
		return Data(k)
	}

	/// Why the sessions end (and, for `uiLock`, why they do not). Since the project owner's rule "the native unlock lasts until the next cold start"
	/// `uiLock` is the UI locking itself. It changes nothing in the native session (no wipe, no generation) and only
	/// records that the UI is locked, for the answer authorization. `lock` stays as the native session end (a process end, and the tests that build a
	/// locked wallet); the shell calls `uiLock()` for the UI lock, never `lockAll()`.
	///
	/// Threat note: the unlocked key bundle, the mnemonic key and the keys derived from it (local library, history master) now stay in process memory
	/// until the process ends (or a logout, account switch, passcode change or disable), not until the UI locks. This is the owner's decision; the
	/// exposure window moves from "until the UI lock" to "until the process ends". A cold start inherits nothing.
	///
	/// Earlier text for `lock`: (the same account, the pointer unchanged, an unlocked session turns locked) wipes only the secrets of the wallet and
	/// of the passcode session; a call that is ringing keeps its voice registration and the listen (project owner). The registration,
	/// the OpenPGP page and the listen go only with `accountSwitch` and `logout`. `passcodeChange` and `passcodeDisable` replace the session keys and
	/// end nothing else.
	public enum LockReason {
		case lock, uiLock, accountSwitch, logout, passcodeChange, passcodeDisable

		var endsCallResources: Bool { self == .accountSwitch || self == .logout }

		/// The value of `reason` in the `passcodeState` event.
		public var eventValue: String {
			switch self {
			case .lock: return "lock"
			case .uiLock: return "ui_lock"
			case .accountSwitch: return "account_switch"
			case .logout: return "logout"
			case .passcodeChange: return "passcode_change"
			case .passcodeDisable: return "passcode_disable"
			}
		}
	}

	/// The `passcodeState` payload for `eoa`. `set` and `locked` are carried only when the state is known (no value stands in for an unknown one: a state
	/// that cannot be read leaves both out). `reason` only for the end of a session.
	func statePayload(eoa: String?, reason: LockReason?) -> [String: Any] {
		var payload: [String: Any] = ["type": "passcodeState"]
		if let eoa, !eoa.isEmpty {
			switch appState(eoa: eoa) {
			case .noPasscode: payload["set"] = false; payload["locked"] = false
			case .locked: payload["set"] = true; payload["locked"] = true
			case .unlocked: payload["set"] = true; payload["locked"] = false
			case .unknown: break
			}
		}
		if let reason { payload["reason"] = reason.eventValue }
		return payload
	}

	/// Locks every account: the unlocked bundles are overwritten with zeros, then dropped. The keys are wiped first and the event is sent after, inside
	/// the same critical section of the native-key snapshot, so nothing can observe the event while a key is still held. `lock` is sent only when an
	/// unlocked session turned locked (never at a cold start); the other reasons are sent whenever the call is made.
	public func lockAll(reason: LockReason = .lock) {
		if reason == .uiLock { uiLock(); return }
		// method Y: a lock, a logout and a passcode change drop every held key; an account switch drops those of the accounts left behind (the pointer is already the new one)
		if reason == .accountSwitch { BeamioCipherUnlock.clear(keeping: BeamioNativeAccountPointer.get()) } else { BeamioCipherUnlock.clear() }
		// a lock refreshes the native-key snapshot (25.52Y.70 第 4 項), after the bundles are gone.
		BeamioNativeKeySnapshot.mutate {
			var hadSession = false
			do {
				lock.lock()
				defer { lock.unlock() }
				hadSession = !bundles.isEmpty
				if reason == .logout || reason == .accountSwitch || (reason == .lock && hadSession) {
					// every account that held a session, and the account the pointer names (its session may already be gone)
					var accounts = Set(bundles.keys).union(mnemonicKeys.keys).union(generations.keys)
					if case .value(let pointed) = BeamioNativeAccountPointer.read() { accounts.insert(pointed) }
					for account in accounts { generations[account, default: 0] += 1 }
				}
				for key in Array(bundles.keys) {
					BeamioNativeWallet.wipe(&bundles[key, default: []])
				}
				// a logout or an account switch ends every bound incoming call (addendum 13); a plain lock keeps them
				if reason == .logout || reason == .accountSwitch { incomingCalls.removeAll(); callUiUnlocked.removeAll(); uiLocked.removeAll() }
				bundles.removeAll()
				for key in Array(mnemonicKeys.keys) { BeamioNativeWallet.wipe(&mnemonicKeys[key, default: []]) }
				mnemonicKeys.removeAll()
			}
			// the keys that were derived from the wallet key and sit in memory (local library, history master) are wiped with the session.
			BeamioConetChatModule.lockDerivedKeys()
			// the event, after the keys are gone
			if reason != .lock || hadSession {
				var pointed: String?
				if case .value(let p) = BeamioNativeAccountPointer.read() { pointed = p }
				if reason != .lock || pointed != nil {
					BeamioConetChatModule.emitPasscodeStateEvent(statePayload(eoa: pointed, reason: reason))
				}
			}
			guard reason.endsCallResources else { return }
			// an account switch or a logout ends every voice registration,
			BeamioVoiceEphemeral.clearAll()
			// the OpenPGP page goes with it (asynchronous, so the lock held here is not needed by it),
			BeamioOpenPgpHost.shared.tearDown(reason: "lock")
			// and the running listen loop ends too (asynchronous as well).
			BeamioConetChatModule.stopListenForLock()
		}
	}
}

/// The wallet key store (BeamioChatWalletKeyStoring) over the passcode vault.
///
/// - A device record (no passcode): the key is wrapped by H only. Reads unwrap it.
/// - A passcode record: the key is wrapped by P around H. There is no key in memory until the account is unlocked; reads
/// return the unlocked bundle, and nil while locked.
/// - No record yet: a key from the older store (`legacy`, the published `walletKey` item) is only read: it is not moved to a device record and the old item
/// is not deleted. Nothing is written.
/// - Writes never downgrade: while a passcode is set, a write is refused.
/// - Migration phases (X-21) stay in the legacy store.
public final class BeamioPasscodeWalletStore: BeamioChatWalletKeyStoring {
	public static let standard = BeamioPasscodeWalletStore(
		records: BeamioPasscodeKeychainRecords.standard,
		hardware: BeamioPasscodeKeychainHardware.standard,
		legacy: BeamioChatWalletKeychainStore.standard,
		session: BeamioPasscodeSession.shared
	)

	private let records: BeamioPasscodeRecordStoring
	private let hardware: BeamioPasscodeHardwareKeyStoring
	private let legacy: BeamioChatWalletKeyStoring
	private let session: BeamioPasscodeSession

	public init(records: BeamioPasscodeRecordStoring, hardware: BeamioPasscodeHardwareKeyStoring,
	            legacy: BeamioChatWalletKeyStoring, session: BeamioPasscodeSession) {
		self.records = records
		self.hardware = hardware
		self.legacy = legacy
		self.session = session
	}

	/// The state of the key record. A device record that cannot be unwrapped, or a record that cannot be decoded, is unreadable. A passcode
	/// record is present: its lock is judged by the gate, not here.
	public func keyRecordState(eoa rawEoa: String) -> BeamioChatWalletKeyRecordState {
		let eoa = rawEoa.lowercased()
		switch records.readRecordState(eoa: eoa) {
		case .unavailable:
			return .unreadable
		case .present(let raw):
			guard let r = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw) else { return .unreadable }
			if r.mode == "device" {
				guard var key = try? hardware.unwrap(r.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else { return .unreadable }
				BeamioNativeWallet.wipe(&key)
				return .present
			}
			return .present
		case .absent:
			let published = legacy.keyRecordState(eoa: eoa)
			if published != .absent { return published }
			// no published key record: a no-passcode set of this owner stands in as the key source (the key is derived in memory, never stored)
			guard let raw = rawLegacyStore else { return .absent }
			switch BeamioMnemonicSets.readSet(store: raw, eoa: eoa) {
			case .absent:
				// method Y: the account of a v3 envelope has a key only while its session is unlocked; locked, the key cannot be read yet (never "absent")
				if case .cipher(let held, _) = BeamioMnemonicSets.current(store: raw), held == eoa {
					return BeamioCipherUnlock.isUnlocked(eoa: eoa) ? .present : .unreadable
				}
				return .absent
			case .unreadable, .damaged: return .unreadable
			case .phrase: return BeamioMnemonicSets.derivedKey(store: raw, eoa: eoa) == nil ? .unreadable : .present
			}
		}
	}

	/// Any key record of this store, for any account: a passcode record or a legacy record. Fail closed: a layer that cannot
	/// enumerate answers true.
	public func hasAnyKeyRecord() -> Bool {
		records.hasAnyRecord() || legacy.hasAnyKeyRecord()
	}

	/// The owners of every record, from the record attributes only. nil when a layer cannot name its records.
	public func enumerateKeyOwners() -> [String]? {
		guard let owners = records.enumerateRecordOwners(), let legacyOwners = legacy.enumerateKeyOwners() else { return nil }
		return owners.map { $0.lowercased() } + legacyOwners.map { $0.lowercased() }
	}

	/// The creation time of every key record: the passcode and device records, then the legacy records (Y.163 第 5 項). nil when a layer cannot list.
	public func enumerateKeyCreations() -> [BeamioChatKeyCreation]? {
		guard let owners = records.enumerateRecordCreations(), let legacyCreations = legacy.enumerateKeyCreations() else { return nil }
		return owners.map { BeamioChatKeyCreation(owner: $0.owner.lowercased(), created: $0.created) }
			+ legacyCreations.map { BeamioChatKeyCreation(owner: $0.owner.lowercased(), created: $0.created) }
	}

	/// Every key record of this store: the passcode and device records, then the legacy records. nil when a layer cannot enumerate.
	public func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? {
		guard let owners = records.enumerateRecordOwners(), let legacyEntries = legacy.enumerateKeyEntries() else { return nil }
		return owners.map { checkRecord(owner: $0) } + legacyEntries
	}

	/// One passcode or device record. A passcode record whose passcode is locked is `locked`, not judged.
	private func checkRecord(owner rawOwner: String) -> BeamioChatKeyEntryCheck {
		let eoa = rawOwner.lowercased()
		guard let raw = records.readRecord(eoa: eoa) else { return .unavailable }
		guard let r = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw) else { return .corrupt }
		var key: Data
		if r.mode == "device" {
			guard let unwrapped = try? hardware.unwrap(r.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else { return .unavailable }
			key = unwrapped
		} else {
			guard let bundle = session.bundle(eoa: eoa) else {
				return session.appState(eoa: eoa) == .locked ? .locked(eoa: eoa) : .unavailable
			}
			key = bundle
		}
		defer { BeamioNativeWallet.wipe(&key) }
		guard key.count == 32, let address = BeamioNativeEthSigner.address(privateKey: [UInt8](key)), address.lowercased() == eoa else {
			return .corrupt
		}
		return .valid(eoa: eoa)
	}

	public func read(eoa rawEoa: String) -> Data? {
		let eoa = rawEoa.lowercased()
		let raw: Data
		switch records.readRecordState(eoa: eoa) {
		case .unavailable: return nil
		case .present(let record): raw = record
		case .absent:
			// (2026): the key of the older store (the published `walletKey` item of chat-sdk-ios 0.1.8) is only
			// read. It is not moved into a device record and the old item is not deleted; nothing is written.
			if let published = legacy.read(eoa: eoa) { return published }
			// the no-passcode set of the owner: the key is derived in memory from its phrase and only when it derives the owner's own address
			guard let raw = rawLegacyStore else { return nil }
			if let derived = BeamioMnemonicSets.derivedKey(store: raw, eoa: eoa) { return derived }
			// method Y: the native record is the account's v3 envelope; after a correct passcode the session holds its key in memory (nothing stored)
			if case .cipher(let held, _) = BeamioMnemonicSets.current(store: raw), held == eoa { return BeamioCipherUnlock.key(eoa: eoa) }
			return nil
		}
		if let r = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw) {
			if r.mode == "device" {
				return try? hardware.unwrap(r.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))
			}
			return session.bundle(eoa: eoa)
		}
		return nil
	}

#if BEAMIO_TEST_HOOKS
	/// Test seam only, compiled for the tests and never for a release or store build. The tests of the withdrawn device and passcode record formats set this so that
	/// those formats stay covered; the default is off, which is the production behaviour of `write` and `delete` below.
	static var deviceRecordWritesForTests = false
#endif

	/// project requirement (v281 section 301): a wallet key is no longer written as a device record, because that format was never
	/// published and has been withdrawn. New records go only into the collection format of v269 (keychain, AfterFirstUnlockThisDeviceOnly, new name prefix);
	/// until that storage exists this answers `false`, an honest "not writable now", and never falls back to a device record. The published `walletKey`
	/// item is not overwritten.
	public func write(eoa rawEoa: String, key: Data) -> Bool {
		#if BEAMIO_TEST_HOOKS
		if Self.deviceRecordWritesForTests {
			// a key write and its snapshot refresh are one critical section (25.52Y.70 第 4 項 (c)).
			return BeamioNativeKeySnapshot.mutate {
				let eoa = rawEoa.lowercased()
				if isPasscodeSet(eoa: eoa) { return false }
				return writeDeviceRecord(eoa: eoa, key: key)
			}
		}
		#endif
		_ = (rawEoa, key)
		return false
	}

	/// The delete path stays disabled: nothing in any store is removed, the published `walletKey` item included. Only the unlocked
	/// bundles in memory are forgotten (a logout).
	public func delete(eoa rawEoa: String) {
		#if BEAMIO_TEST_HOOKS
		if Self.deviceRecordWritesForTests {
			BeamioNativeKeySnapshot.mutate {
				let eoa = rawEoa.lowercased()
				records.deleteRecord(eoa: eoa)
				hardware.deleteKey(eoa: eoa)
				legacy.delete(eoa: eoa)
				session.lockAll(reason: .logout)
			}
			return
		}
		#endif
		_ = rawEoa
		BeamioNativeKeySnapshot.mutate {
			session.lockAll(reason: .logout)
		}
	}

	public func migrationMarkerExists(eoa: String) -> Bool { legacy.migrationMarkerExists(eoa: eoa) }
	public func setMigrationMarker(eoa: String) -> Bool { legacy.setMigrationMarker(eoa: eoa) }
	public func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { legacy.migrationPhase(eoa: eoa) }
	public func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
		legacy.setMigrationPhase(eoa: eoa, phase)
	}

	// MARK: - Private

	private func isPasscodeSet(eoa: String) -> Bool {
		switch records.readRecordState(eoa: eoa) {
		case .absent: return false
		case .unavailable: return true
		case .present(let raw):
			guard let r = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw) else { return true }
			return r.mode == "passcode" || r.mode != "device"
		}
	}

#if BEAMIO_TEST_HOOKS
// The device-record write is the withdrawn, never-published format. It exists only for the tests of that format and is not compiled into a
// release or store build.
	/// Writes a device record for `key`, reads it back, unwraps it and compares it with `key`. Only a verified read-back reports success.
	/// A failed write or read-back is rolled back: the record is put back as it was (or removed when there was none). Nothing else is deleted,
	/// and the hardware key is kept (25.52Y.80 第 3 項 (a)).
	private func writeDeviceRecord(eoa: String, key: Data) -> Bool {
		guard !key.isEmpty else { return false }
		let previous = records.readRecord(eoa: eoa)
		if !hardware.hasKey(eoa: eoa), !hardware.createKey(eoa: eoa) { return false }
		guard let blob = try? hardware.wrap(key, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)),
		      let data = try? JSONEncoder().encode(BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob)),
		      records.writeRecord(eoa: eoa, data)
		else {
			rollbackDeviceRecord(eoa: eoa, previous: previous)
			return false
		}
		guard let raw = records.readRecord(eoa: eoa),
		      let back = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw),
		      let unwrapped = try? hardware.unwrap(back.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)),
		      unwrapped == key
		else {
			rollbackDeviceRecord(eoa: eoa, previous: previous)
			return false
		}
		return true
	}

	/// The rollback of a device-record write: the record that was there before, or no record when there was none.
	private func rollbackDeviceRecord(eoa: String, previous: Data?) {
		if let previous {
			_ = records.writeRecord(eoa: eoa, previous)
		} else {
			records.deleteRecord(eoa: eoa)
		}
	}
#endif
}

extension BeamioPasscodeVault {
	/// The standard vault: Keychain records and the H key, as the app uses them.
	public static let standard = BeamioPasscodeVault(records: BeamioPasscodeKeychainRecords.standard,
	                                                 hardware: BeamioPasscodeKeychainHardware.standard)
}

// MARK: - Mnemonic, intent and commit items of the production store (25.52Y.96 第 1 条, 25.52Y.42 第 3、4 项)

/// A store that can judge a locked account by the header of its passcode record (frozen protocol §7.3).
public protocol BeamioLockedMnemonicHeaderJudging {
	func lockedMnemonicHeaderIsValid(owner: String) -> Bool
}

extension BeamioPasscodeWalletStore: BeamioLockedMnemonicHeaderJudging {}

/// The item view of the passcode store, for the import, the creation and the backup display.
/// - `key` is this store's key record: a write, a read, and a record-only delete for a rollback. The hardware key stays (25.52Y.80 第 3 项 (a)).
/// - `mnemonic`, `intent` and `commit` are the chat-wallet items of the legacy layer (`com.beamio.beamio.chat-wallet`, `mnemonic:<eoa>`), wrapped
/// like the key record. A phrase of an account whose passcode is locked is neither read nor returned (25.52CO.4).
extension BeamioPasscodeWalletStore: BeamioChatMnemonicKeyStoring {
	private var mnemonicItems: BeamioChatMnemonicKeyStoring? { legacy as? BeamioChatMnemonicKeyStoring }

	public func itemState(_ kind: BeamioChatWalletItemKind, eoa rawEoa: String) -> BeamioChatItemState {
		let eoa = rawEoa.lowercased()
		switch kind {
		case .key:
			switch keyRecordState(eoa: eoa) {
			case .absent: return .absent
			case .present: return .present
			case .unreadable: return .unreadable
			}
		case .mnemonic:
			// A locked account's phrase is not read at all: its state is unknown, not absent. Except the header of a passcode record: the account is
			// valid and locked (frozen protocol §7.3), its item is present.
			if session.isLocked(eoa: eoa) { return lockedMnemonicHeaderIsValid(owner: eoa) ? .present : .unreadable }
			return mnemonicItems?.itemState(kind, eoa: eoa) ?? .unreadable
		case .intent, .commit:
			return mnemonicItems?.itemState(kind, eoa: eoa) ?? .unreadable
		}
	}

	public func writeItem(_ kind: BeamioChatWalletItemKind, eoa rawEoa: String, value: Data) -> Bool {
		let eoa = rawEoa.lowercased()
		switch kind {
		case .key:
			return write(eoa: eoa, key: value)
		case .mnemonic:
			if session.isLocked(eoa: eoa) { return false }
			// A passcode account keeps its phrase in the record; a write here would put a second, device-bound copy beside the header.
			if mnemonicHeaderPresent(eoa: eoa) { return false }
			return mnemonicItems?.writeItem(kind, eoa: eoa, value: value) ?? false
		case .intent, .commit:
			return mnemonicItems?.writeItem(kind, eoa: eoa, value: value) ?? false
		}
	}

	public func readItem(_ kind: BeamioChatWalletItemKind, eoa rawEoa: String) -> Data? {
		let eoa = rawEoa.lowercased()
		switch kind {
		case .key:
			return read(eoa: eoa)
		case .mnemonic:
			// 25.52CO.4: a locked account's phrase is neither read nor returned.
			if session.isLocked(eoa: eoa) { return nil }
			// The header: the phrase is in the passcode record, opened with the P key that the unlock kept in the session.
			if mnemonicHeaderPresent(eoa: eoa) { return phraseFromRecord(eoa: eoa) }
			return mnemonicItems?.readItem(kind, eoa: eoa)
		case .intent, .commit:
			return mnemonicItems?.readItem(kind, eoa: eoa)
		}
	}

	/// A locked account whose `mnemonic:<eoa>` item is the header and whose passcode record exists and holds a phrase: "valid, locked" (frozen
	/// protocol §7.3). The phrase itself is judged after the unlock.
	public func lockedMnemonicHeaderIsValid(owner rawOwner: String) -> Bool {
		let eoa = rawOwner.lowercased()
		guard session.isLocked(eoa: eoa), mnemonicHeaderPresent(eoa: eoa),
		      case .present(let raw) = records.readRecordState(eoa: eoa),
		      let record = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw),
		      record.mode == "passcode", record.mnemonicBlob != nil else { return false }
		return true
	}

	/// The `mnemonic:<eoa>` item is the passcode header (no secret in it).
	func mnemonicHeaderPresent(eoa: String) -> Bool {
		guard let raw = rawLegacyStoreForShell else { return false }
		guard case .present(let data) = raw.rawRead(account: raw.accountName(.mnemonic, eoa: eoa)) else { return false }
		return BeamioShellMnemonicItem.isHeader(data, owner: eoa)
	}

	/// The phrase of an unlocked passcode record. nil when the account is locked, the session has no P key, or the record has no phrase.
	func phraseFromRecord(eoa rawEoa: String) -> Data? {
		let eoa = rawEoa.lowercased()
		guard !session.isLocked(eoa: eoa), var p = session.mnemonicKey(eoa: eoa),
		      case .present(let raw) = records.readRecordState(eoa: eoa),
		      let record = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw), let blob = record.mnemonicBlob else { return nil }
		defer { BeamioNativeWallet.wipe(&p) }
		return try? BeamioPasscodeWrap.open(blob, key: SymmetricKey(data: p), aad: BeamioPasscodeWrap.aadM(eoa: eoa))
	}

	/// Replaces the device-bound item by the header (frozen protocol §7.4 step 5). The blob key K of the walletCredential is made first when it is missing.
	func writeMnemonicHeader(eoa rawEoa: String) -> Bool {
		let eoa = rawEoa.lowercased()
		guard let raw = rawLegacyStoreForShell, !session.isLocked(eoa: eoa) else { return false }
		// The header is written only when the passcode record holds the phrase and opens it now: otherwise the old item is the only copy.
		guard phraseFromRecord(eoa: eoa) != nil else { return false }
		let name = raw.accountName(.mnemonic, eoa: eoa)
		if case .unreadable = raw.rawRead(account: name) { return false }
		guard BeamioWalletCredentialBlob.createIfMissing(eoa: eoa) else { return false }
		let header = BeamioShellMnemonicItem.header(eoa: eoa)
		guard raw.rawWrite(account: name, bytes: header), case .present(let back) = raw.rawRead(account: name), back == header else { return false }
		return true
	}

	/// Disable: the phrase goes back into the device-bound item, and reads back as written.
	func writeDeviceBoundMnemonic(eoa rawEoa: String, phrase: Data) -> Bool {
		let eoa = rawEoa.lowercased()
		guard let items = mnemonicItems, !session.isLocked(eoa: eoa) else { return false }
		guard items.writeItem(.mnemonic, eoa: eoa, value: phrase), let back = items.readItem(.mnemonic, eoa: eoa) else { return false }
		return back == phrase
	}

	public func deleteItem(_ kind: BeamioChatWalletItemKind, eoa rawEoa: String) -> Bool {
		let eoa = rawEoa.lowercased()
		switch kind {
		case .key:
			// A rollback removes the key record only. delete(eoa:) is not used: it also removes the hardware key and locks every account.
			BeamioNativeKeySnapshot.mutate { records.deleteRecord(eoa: eoa) }
			return keyRecordState(eoa: eoa) == .absent
		case .mnemonic, .intent, .commit:
			return mnemonicItems?.deleteItem(kind, eoa: eoa) ?? false
		}
	}

	public func intentOwners() -> [String]? {
		mnemonicItems?.intentOwners()
	}

	/// The mnemonic items of the legacy layer, with their creation times (attributes only). The key records are not mnemonics and are not listed here.
	public func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? {
		mnemonicItems?.mnemonicRecordCreations()
	}
}

// MARK: - Raw-item view used by the journaled PWA overwrite

/// The passcode store keeps wrapped key records in its own record service, while mnemonic/intent/commit payloads remain
/// in the legacy wallet service. This adapter exposes the stored bytes without unwrapping them so the overwrite journal
/// can isolate and restore each exact payload. It refuses raw access to a passcode account while that account is locked.
extension BeamioPasscodeWalletStore: BeamioChatRawItemStoring {
	private static var passcodeRawKeyPrefix: String { "__beamio_passcode_wallet_key__:" }

	private var rawLegacyStore: BeamioChatRawItemStoring? {
		legacy as? BeamioChatRawItemStoring
	}

	var rawLegacyStoreForShell: BeamioChatRawItemStoring? { rawLegacyStore }

	private static func owner(inRawAccount account: String) -> String? {
		if account.hasPrefix(passcodeRawKeyPrefix) {
			return String(account.dropFirst(passcodeRawKeyPrefix.count)).lowercased()
		}
		for prefix in ["mnemonic:", "intent:", "commit:", "walletKey:"] where account.hasPrefix(prefix) {
			return String(account.dropFirst(prefix.count)).lowercased()
		}
		return setItemOwner(inRawAccount: account)
	}

	/// The owner of a mnemonic set item: `mnemonic.set.<eoa>` (the plaintext set) or `mnemonic.set.<eoa>.c.<digest>` (the cipher version). Any other name that
	/// starts with the set prefix has no owner here (it stays refused by the writer).
	private static func setItemOwner(inRawAccount account: String) -> String? {
		let prefix = BeamioMnemonicSets.setPrefix
		guard account.hasPrefix(prefix) else { return nil }
		let rest = String(account.dropFirst(prefix.count))
		let owner: String
		if let dot = rest.firstIndex(of: ".") {
			let tail = rest[rest.index(after: dot)...]
			guard tail.hasPrefix("c."), tail.count > 2, tail.dropFirst(2).allSatisfy({ $0.isHexDigit }) else { return nil }
			owner = String(rest[..<dot])
		} else {
			owner = rest
		}
		return owner.isEmpty ? nil : owner.lowercased()
	}

	/// Whether the name is a mnemonic set item (plaintext or cipher version). The sets are never deleted through this store (the delete path stays disabled).
	private static func isSetItem(_ account: String) -> Bool { setItemOwner(inRawAccount: account) != nil }

	/// The owner a write of `mnemonic.current` names: the `eoa` of the record being written. nil when the bytes do not name an owner.
	private static func currentRecordOwner(_ bytes: Data) -> String? {
		guard let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any], let eoa = object["eoa"] as? String, !eoa.isEmpty else { return nil }
		return eoa.lowercased()
	}

	private func isPasscodeRecordAccount(_ account: String) -> String? {
		guard account.hasPrefix(Self.passcodeRawKeyPrefix) else { return nil }
		return String(account.dropFirst(Self.passcodeRawKeyPrefix.count)).lowercased()
	}

	public func accountName(_ kind: BeamioChatWalletItemKind, eoa rawEoa: String) -> String {
		let eoa = rawEoa.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
		guard !eoa.isEmpty else { return "" }
		if kind == .key {
			if records.readRecord(eoa: eoa) != nil { return Self.passcodeRawKeyPrefix + eoa }
			if let rawLegacyStore,
			   case .present = rawLegacyStore.rawRead(account: rawLegacyStore.accountName(.key, eoa: eoa)) {
				return rawLegacyStore.accountName(.key, eoa: eoa)
			}
			return Self.passcodeRawKeyPrefix + eoa
		}
		return rawLegacyStore?.accountName(kind, eoa: eoa) ?? ""
	}

	public func rawAccountNames() -> [String]? { rawLegacyStore?.rawAccountNames() }

	public func rawRead(account: String) -> BeamioChatRawItem {
		if let eoa = isPasscodeRecordAccount(account) {
			guard !session.isLocked(eoa: eoa) else { return .unreadable }
			switch records.readRecordState(eoa: eoa) {
			case .present(let raw): return .present(raw)
			case .unavailable: return .unreadable
			case .absent:
				guard let rawLegacyStore else { return .unreadable }
				let legacyName = rawLegacyStore.accountName(.key, eoa: eoa)
				if legacyName.isEmpty { return .unreadable }
				return rawLegacyStore.rawRead(account: legacyName)
			}
		}
		if let eoa = Self.owner(inRawAccount: account), session.isLocked(eoa: eoa) {
			return .unreadable
		}
		guard let rawLegacyStore else { return .unreadable }
		return rawLegacyStore.rawRead(account: account)
	}

	public func rawWrite(account: String, bytes: Data) -> Bool {
		if account == BeamioMnemonicSets.currentName {
			// the device-level pointer of the sets: it names its owner inside the record, and that owner must not be locked
			guard !bytes.isEmpty, let owner = Self.currentRecordOwner(bytes), !session.isLocked(eoa: owner), let rawLegacyStore else { return false }
			return rawLegacyStore.rawWrite(account: account, bytes: bytes)
		}
		guard !bytes.isEmpty,
		      let owner = Self.owner(inRawAccount: account),
		      !session.isLocked(eoa: owner) else { return false }
		if let eoa = isPasscodeRecordAccount(account) {
			guard !session.isLocked(eoa: eoa), records.writeRecord(eoa: eoa, bytes), records.readRecord(eoa: eoa) == bytes else { return false }
			return true
		}
		if let eoa = Self.owner(inRawAccount: account), session.isLocked(eoa: eoa) { return false }
		guard let rawLegacyStore else { return false }
		return rawLegacyStore.rawWrite(account: account, bytes: bytes)
	}

	public func rawDelete(account: String) -> Bool {
		// the sets are not deleted here: the delete path of `mnemonic.set.*` and `mnemonic.current` stays disabled
		if Self.isSetItem(account) || account == BeamioMnemonicSets.currentName { return false }
		guard let owner = Self.owner(inRawAccount: account), !session.isLocked(eoa: owner) else { return false }
		if let eoa = isPasscodeRecordAccount(account) {
			switch records.readRecordState(eoa: eoa) {
			case .unavailable: return false
			case .present:
				records.deleteRecord(eoa: eoa)
				return records.readRecordState(eoa: eoa) == .absent
			case .absent:
				guard let rawLegacyStore else { return false }
				let legacyName = rawLegacyStore.accountName(.key, eoa: eoa)
				return !legacyName.isEmpty && rawLegacyStore.rawDelete(account: legacyName)
			}
		}
		if let eoa = Self.owner(inRawAccount: account), session.isLocked(eoa: eoa) { return false }
		guard let rawLegacyStore else { return false }
		return rawLegacyStore.rawDelete(account: account)
	}

	public func judgeMnemonicPayload(_ bytes: Data, owner rawOwner: String) -> (state: BeamioMnemonicAccountState, phrase: Data?) {
		let owner = rawOwner.lowercased()
		guard !session.isLocked(eoa: owner), let rawLegacyStore else { return (.unreadable, nil) }
		if BeamioShellMnemonicItem.isHeader(bytes, owner: owner) {
			// The header holds no phrase: the phrase of the unlocked record is judged the same way as an item's.
			guard var phrase = phraseFromRecord(eoa: owner) else { return (.unreadable, nil) }
			guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) else {
				BeamioNativeWallet.wipe(&phrase)
				return (.invalid, nil)
			}
			defer { BeamioNativeWallet.wipe(&key) }
			guard BeamioNativeEthSigner.address(privateKey: key)?.lowercased() == owner else {
				BeamioNativeWallet.wipe(&phrase)
				return (.invalid, nil)
			}
			return (.valid, phrase)
		}
		return rawLegacyStore.judgeMnemonicPayload(bytes, owner: owner)
	}
}
