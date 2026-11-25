import Foundation

/// Reads the state of the mark items of an account: `intent`, `mnemonic` and `commit` (25.52Y.83, 25.52Y.92). It reads no secret.
protocol BeamioNativeMarkReading {
	func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState
	/// The state of the plain `mnemonic:<eoa>` device item only, as the readers see it (a retired item reads as absent, an unverified or unknown retirement as unreadable). It does not fall back
	/// to the no-passcode mnemonic set, which `itemState(.mnemonic)` does. The default is `itemState(.mnemonic)`: a store that cannot tell the two apart keeps the conservative answer.
	func legacyMnemonicItemState(eoa: String) -> BeamioChatItemState
}

extension BeamioNativeMarkReading {
	func legacyMnemonicItemState(eoa: String) -> BeamioChatItemState { itemState(.mnemonic, eoa: eoa) }
}

extension BeamioChatWalletKeychainStore: BeamioNativeMarkReading {}

#if BEAMIO_TEST_HOOKS
/// Test only: no mark item anywhere, until a test installs its own mark store.
struct BeamioNativeMarkReadingNone: BeamioNativeMarkReading {
	func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState { .absent }
}
#endif

/// The session snapshot of the native keys (takeover item 1; interface 25.52Y.70 第 4 项, 25.52Y.75).
///
/// The shell record commands and `walletStatus` read this snapshot. They do not decrypt the key records for each command.
/// - Established at the session start: the first command of the process, or the first use after an invalidation.
/// - Refreshed by every event that changes what it holds: an unlock or a lock (`BeamioPasscodeSession`), a passcode change
///   (`BeamioPasscodeVault`), a key-store write (the production stores), a change of the account pointer, and a swap of the key store.
/// - A write and its refresh run in one critical section (`mutate`). A reader that starts after a write has returned takes the new snapshot.
///
/// The full validation (the unseal of each key record, its structure, and the address its key derives) runs only at those events, through the
/// same judgement the store always had (`enumerateKeyEntries`). A record that cannot be checked is never counted as present.
/// While the snapshot is unknown (`current()` is nil), every command answers without reading a payload and without writing.
enum BeamioNativeKeySnapshot {
	/// How the gate of a judgement is decided: a fixed value, or the live session (`presentGate`: a G0 reads as G1).
	enum GateRule: Equatable {
		case fixed(BeamioConetChatModule.NativeGate)
		case presentGate
	}

	/// A storage-derived lock (25.52Y.83): the key record and its marks disagree. `markerMissing`: the record exists, the mnemonic is there, and neither
	/// the commit nor the intent mark is. `recordMissing`: the commit mark exists and the key record is gone. Neither is a passcode lock.
	enum StorageLock: Equatable {
		case markerMissing
		case recordMissing
	}

	/// What the last judgement found. Plain values only: no key, no record content.
	struct Entry {
		/// The account of the judgement (`NativeJudgement.account`).
		let account: String?
		let keyState: BeamioShellRecord.KeyState
		let gateRule: GateRule
		/// The account of the device pointer when its key record exists, readable or not (the record account of `nativeGate`). nil: G0.
		let recordAccount: String?
		/// The judged account is under a passcode lock. The lock is answered `locked`, never as not_ready (25.52Y.70 第 4 项).
		let accountLocked: Bool
		/// A key record is damaged (corrupt or unavailable), or the record account cannot be read from the store.
		/// walletStatus answers `not_ready` with `notReadyReason: "unreadable"` in G1 (25.52Y.39 第 9 项 (b)).
		let unreadable: Bool
		/// The storage-derived lock of the pointer's account when its record and marks disagree (25.52Y.83). nil: none.
		let storageLock: StorageLock?
		/// The category of the keychain failure behind `unreadable` (entitlement, device_locked, other), taken by the judgement that made the snapshot. It stays with
		/// the snapshot: an answer reads it here, never from a global that a later read may have changed.
		var unreadableCause: String = BeamioKeychainFailureNote.other
	}

	private static let updateLock = NSRecursiveLock()
	private static let stateLock = NSLock()
	/// The published snapshot. nil: unknown.
	private static var state: Entry?
	/// Nesting depth of `mutate` on the current thread. Guarded by `updateLock`.
	private static var mutationDepth = 0

	/// The store of the mark items the judgement reads (25.52Y.83, 25.52Y.92). Production reads the Keychain store that keeps the wallet items
	/// (`BeamioChatWalletKeychainStore.standard`); the passcode key store does not keep them. A change refreshes the snapshot.
	/// Tests replace it with an isolated store; the default keeps no mark.
	static var markStore: BeamioNativeMarkReading = defaultMarkStore {
		didSet { invalidate() }
	}

	private static var defaultMarkStore: BeamioNativeMarkReading {
		#if BEAMIO_TEST_HOOKS
		return BeamioNativeMarkReadingNone()
		#else
		return BeamioChatWalletKeychainStore.standard
		#endif
	}

	#if BEAMIO_TEST_HOOKS
	/// Test only: keeps the snapshot unknown, so that no session start establishes it.
	private static var pinnedUnknown = false
	#endif

	/// The snapshot, or nil while it is unknown.
	static func current() -> Entry? {
		stateLock.lock()
		defer { stateLock.unlock() }
		return state
	}

	static var isKnown: Bool { current() != nil }

	/// The session start. Establishes the snapshot when it is unknown; reads the store only then.
	static func sessionStartIfNeeded() {
		guard !isKnown else { return }
		updateLock.lock()
		defer { updateLock.unlock() }
		guard !isKnown else { return }
		#if BEAMIO_TEST_HOOKS
		if pinnedUnknown { return }
		#endif
		publish(judgeLocked())
		// the session start of a process finishes a plaintext cleanup that an earlier run left (it writes through `mutate`, which refreshes the snapshot)
		if let raw = BeamioNativeWallet.keyStore as? BeamioChatRawItemStoring { mutate { BeamioMnemonicSets.resumeRetire(store: raw) } }
	}

	/// Runs a change of the key records, the account pointer or the passcode state, and refreshes the snapshot, in one critical section.
	/// Nested calls on the same thread refresh once, when the outermost call ends.
	@discardableResult
	static func mutate<T>(_ body: () -> T) -> T {
		updateLock.lock()
		defer { updateLock.unlock() }
		mutationDepth += 1
		let result = body()
		mutationDepth -= 1
		if mutationDepth == 0 { refreshAfterWriteLocked() }
		return result
	}

	/// The refresh at the end of a change. A pinned-unknown test keeps the snapshot unknown and reads nothing.
	private static func refreshAfterWriteLocked() {
		// A write of the key records, the marks, the account pointer or the passcode state changes what a preread would read: the reading published for the epoch before it is no longer current. This is
		// the one point every write path goes through (recovery, creation, import, the passcode commands, the page sync), so none of them can leave a stale preread behind.
		BeamioPwaPreread.beforeWrite()
		#if BEAMIO_TEST_HOOKS
		if pinnedUnknown {
			invalidate()
			return
		}
		#endif
		publish(judgeLocked())
	}

	/// Drops the snapshot. The next session start establishes it again. Used where a change cannot pass through `mutate`
	/// (a key-store swap, or the own storage of a test double).
	static func invalidate() {
		stateLock.lock()
		state = nil
		stateLock.unlock()
	}

	#if BEAMIO_TEST_HOOKS
	/// Test only: publishes (or clears) a snapshot that judged the key store unreadable.
	static func pinUnreadableForTests(_ unreadable: Bool) {
		stateLock.lock()
		state = unreadable
			? Entry(account: nil, keyState: .normal, gateRule: .fixed(.g1), recordAccount: nil, accountLocked: false, unreadable: true, storageLock: nil,
			        unreadableCause: BeamioKeychainFailureNote.current)
			: nil
		stateLock.unlock()
	}
	/// Test only: while pinned, the snapshot is unknown and no session start or write establishes it (the answers of an unknown snapshot).
	static func pinUnknownForTests(_ pinned: Bool) {
		updateLock.lock()
		defer { updateLock.unlock() }
		pinnedUnknown = pinned
		invalidate()
	}
	#endif

	/// The gate of an entry, as the live session decides it now: the gate of the record account and the session's readiness.
	static func gate(of entry: Entry) -> BeamioConetChatModule.NativeGate {
		switch entry.gateRule {
		case .fixed(let gate):
			return gate
		case .presentGate:
			let gate = BeamioConetChatModule.gate(forRecordAccount: entry.recordAccount)
			return gate == .g0 ? .g1 : gate
		}
	}

	private static func publish(_ entry: Entry) {
		stateLock.lock()
		state = entry
		stateLock.unlock()
	}

	/// The judgement, computed from the key store, the pointer and the session. Called only under `updateLock`, at the events above.
	/// It never runs for a command. Its rules are those of the former per-command judgement, unchanged.
	private static func judgeLocked() -> Entry {
		BeamioKeychainFailureNote.reset()
		var entry = judgeCore()
		if entry.unreadable { entry.unreadableCause = BeamioKeychainFailureNote.current }
		return entry
	}

	private static func judgeCore() -> Entry {
		let previous = BeamioKeyJudgementDiagnostics.enter(.gate)
		defer { BeamioKeyJudgementDiagnostics.leave(previous) }
		BeamioKeyJudgementDiagnostics.note(.gateJudgements)

		let pointer = BeamioNativeAccountPointer.get()
		// Y.163 第 31、32、34 項: the accounts are the valid mnemonics. The record account is the pointer's account when it has a mnemonic
		// item (readable or not); a pointer with no mnemonic item (absent, or a private-key record only) is no record. An invalid or unreadable
		// mnemonic is not "no record": it is unreadable.
		let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
		let pointerState: BeamioChatWalletKeyRecordState
		switch inventory.state(of: pointer) {
		case .absent: pointerState = .absent
		case .valid: pointerState = .present
		case .invalid, .unreadable: pointerState = .unreadable
		}
		let recordAccount: String? = pointerState == .absent ? nil : pointer
		let marks = judgeMarks(pointer: pointer, keyPresent: pointerState != .absent)
		let storageUnreadable = pointerState == .unreadable || marks.unreadable
		// The pointer the judgement uses: only a pointer with a mnemonic item decides the account (第 34(3) 項).
		let usable = inventory.usablePointer(pointer)

		guard let entries = inventory.credentialEntries else {
			BeamioKeyJudgementDiagnostics.note(.judgementFailures)
			// Y.163 20c, 20h(a): an enumeration that cannot be completed is unreadable, never a G1 "no account" (g1_uninitialized).
			return Entry(account: nil, keyState: .normal, gateRule: .fixed(.g1), recordAccount: recordAccount,
			             accountLocked: false, unreadable: true,
			             storageLock: marks.storageLock)
		}
		// A damaged record is listed with no account name, so it is judged as a whole: it makes the snapshot unreadable.
		let damaged = entries.contains { entry in
			switch entry {
			case .corrupt, .unavailable: return true
			case .valid, .locked: return false
			}
		}
		if damaged {
			BeamioKeyJudgementDiagnostics.note(.judgementFailures)
		}

		let judged = BeamioNativeWalletStateResolver.resolve(pointer: usable, entries: entries)
		let account: String?
		let keyState: BeamioShellRecord.KeyState
		let gateRule: GateRule
		switch judged.state {
		case .present, .locked:
			account = judged.account
			keyState = .normal
			gateRule = .presentGate
		case .notReady:
			if usable.isEmpty {
				account = nil
				keyState = .ambiguous
			} else {
				account = usable
				keyState = .pointerKeyMissing
			}
			gateRule = .fixed(.g0)
		case .absent:
			account = BeamioShellRecord.accountOfCopyWithKey(store: BeamioShellRecord.EncryptedShellRecordStore.production)
			keyState = .normal
			gateRule = .fixed(.g0)
		case .unavailable, .corrupt:
			account = nil
			keyState = .normal
			gateRule = .fixed(.g1)
		}
		let locked = account.map { BeamioPasscodeSession.shared.isLocked(eoa: $0) } ?? false
		return Entry(account: account, keyState: keyState, gateRule: gateRule, recordAccount: recordAccount,
		             accountLocked: locked, unreadable: damaged || storageUnreadable,
		             storageLock: marks.storageLock)
	}

	/// The mark judgement of the pointer's account (25.52Y.83, 25.52Y.92), read from `markStore`, not from the key store. marker_missing: a key
	/// record exists, the commit mark is missing, and an intent or a mnemonic is there. A digest would count the same; iOS keeps no digest item.
	/// A key record with no mark at all is the old pure-key record: accepted, no lock. record_missing: the commit mark exists and the key record is gone.
	/// A mark that cannot be read makes the snapshot unreadable (fail closed); it is not a lock.
	private struct MarkJudgement {
		let storageLock: StorageLock?
		let unreadable: Bool
	}

	private static func judgeMarks(pointer: String, keyPresent: Bool) -> MarkJudgement {
		guard !pointer.isEmpty else { return MarkJudgement(storageLock: nil, unreadable: false) }
		let items = markStore
		let commit = items.itemState(.commit, eoa: pointer)
		let intent = items.itemState(.intent, eoa: pointer)
		// markerMissing guards the half-written sequence of the key-record path (intent, key, plain mnemonic item, commit, intent removed): every half-written state keeps the intent or the plain
		// mnemonic item. The no-passcode mnemonic set is one atomic record (written and read back before the pointer moves) and writes neither, so a set without a commit mark is not
		// half-written. The mnemonic that counts here is therefore the plain device item only (`legacyMnemonicItemState`), not the set that `itemState(.mnemonic)` also reports.
		let legacyMnemonic = items.legacyMnemonicItemState(eoa: pointer)
		if commit == .unreadable || intent == .unreadable || legacyMnemonic == .unreadable {
			return MarkJudgement(storageLock: nil, unreadable: true)
		}
		// An account of the shell passcode protocol (a passcode record, or the device record that passcodeDisable leaves) keeps its mnemonic item as the v3 header or as the device-bound phrase,
		// and never writes a commit mark: that layout is not the key-record path either. A plain mnemonic item beside such a record is therefore not a half-written key-record account.
		let hasVaultRecord: Bool = {
			switch BeamioPasscodeSession.shared.vault?.shellRecord(eoa: pointer) {
			case .some(.passcode), .some(.device): return true
			default: return false
			}
		}()
		if keyPresent, commit == .absent, intent == .present || (legacyMnemonic == .present && !hasVaultRecord) {
			return MarkJudgement(storageLock: .markerMissing, unreadable: false)
		}
		if !keyPresent, commit == .present {
			return MarkJudgement(storageLock: .recordMissing, unreadable: false)
		}
		return MarkJudgement(storageLock: nil, unreadable: false)
	}
}
