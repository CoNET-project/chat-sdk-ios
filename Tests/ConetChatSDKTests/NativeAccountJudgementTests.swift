import XCTest
@testable import ConetChatSDK

/// Batch C (25.52Y.89, Y.90, Y.106–Y.108): the native-side account judgement and kPresent.
/// The page maps the SDK's native answers to has, unknown or confirmed_none (Y.89). The mapping below is a model in the test target: it checks
/// the vector rows TS-01 to TS-10 (pgp-migration-vectors, `nativeMnemonicTriStateCases`, `nativeResidueTriStateCases`) against the answer shapes.
/// The SDK's own answers are tested separately: kPresent on the G0 `identityPublic` answer (gated by identity.kpresent.v1), and the
/// `walletStatus` precedence of a read failure over the passcode lock. Synthetic values only.
final class NativeAccountJudgementTests: XCTestCase {
	/// The native answer, reduced to what the mapping reads. `has` is G1 `g1_uninitialized` or G2 `unlocked`/`locked` (with the account key).
	enum Status { case noKey, has, unreadable, notReady }
	/// The mnemonic residue on the native side (`mnemonic:<eoa>`, or the native record): readable, absent, or a read error.
	enum Mnemonic { case readable, absent, error }
	enum Side: Equatable { case has, unknown(String), confirmedNone }

	/// The mapping of Y.107 (final) with Y.108. has: a readable mnemonic or a has-status. unknown: a read error, a storage-derived lock, not ready,
	/// a missing or non-boolean kPresent on no_key (Y.108 第 2 項), or a snapshot not yet known. confirmed_none: no_key, the reads succeeded,
	/// and no recoverable mnemonic. kPresent never blocks onboarding (Y.107 第 4 項), so its value does not change the result.
	static func judge(snapshotUnknown: Bool, status: Status?, kPresent: Bool?, mnemonic: Mnemonic?, readError: Bool = false) -> Side {
		if snapshotUnknown { return .unknown("snapshot_unknown") }
		if status == .has || mnemonic == .readable { return .has }
		if mnemonic == .error || readError { return .unknown("read_error") }
		switch status {
		case .unreadable?, .notReady?:
			return .unknown("unreadable")
		case .noKey?:
			// 25.52Y.155 (c) and (b): a missing or non-boolean kPresent is unknown; kPresent true does not judge no account.
			guard let present = kPresent else { return .unknown("kpresent_missing") }
			if present { return .unknown("kpresent_true") }
			return .confirmedNone
		case .has?:
			return .has
		case nil:
			return .unknown("no_status")
		}
	}

	// MARK: - TS rows of the vector file (inputs as named there)

	func testTS01NoKeyWithKPresentFalseIsConfirmedNone() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: false, mnemonic: .absent), .confirmedNone)
	}

	func testTS02G1UninitializedIsHas() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .has, kPresent: nil, mnemonic: nil), .has)
	}

	func testTS03G2UnlockedOrLockedIsHas() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .has, kPresent: nil, mnemonic: nil), .has)
	}

	func testTS04UnreadableIsUnknownNotOnboarding() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .unreadable, kPresent: nil, mnemonic: nil), .unknown("unreadable"))
	}

	func testTS05SnapshotUnknownIsUnknown() {
		XCTAssertEqual(Self.judge(snapshotUnknown: true, status: .unreadable, kPresent: nil, mnemonic: nil), .unknown("snapshot_unknown"))
	}

	/// TS-06 (25.52Y.155 (b)): no_key with kPresent true, the read succeeds: unknown, never a confirmed absence. Read from the v2 vector file.
	func testTS06NoKeyWithKPresentTrueIsUnknown() throws {
		let data = try BundledVectorFile.data(resource: "pgp-migration-vectors.v3")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let rows = try XCTUnwrap(root["nativeMnemonicTriStateCases"] as? [[String: Any]])
		let row = try XCTUnwrap(rows.first { $0["id"] as? String == "TS-06" })
		let input = try XCTUnwrap(row["input"] as? [String: Any])
		XCTAssertEqual(input["ws"] as? String, "no_key")
		XCTAssertEqual(input["kPresent"] as? Bool, true)
		XCTAssertEqual(row["expect"] as? String, "unknown", "TS-06 expects unknown (Y.155)")
		let side = Self.judge(snapshotUnknown: input["snapshotUnknown"] as? Bool ?? false, status: .noKey,
		                      kPresent: input["kPresent"] as? Bool, mnemonic: nil)
		guard case .unknown = side else { return XCTFail("TS-06: \(side) is not unknown") }
	}

	/// kPresent missing or not a boolean on no_key is unknown (25.52Y.155 (c)); a false kPresent without a copy stays confirmed absent (a).
	func testKPresentMissingOrNonBooleanIsUnknownAndFalseIsConfirmedNone() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: nil, mnemonic: nil), .unknown("kpresent_missing"))
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: false, mnemonic: nil), .confirmedNone)
	}

	func testTS07MnemonicReadableWithoutKeyIsHas() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: false, mnemonic: .readable), .has)
	}

	/// The residue rows give no walletStatus; the model takes no_key with kPresent false, the state of a device with no key record.
	func testTS08CommitOnlyResidueIsConfirmedNone() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: false, mnemonic: .absent, readError: false), .confirmedNone)
	}

	func testTS09NothingLeftIsConfirmedNone() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: false, mnemonic: .absent, readError: false), .confirmedNone)
	}

	func testTS10MnemonicReadErrorIsUnknown() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: false, mnemonic: .error), .unknown("read_error"))
	}

	/// Y.108 第 2 項: a no_key answer whose kPresent is missing is unknown, never confirmed_none.
	func testNoKeyWithoutKPresentIsUnknown() {
		XCTAssertEqual(Self.judge(snapshotUnknown: false, status: .noKey, kPresent: nil, mnemonic: .absent), .unknown("kpresent_missing"))
	}

	// MARK: - kPresent on the SDK's G0 identityPublic answer (25.52Y.90 第 1, 3, 4 項)

	/// The field is added only with the capability pair declared. Without it the answer is the plain no_key ack, as before.
	func testKPresentIsOmittedWhilePairNotDeclared() {
		let body: [String: Any] = ["type": "identityPublic", "reqId": 7]
		let answer = BeamioConetChatModule.identityPublicNoKeyAnswer(body, declared: false)
		XCTAssertEqual(answer?["error"] as? String, "no_key")
		XCTAssertEqual(answer?["ok"] as? Bool, false)
		XCTAssertNil(answer?["kPresent"], "identity.kpresent.v1 is not declared: no kPresent")
	}

	/// Declared: the boolean from the device's PGP and K records, present only and never the key. Memory store: nothing, then a PGP item.
	func testKPresentIsABooleanFromTheRecordsWhenDeclared() {
		let saved = BeamioChatPgpKeychain.memory
		defer { BeamioChatPgpKeychain.memory = saved }
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		let body: [String: Any] = ["type": "identityPublic", "reqId": "kp-1"]
		XCTAssertEqual(BeamioConetChatModule.identityPublicNoKeyAnswer(body, declared: true)?["kPresent"] as? Bool, false)
		BeamioChatPgpKeychain.memory?.values["userPgpPrivateArmor"] = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----"
		XCTAssertEqual(BeamioConetChatModule.identityPublicNoKeyAnswer(body, declared: true)?["kPresent"] as? Bool, true)
		XCTAssertEqual(BeamioChatPgpKeychain.devicePresenceState(), true)
	}

	/// An invalid reqId is not answered (no event), as before.
	func testAnInvalidReqIdGivesNoAnswer() {
		XCTAssertNil(BeamioConetChatModule.identityPublicNoKeyAnswer(["type": "identityPublic", "reqId": NSNull()], declared: true))
	}

	// MARK: - walletStatus: a read failure is unreadable, never locked (25.52Y.107 第 2 項)

	private final class Sink {
		var events: [[String: Any]] = []
	}

	private func dispatch(_ body: [String: Any]) -> [String: Any]? {
		let sink = Sink()
		BeamioConetChatModule.handleCommand(body, emit: { event in
			sink.events.append((event["event"] as? [String: Any]) ?? event)
		})
		let deadline = Date().addingTimeInterval(5)
		while sink.events.isEmpty, Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.02))
		}
		return (sink.events.first?["result"]) as? [String: Any]
	}

	/// G2 with the record named but unreadable: `not_ready` with `unreadable`, and no accountKey. The read is judged before the passcode lock,
	/// so a read failure is never answered as `locked`. (Whether the session is locked is not forced here; the order is what is tested.)
	func testWalletStatusReadFailureIsUnreadableNotLocked() {
		NativeAccountPointerIsolation.begin()
		let savedStore = BeamioNativeWallet.keyStore
		let store = KeyAccountLevelCheckTests.OwnerStore()
		let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
		store.owners = [account]
		store.unreadable = [account]
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		defer {
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			BeamioNativeWallet.keyStore = savedStore
			NativeAccountPointerIsolation.end()
		}
		let result = dispatch(["type": "walletStatus", "reqId": 11])
		XCTAssertEqual(result?["status"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "unreadable")
		XCTAssertNil(result?["accountKey"])
	}

	// MARK: - walletStatus at G0 with the pointer set and no key record (25.52Y.117, TS-07)

	/// The key store of this case: no key record, and the items of the pointer's account as the test names them. It counts every write and
	/// delete, so a test can show that the answer touched no storage.
	final class ResidueStore: BeamioChatMnemonicKeyStoring {
		var states: [BeamioChatWalletItemKind: BeamioChatItemState] = [:]
		var writes = 0
		var deletes = 0
		func write(eoa: String, key: Data) -> Bool { writes += 1; return false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) { deletes += 1 }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { writes += 1; return false }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .absent }
		func hasAnyKeyRecord() -> Bool { false }
		func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? { [] }
		func enumerateKeyOwners() -> [String]? { [] }
		/// The mnemonic ownership rule: the account of the pointer is listed when its mnemonic item is present (the double holds no phrase: it asserts the verdict).
		var owner: String?
		func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? { states[.mnemonic] == .present ? (owner.map { [BeamioChatKeyCreation(owner: $0, created: nil)] } ?? []) : [] }
		func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState { states[kind] ?? .absent }
		func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool { writes += 1; return false }
		/// A readable mnemonic item holds the public test phrase of `residueAccount` (the account must derive from the phrase to be valid).
		func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? { kind == .mnemonic && states[.mnemonic] == .present ? BeamioPwaWalletSync.normalized(ValidTestAccounts.phraseA) : nil }
		func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool { deletes += 1; return false }
		func intentOwners() -> [String]? { [] }
	}

	/// The account the public test phrase A derives: a readable mnemonic residue must derive its account (the mnemonic ownership rule).
	private var residueAccount: String { ValidTestAccounts.accountA.eoa }

	/// Installs the residue store with the pointer set, and clears the gate. The caller restores the store with `endResidue`.
	private func beginResidue(pointer: String?, states: [BeamioChatWalletItemKind: BeamioChatItemState], store: ResidueStore) -> BeamioChatWalletKeyStoring {
		NativeAccountPointerIsolation.begin()
		let saved = BeamioNativeWallet.keyStore
		store.states = states
		store.owner = pointer
		BeamioNativeWallet.keyStore = store
		if let pointer { BeamioNativeAccountPointer.set(pointer) }
		return saved
	}

	private func endResidue(restoring saved: BeamioChatWalletKeyStoring) {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = saved
		NativeAccountPointerIsolation.end()
	}

	/// G1 form: no session for the pointer's account. `not_ready` with `g1_uninitialized`: has on the page, never no_key, and no write or delete.
	func testResidueWithReadableMnemonicIsHasG1FormNotNoKey() {
		let store = ResidueStore()
		let saved = beginResidue(pointer: residueAccount, states: [.mnemonic: .present], store: store)
		defer { endResidue(restoring: saved) }
		let result = dispatch(["type": "walletStatus", "reqId": 21])
		XCTAssertNotEqual(result?["status"] as? String, "no_key", "TS-07: a readable mnemonic residue is has, never no_key")
		XCTAssertEqual(result?["status"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "g1_uninitialized")
		XCTAssertNil(result?["accountKey"], "the G1 form carries no accountKey")
		XCTAssertEqual(store.writes + store.deletes, 0, "the answer writes and deletes nothing")
	}

	/// G2 form: the session is ready for the pointer's account. `locked` with the accountKey (from the pointer) and `reason: phrase_only`.
	func testResidueWithReadableMnemonicIsHasG2FormLockedPhraseOnly() {
		let store = ResidueStore()
		let saved = beginResidue(pointer: nil, states: [.mnemonic: .present], store: store)
		defer { endResidue(restoring: saved) }
		BeamioConetChatModule.setNativeGateForTests(account: residueAccount, sessionReady: true)
		let result = dispatch(["type": "walletStatus", "reqId": 22])
		XCTAssertNotEqual(result?["status"] as? String, "no_key", "TS-07: a readable mnemonic residue is has, never no_key")
		XCTAssertEqual(result?["status"] as? String, "locked")
		XCTAssertEqual(result?["accountKey"] as? String, residueAccount + ":default")
		XCTAssertEqual(result?["reason"] as? String, "phrase_only")
		XCTAssertEqual(store.writes + store.deletes, 0, "the answer writes and deletes nothing")
	}

	/// A mnemonic that cannot be read is unknown (`not_ready` with `unreadable`), never has and never no_key.
	func testResidueWithUnreadableMnemonicIsUnreadable() {
		let store = ResidueStore()
		let saved = beginResidue(pointer: residueAccount, states: [.mnemonic: .unreadable], store: store)
		defer { endResidue(restoring: saved) }
		let result = dispatch(["type": "walletStatus", "reqId": 23])
		XCTAssertEqual(result?["status"] as? String, "not_ready")
		XCTAssertEqual(result?["notReadyReason"] as? String, "unreadable")
		XCTAssertNil(result?["accountKey"])
	}

	/// Without a pointer there is no account to judge a residue for: the answer stays no_key, as before.
	func testResidueWithoutPointerStaysNoKey() {
		let store = ResidueStore()
		let saved = beginResidue(pointer: nil, states: [.mnemonic: .present], store: store)
		defer { endResidue(restoring: saved) }
		let result = dispatch(["type": "walletStatus", "reqId": 24])
		XCTAssertEqual(result?["status"] as? String, "no_key")
		XCTAssertNil(result?["accountKey"])
	}

	/// A commit residue without a mnemonic keeps the no_key answer (Y.107 第 3 項, TS-08). Not a has case.
	func testCommitOnlyResidueStaysNoKey() {
		let store = ResidueStore()
		let saved = beginResidue(pointer: residueAccount, states: [.commit: .present], store: store)
		defer { endResidue(restoring: saved) }
		let result = dispatch(["type": "walletStatus", "reqId": 25])
		XCTAssertEqual(result?["status"] as? String, "no_key")
		XCTAssertNil(result?["accountKey"])
	}

	/// 25.52Y.118: `unlocked` always carries the accountKey (eoa + ":default"). No passcode is set here, so the account is not locked.
	func testWalletStatusUnlockedCarriesAccountKey() {
		NativeAccountPointerIsolation.begin()
		let savedStore = BeamioNativeWallet.keyStore
		let savedVault = BeamioPasscodeSession.shared.vault
		let store = KeyAccountLevelCheckTests.OwnerStore()
		let account = residueAccount
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		BeamioPasscodeSession.shared.vault = nil
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		defer {
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			BeamioPasscodeSession.shared.vault = savedVault
			BeamioNativeWallet.keyStore = savedStore
			NativeAccountPointerIsolation.end()
		}
		let result = dispatch(["type": "walletStatus", "reqId": 26])
		XCTAssertEqual(result?["status"] as? String, "unlocked")
		XCTAssertEqual(result?["accountKey"] as? String, account + ":default")
	}
}
