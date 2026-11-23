import XCTest
@testable import ConetChatSDK

/// The narrow discard of private-key records, through `pwaEmptySignal` (25.52Y.163 r2.5.19, 第 46、53、58、59(4) 项). A private-key record is a key
/// with no valid mnemonic. Nothing else is named by the discard: the pending PGP record of chat-pgp-pending is outside its range (project ruling).
/// Synthetic keys only; no key bytes are asserted in text.
final class PwaEmptySignalDiscardTests: XCTestCase {
	private let privateEoa = "0x1111111111111111111111111111111111111111"
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioPwaWalletSync.restartForTests()
		_ = store.write(eoa: privateEoa, key: Data(repeating: 0x11, count: 32))
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func signal(_ state: String, seq: Int64 = 100, nativeReadSeq: Int64? = nil) -> [String: Any] {
		BeamioPwaWalletSync.answer(["type": "pwaEmptySignal", "reqId": 1, "trustedOrigin": true,
		                            "seq": NSNumber(value: seq), "pwaState": state],
		                           snapshotKnown: true, storageLocked: false, nativeReadSeq: nativeReadSeq ?? seq)
	}

	private func auditRows() -> [[String: Any]] {
		guard case .present(let bytes) = store.rawRead(account: BeamioNarrowDiscardStore.auditAccount),
		      let rows = try? JSONSerialization.jsonObject(with: bytes) as? [[String: Any]]
		else { return [] }
		return rows
	}

	private func keyKept() -> Bool {
		store.read(eoa: privateEoa) != nil
	}

	/// iOS review 2026-11-17 (PS-05, scope pwa): the native snapshot was taken at seq 3, the signal is seq 4. Both sides are explicitly empty, and the
	/// signal is the latest accepted seq, yet nothing is discarded: the discard needs the snapshot at the signal's own seq.
	func testANativeSnapshotAtAnotherSeqDiscardsNothing() {
		BeamioPwaWalletSync.recordAccepted(3)
		let answer = signal("explicit_empty", seq: 4, nativeReadSeq: 3)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "ok", "the signal itself is accepted and recorded")
		XCTAssertTrue(keyKept(), "a snapshot from another seq never discards")
		XCTAssertTrue(auditRows().isEmpty, "no discard audit row")
	}

	/// The same snapshot seq as the signal, both sides explicitly empty and the latest seq: the discard runs.
	func testTheSameSnapshotSeqWithBothExplicitEmptyDiscards() {
		BeamioPwaWalletSync.recordAccepted(3)
		let answer = signal("explicit_empty", seq: 4, nativeReadSeq: 4)
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertTrue(keyKept(), "not discarded: a signal never removes a record")
	}

	// 第 46(6) 项, 第 59(4)(b) 项: an explicitly empty signal with no mnemonic on the device discards the private-key record, with one audit row.
	// 2026-11-17 project constant (the project lead): an explicitly empty signal never removes a record, even a private-key record with no mnemonic.
	func testAnExplicitEmptySignalDeletesNothing() {
		XCTAssertEqual(signal("explicit_empty")["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "the private-key record is kept")
		XCTAssertTrue(auditRows().isEmpty, "no discard, no audit row")
		XCTAssertEqual(store.rawRead(account: BeamioNarrowDiscardStore.intentAccount), .absent, "no intent is written")
		XCTAssertFalse(store.rawAccounts.keys.contains { $0.hasPrefix(BeamioNarrowDiscardStore.isolationPrefix) }, "no copy is made")
	}

	// 第 46 项: chat-pgp-pending is not in the discard range; its record survives a discard.
	func testTheChatPgpPendingRecordIsOutsideTheDiscardRange() {
		let pending = "chat-pgp-pending." + privateEoa
		store.rawAccounts[pending] = Data("pending-record".utf8)
		XCTAssertEqual(signal("explicit_empty")["ok"] as? Bool, true)
		XCTAssertTrue(keyKept())
		XCTAssertEqual(store.rawAccounts[pending], Data("pending-record".utf8), "the pending PGP record is not touched")
	}

	// 第 46(1) 项, 第 53(3) 项: unknown or valid is not a basis for a deletion; the signal is accepted and nothing is removed.
	func testOnlyAnExplicitEmptySignalDiscards() {
		XCTAssertEqual(signal("unknown")["ok"] as? Bool, true)
		XCTAssertEqual(signal("valid", seq: 101)["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "neither unknown nor valid removes a record")
		XCTAssertTrue(auditRows().isEmpty, "no discard, no audit row")
	}

	// 第 42(4) 项, 第 46(2) 项: a valid mnemonic on the device means the native side is not explicitly empty, so nothing is removed.
	func testAMnemonicOnTheDeviceBlocksTheDiscard() {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { return XCTFail("the phrase derives an account") }
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: derived.eoa, value: BeamioPwaWalletSync.normalized(phrase)))
		XCTAssertTrue(store.writeItem(.commit, eoa: derived.eoa, value: Data(#"{"v":1}"#.utf8)))
		XCTAssertEqual(signal("explicit_empty")["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "the private-key record stays while a mnemonic is held")
	}

	// 第 56(1) 项, 第 59(4)(d) 项: a stale signal is not recorded and nothing is discarded.
	func testAStaleSignalDiscardsNothing() {
		XCTAssertEqual(signal("unknown", seq: 10)["ok"] as? Bool, true)
		let stale = signal("explicit_empty", seq: 5)
		XCTAssertEqual((stale["result"] as? [String: Any])?["code"] as? String, "stale_seq")
		XCTAssertTrue(keyKept())
	}

	// 第 59(4)(c) 项: the intent cannot be written, so the discard is not durable: write_failed with reason internal_state; nothing is removed.
	// 2026-11-17 project constant: no intent is written on this path, so a failing write cannot make a removal; the signal is accepted and nothing is removed.
	func testAFailedWriteOnTheSignalPathRemovesNothing() {
		store.failMutationAt = store.mutationCount + 1
		let answer = signal("explicit_empty")
		store.failMutationAt = nil
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "nothing is removed")
	}

	// 第 46(3) 项: the audit row comes before any record moves; a failed audit removes nothing.
	// 2026-11-17 project constant: no audit row is written on this path, and nothing is removed.
	func testAFailedAuditOnTheSignalPathRemovesNothing() {
		let base = store.mutationCount
		store.failMutationAt = base + 2
		let answer = signal("explicit_empty")
		store.failMutationAt = nil
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "nothing is removed")
		XCTAssertEqual(store.rawRead(account: BeamioNarrowDiscardStore.intentAccount), .absent)
	}

	// 第 46(5) 项, 第 55(1) 项: a removal that fails after the copy restores the record, writes the abort row (count 0), and removes the intent.
	// 2026-11-17 project constant: no removal is attempted, so no restore or abort row is needed; the record stays.
	func testNoRemovalIsAttemptedSoNoAbortRowIsWritten() {
		let base = store.mutationCount
		store.failMutationAt = base + 4
		let answer = signal("explicit_empty")
		store.failMutationAt = nil
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "the record was never removed")
		XCTAssertTrue(auditRows().isEmpty, "no abort row: nothing was attempted")
		XCTAssertFalse(store.rawAccounts.keys.contains { $0.hasPrefix(BeamioNarrowDiscardStore.isolationPrefix) }, "no copy is left")
	}

	// 第 55(1) 項: a leftover prepared intent is rolled back from its copy at the next start; the record is restored byte for byte.
	func testAStartupRollsBackALeftoverPreparedIntent() {
		let from = store.accountName(.key, eoa: privateEoa)
		let bytes = Data(repeating: 0x22, count: 32)
		let copy = BeamioNarrowDiscardStore.isolationPrefix + "t1." + from
		let move = BeamioPwaPhraseOverwrite.Move(from: from, to: copy, digest: BeamioPwaPhraseOverwrite.digest(bytes))
		XCTAssertTrue(store.rawWrite(account: copy, bytes: bytes))
		XCTAssertTrue(store.rawWrite(account: BeamioNarrowDiscardStore.intentAccount,
		                             bytes: BeamioNarrowDiscardStore.intentBytes(phase: "prepared", utc: "1970-01-01T00:00:00Z", moves: [move])))
		store.delete(eoa: privateEoa)
		XCTAssertTrue(BeamioNarrowDiscardStore.recoverAtStart(store: store))
		XCTAssertEqual(store.read(eoa: privateEoa), bytes, "the record is restored byte for byte")
		XCTAssertEqual(store.rawRead(account: BeamioNarrowDiscardStore.intentAccount), .absent)
		XCTAssertEqual(store.rawRead(account: copy), .absent, "the copy is removed")
	}

	/// Seeds a leftover prepared intent with its copy, and the record removed: the state a crash leaves behind.
	private func seedLeftoverIntent(tag: String) -> (copy: String, bytes: Data) {
		let from = store.accountName(.key, eoa: privateEoa)
		let bytes = Data(repeating: 0x33, count: 32)
		let copy = BeamioNarrowDiscardStore.isolationPrefix + tag + "." + from
		let move = BeamioPwaPhraseOverwrite.Move(from: from, to: copy, digest: BeamioPwaPhraseOverwrite.digest(bytes))
		XCTAssertTrue(store.rawWrite(account: copy, bytes: bytes))
		XCTAssertTrue(store.rawWrite(account: BeamioNarrowDiscardStore.intentAccount,
		                             bytes: BeamioNarrowDiscardStore.intentBytes(phase: "prepared", utc: "1970-01-01T00:00:00Z", moves: [move])))
		store.delete(eoa: privateEoa)
		return (copy, bytes)
	}

	// project ruling: the start-up settles a leftover discard intent once per process, not at the next signal.
	func testStartupSettlesALeftoverDiscardIntentOnce() {
		let first = seedLeftoverIntent(tag: "s1")
		BeamioPwaPhraseOverwrite.resetStartupForTests()
		BeamioPwaPhraseOverwrite.settleOnceAtStart(store: store)
		XCTAssertEqual(store.read(eoa: privateEoa), first.bytes, "the leftover is rolled back at the start")
		XCTAssertEqual(store.rawRead(account: BeamioNarrowDiscardStore.intentAccount), .absent)
		XCTAssertEqual(store.rawRead(account: first.copy), .absent)
		// A second leftover is not settled by a second run in the same process: the start-up runs once.
		let second = seedLeftoverIntent(tag: "s2")
		BeamioPwaPhraseOverwrite.settleOnceAtStart(store: store)
		XCTAssertNotEqual(store.rawRead(account: BeamioNarrowDiscardStore.intentAccount), .absent, "the second run is not performed")
		XCTAssertEqual(store.read(eoa: privateEoa), nil, "the second leftover is still pending")
		XCTAssertEqual(store.rawRead(account: second.copy) != .absent, true)
	}

	// project ruling (第 53(7) 项): an older empty signal, after a higher accepted seq, is stale and discards nothing.
	func testAnOlderEmptySignalIsNotDiscardedAfterAHigherSeq() {
		XCTAssertEqual(signal("unknown", seq: 200)["ok"] as? Bool, true)
		let older = signal("explicit_empty", seq: 100)
		XCTAssertEqual((older["result"] as? [String: Any])?["code"] as? String, "stale_seq")
		XCTAssertTrue(keyKept(), "the older empty signal is void")
		XCTAssertTrue(auditRows().isEmpty)
	}

	// project ruling: a later higher-seq sync with a mnemonic. The discard runs only when its signal is the latest accepted seq at the time of the
	// decision, so a sync after it does not resurrect the removed record, and the sync does not discard anything itself.
	func testAHigherSyncAfterAnExplicitSignalKeepsTheDiscardAndDiscardsNothingNew() {
		XCTAssertEqual(signal("explicit_empty", seq: 100)["ok"] as? Bool, true)
		XCTAssertTrue(keyKept(), "no discard runs: a signal never removes a record")
		let sync = BeamioPwaWalletSync.answer(["type": "pwaWalletSync", "reqId": 2, "trustedOrigin": true,
		                                        "seq": NSNumber(value: Int64(200)), "phrase": phrase],
		                                       snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((sync["result"] as? [String: Any])?["sync"] as? String, "updated")
		XCTAssertTrue(auditRows().isEmpty, "no discard audit row is written")
	}
}
