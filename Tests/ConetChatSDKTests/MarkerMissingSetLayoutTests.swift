#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The storage-derived lock `markerMissing` and the no-passcode mnemonic set. `markerMissing` guards the half-written sequence of the key-record path (intent, key, plain mnemonic item,
/// commit, intent removed); the set is one atomic record that writes none of those, so a set without a commit mark must not lock the account. These tests run the PRODUCT stores over the in-memory
/// Keychain with the REAL mark store (the default of the test build is "no marks", so a test with a substitute mark store would not see this lock). Synthetic phrase, key and passcode only.
final class MarkerMissingSetLayoutTests: XCTestCase {
	private var seq = 0
	private var req = 980_000
	private var syn: (phrase: String, eoa: String, passcode: String)!
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedMarks: BeamioNativeMarkReading!
	private var savedPgpMemory: BeamioChatPgpKeychain.MemoryRecords?

	override func setUpWithError() throws {
		try super.setUpWithError()
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let i = try XCTUnwrap(root["syntheticInputs"] as? [String: Any])
		syn = (i["phrase"] as? String ?? "", (i["eoa"] as? String ?? "").lowercased(), i["sixDigitPasscode"] as? String ?? "")
		NativeAccountPointerIsolation.begin()
		AdmittedCreationDevice.install()
		BeamioChatWalletTestMemory.items = [:]
		BeamioNativeAccountPointer.clear()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
		savedMarks = BeamioNativeKeySnapshot.markStore
		BeamioNativeKeySnapshot.markStore = BeamioChatWalletKeychainStore.standard
		BeamioCipherUnlock.clear()
		BeamioMnemonicSets.retireFaultForTests = nil
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeySnapshot.invalidate()
		BeamioPwaWalletSync.restartForTests()
		seq = 0
		// no SI node roster from another test: init must stop at the node stage
		savedPgpMemory = BeamioChatPgpKeychain.memory
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = savedPgpMemory
		BeamioMnemonicSets.retireFaultForTests = nil
		BeamioCipherUnlock.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeKeySnapshot.markStore = savedMarks
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioChatWalletTestMemory.items = [:]
		AdmittedCreationDevice.remove()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	// MARK: - helpers

	private let service = "com.beamio.beamio.chat-wallet"
	private var kc: BeamioChatWalletKeychainStore { BeamioChatWalletKeychainStore.standard }
	private var raw: BeamioChatRawItemStoring { BeamioNativeWallet.keyStore as! BeamioChatRawItemStoring }
	private var items: [String: Data] { BeamioChatWalletTestMemory.items ?? [:] }
	private lazy var theEnvelope: [String: Any] = BeamioMnemonicCipherV3.sealForTests(phrase: syn.phrase, passcode: Array(syn.passcode.utf8), eoa: syn.eoa)!
	private var phraseBytes: Data { BeamioPwaWalletSync.normalized(syn.phrase) }
	private var derivedKey: Data { var d = BeamioPwaWalletSync.derivedAccount(phrase: syn.phrase)!; defer { BeamioNativeWallet.wipe(&d.key) }; return Data(d.key) }

	/// The snapshot as a fresh session start judges it.
	private func snapshot() -> BeamioNativeKeySnapshot.Entry? {
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		return BeamioNativeKeySnapshot.current()
	}

	@discardableResult
	private func sync(_ body: [String: Any]) -> [String: Any] {
		req += 1; seq += 1
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		var full: [String: Any] = ["type": "pwaWalletSync", "reqId": req, "seq": NSNumber(value: seq), "trustedOrigin": true]
		for (k, v) in body { full[k] = v }
		return BeamioPwaWalletSync.answer(full, snapshotKnown: BeamioNativeKeySnapshot.isKnown, storageLocked: BeamioNativeKeySnapshot.current()?.storageLock != nil)
	}

	private func preread() -> [String: Any] {
		req += 1
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		return BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: req, seq: 100_000 + req)["result"] as? [String: Any] ?? [:]
	}

	/// One bridge command through the module, its one answer.
	private func command(_ type: String, _ extra: [String: Any] = [:]) -> [String: Any] {
		req += 1
		var body: [String: Any] = ["type": type, "reqId": req]
		for (k, v) in extra { body[k] = v }
		var answer: [String: Any]?
		let done = expectation(description: type)
		BeamioConetChatModule.handleCommand(body) { payload in
			guard answer == nil, let event = payload["event"] as? [String: Any], "\(event["reqId"] ?? "")" == "\(body["reqId"] ?? "")" else { return }
			answer = event
			done.fulfill()
		}
		wait(for: [done], timeout: 10)
		return answer ?? [:]
	}

	private func status() -> [String: Any] { command("walletStatus")["result"] as? [String: Any] ?? [:] }

	private func lock(_ file: StaticString = #filePath, line: UInt = #line) -> String {
		guard let e = snapshot() else { XCTFail("no snapshot", file: file, line: line); return "none?" }
		if e.unreadable && e.storageLock == nil { return "unreadable" }
		switch e.storageLock {
		case .none: return "none"
		case .some(.markerMissing): return "markerMissing"
		case .some(.recordMissing): return "recordMissing"
		}
	}

	private func commitJSON() -> Data { Data("{\"v\":1,\"eoa\":\"\(syn.eoa)\"}".utf8) }
	private func intentJSON(keep: Bool = false) -> Data {
		(try? JSONSerialization.data(withJSONObject: ["v": 1, "eoa": syn.eoa, "mnemonicPlanned": true, "blobKeyPlanned": true, "startedAt": "1970-01-01T00:00:00Z", "phase": "begun", "keep": keep] as [String: Any], options: [.sortedKeys])) ?? Data()
	}

	/// The older key-record account: the plain mnemonic item and the wallet key record (what the legacy path writes before the commit mark).
	private func writeLegacyItems() {
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: phraseBytes))
		XCTAssertTrue(kc.write(eoa: syn.eoa, key: derivedKey))
		BeamioNativeAccountPointer.set(syn.eoa)
	}

	/// A complete key-record account (commit present), converted by a passcode sync: the v3 record is verified and the older copies are retired. Then the commit mark and the intent are removed and
	/// the plain item is put back on disk (an interrupted deletion), so only the view decides what the lock sees.
	private func makeRetiredAccountWithoutCommit() {
		writeLegacyItems()
		XCTAssertTrue(kc.writeItem(.commit, eoa: syn.eoa, value: commitJSON()))
		let stored = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((stored["result"] as? [String: Any])?["decrypted"] as? Bool, true, "\(stored)")
		_ = kc.deleteItem(.commit, eoa: syn.eoa)
		BeamioChatWalletTestMemory.put(service, BeamioChatWalletKeychainStore.itemAccount(.mnemonic, owner: syn.eoa), phraseBytes)
		BeamioNativeKeySnapshot.invalidate()
	}

	private func writeSet() {
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: syn.phrase, store: raw, utc: "1970-01-01T00:00:00Z"), .updated)
		BeamioNativeAccountPointer.set(syn.eoa)
	}

	// MARK: - the state matrix (the set, and the plain device item as legacyView shows it) x (commit, intent)
	//
	//  mnemonic source seen by judgeMarks      commit  intent   expected
	//  --------------------------------------  ------  ------   ----------------------------------------------------------
	//  set only (no plain item)                 no      no       none            (the fix: an atomic set is not half-written)
	//  set only                                 no      yes      markerMissing   (a half-written key-record sequence left an intent)
	//  set only                                 yes     no       none
	//  plain item, legacyView live              no      no       markerMissing   (the commit mark vanished from a key-record account)
	//  plain item, legacyView live              yes     no       none            (a complete key-record account)
	//  plain item, legacyView live              no      yes      markerMissing   (half written)
	//  set + plain item, legacyView live        no      no       markerMissing   (a stray half-written plain item: conservative)
	//  v3 verified + plain item, retired        no      no       none            (the plain item is hidden: it reads as absent)
	//  v3 verified + plain item, retired        no      yes      markerMissing   (an intent is an intent)
	//  retiredUnverified                        no      no       unreadable      (never "no account", never a lock)
	//  retired record unreadable (unknown)      -       -        unreadable

	func testMatrixSetOnlyWithoutCommitOrIntentIsNotLocked() {
		writeSet()
		XCTAssertEqual(lock(), "none")
	}

	func testMatrixSetWithAnIntentIsStillMarkerMissing() {
		writeSet()
		XCTAssertTrue(kc.writeItem(.intent, eoa: syn.eoa, value: intentJSON()))
		XCTAssertEqual(lock(), "markerMissing")
	}

	func testMatrixSetWithACommitIsNotLocked() {
		writeSet()
		XCTAssertTrue(kc.writeItem(.commit, eoa: syn.eoa, value: commitJSON()))
		XCTAssertEqual(lock(), "none")
	}

	func testMatrixLivePlainItemWithoutCommitIsMarkerMissing() {
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: phraseBytes))
		BeamioNativeAccountPointer.set(syn.eoa)
		XCTAssertEqual(lock(), "markerMissing")
	}

	func testMatrixLivePlainItemWithACommitIsNotLocked() {
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: phraseBytes))
		XCTAssertTrue(kc.writeItem(.commit, eoa: syn.eoa, value: commitJSON()))
		BeamioNativeAccountPointer.set(syn.eoa)
		XCTAssertEqual(lock(), "none")
	}

	func testMatrixLivePlainItemWithAnIntentAndNoCommitIsMarkerMissing() {
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: phraseBytes))
		XCTAssertTrue(kc.writeItem(.intent, eoa: syn.eoa, value: intentJSON()))
		BeamioNativeAccountPointer.set(syn.eoa)
		XCTAssertEqual(lock(), "markerMissing")
	}

	func testMatrixTheSetBesideAStrayPlainItemWithoutCommitStaysMarkerMissing() {
		writeSet()
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: phraseBytes))
		XCTAssertEqual(lock(), "markerMissing", "a stray plain item without a commit is a half-written key-record account: the lock stays")
	}

	/// Retired: the v3 record is verified and the older copies' cleanup record exists, so the readers see the plain item as absent although it may still be on disk. The lock must follow what the
	/// readers see (legacyView), not the raw item: a raw read of the plain item would make this test fail.
	func testMatrixARetiredPlainItemIsHiddenAndDoesNotLock() {
		makeRetiredAccountWithoutCommit()
		XCTAssertEqual(BeamioMnemonicSets.legacyView(store: raw, eoa: syn.eoa), .retired)
		XCTAssertEqual(kc.itemState(.mnemonic, eoa: syn.eoa), .present, "the v3 record is the account's mnemonic")
		XCTAssertEqual(kc.legacyMnemonicItemState(eoa: syn.eoa), .absent, "the retired plain item reads as absent")
		XCTAssertEqual(lock(), "none")
	}

	func testMatrixARetiredPlainItemWithAnIntentIsStillMarkerMissing() {
		makeRetiredAccountWithoutCommit()
		XCTAssertEqual(BeamioMnemonicSets.legacyView(store: raw, eoa: syn.eoa), .retired)
		XCTAssertTrue(kc.writeItem(.intent, eoa: syn.eoa, value: intentJSON()))
		XCTAssertEqual(lock(), "markerMissing")
	}

	/// retiredUnverified: the pointer and the cleanup record retire the plain copies but the v3 record does not read back.
	func testMatrixRetiredUnverifiedIsUnreadableNotALock() {
		makeRetiredAccountWithoutCommit()
		// remove the verified v3 record, keep the cleanup record: the view becomes retiredUnverified
		for name in items.keys where name.contains(BeamioMnemonicSets.setName(syn.eoa) + ".c.") {
			if let account = name.components(separatedBy: "\u{1}").last { BeamioChatWalletTestMemory.remove(service, account) }
		}
		XCTAssertEqual(BeamioMnemonicSets.legacyView(store: raw, eoa: syn.eoa), .retiredUnverified)
		XCTAssertEqual(kc.legacyMnemonicItemState(eoa: syn.eoa), .unreadable)
		let state = lock()
		XCTAssertNotEqual(state, "markerMissing")
		XCTAssertNotEqual(state, "none", "an unverified retirement is never read as a healthy account")
	}

	/// The only unreadable mark is the plain item as the retirement view shows it: a set is valid, a cleanup record of the older copies exists, and no v3 record verifies it (retiredUnverified).
	/// The legacy mnemonic state is then unreadable, and the snapshot must be unreadable: not a lock, and not a healthy account. (Ignoring the legacy state in judgeMarks does not change this answer,
	/// because the account inventory reads the same plain item and is unreadable too: an equivalent mutant, kept as a redundant fail-closed clause.)
	func testAnUnreadableLegacyMarkAloneMakesTheSnapshotUnreadable() {
		writeSet()
		XCTAssertEqual(lock(), "none")
		let pending = Data("{\"v\":1,\"eoa\":\"\(syn.eoa)\",\"state\":\"pending\"}".utf8)
		XCTAssertTrue(raw.rawWrite(account: BeamioMnemonicSets.legacyRetireName(syn.eoa), bytes: pending))
		XCTAssertEqual(BeamioMnemonicSets.legacyView(store: raw, eoa: syn.eoa), .retiredUnverified)
		XCTAssertEqual(kc.legacyMnemonicItemState(eoa: syn.eoa), .unreadable)
		XCTAssertEqual(lock(), "unreadable")
	}

	/// The product mark store with one kind of mark made unreadable (a Keychain read that fails), everything else delegated.
	private struct MarksWithUnreadable: BeamioNativeMarkReading {
		let kind: BeamioChatWalletItemKind
		func itemState(_ k: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
			k == kind ? .unreadable : BeamioChatWalletKeychainStore.standard.itemState(k, eoa: eoa)
		}
		func legacyMnemonicItemState(eoa: String) -> BeamioChatItemState { BeamioChatWalletKeychainStore.standard.legacyMnemonicItemState(eoa: eoa) }
	}

	/// An unreadable commit mark is unknown: the snapshot is unreadable. It is neither let through (no lock, healthy) nor locked. Ignoring `commit == .unreadable` in the judgement would make this test fail.
	func testAnUnreadableCommitMarkMakesTheSnapshotUnreadable() {
		writeSet()
		XCTAssertEqual(lock(), "none")
		BeamioNativeKeySnapshot.markStore = MarksWithUnreadable(kind: .commit)
		XCTAssertEqual(lock(), "unreadable")
	}

	/// An unreadable intent mark likewise. Ignoring `intent == .unreadable` in the judgement would make this test fail.
	func testAnUnreadableIntentMarkMakesTheSnapshotUnreadable() {
		writeSet()
		XCTAssertEqual(lock(), "none")
		BeamioNativeKeySnapshot.markStore = MarksWithUnreadable(kind: .intent)
		XCTAssertEqual(lock(), "unreadable")
	}

	// MARK: - the three writers of the set layout leave no lock, and the gates open

	private func assertOpenAfterTheWrite(_ label: String, file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertEqual(lock(file, line: line), "none", "\(label): the snapshot has no lock", file: file, line: line)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, label, file: file, line: line)
		let walletStatus = status()
		XCTAssertEqual(walletStatus["status"] as? String, "not_ready", label, file: file, line: line)
		XCTAssertEqual(walletStatus["notReadyReason"] as? String, "g1_uninitialized", "\(label): the G1 answer, not unreadable", file: file, line: line)
		// init is no longer answered in front of the gate: it reaches the node stage (nodes_unavailable with none; bad_request for a value that is not a list)
		let noNodes = command("init", ["payload": ["identity": ["eoa": syn.eoa]]])
		XCTAssertEqual(noNodes["error"] as? String, "nodes_unavailable", "\(label): init passes the key stage: \(noNodes)", file: file, line: line)
		let badNodes = command("init", ["payload": ["identity": ["eoa": syn.eoa], "nodes": "x"]])
		XCTAssertEqual(badNodes["error"] as? String, "bad_request", label, file: file, line: line)
		// pgpMigrate before the session is ready: the G1 answer
		XCTAssertEqual(command("pgpMigrate")["error"] as? String, "not_ready", label, file: file, line: line)
	}

	func testRecoveryLeavesNoLockAndTheGatesOpen() {
		let out = BeamioNativeKeyImport.importRecoveryPhrase(text: syn.phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore)
		XCTAssertEqual(out, .imported)
		assertOpenAfterTheWrite("recovery")
	}

	func testNativeCreateLeavesNoLockAndTheGatesOpen() throws {
		let made = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: [UInt8](repeating: 0x42, count: 16), userExplicit: true)
		guard case .made(let material) = made else { return XCTFail("the creation must succeed: \(made)") }
		syn = (syn.phrase, material.eoa, syn.passcode)
		assertOpenAfterTheWrite("native create")
	}

	func testPageSyncOfAPhraseLeavesNoLockOnceThePointerNamesTheAccount() {
		let answer = sync(["eoa": syn.eoa, "phrase": syn.phrase])
		XCTAssertEqual((answer["result"] as? [String: Any])?["sync"] as? String, "updated", "\(answer)")
		BeamioNativeAccountPointer.set(syn.eoa)   // what init's silent selection does for the one account
		assertOpenAfterTheWrite("page sync")
	}

	/// The session is ready for the recovered account: pgpMigrate runs and answers with a result (the lock used to refuse it at every gate state).
	func testPgpMigrateRunsAtG2AfterARecovery() throws {
		try PgpMigrationTestSupport.requireX19()
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: syn.phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore), .imported)
		XCTAssertEqual(lock(), "none")
		BeamioConetChatModule.setNativeGateForTests(account: syn.eoa, sessionReady: true)
		BeamioConetChatModule.pgpMigrationEnvironmentOverride = PgpMigrationTestSupport.environment(store: PgpMigrationTestSupport.MemoryStore(), crypto: PgpMigrationTestSupport.Crypto(), registeredArmor: nil)
		defer { BeamioConetChatModule.pgpMigrationEnvironmentOverride = nil }
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "pgpMigrate", "reqId": "m1"], emit: { event in events.append((event["event"] as? [String: Any]) ?? event) })
		let deadline = Date().addingTimeInterval(15)
		while !events.contains(where: { $0["type"] as? String == "pgpMigrateResult" }) && Date() < deadline { RunLoop.main.run(until: Date().addingTimeInterval(0.01)) }
		XCTAssertEqual(events.first { $0["type"] as? String == "ack" }?["ok"] as? Bool, true, "\(events)")
		XCTAssertNotNil(events.first { $0["type"] as? String == "pgpMigrateResult" }, "a result event arrives: \(events)")
	}

	// MARK: - the sync, preread and shell record on a recovered account

	func testSyncOfTheSamePhraseIsIdempotentAndWritesNothing() {
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: syn.phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore), .imported)
		let before = items
		let answer = sync(["eoa": syn.eoa, "phrase": syn.phrase])
		XCTAssertEqual((answer["result"] as? [String: Any])?["sync"] as? String, "idempotent", "\(answer)")
		XCTAssertEqual(items, before, "nothing was rewritten")
	}

	/// Another phrase is another account: it is added as its own set, and it neither replaces the recovered account's set nor moves the account pointer.
	func testSyncOfAnotherPhraseDoesNotReplaceTheRecoveredAccount() {
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: syn.phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore), .imported)
		let recoveredSetName = items.keys.first { $0.hasSuffix(BeamioMnemonicSets.setName(syn.eoa)) }
		let recoveredSet = recoveredSetName.flatMap { items[$0] }
		XCTAssertNotNil(recoveredSet)
		let other = "legal winner thank year wave sausage worth useful legal winner thank yellow"
		let otherEoa = BeamioPwaWalletSync.derivedAccount(phrase: other)!.eoa
		let answer = sync(["eoa": otherEoa, "phrase": other])
		XCTAssertEqual((answer["result"] as? [String: Any])?["eoa"] as? String, otherEoa, "\(answer)")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), syn.eoa, "the account pointer did not move")
		XCTAssertEqual(recoveredSetName.flatMap { items[$0] }, recoveredSet, "the recovered account's set is byte for byte the same")
		XCTAssertEqual(lock(), "none")
		XCTAssertEqual(status()["notReadyReason"] as? String, "g1_uninitialized")
	}

	func testPrereadReturnsThePhraseOnlyForTheNoPasscodeSet() {
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: syn.phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore), .imported)
		let read = preread()
		XCTAssertEqual(read["code"] as? String, "ok")
		XCTAssertEqual(read["mnemonic"] as? String, String(decoding: phraseBytes, as: UTF8.self))
		XCTAssertEqual(read["eoa"] as? String, syn.eoa)
		XCTAssertNil(read["cipher"])
	}

	func testShellRecordReadAnswersTheG1FormBeforeInitAndIsNotLocked() {
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: syn.phrase, expectedEoa: "", store: BeamioNativeWallet.keyStore), .imported)
		let answer = command("shellRecordRead", ["eoa": syn.eoa])
		let result = answer["result"] as? [String: Any]
		XCTAssertEqual(result?["code"] as? String, "not_ready", "\(answer)")
		XCTAssertEqual(result?["notReadyReason"] as? String, "g1_uninitialized", "the G1 form, not the unreadable lock answer")
		XCTAssertEqual(result?["retryable"] as? Bool, true)
	}

	// MARK: - the passcode forms (the lock must not change what they showed)

	/// v3 envelope, the production passcode form: the pointer stays empty (the device names the account by the envelope), so the mark judgement never applies. Locked: not_ready /
	/// passcode_not_provided, the preread returns the cipher and never a phrase, the address command is not_ready. Unlocked: unlocked, the address answers.
	func testV3EnvelopeLockedAndUnlockedAreUnchanged() {
		let stored = sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertEqual((stored["result"] as? [String: Any])?["decrypted"] as? Bool, false, "\(stored)")
		XCTAssertEqual(lock(), "none")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the v3 account is named by its envelope, not by the pointer")
		var locked = status()
		XCTAssertEqual(locked["status"] as? String, "not_ready")
		XCTAssertEqual(locked["notReadyReason"] as? String, "passcode_not_provided")
		XCTAssertEqual(locked["retryable"] as? Bool, true)
		let read = preread()
		XCTAssertNil(read["mnemonic"], "a v3 account never returns the phrase")
		XCTAssertNotNil(read["cipher"])
		XCTAssertEqual(command("walletAddress")["error"] as? String, "not_ready")
		XCTAssertEqual(command("deriveSubkeys")["error"] as? String, "no_key", "with no account pointer the gate is G0: unchanged by this change")
		let unlocked = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((unlocked["result"] as? [String: Any])?["decrypted"] as? Bool, true, "\(unlocked)")
		XCTAssertEqual(lock(), "none")
		locked = status()
		XCTAssertEqual(locked["status"] as? String, "unlocked")
		XCTAssertEqual((command("walletAddress")["result"] as? [String: Any])?["address"] as? String, syn.eoa)
		XCTAssertNil(preread()["mnemonic"])
	}

	/// The older vault form: a no-passcode set with a passcode record beside it (the account is locked and its phrase is hidden). The snapshot is unreadable (unknown, never absent and never
	/// a lock), walletStatus is not_ready / unreadable, key commands are not_ready and the preread returns no phrase. The change does not touch this branch (the unreadable answer comes first).
	func testTheOlderVaultFormLockedSetStaysUnreadable() throws {
		writeSet()
		let record = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		XCTAssertTrue(BeamioPasscodeKeychainRecords.standard.writeRecord(eoa: syn.eoa, try JSONEncoder().encode(record)))
		defer { BeamioPasscodeKeychainRecords.standard.deleteRecord(eoa: syn.eoa) }
		BeamioNativeKeySnapshot.invalidate()
		XCTAssertTrue(BeamioPasscodeSession.shared.isLocked(eoa: syn.eoa))
		XCTAssertEqual(lock(), "unreadable")
		XCTAssertEqual(status()["notReadyReason"] as? String, "unreadable")
		XCTAssertEqual(command("deriveSubkeys")["error"] as? String, "not_ready")
		let read = preread()
		XCTAssertNil(read["mnemonic"])
		XCTAssertEqual(read["code"] as? String, "read_error")
	}

	// MARK: - a stale intent: who clears it, and when
	//
	// The intent is written first and removed last by the key-record import path only. The start-up reconciliation (`BeamioNativeKeyImport.reconcileOnceAtStart`, called by `handleCommand`
	// before the first command of every process) removes an intent that has a commit, and rolls back an intent that has none (its key and plain mnemonic item, then the intent). An intent that
	// cannot be read or judged deletes nothing and marks the account unavailable for that process; the next process tries again. A set account never writes an intent.

	func testAStaleIntentWithACommitIsRemovedAtTheNextStart() {
		writeSet()
		XCTAssertTrue(kc.writeItem(.commit, eoa: syn.eoa, value: commitJSON()))
		XCTAssertTrue(kc.writeItem(.intent, eoa: syn.eoa, value: intentJSON()))
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeyImport.reconcileOnceAtStart()
		XCTAssertEqual(kc.itemState(.intent, eoa: syn.eoa), .absent, "the leftover intent is gone")
		XCTAssertEqual(lock(), "none")
	}

	/// An interrupted key-record import (intent, wallet key record, plain mnemonic item, no commit) on the product store: the start-up reconciliation rolls the registered records back in reverse order.
	/// The product passcode store has its device-record deletes switched off, so the key record cannot be removed; the rollback then fails after the mnemonic item is gone, the intent is kept and
	/// the account is marked unavailable for the process (fail closed, retried at the next start). Before the reconciliation the account is `markerMissing`; after it the plain mnemonic item (the
	/// part the lock guarded) is gone, so the snapshot no longer reports `markerMissing`. This documents the state; it is not produced by the set layout (a set never writes an intent).
	func testAnInterruptedKeyRecordImportIsFailClosedAfterTheReconciliation() {
		XCTAssertTrue(kc.writeItem(.intent, eoa: syn.eoa, value: intentJSON()))
		XCTAssertTrue(kc.write(eoa: syn.eoa, key: derivedKey))
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: phraseBytes))
		BeamioNativeAccountPointer.set(syn.eoa)
		XCTAssertEqual(lock(), "markerMissing", "before the start-up reconciliation the half-written account is locked")
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeyImport.reconcileOnceAtStart()
		XCTAssertEqual(kc.itemState(.mnemonic, eoa: syn.eoa), .absent, "the plain mnemonic item was rolled back")
		XCTAssertEqual(kc.itemState(.intent, eoa: syn.eoa), .present, "the intent is kept: the key record could not be removed")
		XCTAssertTrue(BeamioNativeKeyImport.isIntentUnavailable(eoa: syn.eoa), "the account is unavailable for this process")
		XCTAssertNotEqual(lock(), "markerMissing")
	}

	/// An intent that cannot be judged deletes nothing and keeps the account locked (fail closed); this is by design, it is not caused by the set layout, and it is retried at every start.
	func testAnUnjudgeableIntentDeletesNothingAndStaysLocked() {
		writeSet()
		XCTAssertTrue(kc.writeItem(.intent, eoa: syn.eoa, value: Data("not json".utf8)))
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeyImport.reconcileOnceAtStart()
		XCTAssertEqual(kc.itemState(.intent, eoa: syn.eoa), .present, "nothing was deleted")
		XCTAssertTrue(BeamioNativeKeyImport.isIntentUnavailable(eoa: syn.eoa))
		XCTAssertEqual(lock(), "markerMissing")
	}

	/// A set account with no intent never gets one, whatever the start-up does: the lock cannot appear after the reconciliation either.
	func testASetAccountStaysUnlockedAcrossTheStartUpReconciliation() {
		writeSet()
		BeamioNativeKeyImport.resetStartupForTests()
		BeamioNativeKeyImport.reconcileOnceAtStart()
		XCTAssertEqual(lock(), "none")
		XCTAssertEqual(kc.itemState(.intent, eoa: syn.eoa), .absent)
	}

	// MARK: - nothing is written by the judgement

	func testTheJudgementWritesNothing() {
		writeSet()
		let before = items
		_ = lock()
		_ = status()
		XCTAssertEqual(items, before, "judging the snapshot does not change a single Keychain item")
	}
}
#endif
