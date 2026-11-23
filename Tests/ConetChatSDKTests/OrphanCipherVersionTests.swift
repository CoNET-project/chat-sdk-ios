#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// A v3 cipher version item (`mnemonic.set.<eoa>.c.<digest>`) is written before the pointer `mnemonic.current` names it, so a refused pointer write leaves a version that no
/// pointer names. Such a version is a recorded account: the preread answers `read_error` (never `confirmed_missing`), and a creation is blocked beside it (the probe finds a
/// residue). Sending the same envelope again writes the pointer, and the state is normal again. Run through the product store over the in-memory Keychain.
final class OrphanCipherVersionTests: XCTestCase {
	private var seq = 0
	private var req = 960_000
	private var syn: (phrase: String, eoa: String, passcode: String)!
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUpWithError() throws {
		try super.setUpWithError()
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let i = try XCTUnwrap(root["syntheticInputs"] as? [String: Any])
		syn = (i["phrase"] as? String ?? "", (i["eoa"] as? String ?? "").lowercased(), i["sixDigitPasscode"] as? String ?? "")
		NativeAccountPointerIsolation.begin()
		BeamioChatWalletTestMemory.items = [:]
		BeamioNativeAccountPointer.clear()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore.standard
		BeamioCipherUnlock.clear()
		BeamioNativeKeySnapshot.invalidate()
		BeamioPwaWalletSync.restartForTests()
		seq = 0
	}

	override func tearDown() {
		BeamioCipherUnlock.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioChatWalletTestMemory.items = [:]
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// One envelope for a test (a seal draws a new salt and iv, so a second call would be another envelope).
	private lazy var theEnvelope: [String: Any] = BeamioMnemonicCipherV3.sealForTests(phrase: syn.phrase, passcode: Array(syn.passcode.utf8), eoa: syn.eoa)!
	private func envelope() -> [String: Any] { theEnvelope }

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
		let answer = BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: req, seq: 100_000 + req)
		return answer["result"] as? [String: Any] ?? [:]
	}

	private var items: [String: Data] { BeamioChatWalletTestMemory.items ?? [:] }
	private func pointerKey() -> String? { items.keys.first { $0.hasSuffix(BeamioMnemonicSets.currentName) } }
	private var versionKeys: [String] { items.keys.filter { $0.contains(BeamioMnemonicSets.setName(syn.eoa) + ".c.") } }

	/// The state after a pointer write that was refused: the version item is stored, the pointer is not.
	private func makeOrphan() {
		let first = sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertEqual((first["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertEqual(versionKeys.count, 1, "one version item")
		let key = try? XCTUnwrap(pointerKey())
		BeamioChatWalletTestMemory.items?.removeValue(forKey: key ?? "")
		XCTAssertNil(pointerKey(), "no pointer")
		BeamioPwaPreread.restartForTests()   // the published reading was taken before the pointer went; a refused pointer write publishes the reading after it
		BeamioNativeKeySnapshot.invalidate()
	}

	// MARK: - the names

	func testTheVersionNameParserAcceptsOnlyCipherVersionNames() {
		let eoa = "0x" + String(repeating: "a", count: 40)
		XCTAssertEqual(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic.set.\(eoa).c.0123456789abcdef"), eoa)
		XCTAssertNil(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic.set.\(eoa)"), "the plaintext set is not a version")
		XCTAssertNil(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic.set.\(eoa).c."), "no digest")
		XCTAssertNil(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic.set..c.0123"), "no owner")
		XCTAssertNil(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic.current"))
		XCTAssertNil(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic:\(eoa)"))
		XCTAssertNil(BeamioMnemonicSets.cipherVersionOwner(inAccount: "mnemonic.set.a.b.c.0123"), "an owner holds no dot")
	}

	// MARK: - T4: the preread

	/// T4: a version, no pointer: the preread is a read failure, not a confirmed absence (the record exists and cannot be named yet).
	func testAnOrphanVersionWithoutAPointerIsAReadErrorAndNotConfirmedMissing() {
		makeOrphan()
		let before = items
		let answer = preread()
		XCTAssertEqual(items, before, "OV-01: the preread writes and deletes nothing")
		XCTAssertEqual(answer["code"] as? String, "read_error", "T4")
		XCTAssertNotEqual(answer["code"] as? String, "confirmed_missing")
		XCTAssertNil(answer["cipher"], "nothing is read from an unnamed version")
	}

	/// An empty store is still a confirmed absence (T0): the new rule does not turn every store into a failure.
	func testAnEmptyStoreIsStillConfirmedMissing() {
		XCTAssertEqual(preread()["code"] as? String, "confirmed_missing", "T0")
	}

	/// With a pointer the versions are named and the answer is the normal one: another account's orphan version does not change it.
	func testAVersionBesideANamingPointerKeepsTheNormalAnswer() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertNotNil(pointerKey())
		let answer = preread()
		XCTAssertEqual(answer["code"] as? String, "ok", "T3")
		XCTAssertNotNil(answer["cipher"])
	}

	// MARK: - T10: the creation

	/// T10: a version, no pointer: the residue probe finds a residue, and makeAccount does not create beside it (nothing is written).
	func testAnOrphanVersionBlocksTheCreation() {
		makeOrphan()
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).accounts.isEmpty, "no inventory lists the unnamed version")
		XCTAssertEqual(BeamioResidueProbe.probe(), .present, "the version is a residue")
		XCTAssertEqual(BeamioResidueProbe.probe(ignoringIntents: true), .present, "also for the walletStatus G0 probe")
		let before = items
		let outcome = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true)
		guard case .failed(let code) = outcome else { return XCTFail("T10: a creation beside an orphan version must not go ahead") }
		XCTAssertEqual(code, .notReady, "T10")
		XCTAssertEqual(items, before, "nothing was created")
	}

	/// An empty store still creates (the residue rule is not a general block).
	func testAnEmptyStoreHasNoResidue() {
		XCTAssertEqual(BeamioResidueProbe.probe(), .absent)
		XCTAssertEqual(BeamioResidueProbe.probe(ignoringIntents: true), .absent)
	}

	// MARK: - the self-healing retry

	/// Sending the same envelope again writes the pointer: the state is normal (the preread answers ok with the envelope, the signing account is named, no second version).
	func testTheSameEnvelopeAgainWritesThePointerAndTheStateIsNormalAgain() {
		makeOrphan()
		XCTAssertEqual(preread()["code"] as? String, "read_error")
		let retry = sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertEqual((retry["result"] as? [String: Any])?["code"] as? String, "ok", "the retry is accepted: \(retry)")
		XCTAssertEqual(versionKeys.count, 1, "no second version")
		XCTAssertNotNil(pointerKey(), "the pointer is written")
		let answer = preread()
		XCTAssertEqual(answer["code"] as? String, "ok", "the state is normal again")
		XCTAssertNotNil(answer["cipher"])
		// the account is listed again (a creation judges it by its own state, as for every named account)
		let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
		XCTAssertEqual(inventory.accounts.map { $0.eoa.lowercased() }, [syn.eoa], "the account is named by the pointer")
		// OV-04: once the account is unlocked (the same envelope with its passcode), the session is ready and the guard denies: the account exists
		let unlocked = sync(["eoa": syn.eoa, "cipher": envelope(), "passcode": syn.passcode])
		XCTAssertEqual((unlocked["result"] as? [String: Any])?["decrypted"] as? Bool, true)
		BeamioConetChatModule.setNativeGateForTests(account: syn.eoa, sessionReady: true)
		guard case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else {
			return XCTFail("OV-04: the account exists, the guard denies")
		}
		XCTAssertEqual(code, .alreadyExists, "OV-04")
	}

	/// Another envelope of the same account without a passcode is still refused (v3.3) while the orphan stays: the retry that heals is the same envelope.
	func testADifferentEnvelopeWithoutAPasscodeDoesNotHealAndStaysRefused() {
		makeOrphan()
		var other = envelope()
		var ct = Data(base64Encoded: other["ct"] as? String ?? "")!
		ct[0] ^= 1
		other["ct"] = ct.base64EncodedString()
		let answer = sync(["eoa": syn.eoa, "cipher": other])
		XCTAssertEqual(answer["error"] as? String, "bad_request")
		XCTAssertNil(pointerKey(), "nothing was written")
		XCTAssertEqual(preread()["code"] as? String, "read_error")
	}

	// MARK: - OV-02, OV-03, OV-06, OV-07

	private func removePointer() {
		let key = pointerKey() ?? ""
		BeamioChatWalletTestMemory.items?.removeValue(forKey: key)
		BeamioPwaPreread.restartForTests()
		BeamioNativeKeySnapshot.invalidate()
	}

	/// OV-02: two orphan versions of one account (a re-sealed envelope under another passcode, accepted with its passcode), no pointer: read_error, the guard denies, nothing changes.
	func testTwoOrphanVersionsOfOneAccountAreAReadErrorAndDenyTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let second = BeamioMnemonicCipherV3.sealForTests(phrase: syn.phrase, passcode: Array("246810".utf8), eoa: syn.eoa)!
		let accepted = sync(["eoa": syn.eoa, "cipher": second, "passcode": "246810"])
		XCTAssertNotNil((accepted["result"] as? [String: Any])?["code"], "the second version is accepted with its passcode")
		XCTAssertEqual(versionKeys.count, 2, "two versions")
		removePointer()
		let before = items
		XCTAssertEqual(preread()["code"] as? String, "read_error", "OV-02")
		guard case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else { return XCTFail("OV-02: deny") }
		XCTAssertEqual(code, .notReady)
		XCTAssertEqual(items, before, "OV-02: nothing changed")
	}

	/// OV-02: orphan versions of two different accounts, no pointer.
	func testOrphanVersionsOfTwoAccountsAreAReadErrorAndDenyTheCreation() {
		let b = ValidTestAccounts.accountB
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let envB = BeamioMnemonicCipherV3.sealForTests(phrase: ValidTestAccounts.phraseB, passcode: Array("246810".utf8), eoa: b.eoa)!
		sync(["eoa": b.eoa, "cipher": envB])
		XCTAssertEqual(items.keys.filter { $0.contains(".c.") }.count, 2, "one version of each account")
		removePointer()
		let before = items
		XCTAssertEqual(preread()["code"] as? String, "read_error", "OV-02")
		guard case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else { return XCTFail("OV-02: deny") }
		XCTAssertEqual(code, .notReady)
		XCTAssertEqual(items, before, "OV-02: nothing changed")
	}

	/// OV-03: the orphan version is damaged, no pointer: the name alone is enough, read_error and the guard denies; the damaged bytes are kept.
	func testADamagedOrphanVersionIsAReadErrorAndDeniesTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let versionKey = try? XCTUnwrap(versionKeys.first)
		let damaged = versionKey ?? ""
		BeamioChatWalletTestMemory.items?[damaged] = Data("not a record".utf8)
		removePointer()
		let before = items
		XCTAssertEqual(preread()["code"] as? String, "read_error", "OV-03")
		guard case .failed = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else { return XCTFail("OV-03: deny") }
		XCTAssertEqual(items, before, "OV-03: the damaged bytes are kept")
	}

	/// OV-06: nothing at all: confirmed_missing, and the guard allows (a creation goes ahead when no other blocker exists).
	func testNothingAtAllAllowsTheCreation() {
		XCTAssertEqual(preread()["code"] as? String, "confirmed_missing", "OV-06")
		guard case .made = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else { return XCTFail("OV-06: allow") }
	}

	/// OV-07: a plaintext set without a pointer is the same class but is listed by the inventory: the preread is not confirmed_missing (iOS answers ok with the phrase).
	func testAPlaintextSetWithoutAPointerIsNotConfirmedMissing() {
		sync(["eoa": syn.eoa, "phrase": syn.phrase])
		removePointer()
		let answer = preread()
		XCTAssertNotEqual(answer["code"] as? String, "confirmed_missing", "OV-07")
		XCTAssertEqual(answer["code"] as? String, "ok", "T2")
	}

	// MARK: - the residue is the orphan only (a pointer names the versions), and the cleared identity

	/// A version with its pointer is no residue: the probe is absent, whatever versions the pointer's account keeps.
	func testAVersionWithAPointerIsNoResidue() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertNotNil(pointerKey())
		XCTAssertEqual(BeamioResidueProbe.probe(), .absent)
		XCTAssertEqual(BeamioResidueProbe.probe(ignoringIntents: true), .absent)
	}

	/// v3 account, pointer in place, identity cleared: the inventory lists no account, the versions stay (by design), and the creation goes ahead (not a permanent not_ready).
	func testACleanedIdentityOfAV3AccountWithAPointerAllowsTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertTrue(BeamioIdentityCleared.record(accounts: [syn.eoa], store: BeamioNativeWallet.keyStore))
		BeamioNativeKeySnapshot.invalidate()
		XCTAssertTrue(BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore).accounts.isEmpty, "the cleared account is not listed")
		XCTAssertEqual(versionKeys.count, 1, "the version is kept")
		XCTAssertNotNil(pointerKey(), "the pointer is kept")
		XCTAssertEqual(BeamioResidueProbe.probe(), .absent, "a named version is no residue")
		guard case .made = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else {
			return XCTFail("the creation goes ahead after a clear (as v0.1.9 and Android)")
		}
	}

	// MARK: - three cases: a cleared identity allows a creation, an orphan blocks it, an unknown read blocks it and keeps the data

	/// CASE 1 (cleared on purpose, aligned with Android): an orphan version of an identity that was cleared is ignored with it. The probe is absent, the preread is not a read
	/// failure (the inventory lists nothing, so it is confirmed_missing), the creation goes ahead; the kept version and the marker stay byte for byte.
	func testCase1AnOrphanVersionOfAClearedIdentityIsIgnoredAndAllowsTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertTrue(BeamioIdentityCleared.record(accounts: [syn.eoa], store: BeamioNativeWallet.keyStore))
		removePointer()
		let versionBefore = versionKeys.map { ($0, items[$0]) }
		let before = items
		XCTAssertEqual(BeamioResidueProbe.probe(), .absent, "CASE 1: the cleared identity's version is no residue")
		XCTAssertEqual(BeamioResidueProbe.probe(ignoringIntents: true), .absent)
		XCTAssertEqual(preread()["code"] as? String, "confirmed_missing", "CASE 1: not a read failure")
		XCTAssertEqual(items, before, "CASE 1: the probe and the preread write and delete nothing")
		guard case .made = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else {
			return XCTFail("CASE 1: the creation goes ahead")
		}
		for (key, bytes) in versionBefore { XCTAssertEqual(items[key], bytes, "CASE 1: the kept version is byte for byte as it was") }
	}

	/// CASE 1 (limit): only the cleared identity's versions are ignored. An orphan version of another identity that was not cleared still blocks.
	func testCase1AnOrphanVersionOfAnotherIdentityStillBlocks() {
		let b = ValidTestAccounts.accountB
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let envB = BeamioMnemonicCipherV3.sealForTests(phrase: ValidTestAccounts.phraseB, passcode: Array("246810".utf8), eoa: b.eoa)!
		sync(["eoa": b.eoa, "cipher": envB])
		XCTAssertTrue(BeamioIdentityCleared.record(accounts: [syn.eoa], store: BeamioNativeWallet.keyStore))   // A is cleared, B is not
		removePointer()
		XCTAssertEqual(BeamioResidueProbe.probe(), .present, "CASE 1: B's version is not cleared")
		XCTAssertEqual(preread()["code"] as? String, "read_error")
	}

	/// CASE 2 (an orphan whose pointer is confirmed missing): read_error, the creation denied, nothing written, the self-heal kept. The detailed assertions are
	/// testAnOrphanVersionWithoutAPointerIsAReadErrorAndNotConfirmedMissing (T4), testAnOrphanVersionBlocksTheCreation (T10) and
	/// testTheSameEnvelopeAgainWritesThePointerAndTheStateIsNormalAgain; this one adds the byte snapshot over the three steps.
	func testCase2AnOrphanIsBlockedWithoutAnyWriteAndHealsWithTheSameEnvelope() {
		makeOrphan()
		let snapshot = items
		XCTAssertEqual(preread()["code"] as? String, "read_error")
		_ = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true)
		XCTAssertEqual(items, snapshot, "CASE 2: no write and no delete by the preread or the guard")
		let retry = sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertEqual((retry["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertEqual(preread()["code"] as? String, "ok", "CASE 2: the self-heal still works")
	}

	/// CASE 3a (unknown: the pointer cannot be read): read_error, the data kept untouched, never a confirmed absence. Over a store that fails the pointer read.
	func testCase3TheUnreadablePointerIsAReadErrorAndKeepsTheData() {
		let m = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = m
		sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertFalse(m.rawAccounts.isEmpty)
		m.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		BeamioPwaPreread.restartForTests(); BeamioNativeKeySnapshot.invalidate()
		let before = m.rawAccounts
		XCTAssertEqual(preread()["code"] as? String, "read_error", "CASE 3: a locked or unreadable pointer is not an absence")
		XCTAssertEqual(m.rawAccounts, before, "CASE 3: the data is kept, not deleted and not overwritten")
	}

	/// CASE 3b (unknown: the items cannot be listed, the pointer is missing): read_error, the data kept.
	func testCase3AnItemListThatFailsIsAReadErrorAndKeepsTheData() {
		let m = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = m
		sync(["eoa": syn.eoa, "cipher": envelope()])
		m.rawAccounts.removeValue(forKey: BeamioMnemonicSets.currentName)
		m.rawNamesUnavailable = true
		BeamioPwaPreread.restartForTests(); BeamioNativeKeySnapshot.invalidate()
		let before = m.rawAccounts
		XCTAssertEqual(preread()["code"] as? String, "read_error", "CASE 3: a failed listing is not 'no versions'")
		XCTAssertEqual(m.rawAccounts, before, "CASE 3: nothing written or deleted")
	}

	/// CASE 3c (unknown: the identity marker cannot be read, an orphan exists): read_error, the data kept; the residue judgement blocks too.
	func testCase3AnUnreadableMarkerWithAnOrphanIsAReadErrorAndBlocks() {
		let m = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = m
		sync(["eoa": syn.eoa, "cipher": envelope()])
		m.rawAccounts.removeValue(forKey: BeamioMnemonicSets.currentName)
		m.failRawReadAccounts.insert(BeamioIdentityCleared.itemName)
		BeamioPwaPreread.restartForTests(); BeamioNativeKeySnapshot.invalidate()
		let before = m.rawAccounts
		XCTAssertEqual(preread()["code"] as? String, "read_error", "CASE 3: an unreadable marker is unknown")
		XCTAssertEqual(m.rawAccounts, before)
		let orphanName = m.rawAccounts.keys.first { BeamioMnemonicSets.cipherVersionOwner(inAccount: $0) != nil } ?? ""
		XCTAssertTrue(BeamioResidueProbe.hasResidue(in: [orphanName], prefixes: ["mnemonic:", "commit:"]), "CASE 3: the residue judgement blocks")
	}

	/// CASE 3d (unknown: the residue probe fails, or the inventory cannot be read): the creation is not_ready and nothing is written; a failure is never a go-ahead.
	func testCase3AFailedResidueProbeDeniesTheCreationAndWritesNothing() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let before = items
		BeamioResidueProbe.overrideForTests = { .failed }
		defer { BeamioResidueProbe.overrideForTests = nil }
		guard case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else {
			return XCTFail("CASE 3: a failed probe must not allow the creation")
		}
		XCTAssertEqual(code, .notReady)
		XCTAssertEqual(items, before, "CASE 3: nothing written")
	}

	// MARK: - a pointer that exists but is unknown: damaged, or naming a version that is missing

	private func setPointer(_ bytes: Data) {
		let key = pointerKey() ?? ""
		BeamioChatWalletTestMemory.items?[key] = bytes
		BeamioPwaPreread.restartForTests()
		BeamioNativeKeySnapshot.invalidate()
	}

	/// The preread answers read_error and the creation is denied (not_ready), with nothing written or deleted: the snapshot and the item count are the same.
	private func assertUnknownPointerBlocks(_ label: String, file: StaticString = #filePath, line: UInt = #line) {
		let snapshot = items
		XCTAssertEqual(preread()["code"] as? String, "read_error", "\(label): the preread", file: file, line: line)
		guard case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: BeamioNativeWallet.keyStore, entropy: nil, userExplicit: true) else {
			return XCTFail("\(label): a pointer that is unknown must not allow a creation", file: file, line: line)
		}
		XCTAssertEqual(code, .notReady, "\(label)", file: file, line: line)
		XCTAssertEqual(items, snapshot, "\(label): nothing written, nothing deleted", file: file, line: line)
		XCTAssertEqual(items.count, snapshot.count, "\(label): the item count is the same", file: file, line: line)
	}

	/// The pointer content is damaged (cannot be parsed), its version is in place: unknown.
	func testADamagedPointerWithTheVersionInPlaceBlocksTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		XCTAssertEqual(versionKeys.count, 1)
		setPointer(Data("not a pointer".utf8))
		assertUnknownPointerBlocks("damaged pointer")
		XCTAssertEqual(versionKeys.count, 1, "the version is kept")
	}

	/// The pointer parses but names a version that does not exist (another digest), the real version stays: unknown.
	func testAPointerNamingAMissingVersionBlocksTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let missing = BeamioMnemonicSets.setName(syn.eoa) + ".c.0000000000000000"
		let pointer = try? JSONSerialization.data(withJSONObject: ["v": 1, "eoa": syn.eoa, "kind": "cipher", "item": missing] as [String: Any], options: [.sortedKeys])
		setPointer(pointer ?? Data())
		assertUnknownPointerBlocks("pointer to a missing version")
	}

	/// The version the pointer names was lost (the pointer stays): unknown.
	func testAPointerWhoseVersionWasLostBlocksTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let version = versionKeys.first ?? ""
		BeamioChatWalletTestMemory.items?.removeValue(forKey: version)
		XCTAssertTrue(versionKeys.isEmpty)
		BeamioPwaPreread.restartForTests(); BeamioNativeKeySnapshot.invalidate()
		assertUnknownPointerBlocks("pointer, version lost")
	}

	/// The no-passcode pointer names a plaintext set that is missing: unknown, as for the v3 pointer.
	func testAPlaintextPointerWhoseSetIsMissingBlocksTheCreation() {
		sync(["eoa": syn.eoa, "phrase": syn.phrase])
		let setKey = items.keys.first { $0.hasSuffix(BeamioMnemonicSets.setName(syn.eoa)) } ?? ""
		BeamioChatWalletTestMemory.items?.removeValue(forKey: setKey)
		BeamioPwaPreread.restartForTests(); BeamioNativeKeySnapshot.invalidate()
		assertUnknownPointerBlocks("plaintext pointer, set missing")
	}

	/// The version the pointer names is damaged (the record does not verify): unknown.
	func testAPointerWhoseVersionIsDamagedBlocksTheCreation() {
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let version = versionKeys.first ?? ""
		BeamioChatWalletTestMemory.items?[version] = Data("not a record".utf8)
		BeamioPwaPreread.restartForTests(); BeamioNativeKeySnapshot.invalidate()
		assertUnknownPointerBlocks("pointer, damaged version")
	}
}
#endif
