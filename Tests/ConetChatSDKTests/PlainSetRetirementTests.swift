#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The native mnemonic persistence contract: with no passcode the preread returns the phrase; once the account's v3 record is written, read back and named by the pointer, the old
/// plaintext Keychain set of that account is deleted silently (a cleanup record first, no secret in it), and from then on the preread returns the cipher only, whether or not the cleanup
/// finished. Run through the product store over the in-memory Keychain.
final class PlainSetRetirementTests: XCTestCase {
	private var seq = 0
	private var req = 970_000
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
		BeamioMnemonicSets.retireFaultForTests = nil
		BeamioNativeKeySnapshot.invalidate()
		BeamioPwaWalletSync.restartForTests()
		seq = 0
	}

	override func tearDown() {
		BeamioMnemonicSets.retireFaultForTests = nil
		BeamioCipherUnlock.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioChatWalletTestMemory.items = [:]
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private lazy var theEnvelope: [String: Any] = BeamioMnemonicCipherV3.sealForTests(phrase: syn.phrase, passcode: Array(syn.passcode.utf8), eoa: syn.eoa)!

	@discardableResult
	private func sync(_ body: [String: Any]) -> [String: Any] {
		req += 1; seq += 1
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		var full: [String: Any] = ["type": "pwaWalletSync", "reqId": req, "seq": NSNumber(value: seq), "trustedOrigin": true]
		for (k, v) in body { full[k] = v }
		return BeamioPwaWalletSync.answer(full, snapshotKnown: BeamioNativeKeySnapshot.isKnown, storageLocked: BeamioNativeKeySnapshot.current()?.storageLock != nil)
	}

	private func prereadAck() -> [String: Any] {
		req += 1
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		return BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: req, seq: 100_000 + req)
	}

	private func preread() -> [String: Any] { prereadAck()["result"] as? [String: Any] ?? [:] }

	private var items: [String: Data] { BeamioChatWalletTestMemory.items ?? [:] }
	private func keys(containing name: String) -> [String] { items.keys.filter { $0.hasSuffix(name) } }
	private var plainKey: [String] { keys(containing: BeamioMnemonicSets.setName(syn.eoa)) }
	private var retireKey: [String] { keys(containing: BeamioMnemonicSets.retireName(syn.eoa)) }
	private var pointerKey: [String] { keys(containing: BeamioMnemonicSets.currentName) }
	private var versionKeys: [String] { items.keys.filter { $0.contains(BeamioMnemonicSets.setName(syn.eoa) + ".c.") } }
	private var raw: BeamioChatRawItemStoring { BeamioNativeWallet.keyStore as! BeamioChatRawItemStoring }

	private func syncPlain() {
		let answer = sync(["eoa": syn.eoa, "phrase": syn.phrase])
		XCTAssertEqual((answer["result"] as? [String: Any])?["sync"] as? String, "updated", "\(answer)")
	}

	/// The shell's preread allow-list (the codes and the fields of an ok answer), applied here to the real answers.
	private func shellFilter(_ ack: [String: Any]) -> [String: Any] {
		let prereadCodes: Set<String> = ["ok", "confirmed_missing", "read_error", "not_ready"]
		let prereadOkKeys: Set<String> = ["code", "mnemonic", "eoa", "cipher"]
		guard let result = ack["result"] as? [String: Any] else { return ack }
		let code = result["code"] as? String ?? ""
		var out = ack
		if code == "ok" {
			out["result"] = result.filter { prereadOkKeys.contains($0.key) }
		} else if prereadCodes.contains(code) {
			out["result"] = ["code": code]
		} else {
			out["result"] = ["code": "read_error"]
		}
		return out
	}

	// MARK: - the two answers

	/// No passcode: the preread returns the phrase with the address, and the plaintext set is intact, no cleanup record.
	func testNoPasscodeReturnsThePhraseAndKeepsThePlainSet() {
		syncPlain()
		let answer = preread()
		XCTAssertEqual(answer["code"] as? String, "ok")
		XCTAssertEqual(answer["mnemonic"] as? String, String(decoding: BeamioPwaWalletSync.normalized(syn.phrase), as: UTF8.self))
		XCTAssertEqual(answer["eoa"] as? String, syn.eoa)
		XCTAssertNil(answer["cipher"])
		XCTAssertEqual(plainKey.count, 1, "the plaintext set is intact")
		XCTAssertTrue(retireKey.isEmpty, "no cleanup record without a passcode state")
	}

	/// With a passcode: the cipher with its eight fields, equal to what was stored; no phrase.
	func testPasscodeReturnsTheCipherWithEightFieldsAndNoPhrase() {
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		let answer = preread()
		XCTAssertEqual(answer["code"] as? String, "ok")
		XCTAssertNil(answer["mnemonic"])
		let cipher = answer["cipher"] as? [String: Any]
		XCTAssertEqual(Set(cipher?.keys.map { $0 } ?? []), ["v", "mode", "eoa", "kdf", "salt", "iv", "alg", "ct"])
		for (k, v) in theEnvelope { XCTAssertEqual("\(cipher?[k] ?? "")", "\(v)", "field \(k) is returned as it was stored") }
	}

	// MARK: - the conversion

	/// A passcode set on an account that held a plaintext set: after the v3 record is written and named, the plaintext set is gone, the cleanup record says done, and only the cipher is returned.
	func testTheOldPlainSetIsDeletedSilentlyAndOnlyTheCipherIsReturned() {
		syncPlain()
		XCTAssertEqual(plainKey.count, 1)
		let answer = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((answer["result"] as? [String: Any])?["decrypted"] as? Bool, true, "\(answer)")
		XCTAssertTrue(plainKey.isEmpty, "the plaintext set is deleted")
		XCTAssertEqual(retireKey.count, 1, "the cleanup record stays as the tombstone")
		let record = try? JSONSerialization.jsonObject(with: items[retireKey[0]] ?? Data()) as? [String: Any]
		XCTAssertEqual(record?["state"] as? String, "done")
		XCTAssertEqual(Set(record?.keys.map { $0 } ?? []), ["v", "eoa", "state"], "the record holds no secret")
		let read = preread()
		XCTAssertEqual(read["code"] as? String, "ok")
		XCTAssertNotNil(read["cipher"])
		XCTAssertNil(read["mnemonic"])
		XCTAssertNil(BeamioMnemonicSets.derivedKey(store: raw, eoa: syn.eoa), "no plaintext key source")
	}

	/// The same without a passcode in the sync (the page only mirrors the envelope): the plaintext set goes too, and the answer is the cipher.
	func testAStoreOnlyCipherSyncAlsoRetiresThePlainSet() {
		syncPlain()
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertTrue(plainKey.isEmpty)
		let read = preread()
		XCTAssertNotNil(read["cipher"]); XCTAssertNil(read["mnemonic"])
	}

	/// An account with only a v3 record and no plaintext set before: nothing to delete, the cleanup record is written and done, the answer is the cipher.
	func testAnAccountWithNoPlainSetJustGetsTheTombstone() {
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertTrue(plainKey.isEmpty)
		XCTAssertEqual(preread()["code"] as? String, "ok")
	}

	// MARK: - an interrupted cleanup never falls back to the plaintext

	private func assertCipherOnlyWhilePlainStays(_ label: String, plainStays: Bool = true, file: StaticString = #filePath, line: UInt = #line) {
		let read = preread()
		XCTAssertEqual(read["code"] as? String, "ok", label, file: file, line: line)
		XCTAssertNotNil(read["cipher"], label, file: file, line: line)
		XCTAssertNil(read["mnemonic"], "\(label): the phrase is never returned", file: file, line: line)
		XCTAssertEqual(!plainKey.isEmpty, plainStays, label, file: file, line: line)
		XCTAssertNil(BeamioMnemonicSets.derivedKey(store: raw, eoa: syn.eoa), "\(label): the plaintext is no key source", file: file, line: line)
		if case .absent = BeamioMnemonicSets.readSet(store: raw, eoa: syn.eoa) {} else { XCTFail("\(label): the plaintext set reads as absent", file: file, line: line) }
	}

	private func runInterrupted(_ fault: BeamioMnemonicSets.RetireFault, plainStays: Bool, hasRecord: Bool) {
		syncPlain()
		BeamioMnemonicSets.retireFaultForTests = fault
		let answer = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "ok", "the save itself succeeds: \(answer)")
		XCTAssertEqual(retireKey.isEmpty, !hasRecord)
		assertCipherOnlyWhilePlainStays("\(fault)", plainStays: plainStays)
		// a restart (the session start) with the fault gone finishes the cleanup
		BeamioMnemonicSets.retireFaultForTests = nil
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertTrue(plainKey.isEmpty, "\(fault): the restart finishes the cleanup")
		XCTAssertEqual(retireKey.count, 1)
		assertCipherOnlyWhilePlainStays("\(fault) after the restart", plainStays: false)
	}

	func testAFailureBeforeTheCleanupRecordLeavesThePlainSetUnusedAndARestartFinishes() {
		runInterrupted(.beforeIntent, plainStays: true, hasRecord: false)
	}

	func testAFailureBeforeTheDeletionLeavesThePlainSetUnusedAndARestartFinishes() {
		runInterrupted(.beforeDelete, plainStays: true, hasRecord: true)
	}

	func testAFailingDeletionLeavesThePlainSetUnusedAndARestartFinishes() {
		runInterrupted(.deleteFails, plainStays: true, hasRecord: true)
	}

	func testAFailureAfterTheDeletionStillReturnsTheCipherOnlyAndARestartMarksDone() {
		runInterrupted(.beforeDoneMark, plainStays: false, hasRecord: true)
	}

	/// The retry is the same sync again: the same envelope is idempotent and finishes the cleanup.
	func testTheSameEnvelopeAgainFinishesAnInterruptedCleanup() {
		syncPlain()
		BeamioMnemonicSets.retireFaultForTests = .deleteFails
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertEqual(plainKey.count, 1)
		BeamioMnemonicSets.retireFaultForTests = nil
		let again = sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertEqual((again["result"] as? [String: Any])?["code"] as? String, "ok")
		XCTAssertTrue(plainKey.isEmpty)
		XCTAssertEqual(versionKeys.count, 1, "no second version")
		assertCipherOnlyWhilePlainStays("retry", plainStays: false)
	}

	/// The orphan and interruption rules do not fall back to the plaintext: after the conversion, the pointer is gone, the preread is a read error and never the phrase.
	func testAnOrphanAfterTheConversionNeverReturnsThePhrase() {
		syncPlain()
		BeamioMnemonicSets.retireFaultForTests = .deleteFails
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		BeamioMnemonicSets.retireFaultForTests = nil
		for k in pointerKey { BeamioChatWalletTestMemory.items?.removeValue(forKey: k) }
		BeamioPwaPreread.restartForTests()
		BeamioNativeKeySnapshot.invalidate()
		let read = prereadAck()["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(read["code"] as? String, "read_error")
		XCTAssertNil(read["mnemonic"])
		XCTAssertNil(BeamioMnemonicSets.derivedKey(store: raw, eoa: syn.eoa), "the cleanup record retires the plaintext while the pointer is missing")
	}


	// MARK: - the ciphertext is verified before the plaintext is deleted

	/// The state of the probe P1: the cleanup failed at the deletion, then the version item is lost (or damaged) while the pointer still names it. The plaintext set must stay on disk
	/// (it is the only copy), it is still never read or returned, and the cleanup is not completed on a restart.
	private func makeUnverifiedCipher(damage: Bool) -> (name: String, bytes: Data) {
		syncPlain()
		BeamioMnemonicSets.retireFaultForTests = .deleteFails
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		BeamioMnemonicSets.retireFaultForTests = nil
		XCTAssertEqual(plainKey.count, 1)
		let version = versionKeys[0]
		let original = items[version] ?? Data()
		if damage { BeamioChatWalletTestMemory.items?[version] = Data("{\"v\":1,\"mode\":\"cipher\"}".utf8) } else { BeamioChatWalletTestMemory.items?.removeValue(forKey: version) }
		BeamioPwaPreread.restartForTests()
		return (version, original)
	}

	private func assertPlainKeptButUnused(_ label: String, file: StaticString = #filePath, line: UInt = #line) {
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(plainKey.count, 1, "\(label): the plaintext set is not deleted", file: file, line: line)
		let read = preread()
		XCTAssertEqual(read["code"] as? String, "read_error", label, file: file, line: line)
		XCTAssertNil(read["mnemonic"], "\(label): the phrase is never returned", file: file, line: line)
		XCTAssertNil(BeamioMnemonicSets.derivedKey(store: raw, eoa: syn.eoa), "\(label): no key from the plaintext", file: file, line: line)
		if case .absent = BeamioMnemonicSets.readSet(store: raw, eoa: syn.eoa) {} else { XCTFail("\(label): the plaintext set reads as absent", file: file, line: line) }
	}

	func testALostVersionItemKeepsThePlainSetOnDisk() {
		let lost = makeUnverifiedCipher(damage: false)
		assertPlainKeptButUnused("lost version")
		// the version comes back (restored): the next start finishes the cleanup
		BeamioChatWalletTestMemory.items?[lost.name] = lost.bytes
		BeamioPwaPreread.restartForTests()
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertTrue(plainKey.isEmpty, "with the version readable again the cleanup completes")
		XCTAssertEqual(preread()["code"] as? String, "ok")
	}

	func testADamagedVersionItemKeepsThePlainSetOnDisk() {
		_ = makeUnverifiedCipher(damage: true)
		assertPlainKeptButUnused("damaged version")
	}

	/// The cleanup of a sync is not run on a version that does not read back: a retry of the same envelope with the version item gone writes it again, then verifies and deletes.
	func testTheSameEnvelopeAgainRewritesTheLostVersionAndThenDeletes() {
		_ = makeUnverifiedCipher(damage: false)
		let again = sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertEqual((again["result"] as? [String: Any])?["code"] as? String, "ok", "\(again)")
		XCTAssertEqual(versionKeys.count, 1)
		XCTAssertTrue(plainKey.isEmpty)
		XCTAssertNotNil(preread()["cipher"])
	}

	// MARK: - a plaintext set chosen again, then another account

	private func makeReselected(_ fault: BeamioMnemonicSets.RetireFault?) -> BeamioMnemonicSets.Save {
		syncPlain()
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertTrue(plainKey.isEmpty)
		BeamioMnemonicSets.retireFaultForTests = fault
		let saved = BeamioMnemonicSets.save(phrase: syn.phrase, store: raw, utc: "2026-11-23T00:00:00Z")
		BeamioMnemonicSets.retireFaultForTests = nil
		return saved
	}

	/// The probe P2: the cleanup record cannot be deleted when the plaintext set is chosen again; the record is marked `reselected`, the save is complete, and a later pointer to another
	/// account with a restart does not delete the live plaintext set of the first account.
	func testAReselectedPlainSetSurvivesAPointerToAnotherAccountAndARestart() throws {
		XCTAssertEqual(makeReselected(.reselectDeleteFails), .updated)
		let record = try? JSONSerialization.jsonObject(with: items[retireKey[0]] ?? Data()) as? [String: Any]
		XCTAssertEqual(record?["state"] as? String, "reselected")
		// the pointer now names another account's plaintext set
		let other = "0x" + String(repeating: "b", count: 40)
		let pointer = try XCTUnwrap(try? JSONSerialization.data(withJSONObject: ["v": 1, "eoa": other], options: [.sortedKeys]))
		XCTAssertTrue(raw.rawWrite(account: BeamioMnemonicSets.currentName, bytes: pointer))
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(plainKey.count, 1, "the live plaintext set of the first account is not deleted")
		if case .phrase = BeamioMnemonicSets.readSet(store: raw, eoa: syn.eoa) {} else { XCTFail("the first account's plaintext set is still live") }
	}

	/// When neither the deletion nor the mark of the cleanup record works, the save is not complete (a failure), and the same save again completes it.
	func testASaveThatCannotClearTheCleanupRecordIsAFailureAndTheRetryCompletes() {
		XCTAssertEqual(makeReselected(.reselectMarkFails), .failed("internal_state"))
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: syn.phrase, store: raw, utc: "2026-11-23T00:00:01Z"), .idempotent)
		XCTAssertTrue(retireKey.isEmpty, "the retry cleared the record")
	}

	/// A `reselected` record becomes `pending` again when the account goes back to a passcode record, and the plaintext set is then deleted.
	func testAReselectedRecordIsRetiredAgainByANewV3Record() throws {
		XCTAssertEqual(makeReselected(.reselectDeleteFails), .updated)
		let again = sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertEqual((again["result"] as? [String: Any])?["code"] as? String, "ok", "\(again)")
		XCTAssertTrue(plainKey.isEmpty)
		let record = try? JSONSerialization.jsonObject(with: items[retireKey[0]] ?? Data()) as? [String: Any]
		XCTAssertEqual(record?["state"] as? String, "done")
		XCTAssertNotNil(preread()["cipher"])
	}


	// MARK: - the older device copies (`mnemonic:<eoa>` and `walletKey:<eoa>`)

	private var kc: BeamioChatWalletKeychainStore { BeamioChatWalletKeychainStore.standard }
	private var legacyKeys: [String] { items.keys.filter { $0.hasSuffix("mnemonic:" + syn.eoa) || $0.hasSuffix("walletKey:" + syn.eoa) || $0.hasSuffix("blobKey:" + syn.eoa) } }
	private var derivedKey: Data { var d = BeamioPwaWalletSync.derivedAccount(phrase: syn.phrase)!; defer { BeamioNativeWallet.wipe(&d.key) }; return Data(d.key) }

	/// An account the way an older build kept it: the wrapped mnemonic item, the credential key that goes with it, and the wallet key record.
	private func makeLegacyAccount() {
		XCTAssertTrue(kc.writeItem(.mnemonic, eoa: syn.eoa, value: BeamioPwaWalletSync.normalized(syn.phrase)))
		XCTAssertTrue(kc.write(eoa: syn.eoa, key: derivedKey))
		XCTAssertEqual(legacyKeys.count, 3, "mnemonic item, credential key, wallet key record")
		XCTAssertEqual(kc.readItem(.mnemonic, eoa: syn.eoa), BeamioPwaWalletSync.normalized(syn.phrase))
		XCTAssertEqual(kc.read(eoa: syn.eoa), derivedKey)
		XCTAssertEqual(kc.keyRecordState(eoa: syn.eoa), .present)
	}

	private func assertLegacyHidden(_ label: String, state: BeamioChatItemState, keyState: BeamioChatWalletKeyRecordState, file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertNil(kc.readItem(.mnemonic, eoa: syn.eoa), "\(label): no wrapped phrase", file: file, line: line)
		XCTAssertNil(kc.readItem(.key, eoa: syn.eoa), "\(label): no key record bytes", file: file, line: line)
		XCTAssertNil(kc.read(eoa: syn.eoa), "\(label): no key", file: file, line: line)
		XCTAssertEqual(kc.itemState(.mnemonic, eoa: syn.eoa), state, label, file: file, line: line)
		XCTAssertEqual(kc.keyRecordState(eoa: syn.eoa), keyState, label, file: file, line: line)
	}

	/// Old copies present, then a passcode is set: after the v3 record reads back, both copies (and the credential key) are deleted, nothing but the cipher is returned, and the key comes from
	/// the unlocked v3 record, so signing does not turn into "no account".
	func testTheOlderDeviceCopiesAreDeletedAndTheKeyComesFromTheUnlockedV3Record() {
		makeLegacyAccount()
		let answer = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((answer["result"] as? [String: Any])?["decrypted"] as? Bool, true, "\(answer)")
		XCTAssertTrue(legacyKeys.isEmpty, "the wrapped mnemonic item, its credential key and the wallet key record are gone")
		XCTAssertFalse(kc.hasAnyKeyRecord(), "no wallet key record is left")
		XCTAssertEqual(kc.enumerateKeyOwners() ?? ["?"], [])
		assertLegacyHidden("after the cleanup", state: .present, keyState: .absent)   // the mnemonic item is the account's v3 record
		let read = preread()
		XCTAssertNotNil(read["cipher"]); XCTAssertNil(read["mnemonic"])
		// the key comes from the unlocked v3 record
		XCTAssertEqual(BeamioNativeWallet.keyStore.read(eoa: syn.eoa), derivedKey, "signing and derivation take the key of the unlocked v3 record")
		XCTAssertEqual(BeamioNativeWallet.keyStore.keyRecordState(eoa: syn.eoa), .present)
	}

	/// The combination of the two kinds of record for one address (a native account of an older build that the page then gave a passcode): a v3 record that came in without a passcode
	/// proves nothing about the address, so it retires nothing: the older copies stay as they were. The later unlock with the passcode proves the address and retires them.
	func testAV3RecordWithoutAPasscodeRetiresNothingAndTheLaterUnlockDoes() {
		makeLegacyAccount()
		let stored = sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertEqual((stored["result"] as? [String: Any])?["decrypted"] as? Bool, false)
		XCTAssertEqual(legacyKeys.count, 3, "nothing is deleted without the proof of the address")
		XCTAssertTrue(items.keys.filter { $0.hasSuffix(BeamioMnemonicSets.legacyRetireName(syn.eoa)) }.isEmpty, "no retirement record")
		XCTAssertEqual(kc.read(eoa: syn.eoa), derivedKey, "the older copies are still the key source (the combination exists)")
		let unlocked = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((unlocked["result"] as? [String: Any])?["decrypted"] as? Bool, true)
		XCTAssertTrue(legacyKeys.isEmpty, "the unlock proved the address: the copies are retired and deleted")
		assertLegacyHidden("after the unlock", state: .present, keyState: .absent)
	}

	/// Locked after a restart with the account fully converted: no key until the unlock, an unreadable record and never an absent account.
	func testWhileLockedAfterTheConversionThereIsNoKeyAndTheRecordIsUnreadableNotAbsent() {
		makeLegacyAccount()
		sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertTrue(legacyKeys.isEmpty)
		BeamioCipherUnlock.clear()
		BeamioNativeKeySnapshot.invalidate()
		XCTAssertNil(BeamioNativeWallet.keyStore.read(eoa: syn.eoa), "no key while locked")
		XCTAssertEqual(BeamioNativeWallet.keyStore.keyRecordState(eoa: syn.eoa), .unreadable, "locked is an unreadable record, not absent")
		XCTAssertNotNil(preread()["cipher"])
	}

	/// An address that the passcode does not prove (the envelope names this address, the phrase under it derives another): nothing is written and the older copies are kept.
	func testAnAddressThatTheUnlockDoesNotProveRetiresNothing() throws {
		makeLegacyAccount()
		let other = "legal winner thank year wave sausage worth useful legal winner thank yellow"
		let bogus = try XCTUnwrap(BeamioMnemonicCipherV3.sealForTests(phrase: other, passcode: Array(syn.passcode.utf8), eoa: syn.eoa))
		let before = items
		let answer = sync(["eoa": syn.eoa, "cipher": bogus, "passcode": syn.passcode])
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "verify_failed")
		XCTAssertEqual(items, before, "nothing was written or deleted")
		XCTAssertEqual(kc.read(eoa: syn.eoa), derivedKey)
	}

	/// The retirement itself refuses without the proof: no held key, or a held key that derives another address, deletes nothing and writes no record.
	func testRetireLegacyNeedsTheHeldKeyOfThisAddress() {
		makeLegacyAccount()
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertFalse(BeamioMnemonicSets.retireLegacy(eoa: syn.eoa, store: raw), "locked: no proof")
		XCTAssertEqual(legacyKeys.count, 3)
		BeamioCipherUnlock.hold(eoa: syn.eoa, key: [UInt8](repeating: 7, count: 32))
		XCTAssertFalse(BeamioMnemonicSets.retireLegacy(eoa: syn.eoa, store: raw), "a held key of another address is no proof")
		XCTAssertEqual(legacyKeys.count, 3)
		XCTAssertTrue(items.keys.filter { $0.hasSuffix(BeamioMnemonicSets.legacyRetireName(syn.eoa)) }.isEmpty)
		BeamioCipherUnlock.hold(eoa: syn.eoa, key: [UInt8](derivedKey))
		XCTAssertTrue(BeamioMnemonicSets.retireLegacy(eoa: syn.eoa, store: raw))
		XCTAssertTrue(legacyKeys.isEmpty)
	}

	private func runLegacyInterrupted(_ fault: BeamioMnemonicSets.RetireFault, hasRecord: Bool) {
		makeLegacyAccount()
		BeamioMnemonicSets.retireFaultForTests = fault
		let answer = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		XCTAssertEqual((answer["result"] as? [String: Any])?["decrypted"] as? Bool, true, "the save itself succeeds: \(answer)")
		XCTAssertEqual(items.keys.contains { $0.hasSuffix(BeamioMnemonicSets.legacyRetireName(syn.eoa)) }, hasRecord)
		if hasRecord {
			// the record exists: the copies are retired by the pointer and the record, still on disk (except after the last deletion), never returned
			if fault != .beforeDoneMark { XCTAssertEqual(legacyKeys.count, 3, "\(fault): the copies are still on disk") }
			assertLegacyHidden("\(fault)", state: .present, keyState: .absent)
		} else {
			// no record: the address proof was not recorded, so the copies are still the live ones until the retry
			XCTAssertEqual(legacyKeys.count, 3)
			XCTAssertEqual(kc.read(eoa: syn.eoa), derivedKey)
		}
		XCTAssertEqual(BeamioNativeWallet.keyStore.read(eoa: syn.eoa), derivedKey, "\(fault): the key is available")
		let read = preread()
		XCTAssertNotNil(read["cipher"]); XCTAssertNil(read["mnemonic"])
		BeamioMnemonicSets.retireFaultForTests = nil
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertTrue(legacyKeys.isEmpty, "\(fault): the next start finishes the cleanup")
		assertLegacyHidden("\(fault) after the restart", state: .present, keyState: .absent)
	}

	func testLegacyFailureBeforeTheRecordThenARestartFinishes() { runLegacyInterrupted(.beforeIntent, hasRecord: false) }
	func testLegacyFailureBeforeTheDeletionThenARestartFinishes() { runLegacyInterrupted(.beforeDelete, hasRecord: true) }
	func testLegacyFailingDeletionThenARestartFinishes() { runLegacyInterrupted(.deleteFails, hasRecord: true) }
	func testLegacyFailureBeforeTheDoneMarkThenARestartFinishes() { runLegacyInterrupted(.beforeDoneMark, hasRecord: true) }

	/// A v3 record that does not read back: the old copies are not deleted (they may be the only copy), and they are not returned either; the account reads as unreadable, never absent.
	func testALostVersionKeepsTheOlderCopiesOnDiskButHidden() {
		makeLegacyAccount()
		BeamioMnemonicSets.retireFaultForTests = .deleteFails
		sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		BeamioMnemonicSets.retireFaultForTests = nil
		let version = versionKeys[0]
		let original = items[version] ?? Data()
		BeamioChatWalletTestMemory.items?.removeValue(forKey: version)
		BeamioPwaPreread.restartForTests()
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(legacyKeys.count, 3, "the copies are not deleted without a verified v3 record")
		assertLegacyHidden("lost version", state: .unreadable, keyState: .unreadable)
		XCTAssertEqual(preread()["code"] as? String, "read_error")
		// the version comes back: the next start deletes the copies
		BeamioChatWalletTestMemory.items?[version] = original
		BeamioPwaPreread.restartForTests()
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertTrue(legacyKeys.isEmpty)
	}

	/// An account that has no v3 record is unchanged: its old copies are read as before.
	func testAnAccountWithoutAV3RecordKeepsItsOlderCopies() {
		makeLegacyAccount()
		XCTAssertEqual(kc.readItem(.mnemonic, eoa: syn.eoa), BeamioPwaWalletSync.normalized(syn.phrase))
		XCTAssertEqual(kc.read(eoa: syn.eoa), derivedKey)
		XCTAssertTrue(kc.hasAnyKeyRecord())
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(legacyKeys.count, 3, "no cleanup without a v3 record")
	}

	/// A wrong passcode with the old copies in place: unlock_failed and every item is unchanged byte for byte.
	func testAWrongPasscodeLeavesTheOlderCopiesUntouched() {
		makeLegacyAccount()
		let before = items
		let answer = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": "000000"])
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "unlock_failed")
		XCTAssertEqual(items, before, "nothing changed")
		XCTAssertEqual(kc.read(eoa: syn.eoa), derivedKey)
	}

	/// The whole conversion with the old copies, with the standard error captured: no phrase word, passcode, cipher text or key bytes in the log.
	func testTheLogsHoldNoSecretWithTheOlderCopies() throws {
		let path = NSTemporaryDirectory() + "retire-legacy-log-\(UUID().uuidString).txt"
		FileManager.default.createFile(atPath: path, contents: nil)
		defer { try? FileManager.default.removeItem(atPath: path) }
		let handle = try XCTUnwrap(FileHandle(forWritingAtPath: path))
		let saved = dup(STDERR_FILENO)
		dup2(handle.fileDescriptor, STDERR_FILENO)
		makeLegacyAccount()
		BeamioMnemonicSets.retireFaultForTests = .deleteFails
		sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		BeamioMnemonicSets.retireFaultForTests = nil
		sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": "000000"])
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		_ = preread()
		_ = BeamioNativeWallet.keyStore.read(eoa: syn.eoa)
		fflush(stderr)
		dup2(saved, STDERR_FILENO); close(saved)
		try handle.close()
		let log = try String(contentsOfFile: path, encoding: .utf8).lowercased()
		let words = syn.phrase.lowercased().split(separator: " ").map(String.init)
		XCTAssertFalse(words.contains { $0.count > 3 && log.contains($0) }, "no phrase word in the log")
		XCTAssertFalse(log.contains(syn.passcode), "no passcode in the log")
		XCTAssertFalse(log.contains((theEnvelope["ct"] as? String ?? "?").lowercased()), "no cipher text in the log")
		XCTAssertFalse(log.contains(derivedKey.map { String(format: "%02x", $0) }.joined()), "no key bytes in the log")
	}

	// MARK: - a wrong passcode, locks and read failures

	private func snapshotItems() -> [String: Data] { items }

	/// A wrong passcode: unlock_failed; the plaintext set, the versions, the pointer and every other item are unchanged byte for byte.
	func testAWrongPasscodeChangesNothing() {
		syncPlain()
		let before = snapshotItems()
		let answer = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": "000000"])
		XCTAssertEqual((answer["result"] as? [String: Any])?["code"] as? String, "unlock_failed")
		XCTAssertEqual(snapshotItems(), before, "nothing changed")
		XCTAssertEqual(plainKey.count, 1)
		XCTAssertEqual(preread()["code"] as? String, "ok")
		// and after the conversion, a wrong passcode on the converted account changes nothing either
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		let converted = snapshotItems()
		let wrong = sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": "000000"])
		XCTAssertEqual((wrong["result"] as? [String: Any])?["code"] as? String, "unlock_failed")
		XCTAssertEqual(snapshotItems(), converted)
	}

	/// A damaged pointer, the device storage lock, and a store that cannot list its items are read errors, never a confirmed absence and never the phrase.
	func testLockedAndUnreadableStatesAreReadErrors() {
		syncPlain()
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		// storage lock
		let locked = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 5, "seq": NSNumber(value: 200_000), "trustedOrigin": true], snapshotKnown: true, storageLocked: true)
		XCTAssertEqual((locked["result"] as? [String: Any])?["code"] as? String, "read_error")
		// snapshot unknown
		let unknown = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 6, "seq": NSNumber(value: 200_001), "trustedOrigin": true], snapshotKnown: false, storageLocked: false)
		XCTAssertEqual((unknown["result"] as? [String: Any])?["code"] as? String, "read_error")
		// a damaged pointer
		let pointer = pointerKey[0]
		let saved = items[pointer]
		BeamioChatWalletTestMemory.items?[pointer] = Data("not json".utf8)
		BeamioPwaPreread.restartForTests()
		let damaged = preread()
		XCTAssertEqual(damaged["code"] as? String, "read_error")
		XCTAssertNil(damaged["mnemonic"])
		BeamioChatWalletTestMemory.items?[pointer] = saved
		BeamioPwaPreread.restartForTests()
		XCTAssertEqual(preread()["code"] as? String, "ok", "restored")
	}

	/// An empty store is still a confirmed absence.
	func testAnEmptyStoreIsStillAConfirmedAbsence() {
		XCTAssertEqual(preread()["code"] as? String, "confirmed_missing")
	}

	// MARK: - a plaintext set chosen again

	/// A native import that names the plaintext set again (the pointer moves to it) makes it live again and drops the old cleanup record.
	func testAPointerThatNamesThePlainSetAgainKeepsItLive() {
		syncPlain()
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		XCTAssertTrue(plainKey.isEmpty)
		XCTAssertEqual(retireKey.count, 1)
		XCTAssertEqual(BeamioMnemonicSets.save(phrase: syn.phrase, store: raw, utc: "2026-11-23T00:00:00Z"), .updated)
		XCTAssertTrue(retireKey.isEmpty, "the old cleanup record no longer applies")
		if case .phrase = BeamioMnemonicSets.readSet(store: raw, eoa: syn.eoa) {} else { XCTFail("the plaintext set is live again") }
	}

	// MARK: - nothing secret in logs or on the network

	/// The sync and the preread, run through the whole conversion with the standard error captured, write none of the phrase words, the passcode or the cipher text to the log.
	func testTheLogsHoldNoSecret() throws {
		let path = NSTemporaryDirectory() + "retire-log-\(UUID().uuidString).txt"
		FileManager.default.createFile(atPath: path, contents: nil)
		defer { try? FileManager.default.removeItem(atPath: path) }
		let handle = try XCTUnwrap(FileHandle(forWritingAtPath: path))
		let saved = dup(STDERR_FILENO)
		dup2(handle.fileDescriptor, STDERR_FILENO)
		syncPlain()
		_ = preread()
		BeamioMnemonicSets.retireFaultForTests = .deleteFails
		sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": syn.passcode])
		BeamioMnemonicSets.retireFaultForTests = nil
		sync(["eoa": syn.eoa, "cipher": theEnvelope, "passcode": "000000"])
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		_ = preread()
		fflush(stderr)
		dup2(saved, STDERR_FILENO); close(saved)
		try handle.close()
		let log = try String(contentsOfFile: path, encoding: .utf8).lowercased()
		let words = syn.phrase.lowercased().split(separator: " ").map(String.init)
		XCTAssertFalse(words.contains { $0.count > 3 && log.contains($0) }, "no phrase word in the log")
		XCTAssertFalse(log.contains(syn.passcode), "no passcode in the log")
		XCTAssertFalse(log.contains((theEnvelope["ct"] as? String ?? "?").lowercased()), "no cipher text in the log")
	}

	/// The sources of the sync, the preread and the cleanup open no network connection and write no log line with a secret.
	func testTheSourcesHaveNoNetworkAndNoSecretLog() throws {
		let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources/ConetChatSDK")
		for name in ["BeamioPwaWalletSync.swift", "BeamioMnemonicSets.swift", "BeamioMnemonicCipherV3.swift", "BeamioPwaPreread.swift", "BeamioCipherUnlock.swift", "BeamioPasscodeSession.swift", "BeamioChatWalletKeychain.swift"] {
			var text = try String(contentsOf: root.appendingPathComponent(name), encoding: .utf8)
			// the one existing line that logs the kind of an item that was not removed (a name word only, never a value)
			text = text.split(separator: "\n").filter { !$0.contains("account delete: the %@ item was not removed") }.joined(separator: "\n")
			for banned in ["URLSession", "URLRequest", "NWConnection", "NSLog(", "print(", "os_log", "Logger("] {
				XCTAssertFalse(text.contains(banned), "\(name) must not contain \(banned)")
			}
		}
	}

	// MARK: - through the shell's allow-list

	/// The shell keeps the fields of both answers: the phrase answer keeps code, mnemonic and eoa; the cipher answer keeps code and all eight cipher fields.
	func testBothAnswersSurviveTheShellFilter() {
		syncPlain()
		let plainAck = prereadAck()
		let plainOut = (shellFilter(plainAck)["result"] as? [String: Any]) ?? [:]
		XCTAssertEqual(Set(plainOut.keys), ["code", "mnemonic", "eoa"])
		XCTAssertEqual(plainOut["mnemonic"] as? String, (plainAck["result"] as? [String: Any])?["mnemonic"] as? String)
		sync(["eoa": syn.eoa, "cipher": theEnvelope])
		let cipherAck = prereadAck()
		let cipherOut = (shellFilter(cipherAck)["result"] as? [String: Any]) ?? [:]
		XCTAssertEqual(Set(cipherOut.keys), ["code", "cipher"])
		XCTAssertEqual(Set((cipherOut["cipher"] as? [String: Any])?.keys.map { $0 } ?? []), ["v", "mode", "eoa", "kdf", "salt", "iv", "alg", "ct"])
		XCTAssertEqual(NSDictionary(dictionary: cipherOut["cipher"] as? [String: Any] ?? [:]), NSDictionary(dictionary: theEnvelope))
	}
}
#endif
