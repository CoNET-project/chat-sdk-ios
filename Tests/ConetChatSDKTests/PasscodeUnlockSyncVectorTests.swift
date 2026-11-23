#if BEAMIO_TEST_HOOKS
import XCTest
import CryptoKit
import OSLog
@testable import ConetChatSDK

/// Method Y (the passcode protection stays in the store): the SDK cases MS-01 to MS-11 of passcode-unlock-sync-vectors.v1, run through the product classes
/// (`BeamioPasscodeWalletStore.standard` over the in-memory Keychain, `BeamioPwaWalletSync`, the module commands). Nothing is written by hand: every state is
/// built by the sync itself. The synthetic phrase, passcode and account come from the shared cipher vector file; the store is compared by its SHA-256 only.
final class PasscodeUnlockSyncVectorTests: XCTestCase {
	private struct Synthetic { let phrase: String; let eoa: String; let passcode: String }
	private var seq = 0
	private var req = 950_000
	private var syn: Synthetic!
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUpWithError() throws {
		try super.setUpWithError()
		let data = try BundledVectorFile.data(resource: "mnemonic-cipher-format.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let i = try XCTUnwrap(root["syntheticInputs"] as? [String: Any])
		syn = Synthetic(phrase: i["phrase"] as? String ?? "", eoa: (i["eoa"] as? String ?? "").lowercased(), passcode: i["sixDigitPasscode"] as? String ?? "")
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
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioChatWalletTestMemory.items = [:]
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	// MARK: - helpers

	private func envelope(phrase: String? = nil, eoa: String? = nil, passcode: String? = nil) -> [String: Any] {
		BeamioMnemonicCipherV3.sealForTests(phrase: phrase ?? syn.phrase, passcode: Array((passcode ?? syn.passcode).utf8), eoa: eoa ?? syn.eoa)!
	}

	@discardableResult
	private func sync(_ body: [String: Any], seq forced: Int? = nil, trusted: Bool = true) -> [String: Any] {
		req += 1; seq += 1
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		var full: [String: Any] = ["type": "pwaWalletSync", "reqId": req, "seq": NSNumber(value: forced ?? seq), "trustedOrigin": trusted]
		for (k, v) in body { full[k] = v }
		return BeamioPwaWalletSync.answer(full, snapshotKnown: BeamioNativeKeySnapshot.isKnown, storageLocked: BeamioNativeKeySnapshot.current()?.storageLock != nil)
	}

	private func command(_ type: String, _ extra: [String: Any] = [:]) -> [String: Any] {
		req += 1
		var body = extra; body["type"] = type; body["reqId"] = req
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in if let e = payload["event"] as? [String: Any] { events.append(e) } }
		let drained = expectation(description: "drain"); DispatchQueue.main.async { drained.fulfill() }; wait(for: [drained], timeout: 5)
		return events.first { $0["type"] as? String == "ack" && $0["reqId"] as? Int == req } ?? [:]
	}

	private func result(_ answer: [String: Any]) -> [String: Any] { answer["result"] as? [String: Any] ?? [:] }

	/// SHA-256 over every item of the in-memory Keychain (names and bytes), with the item count.
	private func storeHash() -> String {
		var h = SHA256()
		let items = (BeamioChatWalletTestMemory.items ?? [:]).sorted { $0.key < $1.key }
		for (k, v) in items { h.update(data: Data(k.utf8)); h.update(data: v) }
		return h.finalize().map { String(format: "%02x", $0) }.joined() + ":\(items.count)"
	}

	private func itemNames() -> Set<String> { Set((BeamioChatWalletTestMemory.items ?? [:]).keys) }

	private func raw() -> BeamioChatRawItemStoring { BeamioNativeWallet.keyStore as! BeamioChatRawItemStoring }

	private func currentCipherEoa() -> String? {
		if case .cipher(let eoa, _) = BeamioMnemonicSets.current(store: raw()) { return eoa }
		return nil
	}

	private func assertOkUnlocked(_ answer: [String: Any], _ id: String) {
		XCTAssertEqual(answer["ok"] as? Bool, true, id)
		XCTAssertEqual(result(answer)["code"] as? String, "ok", id)
		XCTAssertEqual(result(answer)["decrypted"] as? Bool, true, id)
		XCTAssertEqual(result(answer)["stored"] as? Bool, true, id)
		XCTAssertEqual(result(answer)["readback"] as? String, "match", id)
	}

	private func assertSigns(_ eoa: String, _ id: String) {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		switch BeamioNativeWallet.signEip191(eoa: eoa, message: "m6") {
		case .success(let s): XCTAssertEqual(BeamioNativeEthSigner.recoverEip191AddressForTests(message: "m6", signature: s), eoa, "\(id): the signature recovers the account")
		case .failure(let f): XCTFail("\(id): signing failed \(f)")
		}
	}

	private func assertSigningRefused(_ eoa: String, _ id: String) {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		if case .success = BeamioNativeWallet.signEip191(eoa: eoa, message: "m6") { XCTFail("\(id): a locked account must not sign") }
	}

	// MARK: - MS-01 .. MS-11

	/// MS-01: the native record is the v3 envelope of A; the same envelope with the correct passcode: unlocked, the store bytes unchanged, the record still the envelope.
	func testMS01SameEnvelopeCorrectPasscodeUnlocksWithoutWriting() {
		let env = envelope()
		XCTAssertEqual(result(sync(["eoa": syn.eoa, "cipher": env]))["code"] as? String, "ok")   // S-cipher(A), built by the product path
		let before = storeHash()
		let answer = sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode])
		assertOkUnlocked(answer, "MS-01")
		XCTAssertEqual(storeHash(), before, "MS-01: the store bytes are unchanged")
		XCTAssertEqual(currentCipherEoa(), syn.eoa, "MS-01: the record is still the v3 envelope")
		XCTAssertTrue(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
		assertSigns(syn.eoa, "MS-01")
		XCTAssertEqual(result(command("passcodeStatus"))["nativeLocked"] as? Bool, false, "MS-01: passcodeStatus.nativeLocked is false")
	}

	/// MS-02: after MS-01 the page sends the plaintext phrase of A: the ciphertext is not replaced.
	func testMS02APlaintextPhraseDoesNotReplaceTheEnvelope() {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "MS-01")
		let before = storeHash()
		let answer = sync(["eoa": syn.eoa, "phrase": syn.phrase])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result(answer)["sync"] as? String, "unchanged")
		XCTAssertEqual(result(answer)["eoa"] as? String, syn.eoa)
		XCTAssertEqual(storeHash(), before, "MS-02: the store bytes are unchanged")
		XCTAssertEqual(currentCipherEoa(), syn.eoa, "MS-02: still the v3 envelope")
		XCTAssertFalse(itemNames().contains { $0.hasSuffix(BeamioMnemonicSets.setName(syn.eoa)) }, "MS-02: no plaintext set was written")
	}

	/// MS-03: the native store is empty; the correct passcode: the envelope itself is stored (never a plaintext set), and the session is ready.
	func testMS03EmptyStoreCorrectPasscodeStoresTheEnvelopeAndUnlocks() {
		XCTAssertTrue(itemNames().isEmpty)
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": envelope(), "passcode": syn.passcode]), "MS-03")
		XCTAssertEqual(currentCipherEoa(), syn.eoa)
		XCTAssertFalse(itemNames().contains { $0.hasSuffix(BeamioMnemonicSets.setName(syn.eoa)) }, "MS-03: never a plaintext set")
		XCTAssertEqual(itemNames().count, 2, "MS-03: one envelope version and the pointer")
		assertSigns(syn.eoa, "MS-03")
	}

	/// MS-04: a wrong passcode, the same envelope: unlock_failed, nothing written, the session stays locked.
	func testMS04WrongPasscodeSameEnvelope() {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		let before = storeHash()
		let answer = sync(["eoa": syn.eoa, "cipher": env, "passcode": "000000"])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result(answer)["code"] as? String, "unlock_failed")
		XCTAssertEqual(storeHash(), before)
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
		assertSigningRefused(syn.eoa, "MS-04")
	}

	/// MS-05: a wrong passcode on an empty store: unlock_failed, nothing is stored.
	func testMS05WrongPasscodeEmptyStore() {
		let answer = sync(["eoa": syn.eoa, "cipher": envelope(), "passcode": "000000"])
		XCTAssertEqual(result(answer)["code"] as? String, "unlock_failed")
		XCTAssertTrue(itemNames().isEmpty, "MS-05: nothing stored")
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
	}

	/// MS-06: the envelope of B while the native record holds A: decrypt first, then the different-account rule (a new version, the items of A kept); a wrong passcode writes nothing.
	func testMS06AnEnvelopeOfAnotherAccount() {
		let b = ValidTestAccounts.accountB
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let before = storeHash(); let namesBefore = itemNames()
		let envB = envelope(phrase: ValidTestAccounts.phraseB, eoa: b.eoa, passcode: "246810")
		let wrong = sync(["eoa": b.eoa, "cipher": envB, "passcode": "000000"])
		XCTAssertEqual(result(wrong)["code"] as? String, "unlock_failed")
		XCTAssertEqual(storeHash(), before, "MS-06: a wrong passcode writes nothing")
		let right = sync(["eoa": b.eoa, "cipher": envB, "passcode": "246810"])
		XCTAssertEqual(right["ok"] as? Bool, true, "MS-06")
		XCTAssertEqual(result(right)["sync"] as? String, "updated", "MS-06: updated_switched")
		XCTAssertEqual(result(right)["eoa"] as? String, b.eoa, "MS-06: the declared eoa")
		XCTAssertNil(result(right)["code"], "MS-06: not the ok_unlocked shape")
		XCTAssertTrue(BeamioCipherUnlock.isUnlocked(eoa: b.eoa), "MS-06: the session is ready for B")
		XCTAssertEqual(currentCipherEoa(), b.eoa, "MS-06: the record is the envelope of B")
		XCTAssertTrue(namesBefore.isSubset(of: itemNames()), "MS-06: every old item of A is kept")
		assertSigns(b.eoa, "MS-06")
	}

	private final class LockRecords: BeamioPasscodeRecordStoring {
		var data: [String: Data] = [:]
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class LockHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	/// MS-07: a read fault on the set (the owner is locked, so the product store answers unreadable): nothing is written, the pointer does not move, the session is not unlocked.
	func testMS07AReadFaultWritesNothingAndDoesNotUnlock() throws {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		let records = LockRecords()
		let savedVault = BeamioPasscodeSession.shared.vault
		defer { BeamioPasscodeSession.shared.vault = savedVault; BeamioPasscodeSession.shared.lockAll() }
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: LockHardware())
		BeamioPasscodeSession.shared.lockAll()
		records.data[syn.eoa] = try JSONEncoder().encode(BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 8)))
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore(records: records, hardware: LockHardware(), legacy: BeamioChatWalletKeychainStore.standard, session: BeamioPasscodeSession.shared)
		BeamioNativeKeySnapshot.invalidate()
		let before = storeHash(); let pointerBefore = BeamioNativeAccountPointer.get()
		let answer = sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode])
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "write_failed")
		XCTAssertEqual(answer["reason"] as? String, "internal_state", "the existing flat shape of the failure")
		XCTAssertEqual(storeHash(), before, "MS-07: nothing written")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), pointerBefore, "MS-07: the pointer does not move")
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa), "MS-07: not unlocked")
	}

	/// MS-08: an invalid envelope is never ok and writes nothing.
	func testMS08AnInvalidEnvelopeIsNeverOk() {
		let good = envelope()
		var cases: [[String: Any]] = []
		for (key, value) in [("v", 2), ("mode", "plain"), ("kdf", "argon2id/m=1/t=1/p=1/dkLen=32"), ("alg", "AES-128-GCM")] as [(String, Any)] {
			var bad = good; bad[key] = value; cases.append(bad)
		}
		var tampered = good
		var ct = Data(base64Encoded: tampered["ct"] as! String)!; ct[0] ^= 0x01
		tampered["ct"] = ct.base64EncodedString(); cases.append(tampered)
		for (index, bad) in cases.enumerated() {
			let before = storeHash()
			let answer = sync(["eoa": syn.eoa, "cipher": bad, "passcode": syn.passcode])
			let code = result(answer)["code"] as? String
			let error = answer["error"] as? String
			if index < 4 {
				XCTAssertEqual(error, "bad_request", "MS-08: a shape problem is a bad_request (case \(index))")
			} else {
				XCTAssertEqual(code, "unlock_failed", "MS-08: a tampered ciphertext does not authenticate")
			}
			XCTAssertNotEqual(code, "ok")
			XCTAssertEqual(storeHash(), before, "MS-08: nothing written")
		}
	}

	/// MS-09: no passcode with an envelope: stored and still locked; an identical envelope is not rewritten.
	func testMS09NoPasscodeStoresTheEnvelopeAndStaysLocked() {
		let env = envelope()
		let first = sync(["eoa": syn.eoa, "cipher": env])
		XCTAssertEqual(first["ok"] as? Bool, true)
		XCTAssertEqual(result(first)["code"] as? String, "ok")
		XCTAssertEqual(result(first)["decrypted"] as? Bool, false)
		XCTAssertEqual(result(first)["stored"] as? Bool, true)
		XCTAssertEqual(currentCipherEoa(), syn.eoa)
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa), "MS-09: still locked")
		let before = storeHash()
		let again = sync(["eoa": syn.eoa, "cipher": env])
		XCTAssertEqual(result(again)["decrypted"] as? Bool, false)
		XCTAssertEqual(storeHash(), before, "MS-09: an identical envelope is not rewritten")
	}

	/// MS-10: after MS-01 and a restart (the process memory is gone): the record is still the envelope, preread answers it, the session is locked, signing is refused.
	func testMS10AfterARestartTheRecordIsStillTheEnvelopeAndLocked() {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "MS-01")
		let before = storeHash()
		BeamioCipherUnlock.clear()   // a new process: the held key is memory only
		BeamioNativeKeySnapshot.invalidate()
		XCTAssertEqual(storeHash(), before, "MS-10: the record is the same bytes")
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		req += 1
		let preread = BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: req, seq: 1000)
		XCTAssertEqual(result(preread)["code"] as? String, "ok")
		let stored = result(preread)["cipher"] as? [String: Any]
		XCTAssertEqual(stored.map { NSDictionary(dictionary: $0) }, NSDictionary(dictionary: env), "MS-10: the same envelope")
		let status = result(command("passcodeStatus"))
		XCTAssertEqual(status["nativeLocked"] as? Bool, true)
		let wallet = result(command("walletStatus"))
		XCTAssertEqual(wallet["status"] as? String, "not_ready")
		XCTAssertEqual(wallet["notReadyReason"] as? String, "passcode_not_provided")
		assertSigningRefused(syn.eoa, "MS-10")
	}

	/// MS-11: the status commands see the account behind a v3 record: present but needs the passcode; never no_key.
	func testMS11StatusCommandsSeeTheAccountBehindAnEnvelope() {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		BeamioNativeKeySnapshot.invalidate()
		let wallet = result(command("walletStatus"))
		XCTAssertEqual(wallet["status"] as? String, "not_ready")
		XCTAssertEqual(wallet["notReadyReason"] as? String, "passcode_not_provided")
		let status = result(command("passcodeStatus"))
		XCTAssertEqual(status["hasKey"] as? Bool, true)
		XCTAssertEqual(status["nativeLocked"] as? Bool, true)
		let address = command("walletAddress")
		XCTAssertEqual(address["ok"] as? Bool, false)
		XCTAssertNotEqual(address["error"] as? String, "no_key", "MS-11: never no_key for a present envelope")
		XCTAssertEqual(address["error"] as? String, "not_ready")
		// after the unlock the same commands answer unlocked and the address
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "unlock")
		XCTAssertEqual(result(command("walletStatus"))["status"] as? String, "unlocked")
		XCTAssertEqual(result(command("walletAddress"))["address"] as? String, syn.eoa)
	}

	// MARK: - The plaintext path (no passcode) and the rest of the vector file

	private func itemBytes() -> [String: Data] { BeamioChatWalletTestMemory.items ?? [:] }

	/// MS-12: no passcode, the native store empty: the plaintext set is created, and the account is ready.
	func testMS12NoPasscodeEmptyStoreCreatesThePlaintextSet() {
		let a = ValidTestAccounts.accountA
		let answer = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result(answer)["sync"] as? String, "updated")
		XCTAssertEqual(result(answer)["eoa"] as? String, a.eoa)
		XCTAssertEqual(itemNames().count, 2, "MS-12: the set and the pointer")
		assertSigns(a.eoa, "MS-12")
	}

	/// MS-13: the same eoa and the same phrase again (every start): idempotent, nothing written, the account ready.
	func testMS13TheSamePhraseAgainIsIdempotent() {
		let a = ValidTestAccounts.accountA
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		let before = storeHash()
		let again = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(result(again)["sync"] as? String, "idempotent")
		XCTAssertEqual(result(again)["eoa"] as? String, a.eoa)
		XCTAssertEqual(storeHash(), before, "MS-13: nothing written")
		assertSigns(a.eoa, "MS-13")
	}

	/// MS-14 (the account switch, M6 v3): the derived address matches the request but differs from the native current record: the new account is saved as its own set, the old
	/// record is kept byte for byte, and `current` moves only after the new set is written and read back.
	func testMS14AnAccountSwitchSavesANewSetAndKeepsTheOldOne() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		let old = itemBytes()
		let answer = sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result(answer)["sync"] as? String, "updated")
		let now = itemBytes()
		for (name, bytes) in old where name != "com.beamio.beamio.chat-wallet\u{1}" + BeamioMnemonicSets.currentName {
			XCTAssertEqual(now[name], bytes, "MS-14: \(name) is kept as it was")
		}
		XCTAssertGreaterThan(now.count, old.count, "MS-14: the set of B is new")
		assertSigns(b.eoa, "MS-14")
		XCTAssertEqual(BeamioNativeWallet.keyStore.read(eoa: a.eoa), a.key, "MS-14: the old account is still readable")
	}

	/// MS-15: the eoa given does not match the phrase: bad_request, nothing written.
	func testMS15AnEoaThatTheyPhraseDoesNotDeriveIsBadRequest() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		let before = storeHash()
		let answer = sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "bad_request")
		XCTAssertEqual(storeHash(), before)
		_ = a
	}

	/// MS-16: a read fault on the current record (the owner is locked): write_failed/internal_state, nothing written, the pointer unchanged.
	func testMS16AReadFaultOnThePlaintextPathWritesNothing() throws {
		let a = ValidTestAccounts.accountA
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		let records = LockRecords()
		let savedVault = BeamioPasscodeSession.shared.vault
		defer { BeamioPasscodeSession.shared.vault = savedVault; BeamioPasscodeSession.shared.lockAll() }
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: LockHardware())
		BeamioPasscodeSession.shared.lockAll()
		records.data[a.eoa] = try JSONEncoder().encode(BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 8)))
		BeamioNativeWallet.keyStore = BeamioPasscodeWalletStore(records: records, hardware: LockHardware(), legacy: BeamioChatWalletKeychainStore.standard, session: BeamioPasscodeSession.shared)
		BeamioNativeKeySnapshot.invalidate()
		let before = storeHash(); let pointer = BeamioNativeAccountPointer.get()
		let answer = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "write_failed")
		XCTAssertEqual(answer["reason"] as? String, "internal_state")
		XCTAssertEqual(storeHash(), before)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), pointer)
	}

	/// MS-17: the envelope opens with the passcode, but its phrase derives another account (or the request names another eoa): nothing written, nothing unlocked.
	func testMS17IdentityFailuresWriteNothingAndUnlockNothing() {
		let b = ValidTestAccounts.accountB
		// an envelope of eoa A whose ciphertext holds the phrase of B
		let foreign = envelope(phrase: ValidTestAccounts.phraseB, eoa: syn.eoa)
		var before = storeHash()
		var answer = sync(["eoa": syn.eoa, "cipher": foreign, "passcode": syn.passcode])
		XCTAssertEqual(result(answer)["code"] as? String, "verify_failed")
		XCTAssertEqual(storeHash(), before)
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
		// the request names B, the envelope is A's
		before = storeHash()
		answer = sync(["eoa": b.eoa, "cipher": envelope(), "passcode": syn.passcode])
		XCTAssertEqual(result(answer)["code"] as? String, "verify_failed", "a request eoa that is not the envelope's is an identity failure")
		XCTAssertEqual(storeHash(), before)
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
	}

	/// MS-18 and SC-01: after an unlock no store item holds the passcode, the phrase or the derived key; a lock drops the session key.
	func testMS18NothingSecretIsStoredAndALockDropsTheKey() {
		let env = envelope()
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "MS-18")
		let secrets: [(String, Data)] = [("passcode", Data(syn.passcode.utf8)), ("phrase", Data(syn.phrase.utf8)), ("key", BeamioCipherUnlock.key(eoa: syn.eoa) ?? Data())]
		XCTAssertEqual(secrets[2].1.count, 32, "the session holds the key")
		for (name, bytes) in itemBytes() {
			for (label, secret) in secrets where !secret.isEmpty {
				XCTAssertNil(bytes.range(of: secret), "SC-01: item \(name.split(separator: "\u{1}").last ?? "") holds the \(label)")
				XCTAssertNil(bytes.range(of: Data(secret.map { String(format: "%02x", $0) }.joined().utf8)), "SC-01: item holds the hex of the \(label)")
			}
		}
		BeamioPasscodeSession.shared.lockAll()
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa), "MS-18: a lock drops the session key")
		assertSigningRefused(syn.eoa, "MS-18")
	}

	/// MS-19: a fixed challenge signed by the session recovers to A; before the unlock and after a restart it is refused.
	func testMS19SigningFollowsTheSessionLock() {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		assertSigningRefused(syn.eoa, "MS-19 before the unlock")
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "MS-19")
		assertSigns(syn.eoa, "MS-19 after the unlock")
		BeamioCipherUnlock.clear()
		BeamioNativeKeySnapshot.invalidate()
		assertSigningRefused(syn.eoa, "MS-19 after a restart")
	}

	/// MS-20: the same sync again in one process: ok_unlocked again, the store bytes unchanged.
	func testMS20ARepeatedSyncIsStillUnlockedAndWritesNothing() {
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env])
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "first")
		let before = storeHash()
		assertOkUnlocked(sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode]), "MS-20")
		XCTAssertEqual(storeHash(), before)
	}

	/// MS-21: a stale seq or an untrusted origin is refused as before, for every form, and writes nothing.
	func testMS21StaleSeqAndUntrustedOriginAreRefusedForEveryForm() {
		let a = ValidTestAccounts.accountA
		let env = envelope()
		sync(["eoa": syn.eoa, "cipher": env], seq: 10)
		let before = storeHash()
		let forms: [[String: Any]] = [["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode], ["eoa": syn.eoa, "cipher": env], ["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA]]
		for form in forms {
			XCTAssertEqual(sync(form, seq: 3)["error"] as? String, "stale_seq")
			XCTAssertEqual(sync(form, seq: 11, trusted: false)["error"] as? String, "untrusted_source")
		}
		XCTAssertEqual(storeHash(), before)
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
	}

	/// SC-02: the passcode, the phrase and the key do not reach any log on any path: stderr (NSLog), stdout (print) and the unified log (os_log) are all read back while a complete
	/// run goes through every command. Three canaries (one per channel) first prove that each channel is really captured.
	func testSC02NoSecretReachesAnyLog() throws {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		let env = envelope()
		let envB = envelope(phrase: ValidTestAccounts.phraseB, eoa: b.eoa, passcode: "246810")
		let started = Date()
		var logStore: OSLogStore?
		logStore = try? OSLogStore(scope: .currentProcessIdentifier)
		let channels = captureStdStreams {
			NSLog("[canary] stderr-channel-canary")
			print("[canary] stdout-channel-canary")
			os_log("[canary] oslog-channel-canary", log: OSLog(subsystem: "network.conet.sdk-test", category: "canary"))
			_ = sync(["eoa": syn.eoa, "cipher": env])
			_ = sync(["eoa": syn.eoa, "cipher": env, "passcode": wrongPasscode])
			_ = sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode])
			_ = sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode])
			_ = sync(["eoa": syn.eoa, "phrase": syn.phrase])
			_ = sync(["eoa": b.eoa, "cipher": envB, "passcode": "246810"])
			_ = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
			_ = sync(["eoa": syn.eoa, "cipher": env, "passcode": syn.passcode])
			_ = command("passcodeStatus"); _ = command("walletStatus"); _ = command("walletAddress")
			_ = BeamioNativeWallet.signEip191(eoa: syn.eoa, message: "log")
			req += 1; _ = BeamioPwaWalletSyncEngine.nativeMnemonicPreread(reqId: req, seq: 5000)
			_ = BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore)
			BeamioPasscodeSession.shared.lockAll()
			BeamioCipherUnlock.clear()
		}
		Thread.sleep(forTimeInterval: 0.5)
		var unified = ""
		if let logStore {
			let entries = try logStore.getEntries(at: logStore.position(date: started))
			for case let entry as OSLogEntryLog in entries { unified += entry.composedMessage + "\n" }
		}
		XCTAssertTrue(channels.stderr.contains("stderr-channel-canary"), "the stderr capture works")
		XCTAssertTrue(channels.stdout.contains("stdout-channel-canary"), "the stdout capture works")
		XCTAssertTrue(unified.contains("oslog-channel-canary"), "the unified log capture works")
		let keyHex = [ValidTestAccounts.accountA.key, ValidTestAccounts.accountB.key].map { $0.map { String(format: "%02x", $0) }.joined() }
		let secrets: [(String, String)] = [("passcode", syn.passcode), ("wrong passcode", wrongPasscode), ("B passcode", "246810"), ("phrase A", syn.phrase), ("phrase A (account A)", ValidTestAccounts.phraseA),
		                                   ("phrase B", ValidTestAccounts.phraseB), ("key A hex", keyHex[0]), ("key B hex", keyHex[1])]
		for (channel, text) in [("stderr", channels.stderr), ("stdout", channels.stdout), ("os_log", unified)] {
			for (name, secret) in secrets {
				// a number is a secret only as a whole token (a longer number or a float that merely contains the digits is not a leak)
				let found = secret.allSatisfy({ $0.isNumber }) ? text.range(of: "(?<![0-9.])" + secret + "(?![0-9])", options: .regularExpression) != nil : text.contains(secret)
				XCTAssertFalse(found, "SC-02: the \(channel) log holds the \(name)")
			}
		}
	}

	/// An arbitrary six digits that no other log line is likely to carry.
	private var wrongPasscode: String { "739152" }

	private func captureStdStreams(_ body: () -> Void) -> (stderr: String, stdout: String) {
		fflush(stderr); fflush(stdout)
		let savedErr = dup(STDERR_FILENO), savedOut = dup(STDOUT_FILENO)
		let errPipe = Pipe(), outPipe = Pipe()
		dup2(errPipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)
		dup2(outPipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
		body()
		fflush(stderr); fflush(stdout)
		dup2(savedErr, STDERR_FILENO); dup2(savedOut, STDOUT_FILENO)
		close(savedErr); close(savedOut)
		errPipe.fileHandleForWriting.closeFile(); outPipe.fileHandleForWriting.closeFile()
		return (String(decoding: errPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
		        String(decoding: outPipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
	}

	/// The public entry of the passcode form (the shell's seam): the same answers as the internal path, with the passcode optional.
	func testThePublicEngineEntryCarriesTheCipherAndThePasscode() {
		let env = envelope()
		let mirror = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 1, seq: 1, eoa: syn.eoa, cipher: env, passcode: nil)
		XCTAssertEqual(result(mirror)["decrypted"] as? Bool, false)
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa))
		let before = storeHash()
		let wrong = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 2, seq: 2, eoa: syn.eoa, cipher: env, passcode: "000000")
		XCTAssertEqual(result(wrong)["code"] as? String, "unlock_failed")
		let right = BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 3, seq: 3, eoa: syn.eoa, cipher: env, passcode: syn.passcode)
		assertOkUnlocked(right, "public entry")
		XCTAssertEqual(storeHash(), before, "nothing written by the wrong or the right passcode on the same envelope")
		XCTAssertEqual(result(BeamioPwaWalletSyncEngine.pwaWalletSync(reqId: 4, seq: 4, eoa: ValidTestAccounts.accountB.eoa, cipher: env, passcode: syn.passcode))["code"] as? String, "verify_failed",
		               "an eoa that is not the envelope's")
	}

	// MARK: - The legal account switch (M6 v3: MS-22 .. MS-31)

	private func currentPointerBytes() -> Data? { itemBytes().first { $0.key.hasSuffix(BeamioMnemonicSets.currentName) }?.value }

	private func setItems() -> [String: Data] { itemBytes().filter { $0.key.contains("mnemonic.set.") } }

	private func currentEoa() -> String? {
		guard let bytes = currentPointerBytes(), let o = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any] else { return nil }
		return o["eoa"] as? String
	}

	/// MS-22: no passcode: A is current, the page holds B (the declared eoa is the address of B's phrase): B's set is written, then current moves; A's items are identical.
	func testMS22ALegalSwitchWithoutAPasscode() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		let old = itemBytes()
		let answer = sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		XCTAssertEqual(result(answer)["sync"] as? String, "updated")
		XCTAssertEqual(currentEoa(), b.eoa, "MS-22: current is B")
		let now = itemBytes()
		for (name, bytes) in old where !name.hasSuffix(BeamioMnemonicSets.currentName) { XCTAssertEqual(now[name], bytes, "MS-22: A's \(name.split(separator: "\u{1}").last ?? "") is identical") }
		XCTAssertEqual(now.count, old.count + 1, "MS-22: exactly B's set is added")
		XCTAssertNotNil(now.first { $0.key.hasSuffix(BeamioMnemonicSets.setName(b.eoa)) }, "MS-22: B's own set")
	}

	/// MS-23: the passcode path: B's v3 envelope and the correct passcode, from a plaintext A and from an envelope of A: B is persisted as its envelope, never a plaintext set.
	func testMS23ALegalSwitchWithAPasscodeKeepsTheEnvelope() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		for from in ["plaintext", "envelope"] {
			BeamioChatWalletTestMemory.items = [:]; BeamioCipherUnlock.clear(); BeamioNativeKeySnapshot.invalidate(); BeamioPwaWalletSync.restartForTests(); seq = 0
			if from == "plaintext" { sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA]) } else { sync(["eoa": syn.eoa, "cipher": envelope()]) }
			let old = itemBytes()
			let envB = envelope(phrase: ValidTestAccounts.phraseB, eoa: b.eoa, passcode: "246810")
			let answer = sync(["eoa": b.eoa, "cipher": envB, "passcode": "246810"])
			XCTAssertEqual(answer["ok"] as? Bool, true, "MS-23 from \(from)")
			XCTAssertEqual(result(answer)["sync"] as? String, "updated", "MS-23 from \(from): updated_switched")
			XCTAssertEqual(result(answer)["eoa"] as? String, b.eoa)
			XCTAssertTrue(BeamioCipherUnlock.isUnlocked(eoa: b.eoa), "MS-23 from \(from): the session is ready for B")
			XCTAssertEqual(currentCipherEoa(), b.eoa, "MS-23: current is B's envelope")
			XCTAssertFalse(itemNames().contains { $0.hasSuffix(BeamioMnemonicSets.setName(b.eoa)) }, "MS-23: never a plaintext set of B")
			for (name, bytes) in old where !name.hasSuffix(BeamioMnemonicSets.currentName) { XCTAssertEqual(itemBytes()[name], bytes, "MS-23: the old items are identical") }
			assertSigns(b.eoa, "MS-23 from \(from)")
		}
	}

	/// MS-24: switching back to A (A's set exists with identical material): only the pointer moves; no set bytes change.
	func testMS24SwitchingBackMovesOnlyThePointer() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		let sets = setItems()
		let back = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(result(back)["sync"] as? String, "updated")
		XCTAssertEqual(currentEoa(), a.eoa)
		XCTAssertEqual(setItems(), sets, "MS-24: no set bytes change")
		assertSigns(a.eoa, "MS-24")
	}

	/// MS-25 and MS-27: a fault during a switch (the set write fails, the read-back does not match, the pointer write fails): current stays A, A's set is unchanged, nothing is
	/// deleted, and the answer is write_failed with a fixed reason; the next sync completes the switch.
	func testMS25AFaultDuringASwitchKeepsCurrentAndDeletesNothing() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		let envB = envelope(phrase: ValidTestAccounts.phraseB, eoa: b.eoa, passcode: "246810")
		for useCipher in [false, true] {
			for fault in ["setWrite", "readBack", "pointerWrite"] {
				let memory = MemoryNativeKeyStore()
				BeamioNativeWallet.keyStore = memory
				BeamioCipherUnlock.clear(); BeamioNativeKeySnapshot.invalidate(); BeamioPwaWalletSync.restartForTests(); seq = 0
				XCTAssertEqual(result(sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA]))["sync"] as? String, "updated")
				let aItems = memory.rawAccounts
				// the item the sync writes first: B's plaintext set, or the version of B's envelope (named by the digest of its canonical form)
				let bName: String
				if useCipher, let parsed = BeamioMnemonicCipherV3.parse(envB) {
					bName = BeamioMnemonicSets.setName(b.eoa) + ".c." + String(SHA256.hash(data: parsed.canonical).map { String(format: "%02x", $0) }.joined().prefix(16))
				} else {
					bName = BeamioMnemonicSets.setName(b.eoa)
				}
				switch fault {
				case "setWrite": memory.failWriteAccounts.insert(bName)
				case "readBack": memory.dropWriteAccounts.insert(bName)
				default: memory.failWriteAccounts.insert(BeamioMnemonicSets.currentName)
				}
				let body: [String: Any] = useCipher ? ["eoa": b.eoa, "cipher": envB, "passcode": "246810"] : ["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB]
				let answer = sync(body)
				let label = "MS-25 \(useCipher ? "cipher" : "plaintext") \(fault)"
				XCTAssertEqual(answer["ok"] as? Bool, false, label)
				XCTAssertEqual(answer["error"] as? String, "write_failed", label)
				// a refused write is storage_write; a read-back that does not match is internal_state (the state cannot be confirmed)
				XCTAssertEqual(answer["reason"] as? String, fault == "readBack" ? "internal_state" : "storage_write", label)
				for (name, bytes) in aItems { XCTAssertEqual(memory.rawAccounts[name], bytes, "\(label): A's \(name) is unchanged") }
				if case .ok(let eoa, _) = BeamioMnemonicSets.current(store: memory) { XCTAssertEqual(eoa, a.eoa, "\(label): current stays A") } else { XCTFail("\(label): current is not A") }
				XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: b.eoa), "\(label): B is not unlocked")
				// the fault is gone: the next sync completes the switch
				memory.failWriteAccounts = []; memory.dropWriteAccounts = []
				let next = sync(body)
				XCTAssertEqual(next["ok"] as? Bool, true, "\(label): the next sync completes")
			}
		}
	}

	/// MS-26: a wrong passcode on a switch: unlock_failed, nothing written, current stays A.
	func testMS26AWrongPasscodeOnASwitchWritesNothing() {
		let b = ValidTestAccounts.accountB
		sync(["eoa": syn.eoa, "cipher": envelope()])
		let before = storeHash()
		let answer = sync(["eoa": b.eoa, "cipher": envelope(phrase: ValidTestAccounts.phraseB, eoa: b.eoa, passcode: "246810"), "passcode": "000000"])
		XCTAssertEqual(result(answer)["code"] as? String, "unlock_failed")
		XCTAssertEqual(storeHash(), before)
		XCTAssertEqual(currentCipherEoa(), syn.eoa, "MS-26: current stays A")
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: b.eoa))
	}

	/// MS-28: an identity failure on a switch: verify_failed on the passcode path, bad_request without a passcode; nothing written, current unchanged.
	func testMS28AnIdentityFailureOnASwitchWritesNothing() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		let before = storeHash()
		let noPasscode = sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(noPasscode["error"] as? String, "bad_request")
		let foreign = envelope(phrase: ValidTestAccounts.phraseA, eoa: b.eoa, passcode: "246810")   // opens, but the phrase is A's, not B's
		let passcode = sync(["eoa": b.eoa, "cipher": foreign, "passcode": "246810"])
		XCTAssertEqual(result(passcode)["code"] as? String, "verify_failed")
		XCTAssertEqual(storeHash(), before)
		XCTAssertEqual(currentEoa(), a.eoa, "MS-28: current unchanged")
	}

	/// MS-30 and MS-31: no step renames, isolates or rewrites A's set during a switch, and nothing waits for the user: the answer comes back synchronously.
	func testMS30NoRenameAndMS31NoInteraction() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		let before = Set(itemNames())
		let aSetName = itemNames().first { $0.hasSuffix(BeamioMnemonicSets.setName(a.eoa)) }
		let answer = sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])   // a synchronous call that returns: no prompt, no continuation
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertTrue(before.isSubset(of: itemNames()), "MS-30: every old name is still there (nothing renamed or removed)")
		XCTAssertNotNil(aSetName)
		XCTAssertFalse(itemNames().contains { $0.contains("wallet.iso.") || $0.contains("overwrite") }, "MS-30: no isolation or journal item")
	}

	// MARK: - init and the silent selection follow the current record (MS-32, MS-33)

	/// MS-32: the current record is the v3 envelope of A while other sets are present and the pointer is empty: the selection follows current (A), never another account;
	/// init gives not_ready with the reason passcode_not_provided until A is unlocked, and no other set is touched.
	func testMS32ACipherCurrentIsFollowedAndNothingElseIsSelected() {
		let b = ValidTestAccounts.accountB
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])             // B's plaintext set is the older account
		sync(["eoa": syn.eoa, "cipher": envelope()])                          // current is now A's envelope
		BeamioNativeAccountPointer.clear()
		let bSet = itemBytes().first { $0.key.hasSuffix(BeamioMnemonicSets.setName(b.eoa)) }
		XCTAssertNotNil(bSet)
		XCTAssertEqual(BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore), .selected(syn.eoa), "MS-32: the selection follows current")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), syn.eoa, "MS-32: the pointer is A's, not B's")
		XCTAssertEqual(itemBytes().first { $0.key.hasSuffix(BeamioMnemonicSets.setName(b.eoa)) }?.value, bSet?.value, "MS-32: B's set is untouched")
		// init for A: not_ready with the passcode reason
		var events: [[String: Any]] = []
		let reqId = 951_001
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": reqId, "payload": ["identity": ["eoaAddress": syn.eoa]]]) { payload in
			events.append((payload["event"] as? [String: Any]) ?? payload)
		}
		let drained = expectation(description: "drain"); DispatchQueue.main.async { drained.fulfill() }; wait(for: [drained], timeout: 5)
		let refusal = events.first { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId && $0["ok"] as? Bool == false }
		XCTAssertEqual(refusal?["error"] as? String, "not_ready", "MS-32: init is not_ready while A is locked (events \(events.map { $0["type"] as? String ?? "?" }))")
		XCTAssertEqual(refusal?["reason"] as? String, "passcode_not_provided")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), syn.eoa, "MS-32: still A")
	}

	/// MS-33: after a switch to B, the selection follows the new current (B) even when A is the older account.
	func testMS33AfterASwitchTheSelectionFollowsTheNewCurrent() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		BeamioNativeAccountPointer.clear()
		XCTAssertEqual(currentEoa(), b.eoa)
		XCTAssertEqual(BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore), .selected(b.eoa), "MS-33: init and the selection follow B")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), b.eoa)
		XCTAssertNotEqual(BeamioNativeAccountPointer.get(), a.eoa, "MS-33: A is not selected by the first-entry rule")
	}

	/// A cipher version of A that is not current (the device switched to B) still keeps A protected: a plaintext sync of A is `unchanged` and does not downgrade it or move current.
	func testAPlaintextSyncDoesNotDowngradeANonCurrentEnvelope() {
		let a = ValidTestAccounts.accountA
		let envA = envelope(phrase: ValidTestAccounts.phraseA, eoa: a.eoa, passcode: "135790")
		sync(["eoa": a.eoa, "cipher": envA])
		let b = ValidTestAccounts.accountB
		XCTAssertEqual(result(sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB]))["sync"] as? String, "updated")   // current is B's plaintext set
		XCTAssertEqual(currentEoa(), b.eoa)
		let before = storeHash()
		let answer = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result(answer)["sync"] as? String, "unchanged")
		XCTAssertEqual(result(answer)["eoa"] as? String, a.eoa)
		XCTAssertEqual(storeHash(), before, "nothing written")
		XCTAssertEqual(currentEoa(), b.eoa, "current did not move")
		XCTAssertFalse(itemNames().contains { $0.hasSuffix(BeamioMnemonicSets.setName(a.eoa)) }, "no plaintext set of A")
		BeamioNativeAccountPointer.set(a.eoa)
		assertSigningRefused(a.eoa, "A stays locked without its passcode")
	}

	/// MS-35: B is current; the envelope of A is synced without a passcode (store only), then A's plaintext: `unchanged`, the store bytes unchanged by the second step.
	func testMS35AnEnvelopeSyncedWhileAnotherAccountIsCurrentIsNotDowngraded() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		let step1 = sync(["eoa": a.eoa, "cipher": envelope(phrase: ValidTestAccounts.phraseA, eoa: a.eoa, passcode: "135790")])
		XCTAssertEqual(result(step1)["code"] as? String, "ok", "step 1: stored")
		XCTAssertEqual(result(step1)["decrypted"] as? Bool, false)
		let before = storeHash(); let current = currentCipherEoa() ?? currentEoa()
		let step2 = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(result(step2)["sync"] as? String, "unchanged")
		XCTAssertEqual(storeHash(), before, "MS-35: the store bytes are unchanged by step 2")
		XCTAssertEqual(currentCipherEoa() ?? currentEoa(), current, "MS-35: current is unchanged by step 2")
	}

	/// MS-37: the order of the checks: the request eoa against the envelope eoa comes before the decryption, so an eoa that differs and a wrong passcode answer verify_failed.
	func testMS37TheEoaIsComparedBeforeTheDecryption() {
		let b = ValidTestAccounts.accountB
		let before = storeHash()
		let answer = sync(["eoa": b.eoa, "cipher": envelope(), "passcode": wrongPasscode])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result(answer)["code"] as? String, "verify_failed", "MS-37: verify_failed, not unlock_failed")
		XCTAssertEqual(storeHash(), before)
		// the shape comes first
		var malformed = envelope(); malformed["v"] = 2
		XCTAssertEqual(sync(["eoa": b.eoa, "cipher": malformed, "passcode": wrongPasscode])["error"] as? String, "bad_request", "a shape problem is a bad_request, even with another eoa and a wrong passcode")
		XCTAssertEqual(sync(["eoa": syn.eoa, "cipher": "not an object", "passcode": syn.passcode])["error"] as? String, "bad_request", "a body that is not an envelope object is a bad_request")
	}

	/// The four steps of the passcode path in their order (M6 v3.2): 1 the shape (bad_request), 2 the request eoa against the envelope eoa (verify_failed, before the decryption),
	/// 3 the decryption (unlock_failed), 4 the derived address (verify_failed). Each step is reached only when the earlier ones pass, and none of them writes or unlocks.
	func testTheFourStepsOfThePasscodePathRunInOrder() {
		let b = ValidTestAccounts.accountB
		let env = envelope()
		let before = storeHash()
		func step(_ body: [String: Any]) -> String {
			let answer = sync(body)
			return (answer["error"] as? String) ?? (result(answer)["code"] as? String) ?? "?"
		}
		var wrongShape = env; wrongShape["alg"] = "AES-128-GCM"
		var missing = env; missing.removeValue(forKey: "ct")
		// 1: the shape beats everything after it: another eoa and a wrong passcode still answer bad_request
		XCTAssertEqual(step(["eoa": b.eoa, "cipher": wrongShape, "passcode": wrongPasscode]), "bad_request")
		XCTAssertEqual(step(["eoa": b.eoa, "cipher": missing, "passcode": wrongPasscode]), "bad_request", "a missing field is a shape problem")
		XCTAssertEqual(step(["eoa": syn.eoa, "cipher": [String: Any](), "passcode": syn.passcode]), "bad_request", "an empty envelope")
		XCTAssertEqual(step(["eoa": syn.eoa, "passcode": syn.passcode]), "bad_request", "no envelope at all")
		// 2: the shape is fine, the request eoa is not the envelope's: verify_failed before the decryption, whatever the passcode
		XCTAssertEqual(step(["eoa": b.eoa, "cipher": env, "passcode": wrongPasscode]), "verify_failed", "another eoa and a wrong passcode")
		XCTAssertEqual(step(["eoa": b.eoa, "cipher": env, "passcode": syn.passcode]), "verify_failed", "another eoa and the right passcode")
		XCTAssertEqual(step(["eoa": b.eoa, "cipher": env]), "verify_failed", "another eoa and no passcode")
		// 3: the eoa matches: the decryption decides
		XCTAssertEqual(step(["eoa": syn.eoa, "cipher": env, "passcode": wrongPasscode]), "unlock_failed")
		// 4: the passcode opens it, but the phrase derives another address
		let foreign = envelope(phrase: ValidTestAccounts.phraseB, eoa: syn.eoa)
		XCTAssertEqual(step(["eoa": syn.eoa, "cipher": foreign, "passcode": syn.passcode]), "verify_failed")
		XCTAssertEqual(storeHash(), before, "no step wrote anything")
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa), "no step unlocked anything")
	}

	/// MS-38: a plaintext set of A and no v3 set of A, B current: the plaintext rules are unchanged (the pointer moves, A's set bytes stay).
	func testMS38APlaintextAccountWithoutAnEnvelopeKeepsThePlaintextRules() {
		let a = ValidTestAccounts.accountA, b = ValidTestAccounts.accountB
		sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		let sets = setItems()
		let answer = sync(["eoa": a.eoa, "phrase": ValidTestAccounts.phraseA])
		XCTAssertEqual(result(answer)["sync"] as? String, "updated")
		XCTAssertEqual(currentEoa(), a.eoa)
		XCTAssertEqual(setItems(), sets, "MS-38: A's set bytes stay")
	}

	// MARK: - MS-39 .. MS-42 (M6 v3.3: an envelope that cannot be verified never replaces an existing v3 version)

	private func flippedCt(_ env: [String: Any]) -> [String: Any] {
		var out = env; var ct = Data(base64Encoded: env["ct"] as? String ?? "")!; ct[0] ^= 1; out["ct"] = ct.base64EncodedString(); return out
	}

	private func versionNames(_ eoa: String) -> Set<String> { itemNames().filter { $0.contains(BeamioMnemonicSets.setName(eoa) + ".c.") } }

	/// MS-39: store-only, same account, same canonical bytes as an existing version: idempotent. A current: unchanged; B current: only the pointer moves.
	func testMS39StoreOnlyWithTheSameBytesIsIdempotent() {
		let b = ValidTestAccounts.accountB
		let e1 = envelope()
		sync(["eoa": syn.eoa, "cipher": e1])
		var before = storeHash()
		var answer = sync(["eoa": syn.eoa, "cipher": e1])
		XCTAssertEqual(result(answer)["code"] as? String, "ok", "MS-39 A current"); XCTAssertEqual(result(answer)["decrypted"] as? Bool, false)
		XCTAssertEqual(storeHash(), before, "MS-39 A current: unchanged")
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])
		let versions = versionNames(syn.eoa); before = storeHash()
		answer = sync(["eoa": syn.eoa, "cipher": e1])
		XCTAssertEqual(result(answer)["code"] as? String, "ok", "MS-39 B current")
		XCTAssertEqual(versionNames(syn.eoa), versions, "MS-39: no version added")
		XCTAssertNotEqual(storeHash(), before, "MS-39 B current: the pointer moved")
		XCTAssertEqual(currentCipherEoa(), syn.eoa)
	}

	/// MS-40: store-only, same account, other bytes (a changed ct, or a re-seal under another passcode): bad_request, nothing written, current unchanged.
	func testMS40StoreOnlyWithOtherBytesIsRefused() {
		let b = ValidTestAccounts.accountB
		let e1 = envelope()
		let others: [[String: Any]] = [flippedCt(e1), envelope(passcode: "246810")]
		for currentIsB in [false, true] {
			BeamioChatWalletTestMemory.items = [:]; BeamioNativeAccountPointer.clear(); BeamioCipherUnlock.clear(); BeamioNativeKeySnapshot.invalidate(); BeamioPwaWalletSync.restartForTests(); seq = 0
			sync(["eoa": syn.eoa, "cipher": e1])
			if currentIsB { sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB]) }
			let before = storeHash()
			for (i, other) in others.enumerated() {
				let answer = sync(["eoa": syn.eoa, "cipher": other])
				XCTAssertEqual(answer["error"] as? String, "bad_request", "MS-40 variant \(i) currentIsB=\(currentIsB)")
				XCTAssertEqual(storeHash(), before, "MS-40 variant \(i): nothing written, no version added, current unchanged, E1 byte-identical")
			}
		}
	}

	/// MS-41: store-only, the account has no set: stored as its first version (locked); a later store-only with other bytes is refused as MS-40.
	func testMS41StoreOnlyWithNoSetStoresTheFirstVersion() {
		let b = ValidTestAccounts.accountB
		sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB])   // only another account's set
		let e1 = envelope()
		let answer = sync(["eoa": syn.eoa, "cipher": e1])
		XCTAssertEqual(result(answer)["code"] as? String, "ok", "MS-41"); XCTAssertEqual(result(answer)["decrypted"] as? Bool, false)
		XCTAssertEqual(versionNames(syn.eoa).count, 1, "MS-41: the first version")
		XCTAssertFalse(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa), "MS-41: locked")
		let before = storeHash()
		XCTAssertEqual(sync(["eoa": syn.eoa, "cipher": flippedCt(e1)])["error"] as? String, "bad_request", "MS-41: a later store-only with other bytes")
		XCTAssertEqual(storeHash(), before)
	}

	/// MS-42: with the passcode: other bytes that decrypt and derive the declared address are accepted (one version added, current points to it, session ready, E1 kept);
	/// a wrong passcode is unlock_failed (nothing written); a right passcode with a derived address that differs is verify_failed (nothing written).
	func testMS42WithThePasscodeAReSealedEnvelopeIsAccepted() {
		let b = ValidTestAccounts.accountB
		let e1 = envelope(), e2 = envelope(passcode: "246810")
		for currentIsB in [false, true] {
			BeamioChatWalletTestMemory.items = [:]; BeamioNativeAccountPointer.clear(); BeamioCipherUnlock.clear(); BeamioNativeKeySnapshot.invalidate(); BeamioPwaWalletSync.restartForTests(); seq = 0
			sync(["eoa": syn.eoa, "cipher": e1])
			if currentIsB { sync(["eoa": b.eoa, "phrase": ValidTestAccounts.phraseB]) }
			let versions = versionNames(syn.eoa); var before = storeHash()
			// wrong passcode
			XCTAssertEqual(result(sync(["eoa": syn.eoa, "cipher": e2, "passcode": syn.passcode]))["code"] as? String, "unlock_failed", "MS-42 wrong passcode")
			XCTAssertEqual(storeHash(), before)
			// right passcode, another derived address
			let foreign = envelope(phrase: ValidTestAccounts.phraseB, eoa: syn.eoa, passcode: "246810")
			XCTAssertEqual(result(sync(["eoa": syn.eoa, "cipher": foreign, "passcode": "246810"]))["code"] as? String, "verify_failed", "MS-42 derived address differs")
			XCTAssertEqual(storeHash(), before)
			// right passcode
			let answer = sync(["eoa": syn.eoa, "cipher": e2, "passcode": "246810"])
			if currentIsB { XCTAssertEqual(result(answer)["sync"] as? String, "updated", "MS-42: updated_switched when current was B") } else { assertOkUnlocked(answer, "MS-42") }
			let now = versionNames(syn.eoa)
			XCTAssertEqual(now.count, versions.count + 1, "MS-42: one version added"); XCTAssertTrue(versions.isSubset(of: now), "MS-42: E1 kept")
			XCTAssertEqual(currentCipherEoa(), syn.eoa, "MS-42: current points to the new version")
			XCTAssertTrue(BeamioCipherUnlock.isUnlocked(eoa: syn.eoa), "MS-42: the session is ready")
			before = storeHash()
			XCTAssertEqual(result(sync(["eoa": syn.eoa, "cipher": e2, "passcode": "246810"]))["code"] as? String, "ok", "MS-42: the same bytes again are idempotent")
			XCTAssertEqual(storeHash(), before)
		}
	}
}
#endif
