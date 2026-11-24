import XCTest
@testable import ConetChatSDK

/// The passcode state of `pwaWalletSync` and `nativeMnemonicPreread` (finalized sections 5 and 6;): the v3 envelope is stored as sent, read back, and only then does
/// `current` move; with a passcode it is opened in memory only (vendored Argon2id); the preread returns the saved ciphertext as it is, with no passcode and no unlock. Synthetic fixture only.
final class MnemonicCipherSyncTests: XCTestCase {
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var nextSeq: Int64 = 2000
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var fixture: [String: Any] = [:]

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioPwaWalletSync.restartForTests()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		if let data = try? BundledVectorFile.data(resource: "mnemonic-cipher-format.v4"),
		   let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { fixture = root }
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private let passcode = "482913"
	private let eoa = "0xd49251e1e9f4d4d5bac808861fa4ce23053c986f"

	private func envelope(_ id: String) throws -> [String: Any] {
		let cases = try XCTUnwrap(fixture["cases"] as? [[String: Any]])
		let c = try XCTUnwrap(cases.first { ($0["id"] as? String ?? "").hasPrefix(id) }, id)
		return try XCTUnwrap(c["envelope"] as? [String: Any], id)
	}

	private func sync(_ fields: [String: Any], trusted: Bool = true) -> [String: Any] {
		nextSeq += 1
		var body: [String: Any] = ["type": "pwaWalletSync", "reqId": 1, "seq": NSNumber(value: nextSeq)]
		if trusted { body["trustedOrigin"] = true }
		for (k, v) in fields { body[k] = v }
		return BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)
	}

	private func preread() -> [String: Any]? {
		nextSeq += 1
		let body: [String: Any] = ["type": "nativeMnemonicPreread", "reqId": 2, "trustedOrigin": true, "seq": NSNumber(value: nextSeq)]
		BeamioPwaWalletSync.restartForTests()
		return BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false)["result"] as? [String: Any]
	}

	private func canonical(_ value: Any?) -> String {
		guard let value, let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return "nil" }
		return String(decoding: data, as: UTF8.self)
	}

	private func code(_ answer: [String: Any]) -> String? { (answer["result"] as? [String: Any])?["code"] as? String }

	/// no passcode: the envelope is stored as sent, read back, current moves; nothing is decrypted
	func testWithoutAPasscodeTheEnvelopeIsStoredAndReadBackAndNotDecrypted() throws {
		let e = try envelope("MCF3-01")
		let answer = sync(["cipher": e])
		let result = try XCTUnwrap(answer["result"] as? [String: Any])
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertEqual(result["stored"] as? Bool, true)
		XCTAssertEqual(result["readback"] as? String, "match", "readback is the string match, never a Boolean")
		XCTAssertEqual(result["decrypted"] as? Bool, false)
		XCTAssertTrue(store.rawAccounts.keys.contains(BeamioMnemonicSets.currentName))
		XCTAssertTrue(store.rawAccounts.keys.contains { $0.hasPrefix(BeamioMnemonicSets.setName(eoa) + ".c.") }, "a versioned cipher item under the new prefix")
		XCTAssertFalse(String(describing: store.rawAccounts.values.map { String(decoding: $0, as: UTF8.self) }).contains(passcode), "no passcode is stored")
	}

	/// PRR-02 and PRR-05: the ciphertext is returned as it is, without a passcode, without an unlock, and with no SDK session; the plaintext is not returned
	func testPRR02TheSavedCiphertextIsReturnedAsItIsWithoutAPasscodeOrASession() throws {
		let e = try envelope("MCF3-01")
		_ = sync(["cipher": e])
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		let result = try XCTUnwrap(preread())
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertEqual(canonical(result["cipher"]), canonical(e), "the envelope comes back as it was sent")
		XCTAssertNil(result["mnemonic"], "the passcode state never returns the plaintext")
		XCTAssertNil(result["notReadyReason"])
		XCTAssertNotEqual(result["code"] as? String, "passcode_not_provided", "no passcode gate")
	}

	/// the right passcode: the envelope is opened in memory (decrypted true) and stored
	func testTheRightPasscodeOpensTheEnvelopeInMemoryAndStoresIt() throws {
		let answer = sync(["cipher": try envelope("MCF3-01"), "passcode": passcode])
		let result = try XCTUnwrap(answer["result"] as? [String: Any])
		XCTAssertEqual(result["code"] as? String, "ok")
		XCTAssertEqual(result["decrypted"] as? Bool, true)
		XCTAssertEqual(result["stored"] as? Bool, true)
		XCTAssertEqual(result["readback"] as? String, "match", "readback is the string match, never a Boolean")
		let text = String(describing: store.rawAccounts.values.map { String(decoding: $0, as: UTF8.self) })
		XCTAssertFalse(text.contains(passcode), "the passcode is not stored")
		XCTAssertFalse(text.contains("fog spot notable"), "the plaintext is not stored")
	}

	/// the closed set: a wrong passcode and a tampered ciphertext are unlock_failed; a shape problem is bad_request; an address problem is verify_failed; none of them writes
	func testTheFailuresAnswerTheClosedSetAndWriteNothing() throws {
		var before = store.rawAccounts
		XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-01"), "passcode": "000000"])), "unlock_failed", "a wrong passcode")
		XCTAssertEqual(store.rawAccounts, before)
		XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-03"), "passcode": passcode])), "unlock_failed", "a tampered ciphertext")
		XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-06"), "passcode": passcode])), "unlock_failed", "the AAD bound to another eoa")
		XCTAssertEqual(store.rawAccounts, before)
		// the shape is judged first (M6 v3.2): version 2 is a bad_request, before any decryption, even without a passcode
		XCTAssertEqual(sync(["cipher": try envelope("MCF3-04")])["error"] as? String, "bad_request", "version 2")
		XCTAssertEqual(sync(["cipher": try envelope("MCF3-04"), "passcode": passcode])["error"] as? String, "bad_request")
		XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-05"), "passcode": passcode])), "verify_failed", "the derived address is not the envelope's")
		XCTAssertEqual(store.rawAccounts, before, "nothing was written by any failure")
		// no retry count and no cooldown: many wrong passcodes are each unlock_failed, and the right one then opens at once
		for _ in 0..<5 { XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-01"), "passcode": "111111"])), "unlock_failed") }
		XCTAssertEqual((sync(["cipher": try envelope("MCF3-01"), "passcode": passcode])["result"] as? [String: Any])?["decrypted"] as? Bool, true)
		before = store.rawAccounts
		XCTAssertFalse(before.isEmpty)
	}

	/// the same bytes are idempotent; another envelope of the same address without a passcode cannot be verified and is refused (M6 v3.3: bad_request, nothing written, current unchanged)
	func testTheSameBytesAreIdempotentAndOtherBytesWithoutAPasscodeAreRefused() throws {
		let e = try envelope("MCF3-01")
		_ = sync(["cipher": e])
		let first = store.rawAccounts
		_ = sync(["cipher": e])
		XCTAssertEqual(store.rawAccounts, first, "the same bytes change nothing")
		var other = e
		other["iv"] = Data(repeating: 9, count: 12).base64EncodedString()
		XCTAssertEqual(sync(["cipher": other])["error"] as? String, "bad_request")
		XCTAssertEqual(store.rawAccounts, first, "nothing was written, no version added, current unchanged")
		XCTAssertEqual(canonical(try XCTUnwrap(preread())["cipher"]), canonical(e), "current is still the first version")
	}

	/// a plaintext set and a cipher version of the same mnemonic are separate until the version is stored and named: then the plaintext set of the account is deleted silently (a cleanup
	/// record stays), the answer is the cipher only, and a plaintext phrase never replaces the envelope
	func testPlaintextAndCipherVersionsCoexistAndAPlaintextPhraseDoesNotReplaceTheEnvelope() throws {
		let fog = "fog spot notable regret pizza coffee harvest ensure fog spot notable reflect"
		XCTAssertEqual((sync(["phrase": fog])["result"] as? [String: Any])?["sync"] as? String, "updated")
		let plain = try XCTUnwrap(preread())
		XCTAssertEqual(plain["code"] as? String, "ok")
		XCTAssertEqual(plain["mnemonic"] as? String, fog)
		XCTAssertNotNil(store.rawAccounts[BeamioMnemonicSets.setName(eoa)], "the plaintext set exists before the passcode state")
		XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-01")])), "ok")
		let now = try XCTUnwrap(preread())
		XCTAssertNotNil(now["cipher"], "current is now the passcode state")
		XCTAssertNil(now["mnemonic"])
		XCTAssertNil(store.rawAccounts[BeamioMnemonicSets.setName(eoa)], "the plaintext set is deleted once the passcode state holds the account")
		XCTAssertNotNil(store.rawAccounts[BeamioMnemonicSets.retireName(eoa)], "the cleanup record stays")
		// method Y: a plaintext phrase never replaces the v3 envelope of the same account; the record stays the envelope and nothing is written
		let before = store.rawAccounts
		XCTAssertEqual((sync(["phrase": fog])["result"] as? [String: Any])?["sync"] as? String, "unchanged", "the envelope is not replaced by the plaintext set")
		XCTAssertEqual(store.rawAccounts, before, "nothing is written")
		XCTAssertNotNil(try XCTUnwrap(preread())["cipher"], "current is still the passcode state")
		XCTAssertTrue(store.rawAccounts.keys.contains { $0.contains(".c.") }, "the cipher version stays")
	}

	/// a different address (the envelope's eoa differs from the current one) is a change of account: the new set is written first, current moves second, the old stays
	func testAnEnvelopeOfAnotherAddressIsAChangeOfAccount() throws {
		_ = sync(["phrase": phraseA])
		let aSet = store.rawAccounts[BeamioMnemonicSets.setName(BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!.eoa)]
		XCTAssertEqual(code(sync(["cipher": try envelope("MCF3-01")])), "ok")
		XCTAssertNotNil(try XCTUnwrap(preread())["cipher"])
		XCTAssertEqual(store.rawAccounts[BeamioMnemonicSets.setName(BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!.eoa)], aSet, "the first account's set is kept")
	}

	/// a failed write leaves current and the older versions as they were
	func testAFailedCipherWriteLeavesCurrentAsItWas() throws {
		let e = try envelope("MCF3-01")
		_ = sync(["phrase": phraseA])
		let before = store.rawAccounts
		store.failRawWriteContaining = "\"mode\":\"cipher\""
		let answer = sync(["cipher": e])
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "write_failed")
		XCTAssertEqual(store.rawAccounts, before, "nothing changed")
		XCTAssertEqual(try XCTUnwrap(preread())["mnemonic"] as? String, phraseA, "current is still the first mnemonic")
	}

	/// trustedOrigin is filled by the shell only: a value the page puts in is not trusted, and a missing or false value is refused before anything is read or written
	func testTheTrustedOriginMustBeTrueOrTheCommandIsRefusedBeforeAnyReadOrWrite() throws {
		let e = try envelope("MCF3-01")
		let before = store.rawAccounts
		let missing = sync(["cipher": e], trusted: false)
		XCTAssertEqual(missing["error"] as? String, "untrusted_source")
		let explicitFalse = sync(["cipher": e, "trustedOrigin": false])
		XCTAssertEqual(explicitFalse["error"] as? String, "untrusted_source")
		let phraseUntrusted = sync(["phrase": phraseA], trusted: false)
		XCTAssertEqual(phraseUntrusted["error"] as? String, "untrusted_source")
		let notABool = sync(["cipher": e, "trustedOrigin": "true"])
		XCTAssertEqual(notABool["error"] as? String, "untrusted_source", "only the Boolean true counts")
		XCTAssertEqual(store.rawAccounts, before, "nothing was read into or written to the store")
		XCTAssertNil(missing["result"])
		let read = BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 3, "seq": NSNumber(value: Int64(5000))], snapshotKnown: true, storageLocked: false)
		XCTAssertEqual(read["error"] as? String, "untrusted_source", "the preread is refused the same way")
	}

	/// the credential fields: cipher and passcode are the fields of this state; any other credential field is refused; a phrase together with a cipher is a bad request
	func testCredentialFieldsAndShapes() throws {
		let e = try envelope("MCF3-01")
		XCTAssertEqual(sync(["cipher": e, "privateKeyArmor": "x"])["error"] as? String, "key_over_bridge_refused")
		XCTAssertEqual(sync(["cipher": e, "mnemonicPhrase": "x"])["error"] as? String, "key_over_bridge_refused")
		XCTAssertEqual(sync(["cipher": e, "phrase": phraseA])["error"] as? String, "bad_request")
		XCTAssertEqual(sync(["cipher": e, "passcode": 482913])["error"] as? String, "bad_request", "a passcode that is not a string")
		XCTAssertEqual(sync(["cipher": "not an object"])["error"] as? String, "bad_request")
		XCTAssertTrue(store.rawAccounts.isEmpty)
	}

	/// the new code logs nothing: no NSLog or print in the cipher and set files
	func testTheCipherAndSetSourcesNeverLog() throws {
		let dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources/ConetChatSDK")
		for name in ["BeamioMnemonicCipherV3.swift", "BeamioMnemonicSets.swift", "BeamioArgon2id.swift"] {
			let text = try String(contentsOf: dir.appendingPathComponent(name), encoding: .utf8)
			XCTAssertFalse(text.contains("NSLog("), "\(name) has no NSLog")
			XCTAssertFalse(text.contains("print("), "\(name) has no print")
			XCTAssertFalse(text.contains("os_log"), "\(name) has no os_log")
		}
	}

	/// the conversion after a passcode is set or changed: the first sync carries the passcode and answers decrypted:true; a later sync without it only stores and answers decrypted:false
	func testTheFirstSyncAfterASetCarriesThePasscodeAndALaterOneDoesNot() throws {
		let e = try envelope("MCF3-01")
		let first = try XCTUnwrap(sync(["cipher": e, "passcode": passcode])["result"] as? [String: Any])
		XCTAssertEqual(first["decrypted"] as? Bool, true, "the conversion is complete when the shell decrypted and checked the address")
		let later = try XCTUnwrap(sync(["cipher": e])["result"] as? [String: Any])
		XCTAssertEqual(later["code"] as? String, "ok")
		XCTAssertEqual(later["decrypted"] as? Bool, false, "without a passcode the SDK only stores")
		XCTAssertEqual(later["readback"] as? String, "match")
	}

	/// MS-R1 on the ciphertext branch: when the `current` pointer cannot be read, saveCipher writes nothing and deletes nothing: before and after are byte for byte the same.
	func testMSR1ACipherSaveThatCannotReadTheCurrentPointerWritesNothing() throws {
		let e = try envelope("MCF3-01")
		XCTAssertEqual(try XCTUnwrap(sync(["cipher": e])["result"] as? [String: Any])["code"] as? String, "ok", "the first envelope is stored and current")
		let rawBefore = store.rawAccounts, keysBefore = store.keys
		// a different envelope of the same account (a new version) while the pointer is unreadable
		let other = try envelope("MCF3-02")
		store.failRawReadAccounts.insert(BeamioMnemonicSets.currentName)
		BeamioPwaWalletSync.restartForTests()
		let answer = sync(["cipher": other])
		XCTAssertEqual(answer["ok"] as? Bool, false, "a read fault is reported, never success")
		XCTAssertEqual(store.rawAccounts, rawBefore, "MS-R1: nothing is written, nothing is deleted (bytes before and after are equal)")
		XCTAssertEqual(store.keys, keysBefore)
		// and straight on the store layer, without the command path
		guard let parsed = BeamioMnemonicCipherV3.parse(other) else { return XCTFail("the envelope parses") }
		guard case .failed = BeamioMnemonicSets.saveCipher(envelope: parsed, store: store, utc: "x") else { return XCTFail("saveCipher reports the read fault") }
		XCTAssertEqual(store.rawAccounts, rawBefore)
	}
}
