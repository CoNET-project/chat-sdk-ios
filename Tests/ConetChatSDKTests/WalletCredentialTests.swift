#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// walletCredential: the request checks in order, the get answer with its blob, and the unseal
/// answer. The capability is declared by the test seam (the QA list is compiled only under BEAMIO_QA_BUILD). The blob key lives in the test
/// host's Keychain under its own account name, and is deleted after each test. Synthetic data only.
final class WalletCredentialTests: XCTestCase {
	/// Two BIP-39 test vectors: the phrase and its account.
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var account = ""
	private var savedNativeStore: BeamioChatWalletKeyStoring?

	/// The blob key lives in the Keychain. In a SwiftPM test host without the keychain entitlement the Keychain refuses writes (SecItemAdd returns
	/// errSecMissingEntitlement, -34018, as the production-store tests record); those tests skip there and run on a host that can write.
	override func setUpWithError() throws {
		try super.setUpWithError()
		let probe = "0x00000000000000000000000000000000000000ff"
		let writable = BeamioWalletCredentialBlob.createIfMissing(eoa: probe)
		_ = BeamioWalletCredentialBlob.delete(eoa: probe)
		try XCTSkipUnless(writable, "the Keychain cannot be written in this test host (errSecMissingEntitlement, -34018): the blob key needs a keychain-entitled host")
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let eoa = BeamioNativeEthSigner.address(privateKey: derived)
		else { fatalError("the test vector does not derive") }
		account = eoa.lowercased()
		let items = MnemonicIntentStorageTests.MemStore()
		_ = items.writeItem(.key, eoa: account, value: Data(derived))
		_ = items.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		// A mnemonic needs its commit (a mnemonic without commit or intent is a corruption, (k)(4)).
		_ = items.writeItem(.commit, eoa: account, value: Data("{\"v\":1,\"eoa\":\"\(account)\",\"committedAt\":\"2026-11-15T06:00:00Z\"}".utf8))
		savedNativeStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = items
		BeamioNativeAccountPointer.set(account)
		BeamioWindowWallet.declaredOverride = true
	}

	override func tearDown() {
		deleteBlobKey()
		BeamioWindowWallet.declaredOverride = nil
		BeamioNativeAccountPointer.clear()
		BeamioNativeWallet.keyStore = savedNativeStore ?? BeamioPasscodeWalletStore.standard
		super.tearDown()
	}

	private func deleteBlobKey() {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: BeamioWalletCredentialBlob.service,
			kSecAttrAccount as String: "blobKey:" + account,
		]
		SecItemDelete(query as CFDictionary)
	}

	private func call(_ body: [String: Any], trust: WindowTrust = .trusted) -> [String: Any] {
		var out: [String: Any] = [:]
		BeamioWindowWallet.walletCredential(body, trust: trust) { out = $0 }
		return out
	}

	/// order: an untrusted call is not_trusted before anything else.
	/// Y.44 第 4 项 (r3rz): an origin or frame mismatch is origin_refused; a package or capability failure is not_trusted.
	func testAnUntrustedOriginIsOriginRefused() {
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9401], trust: .originRefused)["error"] as? String, "origin_refused")
	}

	func testAPackageFailureIsNotTrusted() {
		var out: [String: Any] = [:]
		BeamioWindowWallet.walletCredential(["type": "walletCredential", "reqId": 9402], trust: .notTrusted) { out = $0 }
		XCTAssertEqual(out["error"] as? String, "not_trusted")
	}

	/// order: a reqId that is not legal is bad_request with reqId null.
	func testAnIllegalReqIdIsBadRequestWithNullReqId() {
		let out = call(["type": "walletCredential"])
		XCTAssertEqual(out["error"] as? String, "bad_request")
		XCTAssertTrue(out["reqId"] is NSNull)
	}

	/// without the declared capability the answer is not_trusted, and the Keychain is not read.
	func testWithoutTheCapabilityItIsNotTrusted() {
		BeamioWindowWallet.declaredOverride = false
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9402])["error"] as? String, "not_trusted")
	}

	/// 第 4 項: a key-shaped field name is key_over_bridge_refused, before any other check.
	func testAKeyShapedFieldIsRefused() {
		for name in ["mnemonic", "mnemonicPhrase", "privateKeyArmor", "eoaPrivateKey", "pgpPassphrase"] {
			XCTAssertEqual(call(["type": "walletCredential", "reqId": 9403, name: "x"])["error"] as? String, "key_over_bridge_refused", name)
		}
	}

	/// 第 1、3 项: an other field is bad_request; mode other than "unseal", a mode without a blob, and a blob that is not a string are bad_request.
	func testOtherFieldsAndAnInvalidModeAreBadRequest() {
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9404, "extra": 1])["error"] as? String, "bad_request")
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9405, "mode": "seal", "blob": "00"])["error"] as? String, "bad_request")
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9406, "mode": "unseal"])["error"] as? String, "bad_request")
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9407, "blob": "00"])["error"] as? String, "bad_request")
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9408, "mode": "unseal", "blob": 5])["error"] as? String, "bad_request")
	}

	private func blobKeyPresent() -> Bool {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: BeamioWalletCredentialBlob.service,
			kSecAttrAccount as String: "blobKey:" + account,
		]
		return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
	}

	/// /: K follows the mnemonic record. It is created with the mnemonic write, and removed with the mnemonic record or the account's clear.
	func testTheBlobKeyFollowsTheMnemonicRecord() {
		let store = BeamioChatWalletKeychainStore.standard
		defer { _ = store.deleteItem(.mnemonic, eoa: account); _ = store.deleteItem(.key, eoa: account) }
		_ = store.deleteItem(.mnemonic, eoa: account)
		XCTAssertFalse(blobKeyPresent(), "no key before the mnemonic")
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8)))
		XCTAssertTrue(blobKeyPresent(), "the key is created with the mnemonic record")
		XCTAssertTrue(store.deleteItem(.mnemonic, eoa: account))
		XCTAssertFalse(blobKeyPresent(), "the key is removed with the mnemonic record")
		_ = store.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		XCTAssertTrue(blobKeyPresent())
		_ = store.clearWalletItems(eoa: account)
		XCTAssertFalse(blobKeyPresent(), "the key is removed when the account is cleared")
	}

	/// upgrade path: an account whose mnemonic exists but whose K does not gets K at the first walletCredential, in the same call.
	func testAnUpgradedAccountGetsItsKeyAtTheFirstCredentialRead() {
		XCTAssertFalse(blobKeyPresent(), "no K before the first read")
		let out = call(["type": "walletCredential", "reqId": 9420])
		XCTAssertEqual(out["ok"] as? Bool, true)
		XCTAssertTrue(blobKeyPresent(), "K is created by the read")
	}

	/// /: a key-only account (no mnemonic record) gets no K and answers unavailable (no orphan K).
	func testNoMnemonicMeansNoKeyAndUnavailable() {
		let items = MnemonicIntentStorageTests.MemStore()
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		_ = items.writeItem(.key, eoa: account, value: Data(derived))
		BeamioNativeWallet.keyStore = items
		XCTAssertEqual(call(["type": "walletCredential", "reqId": 9421])["error"] as? String, "unavailable")
		XCTAssertFalse(blobKeyPresent(), "no K without a mnemonic record")
	}

	/// clearing the account removes its mnemonic record, its K, and its key item.
	func testAccountDeletionRemovesMnemonicKeyAndKey() {
		let store = BeamioChatWalletKeychainStore.standard
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		_ = store.writeItem(.key, eoa: account, value: Data(derived))
		_ = store.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		XCTAssertTrue(blobKeyPresent())
		XCTAssertTrue(store.clearWalletItems(eoa: account), "every step is ok")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: account), .absent)
		XCTAssertEqual(store.itemState(.key, eoa: account), .present, "the published walletKey item is never deleted by clearWalletItems")
		XCTAssertFalse(blobKeyPresent())
	}

	/// the rollback of a key write removes the key item only; the mnemonic and K of the account stay.
	func testTheKeyRollbackKeepsTheMnemonicAndK() {
		let store = BeamioChatWalletKeychainStore.standard
		defer { _ = store.clearWalletItems(eoa: account) }
		_ = store.clearWalletItems(eoa: account)
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		_ = store.writeItem(.key, eoa: account, value: Data(derived))
		_ = store.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		store.delete(eoa: account)
		XCTAssertEqual(store.itemState(.key, eoa: account), .absent, "the key item is removed")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: account), .present, "the mnemonic stays")
		XCTAssertTrue(blobKeyPresent(), "K stays")
	}

	/// /: when K cannot be made, the mnemonic write fails as a whole and no mnemonic record is left without K.
	func testAFailedKeyCreationLeavesNoMnemonicRecord() {
		let store = BeamioChatWalletKeychainStore.standard
		defer { _ = store.clearWalletItems(eoa: account); BeamioWalletCredentialBlob.failCreationForTests = false }
		_ = store.clearWalletItems(eoa: account)
		BeamioWalletCredentialBlob.failCreationForTests = true
		XCTAssertFalse(store.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8)), "the write fails")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: account), .absent, "no mnemonic record")
		XCTAssertFalse(blobKeyPresent(), "no K")
	}

	/// 2: a failed step of the wallet clear is reported as a failure, every step is still tried, and nothing is reported as cleared.
	func testAFailedWalletClearStepIsReportedAsAFailure() {
		let store = BeamioChatWalletKeychainStore.standard
		defer { BeamioChatWalletKeychainStore.clearFailStepForTests = nil; _ = store.clearWalletItems(eoa: account) }
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		_ = store.writeItem(.key, eoa: account, value: Data(derived))
		_ = store.writeItem(.mnemonic, eoa: account, value: Data(phrase.utf8))
		BeamioChatWalletKeychainStore.clearFailStepForTests = "blobKey"
		XCTAssertFalse(store.clearWalletItems(eoa: account), "a failed step is a failed clear")
		XCTAssertEqual(store.itemState(.mnemonic, eoa: account), .absent, "the other steps are still tried")
		XCTAssertEqual(store.itemState(.key, eoa: account), .present, "the key item is kept")
		BeamioChatWalletKeychainStore.clearFailStepForTests = nil
		XCTAssertTrue(store.clearWalletItems(eoa: account), "a retry completes the clear")
	}

	/// the get answer carries eoa, credentialKind mnemonic, the phrase and the blob; the blob is hex and is not the phrase.
	func testTheGetAnswerCarriesThePhraseAndAHexBlob() {
		let out = call(["type": "walletCredential", "reqId": 9409])
		XCTAssertEqual(out["ok"] as? Bool, true)
		let result = out["result"] as? [String: Any]
		XCTAssertEqual(result?["eoa"] as? String, account)
		XCTAssertEqual(result?["credentialKind"] as? String, "mnemonic")
		XCTAssertEqual(result?["mnemonic"] as? String, phrase)
		let blob = result?["blob"] as? String ?? ""
		XCTAssertFalse(blob.isEmpty)
		XCTAssertNotEqual(blob, phrase)
		XCTAssertNotNil(BeamioWalletCredentialBlob.dataFromHex(blob), "the blob is hex")
		XCTAssertNil(result?["eoaPrivateKey"], "no private key field")
	}

	/// an unseal of the blob returns the phrase without a blob, and the same eoa.
	func testUnsealReturnsThePhraseWithoutABlob() {
		let blob = (call(["type": "walletCredential", "reqId": 9410])["result"] as? [String: Any])?["blob"] as? String ?? ""
		let out = call(["type": "walletCredential", "reqId": 9411, "mode": "unseal", "blob": blob])
		XCTAssertEqual(out["ok"] as? Bool, true)
		let result = out["result"] as? [String: Any]
		XCTAssertEqual(result?["mnemonic"] as? String, phrase)
		XCTAssertEqual(result?["eoa"] as? String, account)
		XCTAssertNil(result?["blob"], "an unseal answer carries no blob")
	}

	/// a blob that does not open, or a blob of another account, is unavailable.
	func testAnUnopenableBlobIsUnavailable() {
		let got = call(["type": "walletCredential", "reqId": 9412])
		XCTAssertEqual(got["ok"] as? Bool, true, "the get answer is ok: \(got["error"] ?? "")")
		let blob = (got["result"] as? [String: Any])?["blob"] as? String ?? ""
		guard !blob.isEmpty else { return }
		var tampered = Array(blob)
		tampered[tampered.count - 1] = tampered.last == "0" ? "1" : "0"
		let out = call(["type": "walletCredential", "reqId": 9413, "mode": "unseal", "blob": String(tampered)])
		XCTAssertEqual(out["error"] as? String, "unavailable")
		XCTAssertNil(out["result"])
	}

	/// 第 6 項 and (b): an account without a stored phrase (a key-only account) answers unavailable and no key.
	func testAKeyOnlyAccountAnswersUnavailableWithNoKey() {
		let items = MnemonicIntentStorageTests.MemStore()
		guard case .key(let derived) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return XCTFail() }
		_ = items.writeItem(.key, eoa: account, value: Data(derived))
		BeamioNativeWallet.keyStore = items
		let out = call(["type": "walletCredential", "reqId": 9414])
		XCTAssertEqual(out["error"] as? String, "unavailable")
		XCTAssertNil(out["result"])
	}

	/// The blob key is per account and is created once: a second get keeps the same key, so the first blob still opens.
	func testTheBlobKeyIsStableForTheAccount() {
		let first = (call(["type": "walletCredential", "reqId": 9415])["result"] as? [String: Any])?["blob"] as? String ?? ""
		let second = (call(["type": "walletCredential", "reqId": 9416])["result"] as? [String: Any])?["blob"] as? String ?? ""
		XCTAssertNotEqual(first, second, "each blob has a fresh nonce")
		let opened = call(["type": "walletCredential", "reqId": 9417, "mode": "unseal", "blob": first])
		XCTAssertEqual((opened["result"] as? [String: Any])?["mnemonic"] as? String, phrase)
	}
}
#endif
#if BEAMIO_TEST_HOOKS
// Test build only: this file's Keychain calls are answered from the test store (BeamioTestKeychainStore), never the real Keychain.
fileprivate func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.copyMatching(query, result)
}
fileprivate func SecItemDelete(_ query: CFDictionary) -> OSStatus {
	BeamioTestKeychainStore.delete(query)
}
#endif
