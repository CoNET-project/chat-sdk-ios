import XCTest
@testable import ConetChatSDK

/// The key-level check (10633, handover item 1): the native key, the keychain's account attribute and the page copy's EOA must be one account.
/// A mismatch refuses the signing (`key_account_mismatch`): nothing is signed, created, deleted or changed. Synthetic keys only.
final class KeyAccountLevelCheckTests: XCTestCase {
	/// An in-memory store whose account attributes can be set apart from its keys (the attribute is what the keychain names).
	final class OwnerStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var owners: [String]?
		/// true: the keychain cannot name its accounts (the listing fails, or a record has no attribute account).
		var unnamed = false
		/// The accounts whose key material was read. VR-19 ruling: the check never reads another account's key.
		var readAccounts: [String] = []
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { readAccounts.append(eoa.lowercased()); return keys[eoa.lowercased()] }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double lists the accounts it names.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		/// Accounts whose mnemonic item exists (valid) whatever the listing says: a record for the pointer's account that the listing does not name.
		var mnemonicStates: [String: BeamioMnemonicAccountState] = [:]
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState {
			if let forced = mnemonicStates[owner.lowercased()] { return forced }
			return (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent
		}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func enumerateKeyOwners() -> [String]? { unnamed ? nil : (owners ?? Array(keys.keys)) }
		/// Accounts whose key record is named but cannot be read (the storage-derived unreadable state).
		var unreadable: Set<String> = []
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState {
			let key = eoa.lowercased()
			if unreadable.contains(key) { return .unreadable }
			return keys[key] == nil ? .absent : .present
		}
	}

	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let keyHex = String(repeating: "11", count: 32)
	private let otherKeyHex = String(repeating: "22", count: 32)
	private let other = "0x0000000000000000000000000000000000000abc"
	private var store: OwnerStore!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = OwnerStore()
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.set(eoa)
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		BeamioKeyJudgementDiagnostics.reset()
	}

	override func tearDown() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	func testAMatchingKeyAccountSigns() {
		store.keys[eoa] = keyBytes(keyHex)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .matched)
		XCTAssertNotNil(try? BeamioNativeWallet.signEip191(eoa: eoa, message: "hello").get())
		XCTAssertEqual(BeamioKeyJudgementDiagnostics.qaSnapshot()?["keyAccountMismatches"], 0)
	}

	func testAKeyNamedForAnotherAccountRefusesSigning() {
		store.keys[eoa] = keyBytes(keyHex)
		store.owners = [other]                 // the listing names another account only
		store.mnemonicStates[eoa] = .valid     // while the pointer's account has a record: the device is G2 for it
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .mismatch)
		guard case .failure(.rejected("key_account_mismatch")) = BeamioNativeWallet.signEip191(eoa: eoa, message: "hello") else {
			return XCTFail("a key named for another account must be refused as key_account_mismatch")
		}
		XCTAssertEqual(BeamioKeyJudgementDiagnostics.qaSnapshot()?["keyAccountMismatches"], 1)
	}

	func testAKeyDerivingAnotherAddressRefusesSigning() {
		store.keys[eoa] = keyBytes(otherKeyHex)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2, "the refusal is judged at G2, not for want of a record")
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .mismatch)
		guard case .failure(.rejected("key_account_mismatch")) = BeamioNativeWallet.signEip191(eoa: eoa, message: "hello") else {
			return XCTFail("a key that derives another address must be refused as key_account_mismatch")
		}
		XCTAssertEqual(BeamioKeyJudgementDiagnostics.qaSnapshot()?["keyAccountMismatches"], 1)
	}

	func testAnUnnamedKeychainFailsClosed() {
		store.keys[eoa] = keyBytes(keyHex)
		store.unnamed = true
		store.mnemonicStates[eoa] = .valid     // the pointer's account has a record, the listing cannot be made: G2 for it, the check unknown
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .unknown)
		guard case .failure(.storageUnreadable) = BeamioNativeWallet.signEip191(eoa: eoa, message: "hello") else {
			return XCTFail("a keychain that cannot name its accounts must fail closed")
		}
	}

	func testNoKeyIsNotAMismatch() {
		store.owners = []
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .noKey)
		guard case .failure(.walletKeyMissing) = BeamioNativeWallet.signEip191(eoa: eoa, message: "hello") else {
			return XCTFail("no key stays walletKeyMissing, not a mismatch")
		}
		XCTAssertEqual(BeamioKeyJudgementDiagnostics.qaSnapshot()?["keyAccountMismatches"], 0)
	}

	/// VR-19 ruling (25.52Y.114 第 5 项, 25.52Y.14 第 6 项 (a)): with the pointer set, the pointer's account decides while another account's key is on the device.
	/// The other key is named, never read, never deleted or overwritten.
	func testPointerAccountDecidesWhileAnotherAccountsKeyIsOnTheDevice() {
		store.keys[eoa] = keyBytes(keyHex)
		store.keys[other] = keyBytes(otherKeyHex)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .matched)
		XCTAssertNotNil(try? BeamioNativeWallet.signEip191(eoa: eoa, message: "hello").get())
		XCTAssertNil(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"))
		XCTAssertFalse(store.readAccounts.contains(other), "the other account's key is never read")
		XCTAssertNotNil(store.keys[other], "the other account's key is not deleted or overwritten")
		XCTAssertEqual(BeamioKeyJudgementDiagnostics.qaSnapshot()?["keyAccountMismatches"], 0)
	}

	/// VR-19 ruling: with the pointer empty, several keys stay unknown (GZ.3): init answers not_ready and writes no pointer.
	func testPointerEmptyWithSeveralKeysIsNotReadyAndWritesNoPointer() {
		BeamioNativeAccountPointer.clear()
		store.keys[eoa] = keyBytes(keyHex)
		store.keys[other] = keyBytes(otherKeyHex)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .unknown)
		XCTAssertEqual(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"), "not_ready")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), "", "the check writes no pointer (GZ.3)")
	}

	/// VR-19 ruling: the pointer's own key missing fails closed (mismatch), and no other account's key is read to stand in for it.
	func testPointerAccountKeyMissingFailsClosed() {
		store.keys[other] = keyBytes(otherKeyHex)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .mismatch)
		XCTAssertEqual(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"), "needs_native_recovery")
		XCTAssertFalse(store.readAccounts.contains(other))
		XCTAssertNotNil(store.keys[other])
	}

	/// VR-19 ruling: the pointer's own key named but unreadable fails closed (unknown, not_ready, no signing).
	func testPointerAccountKeyUnreadableFailsClosed() {
		store.owners = [eoa, other]
		store.unreadable = [eoa]
		store.keys[other] = keyBytes(otherKeyHex)
		XCTAssertEqual(BeamioNativeWallet.verifyKeyAccount(eoa: eoa), .unknown)
		XCTAssertEqual(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"), "not_ready")
		guard case .failure(.storageUnreadable) = BeamioNativeWallet.signEip191(eoa: eoa, message: "hello") else {
			return XCTFail("an unreadable pointer key must fail closed")
		}
		XCTAssertFalse(store.readAccounts.contains(other))
	}

	/// Test helper: the bytes of a hex string (no prefix). The same shape as the helper of BeamioNativeWalletTests, which is private to that file.
	private func keyBytes(_ hex: String) -> Data {
		var out = Data()
		var i = hex.startIndex
		while i < hex.endIndex {
			let j = hex.index(i, offsetBy: 2)
			out.append(UInt8(hex[i ..< j], radix: 16)!)
			i = j
		}
		return out
	}

	/// The session-start decision (init and the no-page listen call this function). The init handler itself is not driven here.
	func testSessionStartRefusesAMismatchAsNativeRecovery() {
		store.keys[eoa] = keyBytes(keyHex)
		store.owners = [other]
		XCTAssertEqual(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"), "needs_native_recovery")
	}

	func testSessionStartFailsClosedWhenTheCheckIsUnknown() {
		store.keys[eoa] = keyBytes(keyHex)
		store.unnamed = true
		XCTAssertEqual(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"), "not_ready")
	}

	func testSessionStartProceedsOnAMatchAndWithNoKey() {
		store.keys[eoa] = keyBytes(keyHex)
		XCTAssertNil(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"))
		store.keys[eoa] = nil
		store.owners = []
		XCTAssertNil(BeamioNativeWallet.sessionStartRefusal(eoa: eoa, place: "test"))
	}
}
