import XCTest
@testable import ConetChatSDK

/// walletState (; additive to `passcodeStatus`,): the rules of the resolver, and the wiring of the field into `passcodeStatus`.
/// The product store cannot be enumerated in the simulator (no Keychain entitlement), so the wiring uses the memory store, whose enumeration checks each key
/// the way the product store checks one.
final class NativeWalletStateTests: XCTestCase {
	private let a = "0x1111111111111111111111111111111111111111"
	private let b = "0x2222222222222222222222222222222222222222"
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedDefaults: BeamioDefaultsStoring!
	private var suite: BeamioDefaultsStoring!

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		savedDefaults = BeamioNativeAccountPointer.defaults
		suite = BeamioMemoryDefaults()
		BeamioNativeAccountPointer.defaults = suite
		BeamioNativeAccountPointer.clear()
	}

	override func tearDown() {
		BeamioNativeAccountPointer.clear()
		BeamioNativeAccountPointer.defaults = savedDefaults
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func resolve(pointer: String = "", _ entries: [BeamioChatKeyEntryCheck]?) -> (state: BeamioNativeWalletState, account: String?) {
		BeamioNativeWalletStateResolver.resolve(pointer: pointer, entries: entries)
	}

	// MARK: Pointer empty

	func testAnEmptyEnumerationWithNoPointerIsAbsent() {
		let r = resolve([])
		XCTAssertEqual(r.state, .absent)
		XCTAssertNil(r.account)
	}

	/// AD-17 (state): the pointer is empty and exactly one valid key is stored: present, for that account.
	func testOneValidKeyWithNoPointerIsPresent() {
		let r = resolve([.valid(eoa: a)])
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, a)
	}

	/// AD-18: the pointer is empty and two accounts' keys are stored: not_ready, and no key is chosen.
	func testTwoKeysWithNoPointerAreNotReady() {
		let r = resolve([.valid(eoa: a), .valid(eoa: b)])
		XCTAssertEqual(r.state, .notReady)
		XCTAssertNil(r.account)
	}

	/// a per-account record and a legacy record at one address are one key.
	func testTheSameAddressTwiceIsOneKey() {
		let r = resolve([.valid(eoa: a), .valid(eoa: a)])
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, a)
	}

	/// An entry that cannot be read now makes the enumeration incomplete: unavailable, never absent.
	func testAnUnavailableEntryMakesTheEnumerationUnavailable() {
		XCTAssertEqual(resolve([.valid(eoa: a), .unavailable]).state, .unavailable)
		XCTAssertEqual(resolve([.unavailable]).state, .unavailable)
	}

	/// An enumeration that cannot be completed is not_ready, never absent (walletstate-vectors AD-06).
	func testAnEnumerationThatCannotBeCompletedIsNotReady() {
		let r = resolve(nil)
		XCTAssertEqual(r.state, .notReady)
		XCTAssertNil(r.account)
	}

	/// A record that is listed and cannot be used is corrupt, not absent.
	func testCorruptOnlyIsCorruptNotAbsent() {
		XCTAssertEqual(resolve([.corrupt]).state, .corrupt)
	}

	/// A corrupt record is not a key: beside one valid key the state is present (: exactly one valid key).
	func testAValidKeyBesideACorruptOneIsPresent() {
		let r = resolve([.valid(eoa: a), .corrupt])
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, a)
	}

	/// A passcode record whose passcode is locked is locked, for that account.
	func testALockedKeyIsLocked() {
		let r = resolve([.locked(eoa: a)])
		XCTAssertEqual(r.state, .locked)
		XCTAssertEqual(r.account, a)
	}

	// MARK: Pointer set (: the pointer's record decides, and must agree with the enumeration)

	func testAPointerWithItsOwnKeyIsPresent() {
		let r = resolve(pointer: a, [.valid(eoa: a)])
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, a)
	}

	func testAPointerWithItsLockedKeyIsLocked() {
		let r = resolve(pointer: a, [.locked(eoa: a)])
		XCTAssertEqual(r.state, .locked)
		XCTAssertEqual(r.account, a)
	}

	/// item 3: with no native key, a page copy that holds the account's EOA key is present, whatever the migration
	/// state; a pending or failed migration keeps it and it is never absent.
	func testAPageCopyWithAKeyIsThePresentOverlayWhenNoNativeKeyExists() {
		let r = BeamioNativeWalletStateResolver.resolve(pointer: "", entries: [], pageCopyKey: a)
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, a)
	}

	/// The overlay does not decide while a native key exists: the native key decides (AD-34 third step).
	func testTheOverlayDoesNotOverrideANativeKey() {
		let r = BeamioNativeWalletStateResolver.resolve(pointer: "", entries: [.valid(eoa: b)], pageCopyKey: a)
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, b)
	}

	/// A pointer that names another account than the copy's does not take the copy: not_ready, no fallback (item 6(b)).
	func testAnOverlayDoesNotTakeAPointerOfAnotherAccount() {
		let r = BeamioNativeWalletStateResolver.resolve(pointer: b, entries: [], pageCopyKey: a)
		XCTAssertEqual(r.state, .notReady)
		XCTAssertNil(r.account)
	}

	/// An enumeration that cannot be completed stays not_ready, even with a page copy present (the overlay is judged after the enumeration).
	func testAnOverlayDoesNotHideAnUnfinishedEnumeration() {
		let r = BeamioNativeWalletStateResolver.resolve(pointer: "", entries: nil, pageCopyKey: a)
		XCTAssertEqual(r.state, .notReady)
	}

	/// A pointer with no key of its account is not_ready, with no fallback to the enumeration (item 6(b), AD-27).
	func testAPointerWithNoKeyIsNotReady() {
		let r = resolve(pointer: a, [])
		XCTAssertEqual(r.state, .notReady)
		XCTAssertNil(r.account)
	}

	/// The pointer names one account and the store holds another's key: the records disagree, not_ready (never deleted or rewritten).
	func testAPointerWithAnotherAccountsKeyIsNotReady() {
		let r = resolve(pointer: a, [.valid(eoa: b)])
		XCTAssertEqual(r.state, .notReady)
		XCTAssertNil(r.account)
	}

	/// The pointer's own key decides even with another key on the device (item 6(a), AD-26, AD-28).
	func testAPointerWithItsKeyAndAnotherIsPresent() {
		let r = resolve(pointer: a, [.valid(eoa: a), .valid(eoa: b)])
		XCTAssertEqual(r.state, .present)
		XCTAssertEqual(r.account, a)
	}

	/// A corrupt record cannot be attributed to the pointer's account: not_ready, never absent.
	func testAPointerWithACorruptRecordIsNotReady() {
		XCTAssertEqual(resolve(pointer: a, [.corrupt]).state, .notReady)
	}

	// MARK: Legacy key field (; the rule of the store, 4042c16)

	func testTheLegacyKeyNeedsSixtyFourHexDigits() {
		let sixtyFour = String(repeating: "11", count: 32)
		XCTAssertEqual(BeamioChatWalletKeychainStore.legacyKeyBytes(sixtyFour)?.count, 32)
		XCTAssertEqual(BeamioChatWalletKeychainStore.legacyKeyBytes("0x" + sixtyFour)?.count, 32)
		XCTAssertNil(BeamioChatWalletKeychainStore.legacyKeyBytes(String(repeating: "11", count: 31)))
		XCTAssertNil(BeamioChatWalletKeychainStore.legacyKeyBytes(String(repeating: "zz", count: 32)))
		XCTAssertNil(BeamioChatWalletKeychainStore.legacyKeyBytes(nil))
	}

	// MARK: passcodeStatus wiring (AD-16)

	/// `passcodeStatus` keeps its three fields and adds `walletState`, with no key material.
	func testPasscodeStatusAddsTheWalletStateAndNoMaterial() {
		// a valid account (its key and the mnemonic that derives it): a key alone is no account since Y.163 items 31 and 32, and its walletState is absent
		let store = MemoryNativeKeyStore()
		let eoa = ValidTestAccounts.install(store).eoa
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.set(eoa)
		let result = passcodeStatus()
		XCTAssertEqual(Set(result.keys), ["set", "locked", "hasKey", "walletState", "nativeLocked"])
		XCTAssertEqual(result["walletState"] as? String, "present")
		XCTAssertEqual(result["hasKey"] as? Bool, true)
	}

	/// No pointer and no key: absent, and hasKey is false.
	func testPasscodeStatusWithNoKeyIsAbsent() {
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		let result = passcodeStatus()
		XCTAssertEqual(result["walletState"] as? String, "absent")
		XCTAssertEqual(result["hasKey"] as? Bool, false)
	}

	private func passcodeStatus() -> [String: Any] {
		var result: [String: Any] = [:]
		let done = expectation(description: "passcodeStatus ack")
		BeamioConetChatModule.chatModuleCommand(["type": "passcodeStatus", "reqId": 7], emit: { event in
			guard let inner = event["event"] as? [String: Any], inner["type"] as? String == "ack" else { return }
			result = inner["result"] as? [String: Any] ?? [:]
			done.fulfill()
		})
		wait(for: [done], timeout: 5)
		return result
	}
}
