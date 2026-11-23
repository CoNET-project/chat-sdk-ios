import XCTest
@testable import ConetChatSDK

/// The production state probe of a wallet key record (iOS review 2026-11-17, condition b): the Keychain query suppresses the authentication UI and
/// reads attributes only, and every status other than "found" or "not found" is unreadable. The simulator test host has no Keychain entitlement, so
/// the query and the mapping are tested directly; the production branch is the probe followed by `readWithoutUI`. No Keychain item is touched.
final class KeychainStateProbeTests: XCTestCase {
	private let store = BeamioChatWalletKeychainStore(service: "keychain-state-probe-test")

	func testTheProbeQueryNeverPromptsAndReadsNoValue() {
		let query = store.stateProbeQuery(account: "walletKey:0x9858effd232b4033e47d90003d41ec34ecaeda94")
		XCTAssertEqual(query[kSecUseAuthenticationUI as String] as? String, kSecUseAuthenticationUIFail as String,
		               "the probe fails instead of prompting")
		XCTAssertEqual(query[kSecReturnAttributes as String] as? Bool, true, "attributes only")
		XCTAssertNil(query[kSecReturnData as String], "the probe never returns the value")
		XCTAssertEqual(query[kSecMatchLimit as String] as? String, kSecMatchLimitOne as String, "at most one item")
		XCTAssertEqual(query[kSecAttrService as String] as? String, "keychain-state-probe-test")
	}

	func testTheProbeMapsEveryStatus() {
		XCTAssertNil(BeamioChatWalletKeychainStore.probeAnswer(errSecSuccess), "found: go on to the value read")
		XCTAssertEqual(BeamioChatWalletKeychainStore.probeAnswer(errSecItemNotFound), .absent, "no item is absent")
	}

	/// A protected item (locked device) and a failing probe are unreadable, never absent and never a prompt.
	func testAFailingProbeIsUnreadableNeverAbsent() {
		XCTAssertEqual(BeamioChatWalletKeychainStore.probeAnswer(errSecInteractionNotAllowed), .unreadable)
		XCTAssertEqual(BeamioChatWalletKeychainStore.probeAnswer(errSecAuthFailed), .unreadable)
		XCTAssertEqual(BeamioChatWalletKeychainStore.probeAnswer(errSecMissingEntitlement), .unreadable)
		XCTAssertEqual(BeamioChatWalletKeychainStore.probeAnswer(errSecParam), .unreadable)
	}
}
