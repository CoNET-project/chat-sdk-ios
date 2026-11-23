import XCTest
@testable import ConetChatSDK

/// The mnemonic judgement of one account (mnemonicAccountState): valid, invalid, absent, and an owner that the phrase does not derive.
/// Recovers and checks the recovery mnemonic only; no private key is kept or named here.
final class MnemonicAccountStateTests: XCTestCase {
	private let store = BeamioChatWalletKeychainStore(service: "mnemonic-account-state-test")

	/// The address the given phrase derives, computed the way the creation derives it.
	private func derivedAddress(for phrase: String) -> String? {
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phrase) else { return nil }
		return BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
	}

	func testAValidPhraseOfTheOwnerIsValid() throws {
		let phrase = try XCTUnwrap(BeamioNativeAccountCreate.phrase(entropy: [UInt8](repeating: 0, count: 16)))
		let owner = try XCTUnwrap(derivedAddress(for: phrase))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: owner, value: Data(phrase.utf8)))
		XCTAssertEqual(store.mnemonicAccountState(owner: owner), .valid)
	}

	func testAPhraseThatFailsTheCheckIsInvalid() {
		let owner = "0x1111111111111111111111111111111111111111"
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: owner, value: Data("not a recovery phrase".utf8)))
		XCTAssertEqual(store.mnemonicAccountState(owner: owner), .invalid)
	}

	func testAPhraseThatDerivesAnotherAddressIsInvalid() throws {
		let phrase = try XCTUnwrap(BeamioNativeAccountCreate.phrase(entropy: [UInt8](repeating: 0, count: 16)))
		let other = "0x2222222222222222222222222222222222222222"
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: other, value: Data(phrase.utf8)))
		XCTAssertEqual(store.mnemonicAccountState(owner: other), .invalid, "a phrase that derives another address is not this account's")
	}

	func testNoPhraseItemIsAbsent() {
		XCTAssertEqual(store.mnemonicAccountState(owner: "0x3333333333333333333333333333333333333333"), .absent)
	}
}
