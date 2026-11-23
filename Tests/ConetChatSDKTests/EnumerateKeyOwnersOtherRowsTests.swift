#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// interface 25.52Y.105 第 1 项: a row of another kind (mnemonic, phase, intent, commit) is skipped by the owner enumeration and does not make
/// it fail. The legacy single item names no owner, so it stays fail closed (nil). Synthetic data only, held in the test memory, never in the Keychain.
final class EnumerateKeyOwnersOtherRowsTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let other = "0x2222222222222222222222222222222222222222"
	private let service = "com.beamio.beamio.chat-wallet"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private let phrase = Data("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".utf8)
	private var savedMemory: [String: Data]?

	override func setUp() {
		super.setUp()
		savedMemory = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
	}

	override func tearDown() {
		BeamioChatWalletTestMemory.items = savedMemory
		super.tearDown()
	}

	func testOtherKindsOfTheSameAccountAreSkipped() {
		let store = BeamioChatWalletKeychainStore.standard
		XCTAssertTrue(store.write(eoa: account, key: keyData))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: account, value: phrase), "mnemonic row written")
		XCTAssertTrue(store.writeItem(.intent, eoa: account, value: Data("{}".utf8)), "intent row written")
		XCTAssertTrue(store.writeItem(.commit, eoa: account, value: Data("{}".utf8)), "commit row written")
		XCTAssertTrue(store.setMigrationPhase(eoa: account, .running), "phase row written")
		XCTAssertEqual(store.enumerateKeyOwners(), [account], "the other rows do not fail the enumeration")
	}

	func testAnAccountWithOnlyOtherRowsIsSkippedAndTheKeyAccountIsStillListed() {
		let store = BeamioChatWalletKeychainStore.standard
		XCTAssertTrue(store.write(eoa: account, key: keyData))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: other, value: phrase), "a mnemonic row with no key of its own")
		XCTAssertEqual(store.enumerateKeyOwners(), [account], "the key account is listed; the other row is skipped")
	}

	func testTheLegacySingleItemStaysFailClosed() {
		let store = BeamioChatWalletKeychainStore.standard
		XCTAssertTrue(store.write(eoa: account, key: keyData))
		BeamioChatWalletTestMemory.put(service, "walletKey", Data("{}".utf8))
		XCTAssertNil(store.enumerateKeyOwners(), "the legacy item names no owner, so the enumeration is unknown")
	}

	func testAnEmptyStoreAnswersAnEmptyListNotNil() {
		XCTAssertEqual(BeamioChatWalletKeychainStore.standard.enumerateKeyOwners(), [], "no item is an empty enumeration, not an unknown one")
	}
}
#endif
