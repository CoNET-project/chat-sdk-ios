import XCTest
@testable import ConetChatSDK

/// The EOA key written by a native import is read back by the native signing command, with no WebView in the path (
/// question, 2026-11-13). The key store is the in-memory test store: the Keychain is not reachable in the test host
/// (-34018, see ChatLocalWalletBoundaryTests), so the Keychain path itself is verified on a device, not here.
final class NativeSigningAfterImportTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	/// The public BIP-39 test key of the derivation vectors (its address is `account`). Not a wallet key.
	private let testKeyHex = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"

	final class ImportKeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = ImportKeyStore()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	func testTheImportedKeyIsReadBackAndSignsNatively() throws {
		let restoreG2 = WalletG2Gate.enter(account: account)
		defer { restoreG2() }
		let store = try XCTUnwrap(BeamioNativeWallet.keyStore as? ImportKeyStore)
		let imported = BeamioNativeKeyImport.importPrivateKey(text: "0x" + testKeyHex, expectedEoa: account, store: store)
		XCTAssertEqual(imported, .imported)
		XCTAssertNotNil(store.read(eoa: account), "the key is in the native store after the import")

		// The native signing command reads the key from the store and signs in-process (C2 path, no WebView).
		let domain = "beamio.chat.history.v1|224422|" + account
		let key = try XCTUnwrap(AddressPGPChain.bytes(fromHex: testKeyHex))
		let expected = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: key, message: domain))
		XCTAssertEqual(BeamioNativeWallet.signEip191(eoa: account, message: domain), .success(expected))
	}

	func testAnAccountWithoutAStoredKeyCannotSign() {
		let other = "0x1111111111111111111111111111111111111111"
		XCTAssertEqual(BeamioNativeWallet.signEip191(eoa: other, message: "x"), .failure(.walletKeyMissing))
	}
}
