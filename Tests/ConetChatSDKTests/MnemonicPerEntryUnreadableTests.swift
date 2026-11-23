import XCTest
@testable import ConetChatSDK

/// M-5: a per-entry read failure keeps the `unavailable` contract, never `locked`. Startup stays undetermined, creation and
/// overwrite are blocked, and a later readable read resolves the state (retry). The storage-derived lock is not touched here.
final class MnemonicPerEntryUnreadableTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var accountA = ""
	private var accountB = ""

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		accountA = account(phraseA)
		accountB = account(phraseB)
		XCTAssertEqual(BeamioNativeRestore.restoreWrite(phrase: phraseA, userExplicit: true, sessionIsG2: false, store: store), .ok(eoa: accountA))
		XCTAssertEqual(BeamioNativeRestore.restoreWrite(phrase: phraseB, userExplicit: true, sessionIsG2: false, store: store), .ok(eoa: accountB))
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func account(_ phrase: String) -> String {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { preconditionFailure("the test phrase derives an account") }
		return derived.eoa.lowercased()
	}

	private func resolved(pointer: String) -> (state: BeamioNativeWalletState, account: String?) {
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		return BeamioNativeWalletStateResolver.resolve(pointer: pointer, entries: inventory.entries)
	}

	func testAPerEntryReadFailureIsUnavailableNotLockedNorAbsentNorPresent() {
		store.mnemonic.failReadOwners = [accountB]
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		XCTAssertTrue(inventory.enumerated)
		XCTAssertEqual(inventory.state(of: accountB), .unreadable)
		XCTAssertTrue(inventory.readFailed, "a failed item read is an unknown judgement, never no account")
		for pointer in ["", accountA] {
			let answer = resolved(pointer: pointer)
			XCTAssertEqual(answer.state, .unavailable, "pointer \(pointer): startup stays undetermined")
			XCTAssertNil(answer.account)
		}
	}

	func testAPerEntryReadFailureBlocksCreationAndOverwriteAndWritesNothing() {
		store.mnemonic.failReadOwners = [accountB]
		let writes = store.mutationCount
		XCTAssertEqual(BeamioNativeRestore.restoreWrite(phrase: phraseA, userExplicit: true, sessionIsG2: false, store: store), .notReady)
		XCTAssertEqual(store.mutationCount, writes, "no entry is created or overwritten while an entry is unreadable")
	}

	func testAPerEntryReadFailureBlocksTheConfirmAndLeavesThePointer() {
		store.mnemonic.failReadOwners = [accountB]
		BeamioNativeAccountPointer.set(accountA)
		let writes = store.mutationCount
		XCTAssertEqual(BeamioNativeRestore.restoreConfirm(eoa: accountB, userExplicit: true, store: store), .notReady)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), accountA)
		XCTAssertEqual(store.mutationCount, writes)
	}

	func testTheStateResolvesAgainOnceTheEntryReadsAgain() {
		store.mnemonic.failReadOwners = [accountB]
		XCTAssertEqual(resolved(pointer: accountA).state, .unavailable)
		store.mnemonic.failReadOwners = []
		let answer = resolved(pointer: accountA)
		XCTAssertEqual(answer.state, .present, "retry: a readable entry resolves the pointer's account")
		XCTAssertEqual(answer.account, accountA)
		XCTAssertTrue(!BeamioNativeMnemonicInventory.read(store: store).readFailed)
	}
}
