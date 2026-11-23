import XCTest
@testable import ConetChatSDK

/// Regression (review of 883524f, requirement): a marker that carries another account's moves, on an account A that already holds a valid mnemonic
/// and key, must not move A's key, mnemonic or commit. Only the names the marker lists are acted on; the other account is restored from its sealed copy.
/// The commit being absent is a consistency question only: it blocks writes and moves no valid record.
final class RecoveryValidAccountRegressionTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	private func derived(_ phrase: String) -> (eoa: String, key: Data) {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { preconditionFailure("the phrase derives an account") }
		return d
	}

	/// A holds a valid key and mnemonic; the commit is written when `withCommit`. A marker (pending, eoa A) lists O's mnemonic move: O's live mnemonic
	/// is gone and its sealed copy holds its phrase.
	private func seed(withCommit: Bool) -> (a: String, o: String) {
		let a = derived(phraseA)
		let o = derived(phraseB)
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		if withCommit {
			XCTAssertTrue(store.writeItem(.commit, eoa: a.eoa, value: Data(#"{"v":1,"eoa":"\#(a.eoa)","committedAt":"2026-11-17T00:00:00Z"}"#.utf8)))
		}
		let copyName = BeamioPwaPhraseOverwrite.isolationPrefix + "reg." + store.accountName(.mnemonic, eoa: o.eoa)
		let copy = BeamioPwaWalletSync.normalized(phraseB)
		store.rawAccounts[copyName] = copy
		let marker: [String: Any] = [
			"v": 1, "phase": "pending", "eoa": a.eoa, "tag": "reg", "source": "pwaWalletSync", "utc": "2026-11-17T00:00:00Z",
			"owners": [o.eoa], "partials": [],
			"moves": [["from": store.accountName(.mnemonic, eoa: o.eoa), "to": copyName, "digest": BeamioPwaPhraseOverwrite.digest(copy)]],
		]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])) ?? Data()
		return (a.eoa, o.eoa)
	}

	private func assertAccountAUntouched(_ a: String, withCommit: Bool, file: StaticString = #filePath, line: UInt = #line) {
		XCTAssertNotNil(store.keys[a.lowercased()], "A's key stays under its fixed name", file: file, line: line)
		XCTAssertEqual(store.mnemonicAccountState(owner: a), .valid, "A's mnemonic stays valid under its fixed name", file: file, line: line)
		XCTAssertEqual(store.itemState(.commit, eoa: a) == .present, withCommit, "A's commit is unchanged", file: file, line: line)
		let movedA = store.rawAccounts.keys.filter { $0.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) && $0.contains(a.lowercased()) }
		XCTAssertTrue(movedA.isEmpty, "no record of A is moved into isolation: \(movedA)", file: file, line: line)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
		XCTAssertEqual(reading.state, .valid, "the preread answers A", file: file, line: line)
		XCTAssertEqual(reading.eoa, a.lowercased(), file: file, line: line)
	}

	/// Ruling (b): the commit present (consistent): A untouched; the other account's sealed copy stays isolated (kept, bytes unchanged), not restored.
	func testValidAccountWithCommitKeepsItsRecordsAndOtherAccountStaysIsolated() {
		let (a, o) = seed(withCommit: true)
		let copyName = store.rawAccounts.keys.first { $0.hasPrefix(BeamioPwaPhraseOverwrite.isolationPrefix) && $0.contains(o.lowercased()) }
		let copyBefore = copyName.flatMap { store.rawAccounts[$0] }
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "the start-up recovery completes")
		assertAccountAUntouched(a, withCommit: true)
		XCTAssertEqual(store.rawRead(account: store.accountName(.mnemonic, eoa: o)), .absent, "O's mnemonic is not restored to its name")
		XCTAssertEqual(copyName.flatMap { store.rawAccounts[$0] }, copyBefore, "O's sealed copy is kept, byte for byte")
	}

	/// Ruling (c): the commit absent, A valid under its fixed name: roll forward. A's preread is valid, and O stays isolated, so no second valid account is
	/// created by recovery.
	func testValidAccountWithoutCommitRollsForwardAndOtherAccountStaysIsolated() {
		let (a, o) = seed(withCommit: false)
		XCTAssertTrue(BeamioPwaPhraseOverwrite.recoverAtStart(store: store), "the start-up recovery completes")
		assertAccountAUntouched(a, withCommit: false)
		XCTAssertEqual(store.rawRead(account: store.accountName(.mnemonic, eoa: o)), .absent, "O is not restored: no second valid account")
	}
}
