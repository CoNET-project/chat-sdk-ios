#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Review 2026-11-17 on fe78659: (A) a shell copy whose bytes cannot be read (a file-protection lock) is a transient read failure, unknown, never
/// deterministic; (B) a marked mnemonic is ignored only when its key record is present (absent or unreadable is unknown).
final class E9ReviewFixTests: XCTestCase {
	private final class Keys: BeamioShellRecord.KeyStorage {
		var keys: [String: Data] = [:]
		func readKey(account: String) -> BeamioShellRecord.KeyRead {
			guard let key = keys[account] else { return .notFound }
			return .found(key)
		}
		@discardableResult
		func writeKey(account: String, _ key: Data) -> Bool {
			keys[account] = key
			return true
		}
	}

	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedDeterministic: ((String) -> Bool)?
	private var directory: URL?
	private var savedShellReader: ((String) -> BeamioShellRecord.ShellRecordRead)?

	override func setUp() {
		super.setUp()
		savedShellReader = BeamioPwaWalletSync.shellCopyReader
		savedStore = BeamioNativeWallet.keyStore
		savedDeterministic = BeamioPwaWalletSync.shellCopyDeterministic
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		directory = FileManager.default.temporaryDirectory.appendingPathComponent("e9-review-\(UUID().uuidString)", isDirectory: true)
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioPwaWalletSync.shellCopyDeterministic = savedDeterministic ?? { BeamioShellRecord.EncryptedShellRecordStore.production.readFailureIsDeterministic(account: $0) }
		BeamioPwaWalletSync.shellCopyReader = savedShellReader ?? { BeamioShellRecord.EncryptedShellRecordStore.production.read(account: $0) }
		if let directory { try? FileManager.default.removeItem(at: directory) }
		super.tearDown()
	}

	/// (A) The record is written, then its bytes become unreadable (the file-protection lock): the failure is transient, not deterministic.
	func testAShellCopyThatCannotBeReadIsTransientNotDeterministic() throws {
		let keys = Keys()
		let shell = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: keys)
		let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(shell.write(account: account, ["rev": 1, "schemaVersion": 2, "profiles": []]), "the record is written")
		let url = shell.fileURL(in: directory!, account)
		try? FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: url.path)
		defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path) }
		XCTAssertFalse(shell.readFailureIsDeterministic(account: account),
		               "a read that itself fails (a locked file) is transient: unknown, never ignored")
	}

	/// (A) The same record under a pending marker, read through the reader, is unknown when its bytes cannot be read.
	func testAShellCopyLockedUnderAPendingMarkerIsUnknown() throws {
		let keys = Keys()
		let shell = BeamioShellRecord.EncryptedShellRecordStore(directory: directory, keys: keys)
		let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
		// the write below is refused while the console is locked: skipped here, before it, with a counted reason (assertions above it run either way); run when unlocked
		try skipIfConsoleLocked()
		XCTAssertTrue(shell.write(account: account, ["rev": 1, "schemaVersion": 2, "profiles": []]))
		let url = shell.fileURL(in: directory!, account)
		try? FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: url.path)
		defer { try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path) }
		BeamioPwaWalletSync.shellCopyReader = { _ in .unreadable }
		BeamioPwaWalletSync.shellCopyDeterministic = { shell.readFailureIsDeterministic(account: $0) }
		XCTAssertEqual(BeamioPwaWalletSync.shellCopy(owner: account, pendingOwners: [account]), .unknown,
		               "a locked shell copy under a pending marker is unknown, not absent")
	}

	/// (B) A marked mnemonic with a deterministic failure is ignored only when its key record is present.
	func testBAMarkedUnreadableMnemonicWithAnUnreadableKeyIsUnknown() {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { return XCTFail("the phrase derives") }
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: d.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.mnemonic.failReadOwners.insert(d.eoa.lowercased())
		store.failKeyReadOwners.insert(d.eoa.lowercased())
		let object: [String: Any] = ["v": 1, "phase": "pending", "eoa": d.eoa, "tag": "rv", "source": "pwaWalletSync",
		                             "utc": "2026-11-17T00:00:00Z", "owners": [d.eoa], "moves": [], "partials": []]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .unknown,
		               "an unreadable key record (temporary) does not allow ignoring the marked mnemonic")
	}

	/// (B) The same with a present key record and a deterministic failure: ignored, absent.
	func testBBMarkedUnreadableMnemonicWithAPresentKeyIsIgnored() {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { return XCTFail("the phrase derives") }
		XCTAssertTrue(store.writeItem(.key, eoa: d.eoa, value: d.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: d.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.mnemonic.failReadOwners.insert(d.eoa.lowercased())
		let object: [String: Any] = ["v": 1, "phase": "pending", "eoa": d.eoa, "tag": "rv", "source": "pwaWalletSync",
		                             "utc": "2026-11-17T00:00:00Z", "owners": [d.eoa], "moves": [], "partials": []]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
		XCTAssertEqual(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state, .absent)
	}
	// MARK: - SS-32-u (E9.11.24, 2026-11-17): a first read that is invalid is confirmed only when a second read is also invalid.

	private func scriptedInventory(_ second: BeamioMnemonicAccountState) -> BeamioNativeMnemonicInventory {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { preconditionFailure("derives") }
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: d.eoa, value: Data("not a valid phrase for this account".utf8)))
		store.mnemonicStateScript[d.eoa.lowercased()] = [.invalid, second]
		return BeamioNativeMnemonicInventory.read(store: store)
	}

	/// First invalid, second valid (a different content): unreadable, not confirmed invalid.
	func testSS32uFirstInvalidSecondValidIsUnreadable() {
		let inv = scriptedInventory(.valid)
		let eoa = BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!.eoa.lowercased()
		XCTAssertEqual(inv.state(of: eoa), .unreadable, "SS-32-u: an unconfirmed invalid reading is unreadable")
		XCTAssertTrue(inv.readFailed, "SS-32-u: an unconfirmed reading is a read failure (unknown)")
	}

	/// First invalid, second missing: unreadable.
	func testSS32uFirstInvalidSecondMissingIsUnreadable() {
		let inv = scriptedInventory(.absent)
		let eoa = BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!.eoa.lowercased()
		XCTAssertEqual(inv.state(of: eoa), .unreadable, "SS-32-u: a second read that does not confirm the invalid reading is unreadable")
	}

	/// First invalid, second read fails: unreadable.
	func testSS32uFirstInvalidSecondReadFailureIsUnreadable() {
		let inv = scriptedInventory(.unreadable)
		let eoa = BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!.eoa.lowercased()
		XCTAssertEqual(inv.state(of: eoa), .unreadable, "SS-32-u: a second read failure is unreadable")
		XCTAssertTrue(inv.readFailed)
	}

	/// Control: first and second both invalid is confirmed (SS-32-c): invalid, not a read failure.
	func testSS32cFirstAndSecondInvalidAreConfirmed() {
		let inv = scriptedInventory(.invalid)
		let eoa = BeamioPwaWalletSync.derivedAccount(phrase: phraseA)!.eoa.lowercased()
		XCTAssertEqual(inv.state(of: eoa), .invalid, "SS-32-c: two identical invalid readings confirm the invalid mnemonic")
		XCTAssertFalse(inv.readFailed, "SS-32-c: a confirmed invalid mnemonic is not a read failure")
	}
	/// Ruling (1d57a98 review): both reads invalid, the stored bytes differ: not confirmed, unreadable (not no_key).
	func testSS32uBothInvalidWithDifferentBytesIsUnreadable() {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { return XCTFail("derives") }
		let eoa = d.eoa.lowercased()
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: d.eoa, value: Data("not a valid phrase for this account".utf8)))
		store.mnemonicStateScript[eoa] = [.invalid, .invalid]
		store.mnemonicBytesScript[eoa] = [Data("first invalid reading".utf8), Data("second invalid reading, different bytes".utf8)]
		let inv = BeamioNativeMnemonicInventory.read(store: store)
		XCTAssertEqual(inv.state(of: eoa), .unreadable, "SS-32-u: two invalid readings with different bytes do not confirm the invalid mnemonic")
		XCTAssertTrue(inv.readFailed)
	}

	/// Control: both reads invalid with the same bytes is confirmed (SS-32-c, bytes).
	func testSS32cBothInvalidWithSameBytesIsConfirmed() {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { return XCTFail("derives") }
		let eoa = d.eoa.lowercased()
		let same = Data("the same invalid reading".utf8)
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: d.eoa, value: same))
		store.mnemonicStateScript[eoa] = [.invalid, .invalid]
		store.mnemonicBytesScript[eoa] = [same, same]
		let inv = BeamioNativeMnemonicInventory.read(store: store)
		XCTAssertEqual(inv.state(of: eoa), .invalid, "SS-32-c: two identical invalid readings confirm the invalid mnemonic")
		XCTAssertFalse(inv.readFailed)
	}
}
#endif
