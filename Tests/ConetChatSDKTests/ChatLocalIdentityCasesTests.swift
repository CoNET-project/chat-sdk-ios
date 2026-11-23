import XCTest
@testable import ConetChatSDK

/// Spec 22.8 identity cases (synthetic identities only). Covered here: T-37 (restart, lock, re-unlock keeps the data),
/// T-38 (a key for another account on the same file is refused with kcvMismatch), and T-42 (the local path needs no
/// EIP-191 signature). T-36 (auto unlock in the shell) and T-39 (file names from K_dev) are not in this package.
final class ChatLocalIdentityCasesTests: XCTestCase {
	private let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let viewport = BeamioChatViewport(widthPt: 390, heightPt: 780, orientation: .portrait)

	private func makeRoot() -> URL {
		FileManager.default.temporaryDirectory.appendingPathComponent("identity-\(UUID().uuidString)", isDirectory: true)
	}

	func testT37RestartLockAndReUnlockKeepTheData() throws {
		let root = makeRoot()
		let localRoot = Data(repeating: 5, count: 32)
		let conv = "0x3333333333333333333333333333333333333333"
		let first = BeamioConetChatLocalStore(rootDirectory: root)
		try first.unlock(accountKey: account + ":default", localRoot: localRoot)
		_ = try first.importBatch(accountKey: account + ":default", rows: [
			BeamioChatImportRow(convKey: conv, dir: "in", ts: 1767225601234, sendId: "t37-1", body: "before restart"),
		])
		first.lock()
		XCTAssertFalse(first.isUnlocked)
		XCTAssertEqual(first.openConversation(convKey: conv, viewport: viewport).items, [], "locked: nothing is returned")

		// A new process: a new store object on the same files, same key.
		let restarted = BeamioConetChatLocalStore(rootDirectory: root)
		try restarted.unlock(accountKey: account + ":default", localRoot: localRoot)
		XCTAssertEqual(restarted.openConversation(convKey: conv, viewport: viewport).items.compactMap { $0.body },
		               ["before restart"], "re-unlock returns the same data")
	}

	func testT38AKeyForAnotherAccountOnTheSameFileIsRefused() throws {
		let root = makeRoot()
		let owner = BeamioConetChatLocalStore(rootDirectory: root)
		try owner.unlock(accountKey: account + ":default", localRoot: Data(repeating: 5, count: 32))
		owner.lock()
		let intruder = BeamioConetChatLocalStore(rootDirectory: root)
		XCTAssertThrowsError(try intruder.unlock(accountKey: account + ":default", localRoot: Data(repeating: 6, count: 32))) { error in
			XCTAssertEqual(error as? BeamioChatLocalError, .kcvMismatch, "the key check fails; no data is returned")
		}
		XCTAssertFalse(intruder.isUnlocked)
	}

	func testT42TheLocalPathNeedsNoSignature() throws {
		// Only the native key store is needed (R_db from the key). No signer is set and no EIP-191 request is made.
		let store = BeamioChatWalletKeyStoreForT42()
		let eoa = account
		store.keys[eoa] = Data(repeating: 0x11, count: 32)
		let savedSigner = BeamioConetChatSignBroker.currentSignerEoa()
		BeamioConetChatSignBroker.clearSigner()
		defer { if !savedSigner.isEmpty { BeamioConetChatSignBroker.setSignerEoa(savedSigner) } }
		let root = try XCTUnwrap(BeamioChatWalletBoundary.localRoot(eoa: eoa, store: store))
		let library = BeamioConetChatLocalStore(rootDirectory: makeRoot())
		try library.unlock(accountKey: eoa + ":default", localRoot: root)
		XCTAssertTrue(library.isUnlocked)
		XCTAssertEqual(library.openConversation(convKey: "0x4444444444444444444444444444444444444444", viewport: viewport).source, .local)
	}
}

/// In-memory key store for the T-42 case.
private final class BeamioChatWalletKeyStoreForT42: BeamioChatWalletKeyStoring {
	var keys: [String: Data] = [:]
	func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
	func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
	func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
	func delete(eoa: String) { keys[eoa.lowercased()] = nil }
	func migrationMarkerExists(eoa: String) -> Bool { false }
	func setMigrationMarker(eoa: String) -> Bool { true }
}
