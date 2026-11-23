import XCTest
@testable import ConetChatSDK

/// The preread epoch (25.52Y.163 r2.5.19, 第 42(2) 项, 第 49(2) 项, 第 59(3)(f) 项): a start-up read is published only at its own epoch, a read
/// still pending answers `unknown`, and a write publishes the store as it is after the write. Synthetic phrase only; no key material.
final class PwaPrereadEpochTests: XCTestCase {
	private let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
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

	private func preread(seq: Int64 = 200) -> [String: Any] {
		BeamioPwaWalletSync.answer(["type": "nativeMnemonicPreread", "reqId": 1, "trustedOrigin": true, "seq": NSNumber(value: seq)],
		                           snapshotKnown: true, storageLocked: false)
	}

	/// the answer's code, mapped back to the internal state words the tests below were written in: ok = valid, confirmed_missing = absent, read_error = unknown
	private func state(_ answer: [String: Any]) -> String? {
		switch (answer["result"] as? [String: Any])?["code"] as? String {
		case "ok": return "valid"
		case "confirmed_missing": return "absent"
		case "read_error": return "unknown"
		default: return nil
		}
	}

	// 第 42(3) 项: while the start-up read of the current epoch is pending, the answer is unknown, never an empty answer.
	func testAPendingStartReadAnswersUnknownUntilItIsPublished() throws {
		let account = try XCTUnwrap(BeamioPwaWalletSync.derivedAccount(phrase: phrase))
		let epoch = BeamioPwaPreread.advance(pending: true)
		XCTAssertEqual(state(preread()), "unknown", "pending: unknown")
		XCTAssertTrue(BeamioPwaPreread.publish(.init(state: .valid, eoa: account.eoa, phrase: phrase), epoch: epoch))
		XCTAssertEqual(state(preread()), "valid", "published at the current epoch")
	}

	// 第 49(2) 項: a reading of an older epoch is dropped; the answer is the store as it is now.
	func testAReadingOfAnOlderEpochIsDropped() throws {
		let account = try XCTUnwrap(BeamioPwaWalletSync.derivedAccount(phrase: phrase))
		let old = BeamioPwaPreread.advance(pending: true)
		BeamioPwaPreread.beforeWrite()
		XCTAssertFalse(BeamioPwaPreread.publish(.init(state: .valid, eoa: account.eoa, phrase: phrase), epoch: old),
		               "a reading of an older epoch is not published")
		XCTAssertEqual(state(preread()), "absent", "the empty store is read now")
	}

	// 第 59(3)(f) 項: after a write, the store is read again and published; the preread answers the written account with its phrase.
	func testAWriteIsPublishedAfterTheWrite() throws {
		XCTAssertEqual(state(preread()), "absent", "before the write the store is empty")
		let answer = BeamioPwaWalletSync.answer(["type": "pwaWalletSync", "reqId": 2, "trustedOrigin": true,
		                                         "seq": NSNumber(value: Int64(100)), "phrase": phrase],
		                                        snapshotKnown: true, storageLocked: false)
		XCTAssertEqual((answer["result"] as? [String: Any])?["sync"] as? String, "updated")
		let after = preread()
		XCTAssertEqual(state(after), "valid")
		let account = try XCTUnwrap(BeamioPwaWalletSync.derivedAccount(phrase: phrase))
		XCTAssertEqual((after["result"] as? [String: Any])?["eoa"] as? String, account.eoa)
		XCTAssertEqual((after["result"] as? [String: Any])?["mnemonic"] as? String, phrase)
	}

	// 第 42(2) 項: the start-up read runs on a background queue and is published at its epoch; until then the answer is unknown.
	func testTheShellStartReadIsPublishedAtItsEpoch() {
		BeamioPwaPreread.startAsync(snapshotKnown: true, storageLocked: false, store: store)
		let deadline = Date().addingTimeInterval(5)
		while state(preread()) == "unknown", Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.01))
		}
		XCTAssertEqual(state(preread()), "absent", "the start-up read of the empty store is published")
	}
}
