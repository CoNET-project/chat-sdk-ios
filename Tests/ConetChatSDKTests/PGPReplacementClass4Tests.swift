#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The explicit replacement of class 4. iOS does not implement it yet, so a `pgpIdentityCreate` request for an account in a
/// class-4 local state answers `not_supported`, and nothing is prepared, written or deleted. An account with no PGP record is not class 4 and is not
/// answered `not_supported` by this rule. Synthetic values only.
final class PGPReplacementClass4Tests: XCTestCase {
	private let alice = "0xA11CE00000000000000000000000000000000001"
	private let privateA = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-alice\n-----END PGP PRIVATE KEY BLOCK-----"
	private let publicA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-alice\n-----END PGP PUBLIC KEY BLOCK-----"
	private let keyData = Data(repeating: 0x42, count: 32)
	private var savedStore: BeamioChatWalletKeyStoring!
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		savedStore = BeamioNativeWallet.keyStore
		let store = ChatLocalWalletBoundaryTests.MemoryWalletKeyStore()
		store.keys[alice.lowercased()] = keyData
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
		BeamioConetChatModule.setNativeGateForTests(account: alice, sessionReady: true)
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore
		BeamioChatPgpKeychain.memory = nil
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// The answer of one request, after the main queue has run.
	private func answer(_ reqId: Int, type: String = "pgpIdentityCreate") -> [String: Any]? {
		BeamioConetChatModule.handleCommand(["type": type, "reqId": reqId, "accountKey": alice + ":default", "idempotencyKey": "key-\(reqId)"],
		                                    emit: { _ in })
		RunLoop.current.run(until: Date().addingTimeInterval(0.2))
		return events.compactMap { $0["event"] as? [String: Any] }.first { $0["reqId"] as? Int == reqId }
	}

	private func savePGPRecord() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: privateA, publicKeyArmor: publicA, pgpKeyId: "keyA",
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: alice)))
	}

	/// Class 4 by an unreadable PGP record: not_supported, and the memory store is unchanged (nothing pending, nothing deleted).
	func testAReplacementOfAnUnreadableRecordIsNotSupportedAndWritesNothing() {
		let values = BeamioChatPgpKeychain.memory
		values?.values[BeamioChatPgpKeychain.accountKey(eoa: alice) + "|userPgpPrivateArmor"] = "not a PGP private key"
		let before = values?.values

		let ack = answer(9101)

		XCTAssertEqual(ack?["error"] as? String, "not_supported")
		XCTAssertEqual(values?.values, before, "nothing is prepared, written or deleted")
	}

	/// Class 4 by a restore marked incomplete: not_supported, and nothing changes.
	func testAReplacementOfAnIncompleteRestoreIsNotSupported() {
		savePGPRecord()
		_ = BeamioChatPgpKeychain.markRestoreIncomplete(eoa: alice)
		let before = BeamioChatPgpKeychain.memory?.values

		let ack = answer(9102)

		XCTAssertEqual(ack?["error"] as? String, "not_supported")
		XCTAssertEqual(BeamioChatPgpKeychain.memory?.values, before, "nothing changes")
	}

	/// Not class 4: an account with no PGP record is not answered `not_supported` by the class-4 rule (the existing path answers as before).
	func testAnAccountWithNoRecordIsNotAnsweredNotSupportedByTheClass4Rule() {
		XCTAssertFalse(BeamioPGPRestoreCommands.isClass4LocalState(eoa: alice), "no record is not class 4")

		let ack = answer(9103)

		XCTAssertNotEqual(ack?["error"] as? String, "not_supported", "the class-4 rule does not apply")
	}
}
#endif
