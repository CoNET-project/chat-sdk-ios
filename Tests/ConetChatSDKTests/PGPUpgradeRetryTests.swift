import XCTest
@testable import ConetChatSDK

/// `pgpUpgradeRetry` (25.52Y.63 第 2 条, 25.52Y.62, 25.52Y.96 第 3 条). The refusals and the answers that need no PGP armor run on every
/// build. `upgraded_from_L` needs the X-19 identity check on a real key; it is not covered here (see the receipt).
/// Synthetic data only: the account is a made-up EOA, and the armor text is a placeholder that never parses as a key.
final class PGPUpgradeRetryTests: XCTestCase {
	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		// The PGP records stay in memory: the Keychain of the test host is never written by this suite.
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = nil
		super.tearDown()
	}

	private let eoa = "0x2222222222222222222222222222222222222222"

	func testAPrivateKeyFieldIsRefusedBeforeAnythingElse() {
		let body: [String: Any] = ["type": "pgpUpgradeRetry", "reqId": 1, "accountKey": eoa + ":default", "privateKeyArmor": "x"]
		XCTAssertEqual(BeamioPGPUpgradeRetry.refusal(body, account: eoa), "key_over_bridge_refused")
	}

	func testAnyOtherFieldIsBadRequest() {
		let body: [String: Any] = ["type": "pgpUpgradeRetry", "reqId": 2, "accountKey": eoa + ":default", "extra": 1]
		XCTAssertEqual(BeamioPGPUpgradeRetry.refusal(body, account: eoa), "bad_request")
		let missing: [String: Any] = ["type": "pgpUpgradeRetry", "reqId": 3]
		XCTAssertEqual(BeamioPGPUpgradeRetry.refusal(missing, account: eoa), "bad_request")
	}

	func testAnAccountKeyOfAnotherAccountIsAccountMismatch() {
		let other = "0x3333333333333333333333333333333333333333"
		let body: [String: Any] = ["type": "pgpUpgradeRetry", "reqId": 4, "accountKey": other + ":default"]
		XCTAssertEqual(BeamioPGPUpgradeRetry.refusal(body, account: eoa), "account_mismatch")
	}

	func testTheAccountKeyIsComparedAfterLowerCasing() {
		let body: [String: Any] = ["type": "pgpUpgradeRetry", "reqId": 5, "accountKey": eoa.uppercased() + ":default"]
		XCTAssertNil(BeamioPGPUpgradeRetry.refusal(body, account: eoa), "a case difference alone is not a mismatch")
	}

	func testNoAccountIsNotReady() {
		let body: [String: Any] = ["type": "pgpUpgradeRetry", "reqId": 6, "accountKey": eoa + ":default"]
		XCTAssertEqual(BeamioPGPUpgradeRetry.refusal(body, account: ""), "not_ready")
	}

	func testWithoutAKeyRecordAndWithoutALegacyRecordTheRetryWaitsForMigration() {
		XCTAssertEqual(BeamioPGPUpgradeRetry.decide(eoa: eoa), .migrationRetry)
	}

	func testAnExistingKeyRecordIsKeptNotOverwritten() {
		let secrets = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----placeholder", publicKeyArmor: "pub", pgpKeyId: "ABCDEF0123456789",
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa
		)
		XCTAssertTrue(BeamioChatPgpKeychain.save(secrets))
		XCTAssertEqual(BeamioPGPUpgradeRetry.decide(eoa: eoa), .keepExisting)
		guard case .record(let kept) = BeamioChatPgpKeychain.readK(eoa: eoa) else {
			return XCTFail("the K record is still readable")
		}
		XCTAssertEqual(kept["keyId"], "ABCDEF0123456789", "the existing key is not replaced")
	}

	func testTheRetryAnswerNamesOnlyTheSpecCodes() {
		let codes = Set(["upgraded_from_L", "keep_existing", "pgp_migration_retry"])
		XCTAssertEqual(Set([BeamioPGPUpgradeRetry.Code.upgradedFromL, .keepExisting, .migrationRetry].map { $0.rawValue }), codes)
	}
}
