#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// S-1: no private key, mnemonic or PGP private key crosses the bridge into the PGP keychain.
/// Synthetic values only; none of them is a user key.
final class PgpBridgeRefusalTests: XCTestCase {
	private let fakePrivate = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-test-only\n-----END PGP PRIVATE KEY BLOCK-----"
	private let fakePublic = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-test-only\n-----END PGP PUBLIC KEY BLOCK-----"
	private let fakeHex64 = String(repeating: "1", count: 64)
	/// Synthetic account for the record these tests store (per-account keying, spec D5).
	private let account = "0x1111111111111111111111111111111111111111"

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = nil
		super.tearDown()
	}

	func testPrivateFieldNamesAreRefused() {
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["privateKeyArmor": fakePrivate, "pgpKeyId": "k1"]),
		               ["privateKeyArmor"])
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["mnemonic": "synthetic words"]), ["mnemonic"])
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["walletPrivateKey": "anything"]), ["walletPrivateKey"])
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["pgpPassphrase": "synthetic"]), ["pgpPassphrase"])
	}

	/// Same rule as the identity path: a forbidden field is refused even when empty (identity vectors, presence-based).
	func testEmptyPrivateFieldIsRefusedLikeTheIdentityPath() {
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["privateKeyArmor": ""]), ["privateKeyArmor"])
	}

	func testPrivateBlockUnderAnyNameIsRefused() {
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["routePublicKeyArmor": fakePrivate]),
		               ["routePublicKeyArmor"])
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["siNodes": [["note": fakePrivate]]]), ["note"])
	}

	func testHex64UnderAnyNameIsRefused() {
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["x": "0x" + fakeHex64]), ["x"])
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["x": fakeHex64]), ["x"])
	}

	func testPublicPayloadIsAccepted() {
		let body: [String: Any] = [
			"publicKeyArmor": fakePublic,
			"routePublicKeyArmor": fakePublic,
			"pgpKeyId": "abc123",
			"entryDomains": ["a.example", "b.example"],
			"eoa": "0x" + String(repeating: "a", count: 40),
			"siNodes": [["ip": "10.0.0.1", "domain": "n1.example"]],
		]
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: body), [])
	}

	/// Negative path with a stored record: a payload that carries private material changes nothing and reports `false`.
	/// Without the guard in `upsert(eoa:fromWeb:)` this call would overwrite `pgpKeyId`, so the test fails if the guard is removed.
	func testUpsertKeepsTheStoredRecordWhenPrivateMaterialIsSent() {
		let stored = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: fakePrivate,
			publicKeyArmor: fakePublic,
			pgpKeyId: "stored-id",
			routePublicKeyArmor: "",
			entryDomains: [],
			siNodes: [],
			mailboxIp: "",
			eoa: account
		)
		XCTAssertTrue(BeamioChatPgpKeychain.save(stored))
		let ok = BeamioChatPgpKeychain.upsert(eoa: account, fromWeb: ["privateKeyArmor": fakePrivate + "x", "pgpKeyId": "changed-id"])
		XCTAssertFalse(ok)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: account)?.pgpKeyId, "stored-id")
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: account)?.privateKeyArmor, fakePrivate)
	}

	/// A public-only update still works, so the guard does not block the normal PWA path.
	func testUpsertStillAcceptsPublicFields() {
		let stored = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: fakePrivate,
			publicKeyArmor: fakePublic,
			pgpKeyId: "stored-id",
			routePublicKeyArmor: "",
			entryDomains: [],
			siNodes: [],
			mailboxIp: "",
			eoa: account
		)
		XCTAssertTrue(BeamioChatPgpKeychain.save(stored))
		let ok = BeamioChatPgpKeychain.upsert(eoa: account, fromWeb: ["pgpKeyId": "new-id"])
		XCTAssertTrue(ok)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: account)?.pgpKeyId, "new-id")
	}

	/// The eight forms found accepted by the PGP path. The same rule as the identity
	/// path now decides them.
	func testTheReviewedPrivateFormsAreRefusedLikeTheIdentityPath() {
		let zwsp = "\u{200B}"
		let hex32 = String(repeating: "a", count: 32)
		let cases: [([String: Any], String)] = [
			(["WalletPrivateKey": "synthetic"], "WalletPrivateKey"),
			(["PRIVATEKEYHEX": "synthetic"], "PRIVATEKEYHEX"),
			(["extra": ["PgpPassphrase": "synthetic"]], "PgpPassphrase"),
			(["mnemonic ": "synthetic"], "mnemonic "),
			(["mnemonic" + zwsp: "synthetic"], "mnemonic" + zwsp),
			(["extra": ["mnemonic": "synthetic"]], "mnemonic"),
			(["extra": [["privateKeyHex": "synthetic"]]], "privateKeyHex"),
			(["privateKeyArmor": ""], "privateKeyArmor"),
			(["note": "0x" + hex32 + zwsp + hex32], "note"),
			(["note": "0x" + String(repeating: "1", count: 63) + "f\u{0301}"], "note"),
			(["note": "-----BEGINPGPPRIVATEKEYBLOCK-----"], "note"),
			(["note": "-----BEGIN PGP PRIVATE\u{00A0}KEY BLOCK-----"], "note"),
		]
		for (body, field) in cases {
			XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: body), [field], "\(body)")
		}
	}

	/// The exact path `payload.nodes` keeps its 64-hex exemption; the same key under another path does not.
	func testTheExactNodesPathIsStillExempt() {
		let hex = "0x" + String(repeating: "a", count: 64)
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["nodes": [["armoredPublicKey": hex]]]), [])
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["extra": ["nodes": [["x": hex]]]]), ["x"])
	}

	/// The review probe's exact value (64 digits with a zero-width character in the middle), with and without the `eoa` field.
	func testProbeZeroWidthHex64IsRefusedByTheSharedRule() {
		let hex = String(repeating: "1", count: 32) + "\u{200B}" + String(repeating: "1", count: 32)
		XCTAssertEqual(BeamioChatPgpKeychain.refusedPrivateFields(in: ["note": hex]), ["note"])
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["eoa": "0x3958", "note": hex]), "note")
	}
}
#endif
