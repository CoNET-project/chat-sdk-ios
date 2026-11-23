#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// X-19 native message decrypt: C3 `pgpDecrypt` with a generated PGP key fixture. No interop file is needed:
/// the key pair is made by X-19 and the message is encrypted to it with the test-only encrypt hook. Synthetic keys only.
/// Cases that need the framework skip where it is not linked (macOS `swift test`); the iOS simulator runs them all.
final class PGPDecryptX19VerifyTests: XCTestCase {
	private let account = "0x1111111111111111111111111111111111111111"
	private let other = "0x2222222222222222222222222222222222222222"
	private var savedVault: BeamioPasscodeVault?
	private var records: BeamioChatPgpKeychain.MemoryRecords!

	override func setUp() {
		super.setUp()
		records = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.memory = records
		BeamioChatPgpKeychain.testUnreadableFields = []
		savedVault = BeamioPasscodeSession.shared.vault
		BeamioPGPNative.linkedOverrideForTests = nil
	}

	override func tearDown() {
		BeamioPGPNative.linkedOverrideForTests = nil
		BeamioChatPgpKeychain.testUnreadableFields = []
		BeamioChatPgpKeychain.memory = nil
		BeamioPasscodeSession.shared.vault = savedVault
		super.tearDown()
	}

	private func makeKey(_ name: String) throws -> (priv: String, pub: String) {
		guard case let .success(pair) = BeamioPGPNative.generateKeyPair(name: name) else {
			throw XCTSkip("X-19 is not linked in this build")
		}
		return (pair.privateArmor, pair.publicArmor)
	}

	private func encrypt(_ text: String, to pub: String) throws -> Data {
		let armor = try XCTUnwrap(BeamioPGPNative.encryptArmoredForTests(publicArmor: pub, plaintext: Data(text.utf8)))
		return Data(armor.utf8)
	}

	private func store(_ priv: String, pub: String, eoa: String) {
		XCTAssertTrue(BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: priv, publicKeyArmor: pub, pgpKeyId: "", routePublicKeyArmor: "",
			entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)))
	}

	private let offer = #"{"type":"voiceOffer","callId":"c1","sessionId":"s1","note":"你好"}"#

	// MARK: positive

	func testDecryptsAGeneratedFixtureIncludingACallOfferLine() throws {
		let k = try makeKey("x19-positive")
		store(k.priv, pub: k.pub, eoa: account)
		for text in ["hello", offer, "line1\nline2"] {
			XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: try encrypt(text, to: k.pub)),
			               .success(Data(text.utf8)), text)
		}
		// the account is matched case-insensitively
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account.uppercased().replacingOccurrences(of: "0X", with: "0x"),
		                                             message: try encrypt("hello", to: k.pub)), .success(Data("hello".utf8)))
	}

	// MARK: failure classes

	func testMissingKeyIsNoPgpKeyAndAnotherAccountIsRefused() throws {
		let k = try makeKey("x19-missing")
		let msg = try encrypt("hello", to: k.pub)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg), .failure(.rejected("no_pgp_key")))
		store(k.priv, pub: k.pub, eoa: account)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: other, message: msg), .failure(.rejected("no_pgp_key")))
		XCTAssertEqual(BeamioPGPInbound.code(for: .rejected("no_pgp_key")), "pgp_source_unavailable")
	}

	func testALockedAccountStillOpensAnIncomingOfferButNotTheWalletKey() throws {
		let k = try makeKey("x19-locked")
		store(k.priv, pub: k.pub, eoa: account)
		let msg = try encrypt(offer, to: k.pub)
		// no vault: the lock state is unknown, which counts as locked (fail closed)
		BeamioPasscodeSession.shared.vault = nil
		XCTAssertTrue(BeamioPasscodeSession.shared.isLocked(eoa: account))
		// the offer of a ringing call opens: the PGP key is not under the wallet passcode
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg), .success(Data(offer.utf8)))
		// the wallet side stays refused while locked
		XCTAssertEqual(BeamioNativeWallet.pgpSign(eoa: account, purposeId: "voiceSignal", sigType: 0x00, data: Data([1])), .failure(.locked))
		XCTAssertEqual(BeamioPGPInbound.code(for: .locked), "locked")
	}

	func testUnreadableRecordIsNotReadyNeverMissing() throws {
		let k = try makeKey("x19-unreadable")
		store(k.priv, pub: k.pub, eoa: account)
		let msg = try encrypt("hello", to: k.pub)
		BeamioChatPgpKeychain.testUnreadableFields = Set(["userPgpPrivateArmor"])
		let result = BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg)
		XCTAssertEqual(result, .failure(.storageUnreadable))
		XCTAssertEqual(BeamioNativeWallet.Failure.storageUnreadable.refusalCode, "not_ready")
		XCTAssertEqual(BeamioPGPInbound.code(for: .storageUnreadable), "not_ready")
	}

	func testCorruptOrWrongKeyIsDecryptFailedWithNoPlaintext() throws {
		let k = try makeKey("x19-good")
		let wrong = try makeKey("x19-wrong")
		let msg = try encrypt("secret-text", to: k.pub)
		// a key block that has the PGP header and a damaged body
		let corrupt = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAAAAAA\n-----END PGP PRIVATE KEY BLOCK-----"
		store(corrupt, pub: k.pub, eoa: account)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg), .failure(.rejected("decrypt_failed")))
		// a valid key that is not the recipient
		store(wrong.priv, pub: wrong.pub, eoa: account)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg), .failure(.rejected("decrypt_failed")))
		// a damaged message
		store(k.priv, pub: k.pub, eoa: account)
		let damaged = Data("-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----".utf8)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: damaged), .failure(.rejected("decrypt_failed")))
		XCTAssertEqual(BeamioPGPInbound.code(for: .rejected("decrypt_failed")), "decrypt_failed")
	}

	// MARK: no signature, no leak, no disk

	func testDecryptNeverSignsAndSignStaysClosed() throws {
		let k = try makeKey("x19-nosign")
		store(k.priv, pub: k.pub, eoa: account)
		_ = BeamioNativeWallet.pgpDecrypt(eoa: account, message: try encrypt("hello", to: k.pub))
		XCTAssertTrue(BeamioPGPPurpose.registered.isEmpty, "decrypt approval registers no signing purpose")
		for purpose in ["chatEnvelope", "groupMessage", "voiceSignal", "decrypt", "pgpDecrypt", ""] {
			for sigType: UInt8 in [0x00, 0x01, 0x02] {
				guard case .failure = BeamioNativeWallet.pgpSign(eoa: account, purposeId: purpose, sigType: sigType, data: Data([1])) else {
					return XCTFail("pgpSign must refuse \(purpose)/\(sigType)")
				}
			}
		}
		XCTAssertEqual(BeamioNativeWallet.pgpSign(eoa: account, purposeId: "voiceSignal", sigType: 0x00, data: Data([1])),
		               .failure(.rejected("purpose_not_registered")))
	}

	func testFailuresCarryNoKeyOrPlaintextAndNothingIsWritten() throws {
		let k = try makeKey("x19-hygiene")
		let wrong = try makeKey("x19-hygiene-wrong")
		store(wrong.priv, pub: wrong.pub, eoa: account)
		let before = records.values
		let msg = try encrypt("PLAINTEXT-MARKER-77", to: k.pub)
		let results: [Result<Data, BeamioNativeWallet.Failure>] = [
			BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg),
			BeamioNativeWallet.pgpDecrypt(eoa: other, message: msg),
			BeamioNativeWallet.pgpDecrypt(eoa: account, message: Data("not pgp".utf8)),
		]
		for r in results {
			let text = String(describing: r)
			XCTAssertFalse(text.contains("PRIVATE KEY"))
			XCTAssertFalse(text.contains("PLAINTEXT-MARKER-77"))
			XCTAssertFalse(text.contains(wrong.priv.prefix(60)))
		}
		// a success also leaves the record store as it was: decrypt writes nothing
		store(k.priv, pub: k.pub, eoa: account)
		let stored = records.values
		_ = BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg)
		XCTAssertEqual(records.values, stored)
		XCTAssertNotEqual(before, stored) // the fixture itself was stored, nothing else changed
	}

	// MARK: not linked: pending, no WebView fallback

	func testNotLinkedIsPendingEverywhereAndNeverFallsBackToTheWebView() throws {
		let k = try makeKey("x19-unlinked")
		store(k.priv, pub: k.pub, eoa: account)
		let msg = try encrypt("hello", to: k.pub)
		BeamioPGPNative.linkedOverrideForTests = false
		XCTAssertFalse(BeamioPGPNative.linked)
		XCTAssertFalse(BeamioPGPNative.available)
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg), .failure(.pending("pgp_native_pending")))
		XCTAssertEqual(BeamioPGPInbound.code(for: .pending("pgp_native_pending")), "not_supported")
		// the listen path: nothing is delivered, the failure callback runs, and the WebView host is not asked for a decrypt
		let session = BeamioConetChatModule.Session()
		session.eoa = account
		var delivered = 0
		var failed = 0
		BeamioConetChatListenSession.decryptArmor(session: session, armored: String(decoding: msg, as: UTF8.self),
		                                          onFailure: { failed += 1 }, onLine: { _, _ in delivered += 1 })
		XCTAssertEqual(delivered, 0)
		XCTAssertEqual(failed, 1)
		BeamioPGPNative.linkedOverrideForTests = nil
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: account, message: msg), .success(Data("hello".utf8)))
	}
}
#endif
