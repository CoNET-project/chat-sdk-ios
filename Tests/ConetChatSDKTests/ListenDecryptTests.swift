#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// the mailbox listen decrypts an inbound frame natively. A frame that decrypts goes on to `onLine` with its armor hash (keccak256
/// of the armor text, the chat-daemon vectors' definition). A frame that does not decrypt goes to `onFailure` only: no line, so nothing is
/// stored, shown or acked. Generated keys and messages only; no network is reached.
final class ListenDecryptTests: XCTestCase {
	private let account = "0x3333333333333333333333333333333333333333"
	private var generated: (privateArmor: String, publicArmor: String)?
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioConetChatInboxStore.clear()
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioChatPgpKeychain.memory = nil
		BeamioConetChatInboxStore.clear()
		super.tearDown()
	}

	private func session() -> BeamioConetChatModule.Session {
		let s = BeamioConetChatModule.Session()
		s.eoa = account
		return s
	}

	/// The account's key pair, generated once per test run by the native layer.
	private func keys() throws -> (privateArmor: String, publicArmor: String) {
		if let generated { return generated }
		let pair = try BeamioPGPNative.generateKeyPair(name: "Beamio listen decrypt test").get()
		generated = pair
		return pair
	}

	/// Saves the account's PGP record (the key the listen decrypts with).
	private func saveRecord() throws {
		let key = try keys()
		let subkey = try XCTUnwrap(BeamioPGPBackup.keyIdentity(armor: key.publicArmor)?.subkeyKeyID)
		XCTAssertTrue(BeamioChatPgpKeychain.save(BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: key.privateArmor, publicKeyArmor: key.publicArmor, pgpKeyId: subkey,
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: account)))
	}

	/// An OpenPGP message of `plaintext` to the account's key.
	private func encryptedToAccount(_ plaintext: String) throws -> String {
		let key = try keys()
		return try XCTUnwrap(BeamioPGPNative.encryptArmoredForTests(publicArmor: key.publicArmor, plaintext: Data(plaintext.utf8)))
	}

	/// Runs `decryptArmor` and returns the lines it delivered and how often it failed.
	private func decrypt(_ armored: String) -> (lines: [(line: String, hash: String)], failures: Int) {
		var lines: [(line: String, hash: String)] = []
		var failures = 0
		BeamioConetChatListenSession.decryptArmor(session: session(), armored: armored, onFailure: { failures += 1 }) { line, hash in
			lines.append((line: line, hash: hash))
		}
		return (lines, failures)
	}

	private let junk = "-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----"

	/// The armor hash is keccak256 of the armor text, as the shared chat-daemon vectors define it (no native layer needed).
	func testTheArmorHashIsTheVectorHash() throws {
		let url = try XCTUnwrap(Bundle.module.url(forResource: "chat-daemon-vectors.v1", withExtension: "json"))
		let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
		for envelope in try XCTUnwrap(root["envelopes"] as? [[String: Any]]) {
			let armor = try XCTUnwrap(envelope["armor"] as? String)
			let expected = try XCTUnwrap(envelope["armorHash"] as? String)
			XCTAssertEqual(BeamioConetChatListenSession.armorHash(armor), expected, "vector \(envelope["name"] ?? "?")")
		}
	}

	/// A frame that decrypts goes on to `onLine` once, with `_beamioPgpArmorHash` set to the armor hash, and with the envelope unchanged.
	func testADecryptedFrameGoesOnWithItsArmorHash() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build")
		try saveRecord()
		let envelope = #"{"sendId":"listen-1","from":"0x1111111111111111111111111111111111111111","text":"hi","createdAt":1730419200000}"#
		let armored = try encryptedToAccount(envelope)

		let result = decrypt(armored)

		XCTAssertEqual(result.failures, 0, "a decrypted frame is not a failure")
		XCTAssertEqual(result.lines.count, 1, "exactly one line goes on")
		let delivered = try XCTUnwrap(result.lines.first)
		XCTAssertEqual(delivered.hash, BeamioConetChatListenSession.armorHash(armored))
		XCTAssertTrue(delivered.hash.hasPrefix("0x") && delivered.hash.count == 66, "0x and 32 bytes of hex")
		let obj = try XCTUnwrap(BeamioConetChatListenSession.jsonObject(delivered.line))
		XCTAssertEqual(obj["_beamioPgpArmorHash"] as? String, delivered.hash)
		XCTAssertEqual(obj["sendId"] as? String, "listen-1")
		XCTAssertEqual(obj["text"] as? String, "hi")
	}

	/// A frame that does not decrypt goes to `onFailure` only: no line is delivered.
	func testAFrameThatDoesNotDecryptGoesToFailureOnly() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build")
		try saveRecord()

		let result = decrypt(junk)

		XCTAssertEqual(result.failures, 1, "the failure is reported once")
		XCTAssertTrue(result.lines.isEmpty, "no line is delivered for a frame that does not decrypt")
	}

	/// A frame sealed to another key does not decrypt with the account's key: failure, no line.
	func testAFrameForAnotherKeyFailsWithoutDelivery() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build")
		try saveRecord()
		let other = try BeamioPGPNative.generateKeyPair(name: "Beamio listen decrypt other").get()
		let armored = try XCTUnwrap(BeamioPGPNative.encryptArmoredForTests(publicArmor: other.publicArmor, plaintext: Data("{}".utf8)))

		let result = decrypt(armored)

		XCTAssertEqual(result.failures, 1)
		XCTAssertTrue(result.lines.isEmpty)
	}

	/// Without the account's PGP record there is no key: failure, no line.
	func testWithoutAPgpRecordTheFrameFailsWithoutDelivery() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build")
		let armored = try encryptedToAccount("{}")

		let result = decrypt(armored)

		XCTAssertEqual(result.failures, 1)
		XCTAssertTrue(result.lines.isEmpty)
	}

	/// A failed frame writes nothing and emits nothing: no inbox row and no event. The ack follows only a stored frame, so none is sent.
	func testAFailedFrameWritesNothingAndSendsNoAck() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build")
		try saveRecord()

		_ = decrypt(junk)

		XCTAssertTrue(events.isEmpty, "a failed decrypt emits no event, so no ack goes out")
		XCTAssertEqual(BeamioConetChatInboxStore.list().count, 0, "a failed decrypt stores nothing")
	}
}
#endif
