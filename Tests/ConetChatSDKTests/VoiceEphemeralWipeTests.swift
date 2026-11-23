#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The channel key T is overwritten with zeros when it is dropped: at its expiry (found at the next enroll, sign or seal), by `clear(sid:)` when the
/// call ends, and by `clearAll()`. The wipe probe sees each overwrite: 32 bytes, non-zero before, all zero after.
final class VoiceEphemeralWipeTests: XCTestCase {
	private let sidA = String(repeating: "a1", count: 16)
	private let sidB = String(repeating: "b2", count: 16)
	private let sidC = String(repeating: "c3", count: 16)

	override func setUp() {
		super.setUp()
		BeamioVoiceEphemeral.clearAll()
		BeamioVoiceEphemeral.testClock = 1_000
	}

	override func tearDown() {
		BeamioVoiceEphemeral.testClock = nil
		BeamioVoiceEphemeral.clearAll()
		_ = BeamioWipeProbe.stop()
		super.tearDown()
	}

	/// The overwrites of the held keys: they are `Data` (no address recorded by the probe), 32 bytes. The short-lived copies that sign and enroll make
	/// are byte arrays and are wiped too, but they are not what is counted here.
	private func wipes() -> [BeamioWipeProbe.Event] { BeamioWipeProbe.stop().filter { $0.count == 32 && $0.address == nil } }

	func testAnExpiredKeyIsWipedAndRemovedAtTheNextEnroll() {
		XCTAssertEqual(BeamioVoiceEphemeral.enroll(sid: sidA, expiresAt: 1_100) != .failed, true)
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1)
		BeamioVoiceEphemeral.testClock = 1_200 // sidA is over
		BeamioWipeProbe.start()
		guard case .registered = BeamioVoiceEphemeral.enroll(sid: sidB, expiresAt: 2_000) else { return XCTFail() }
		let seen = wipes()
		XCTAssertEqual(seen.count, 1, "the expired key was overwritten once")
		XCTAssertTrue(seen.allSatisfy { $0.hadNonZero && $0.allZero })
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1, "only the new key is held")
		XCTAssertEqual(BeamioVoiceEphemeral.sign(sid: sidA, wk: Data(repeating: 1, count: 32).base64EncodedString(), relayKeyId: "ab", timestamp: 1).isFailureUnknown, true, "the expired key is gone")
	}

	func testAnExpiredKeyIsWipedAtTheNextSignAndAcceptText() {
		_ = BeamioVoiceEphemeral.enroll(sid: sidA, expiresAt: 1_100)
		_ = BeamioVoiceEphemeral.enroll(sid: sidB, expiresAt: 5_000)
		BeamioVoiceEphemeral.testClock = 1_200
		BeamioWipeProbe.start()
		// a sign for the live channel finds and drops the expired one
		let wk = Data(repeating: 1, count: 32).base64EncodedString()
		if case .failure = BeamioVoiceEphemeral.sign(sid: sidB, wk: wk, relayKeyId: "ab", timestamp: 1) { XCTFail("the live channel signs") }
		XCTAssertEqual(wipes().count, 1)
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1)
		// the same through the accept text
		_ = BeamioVoiceEphemeral.enroll(sid: sidC, expiresAt: 1_300)
		BeamioVoiceEphemeral.testClock = 1_400
		BeamioWipeProbe.start()
		if case .failure = BeamioVoiceEphemeral.acceptText(sid: sidB) { XCTFail("the live channel answers") }
		XCTAssertEqual(wipes().count, 1)
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1)
	}

	func testAKeyThatIsStillLiveIsNotTouched() {
		_ = BeamioVoiceEphemeral.enroll(sid: sidA, expiresAt: 1_100)
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.testClock = 1_050
		_ = BeamioVoiceEphemeral.enroll(sid: sidB, expiresAt: 2_000)
		XCTAssertTrue(wipes().isEmpty)
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 2)
	}

	func testClearWipesTheKeyOfThatChannelOnly() {
		_ = BeamioVoiceEphemeral.enroll(sid: sidA, expiresAt: 9_000)
		_ = BeamioVoiceEphemeral.enroll(sid: sidB, expiresAt: 9_000)
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.clear(sid: sidA)
		let seen = wipes()
		XCTAssertEqual(seen.count, 1)
		XCTAssertTrue(seen.allSatisfy { $0.hadNonZero && $0.allZero })
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1)
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.clear(sid: sidA) // a sid with no key: a no-op
		XCTAssertTrue(wipes().isEmpty)
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 1)
		XCTAssertEqual(BeamioVoiceEphemeral.acceptText(sid: sidA).isUnknown, true, "the cleared channel has no key")
	}

	func testClearAllWipesEveryKey() {
		_ = BeamioVoiceEphemeral.enroll(sid: sidA, expiresAt: 9_000)
		_ = BeamioVoiceEphemeral.enroll(sid: sidB, expiresAt: 9_000)
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.clearAll()
		let seen = wipes()
		XCTAssertEqual(seen.count, 2)
		XCTAssertTrue(seen.allSatisfy { $0.hadNonZero && $0.allZero })
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0)
	}
}

private extension Result where Failure == BeamioVoiceEphemeral.Failure {
	var isFailureUnknown: Bool { if case .failure(.unknownChannel) = self { return true } else { return false } }
	var isUnknown: Bool { isFailureUnknown }
}
#endif

#if BEAMIO_TEST_HOOKS
/// Project owner's alternative A (2026-11-21): the shipped `voiceEphemeralSeal` fails closed, and the public call-end hook.
final class VoiceEphemeralAlternativeATests: XCTestCase {
	private let sid = String(repeating: "d4", count: 16)
	private final class KeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioVoiceEphemeral.clearAll()
		BeamioConetChatModule.legacySealForTests = false
		savedStore = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore
		BeamioVoiceEphemeral.clearAll()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	func testTheShippedSealAnswersUnknownCommandAndSealsNothing() {
		XCTAssertNotEqual(BeamioVoiceEphemeral.enroll(sid: sid, expiresAt: Int64.max - 1), .failed)
		var answers: [[String: Any]] = []
		let done = expectation(description: "answer")
		// a session at G2, so the command reaches its own handler (at G0 or G1 the gate answers first)
		let key = [UInt8](repeating: 0x11, count: 32)
		let account = BeamioNativeEthSigner.address(privateKey: key)!.lowercased()
		let store = KeyStore()
		_ = store.write(eoa: account, key: Data(key))
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		BeamioConetChatModule.handleCommand([
			"type": "voiceEphemeralSeal", "reqId": 4242, "sid": sid,
			"recipientPgpPublicArmored": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----",
		]) { out in
			let event = (out["event"] as? [String: Any]) ?? out
			if event["type"] as? String == "ack" { answers.append(event); done.fulfill() }
		}
		wait(for: [done], timeout: 10)
		XCTAssertEqual(answers.first?["ok"] as? Bool, false)
		XCTAssertEqual(answers.first?["error"] as? String, "unknown_command")
		XCTAssertNil(answers.first?["result"], "nothing sealed, nothing leaves")
		XCTAssertFalse(String(describing: answers).contains("BEGIN PGP MESSAGE"))
	}

	func testClearCallWipesEverySidAndIsIdempotent() {
		let other = String(repeating: "e5", count: 16)
		_ = BeamioVoiceEphemeral.enroll(sid: sid, expiresAt: Int64.max - 1)
		_ = BeamioVoiceEphemeral.enroll(sid: other, expiresAt: Int64.max - 1)
		BeamioWipeProbe.start()
		BeamioVoiceEphemeral.clearCall(sids: [sid, other, "not-a-sid", sid])
		let seen = BeamioWipeProbe.stop().filter { $0.count == 32 && $0.address == nil }
		XCTAssertEqual(seen.count, 2, "each held key overwritten once; a repeated, unknown or malformed sid is ignored")
		XCTAssertTrue(seen.allSatisfy { $0.hadNonZero && $0.allZero })
		XCTAssertEqual(BeamioVoiceEphemeral.heldCountForTests, 0)
		BeamioVoiceEphemeral.clearCall(sids: [])
	}
}
#endif
