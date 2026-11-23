#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// (interface ruling on): a failure while `voiceEphemeralRegister` executes, after the gate and the arguments pass, answers
/// `register_failed`. It returns no address and no material, stores nothing, emits no event, and does not change an existing registration.
/// Synthetic data only; the failure is made by the test hook of the key generation.
final class VoiceEphemeralRegisterFailureTests: XCTestCase {
	/// The derivation test key (synthetic, public test material) derives this address.
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private let sid = "0123456789abcdef0123456789abcdef"
	private let now: Int64 = 1762000000

	/// An in-memory key store, local to this file.
	private final class Keys: BeamioChatWalletKeyStoring {
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
	private var events: [[String: Any]] = []

	override func setUp() {
		// the retired seal path (T sealed to the peer's OpenPGP key) is covered here only; the shipped command fails closed (alternative A)
		BeamioConetChatModule.legacySealForTests = true
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		let store = Keys()
		store.keys[account] = keyData
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
		BeamioVoiceEphemeral.clearAll()
		BeamioVoiceEphemeral.testClock = now
		BeamioVoiceEphemeral.testFailKeyGeneration = false
		// G2: the record of the account and its session ready (the gate of voiceEphemeralRegister).
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		events = []
		BeamioConetChatModule.nativeObserver = { out in
			// a session-end passcodeState event is not what this test counts
			if (out["event"] as? [String: Any])?["type"] as? String == "passcodeState" { return }
			self.events.append(out)
		}
	}

	override func tearDown() {
		BeamioConetChatModule.legacySealForTests = false
		BeamioVoiceEphemeral.testFailKeyGeneration = false
		BeamioConetChatModule.nativeObserver = nil
		BeamioVoiceEphemeral.testClock = nil
		BeamioVoiceEphemeral.clearAll()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func answers(_ reqId: String) -> [[String: Any]] {
		events.compactMap { $0["event"] as? [String: Any] }.filter { ($0["reqId"] as? String) == reqId }
	}

	private func waitForAnswer(_ reqId: String) {
		let deadline = Date().addingTimeInterval(10)
		while answers(reqId).isEmpty && Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
	}

	func testAFailureWhileRegisteringAnswersRegisterFailedAndLeavesNothing() {
		BeamioVoiceEphemeral.testFailKeyGeneration = true
		BeamioConetChatModule.handleCommand(["type": "voiceEphemeralRegister", "reqId": "f1", "sid": sid, "expiresAt": now + 600], emit: { _ in })
		waitForAnswer("f1")
		let got = answers("f1")
		XCTAssertEqual(got.count, 1, "exactly one answer, and no event")
		XCTAssertEqual(got.first?["type"] as? String, "ack")
		XCTAssertEqual(got.first?["ok"] as? Bool, false)
		XCTAssertEqual(got.first?["error"] as? String, "register_failed")
		XCTAssertNil(got.first?["result"], "no address and no material")
		XCTAssertEqual(Set((got.first ?? [:]).keys), ["type", "reqId", "ok", "error"], "the answer has only the error fields")
		XCTAssertEqual(events.count, 1, "the failure emits no other event")
		BeamioVoiceEphemeral.testFailKeyGeneration = false
		XCTAssertEqual(BeamioVoiceEphemeral.acceptText(sid: sid), .failure(.unknownChannel), "nothing is stored after the failure")
	}

	func testAFailureDoesNotReviveOrReplaceAnExpiredRegistration() {
		guard case .registered = BeamioVoiceEphemeral.enroll(sid: sid, expiresAt: now + 60) else { return XCTFail("the first registration succeeds") }
		BeamioVoiceEphemeral.testClock = now + 120   // the registration has expired
		BeamioVoiceEphemeral.testFailKeyGeneration = true
		XCTAssertEqual(BeamioVoiceEphemeral.enroll(sid: sid, expiresAt: now + 600), .failed)
		BeamioVoiceEphemeral.testFailKeyGeneration = false
		XCTAssertEqual(BeamioVoiceEphemeral.acceptText(sid: sid), .failure(.unknownChannel), "the expired registration is not revived")
	}
}
#endif
