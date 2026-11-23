import Foundation
import XCTest
@testable import ConetChatSDK

/// W7 `ephemeralSign`: the only purpose is `voiceListen`. The spec's inputs are sid, wk, relayKeyId and
/// timestamp; a request with no `kind` is the voiceListen purpose, an explicit `voiceListen` is accepted, and any other purpose is
/// bad_request. An unregistered sid is unknown_channel for the listen purpose. No key material is returned. Synthetic values only.
final class W7VoiceListenPurposeTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let sid = "0123456789abcdef0123456789abcdef"
	private let unknownSid = "ffffffffffffffffffffffffffffffff"
	private let wk = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw="
	private var savedStore: BeamioChatWalletKeyStoring?
	private var events: [[String: Any]] = []

	/// In-memory native store holding the synthetic account key (the wallet module's store in tests).
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		let store = Store()
		store.keys[account] = Data(repeating: 0x42, count: 32)
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
		XCTAssertTrue(BeamioVoiceEphemeral.register(sid: sid, privateKey: [UInt8](repeating: 0x5a, count: 32)))
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioVoiceEphemeral.clear(sid: sid)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// The answer to one request, read after the main queue has delivered it.
	private func answer(_ body: [String: Any]) -> [String: Any]? {
		let reqId = body["reqId"] as? Int ?? -1
		events = []
		BeamioConetChatModule.handleCommand(body, emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while Date() < deadline && !events.contains(where: { ($0["event"] as? [String: Any])?["reqId"] as? Int == reqId }) {
			RunLoop.current.run(until: Date().addingTimeInterval(0.02))
		}
		return events.compactMap { $0["event"] as? [String: Any] }.first { $0["reqId"] as? Int == reqId }
	}

	private func body(reqId: Int, sid: String? = nil, kind: Any? = nil) -> [String: Any] {
		var body: [String: Any] = [
			"type": "ephemeralSign", "reqId": reqId, "sid": sid ?? self.sid, "wk": wk,
			"relayKeyId": "SYN-PGPKEYID-A-0001", "timestamp": 1762992000,
		]
		if let kind { body["kind"] = kind }
		return body
	}

	/// An absent kind is the voiceListen purpose (the spec's inputs do not carry a kind): the signature is returned.
	func testAnAbsentKindIsTheVoiceListenPurpose() {
		let out = answer(body(reqId: 1))
		XCTAssertEqual(out?["ok"] as? Bool, true)
		let result = out?["result"] as? [String: Any]
		XCTAssertEqual(Set(result?.keys ?? [:].keys), ["temp", "tempSig"], "no key material is returned")
	}

	/// An explicit voiceListen is accepted, with the same answer shape.
	func testAnExplicitVoiceListenKindIsAccepted() {
		let out = answer(body(reqId: 2, kind: "voiceListen"))
		XCTAssertEqual(out?["ok"] as? Bool, true)
		XCTAssertEqual(Set((out?["result"] as? [String: Any] ?? [:]).keys), ["temp", "tempSig"])
	}

	/// Any other purpose is bad_request, and nothing is signed: the W5 voice purpose and malformed kinds are not W7.
	func testAnyOtherPurposeIsBadRequest() {
		for (index, kind) in ["voicePay", "voice", "text", ""].enumerated() {
			let out = answer(body(reqId: 10 + index, kind: kind))
			XCTAssertEqual(out?["error"] as? String, "bad_request", "kind \(kind)")
			XCTAssertNil(out?["result"], "kind \(kind): no signature")
		}
	}

	/// The listen purpose with a sid that has no key: unknown_channel, the new code.
	func testAnUnregisteredSidWithTheListenPurposeIsUnknownChannel() {
		let out = answer(body(reqId: 30, sid: unknownSid, kind: "voiceListen"))
		XCTAssertEqual(out?["error"] as? String, "unknown_channel")
		XCTAssertNil(out?["result"])
	}
}
