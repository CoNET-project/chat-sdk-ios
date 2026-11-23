import XCTest
@testable import ConetChatSDK

/// (`pgpDecrypt` deleted), and, and step 3: a name that is not in table T is answered
/// `unknown_command`, exactly once, before the gate, in G0, G1 and G2. The 26 names are the list of the release audit
/// (item 2a): the four NOT_BRIDGE names, `pgpDecrypt` (deleted by), and the 21 names of `innerUnknown.names`.
/// Default-on: no vector file and no environment variable is needed. Synthetic data only.
final class CK3InnerUnknownNameTests: XCTestCase {
	/// `innerUnknown.names` of `gate-state-vectors.v1.json`:, the 13 outer gated names and `identity.provision`.
	static let innerUnknownNames: [String] = [
		"saveRecoveryQrToPhotos", "scanRecoveryQr", "startPhysicalCardBind",
		"notifyVoiceMicReady", "queryIncomingCallOutcome", "startNativeVoiceMic", "cacheCallerAvatars",
		"prepareSystemCall", "cancelPreparedSystemCall", "startSystemCall", "reportIncomingSystemCall", "endSystemCall",
		"clearOfflineChatAlerts", "notifyBackgroundChat", "postPgpCiphertext", "setNativeVoiceRelayNodes", "setNativeSiNodeRoster",
		"chatModuleSignResponse", "bindPushIdentity", "registerPushDeviceHttp",
		"identity.provision",
	]
	/// NOT_BRIDGE_NAMES: never bridge commands. `signMessage` is answered `unknown_command` in every state.
	static let notBridgeNames = ["deriveLocalKeys", "protocolKeys", "fragmentKeys", "signMessage"]
	/// Deleted by (NK-W6b). Its iOS answer is `unknown_command`.
	static let deletedNames = ["pgpDecrypt"]
	static var allNames: [String] { innerUnknownNames + notBridgeNames + deletedNames }

	private final class Store: BeamioChatWalletKeyStoring {
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

	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// Sends one command and returns every answer it produced for its reqId, after the main queue has drained.
	private func answers(_ body: [String: Any], reqId: Int) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any], event["reqId"] as? Int == reqId { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		return events
	}

	/// One answer, `ok: false`, `unknown_command`. Any second answer for the same reqId fails the case.
	private func assertUnknownOnce(_ name: String, reqId: Int, state: String, file: StaticString = #filePath, line: UInt = #line) {
		let got = answers(["type": name, "reqId": reqId], reqId: reqId)
		XCTAssertEqual(got.count, 1, "\(name) in \(state): exactly one answer", file: file, line: line)
		XCTAssertEqual(got.first?["ok"] as? Bool, false, "\(name) in \(state): ok false", file: file, line: line)
		XCTAssertEqual(got.first?["error"] as? String, "unknown_command", "\(name) in \(state): unknown_command", file: file, line: line)
	}

	func testTheTwentySixNamesAreTheAuditList() {
		XCTAssertEqual(Self.innerUnknownNames.count, 21)
		XCTAssertEqual(Set(Self.allNames).count, 26, "the four groups do not overlap")
	}

	func testNoneOfTheTwentySixIsAKnownBridgeName() {
		for name in Self.allNames {
			XCTAssertFalse(BeamioConetChatModule.knownBridgeCommand(name), "\(name) must not be a known bridge name")
			XCTAssertFalse(BeamioConetChatModule.dispatchedCommands.contains(name), "\(name) must not be dispatched")
			XCTAssertFalse(BeamioConetChatModule.noKeyCommandTable.contains(name), "\(name) must not be in table T")
		}
	}

	func testEachNameIsUnknownCommandOnceBeforeTheGateAtG0() {
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g0)
		for (index, name) in Self.allNames.enumerated() {
			assertUnknownOnce(name, reqId: 1000 + index, state: "G0")
		}
	}

	#if BEAMIO_TEST_HOOKS
	/// G1 (a record, the session not ready) and G2 (the session ready for the record's account). The gate would answer `not_ready` or
	/// `no_key`, so an `unknown_command` answer shows that the name check comes first (step 3).
	func testEachNameIsUnknownCommandOnceBeforeTheGateAtG1AndG2() {
		let account = PgpMigrationTestSupport.eoa
		XCTAssertTrue(store.write(eoa: account, key: Data(repeating: 7, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "the record without a ready session is G1")
		for (index, name) in Self.allNames.enumerated() {
			assertUnknownOnce(name, reqId: 2000 + index, state: "G1")
		}
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2, "the ready session for the record's account is G2")
		for (index, name) in Self.allNames.enumerated() {
			assertUnknownOnce(name, reqId: 3000 + index, state: "G2")
		}
	}
	#endif
}
