import XCTest
@testable import ConetChatSDK

/// The static declaration of the QA candidate. The QA configuration defines BEAMIO_QA_BUILD and declares
/// identity.native-keys.v1 and identity.route-register.native.v1 in the hello list; the production configuration does not. Each side is checked
/// in its own configuration through the public `hello` command. Synthetic values only.
final class QABuildDeclarationTests: XCTestCase {
	/// An in-memory key store for the declared init. It is defined here, not taken from the hook-only test classes, so the QA configuration
	/// (which has no test hooks) compiles.
	private final class QAKeyStore: BeamioChatWalletKeyStoring {
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

	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		events = []
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		super.tearDown()
	}

	/// The capabilities of the `hello` answer, sent through the public command (`handleCommand`), not through the answer function.
	private func helloCapabilities() -> [String] {
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
		BeamioConetChatModule.handleCommand(["type": "hello", "reqId": 700], emit: { _ in })
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		let answer = events.compactMap { $0["event"] as? [String: Any] }.first {
			$0["type"] as? String == "ack" && $0["reqId"] as? Int == 700
		}
		return (answer?["result"] as? [String: Any])?["capabilities"] as? [String] ?? []
	}

#if BEAMIO_QA_BUILD
	/// The QA hello answer, sent through the public command, carries both declared capabilities.
	func testTheHelloCommandDeclaresBothCapabilitiesInTheQABuild() {
		let capabilities = helloCapabilities()
		XCTAssertTrue(capabilities.contains("identity.native-keys.v1"))
		XCTAssertTrue(capabilities.contains("identity.route-register.native.v1"))
	}

	/// The QA-only marker is the registered literal, and it exists only in this configuration.
	func testTheQAMarkerIsTheRegisteredLiteral() {
		XCTAssertEqual(BeamioConetChatProtocol.qaBuildMarker, "beamio-sdk-qa-only-marker")
	}

	/// With the declaration in force, `init` through the command path, with the account's key, reaches ready and G2, and the account is unchanged.
	func testTheDeclaredInitThroughTheCommandReachesG2() {
		let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
		let key = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
		let store = QAKeyStore()
		store.keys[account] = key
		let saved = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		defer { BeamioNativeWallet.keyStore = saved; BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false) }
		BeamioNativeAccountPointer.set(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
		defer { BeamioConetChatModule.nativeObserver = nil }
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 701, "payload": ["identity": ["eoaAddress": account] as [String: Any]]],
		                                    emit: { _ in })
		let deadline = Date().addingTimeInterval(60)
		while Date() < deadline && !events.contains(where: { ($0["event"] as? [String: Any])?["type"] as? String == "ready" }) {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		XCTAssertTrue(events.contains { ($0["event"] as? [String: Any])?["type"] as? String == "ready" }, "the declared init reaches ready")
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 702], emit: { _ in })
		RunLoop.current.run(until: Date().addingTimeInterval(0.2))
		let status = events.compactMap { ($0["event"] as? [String: Any]) }.first { $0["reqId"] as? Int == 702 }
		XCTAssertEqual((status?["result"] as? [String: Any])?["accountKey"] as? String, account + ":default", "the address is unchanged")
	}
#else
	/// The production hello, sent through the public command, declares neither capability: the QA declaration is not compiled in.
	/// The native key pair is shipped (25.52Y.121); the QA-only names stay out of the production build.
	func testTheHelloCommandDeclaresTheNativeKeyPairButNoQACapabilityInTheProductionBuild() {
		let capabilities = helloCapabilities()
		XCTAssertTrue(capabilities.contains("identity.native-keys.v1"))
		XCTAssertTrue(capabilities.contains("identity.kpresent.v1"))
		XCTAssertFalse(capabilities.contains("identity.route-register.native.v1"))
	}
#endif
}
