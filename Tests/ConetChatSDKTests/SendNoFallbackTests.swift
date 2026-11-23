#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Regression tests for the 2026-11-12 items: a failed entry-route wrap is a failure (never the inner armor), a roster
/// node keeps its PGP key across store and load, and the native gate is G1 while the session is not ready or destroyed.
/// Synthetic values only. Not a PGP key: the wrap tests use an invalid key on purpose, so the JS path must fail.
final class SendNoFallbackTests: XCTestCase {
	private let innerArmor = "-----BEGIN PGP MESSAGE-----\nAAAA\n-----END PGP MESSAGE-----"
	private let notAKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-not-a-key\n-----END PGP PUBLIC KEY BLOCK-----"
	private let account = "0x5e5e000000000000000000000000000000000001"

	/// In-memory native store for the gate tests (the signer's key check reads it).
	final class MemoryKeyStore: BeamioChatWalletKeyStoring {
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

	private var savedStore: BeamioChatWalletKeyStoring!
	private var store: MemoryKeyStore!

	override func setUp() {
		super.setUp()
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		store = MemoryKeyStore()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
		BeamioConetChatSignBroker.clearSigner()
	}

	override func tearDown() {
		BeamioConetChatSignBroker.clearSigner()
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		BeamioChatPgpKeychain.memory = nil
		super.tearDown()
	}

	// MARK: - Wrap: a failure is a failure

	func testWrapRefusesInputThatIsNotArmor() {
		let done = expectation(description: "wrap")
		BeamioOpenPgpHost.shared.wrapArmorToEntryRoute(innerArmor: "plain text", entryRoutePublicArmor: notAKey) { result in
			if case .success = result { XCTFail("plain text must not come back as a wrapped result") }
			done.fulfill()
		}
		wait(for: [done], timeout: 20)
	}

	func testWrapRefusesWithoutAnEntryKey() {
		let done = expectation(description: "wrap")
		BeamioOpenPgpHost.shared.wrapArmorToEntryRoute(innerArmor: innerArmor, entryRoutePublicArmor: "") { result in
			if case .success = result { XCTFail("an entry without a key must not be wrapped to") }
			done.fulfill()
		}
		wait(for: [done], timeout: 20)
	}

	/// The JS path fails on an invalid key. The inner armor must not come back as a success (the old silent fallback).
	func testWrapWithAnInvalidEntryKeyFailsAndDoesNotReturnTheInnerArmor() {
		let done = expectation(description: "wrap")
		BeamioOpenPgpHost.shared.wrapArmorToEntryRoute(innerArmor: innerArmor, entryRoutePublicArmor: notAKey) { result in
			switch result {
			case .success(let out):
				XCTFail("a failed wrap came back as success: \(out.prefix(40))")
			case .failure:
				break
			}
			done.fulfill()
		}
		wait(for: [done], timeout: 20)
	}

	// MARK: - Roster: the entry key stays with the node

	func testParseSiNodesKeepsTheArmoredKeyAndAcceptsRowsWithoutOne() {
		let rows: [[String: Any]] = [
			["ip": "10.0.0.1", "domain": "n1.example", "region": "r", "armoredPublicKey": notAKey],
			["ip": "10.0.0.2", "pgpPublicKeyArmored": notAKey],
			["ip": "10.0.0.3"],
		]
		let nodes = BeamioChatPgpKeychain.parseSiNodes(rows)
		XCTAssertEqual(nodes.count, 3)
		XCTAssertEqual(nodes[0].armoredPublicKey, notAKey)
		XCTAssertEqual(nodes[1].armoredPublicKey, notAKey)
		XCTAssertEqual(nodes[2].armoredPublicKey, "", "a row with no key stays keyless (the senders skip it)")
	}

	func testStoredRosterKeepsEachNodesKeyAcrossALoad() {
		let withKey = BeamioChatPgpKeychain.SiNode(ip: "10.0.0.1", domain: "n1.example", region: "r", armoredPublicKey: notAKey)
		let noKey = BeamioChatPgpKeychain.SiNode(ip: "10.0.0.2", domain: "", region: "")
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: [withKey, noKey], mailboxIp: "10.0.0.9"))
		let loaded = BeamioChatPgpKeychain.loadSiNodes()
		XCTAssertEqual(loaded.count, 2)
		XCTAssertEqual(loaded.first(where: { $0.ip == "10.0.0.1" })?.armoredPublicKey, notAKey)
		XCTAssertEqual(loaded.first(where: { $0.ip == "10.0.0.2" })?.armoredPublicKey, "")
	}

	/// A key the page sends fills a roster node that has none. It never replaces a stored key, and adds or removes no node.
	func testAPageKeyFillsAnEmptyRosterKeyOnlyAndNeverReplacesOne() {
		let stored = [
			BeamioChatPgpKeychain.SiNode(ip: "10.0.0.1", domain: "n1.example", region: "r"),
			BeamioChatPgpKeychain.SiNode(ip: "10.0.0.2", domain: "", region: "", armoredPublicKey: notAKey),
		]
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: stored, mailboxIp: nil))
		BeamioConetChatModule.persistEntryKeys([
			BeamioConetChatModule.Node(ip: "10.0.0.1", domain: "n1.example", region: "r", armoredPublicKey: notAKey),
			BeamioConetChatModule.Node(ip: "10.0.0.2", domain: "", region: "", armoredPublicKey: "page-key-that-must-not-win"),
			BeamioConetChatModule.Node(ip: "10.0.0.3", domain: "", region: "", armoredPublicKey: notAKey),
		])
		let loaded = BeamioChatPgpKeychain.loadSiNodes()
		XCTAssertEqual(loaded.count, 2, "no node is added")
		XCTAssertEqual(loaded.first(where: { $0.ip == "10.0.0.1" })?.armoredPublicKey, notAKey)
		XCTAssertEqual(loaded.first(where: { $0.ip == "10.0.0.2" })?.armoredPublicKey, notAKey, "a stored key is not replaced")
	}

	// MARK: - Native gate: a session that is not ready, or destroyed, is not G2

	func testGateIsG1WhileTheSessionIsNotReadyEvenWithTheSignerSet() {
		XCTAssertTrue(BeamioNativeWallet.keyStore.write(eoa: account, key: Data(repeating: 0x11, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		BeamioConetChatSignBroker.setSignerEoa(account)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
	}

	func testGateIsG2OnlyWhenTheSessionIsReadyForTheRecordAccount() {
		XCTAssertTrue(BeamioNativeWallet.keyStore.write(eoa: account, key: Data(repeating: 0x11, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
	}

	func testDestroyClearsTheSignerAndTheGateIsG1() {
		XCTAssertTrue(BeamioNativeWallet.keyStore.write(eoa: account, key: Data(repeating: 0x11, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		BeamioConetChatSignBroker.setSignerEoa(account)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		BeamioConetChatModule.handleCommand(["type": "destroy", "reqId": 1], emit: { _ in })
		XCTAssertEqual(BeamioConetChatSignBroker.currentSignerEoa(), "", "a destroyed session signs nothing")
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1, "the record is still there, the session is gone")
	}
}
#endif
