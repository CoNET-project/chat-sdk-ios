import CryptoKit
import XCTest
@testable import ConetChatSDK

/// B8: the private-key import cases I-1 to I-3 of import-upgrade-vectors.v1.json answer `ok` with the
/// expected account and the state NO_PASSCODE, and the wallet and the chat are usable afterwards. Synthetic key P
/// only (SHA-256 of "chat-local-test-private-key-v1"). Runs with IMPORT_UPGRADE_VECTORS=<path>; skipped without it.
///
/// "Chat usable" is checked by the identity answer the page reads after the import. It does not start a live session:
/// `init` would open the mailbox, and that is outside a unit test.
final class PrivateKeyImportCompletionTests: XCTestCase {
	static let expectedSHA256 = "0e0a5c88657f1a519254aae8ef9b0218614430d006fd84e58c3415493a5e928b"

	/// In-memory native store with the write and read-back failure injections (none are used here).
	final class ImportStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool {
			keys[eoa.lowercased()] = key
			return true
		}
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

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func importCases() throws -> [[String: Any]] {
		guard let path = ProcessInfo.processInfo.environment["IMPORT_UPGRADE_VECTORS"] else {
			throw XCTSkip("set IMPORT_UPGRADE_VECTORS to interface/protocol/import-upgrade-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
		              "vector file sha256 differs from the published value (the digest is not printed)")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return cases.filter { ($0["id"] as? String ?? "").hasPrefix("I-") }
	}

	/// One bridge command through the entry point; returns its ack.
	private func send(_ body: [String: Any]) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(body, emit: { event in
			let inner = (event["event"] as? [String: Any]) ?? event
			if inner["type"] as? String == "ack" {
				ack = inner
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		return ack
	}

	func testThePrivateKeyImportLeavesTheWalletAndTheChatUsable() throws {
		let cases = try importCases()
		XCTAssertEqual(cases.count, 3, "I-1 to I-3")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? String ?? ""
			let ctx = c["ctx"] as? [String: Any] ?? [:]
			let expect = c["expect"] as? [String: Any] ?? [:]
			let eoa = expect["eoa"] as? String ?? ""

			// A fresh native store and no session: a new install before the import (G0).
			let store = ImportStore()
			BeamioNativeWallet.keyStore = store
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)

			let outcome = BeamioNativeKeyImport.importPrivateKey(text: input, expectedEoa: ctx["expectedEoa"] as? String ?? "", store: store)
			XCTAssertEqual(outcome.code, expect["code"] as? String, id)
			XCTAssertEqual(store.keys[eoa]?.count, 32, "\(id): the derived key is written and read back")

			// After the import the device holds the record, and this session has not completed init: G1.
			// NO_PASSCODE: set false, locked false, and the record is present (device-level, hasKey true).
			let status = send(["type": "passcodeStatus", "reqId": 1])?["result"] as? [String: Any]
			XCTAssertEqual(status?["set"] as? Bool, false, "\(id): NO_PASSCODE, set")
			XCTAssertEqual(status?["locked"] as? Bool, false, "\(id): NO_PASSCODE, locked")
			XCTAssertEqual(status?["hasKey"] as? Bool, true, "\(id): the native record is present")
			// Before init the wallet and the chat answer `not_ready`, not `no_key` (the record exists).
			XCTAssertEqual(send(["type": "walletAddress", "reqId": 2])?["error"] as? String, "not_ready", "\(id): G1 before init")

			// The page then sends init, which completes for the record account: G2. The wallet and the chat answer.
			// init sets the signer account as well (handleInit), so the wallet answers for it.
			BeamioConetChatSignBroker.setSignerEoa(eoa)
			BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
			let wallet = send(["type": "walletAddress", "reqId": 3])
			XCTAssertEqual(wallet?["ok"] as? Bool, true, "\(id): the wallet is usable")
			XCTAssertEqual((wallet?["result"] as? [String: Any])?["address"] as? String, eoa, "\(id): the wallet account")

			// The chat side: identity.provision (bridge name provisionIdentity). The shipped list declares identity.native-keys.v1
			// (25.52Y.121), so the `{ready, eoa}` form applies in every build: ready, because the key derives the account.
			let provision = send(["type": "provisionIdentity", "reqId": 4, "payload": ["eoa": eoa]])
			XCTAssertEqual(provision?["ok"] as? Bool, true, "\(id): identity.provision answers")
			XCTAssertEqual((provision?["result"] as? [String: Any])?["ready"] as? Bool, true, "\(id): the chat sees the key for the account")
			XCTAssertNil((provision?["result"] as? [String: Any])?["present"], "\(id): the native-keys form carries no legacy present field")
		}
	}
}
