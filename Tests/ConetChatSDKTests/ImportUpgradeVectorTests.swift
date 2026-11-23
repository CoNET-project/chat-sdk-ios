import CryptoKit
import XCTest
@testable import ConetChatSDK

/// import-upgrade-vectors.v1.json: the 19 cases, run against the native code. Synthetic key
/// only. Runs with IMPORT_UPGRADE_VECTORS=<path to the file>;
/// skipped without it. The expectations are the vector file's, never adjusted to the code.
final class ImportUpgradeVectorTests: XCTestCase {
	static let expectedSHA256 = "0e0a5c88657f1a519254aae8ef9b0218614430d006fd84e58c3415493a5e928b"

	/// In-memory native store with the failure injections of the vectors (writeFail, readbackFail).
	final class Store: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var failWrite = false
		var corruptReadBack = false
		var writes = 0
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			if failWrite { return false }
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? {
			guard let k = keys[eoa.lowercased()] else { return nil }
			return corruptReadBack ? Data(repeating: 0xEE, count: k.count) : k
		}
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

	private let eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
	private let keyHex = "78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd"
	private let otherRecord = Data(repeating: 0x22, count: 32)
	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.setSignerEoa(eoa)
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func cases() throws -> [[String: Any]] {
		guard let path = ProcessInfo.processInfo.environment["IMPORT_UPGRADE_VECTORS"] else {
			throw XCTSkip("set IMPORT_UPGRADE_VECTORS to interface/protocol/import-upgrade-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256, "vector file sha256 differs from the published value (the digest is not printed, so a failure leaves no digest in the log)")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		return try XCTUnwrap(root["cases"] as? [[String: Any]])
	}

	private func keyData() -> Data {
		var out: [UInt8] = []
		var i = keyHex.startIndex
		while i < keyHex.endIndex {
			let j = keyHex.index(i, offsetBy: 2)
			out.append(UInt8(keyHex[i ..< j], radix: 16) ?? 0)
			i = j
		}
		return Data(out)
	}

	/// One bridge command and its ack (the same entry point the page uses).
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

	func testAllNineteenCasesMatchTheVectors() throws {
		for c in try cases() {
			let id = c["id"] as? String ?? "?"
			let expect = c["expect"] as? [String: Any] ?? [:]
			let code = expect["code"] as? String ?? ""
			store = Store()
			BeamioNativeWallet.keyStore = store
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			if let action = c["action"] as? String {
				let state = c["state"] as? [String: Any] ?? [:]
				if state["native"] as? String == "present" {
					store.keys[eoa] = keyData()
					// U-3 expects the wallet answer, which the gate gives in G2 (the vector does not name a session state).
					BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
				}
				let ack = send(["type": action, "reqId": 1, "payload": ["eoa": eoa], "requestId": "any", "kind": "eoaKey",
				                "bytes": [Int](repeating: 0x11, count: 32)])
				XCTAssertEqual(ack?["ok"] as? Bool, code == "ok", id)
				if code == "ok" {
					XCTAssertEqual((ack?["result"] as? [String: Any])?["address"] as? String, expect["address"] as? String, id)
				} else {
					XCTAssertEqual(ack?["error"] as? String, code, id)
					XCTAssertNil(ack?["result"], "\(id): no data is returned")
				}
				if let after = expect["nativeRecordAfter"] as? String {
					XCTAssertEqual(store.keys[eoa] != nil, after == "present", id)
				}
				XCTAssertEqual(store.writes, 0, "\(id): nothing is written by a bridge command")
				continue
			}
			// Import cases: the input text against the account context.
			let ctx = c["ctx"] as? [String: Any] ?? [:]
			let input = c["input"] as? String ?? ""
			if ctx["nativeRecord"] as? Bool == true { store.keys[eoa] = otherRecord }
			store.failWrite = ctx["writeFail"] as? Bool ?? false
			store.corruptReadBack = ctx["readbackFail"] as? Bool ?? false
			let outcome: BeamioNativeKeyImport.Outcome = (ctx["cancelled"] as? Bool == true)
				? .cancelled
				: BeamioNativeKeyImport.importPrivateKey(text: input, expectedEoa: ctx["expectedEoa"] as? String ?? "", store: store)
			XCTAssertEqual(outcome.code, code, id)
			if code == "ok" {
				XCTAssertEqual(expect["eoa"] as? String, eoa, id)
				XCTAssertEqual(store.keys[eoa], keyData(), "\(id): the record is written and read back")
			} else if ctx["nativeRecord"] as? Bool == true {
				XCTAssertEqual(store.keys[eoa], otherRecord, "\(id): an existing record is not overwritten")
			} else {
				XCTAssertNil(store.keys[eoa], "\(id): no record is left behind")
			}
		}
	}
}
