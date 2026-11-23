import XCTest
@testable import ConetChatSDK

/// S-1 acceptance, group A and the bridge answers of group B (T-147 `nativeImportOpen`,
/// T-155 `no_key`, vectors U-1 to U-5). Synthetic key 0x11…11 only; never a user key.
final class BridgeRetirementAcceptanceTests: XCTestCase {
	/// In-memory native store (the wallet module's store in tests).
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var writes = 0
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
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

	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let keyBytes = Data(repeating: 0x11, count: 32)
	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!
	private var emitted: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
		emitted = []
		BeamioConetChatSignBroker.setSignerEoa(eoa)
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// Sends one command through the bridge entry point and returns its ack. Every emitted event is kept in `emitted`.
	private func send(_ body: [String: Any]) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(body, emit: { [weak self] event in
			let inner = (event["event"] as? [String: Any]) ?? event
			self?.emitted.append(inner)
			if inner["type"] as? String == "ack" {
				ack = inner
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		return ack
	}

	// MARK: - Group A: the X-21 commands are retired (T-141, T-142)

	func testTheThreeX21CommandsAnswerNotSupportedAndEmitNoTransferEvents() {
		for (reqId, type) in [(10, "walletTransferOnce"), (11, "walletTransferStatus"), (12, "walletTransferSwitched")] {
			let ack = send(["type": type, "reqId": reqId, "payload": ["eoa": eoa], "requestId": "any", "kind": "eoaKey",
			                "bytes": [Int](repeating: 0x11, count: 32)])
			XCTAssertEqual(ack?["ok"] as? Bool, false, type)
			XCTAssertEqual(ack?["error"] as? String, "not_supported", type)
			XCTAssertNil(ack?["result"], "\(type) returns no bytes or state")
		}
		let types = emitted.compactMap { $0["type"] as? String }
		XCTAssertFalse(types.contains("walletTransferRequest"))
		XCTAssertFalse(types.contains("walletTransferResult"))
		XCTAssertNil(store.keys[eoa], "no key is stored")
		XCTAssertEqual(store.migrationPhase(eoa: eoa), .none, "no state changes")
	}

	// MARK: - Group A: no bridge command takes a private key (T-144)

	private var privateKeyPayloads: [([String: Any], String)] {
		[
			(["identity": ["eoaAddress": eoa, "privateKeyHex": "11"]], "privateKeyHex"),
			(["mnemonic": "synthetic words"], "mnemonic"),
			(["privateKeyArmor": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic\n-----END PGP PRIVATE KEY BLOCK-----"], "privateKeyArmor"),
			(["pgpPrivateKeyArmored": "synthetic"], "pgpPrivateKeyArmored"),
		]
	}

	/// With the account's native key present, a private-key field is refused with its name (T-144). The key is the gate's
	/// precondition: without it the answer is `no_key` (next test,).
	func testInitRefusesAPrivateKeyFieldWhenTheAccountHasAKey() {
		store.keys[eoa] = keyBytes
		// The record is on the device and the session has not completed init (G1): `init` is passed on to the refusal.
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		for (payload, field) in privateKeyPayloads {
			let ack = send(["type": "init", "reqId": 20, "payload": payload])
			XCTAssertEqual(ack?["ok"] as? Bool, false, field)
			XCTAssertEqual(ack?["error"] as? String, "key_over_bridge_refused", field)
			XCTAssertEqual(ack?["field"] as? String, field, "the field name is returned, never the value")
		}
		XCTAssertEqual(store.writes, 0, "nothing is stored from init")
	}

	/// Without a native record the same payloads are still refused as `key_over_bridge_refused`, before the gate.
	/// The field name is returned (never the value), in `field` and in the ack's `result.names`. Nothing is stored.
	func testInitWithAPrivateKeyFieldAndNoRecordIsRefusedBeforeTheGate() {
		for (payload, field) in privateKeyPayloads {
			let ack = send(["type": "init", "reqId": 21, "payload": payload])
			XCTAssertEqual(ack?["error"] as? String, "key_over_bridge_refused", field)
			XCTAssertEqual(ack?["field"] as? String, field, field)
			let names = (ack?["result"] as? [String: Any])?["names"] as? [String] ?? []
			XCTAssertTrue(names.contains { $0 == field || $0.hasSuffix("." + field) }, "the leaf path is in result.names")
		}
		XCTAssertEqual(store.writes, 0)
	}

	/// the identity commands refuse every name of CRED, not only the six of the vector. Each name is refused before the gate,
	/// with the field in `field` and its leaf path in `result.names`; the value is never echoed, and nothing is stored.
	func testEveryCredentialNameIsRefusedByTheIdentityCommands() {
		let value = "BG6-SYNTHETIC-VALUE"
		var checked = 0
		for name in BeamioConetChatModule.credentialFieldNames.sorted() {
			let flat: [String: Any] = ["type": "provisionIdentity", "reqId": 31, name: value]
			let nested: [String: Any] = ["type": "init", "reqId": 32, "payload": ["identity": [name: value]]]
			for (body, path) in [(flat, name), (nested, "payload.identity." + name)] {
				let ack = send(body)
				XCTAssertEqual(ack?["error"] as? String, "key_over_bridge_refused", name)
				XCTAssertEqual(ack?["field"] as? String, name, name)
				let names = (ack?["result"] as? [String: Any])?["names"] as? [String] ?? []
				XCTAssertTrue(names.contains(path), "\(name): the leaf path \(path) is in result.names")
				XCTAssertFalse(String(describing: ack ?? [:]).contains(value), "\(name): the value is never echoed")
				checked += 1
			}
		}
		XCTAssertEqual(checked, BeamioConetChatModule.credentialFieldNames.count * 2, "every CRED name, for both identity commands")
		XCTAssertEqual(store.writes, 0, "nothing is stored from the identity commands")
	}

	// MARK: - Group B: the native import is opened by the page (T-147)

	/// r2.3 (spec 第 41(1) 项): `nativeImportOpen` is not registered. It opens no page and writes nothing.
	func testNativeImportOpenOpensTheNativePageAndCarriesNoData() {
		let ack = send(["type": "nativeImportOpen", "reqId": 30])
		XCTAssertEqual(ack?["error"] as? String, "unknown_command")
		XCTAssertNil(store.keys[eoa], "nothing is written")
	}

	// MARK: - Group B: `no_key` and the account (T-155, vectors U-1, U-3, U-5)

	func testWalletAddressIsNoKeyWithoutANativeRecord() {
		let ack = send(["type": "walletAddress", "reqId": 40])
		XCTAssertEqual(ack?["ok"] as? Bool, false)
		XCTAssertEqual(ack?["error"] as? String, "no_key")
		XCTAssertNil(ack?["result"], "no data is returned without a key")
	}

	func testWalletAddressReturnsTheAccountWhenTheNativeRecordIsPresent() {
		store.keys[eoa] = keyBytes
		// G2: the session has completed init for the record account.
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		let ack = send(["type": "walletAddress", "reqId": 41])
		XCTAssertEqual(ack?["ok"] as? Bool, true)
		XCTAssertEqual((ack?["result"] as? [String: Any])?["address"] as? String, eoa)
		XCTAssertEqual(store.writes, 0, "an upgrade with a native record writes nothing")
	}

	func testPasscodeStatusReportsHasKey() {
		let without = send(["type": "passcodeStatus", "reqId": 42])
		XCTAssertEqual((without?["result"] as? [String: Any])?["hasKey"] as? Bool, false)
		store.keys[eoa] = keyBytes
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		let with = send(["type": "passcodeStatus", "reqId": 43])
		XCTAssertEqual((with?["result"] as? [String: Any])?["hasKey"] as? Bool, true)
	}
}
