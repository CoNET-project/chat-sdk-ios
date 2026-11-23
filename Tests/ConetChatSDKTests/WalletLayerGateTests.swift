import XCTest
@testable import ConetChatSDK

/// The wallet layer of W2 `deriveLocalKeys`, W3 `protocolKeys` and W4 `fragmentKeys` (spec,). These are native functions, not
/// bridge commands. The checks call the native gate function and the wallet functions directly, with no `handleCommand`. The required answers: G0
/// `no_key`, G1 `not_ready` (the rows NK-W2 to NK-W4 and G1-NK-W2 to G1-NK-W4, layer wallet). Synthetic data only.
final class WalletLayerGateTests: XCTestCase {
	/// The four names the bridge answers `unknown_command` and whose wallet answers are native: W2, W3, W4, and `signMessage` (W5).
	private let names = ["deriveLocalKeys", "protocolKeys", "fragmentKeys", "signMessage"]
	private let account = PgpMigrationTestSupport.eoa

	/// A key store with no record: the G0 state of the device.
	private final class EmptyWalletStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { [] }
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { [] }   // the mnemonic ownership rule: an empty store lists no account
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	/// the native gate function answers `no_key` for each of the three names in G0.
	func testTheNativeGateAnswersNoKeyInG0() {
		for name in names {
			XCTAssertEqual(BeamioConetChatModule.gateRefusal(type: name, gate: .g0), "no_key", "\(name) in G0")
		}
	}

	/// the native gate function answers `not_ready` for each of the three names in G1 (a record, no session).
	func testTheNativeGateAnswersNotReadyInG1() {
		for name in names {
			XCTAssertEqual(BeamioConetChatModule.gateRefusal(type: name, gate: .g1), "not_ready", "\(name) in G1")
		}
	}

	/// The gate refuses nothing in G2 for these names: the wallet function then decides (none of them is a bridge name,).
	func testTheNativeGateRefusesNothingInG2() {
		for name in names {
			XCTAssertNil(BeamioConetChatModule.gateRefusal(type: name, gate: .g2), "\(name) in G2")
		}
	}

	/// The wallet functions answer nothing without a key (G0): `localSubkeys` (W2), `protocolValues` (W3), and `historyMaster` (the master from which
	/// W4 derives its fragment keys). The store is empty, so no value is derived and nothing is returned.
	func testTheWalletFunctionsReturnNothingWithoutAKey() {
		let savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		BeamioNativeWallet.keyStore = EmptyWalletStore()
		defer {
			BeamioNativeWallet.keyStore = savedStore
			NativeAccountPointerIsolation.end()
		}
		XCTAssertNil(BeamioConetChatModule.localSubkeys(account: account), "W2 without a key (G0)")
		XCTAssertNil(BeamioConetChatModule.protocolValues(account: account), "W3 without a key (G0)")
		XCTAssertNil(BeamioNativeWallet.historyMaster(eoa: account, chainId: 224422), "the W4 master without a key (G0)")
	}

	/// A key store holding the synthetic test key of the account (the key the derivation vectors use), as the G1 and G2 states need.
	private final class KeyWalletStore: BeamioChatWalletKeyStoring {
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

	/// The gate states of the native wallet functions: the store holds the synthetic test key of the account in G1 and G2, and none
	/// in G0. The record and the session are set through the test gate, as the gate functions read them.
	private func arrangeGate(_ gate: String) -> () -> Void {
		let savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		let store = KeyWalletStore()
		if gate != "G0" {
			store.keys[account.lowercased()] = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
		}
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
		switch gate {
		case "G0": BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		case "G1": BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		default:
			BeamioConetChatSignBroker.setSignerEoa(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		}
		return {
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
	}

	/// The values of the wallet functions behind W2 (`localSubkeys`), W3 (`protocolValues`), W4 (the history master the fragment keys come from), and the
	/// signMessage kinds (`signEip191`, `signSetPointer`, the account-key path). Each is called with a valid input.
	private func walletFunctionAnswers() -> [String: Bool] {
		// (F3): the wallet functions answer for the signer's account (the session's account).
		BeamioConetChatSignBroker.setSignerEoa(account)
		defer { BeamioConetChatSignBroker.clearSigner() }
		let registry = "0x" + String(repeating: "1", count: 40)
		let indexHash = "0x" + String(repeating: "2", count: 64)
		var answers: [String: Bool] = [:]
		answers["localSubkeys (W2)"] = BeamioConetChatModule.localSubkeys(account: account) != nil
		answers["protocolValues (W3)"] = BeamioConetChatModule.protocolValues(account: account) != nil
		answers["historyMaster (W4 master)"] = BeamioNativeWallet.historyMaster(eoa: account, chainId: 224422) != nil
		answers["localRoot"] = BeamioNativeWallet.localRoot(eoa: account) != nil
		if case .success = BeamioNativeWallet.signEip191(eoa: account, message: "SYNTHETIC-MESSAGE") { answers["signEip191 (signMessage)"] = true } else { answers["signEip191 (signMessage)"] = false }
		if case .success = BeamioNativeWallet.signSetPointer(eoa: account, registry: registry, indexHash: indexHash, ts: "1", seq: "1", nonce: "1") {
			answers["signSetPointer (signMessage pointer)"] = true
		} else {
			answers["signSetPointer (signMessage pointer)"] = false
		}
		if case .success = BeamioNativeWallet.withAccountKey(eoa: account, { _ in true }) { answers["withAccountKey (route registration)"] = true } else { answers["withAccountKey (route registration)"] = false }
		return answers
	}

	/// in G0 and G1 every wallet function answers nothing: no value, no signature, no key material.
	func testAtG0AndG1TheWalletFunctionsAnswerNothing() {
		for gate in ["G0", "G1"] {
			let restore = arrangeGate(gate)
			let answers = walletFunctionAnswers()
			restore()
			for (name, answered) in answers.sorted(by: { $0.key < $1.key }) {
				XCTAssertFalse(answered, "\(name) in \(gate) answers nothing")
			}
		}
	}

	/// in G2 for the account the same functions answer their values.
	func testAtG2TheWalletFunctionsAnswerTheirValues() {
		let restore = arrangeGate("G2")
		let answers = walletFunctionAnswers()
		restore()
		for (name, answered) in answers.sorted(by: { $0.key < $1.key }) {
			XCTAssertTrue(answered, "\(name) in G2 answers its value")
		}
	}

	/// A key store whose record exists and cannot be read: the storage-derived Locked state.
	private final class UnreadableWalletStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { nil }
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .unreadable }
	}

	/// the listen authentication of the background path signs in G1 for a readable record, through the listen-auth path only.
	/// Under a storage-derived Locked nothing is signed; with no record nothing is signed.
	func testTheListenAuthSignsInG1OnlyForAReadableRecord() {
		let savedStore = BeamioNativeWallet.keyStore
		NativeAccountPointerIsolation.begin()
		defer {
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		let readable = KeyWalletStore()
		readable.keys[account.lowercased()] = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
		BeamioNativeWallet.keyStore = readable
		XCTAssertFalse(BeamioNativeWallet.storageDerivedLocked(eoa: account), "a readable record is not the storage-derived Locked state")
		if case .failure = BeamioNativeWallet.signListenAuth(eoa: account, message: "SYNTHETIC-AUTH") {
			XCTFail("the listen auth signs in G1 for a readable record")
		}
		BeamioNativeWallet.keyStore = UnreadableWalletStore()
		XCTAssertTrue(BeamioNativeWallet.storageDerivedLocked(eoa: account), "the record exists and cannot be read")
		XCTAssertEqual(BeamioNativeWallet.signListenAuth(eoa: account, message: "SYNTHETIC-AUTH").failureValue, .storageUnreadable,
		               "under a storage-derived Locked nothing is signed")
		BeamioNativeWallet.keyStore = EmptyWalletStore()
		XCTAssertEqual(BeamioNativeWallet.signListenAuth(eoa: account, message: "SYNTHETIC-AUTH").failureValue, .walletKeyMissing,
		               "with no record nothing is signed")
	}
}

private extension Result where Failure == BeamioNativeWallet.Failure {
	/// The failure of a result, nil on success.
	var failureValue: BeamioNativeWallet.Failure? {
		if case .failure(let f) = self { return f }
		return nil
	}
}
