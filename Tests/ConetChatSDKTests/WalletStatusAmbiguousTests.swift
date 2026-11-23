import XCTest
@testable import ConetChatSDK

/// 25.52Y.159 (A): with several native keys and no account pointer (the snapshot is ambiguous), walletStatus answers not_ready with
/// notReadyReason unreadable, never no_key. Nothing is chosen, written or deleted. The QA state line carries no address.
final class WalletStatusAmbiguousTests: XCTestCase {
	private var savedStore: BeamioChatWalletKeyStoring?
	private let keyA = Data(repeating: 0x11, count: 32)
	private let keyB = Data(repeating: 0x22, count: 32)
	private var keyStore = MemoryNativeKeyStore()

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeAccountPointer.clear()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioNativeAccountPointer.clear()
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func flush() {
		let until = Date().addingTimeInterval(0.1)
		while Date() < until { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
	}

	/// The store holds the given keys, each under the account it derives.
	private func use(keys: [Data]) {
		keyStore = MemoryNativeKeyStore()
		for key in keys {
			if let address = BeamioNativeEthSigner.address(privateKey: [UInt8](key)) { keyStore.keys[address.lowercased()] = key }
		}
		BeamioNativeWallet.keyStore = keyStore
		BeamioNativeKeySnapshot.invalidate()
	}

	/// Two valid mnemonic accounts (their keys and the mnemonics that derive them): the ambiguity is between accounts since Y.163 items 31 and 32, not between bare keys.
	private func useTwoAccounts() {
		keyStore = MemoryNativeKeyStore()
		ValidTestAccounts.install(keyStore, phrase: ValidTestAccounts.phraseA)
		ValidTestAccounts.install(keyStore, phrase: ValidTestAccounts.phraseB)
		BeamioNativeWallet.keyStore = keyStore
		BeamioNativeKeySnapshot.invalidate()
	}

	private func ack(_ type: String) -> [String: Any] {
		var sent: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": type, "reqId": 1], emit: { sent.append(($0["event"] as? [String: Any]) ?? $0) })
		flush()
		return sent.first { $0["type"] as? String == "ack" } ?? [:]
	}

	func testSeveralKeysWithoutPointerAnswerNotReadyUnreadable() {
		useTwoAccounts()
		let result = ack("walletStatus")["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["status"] as? String, "not_ready")
		XCTAssertEqual(result["notReadyReason"] as? String, "unreadable")
		XCTAssertEqual(keyStore.keys.count, 2, "no key is deleted")
		XCTAssertEqual(keyStore.mnemonic.items.count, 2, "no mnemonic is deleted")
		XCTAssertTrue(BeamioNativeAccountPointer.get().isEmpty, "nothing is chosen")
	}

	/// Several bare keys (no mnemonic) are no accounts: no ambiguity, no_key (Y.163 items 31 and 32).
	func testSeveralBareKeysAreNoAccountsAndAnswerNoKey() {
		use(keys: [keyA, keyB])
		let result = ack("walletStatus")["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["status"] as? String, "no_key")
	}

	func testNoKeyStillAnswersNoKey() {
		use(keys: [])
		let result = ack("walletStatus")["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["status"] as? String, "no_key")
	}

	func testPasscodeStatusWalletStateIsNotReadyWithSeveralKeys() {
		useTwoAccounts()
		let result = ack("passcodeStatus")["result"] as? [String: Any] ?? [:]
		XCTAssertEqual(result["walletState"] as? String, "not_ready")
	}

	func testTheQAStateLineCarriesCountsAndCodesOnly() {
		let line = BeamioConetChatModule.qaStateLine(keychainWalletEntries: 2, pointerSet: false, keyState: "ambiguous",
		                                             snapshotKnown: true, gate: "g0", walletExit: "not_ready/unreadable",
		                                             shellExit: "not_ready/none")
		XCTAssertEqual(line, "keychainWalletEntries=2 pointerSet=false keyState=ambiguous snapshotKnown=true gate=g0 "
		                     + "walletStatusExit=not_ready/unreadable shellReadExit=not_ready/none")
		XCTAssertNil(line.range(of: "0x"), "no address in the QA line")
	}
}
