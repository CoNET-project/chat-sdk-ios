import XCTest
@testable import ConetChatSDK

/// The unfrozen-command stubs. Gate first: no key is `no_key`, a record without a ready session is
/// `not_ready`. With the gate open, each command is refused with its code, and nothing else: no `result`, no event, no
/// key material. A page confirmation of a value-moving command is `confirmation_not_native` (G-3).
final class NotFrozenCommandTests: XCTestCase {
	private let account = "0x6f6f000000000000000000000000000000000001"

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
		store = MemoryKeyStore()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = store
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// One command through the entry point. Acks are posted on the main queue, so the queue is drained first.
	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			events.append((event["event"] as? [String: Any]) ?? event)
		})
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	private func command(_ type: String, reqId: Int = 7, extra: [String: Any] = [:]) -> [String: Any] {
		var body: [String: Any] = ["type": type, "reqId": reqId, "accountKey": account + ":default"]
		for (k, v) in extra { body[k] = v }
		return body
	}

	private func openGate() {
		XCTAssertTrue(BeamioNativeWallet.keyStore.write(eoa: account, key: Data(repeating: 0x22, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
	}

	func testWithoutAKeyEveryStubIsNoKey() {
		for name in BeamioNotFrozenCommands.names.sorted() {
			let events = dispatch(command(name))
			XCTAssertEqual(events.count, 1, name)
			XCTAssertEqual(events.first?["error"] as? String, "no_key", name)
			XCTAssertNil(events.first?["result"], name)
		}
	}

	func testARecordWithoutAReadySessionIsNotReady() {
		XCTAssertTrue(BeamioNativeWallet.keyStore.write(eoa: account, key: Data(repeating: 0x22, count: 32)))
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		for name in BeamioNotFrozenCommands.names.sorted() {
			let events = dispatch(command(name))
			XCTAssertEqual(events.first?["error"] as? String, "not_ready", name)
		}
	}

	func testWithTheGateOpenEachStubIsRefusedWithItsCodeOnly() {
		openGate()
		for name in BeamioNotFrozenCommands.names.sorted() {
			let events = dispatch(command(name))
			XCTAssertEqual(events.count, 1, name)
			XCTAssertEqual(events.first?["error"] as? String, "not_supported", name)
			XCTAssertNil(events.first?["result"], "\(name) must not return data")
			XCTAssertEqual(events.first?["ok"] as? Bool, false, name)
		}
	}

	func testAPageConfirmationOfAValueMovingCommandIsNotNative() {
		openGate()
		for name in BeamioNotFrozenCommands.valueMoving.sorted() {
			let events = dispatch(command(name, extra: ["confirm": true]))
			XCTAssertEqual(events.first?["error"] as? String, "confirmation_not_native", name)
		}
		// A command that is not value-moving keeps `not_supported` even with the field.
		let events = dispatch(command("historySign", extra: ["confirm": true]))
		XCTAssertEqual(events.first?["error"] as? String, "not_supported")
	}

	func testDeriveSubkeysNeverAnswersWithTheRoot() {
		openGate()
		let events = dispatch(command("deriveSubkeys"))
		XCTAssertNil(events.first?["result"], "C5 must not return R_db or any key")
	}

	func testTheStubNamesAreNotTheImplementedOnes() {
		// walletAddress (N0) and gossipSign (C2) are implemented and must not be swallowed by the stubs.
		XCTAssertFalse(BeamioNotFrozenCommands.names.contains("walletAddress"))
		XCTAssertFalse(BeamioNotFrozenCommands.names.contains("gossipSign"))
		XCTAssertFalse(BeamioNotFrozenCommands.names.contains("pgpDecryptInbound"))
	}
}
