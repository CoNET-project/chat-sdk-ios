import XCTest
@testable import ConetChatSDK

/// The busy state of, in the test target only. A command is held in flight by blocking the chain transport, the public
/// test seam `AddressPGPChain.transport`. While it is in flight, a name outside the command table is sent: it must be answered
/// `unknown_command`, exactly once, and the held command must still answer when it is released. The block exists only in this file and is
/// released before the test ends. Synthetic data only.
final class GateBusyStateTests: XCTestCase {
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

	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private let account = PgpMigrationTestSupport.eoa

	/// A command is in flight (its chain read is blocked in the transport), an unknown name is sent, and it gets exactly one `unknown_command`.
	/// The held command answers after the release.
	func testAnUnknownNameIsUnknownCommandWhileACommandIsInFlight() {
		let savedStore = BeamioNativeWallet.keyStore
		let savedVault = BeamioPasscodeSession.shared.vault
		let savedTransport = AddressPGPChain.transport
		let savedConfiguration = AddressPGPChain.configuration
		NativeAccountPointerIsolation.begin()
		defer {
			AddressPGPChain.transport = savedTransport
			AddressPGPChain.configuration = savedConfiguration
			BeamioPasscodeSession.shared.vault = savedVault
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}

		// G2 with no passcode: a native key for the account, the session ready, and nothing locked.
		let store = Store()
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: MemoryRecords(), hardware: IdentityHardware())
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)

		// The chain is configured, so the restore evaluation reads it through the transport, and the transport is held here.
		AddressPGPChain.configuration = AddressPGPChain.Configuration(
			contract: "0x" + String(repeating: "1", count: 40), chainId: 224422, rpcURL: URL(string: "https://rpc.test.invalid")!
		)
		let entered = expectation(description: "the held command reached the transport")
		let release = DispatchSemaphore(value: 0)
		AddressPGPChain.transport = { _, _ in
			entered.fulfill()
			_ = release.wait(timeout: .now() + 20)
			return .failure(AddressPGPChain.ReadError.transport("released by the test"))
		}

		var events: [[String: Any]] = []
		let heldAnswered = expectation(description: "the held command answers after the release")
		let emit: BeamioConetChatModule.WebEmit = { payload in
			guard let event = payload["event"] as? [String: Any] else { return }
			events.append(event)
			if event["reqId"] as? Int == 9001 { heldAnswered.fulfill() }
		}
		BeamioConetChatModule.handleCommand(["type": "pgpRestoreEvaluate", "reqId": 9001, "accountKey": account + ":default"], emit: emit)
		wait(for: [entered], timeout: 5)

		// In flight: an unknown name is answered at once, once, with unknown_command.
		BeamioConetChatModule.handleCommand(["type": "notAListedName", "reqId": 9002], emit: emit)
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		let unknownAnswers = events.filter { $0["reqId"] as? Int == 9002 }
		XCTAssertEqual(unknownAnswers.count, 1, "exactly one answer to the unknown name, while busy")
		XCTAssertEqual(unknownAnswers.first?["error"] as? String, "unknown_command")
		XCTAssertEqual(events.filter { $0["reqId"] as? Int == 9001 }.count, 0, "the held command has not answered yet")

		// Release the held command: it answers, and nothing else is answered for it.
		release.signal()
		wait(for: [heldAnswered], timeout: 10)
		XCTAssertEqual(events.filter { $0["reqId"] as? Int == 9001 }.count, 1, "the held command answers once")
	}
}
