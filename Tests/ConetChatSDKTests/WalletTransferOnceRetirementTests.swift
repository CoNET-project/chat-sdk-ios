#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// interface 25.52Y.96 第 3 项, 25.52BZ.3: `walletTransferOnce` is a retired name. It is in neither the dispatch list nor the no-key table, and it
/// answers `not_supported` in every state, with no event other than the ack and no change to the store. Synthetic key 0x11…11 only.
final class WalletTransferOnceRetirementTests: XCTestCase {
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let keyBytes = Data(repeating: 0x11, count: 32)
	private var store: BridgeRetirementAcceptanceTests.Store!
	private var savedStore: BeamioChatWalletKeyStoring!
	private var emitted: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		ClearPendingIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = BridgeRetirementAcceptanceTests.Store()
		BeamioNativeWallet.keyStore = store
		emitted = []
		BeamioConetChatSignBroker.clearSigner()
	}

	override func tearDown() {
		BeamioNativeKeySnapshot.pinUnknownForTests(false)
		BeamioNativeClearPending.clear()
		ClearPendingIsolation.end()
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	/// Sends one command through the bridge entry point and returns its ack. Every emitted event is kept in `emitted`.
	private func send(_ type: String, _ reqId: Int) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack \(reqId)")
		let body: [String: Any] = ["type": type, "reqId": reqId, "payload": ["eoa": eoa], "requestId": "any", "kind": "eoaKey",
		                           "bytes": [Int](repeating: 0x11, count: 32)]
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

	func testWalletTransferOnceIsRetiredAndInNeitherCommandTable() {
		XCTAssertTrue(BeamioConetChatModule.retiredCommands.contains("walletTransferOnce"), "the name is retired")
		XCTAssertFalse(BeamioConetChatModule.dispatchedCommands.contains("walletTransferOnce"), "not in the dispatch list")
		XCTAssertFalse(BeamioConetChatModule.noKeyCommandTable.contains("walletTransferOnce"), "not in the no-key table")
		XCTAssertTrue(BeamioConetChatModule.knownBridgeCommand("walletTransferOnce"), "still a known name: it answers not_supported")
	}

	func testWalletTransferOnceAnswersNotSupportedWithNoStateChangeInEveryState() {
		let states: [(label: String, arrange: () -> Void)] = [
			("G0, no key", {}),
			("G1, key present", {
				self.store.keys[self.eoa] = self.keyBytes
				BeamioConetChatSignBroker.setSignerEoa(self.eoa)
			}),
			("native-key snapshot unknown", {
				self.store.keys[self.eoa] = self.keyBytes
				BeamioConetChatSignBroker.setSignerEoa(self.eoa)
				BeamioNativeKeySnapshot.pinUnknownForTests(true)
			}),
			("clear_pending set", {
				self.store.keys[self.eoa] = self.keyBytes
				BeamioNativeClearPending.set()
			}),
		]
		for (index, state) in states.enumerated() {
			store.keys = [:]
			store.writes = 0
			emitted = []
			BeamioNativeKeySnapshot.pinUnknownForTests(false)
			BeamioNativeClearPending.clear()
			state.arrange()
			let keysBefore = store.keys
			let writesBefore = store.writes

			let ack = send("walletTransferOnce", 4000 + index)

			XCTAssertEqual(ack?["ok"] as? Bool, false, "\(state.label): ok is false")
			XCTAssertEqual(ack?["error"] as? String, "not_supported", "\(state.label): the answer is not_supported")
			XCTAssertNil(ack?["result"], "\(state.label): no bytes or state are returned")
			XCTAssertTrue(emitted.allSatisfy { $0["type"] as? String == "ack" }, "\(state.label): no transfer event is emitted")
			XCTAssertEqual(store.keys, keysBefore, "\(state.label): the store is unchanged")
			XCTAssertEqual(store.writes, writesBefore, "\(state.label): nothing is written")
		}
	}
}
#endif
