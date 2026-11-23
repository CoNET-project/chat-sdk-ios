#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// and: at G1 the `nodes` value of `init` is checked after the account
/// checks, before anything else.
/// - a value that is not a list of node objects (null, a string, a string list) is refused as `bad_request`;
/// - an empty list is refused as `nodes_unavailable`, with no Keychain fallback;
/// - a missing key falls back to the nodes already stored in the Keychain; with none stored it is refused as `nodes_unavailable`.
/// No refusal sends `ready` and none changes the session. Synthetic data only.
final class InitNodesRequiredTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let keyData = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var store: NativeCombinationTests.Store!
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		savedMemory = BeamioChatPgpKeychain.memory
		// An empty in-memory Keychain: no roster is stored unless a test stores one.
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		store = NativeCombinationTests.Store()
		store.keys[account] = keyData
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
		// G1: the native key is on the device and no session is ready.
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: false)
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		BeamioChatPgpKeychain.memory = savedMemory
		super.tearDown()
	}

	/// Sends an init with the given `nodes` value (nil: the key is absent) and returns every answer it produced.
	private func sendInit(reqId: Int, nodes: Any?) -> [[String: Any]] {
		var payload: [String: Any] = ["identity": ["eoaAddress": account]]
		if let nodes { payload["nodes"] = nodes }
		var emitted: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": reqId, "payload": payload], emit: { emitted.append($0) })
		// Answers reach the observer on the main queue (emitEvent): drain it before reading, and leave no answer behind for the next test.
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return (emitted + events).map { ($0["event"] as? [String: Any]) ?? $0 }
	}

	private func ack(_ answers: [[String: Any]], reqId: Int) -> [String: Any]? {
		answers.first { $0["type"] as? String == "ack" && $0["reqId"] as? Int == reqId }
	}

	private func assertRefused(_ answers: [[String: Any]], reqId: Int, code: String, sessionBefore: AnyObject?,
	                           file: StaticString = #filePath, line: UInt = #line) {
		let answer = ack(answers, reqId: reqId)
		XCTAssertEqual(answer?["ok"] as? Bool, false, "the init is refused", file: file, line: line)
		XCTAssertEqual(answer?["error"] as? String, code, "the refusal code is \(code)", file: file, line: line)
		XCTAssertFalse(answers.contains { $0["type"] as? String == "ready" }, "no ready is sent", file: file, line: line)
		XCTAssertTrue(sessionBefore === (BeamioConetChatModule.testCurrentSession() as AnyObject?), "the session is not changed", file: file, line: line)
	}

	private func node(_ ip: String) -> [String: Any] {
		["ip": ip, "domain": "node.example.invalid", "region": "test", "armoredPublicKey": "synthetic"]
	}

	/// The key is absent and the Keychain holds no nodes: refused as nodes_unavailable, no ready, the session unchanged.
	func testMissingNodesWithNoKeychainNodesIsNodesUnavailableWithoutReady() {
		let before = BeamioConetChatModule.testCurrentSession() as AnyObject?
		let answers = sendInit(reqId: 9101, nodes: nil)
		assertRefused(answers, reqId: 9101, code: "nodes_unavailable", sessionBefore: before)
	}

	/// An empty list is refused as nodes_unavailable, even when the Keychain holds nodes (no Keychain fallback).
	func testEmptyNodesIsNodesUnavailableWithoutReady() {
		let roster = [BeamioChatPgpKeychain.SiNode(ip: "10.0.0.1", domain: "n1.example", region: "r", armoredPublicKey: "synthetic")]
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: roster, mailboxIp: nil))
		let before = BeamioConetChatModule.testCurrentSession() as AnyObject?
		let answers = sendInit(reqId: 9102, nodes: [[String: Any]]())
		assertRefused(answers, reqId: 9102, code: "nodes_unavailable", sessionBefore: before)
	}

	/// The key is absent but the Keychain holds nodes: the init goes on with the stored nodes and answers `ready` (a successful init answers
	/// with `ready`, not with an ok ack), with no refusal for nodes.
	func testMissingNodesWithKeychainNodesFallsBackToTheStoredNodes() {
		let roster = [BeamioChatPgpKeychain.SiNode(ip: "10.0.0.1", domain: "n1.example", region: "r", armoredPublicKey: "synthetic")]
		XCTAssertTrue(BeamioChatPgpKeychain.storeChainRoster(nodes: roster, mailboxIp: nil))
		var emitted: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 9104, "payload": ["identity": ["eoaAddress": account]]],
		                                    emit: { emitted.append($0) })
		// The answer is delivered on the main queue: spin the run loop (bounded) until the ready event arrives.
		let deadline = Date().addingTimeInterval(5)
		func answers() -> [[String: Any]] { (emitted + events).map { ($0["event"] as? [String: Any]) ?? $0 } }
		while !answers().contains(where: { $0["type"] as? String == "ready" }), Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		let all = answers()
		XCTAssertTrue(all.contains { $0["type"] as? String == "ready" && $0["reqId"] as? Int == 9104 },
		              "the init reaches ready with the stored nodes")
		XCTAssertFalse(all.contains { $0["type"] as? String == "ack" && ["nodes_unavailable", "bad_request"].contains($0["error"] as? String) },
		               "no refusal for nodes")
	}

	/// A value that is not a list of node objects is refused as bad_request, with no ready.
	func testNodesThatAreNotAListOfNodesAreBadRequest() {
		for (index, value) in [NSNull(), "nodes", ["10.0.0.1"]].enumerated() {
			let reqId = 9110 + index
			let before = BeamioConetChatModule.testCurrentSession() as AnyObject?
			let answers = sendInit(reqId: reqId, nodes: value)
			assertRefused(answers, reqId: reqId, code: "bad_request", sessionBefore: before)
		}
	}

	/// A present list is not refused for its nodes: the init goes on (its later answers are not the subject here).
	func testPresentNodesAreNotRefusedForNodes() {
		let answers = sendInit(reqId: 9103, nodes: [node("203.0.113.7")])
		let answer = ack(answers, reqId: 9103)
		XCTAssertNotEqual(answer?["error"] as? String, "nodes_unavailable")
		XCTAssertNotEqual(answer?["error"] as? String, "bad_request")
	}
}
#endif
