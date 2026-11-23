import Foundation
import XCTest
@testable import ConetChatSDK

/// The `getAccount` answer of the registry ABI: the dynamic tuple of 12 fields, with `accountName` at field 0 and `exists` at field 9. The
/// other fields take their defaults. Shared by the mock registry and the transport tests.
func bindingAccountAnswer(name: String, exists: Bool) -> [UInt8] {
	let values: [Any] = [name, "", false, false, false, false, "", "", 0, exists, "", ""]
	var head: [[UInt8]] = []
	var tail: [UInt8] = []
	for value in values {
		if let text = value as? String {
			head.append(BeamioAccountBindingLookup.uintWord(12 * 32 + tail.count))
			let bytes = Array(text.utf8)
			let padding = (32 - bytes.count % 32) % 32
			tail += BeamioAccountBindingLookup.uintWord(bytes.count) + bytes + [UInt8](repeating: 0, count: padding)
		} else if let flag = value as? Bool {
			head.append(BeamioAccountBindingLookup.uintWord(flag ? 1 : 0))
		} else if let number = value as? Int {
			head.append(BeamioAccountBindingLookup.uintWord(number))
		}
	}
	return BeamioAccountBindingLookup.uintWord(32) + head.flatMap { $0 } + tail
}

/// The pre-create binding lookup against a mock registry. Every answer here is a fixture: the
/// in-process transport seam answers the JSON-RPC calls. The transport tests in the second class use a URLProtocol stub under the real
/// https transport. Nothing is sent to a network. The flow tests check the nativeAccountCreateOpen path: the creation step (the host,
/// the generation) is not reached unless the lookup finds no binding.
final class BeamioAccountBindingMockTests: XCTestCase {
	private let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let tag = "qa-binding-fixture"
	private let notFoundData = "0xfaba8ebe"

	private enum Reply {
		case result(String)
		case revert(String?)
		case rpcError
		case raw(Data)
		case transport(Error)
	}

	private var savedTransport: (URL, Data, TimeInterval) -> Result<Data, Error> = BeamioAccountBindingLookup.defaultTransport
	private var savedLocal: (String) -> (present: Bool, unreadable: Bool) = BeamioAccountBindingLookup.defaultLocalState
	private var savedDeviceK: () -> Bool = BeamioAccountBindingLookup.deviceK
	private var savedDispatch: (@escaping () -> Void) -> Void = BeamioAccountBindingLookup.dispatch
	private var savedOverride: ((BeamioAccountBindingLookup.Account) -> BeamioAccountBindingLookup.Outcome)?
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedHost: (() -> Bool)?
	private var transportCalls = 0
	private var hostCalls = 0
	private var store = NativeAccountCreateTests.CreateKeyStore()
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedTransport = BeamioAccountBindingLookup.transport
		savedLocal = BeamioAccountBindingLookup.localState
		savedDeviceK = BeamioAccountBindingLookup.deviceK
		savedDispatch = BeamioAccountBindingLookup.dispatch
		savedOverride = BeamioAccountBindingLookup.override
		savedStore = BeamioNativeWallet.keyStore
		savedHost = BeamioNativeAccountCreate.onCreateRequired
		BeamioAccountBindingLookup.override = nil
		BeamioAccountBindingLookup.dispatch = { $0() }
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: false) }
		BeamioAccountBindingLookup.deviceK = { false }
		BeamioAccountBindingLookup.transport = BeamioAccountBindingLookup.defaultTransport
		store = NativeAccountCreateTests.CreateKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		transportCalls = 0
		hostCalls = 0
		events = []
		BeamioNativeAccountCreate.onCreateRequired = { [weak self] in
			self?.hostCalls += 1
			return true
		}
	}

	override func tearDown() {
		BeamioAccountBindingLookup.transport = savedTransport
		BeamioAccountBindingLookup.localState = savedLocal
		BeamioAccountBindingLookup.deviceK = savedDeviceK
		BeamioAccountBindingLookup.dispatch = savedDispatch
		BeamioAccountBindingLookup.override = savedOverride
		BeamioNativeAccountCreate.onCreateRequired = savedHost
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioConetChatModule.closeAccountCreatePage()
		drain()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	// MARK: - The mock registry

	/// Installs the mock registry: `account` answers `getAccount(address)`, `owner` answers `getOwnerByAccountName(string)`, and any other
	/// selector gets an unrelated revert. Each call is counted, so a test can assert that there was exactly one.
	private func mockRegistry(account: @escaping (String) -> Reply = { _ in .revert(nil) },
	                          owner: @escaping (String) -> Reply = { _ in .revert(nil) }) {
		BeamioAccountBindingLookup.transport = { [weak self] _, payload, _ in
			self?.transportCalls += 1
			guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
			      let params = object["params"] as? [Any],
			      let call = params.first as? [String: Any],
			      let dataHex = call["data"] as? String,
			      let data = AddressPGPChain.bytes(fromHex: dataHex), data.count >= 4
			else { return .failure(BeamioAccountBindingLookup.TransportFailure.other) }
			let selector = Array(data.prefix(4))
			let reply: Reply
			if selector == AddressPGPChain.selector("getAccount(address)") {
				reply = account(AddressPGPChain.hex(Array(data[16 ..< 36])))
			} else if selector == AddressPGPChain.selector("getOwnerByAccountName(string)") {
				reply = owner(self?.decodedTag(data) ?? "")
			} else {
				reply = .revert("0x08c379a0")
			}
			return self?.render(reply) ?? .failure(BeamioAccountBindingLookup.TransportFailure.other)
		}
	}

	private func decodedTag(_ data: [UInt8]) -> String {
		guard let offset = AddressPGPChain.word(data, at: 4), let length = AddressPGPChain.word(data, at: 4 + offset) else { return "" }
		let start = 4 + offset + 32
		guard start + length <= data.count else { return "" }
		return String(decoding: data[start ..< start + length], as: UTF8.self)
	}

	private func render(_ reply: Reply) -> Result<Data, Error> {
		switch reply {
		case .result(let hex):
			return .success(json(["jsonrpc": "2.0", "id": 1, "result": hex]))
		case .revert(let data):
			var error: [String: Any] = ["code": 3, "message": "execution reverted"]
			if let data { error["data"] = data }
			return .success(json(["jsonrpc": "2.0", "id": 1, "error": error]))
		case .rpcError:
			return .success(json(["jsonrpc": "2.0", "id": 1, "error": ["code": -32000, "message": "header not found"]]))
		case .raw(let bytes):
			return .success(bytes)
		case .transport(let error):
			return .failure(error)
		}
	}

	private func json(_ object: [String: Any]) -> Data {
		(try? JSONSerialization.data(withJSONObject: object)) ?? Data()
	}

	private func accountResult(name: String, exists: Bool) -> Reply {
		.result(AddressPGPChain.hex(bindingAccountAnswer(name: name, exists: exists)))
	}

	/// `getOwnerByAccountName`: one address word. Nil is the zero address.
	private func ownerResult(_ address: String?) -> Reply {
		guard let address else { return .result(AddressPGPChain.hex([UInt8](repeating: 0, count: 32))) }
		return .result(AddressPGPChain.hex(AddressPGPChain.addressWord(address)))
	}

	private func accountNotFound() -> Reply {
		.revert(notFoundData)
	}

	private func lookup(_ account: BeamioAccountBindingLookup.Account, now: @escaping () -> Date = Date.init) -> BeamioAccountBindingLookup.Outcome {
		BeamioAccountBindingLookup.lookup(account, now: now)
	}

	// MARK: - Account path (getAccount)

	/// The exact no-argument AccountNotFound and no local account: no binding.
	func testExactAccountNotFoundWithNoLocalAccountIsNoBinding() {
		mockRegistry(account: { _ in self.accountNotFound() })
		XCTAssertEqual(lookup(.eoa(eoa)), .noBinding)
		XCTAssertEqual(transportCalls, 1, "one call: there is no fallback endpoint")
	}

	/// BL-05: the registry does not know the EOA, but the device holds its wallet key record: already bound.
	func testAccountNotFoundWithAWalletKeyRecordIsAlreadyBound() {
		mockRegistry(account: { _ in self.accountNotFound() })
		BeamioAccountBindingLookup.localState = { _ in (present: true, unreadable: false) }
		XCTAssertEqual(lookup(.eoa(eoa)), .alreadyBound)
	}

	/// BL-06: the same with the account record K. The local source is one flag here; the wallet and K states are read apart in
	/// BeamioAccountBindingLookup.defaultLocalState.
	func testAccountNotFoundWithAnAccountRecordKIsAlreadyBound() {
		mockRegistry(account: { _ in self.accountNotFound() })
		BeamioAccountBindingLookup.localState = { _ in (present: true, unreadable: false) }
		XCTAssertEqual(lookup(.eoa(eoa)), .alreadyBound)
	}

	/// BL-07: AccountNotFound with a local source that cannot be read: fail closed, never no binding.
	func testAccountNotFoundWithAnUnreadableLocalSourceIsUnavailable() {
		mockRegistry(account: { _ in self.accountNotFound() })
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: true) }
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("source_unreadable"))
	}

	/// A valid non-empty record is already bound, whatever the local sources say.
	func testAValidExistingRecordIsAlreadyBound() {
		mockRegistry(account: { _ in self.accountResult(name: "qa-existing", exists: true) })
		XCTAssertEqual(lookup(.eoa(eoa)), .alreadyBound)
		XCTAssertEqual(transportCalls, 1)
	}

	/// BL-13: `exists` true with an empty name is a semantic mismatch: unavailable.
	func testExistsWithAnEmptyNameIsUnavailable() {
		mockRegistry(account: { _ in self.accountResult(name: "", exists: true) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("semantic_mismatch"))
	}

	/// `exists` false without the revert is not a no-record answer: unavailable, with or without a name.
	func testExistsFalseWithoutTheRevertIsUnavailable() {
		mockRegistry(account: { _ in self.accountResult(name: "", exists: false) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("exists_false"))
		mockRegistry(account: { _ in self.accountResult(name: "qa-x", exists: false) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("exists_false"))
	}

	/// An `exists` word other than 0 or 1 is not canonical: invalid.
	func testNonCanonicalExistsIsUnavailable() {
		var bytes = bindingAccountAnswer(name: "qa", exists: true)
		bytes[32 + 9 * 32 + 31] = 2
		mockRegistry(account: { _ in .result(AddressPGPChain.hex(bytes)) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("invalid_response"))
	}

	/// The same selector with arguments after it is not the exact AccountNotFound: unavailable.
	func testSameSelectorWithArgumentsIsUnavailable() {
		mockRegistry(account: { _ in .revert(self.notFoundData + String(repeating: "0", count: 62) + "1") })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("revert"))
	}

	/// Another revert selector (here Error(string)) is an unrelated failure: unavailable.
	func testOtherRevertSelectorIsUnavailable() {
		mockRegistry(account: { _ in .revert("0x08c379a0" + String(repeating: "0", count: 8)) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("revert"))
	}

	/// Empty revert data, or a revert with no data, is not AccountNotFound: unavailable.
	func testEmptyRevertDataIsUnavailable() {
		mockRegistry(account: { _ in .revert("0x") })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("revert"))
		mockRegistry(account: { _ in .revert(nil) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("rpc"), "an error without data is a failure of the call")
	}

	/// A JSON-RPC error without data is a failure, not a no-record answer.
	func testRPCErrorIsUnavailable() {
		mockRegistry(account: { _ in .rpcError })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("rpc"))
	}

	/// A result shorter than the tuple head is truncated: invalid.
	func testTruncatedAccountResponseIsUnavailable() {
		let bytes = bindingAccountAnswer(name: "qa", exists: true)
		mockRegistry(account: { _ in .result(AddressPGPChain.hex(Array(bytes.prefix(200)))) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("invalid_response"))
	}

	/// A result that is not hex, and bytes that are not JSON: undecodable, unavailable.
	func testUndecodableResponsesAreUnavailable() {
		mockRegistry(account: { _ in .result("0xzz") })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("malformed"))
		mockRegistry(account: { _ in .raw(Data("not json".utf8)) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("malformed"))
	}

	/// Transport failures are unavailable, each with its reason: connection refused, HTTP status, timeout.
	func testTransportFailuresAreUnavailable() {
		mockRegistry(account: { _ in .transport(URLError(.cannotConnectToHost)) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("transport"))
		mockRegistry(account: { _ in .transport(BeamioAccountBindingLookup.TransportFailure.http) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("http"))
		mockRegistry(account: { _ in .transport(URLError(.timedOut)) })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("timeout"))
	}

	/// A failure of the registry is not hidden by an empty local source: it stays unavailable (never no binding).
	func testRegistryFailureWithNoLocalAccountIsUnavailable() {
		mockRegistry(account: { _ in .rpcError })
		XCTAssertEqual(lookup(.eoa(eoa)), .unavailable("rpc"))
	}

	/// A failure of the registry with a local account is already bound: the positive source wins (step 2).
	func testRegistryFailureWithALocalAccountIsAlreadyBound() {
		mockRegistry(account: { _ in .rpcError })
		BeamioAccountBindingLookup.localState = { _ in (present: true, unreadable: false) }
		XCTAssertEqual(lookup(.eoa(eoa)), .alreadyBound)
	}

	// MARK: - Tag path (getOwnerByAccountName)

	/// BL-01: a decodable zero owner, and no local account: no binding.
	func testTagZeroOwnerIsNoBinding() {
		mockRegistry(owner: { _ in self.ownerResult(nil) })
		XCTAssertEqual(lookup(.tag(tag)), .noBinding)
		XCTAssertEqual(transportCalls, 1)
	}

	/// BL-03: a valid non-zero owner is already bound.
	func testTagNonZeroOwnerIsAlreadyBound() {
		mockRegistry(owner: { _ in self.ownerResult(self.eoa) })
		XCTAssertEqual(lookup(.tag(tag)), .alreadyBound)
	}

	/// BL-14: a 31-byte answer is not an address: unavailable.
	func testTagTruncatedOwnerIsUnavailable() {
		mockRegistry(owner: { _ in .result(AddressPGPChain.hex([UInt8](repeating: 0, count: 31))) })
		XCTAssertEqual(lookup(.tag(tag)), .unavailable("invalid_response"))
	}

	/// BL-27 family: the high 12 bytes of the address word must be zero.
	func testTagOwnerWithHighBytesIsUnavailable() {
		var word = [UInt8](repeating: 0, count: 32)
		word[0] = 1
		mockRegistry(owner: { _ in .result(AddressPGPChain.hex(word)) })
		XCTAssertEqual(lookup(.tag(tag)), .unavailable("invalid_response"))
	}

	/// BL-08: any revert on the tag path is unavailable, never no binding.
	func testTagRevertIsUnavailable() {
		mockRegistry(owner: { _ in .revert(self.notFoundData) })
		XCTAssertEqual(lookup(.tag(tag)), .unavailable("revert"))
	}

	/// BL-17: a valid non-zero owner with an unreadable local source is already bound (positive first).
	func testTagNonZeroOwnerWithAnUnreadableLocalSourceIsAlreadyBound() {
		mockRegistry(owner: { _ in self.ownerResult(self.eoa) })
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: true) }
		XCTAssertEqual(lookup(.tag(tag)), .alreadyBound)
	}

	/// BL-18: a zero owner with an unreadable local source is unavailable (fail closed).
	func testTagZeroOwnerWithAnUnreadableLocalSourceIsUnavailable() {
		mockRegistry(owner: { _ in self.ownerResult(nil) })
		// The device's account (the pointer) is the source that can be unreadable here.
		BeamioNativeAccountPointer.set(eoa)
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: true) }
		XCTAssertEqual(lookup(.tag(tag)), .unavailable("source_unreadable"))
	}

	/// A device account is not positive for a tag: a zero owner with a readable device account is no binding.
	func testTagZeroOwnerWithADeviceAccountIsNoBinding() {
		mockRegistry(owner: { _ in self.ownerResult(nil) })
		BeamioNativeAccountPointer.set(eoa)
		BeamioAccountBindingLookup.localState = { _ in (present: true, unreadable: false) }
		XCTAssertEqual(lookup(.tag(tag)), .noBinding)
	}

	/// BL-32 and BL-34: a device account does not turn a failed registry read into a binding; the failure stays unavailable.
	func testTagFailureWithADeviceAccountIsUnavailable() {
		mockRegistry(owner: { _ in .rpcError })
		BeamioNativeAccountPointer.set(eoa)
		BeamioAccountBindingLookup.localState = { _ in (present: true, unreadable: false) }
		XCTAssertEqual(lookup(.tag(tag)), .unavailable("rpc"))
	}

	/// BL-50: a zero owner while a PGP record of any account is on the device fails closed. The record is not positive.
	func testTagZeroOwnerWithADeviceKRecordIsUnavailable() {
		mockRegistry(owner: { _ in self.ownerResult(nil) })
		BeamioAccountBindingLookup.deviceK = { true }
		XCTAssertEqual(lookup(.tag(tag)), .unavailable("device_k_present"))
	}

	/// BL-51: a valid registry owner is already bound even while a device K record is present.
	func testTagOwnerWithADeviceKRecordIsStillAlreadyBound() {
		mockRegistry(owner: { _ in self.ownerResult(self.eoa) })
		BeamioAccountBindingLookup.deviceK = { true }
		XCTAssertEqual(lookup(.tag(tag)), .alreadyBound)
	}

	// MARK: - The 10 second total

	final class Clock {
		var now = Date(timeIntervalSinceReferenceDate: 0)
	}

	/// BL-16: a valid answer that arrives after the total budget is unavailable.
	func testAnAnswerAfterTheBudgetIsUnavailableEvenWhenPositive() {
		let clock = Clock()
		let eoa = self.eoa
		BeamioAccountBindingLookup.transport = { [weak self] _, _, _ in
			clock.now = clock.now.addingTimeInterval(11)
			return self?.render(self?.ownerResult(eoa) ?? .revert(nil)) ?? .failure(BeamioAccountBindingLookup.TransportFailure.other)
		}
		XCTAssertEqual(lookup(.tag(tag), now: { clock.now }), .unavailable("timeout"))
	}

	/// BL-19: an answer at exactly the budget is still judged by its result (the cap is not exceeded).
	func testAnAnswerAtExactlyTheBudgetIsJudgedByItsResult() {
		let clock = Clock()
		BeamioAccountBindingLookup.transport = { [weak self] _, _, _ in
			clock.now = clock.now.addingTimeInterval(10)
			return self?.render(.revert(self?.notFoundData)) ?? .failure(BeamioAccountBindingLookup.TransportFailure.other)
		}
		XCTAssertEqual(lookup(.eoa(eoa), now: { clock.now }), .noBinding)
	}

	/// The local reads count toward the budget too: a zero owner that is only confirmed after the budget is unavailable.
	func testTheLocalReadsCountTowardTheBudget() {
		let clock = Clock()
		BeamioAccountBindingLookup.transport = { [weak self] _, _, _ in
			clock.now = clock.now.addingTimeInterval(9.5)
			return self?.render(self?.ownerResult(nil) ?? .revert(nil)) ?? .failure(BeamioAccountBindingLookup.TransportFailure.other)
		}
		BeamioNativeAccountPointer.set(eoa)
		BeamioAccountBindingLookup.localState = { _ in
			clock.now = clock.now.addingTimeInterval(1)
			return (present: false, unreadable: false)
		}
		XCTAssertEqual(lookup(.tag(tag), now: { clock.now }), .unavailable("timeout"))
	}

	// MARK: - The open flow (nativeAccountCreateOpen,)

	/// Lets the main queue run everything the open chains onto it: the lookup's completion and the events it emits. The chain is short, so a
	/// few short turns of the run loop are enough, and nothing is left to leak into the next test.
	private func drain() {
		for _ in 0 ..< 5 {
			RunLoop.main.run(until: Date().addingTimeInterval(0.05))
		}
	}

	/// Opens the creation page as the bridge does, and returns the events the open produced.
	private func open(account: Any?, extra: [String: Any] = [:]) -> [[String: Any]] {
		var body: [String: Any] = ["type": "nativeAccountCreateOpen", "reqId": 3]
		if let account { body["account"] = account }
		body.merge(extra) { _, new in new }
		let from = events.count
		BeamioConetChatModule.handleCommand(body, emit: { [weak self] event in
			self?.events.append((event["event"] as? [String: Any]) ?? event)
		})
		drain()
		return Array(events.dropFirst(from))
	}

	private func result(in sent: [[String: Any]]) -> [String: Any]? {
		sent.first { $0["type"] as? String == "nativeAccountCreateResult" }
	}

	private func ack(in sent: [[String: Any]]) -> [String: Any]? {
		sent.first { $0["type"] as? String == "ack" }
	}

	/// No binding: the creation step is reached, once (the host opens the page). Nothing is written before the user confirms.
	func testNoBindingReachesTheCreationStepOnce() {
		mockRegistry(account: { _ in self.accountNotFound() })
		let sent = open(account: eoa)
		XCTAssertEqual(ack(in: sent)?["ok"] as? Bool, true)
		XCTAssertEqual(ack(in: sent)?["page"] as? String, "opened", "a creation page opens: page opened")
		XCTAssertEqual(hostCalls, 1)
		XCTAssertEqual(store.writes, 0)
		XCTAssertNil(result(in: sent), "no binding sends no result: the page is the first screen")
		XCTAssertTrue(BeamioConetChatModule.accountCreatePageOpen())
	}

	/// BL-03/04 through the flow: already bound opens no page, makes no EOA, and sends `already_bound` without an address.
	func testAlreadyBoundOpensNoPageAndSendsTheCodeWithoutAnAddress() {
		mockRegistry(account: { _ in self.accountResult(name: "qa-existing", exists: true) })
		let sent = open(account: eoa)
		XCTAssertEqual(ack(in: sent)?["ok"] as? Bool, true, "the open is answered ok:true")
		XCTAssertEqual(ack(in: sent)?["page"] as? String, "none", "a binding result answers page none")
		XCTAssertNil(ack(in: sent)?["error"])
		XCTAssertEqual(accountCreateCode(result(in: sent)), "already_bound")
		XCTAssertNil(accountCreateEoa(result(in: sent)), "already_bound carries no address (step 4)")
		XCTAssertEqual(hostCalls, 0)
		XCTAssertEqual(store.writes, 0)
		XCTAssertFalse(BeamioConetChatModule.accountCreatePageOpen())
	}

	/// Each failure of the lookup sends `lookup_unavailable`, opens no page and makes no EOA. None of them moves the creation forward.
	func testEveryLookupFailureSendsUnavailableAndOpensNothing() {
		let failures: [(String, () -> Void)] = [
			("rpc error", { self.mockRegistry(account: { _ in .rpcError }) }),
			("other revert", { self.mockRegistry(account: { _ in .revert("0x08c379a0") }) }),
			("empty revert", { self.mockRegistry(account: { _ in .revert("0x") }) }),
			("same selector with arguments", { self.mockRegistry(account: { _ in .revert(self.notFoundData + "00") }) }),
			("undecodable", { self.mockRegistry(account: { _ in .result("0xzz") }) }),
			("connection refused", { self.mockRegistry(account: { _ in .transport(URLError(.cannotConnectToHost)) }) }),
			("http", { self.mockRegistry(account: { _ in .transport(BeamioAccountBindingLookup.TransportFailure.http) }) }),
			("exists false", { self.mockRegistry(account: { _ in self.accountResult(name: "", exists: false) }) }),
		]
		for (label, setUpRegistry) in failures {
			events = []
			hostCalls = 0
			setUpRegistry()
			let sent = open(account: eoa)
			XCTAssertEqual(accountCreateCode(result(in: sent)), "lookup_unavailable", label)
			XCTAssertNil(accountCreateEoa(result(in: sent)), label)
			XCTAssertEqual(ack(in: sent)?["ok"] as? Bool, true, label)
			XCTAssertNil(ack(in: sent)?["error"], label)
			XCTAssertEqual(hostCalls, 0, "\(label): the creation page is not opened")
			XCTAssertEqual(store.writes, 0, "\(label): no EOA is generated or written")
			XCTAssertFalse(BeamioConetChatModule.accountCreatePageOpen(), label)
		}
	}

	/// A tag with no record opens the first screen; a tag whose lookup fails does not.
	func testTagFlowFollowsTheSameRules() {
		mockRegistry(owner: { _ in self.ownerResult(nil) })
		let created = open(account: tag)
		XCTAssertEqual(hostCalls, 1)
		XCTAssertNil(result(in: created))
		// The first page is closed before the next open, which is another reqId.
		BeamioConetChatModule.closeAccountCreatePage()
		drain()
		mockRegistry(owner: { _ in .rpcError })
		let failed = open(account: tag, extra: ["reqId": 4])
		XCTAssertEqual(accountCreateCode(result(in: failed)), "lookup_unavailable")
		XCTAssertEqual(hostCalls, 1, "the failed lookup opened no page")
	}

	/// The account is required and checked before any call: nothing is looked up, nothing is opened.
	func testAMissingOrMalformedAccountIsBadRequestWithoutAnyCall() {
		mockRegistry(account: { _ in self.accountNotFound() })
		let missing = open(account: nil)
		XCTAssertEqual(ack(in: missing)?["error"] as? String, "bad_request")
		let short = open(account: "0x1234")
		XCTAssertEqual(ack(in: short)?["error"] as? String, "bad_request")
		let spaced = open(account: "two words")
		XCTAssertEqual(ack(in: spaced)?["error"] as? String, "bad_request")
		XCTAssertEqual(transportCalls, 0)
		XCTAssertEqual(hostCalls, 0)
	}

	/// A credential field is still refused, and no call is made.
	func testACredentialFieldIsRefusedWithoutAnyCall() {
		mockRegistry(account: { _ in self.accountNotFound() })
		let sent = open(account: eoa, extra: ["mnemonic": "x"])
		XCTAssertEqual(ack(in: sent)?["error"] as? String, "key_over_bridge_refused")
		XCTAssertEqual(transportCalls, 0)
		XCTAssertEqual(hostCalls, 0)
	}
}

/// The real https transport, under a URLProtocol stub: HTTP status, connection refused and timeout go through
/// `BeamioAccountBindingLookup.defaultTransport` as they do on a device. The stub answers in-process; the endpoint is never contacted.
final class BeamioAccountBindingTransportTests: XCTestCase {
	private let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	enum Mode {
		case status(Int, Data)
		case failure(URLError.Code)
		case hang
	}

	final class StubProtocol: URLProtocol {
		static var mode: Mode?
		static var requests = 0

		override class func canInit(with request: URLRequest) -> Bool {
			mode != nil && request.url?.host == BeamioRecoveryRegistry.endpoint.host
		}

		override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

		override func startLoading() {
			StubProtocol.requests += 1
			switch StubProtocol.mode {
			case .status(let code, let body)?:
				let response = HTTPURLResponse(url: request.url!, statusCode: code, httpVersion: "HTTP/1.1", headerFields: nil)!
				client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
				client?.urlProtocol(self, didLoad: body)
				client?.urlProtocolDidFinishLoading(self)
			case .failure(let code)?:
				client?.urlProtocol(self, didFailWithError: URLError(code))
			case .hang?, nil:
				break
			}
		}

		override func stopLoading() {}
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioAccountBindingLookup.transport = BeamioAccountBindingLookup.defaultTransport
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: false) }
		StubProtocol.mode = nil
		StubProtocol.requests = 0
		URLProtocol.registerClass(StubProtocol.self)
	}

	override func tearDown() {
		URLProtocol.unregisterClass(StubProtocol.self)
		StubProtocol.mode = nil
		BeamioAccountBindingLookup.localState = BeamioAccountBindingLookup.defaultLocalState
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func body(_ object: [String: Any]) -> Data {
		(try? JSONSerialization.data(withJSONObject: object)) ?? Data()
	}

	/// A JSON-RPC revert with AccountNotFound data, over the real transport: no binding.
	func testRealTransportAccountNotFoundIsNoBinding() {
		StubProtocol.mode = .status(200, body(["jsonrpc": "2.0", "id": 1,
		                                       "error": ["code": 3, "message": "execution reverted", "data": "0xfaba8ebe"]]))
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .noBinding)
		XCTAssertEqual(StubProtocol.requests, 1, "one request, and no second endpoint")
	}

	/// HTTP 503 is a failure, never a no-record answer.
	func testRealTransportHTTP503IsUnavailable() {
		StubProtocol.mode = .status(503, Data())
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .unavailable("http"))
		XCTAssertEqual(StubProtocol.requests, 1)
	}

	/// Connection refused is a failure, never a no-record answer.
	func testRealTransportConnectionRefusedIsUnavailable() {
		StubProtocol.mode = .failure(.cannotConnectToHost)
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .unavailable("transport"))
	}

	/// A non-empty answer over the real transport is decoded and is already bound.
	func testRealTransportExistingRecordIsAlreadyBound() {
		let answer = bindingAccountAnswer(name: "qa-existing", exists: true)
		StubProtocol.mode = .status(200, body(["jsonrpc": "2.0", "id": 1, "result": AddressPGPChain.hex(answer)]))
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .alreadyBound)
	}

	/// A request that never completes is cut at the total budget: unavailable, and not after more than the budget plus a margin.
	func testRealTransportTimeoutIsUnavailableWithinTheBudget() {
		StubProtocol.mode = .hang
		let started = Date()
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .unavailable("timeout"))
		XCTAssertLessThan(Date().timeIntervalSince(started), BeamioAccountBindingLookup.totalBudget + 1.5)
	}
}
