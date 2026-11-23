import Foundation
import XCTest
@testable import ConetChatSDK

/// `bindingLookupCases` of `pgp-migration-vectors.v1.json`, current version 15a05427… (393 steps, BL-01 to BL-51; spec,
///). Every case runs
/// through the open flow (`nativeAccountCreateOpen`), on a fake clock and a fake registry. `create` opens the first screen once; `already_bound`
/// and `lookup_unavailable` are sent as the result code, with no address. Needs PGP_MIGRATION_VECTORS=<path to pgp-migration-vectors.v1.json>;
/// skipped without it.
final class BeamioAccountBindingVectorTests: XCTestCase {
	private let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let tag = "vector-tag"
	private let notFoundData = "0xfaba8ebe"

	private enum Reply {
		case result(String)
		case revert(String)
		case rpcError
		case raw(Data)
		case transport(Error)
	}

	private var savedTransport = BeamioAccountBindingLookup.transport
	private var savedLocal = BeamioAccountBindingLookup.localState
	private var savedDeviceK: () -> Bool = BeamioAccountBindingLookup.deviceK
	private var savedDispatch = BeamioAccountBindingLookup.dispatch
	private var savedOverride = BeamioAccountBindingLookup.override
	private var savedClock = BeamioAccountBindingLookup.clock
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedHost: (() -> Bool)?
	private var savedPgpMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var transportCalls = 0
	private var hostCalls = 0
	private var store = NativeAccountCreateTests.CreateKeyStore()
	private var events: [[String: Any]] = []
	private var now = Date(timeIntervalSinceReferenceDate: 0)
	private var current: [String: Any] = [:]

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedTransport = BeamioAccountBindingLookup.transport
		savedLocal = BeamioAccountBindingLookup.localState
		savedDeviceK = BeamioAccountBindingLookup.deviceK
		savedDispatch = BeamioAccountBindingLookup.dispatch
		savedOverride = BeamioAccountBindingLookup.override
		savedClock = BeamioAccountBindingLookup.clock
		savedStore = BeamioNativeWallet.keyStore
		savedHost = BeamioNativeAccountCreate.onCreateRequired
		savedPgpMemory = BeamioChatPgpKeychain.memory
		BeamioAccountBindingLookup.override = nil
		BeamioAccountBindingLookup.dispatch = { $0() }
		BeamioAccountBindingLookup.clock = { [weak self] in self?.now ?? Date(timeIntervalSinceReferenceDate: 0) }
		BeamioAccountBindingLookup.transport = { [weak self] _, payload, _ in
			self?.answer(payload) ?? .failure(BeamioAccountBindingLookup.TransportFailure.other)
		}
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: false) }
		BeamioAccountBindingLookup.deviceK = { false }
		store = NativeAccountCreateTests.CreateKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
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
		BeamioAccountBindingLookup.clock = savedClock
		BeamioNativeAccountCreate.onCreateRequired = savedHost
		BeamioChatPgpKeychain.memory = savedPgpMemory
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioConetChatModule.closeAccountCreatePage()
		drain()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func vectorCases() throws -> [[String: Any]] {
		guard let path = ProcessInfo.processInfo.environment["PGP_MIGRATION_VECTORS"] else {
			throw XCTSkip("set PGP_MIGRATION_VECTORS to interface/protocol/pgp-migration-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
		return try XCTUnwrap(root["bindingLookupCases"] as? [[String: Any]])
	}

	func testEveryBindingLookupCaseMatchesItsExpectation() throws {
		let cases = try vectorCases()
		XCTAssertFalse(cases.isEmpty, "the vector file has binding lookup cases")
		for c in cases {
			try runCase(c)
		}
	}

	private func runCase(_ c: [String: Any]) throws {
		let id = try XCTUnwrap(c["id"] as? String)
		let input = try XCTUnwrap(c["input"] as? [String: Any], id)
		let expect = try XCTUnwrap(c["expect"] as? [String: Any], id)
		let wantCode = try XCTUnwrap(expect["code"] as? String, id)
		let wantCreation = try XCTUnwrap(expect["creationEntered"] as? Bool, id)
		reset(input)
		let account = (input["kind"] as? String) == "eoa" ? eoa : tag
		let sent = open(account: account)
		let verify: () -> Void = {
			XCTAssertEqual(self.transportCalls, 1, "\(id): the registry is read once")
			XCTAssertEqual(self.hostCalls, wantCreation ? 1 : 0, "\(id): creation entered")
			XCTAssertEqual(BeamioConetChatModule.accountCreatePageOpen(), wantCode == "create", "\(id): page open")
			XCTAssertEqual(self.ack(in: sent)?["ok"] as? Bool, true, "\(id): the open is answered ok:true")
			if wantCode == "create" {
				XCTAssertNil(self.result(in: sent), "\(id): creation sends no result")
			} else {
				XCTAssertEqual(accountCreateCode(self.result(in: sent)), wantCode, "\(id): result code")
				XCTAssertNil(accountCreateEoa(self.result(in: sent)), "\(id): no address with a binding code")
			}
			XCTAssertEqual(self.store.writes, 0, "\(id): no EOA is written")
		}
		verify()
	}

	/// Clears the device and the counters, then sets the case's local sources and clock.
	private func reset(_ input: [String: Any]) {
		BeamioConetChatModule.closeAccountCreatePage()
		drain()
		// The gate helper also clears the record of the last closed reqId, so each case opens its reqId afresh.
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		events = []
		transportCalls = 0
		hostCalls = 0
		now = Date(timeIntervalSinceReferenceDate: 0)
		store = NativeAccountCreateTests.CreateKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.clear()
		// The device's sources: a wallet key and the K record of this account are positive for it; a failed read is unreadable.
		// A K record of any account (createG0KPresent: K without a wallet key) is the device presence that fails the zero-owner tag path
		// closed. The tag path reads the account pointer, so the pointer is set for it.
		let present = (input["sdkWalletKey"] as? Bool) == true || (input["sdkK"] as? Bool) == true
		let kPresent = (input["sdkK"] as? Bool) == true || (input["createG0KPresent"] as? Bool) == true
		let unreadable = (input["sdkReadFailed"] as? Bool) == true
		// BL-53, BL-54 (25.52Y.109, Z.3 第 7 项): a K record of another workspace is seeded into the PGP store, and the production
		// readers of the device decide the answer. Every other case keeps the stubbed sources above.
		let nonActive = (input["sdkKNonActive"] as? Bool) == true
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		if nonActive {
			BeamioChatPgpKeychain.memory?.values[BeamioChatPgpKeychain.kAccount(eoa: eoa, workspace: "vector-other")] = Self.otherWorkspaceRecord(eoa: eoa)
			BeamioAccountBindingLookup.localState = BeamioAccountBindingLookup.defaultLocalState
			BeamioAccountBindingLookup.deviceK = { BeamioChatPgpKeychain.deviceHasPrivateRecord() }
		} else {
			BeamioAccountBindingLookup.localState = { _ in (present: present, unreadable: unreadable) }
			BeamioAccountBindingLookup.deviceK = { kPresent }
		}
		// PY.18 (r3rz, interface Y.54): a case with the precondition pointerEmpty keeps the pointer empty, whatever its kind.
		let preconditions = input["preconditions"] as? [String: Any]
		let pointerEmpty = (preconditions?["pointerEmpty"] as? Bool) == true
		if (input["kind"] as? String) == "tag" && !pointerEmpty {
			BeamioNativeAccountPointer.set(eoa)
		}
		current = input
	}

	/// One registry answer for the current case. Each call advances the fake clock by the case's `totalMs`.
	private func answer(_ payload: Data) -> Result<Data, Error> {
		transportCalls += 1
		let totalMs = (current["totalMs"] as? NSNumber)?.doubleValue ?? 0
		now = now.addingTimeInterval(totalMs / 1000)
		guard let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
		      let params = object["params"] as? [Any],
		      let call = params.first as? [String: Any],
		      let dataHex = call["data"] as? String,
		      let data = AddressPGPChain.bytes(fromHex: dataHex), data.count >= 4
		else { return .failure(BeamioAccountBindingLookup.TransportFailure.other) }
		let expected = (current["kind"] as? String) == "eoa"
			? AddressPGPChain.selector("getAccount(address)")
			: AddressPGPChain.selector("getOwnerByAccountName(string)")
		guard Array(data.prefix(4)) == expected else { return .failure(BeamioAccountBindingLookup.TransportFailure.other) }
		return render(reply(for: current))
	}

	/// The registry answer the case describes. Raw revert data is passed through unchanged; otherwise the outcome names the answer.
	private func reply(for input: [String: Any]) -> Reply {
		let kind = input["kind"] as? String ?? ""
		if let raw = input["revertData"] as? String { return .revert(raw) }
		let detail = input["detail"] as? String ?? ""
		switch input["outcome"] as? String ?? "" {
		case "empty":
			return kind == "eoa" ? .revert(notFoundData) : .result(AddressPGPChain.hex(zeroWord))
		case "bound":
			return kind == "eoa"
				? accountResult(name: "qa-vector", exists: true)
				: .result(AddressPGPChain.hex(AddressPGPChain.addressWord(eoa)))
		case "revert_not_found":
			return .revert(notFoundData)
		case "revert":
			return .revert("0x08c379a0")
		case "revert_args":
			return .revert(notFoundData + String(repeating: "0", count: 64))
		case "revert_empty":
			return .revert("0x")
		case "rpc_error":
			return .rpcError
		case "http_error":
			return .transport(BeamioAccountBindingLookup.TransportFailure.http)
		case "timeout":
			return .transport(BeamioAccountBindingLookup.TransportFailure.timeout)
		case "connection_refused":
			return .transport(URLError(.cannotConnectToHost))
		case "invalid_response":
			switch detail {
			case "owner_not_20_bytes": return .result(AddressPGPChain.hex(highBitsWord))
			case "exists_true_name_empty": return accountResult(name: "", exists: true)
			default: return .result(AddressPGPChain.hex(shortWord))
			}
		case "truncated":
			return .result(AddressPGPChain.hex(shortWord))
		case "undecodable":
			return .result("0xzz")
		case "semantic_invalid":
			if detail == "exists_false_name_nonempty" { return accountResult(name: "qa-vector", exists: false) }
			return .result(AddressPGPChain.hex(highBitsWord))
		case "non_json":
			return .raw(Data("<html>not json</html>".utf8))
		case "no_result":
			return .raw(json(["jsonrpc": "2.0", "id": 1]))
		case "success_exists_false":
			return accountResult(name: "", exists: false)
		default:
			return .rpcError
		}
	}

	private var zeroWord: [UInt8] { [UInt8](repeating: 0, count: 32) }
	private var shortWord: [UInt8] { [UInt8](repeating: 0, count: 31) }
	private var highBitsWord: [UInt8] {
		var word = zeroWord
		word[0] = 1
		return word
	}

	private func accountResult(name: String, exists: Bool) -> Reply {
		.result(AddressPGPChain.hex(bindingAccountAnswer(name: name, exists: exists)))
	}

	private func render(_ reply: Reply) -> Result<Data, Error> {
		switch reply {
		case .result(let hex):
			return .success(json(["jsonrpc": "2.0", "id": 1, "result": hex]))
		case .revert(let data):
			return .success(json(["jsonrpc": "2.0", "id": 1, "error": ["code": 3, "message": "execution reverted", "data": data]]))
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

	/// A K item of another workspace (the form of 25.52Y.77 第 2 条): a PGP private key of the test account, in memory only.
	private static func otherWorkspaceRecord(eoa: String) -> String {
		let record: [String: String] = [
			"eoa": eoa,
			"workspace": "vector-other",
			"keyId": "vector-other",
			"publicKeyArmor": "",
			"privateKeyArmor": "-----BEGIN PGP PRIVATE KEY BLOCK-----\nvector\n-----END PGP PRIVATE KEY BLOCK-----",
			"createdAt": "2026-11-16T00:00:00Z",
		]
		return String(data: (try? JSONSerialization.data(withJSONObject: record)) ?? Data(), encoding: .utf8) ?? ""
	}

	/// Lets the main queue run everything the open chains onto it, then returns.
	private func drain() {
		for _ in 0 ..< 5 {
			RunLoop.main.run(until: Date().addingTimeInterval(0.05))
		}
	}

	/// Opens the creation page as the bridge does, and returns the events the open produced.
	private func open(account: String) -> [[String: Any]] {
		let body: [String: Any] = ["type": "nativeAccountCreateOpen", "reqId": 3, "account": account]
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
}
