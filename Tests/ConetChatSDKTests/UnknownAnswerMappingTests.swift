import XCTest
@testable import ConetChatSDK

/// The unknown answers of the chain reads (iOS review C-1, coordinator 2026-11-16): a bare `0x`, a timeout and a malformed answer are unknown, never
/// "no record". Binding lookup: they give `unavailable` (page: `lookup_unavailable`). Only the exact AccountNotFound revert is no record. Recovery
/// source: they are errors. The transports are replaced; no chain is reached and the values are synthetic.
final class UnknownAnswerMappingTests: XCTestCase {
	private let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private var savedBindingTransport: ((URL, Data, TimeInterval) -> Result<Data, Error>)!
	private var savedRegistryTransport: ((URL, Data, TimeInterval) -> Result<Data, Error>)!
	/// The `eth_call` answer that both endpoints give: a JSON object (`result` or `error`), or a transport failure.
	private var call: Result<[String: Any], Error> = .success(["result": "0x"])

	override func setUp() {
		super.setUp()
		savedBindingTransport = BeamioAccountBindingLookup.transport
		savedRegistryTransport = BeamioRecoveryRegistry.transport
		let responder: (URL, Data, TimeInterval) -> Result<Data, Error> = { [unowned self] _, body, _ in self.endpointAnswer(body) }
		BeamioAccountBindingLookup.transport = responder
		BeamioRecoveryRegistry.transport = responder
	}

	override func tearDown() {
		BeamioAccountBindingLookup.transport = savedBindingTransport
		BeamioRecoveryRegistry.transport = savedRegistryTransport
		super.tearDown()
	}

	private func endpointAnswer(_ body: Data) -> Result<Data, Error> {
		switch call {
		case .failure(let error): return .failure(error)
		case .success(var object):
			object["jsonrpc"] = "2.0"
			object["id"] = 1
			guard let data = try? JSONSerialization.data(withJSONObject: object) else { return .failure(AddressPGPChain.ReadError.malformed) }
			return .success(data)
		}
	}

	private func failure<T>(of result: Result<T, Error>) -> Error? {
		if case .failure(let error) = result { return error }
		return nil
	}

	// MARK: - Binding lookup: a bare 0x, a timeout and a malformed answer are unavailable

	func testABareZeroIsUnavailableForTheAccount() {
		call = .success(["result": "0x"])
		guard case .unavailable = BeamioAccountBindingLookup.readAccount(eoa, remaining: 10) else {
			return XCTFail("a bare 0x is unknown, never no binding")
		}
	}

	func testABareZeroIsUnavailableForTheOwner() {
		call = .success(["result": "0x"])
		guard case .unavailable = BeamioAccountBindingLookup.readOwner("alice", remaining: 10) else {
			return XCTFail("a bare 0x owner answer is unknown, never a zero address")
		}
	}

	func testATimeoutIsUnavailableForTheAccount() {
		call = .failure(URLError(.timedOut))
		guard case .unavailable(let reason) = BeamioAccountBindingLookup.readAccount(eoa, remaining: 10) else {
			return XCTFail("a timeout is unknown")
		}
		XCTAssertEqual(reason, "timeout")
	}

	func testAMalformedAnswerIsUnavailableForTheAccount() {
		call = .success(["result": "0xzz"])
		guard case .unavailable(let reason) = BeamioAccountBindingLookup.readAccount(eoa, remaining: 10) else {
			return XCTFail("a malformed answer is unknown")
		}
		XCTAssertEqual(reason, "malformed")
	}

	/// Only the exact AccountNotFound revert is no binding.
	func testTheExactAccountNotFoundRevertIsNoBinding() {
		call = .success(["error": ["code": 3, "message": "reverted", "data": "0xfaba8ebe"]])
		guard case .notFound = BeamioAccountBindingLookup.readAccount(eoa, remaining: 10) else {
			return XCTFail("the exact AccountNotFound is no binding")
		}
	}

	/// Any other revert data is unknown, not no binding.
	func testAnotherRevertIsUnavailableNotNoBinding() {
		call = .success(["error": ["code": 3, "message": "reverted", "data": "0x08c379a0"]])
		guard case .unavailable(let reason) = BeamioAccountBindingLookup.readAccount(eoa, remaining: 10) else {
			return XCTFail("another revert is unknown")
		}
		XCTAssertEqual(reason, "revert")
	}

	// MARK: - Recovery source: a timeout and a malformed answer are errors

	func testARecoverySourceTimeoutIsAnError() {
		call = .failure(URLError(.timedOut))
		XCTAssertNotNil(failure(of: BeamioRecoveryRegistry.readRegistry(to: BeamioRecoveryRegistry.registryAddress, data: [0x01])))
	}

	func testARecoverySourceMalformedAnswerIsAnError() {
		call = .success(["result": "0xzz"])
		XCTAssertNotNil(failure(of: BeamioRecoveryRegistry.readRegistry(to: BeamioRecoveryRegistry.registryAddress, data: [0x01])))
	}
}
