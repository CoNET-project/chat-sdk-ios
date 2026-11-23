import XCTest
@testable import ConetChatSDK

/// The recovery source's empty answers, end to end through `BeamioNativeRecovery.restore` (coordinator, iOS review 2026-11-16, C-1). A bare `0x` is
/// unknown: `network_error`, retryable, and it is not a path B failure (the PIN counter is not written). Only a legal ABI empty string (at least 64
/// bytes, length 0) is "no record" (`not_found`). The transport is replaced, the PIN counter is a double, and no chain is reached.
final class RecoveryEmptyAnswerRestoreTests: XCTestCase {
	private final class CountingAttempts: BeamioNativeRecovery.PinAttemptStoring {
		var saves = 0
		func load() -> (failures: Int, lastFailure: Date?) { (0, nil) }
		func save(failures: Int, lastFailure: Date?) { saves += 1 }
	}

	private var savedRegistry: BeamioRecoveryRegistryReading?
	private var savedAttempts: BeamioNativeRecovery.PinAttemptStoring?
	private var savedTransport: ((URL, Data, TimeInterval) -> Result<Data, Error>)!
	private var attempts = CountingAttempts()
	/// The `eth_call` answer that both endpoints give: a JSON object (`result` or `error`).
	private var callAnswer: [String: Any] = ["result": "0x"]

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedRegistry = BeamioNativeRecovery.registry
		savedAttempts = BeamioNativeRecovery.attempts
		savedTransport = BeamioRecoveryRegistry.transport
		BeamioNativeRecovery.registry = BeamioRecoveryRegistry()
		BeamioNativeRecovery.attempts = attempts
		BeamioRecoveryRegistry.transport = { [unowned self] _, body, _ in self.endpointAnswer(body) }
	}

	override func tearDown() {
		BeamioRecoveryRegistry.transport = savedTransport
		BeamioNativeRecovery.attempts = savedAttempts ?? BeamioNativeRecovery.attempts
		BeamioNativeRecovery.registry = savedRegistry
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func endpointAnswer(_ body: Data) -> Result<Data, Error> {
		guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
			return .failure(AddressPGPChain.ReadError.malformed)
		}
		var answer = callAnswer
		answer["jsonrpc"] = "2.0"
		answer["id"] = object["id"] ?? 1
		guard let data = try? JSONSerialization.data(withJSONObject: answer) else { return .failure(AddressPGPChain.ReadError.malformed) }
		return .success(data)
	}

	/// An ABI `string` return value: the offset word (32), the length word, and the UTF-8 bytes padded to 32.
	private func encodedString(_ text: String) -> String {
		func word(_ n: Int) -> [UInt8] { [UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) } }
		let bytes = Array(text.utf8)
		return AddressPGPChain.hex(word(32) + word(bytes.count) + bytes + [UInt8](repeating: 0, count: (32 - bytes.count % 32) % 32))
	}

	private func restore(_ store: MemoryNativeKeyStore) -> BeamioNativeRecovery.RestoreOutcome {
		BeamioNativeRecovery.restore(.account(name: "syn_empty_0001", password: Array("x1".utf8)), store: store)
	}

	/// A bare `0x` is unknown: a retryable network error. The PIN counter is not written, and nothing is written to the store.
	func testABareZeroIsNetworkErrorRetryableAndNotAPathBFailure() {
		callAnswer = ["result": "0x"]
		let store = MemoryNativeKeyStore()
		XCTAssertEqual(restore(store).code, "network_error")
		XCTAssertEqual(restore(store).code, "network_error", "retryable: the same answer is still unknown, not a stored no-record")
		XCTAssertEqual(attempts.saves, 0, "a network error is not a wrong PIN")
		XCTAssertEqual(store.mutationCount, 0)
	}

	/// The legal encoded empty string is the one answer that means no record.
	func testALegalEmptyStringIsNoRecord() {
		callAnswer = ["result": encodedString("")]
		XCTAssertEqual(restore(MemoryNativeKeyStore()).code, "not_found")
		XCTAssertEqual(attempts.saves, 0)
	}

	/// A result shorter than one ABI word is malformed: unknown, not a record.
	func testAShortResultIsNetworkError() {
		callAnswer = ["result": "0x" + String(repeating: "0", count: 62)]
		XCTAssertEqual(restore(MemoryNativeKeyStore()).code, "network_error")
		XCTAssertEqual(attempts.saves, 0)
	}

	/// A non-hex result is malformed: unknown, not a record.
	func testAMalformedResultIsNetworkError() {
		callAnswer = ["result": "0xzz"]
		XCTAssertEqual(restore(MemoryNativeKeyStore()).code, "network_error")
		XCTAssertEqual(attempts.saves, 0)
	}
}
