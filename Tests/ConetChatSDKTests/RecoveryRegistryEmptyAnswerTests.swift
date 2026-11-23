import XCTest
@testable import ConetChatSDK

/// C-1 (iOS review, 2026-11-16): the recovery source answers an ABI `string`. An empty result (`0x`) is not an encoded string, so it is unknown,
/// never "no record". Only an encoded empty string (offset word, zero length word; 64 bytes or more) is "no record". The transport is replaced:
/// no chain is reached, and the values are synthetic.
final class RecoveryRegistryEmptyAnswerTests: XCTestCase {
	private var savedTransport: ((URL, Data, TimeInterval) -> Result<Data, Error>)!
	/// The `eth_call` answer that both endpoints give: a `result` (hex) or an `error` object.
	private var callAnswer: [String: Any] = [:]

	override func setUp() {
		super.setUp()
		savedTransport = BeamioRecoveryRegistry.transport
		BeamioRecoveryRegistry.transport = { [unowned self] _, body, _ in self.endpointAnswer(body) }
	}

	override func tearDown() {
		BeamioRecoveryRegistry.transport = savedTransport
		super.tearDown()
	}

	/// The block queries are answered with one fixed block; `eth_call` with `callAnswer`, both endpoints alike.
	private func endpointAnswer(_ body: Data) -> Result<Data, Error> {
		guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
		      object["method"] as? String == "eth_call"
		else { return .failure(AddressPGPChain.ReadError.rpc("unexpected request")) }
		var answer = callAnswer
		answer["jsonrpc"] = "2.0"
		answer["id"] = object["id"] ?? 1
		guard let data = try? JSONSerialization.data(withJSONObject: answer) else { return .failure(AddressPGPChain.ReadError.malformed) }
		return .success(data)
	}

	private func word(_ n: Int) -> [UInt8] {
		[UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) }
	}

	/// An ABI `string` return value: the offset word (32), the length word, and the UTF-8 bytes padded to 32.
	private func encodedString(_ text: String) -> String {
		let bytes = Array(text.utf8)
		let padding = (32 - bytes.count % 32) % 32
		return AddressPGPChain.hex(word(32) + word(bytes.count) + bytes + [UInt8](repeating: 0, count: padding))
	}

	private func readRecord() -> Result<String, Error> {
		BeamioRecoveryRegistry.readRegistry(to: BeamioRecoveryRegistry.registryAddress, data: [0x01])
	}

	private func failure<T>(of result: Result<T, Error>) -> Error? {
		if case .failure(let error) = result { return error }
		return nil
	}

	private func success<T>(of result: Result<T, Error>) -> T? {
		if case .success(let value) = result { return value }
		return nil
	}

	/// The empty answer `0x` is not an ABI string: it is unknown (an error), never a record that does not exist.
	func testAnEmptyResultIsUnknownNotNoRecord() {
		callAnswer = ["result": "0x"]
		XCTAssertNil(success(of: readRecord()), "0x is not a recovery answer")
		XCTAssertNotNil(failure(of: readRecord()), "0x is unknown: the caller retries, it does not treat the account as absent")
	}

	/// Fewer than the 32 bytes of one word: malformed, not an empty record.
	func testAShortResultIsMalformed() {
		callAnswer = ["result": "0x" + String(repeating: "0", count: 62)]
		XCTAssertNil(success(of: readRecord()))
		XCTAssertNotNil(failure(of: readRecord()))
	}

	/// The encoded empty string is the one answer that means "no record".
	func testAnEncodedEmptyStringIsNoRecord() {
		callAnswer = ["result": encodedString("")]
		XCTAssertEqual(success(of: readRecord()), "")
	}

	func testANonEmptyRecordIsReturned() {
		callAnswer = ["result": encodedString("rec-1")]
		XCTAssertEqual(success(of: readRecord()), "rec-1")
	}

	/// A revert (the registry's error data) is an error, never a record and never an empty one.
	func testARevertIsAnErrorNotNoRecord() {
		callAnswer = ["error": ["code": 3, "message": "reverted", "data": "0xfaba8ebe"]]
		XCTAssertNil(success(of: readRecord()))
		XCTAssertNotNil(failure(of: readRecord()))
	}
}
