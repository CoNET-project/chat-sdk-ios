import CryptoKit
import Foundation
import XCTest
@testable import ConetChatSDK

/// The shipped `hello` list of the iOS SDK (25.52Y.121 第 1 条): 16 names, the 14 implemented names and then `identity.kpresent.v1` and
/// `identity.native-keys.v1` in that order. It is the same in a Release build (no BEAMIO_QA_BUILD); a QA build adds its own names after it.
/// The shared vector file is `chat-daemon-vectors.v1.json`, sha256 13073ba4… (25.52Y.121 第 4 项).
final class HelloShippedListTests: XCTestCase {
	static let shippedIosList: [String] = [
		"identity.provision",
		"signing.local",
		"lifecycle.daemon",
		"inbound.deferAck",
		"inbound.generation.v1",
		"history.v2",
		"call.control",
		"voice.delegated",
		"presence.query",
		"mailbox.command",
		"send.mailboxWrap",
		"history.local.v1",
		"history.page.v1",
		"layout.cache.v1",
		"identity.kpresent.v1",
		"identity.native-keys.v1",
		"wallet.passcode.v1",
	]

	private static let registeredVectorSha = "da2f86b6af55b25d65fc9821f3db0432e81a39d1c5d98da66e01c3f5483dab6a"

	func testTheShippedIosListIsTheSeventeenNamesInOrder() throws {
		#if !BEAMIO_QA_BUILD
		XCTAssertEqual(BeamioConetChatProtocol.capabilities, Self.shippedIosList)
		XCTAssertEqual(BeamioConetChatProtocol.helloResult()["capabilities"] as? [String], Self.shippedIosList)
		#else
		XCTAssertEqual(Array(BeamioConetChatProtocol.capabilities.prefix(Self.shippedIosList.count)), Self.shippedIosList)
		#endif
	}

	func testTheSharedVectorFileIsTheRegisteredOneAndItsIosListIsTheShippedList() throws {
		let url = try XCTUnwrap(Bundle.module.url(forResource: "chat-daemon-vectors.v1", withExtension: "json"))
		let data = try Data(contentsOf: url)
		let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(digest, Self.registeredVectorSha, "the bundled chat-daemon vectors are the registered da2f86b6 file")
		let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		let hello = try XCTUnwrap(root["hello"] as? [String: Any])
		let ios = try XCTUnwrap((hello["implementations"] as? [String: Any])?["ios"] as? [String: Any])
		XCTAssertEqual(ios["capabilities"] as? [String], Self.shippedIosList, "the iOS list of the vector is the shipped list")
	}

	/// A Release build reports the formal version and no qa suffix; a QA build keeps its qa suffix.
	func testTheReleaseSdkVersionCarriesNoQASuffix() {
		#if !BEAMIO_QA_BUILD
		XCTAssertEqual(BeamioConetChatProtocol.sdkVersion, "0.2.3")
		XCTAssertFalse(BeamioConetChatProtocol.sdkVersion.contains("qa"), "a Release sdkVersion carries no qa")
		XCTAssertEqual(BeamioConetChatProtocol.helloResult()["sdkVersion"] as? String, "0.2.3")
		#else
		XCTAssertTrue(BeamioConetChatProtocol.sdkVersion.contains("qa"), "a QA build keeps its qa suffix")
		#endif
	}

	/// Writes the raw `hello` answer of this build to HELLO_DUMP_PATH when that variable is set (receipt evidence; no effect otherwise).
	func testWriteTheHelloAnswerWhenAPathIsGiven() throws {
		guard let path = ProcessInfo.processInfo.environment["HELLO_DUMP_PATH"], !path.isEmpty else {
			throw XCTSkip("set HELLO_DUMP_PATH to write the raw hello answer")
		}
		// The answer as the bridge emits it: the module's own `hello` ack, not a re-built dictionary.
		var ack: [String: Any]?
		let done = expectation(description: "hello ack")
		BeamioConetChatModule.handleCommand(["type": "hello", "reqId": 1, "protocolVersion": 1], emit: { payload in
			let inner = (payload["event"] as? [String: Any]) ?? payload
			if inner["type"] as? String == "ack" {
				ack = inner
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		let data = try JSONSerialization.data(withJSONObject: try XCTUnwrap(ack), options: [.sortedKeys])
		try data.write(to: URL(fileURLWithPath: path))
	}
}
