#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// the hello declares `inbound.generation.v1`; a decrypted JSON object without `text` or `signMessage` does not
/// verify, so the frame is dropped with no marker and no ack. Synthetic data only.
final class HelloInboundGenerationTests: XCTestCase {
	func testHelloDeclaresTheInboundGenerationCapability() {
		let capabilities = BeamioConetChatProtocol.helloResult()["capabilities"] as? [String] ?? []
		XCTAssertTrue(capabilities.contains("inbound.generation.v1"), "the hello answer declares inbound.generation.v1")
	}

	func testAJSONObjectWithoutSignMessageDoesNotVerify() {
		assertDoesNotVerify("{\"text\":\"hello\",\"from\":\"0x1\"}")
	}

	func testAJSONObjectWithoutTextDoesNotVerify() {
		assertDoesNotVerify("{\"signMessage\":\"0xsynthetic\",\"from\":\"0x1\"}")
	}

	private func assertDoesNotVerify(_ plaintext: String) {
		let done = expectation(description: "verify completes")
		var answered = false
		var verified: String?
		BeamioConetChatModule.verifyEnvelope(plaintext: plaintext, host: BeamioOpenPgpHost.shared) { from in
			answered = true
			verified = from
			done.fulfill()
		}
		wait(for: [done], timeout: 5)
		XCTAssertTrue(answered)
		XCTAssertNil(verified, "a frame that does not verify is dropped: no marker, no ack")
	}
}
#endif
