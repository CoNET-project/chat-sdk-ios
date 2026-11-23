import XCTest
@testable import ConetChatSDK

/// (a): while `BeamioPGPNative.available` is false, no start and no resume of the mailbox listen runs. Nothing is connected
/// and no loop is started; the status says `blocked` with the pending code. Synthetic account only; no network is reached.
final class ListenGateTests: XCTestCase {
	private func session() -> BeamioConetChatModule.Session {
		let s = BeamioConetChatModule.Session()
		s.eoa = "0x0000000000000000000000000000000000000001"
		return s
	}

	func testStartDoesNotRunWhileTheNativeLayerIsClosed() throws {
		try XCTSkipIf(BeamioPGPNative.available, "the native layer is open in this build")
		let listen = BeamioConetChatListenSession()
		var statuses: [(String, String?)] = []
		listen.start(
			session: session(),
			onStatus: { statuses.append(($0, $1)) },
			onInbound: { _, _, _, _ in XCTFail("no inbound message may arrive while the layer is closed") }
		)
		XCTAssertFalse(listen.isRunning(), "no loop may be started")
		XCTAssertEqual(statuses.count, 1)
		XCTAssertEqual(statuses.first?.0, "blocked")
		XCTAssertEqual(statuses.first?.1, BeamioPGPNative.pendingCode)
	}

	/// The gate follows the X-19 link, in every build (owner requirement; no QA flag). Nothing is started here, so no network is reached.
	func testTheGateFollowsTheX19Link() {
		XCTAssertEqual(BeamioPGPNative.available, BeamioPGPNative.linked, "open exactly when X-19 is linked, in every build")
	}

	/// With X-19 linked, the listen is not blocked by the native gate: the reason `pgp_native_pending` does not apply.
	func testTheListenIsNotBlockedWhenX19IsLinked() throws {
		try XCTSkipUnless(BeamioPGPNative.linked, "X-19 is not linked in this build (macOS test build); the simulator runs this case")
		XCTAssertTrue(BeamioPGPNative.available)
	}

	func testResumeDoesNotRunWhileTheNativeLayerIsClosed() throws {
		try XCTSkipIf(BeamioPGPNative.available, "the native layer is open in this build")
		let listen = BeamioConetChatListenSession()
		var statuses: [(String, String?)] = []
		listen.resume(
			session: session(),
			onStatus: { statuses.append(($0, $1)) },
			onInbound: { _, _, _, _ in XCTFail("no inbound message may arrive while the layer is closed") }
		)
		XCTAssertFalse(listen.isRunning(), "a resume must not start a loop either")
		XCTAssertFalse(listen.isListening())
		XCTAssertEqual(statuses.first?.0, "blocked")
		XCTAssertEqual(statuses.first?.1, BeamioPGPNative.pendingCode)
	}
}
