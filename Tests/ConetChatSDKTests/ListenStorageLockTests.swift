#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// J1: a storage-derived lock during a run ends the run and drops the account's signer. Test build only: the run
/// is marked without the native gate, so the stop path is exercised. The loop's own check (`storageDerivedLocked`) is covered by
/// WalletLayerGateTests; the loop itself cannot run while the gate is closed (see the receipt).
final class ListenStorageLockTests: XCTestCase {
	override func tearDown() {
		BeamioConetChatSignBroker.clearSigner()
		super.tearDown()
	}

	func testAStorageLockEndsTheRunAndDropsTheSigner() {
		let listen = BeamioConetChatListenSession()
		let gen = listen.markRunningForTests()
		XCTAssertTrue(listen.isRunning())
		BeamioConetChatSignBroker.setSignerEoa("0x0000000000000000000000000000000000000001")
		XCTAssertFalse(BeamioConetChatSignBroker.currentSignerEoa().isEmpty)

		var statuses: [(String, String?)] = []
		listen.endForStorageLock(gen: gen, onStatus: { statuses.append(($0, $1)) })

		XCTAssertFalse(listen.isRunning(), "the run must stop")
		XCTAssertEqual(BeamioConetChatSignBroker.currentSignerEoa(), "", "the signer for the account must be dropped")
		XCTAssertEqual(statuses.count, 1)
		XCTAssertEqual(statuses.first?.0, "idle")
		XCTAssertEqual(statuses.first?.1, "locked")
	}

	/// A run that was already stopped (or replaced) does not report or change anything.
	func testAStaleRunDoesNothing() {
		let listen = BeamioConetChatListenSession()
		let gen = listen.markRunningForTests()
		listen.stop()
		BeamioConetChatSignBroker.setSignerEoa("0x0000000000000000000000000000000000000002")

		var statuses: [(String, String?)] = []
		listen.endForStorageLock(gen: gen, onStatus: { statuses.append(($0, $1)) })

		XCTAssertTrue(statuses.isEmpty, "a stale run must not report")
		XCTAssertFalse(BeamioConetChatSignBroker.currentSignerEoa().isEmpty, "a stale run must not drop the signer")
	}
}
#endif
