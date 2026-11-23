import XCTest
@testable import ConetChatSDK

/// The residue probe of 25.52Y.162 at walletStatus with no pointer: a residue is not_ready/unreadable, no residue is no_key, a failed
/// probe is not_ready/unreadable. The probe reads no value and deletes no item; the test memory of the chat-wallet service is checked
/// before and after.
final class ResidueProbeTests: XCTestCase {
	private var savedItems: [String: Data]?
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedItems = BeamioChatWalletTestMemory.items
		BeamioChatWalletTestMemory.items = [:]
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
		BeamioNativeAccountPointer.clear()
		BeamioNativeKeySnapshot.invalidate()
	}

	override func tearDown() {
		#if BEAMIO_TEST_HOOKS
		BeamioResidueProbe.overrideForTests = nil
		#endif
		BeamioChatWalletTestMemory.items = savedItems
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioNativeAccountPointer.clear()
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func walletStatusResult() -> [String: Any] {
		var sent: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 4], emit: { sent.append(($0["event"] as? [String: Any]) ?? $0) })
		let until = Date().addingTimeInterval(0.1)
		while Date() < until { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
		return (sent.first { $0["type"] as? String == "ack" }?["result"] as? [String: Any]) ?? [:]
	}

	/// A residue exists (a mnemonic item with no key record): not_ready/unreadable. The item is neither read nor deleted.
	func testAResidueAnswersNotReadyUnreadableAndDeletesNothing() {
		let residue = Data("synthetic-residue-value".utf8)
		BeamioChatWalletTestMemory.put("com.beamio.beamio.chat-wallet", "mnemonic:0x0000000000000000000000000000000000000001", residue)
		let before = BeamioChatWalletTestMemory.items
		let result = walletStatusResult()
		XCTAssertEqual(result["status"] as? String, "not_ready")
		XCTAssertEqual(result["notReadyReason"] as? String, "unreadable")
		XCTAssertEqual(BeamioChatWalletTestMemory.items, before, "no item is read into a change, deleted or added")
	}

	/// The probe succeeds and finds no residue: no_key.
	func testNoResidueAnswersNoKey() {
		XCTAssertEqual(BeamioChatWalletTestMemory.items?.count, 0)
		let result = walletStatusResult()
		XCTAssertEqual(result["status"] as? String, "no_key")
	}

	/// The probe fails (refused, incomplete or erroring): not_ready/unreadable, never no_key.
	func testAFailedProbeAnswersNotReadyUnreadable() {
		#if BEAMIO_TEST_HOOKS
		BeamioResidueProbe.overrideForTests = { .failed }
		#endif
		let result = walletStatusResult()
		XCTAssertEqual(result["status"] as? String, "not_ready")
		XCTAssertEqual(result["notReadyReason"] as? String, "unreadable")
	}
}
