#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// Diagnostic only (test build; no product log). Traces the walletStatus chain of E911-01 and E911-03 step by step, so the cause of the
/// `not_ready` answer is written down, not guessed. Printed as `E911DIAG <step> <values>`.
final class E911DiagnosticTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
	}

	override func tearDown() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func trace(_ step: String, _ values: String) {
		print("E911DIAG \(step) \(values)")
	}

	private func snapshotValues() -> String {
		guard let e = BeamioNativeKeySnapshot.current() else { return "current=nil" }
		return "current=present unreadable=\(e.unreadable) storageLock=\(String(describing: e.storageLock))"
	}

	func testTraceE911_01() {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { return XCTFail("derives") }
		let a = d.eoa
		XCTAssertTrue(store.writeItem(.key, eoa: a, value: d.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a, value: BeamioPwaWalletSync.normalized(phraseA)))
		XCTAssertTrue(store.writeItem(.intent, eoa: a, value: Data(#"{"v":1,"phase":"pending"}"#.utf8)))
		let marker: [String: Any] = ["v": 1, "phase": "pending", "eoa": a, "tag": "diag", "source": "pwaWalletSync",
		                             "utc": "2026-11-17T00:00:00Z", "owners": [a], "moves": [], "partials": []]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: marker, options: [.sortedKeys])) ?? Data()
		BeamioNativeAccountPointer.set(a)
		BeamioConetChatModule.setNativeGateForTests(account: a, sessionReady: true)
		trace("01.setup", "pointer=\(BeamioNativeAccountPointer.get()) keyStoreIsStore=\(BeamioNativeWallet.keyStore as AnyObject === store)")
		trace("02.snapshotBeforeStart", snapshotValues())
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		trace("03.snapshotAfterStart", snapshotValues() + " isKnown=\(BeamioNativeKeySnapshot.isKnown)")
		trace("04.settlementLockPending", "\(BeamioConetChatModule.settlementLockPending())")
		trace("05.nativeGate", "\(BeamioConetChatModule.nativeGate())")
		trace("06.recordAccount", "\(String(describing: BeamioConetChatModule.recordAccount()))")
		trace("07.hasRecord", "\(BeamioNativeWallet.hasRecord(eoa: a))")
		trace("08.mnemonicAccountState", "\(store.mnemonicAccountState(owner: a))")
		trace("09.isIntentUnavailable", "\(BeamioNativeKeyImport.isIntentUnavailable(eoa: a))")
		trace("10.walletMarkersUnreadable", "\(BeamioNativeKeyImport.walletMarkersUnreadable(eoa: a, store: store))")
		trace("11.keyRecordState", "\(store.keyRecordState(eoa: a))")
		trace("12.itemStates", "mnemonic=\(store.itemState(.mnemonic, eoa: a)) commit=\(store.itemState(.commit, eoa: a)) intent=\(store.itemState(.intent, eoa: a))")
		trace("13.appState", "\(BeamioPasscodeSession.shared.appState(eoa: a))")
		trace("14.pwaPreread", "\(BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state.rawValue)")
		BeamioPwaPhraseOverwrite.settleOnceAtStart()
		trace("17.afterSettle", snapshotValues() + " isKnown=\(BeamioNativeKeySnapshot.isKnown) gate=\(BeamioConetChatModule.nativeGate()) marker=\(store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount) != .absent) mnemonic=\(store.itemState(.mnemonic, eoa: a))")
		var events: [[String: Any]] = []
		BeamioConetChatModule.nativeObserver = { out in events.append(out) }
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": 9911], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while !events.contains(where: { ($0["event"] as? [String: Any])?["reqId"] as? Int == 9911 }), Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		BeamioConetChatModule.nativeObserver = nil
		trace("15.walletStatusCommandAnswer", "\(events)")
		trace("16.snapshotAfterCommand", snapshotValues() + " isKnown=\(BeamioNativeKeySnapshot.isKnown)")
	}

	func testTraceE911_03() {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phraseA) else { return XCTFail("derives") }
		let a = d.eoa
		XCTAssertTrue(store.writeItem(.key, eoa: a, value: d.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a, value: Data("not a valid phrase for this account".utf8)))
		XCTAssertTrue(store.writeItem(.intent, eoa: a, value: Data(#"{"v":1,"phase":"pending"}"#.utf8)))
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		trace("20.snapshot", snapshotValues() + " isKnown=\(BeamioNativeKeySnapshot.isKnown)")
		trace("21.pointer", "'\(BeamioNativeAccountPointer.get())'")
		trace("22.nativeGate", "\(BeamioConetChatModule.nativeGate())")
		trace("23.recordAccount", "\(String(describing: BeamioConetChatModule.recordAccount()))")
		trace("24.residueProbeAll", "\(BeamioResidueProbe.probe())")
		trace("25.residueProbeIgnoringIntents", "\(BeamioResidueProbe.probe(ignoringIntents: true))")
		trace("26.mnemonicAccountState", "\(store.mnemonicAccountState(owner: a))")
		trace("27.nativeJudgement", "\(BeamioShellRecord.nativeJudgement())")
	}
}
#endif
