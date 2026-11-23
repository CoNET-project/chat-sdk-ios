#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The iOS-applicable E9.10.3 vectors (WK-29a, WK-04a, WK-30a, WK-31a, G1-NK-S1-CORRECTED; SPEC-59E-REVIEWABLE, decided 2026-11-17). The iOS keys are
/// the E9.7 correspondence: REC = `walletKey:<eoa>`, MARK = `wallet.sync.marker`, MNEM = `mnemonic:<eoa>`, INTENT = `intent:<eoa>`.
/// Each case runs `walletStatus` through the command and the preread reading of the same store. A WK-30a `state` is non-normative (E9.10.4-2): only
/// walletStatus and the preread are checked there. An input the store model cannot produce is `NOT_MAPPED` with its reason, and is not counted as passed.
/// Outcomes are printed as `E9103 <id> <outcome> <reason>`.
final class E9103VectorTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var events: [[String: Any]] = []
	private var outcomes: [String] = []

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		savedStore = BeamioNativeWallet.keyStore
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func fresh() {
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioNativeKeySnapshot.invalidate()
	}

	private func owner(_ phrase: String) -> (eoa: String, key: Data) {
		guard let derived = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { preconditionFailure("the test phrase derives an account") }
		return derived
	}

	private func ackResult(_ reqId: Int) -> [String: Any]? {
		events.compactMap { out -> [String: Any]? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack", event["reqId"] as? Int == reqId else { return nil }
			return event["result"] as? [String: Any]
		}.first
	}

	private func walletStatus(_ reqId: Int) -> String {
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": reqId], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while ackResult(reqId) == nil, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
		guard let result = ackResult(reqId) else { return "unanswered" }
		return result["status"] as? String ?? "?"
	}

	private func preread() -> BeamioPwaWalletSync.Preread {
		BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store).state
	}

	/// A pending overwrite marker (MARK) naming `eoa` as its account, with no move: the MARK exists, its record may or may not agree.
	private func markPending(eoa: String) {
		let object: [String: Any] = ["v": 1, "phase": "pending", "eoa": eoa, "tag": "wk", "source": "pwaWalletSync",
		                             "utc": "2026-11-17T00:00:00Z", "owners": [eoa], "moves": [], "partials": []]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
	}

	private func record(_ id: String, _ outcome: String, _ reason: String) {
		outcomes.append("E9103 \(id) \(outcome) \(reason)")
	}

	func testIOSApplicableE9103Vectors() {
		// WK-30a: REC present (key only), MARK and COMMIT absent, MNEM read ok and empty. No account. (state non-normative, E9.10.4-2.)
		fresh()
		let a = owner(phraseA)
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		let ws30 = walletStatus(10030)
		let pr30 = preread()
		if ws30 == "no_key" && pr30 == .absent {
			record("WK-30a", "PASS", "walletStatus no_key, preread absent (state non-normative)")
		} else {
			record("WK-30a", "FAIL", "walletStatus \(ws30), preread \(pr30.rawValue); expected no_key and absent")
		}

		// WK-04a: MARK does not agree with REC (the pending marker names another account), MNEM read ok and empty, no read failure. No account.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		markPending(eoa: owner(phraseB).eoa)
		let ws04 = walletStatus(10004)
		let pr04 = preread()
		XCTAssertEqual(pr04, .absent, "the preread is absent: the marker does not block the reading")
		XCTAssertEqual(ws04, "no_key", "E9.10.3-3: the settlement lock yields to walletStatus when the mnemonic reads empty")
		record("WK-04a", "PASS", "walletStatus no_key, preread absent; the mismatched marker does not block (E4 lock yields to walletStatus)")

		// WK-31a: REC missing (no key record), MARK present, MNEM read ok and empty. No account; the MARK is retained.
		fresh()
		markPending(eoa: a.eoa)
		let ws31 = walletStatus(10031)
		let pr31 = preread()
		let markKept = store.rawRead(account: BeamioPwaPhraseOverwrite.markerAccount) != .absent
		XCTAssertEqual(pr31, .absent, "the preread is absent")
		XCTAssertTrue(markKept, "the marker is kept")
		XCTAssertEqual(ws31, "no_key", "E9.10.3-3: the settlement lock yields to walletStatus")
		record("WK-31a", "PASS", "walletStatus no_key, preread absent, marker kept")

		// WK-29a: REC read failure (aead_failed, walletKey:<eoa> unreadable), MNEM read ok and empty, no INTENT. The current record is no account; the
		// sealed copies are the third position (not in this input); the REC bytes are kept.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		store.failKeyReadOwners.insert(a.eoa.lowercased())
		let ws29 = walletStatus(10029)
		let pr29 = preread()
		XCTAssertEqual(pr29, .absent, "WK-29a: the phrase verdict is absent")
		XCTAssertEqual(ws29, "no_key", "WK-29a: the current record judges no account")
		XCTAssertNotNil(store.keys[a.eoa.lowercased()], "WK-29a: the REC bytes are retained")
		record("WK-29a", "PASS", "walletStatus no_key, preread absent, REC bytes retained")

		// G1-NK-S1-CORRECTED, first branch: a valid MNEM is the normal account (G2), walletStatus unlocked. Probe-equivalent, run again here.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioConetChatModule.setNativeGateForTests(account: a.eoa, sessionReady: true)
		BeamioNativeKeySnapshot.invalidate()
		let wsValid = walletStatus(10601)
		if wsValid == "unlocked", preread() == .valid {
			record("G1-NK-S1-CORRECTED/mnem-valid", "PASS", "walletStatus unlocked (G2), preread valid")
		} else {
			record("G1-NK-S1-CORRECTED/mnem-valid", "FAIL", "walletStatus \(wsValid); expected unlocked")
		}

		// G1-NK-S1-CORRECTED, second branch: MNEM read failure is not_ready / unreadable (the original expectation).
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.mnemonic.failReadOwners.insert(a.eoa.lowercased())
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioNativeKeySnapshot.invalidate()
		let wsFail = walletStatus(10602)
		if wsFail == "not_ready", preread() == .unknown {
			record("G1-NK-S1-CORRECTED/mnem-read-failure", "PASS", "walletStatus not_ready (unreadable), preread unknown")
		} else {
			record("G1-NK-S1-CORRECTED/mnem-read-failure", "FAIL", "walletStatus \(wsFail); expected not_ready")
		}

		// G1-NK-S1-CORRECTED, third branch: keystore unavailable or user unlock needed: the preread is unknown (E9.1-3). The walletStatus answer of a
		// locked keystore is not produced by the in-memory store, so it is not counted here.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		let locked = BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: true, store: store).state
		if locked == .unknown {
			record("G1-NK-S1-CORRECTED/keystore-locked", "PASS", "preread unknown; walletStatus locked answer not produced by the in-memory store")
		} else {
			record("G1-NK-S1-CORRECTED/keystore-locked", "FAIL", "preread \(locked.rawValue); expected unknown")
		}

		// G1-NK-S1-CORRECTED, REC or MARK read failure with MNEM read ok and empty: no_key.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		store.failKeyReadOwners.insert(a.eoa.lowercased())
		let wsRec = walletStatus(10651)
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		markPending(eoa: a.eoa)
		store.failRawReadAccounts.insert(BeamioPwaPhraseOverwrite.markerAccount)
		let wsMark = walletStatus(10652)
		if wsRec == "no_key" && wsMark == "no_key" {
			record("G1-NK-S1-CORRECTED/rec-or-mark-read-failure", "PASS", "walletStatus no_key with REC unreadable and with MARK unreadable (MNEM read ok, empty)")
		} else {
			record("G1-NK-S1-CORRECTED/rec-or-mark-read-failure", "FAIL", "walletStatus REC \(wsRec), MARK \(wsMark); expected no_key")
		}

		// E91-05 (E9.1-4): walletStatus and the preread agree. (a) a mnemonic that reads empty: no_key and absent; (b) a mnemonic read failure: not_ready
		// (unreadable) and unknown.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		let e5a = walletStatus(10501)
		let e5aPre = preread()
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.mnemonic.failReadOwners.insert(a.eoa.lowercased())
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioNativeKeySnapshot.invalidate()
		let e5bStatus = walletStatus(10502)
		let e5bPre = preread()
		if e5a == "no_key", e5aPre == .absent, e5bStatus == "not_ready", e5bPre == .unknown {
			record("E91-05", "PASS", "(a) walletStatus no_key with preread absent; (b) walletStatus not_ready with preread unknown")
		} else {
			record("E91-05", "FAIL", "(a) \(e5a)/\(e5aPre.rawValue); (b) \(e5bStatus)/\(e5bPre.rawValue)")
		}

		for line in outcomes { print(line) }
		let failed = outcomes.filter { $0.contains(" FAIL ") }
		XCTAssertTrue(failed.isEmpty, "failing E9.10.3 vectors: \(failed)")
		XCTAssertGreaterThanOrEqual(outcomes.filter { $0.contains(" PASS ") }.count, 7)
	}
}
#endif
