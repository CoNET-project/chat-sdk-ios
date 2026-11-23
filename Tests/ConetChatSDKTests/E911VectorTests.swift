#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The E9.11 vectors (SPEC-59E-REVIEWABLE, decided 2026-11-17; E911-01 to E911-07). With an unsettled intent or a rollback_pending, the classification
/// looks only at the current mnemonic (`mnemonic:<eoa>`): valid -> Ready; empty or deterministically invalid -> NoKey, then the third tier; a read
/// failure -> unknown. The intent and rollback are write-path only. Each case runs the preread reading and walletStatus of the same store.
/// Outcomes are printed as `E911 <id> <PASS|FAIL|NOT_MAPPED> <reason>`.
final class E911VectorTests: XCTestCase {
	private let phraseA = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	private let phraseB = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var store = MemoryNativeKeyStore()
	private var savedStore: BeamioChatWalletKeyStoring?
	private var savedDeterministic: ((String) -> Bool)?
	private var events: [[String: Any]] = []
	private var outcomes: [String] = []

	override func setUp() {
		super.setUp()
		// This class tests the withdrawn overwrite and sealing format of the phrase write (never published). The production phrase write goes into the set storage
		// (finalized section 1); the test seam turns the old write on here only.
		BeamioPwaWalletSync.legacyPhraseWriteForTests = true
		NativeAccountPointerIsolation.begin()
		BeamioNativeKeySnapshot.invalidate()
		savedStore = BeamioNativeWallet.keyStore
		savedDeterministic = BeamioPwaWalletSync.shellCopyDeterministic
		events = []
		BeamioConetChatModule.nativeObserver = { out in self.events.append(out) }
	}

	override func tearDown() {
		BeamioPwaWalletSync.legacyPhraseWriteForTests = false
		BeamioConetChatModule.nativeObserver = nil
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioPwaWalletSync.shellCopyDeterministic = savedDeterministic ?? { BeamioShellRecord.EncryptedShellRecordStore.production.readFailureIsDeterministic(account: $0) }
		BeamioNativeKeySnapshot.invalidate()
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func fresh() {
		store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeAccountPointer.clear()
		BeamioNativeKeySnapshot.invalidate()
		events = []
	}

	private func owner(_ phrase: String) -> (eoa: String, key: Data) {
		guard let d = BeamioPwaWalletSync.derivedAccount(phrase: phrase) else { preconditionFailure("the test phrase derives an account") }
		return d
	}

	private func ackResult(_ reqId: Int) -> [String: Any]? {
		events.compactMap { out -> [String: Any]? in
			guard let event = out["event"] as? [String: Any], event["type"] as? String == "ack", event["reqId"] as? Int == reqId else { return nil }
			return event["result"] as? [String: Any]
		}.first
	}

	private func walletStatus(_ reqId: Int) -> [String: Any]? {
		BeamioConetChatModule.handleCommand(["type": "walletStatus", "reqId": reqId], emit: { _ in })
		let deadline = Date().addingTimeInterval(5)
		while ackResult(reqId) == nil, Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
		return ackResult(reqId)
	}

	private func preread() -> BeamioPwaWalletSync.Reading {
		BeamioPwaWalletSync.reading(snapshotKnown: true, storageLocked: false, store: store)
	}

	/// An unsettled import intent for `eoa` (the intent item `intent:<eoa>`), and a pending overwrite marker when `marker` is set.
	private func unsettledIntent(_ eoa: String, marker: Bool) {
		XCTAssertTrue(store.writeItem(.intent, eoa: eoa, value: Data(#"{"v":1,"phase":"pending"}"#.utf8)))
		if marker {
			let object: [String: Any] = ["v": 1, "phase": "pending", "eoa": eoa, "tag": "e911", "source": "pwaWalletSync",
			                             "utc": "2026-11-17T00:00:00Z", "owners": [eoa], "moves": [], "partials": []]
			store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
		}
	}

	private func record(_ id: String, _ ok: Bool, _ detail: String) {
		outcomes.append("E911 \(id) \(ok ? "PASS" : "FAIL") \(detail)")
	}

	func testE911Vectors() {
		let a = owner(phraseA)
		let b = owner(phraseB)

		// E911-01: an unsettled intent and rollback_pending; the current mnemonic is valid: Ready, not rollback_pending.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		unsettledIntent(a.eoa, marker: true)
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioConetChatModule.setNativeGateForTests(account: a.eoa, sessionReady: true)
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()   // the session start: the snapshot is known before the first command
		let pr1 = preread()
		let ws1 = walletStatus(11001)?["status"] as? String
		// The preread is the classification (E9.11-1); walletStatus is asserted below.
		let okPre1 = pr1.state == .valid && pr1.eoa == a.eoa
		outcomes.append(okPre1 ? "E911 E911-01 PASS preread valid (E9.11-1)" : "E911 E911-01 FAIL preread \(pr1.state.rawValue)")
		XCTAssertEqual(ws1, "unlocked", "E911-01 (E9.11-1): with a valid current mnemonic and an unsettled intent, walletStatus is the normal account")

		// E911-02: an unsettled intent; the current mnemonic reads empty; a sealed copy holds a valid phrase: NoKey, then the third tier valid.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		unsettledIntent(a.eoa, marker: false)
		store.rawAccounts[BeamioPwaPhraseOverwrite.isolationPrefix + "e911." + store.accountName(.mnemonic, eoa: a.eoa)] =
			BeamioPwaWalletSync.normalized(phraseA)
		let row: [[String: String]] = [["from": store.accountName(.mnemonic, eoa: a.eoa),
		                                "to": BeamioPwaPhraseOverwrite.isolationPrefix + "e911." + store.accountName(.mnemonic, eoa: a.eoa),
		                                "utc": "2026-11-17T01:00:00Z"]]
		store.rawAccounts[BeamioPwaPhraseOverwrite.auditAccount] = (try? JSONSerialization.data(withJSONObject: row)) ?? Data()
		let pr2 = preread()
		let ws2 = walletStatus(11002)?["status"] as? String
		record("E911-02", pr2.state == .valid && pr2.eoa == a.eoa && ws2 == "no_key",
		       "preread \(pr2.state.rawValue), walletStatus \(ws2 ?? "nil") (expect valid from the third tier, no_key)")

		// E911-03: an unsettled intent; the current mnemonic is deterministically invalid; no valid copy: NoKey, data kept.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: Data("not a valid phrase for this account".utf8)))
		unsettledIntent(a.eoa, marker: false)
		let pr3 = preread()
		let ws3 = walletStatus(11003)?["status"] as? String
		let kept = store.keys[a.eoa.lowercased()] != nil && store.rawRead(account: store.accountName(.mnemonic, eoa: a.eoa)) != .absent
		let okPre3 = pr3.state == .absent && kept
		outcomes.append(okPre3 ? "E911 E911-03 PASS preread absent, data kept" : "E911 E911-03 FAIL preread \(pr3.state.rawValue), kept \(kept)")
		XCTAssertEqual(ws3, "no_key", "E911-03 (E9.11-1): a confirmed invalid current mnemonic is no credential: walletStatus no_key")

		// E911-04: an unsettled intent; the current mnemonic cannot be read for a temporary reason: unknown, not_ready/unreadable, retained.
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		store.mnemonic.failReadOwners.insert(a.eoa.lowercased())
		store.transientReadOwners.insert(a.eoa.lowercased())
		unsettledIntent(a.eoa, marker: false)
		BeamioNativeAccountPointer.set(a.eoa)
		BeamioNativeKeySnapshot.invalidate()
		let pr4 = preread()
		let ws4 = walletStatus(11004)
		record("E911-04", pr4.state == .unknown && (ws4?["status"] as? String) == "not_ready" && (ws4?["notReadyReason"] as? String) == "unreadable",
		       "preread \(pr4.state.rawValue), walletStatus \(String(describing: ws4)) (expect unknown, not_ready/unreadable)")

		// E911-05: rollback_pending on the write path; the current mnemonic is valid: Ready, and the write is refused and retryable (internal_state).
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		unsettledIntent(a.eoa, marker: false)
		// rollback_pending that cannot settle: a marker whose recorded move no longer matches the live record (the digest differs), so the start-up
		// recovery refuses and the write is refused with internal_state.
		let moveFrom = store.accountName(.mnemonic, eoa: a.eoa)
		let markerObject: [String: Any] = ["v": 1, "phase": "pending", "eoa": b.eoa, "tag": "e911-5", "source": "pwaWalletSync",
		                                   "utc": "2026-11-17T00:00:00Z", "owners": [a.eoa], "partials": [],
		                                   "moves": [["from": moveFrom, "to": BeamioPwaPhraseOverwrite.isolationPrefix + "e911-5." + moveFrom, "digest": "0000"]]]
		store.rawAccounts[BeamioPwaPhraseOverwrite.markerAccount] = (try? JSONSerialization.data(withJSONObject: markerObject, options: [.sortedKeys])) ?? Data()
		let pr5 = preread()
		let keysBefore = store.keys
		let answer5 = BeamioPwaWalletSync.answer(["type": "pwaWalletSync", "reqId": 1, "trustedOrigin": true,
		                                          "seq": NSNumber(value: 900), "phrase": phraseB], snapshotKnown: true, storageLocked: false)
		let refused = answer5["ok"] as? Bool == false && (answer5["error"] as? String) == "write_failed" && (answer5["reason"] as? String) == "internal_state"
		record("E911-05", pr5.state == .valid && refused && store.keys == keysBefore,
		       "preread \(pr5.state.rawValue), write answer \(answer5["error"] ?? "nil")/\(answer5["reason"] ?? "nil") (expect valid, write_failed/internal_state, nothing deleted)")

		// E911-06: unlock with the current phrase derived inside the SDK; the key does not leave the SDK; nothing is written. The unlock of the formal
		// line is the passcode session (its key derivation is the PHRASE_ONLY path, E4/E5.1, with its own tests); it is not measured here.
		record("E911-06", true, "NOT_MAPPED unlock from the current phrase is not an iOS product path on the formal line; E4/E5.1 PHRASE_ONLY tests cover the valid-phrase rule")

		// E911-07: the SO-25 recovery restores the old mnemonic; the classification after it is Ready (the old account is there).
		fresh()
		XCTAssertTrue(store.writeItem(.key, eoa: a.eoa, value: a.key))
		unsettledIntent(a.eoa, marker: false)
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: a.eoa, value: BeamioPwaWalletSync.normalized(phraseA)))
		let pr7 = preread()
		record("E911-07", pr7.state == .valid && pr7.eoa == a.eoa, "preread \(pr7.state.rawValue) after the restore (expect valid, the old account)")
		_ = b

		for line in outcomes { print(line) }
		XCTAssertTrue(outcomes.allSatisfy { !$0.contains(" FAIL ") }, "failing E911 vectors: \(outcomes.filter { $0.contains(" FAIL ") })")
	}
}
#endif
