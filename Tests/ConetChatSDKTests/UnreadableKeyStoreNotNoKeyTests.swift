#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

///, item 1: a key store that cannot be read (no pointer, G0) never answers no_key. Every command that would answer no_key answers
/// not_ready with notReadyReason unreadable, the cause as a category and retryable by cause (-34018 entitlement: false; -25308 device_locked: true).
final class UnreadableKeyStoreNotNoKeyTests: XCTestCase {
	private final class Unlistable: BeamioChatWalletKeyStoring {
		let status: OSStatus
		init(status: OSStatus = -50) { self.status = status }
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { false }
		func enumerateKeyOwners() -> [String]? { BeamioKeychainFailureNote.note(status); return nil }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { BeamioKeychainFailureNote.note(status); return .unreadable }
		func hasAnyKeyRecord() -> Bool { true }
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { BeamioKeychainFailureNote.note(status); return nil }
	}

	private var saved: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		saved = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = Unlistable()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
	}

	override func tearDown() {
		BeamioKeychainFailureNote.setForTests(nil)
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeWallet.keyStore = saved
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func ask(_ type: String, _ reqId: Int) -> [String: Any]? {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": type, "reqId": reqId, "payload": ["identity": ["eoaAddress": "0x5e5e000000000000000000000000000000000001"]]]) {
			if let e = $0["event"] as? [String: Any] { events.append(e) }
		}
		let drained = expectation(description: "drained"); DispatchQueue.main.async { drained.fulfill() }; wait(for: [drained], timeout: 5)
		return events.first { $0["reqId"] as? Int == reqId }
	}

	private func establishSnapshot() {
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertEqual(BeamioNativeKeySnapshot.current()?.unreadable, true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g0)
	}

	func testEveryNoKeyCommandAnswersNotReadyWhenTheStoreIsUnreadable() {
		for (status, cause, retryable) in [(-34018, "entitlement", false), (-25308, "device_locked", true), (-50, "other", false)] {
			BeamioNativeWallet.keyStore = Unlistable(status: OSStatus(status))
			establishSnapshot()
			for (i, name) in ["init", "walletSignMessage", "historySign", "identityPublic", "clearIdentity"].enumerated() {
				let ack = ask(name, 100 + i)
				XCTAssertEqual(ack?["ok"] as? Bool, false, "\(name) \(status)")
				XCTAssertEqual(ack?["error"] as? String, "not_ready", "\(name) \(status): not no_key")
				XCTAssertEqual(ack?["notReadyReason"] as? String, "unreadable", "\(name) \(status)")
				XCTAssertEqual(ack?["unreadableCause"] as? String, cause, "\(name) \(status)")
				XCTAssertEqual(ack?["retryable"] as? Bool, retryable, "\(name) \(status)")
			}
		}
	}

	/// A device that really has no key still answers no_key: the readable empty store is not the unreadable one.
	func testAReadableEmptyStoreStillAnswersNoKey() {
		BeamioNativeWallet.keyStore = BeamioNativeWalletTestsEmptyStore()
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		XCTAssertNotEqual(BeamioNativeKeySnapshot.current()?.unreadable, true)
		XCTAssertEqual(ask("walletSignMessage", 200)?["error"] as? String, "no_key")
	}
}

/// A readable store with no key at all.
private final class BeamioNativeWalletTestsEmptyStore: BeamioChatWalletKeyStoring {
	func write(eoa: String, key: Data) -> Bool { true }
	func read(eoa: String) -> Data? { nil }
	func delete(eoa: String) {}
	func migrationMarkerExists(eoa: String) -> Bool { false }
	func setMigrationMarker(eoa: String) -> Bool { true }
	func enumerateKeyOwners() -> [String]? { [] }
	func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .absent }
	func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { [] }
}
#endif

#if BEAMIO_TEST_HOOKS
/// The batch vector v2 (v189 section 209): BR2-01 and BR2-02 (unreadable, no pointer: not_ready with the three fields), BR2-03 (SS-32: no_key), BR2-04 (VR-17).
/// Each case is read from the file; its state is set up; the ack the SDK sends is compared with the case's `expect`. BR2-05 and BR2-06 are pending Android qa.8.
final class BatchRulingsV2VectorTests: XCTestCase {
	private final class Unlistable: BeamioChatWalletKeyStoring {
		func write(eoa: String, key: Data) -> Bool { false }
		func read(eoa: String) -> Data? { nil }
		func delete(eoa: String) {}
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { false }
		func enumerateKeyOwners() -> [String]? { nil }
		func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { .unreadable }
		func hasAnyKeyRecord() -> Bool { true }
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { nil }
	}

	private var saved: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		saved = BeamioNativeWallet.keyStore
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
	}

	override func tearDown() {
		BeamioKeychainFailureNote.reset()
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeWallet.keyStore = saved
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func canonical(_ value: Any) -> String {
		guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return "invalid" }
		return String(decoding: data, as: UTF8.self)
	}

	private func ask(_ type: String, _ reqId: Int) -> [String: Any]? {
		var events: [[String: Any]] = []
		// pgpMigrate carries only type and reqId; the other commands take the identity payload
		var body: [String: Any] = ["type": type, "reqId": reqId]
		if type != "pgpMigrate" { body["payload"] = ["identity": ["eoaAddress": "0x5e5e000000000000000000000000000000000001"]] }
		BeamioConetChatModule.handleCommand(body) {
			if let e = $0["event"] as? [String: Any] { events.append(e) }
		}
		let drained = expectation(description: "drained"); DispatchQueue.main.async { drained.fulfill() }; wait(for: [drained], timeout: 5)
		guard var ack = events.first(where: { $0["reqId"] as? Int == reqId }) else { return nil }
		ack.removeValue(forKey: "reqId")
		return ack
	}

	func testTheV2CasesOfTheBatchRulings() throws {
		let data = try BundledVectorFile.data(resource: "batch-rulings-unreadable-nokey-ss32-vr17.v2")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 6)
		var ran = 0
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let state = c["state"] as? [String: Any] ?? [:]
			let command = c["command"] as? String ?? ""
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			BeamioKeychainFailureNote.reset()
			switch id.prefix(6) {
			case "BR2-01", "BR2-02":
				// the store cannot be listed with this status: the snapshot is unreadable and keeps the category of the read that made it so
				BeamioNativeWallet.keyStore = BeamioChatKeychainStatusStore(status: OSStatus(state["osStatus"] as? Int ?? 0))
				BeamioNativeKeySnapshot.invalidate()
				BeamioNativeKeySnapshot.sessionStartIfNeeded()
				XCTAssertEqual(BeamioNativeKeySnapshot.current()?.unreadable, true, id)
				XCTAssertEqual(canonical(ask(command, 100 + ran) as Any), canonical(c["expect"] as Any), id)
				ran += 1
			case "BR2-03":
				// one mnemonic item, read twice and found invalid (confirmed), no pointer, G0: no_key in the envelope, the data kept
				let store = MemoryNativeKeyStore()
				let owner = "0x1111111111111111111111111111111111111111"
				XCTAssertTrue(store.writeItem(.mnemonic, eoa: owner, value: Data("synthetic invalid phrase".utf8)))
				store.mnemonicStateScript[owner] = [.invalid, .invalid, .invalid, .invalid, .invalid, .invalid]
				BeamioNativeWallet.keyStore = store
				BeamioNativeKeySnapshot.invalidate()
				BeamioNativeKeySnapshot.sessionStartIfNeeded()
				XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g0, id)
				XCTAssertEqual(canonical(ask(command, 100 + ran) as Any), canonical(c["expect"] as Any), id)
				XCTAssertEqual(store.mnemonic.itemState(.mnemonic, eoa: owner), .present, "\(id): the data is kept")
				ran += 1
			default:
				continue   // BR2-04 is VR-17 (asserted by the lock tests of 69e0fa6); BR2-05 and BR2-06 wait for Android qa.8
			}
		}
		XCTAssertEqual(ran, 3)
	}

	/// The pgpMigrate exemption path: an unreadable store is not no_key either.
	func testPgpMigrateAtG0WithAnUnreadableStoreIsNotNoKey() {
		BeamioNativeWallet.keyStore = BeamioChatKeychainStatusStore(status: -34018)
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		let ack = ask("pgpMigrate", 300)
		XCTAssertEqual(ack?["error"] as? String, "not_ready")
		XCTAssertEqual(ack?["unreadableCause"] as? String, "entitlement")
		XCTAssertEqual(ack?["retryable"] as? Bool, false)
	}

	/// A failed read on another thread, before or during the judgement, does not change the cause the judging thread's own reads left (the note is per thread, and the
	/// judgement's reads run on its thread: there is no thread hop in the snapshot, inventory or wallet-keychain path).
	func testAReadFailingOnAnotherThreadDoesNotChangeTheCause() {
		BeamioNativeWallet.keyStore = BeamioChatKeychainStatusStore(status: -34018)
		let noisy = DispatchQueue(label: "noise", attributes: .concurrent)
		let stop = NSLock(); var stopped = false
		let done = expectation(description: "noise started")
		noisy.async {
			done.fulfill()
			while true {
				stop.lock(); let s = stopped; stop.unlock(); if s { break }
				BeamioKeychainFailureNote.note(-25308)   // the other thread's read fails with another status, over and over
			}
		}
		wait(for: [done], timeout: 5)
		for _ in 0 ..< 50 {
			BeamioNativeKeySnapshot.invalidate()
			BeamioNativeKeySnapshot.sessionStartIfNeeded()
			XCTAssertEqual(BeamioNativeKeySnapshot.current()?.unreadableCause, "entitlement")
		}
		stop.lock(); stopped = true; stop.unlock()
	}

	/// The cause stays with the snapshot: a later failed read with another status does not change an answer given from this snapshot.
	func testTheCauseStaysWithTheSnapshot() {
		BeamioNativeWallet.keyStore = BeamioChatKeychainStatusStore(status: -34018)
		BeamioNativeKeySnapshot.invalidate()
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		BeamioKeychainFailureNote.note(-25308)   // another read fails later, with another status
		let ack = ask("walletSignMessage", 310)
		XCTAssertEqual(ack?["unreadableCause"] as? String, "entitlement", "the snapshot's cause, not the later read's")
		XCTAssertEqual(ack?["retryable"] as? Bool, false)
	}
}

/// A key store whose listing fails with a Keychain status: it records the status the way the product store does.
private final class BeamioChatKeychainStatusStore: BeamioChatWalletKeyStoring {
	let status: OSStatus
	init(status: OSStatus) { self.status = status }
	func write(eoa: String, key: Data) -> Bool { false }
	func read(eoa: String) -> Data? { BeamioKeychainFailureNote.note(status); return nil }
	func delete(eoa: String) {}
	func migrationMarkerExists(eoa: String) -> Bool { false }
	func setMigrationMarker(eoa: String) -> Bool { false }
	func enumerateKeyOwners() -> [String]? { BeamioKeychainFailureNote.note(status); return nil }
	func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState { BeamioKeychainFailureNote.note(status); return .unreadable }
	func hasAnyKeyRecord() -> Bool { true }
	func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { BeamioKeychainFailureNote.note(status); return nil }
}
#endif
