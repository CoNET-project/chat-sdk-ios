#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// keystore-replica-vectors.v2.1 (KR-01..KR-08; v227 section 247.2, v228/v229; KR-02, KR-04 and KR-08 were changed in the product; KR-05 is the PWA baseline error legacy_store_unreadable (v2.1)): each state of the file is built on the production read path (the shell record read in the normal and in the creation mode,
/// and the replica builder). The file's states are synthetic: `readable` is read as a valid mnemonic account (the only account since Y.163 items 31 and 32), `key_only_orphan` as a key with no mnemonic.
/// The expected words map: read `absent` / `migrating` / `error:<sub>`; `create_write` is the creation-mode read: `allowed` and `allowed_append_only` answer absent (the page may create, appending only),
/// `migrating` answers migrating; `replica` is `ok_same_eoa` (the replica builder answers ok with the account's EOA) or `not_applied` (no page copy was written).
final class KeystoreReplicaV2VectorTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead { records[account].map { .record($0) } ?? .absent }
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool { records[account] = record; return true }
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private var saved: BeamioChatWalletKeyStoring?

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		BeamioNativeAccountPointer.clear()
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		saved = BeamioNativeWallet.keyStore
	}

	override func tearDown() {
		BeamioShellRecord.environmentOverride = nil
		BeamioNativeWallet.keyStore = saved ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	private func environment(store: Store, device: Device, account: String?, creation: Bool) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { account }, store: store, device: device, originAllowed: false, migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent }, locked: { _ in false }, walletCopyApproved: BeamioShellRecord.walletCopyApproved,
			gate: { account == nil ? .g0 : .g2 }, creationMode: { creation }
		)
	}

	private func word(_ answer: [String: Any]) -> String {
		let result = (answer["result"] as? [String: Any]) ?? answer
		let code = result["code"] as? String ?? (answer["error"] as? String ?? "?")
		return code == "error" ? "error:" + (result["sub"] as? String ?? "?") : code
	}

	private func read(_ env: BeamioShellRecord.Environment, _ reqId: Int) -> String {
		BeamioShellRecord.environmentOverride = env
		var out: [String: Any] = [:]
		BeamioWindowWallet.shellRecordRead(["reqId": reqId], trust: .trusted) { out = $0 }
		return word(out)
	}

	/// AK-50 (group E, option B; item 3, section 25.52Y.54/Y.56): a creation-mode READ that finds a legacy record answers
	/// `error/import_not_done`, with or without a pointer and a readable key (the AK-50 state has the pointer set and a key for it). It is neither `absent` nor `migrating`.
	/// The creation read never writes a page copy and never touches the key. KR-04 `create_write` is the page WRITE inside a creation transaction (see below), which answers migrating.
	func testCreationModeReadWithLegacyRecordFoundAnswersImportNotDone() {
		let acct = ValidTestAccounts.accountA
		for pointerSet in [true, false] {
			for withKey in [true, false] {
				let native = MemoryNativeKeyStore()
				if withKey { ValidTestAccounts.install(native) }
				BeamioNativeWallet.keyStore = native
				if pointerSet { BeamioNativeAccountPointer.set(acct.eoa) } else { BeamioNativeAccountPointer.clear() }
				let device = Device()
				device.state.legacyFound = true
				device.state.accountEstablished = pointerSet
				let store = Store()
				let keyBefore = native.keys[acct.eoa]
				let word = read(environment(store: store, device: device, account: nil, creation: true), 9810)
				XCTAssertEqual(word, "error:import_not_done", "AK-50 pointer=\(pointerSet) key=\(withKey)")
				XCTAssertTrue(store.records.isEmpty, "AK-50: the creation read writes no page copy")
				XCTAssertEqual(native.keys[acct.eoa], keyBefore, "AK-50: the key is untouched")
			}
		}
	}

	/// KR-04 `create_write`: the page write inside a creation transaction, for the pending account, in the state of the file.
	private func creationWrite(store: Store, device: Device, account: String, _ reqId: Int) -> String {
		var env = environment(store: store, device: device, account: account, creation: true)
		env.creationTransaction = { _ in true }
		env.originAllowed = true
		BeamioShellRecord.environmentOverride = env
		let answer = BeamioShellRecord.answer(["type": "shellRecordWrite", "reqId": reqId, "record": ["rev": 0, "schemaVersion": 1]], env: env, nativeWrite: false)
		return word(answer)
	}

	/// KR-04 create_write: the page write inside a creation transaction answers migrating and writes no copy when the legacy record is found (true) or the legacy store cannot be read
	/// (read failure, fail closed); with a confirmed-empty legacy store (false) the write is accepted. Pointer set or not, key present or not.
	func testAPageWriteInACreationTransactionIsMigratingWhileALegacyRecordIsFoundOrUnreadable() {
		let acct = ValidTestAccounts.accountA
		for state in ["found", "unreadable", "absent"] {
			for pointerSet in [false, true] {
				let native = MemoryNativeKeyStore()
				BeamioNativeWallet.keyStore = native
				if pointerSet { BeamioNativeAccountPointer.set(acct.eoa) } else { BeamioNativeAccountPointer.clear() }
				let device = Device()
				switch state {
				case "found": device.state.legacyFound = true
				case "unreadable": device.state.legacyUnreadable = true
				default: device.state.legacyConfirmedAbsent = true
				}
				device.state.accountEstablished = pointerSet
				let store = Store()
				let word = creationWrite(store: store, device: device, account: acct.eoa, 9803)
				if state == "absent" && pointerSet { continue }   // a creation transaction starts with the pointer empty; with it set, other rules decide (AK-43)
				if state == "absent" {
					XCTAssertEqual(word, "ok", "legacy confirmed empty pointer=\(pointerSet): the creation write is accepted")
					XCTAssertFalse(store.records.isEmpty, "the accepted write stored the copy")
				} else {
					XCTAssertEqual(word, "migrating", "\(state) pointer=\(pointerSet): migrating")
					XCTAssertTrue(store.records.isEmpty, "\(state) pointer=\(pointerSet): no page copy is written")
				}
			}
		}
	}

	func testEveryCaseOfTheKeystoreReplicaVectorV2() throws {
		let data = try BundledVectorFile.data(resource: "keystore-replica-vectors.v2.1")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.compactMap { $0["id"] as? String }, (1...8).map { String(format: "KR-%02d", $0) })
		let acct = ValidTestAccounts.accountA
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let state = try XCTUnwrap(c["state"] as? [String: Any], id)
			let expect = try XCTUnwrap(c["expect"] as? [String: Any], id)
			let native = MemoryNativeKeyStore()
			switch state["native_key"] as? String ?? "none" {
			case "none": break
			case "key_only_orphan": native.keys[acct.eoa] = acct.key
			case "readable", "valid_mnemonic_readable": ValidTestAccounts.install(native)
			case "unreadable": ValidTestAccounts.install(native); native.keys[acct.eoa] = Data(repeating: 0x11, count: 5)   // a key record that does not derive its account
			default: return XCTFail("\(id): unknown native_key")
			}
			BeamioNativeWallet.keyStore = native
			let pointerSet = state["pointer"] as? Bool ?? false
			if pointerSet { BeamioNativeAccountPointer.set(acct.eoa) } else { BeamioNativeAccountPointer.clear() }
			let device = Device()
			switch state["legacy"] as? String ?? "unread" {
			case "absent": device.state.legacyConfirmedAbsent = true
			case "found": device.state.legacyFound = true
			case "unreadable": device.state.legacyUnreadable = true
			default: break   // unread
			}
			device.state.accountEstablished = pointerSet
			let store = Store()
			// the normal read, with the account the pointer names (none when the pointer is not set)
			let account: String? = pointerSet ? acct.eoa : nil
			let readWord = read(environment(store: store, device: device, account: account, creation: false), 9800)
			// the creation-mode read: no account (the page has none yet), the same device
			// The creation-mode READ (no account yet), the same device. option B: in KR-04 (a found legacy record) it is error:import_not_done (AK-50), not migrating.
			// The page WRITE inside a creation transaction has its own test (testAPageWriteInACreationTransactionIsMigratingWhileALegacyRecordIsFoundOrUnreadable).
			let creationWord = read(environment(store: store, device: device, account: nil, creation: true), 9801)
			let want = expect["read"] as? String ?? ""
			XCTAssertEqual(readWord, want, "\(id): read")
			let create = expect["create_write"] as? String ?? ""
			let createWant: String
			switch create {
			case "migrating": createWant = id == "KR-04" ? "error:import_not_done" : "migrating"
			case "legacy_store_unreadable": createWant = "error:legacy_store_unreadable"   // KR-05 (v2.1): the PWA baseline answers the sub code
			default: createWant = "absent"
			}
			XCTAssertEqual(creationWord, createWant, "\(id): create_write")
			// the replica builder and the page copy
			let replica = expect["replica"] as? String ?? ""
			if replica == "ok_same_eoa" {
				let direct = BeamioShellRecord.replicaAnswer(env: environment(store: Store(), device: device, account: acct.eoa, creation: true), account: acct.eoa, reqId: 9802)
				XCTAssertEqual(direct["code"] as? String, "ok", "\(id): replica ok")
				let profile = (((direct["record"] as? [String: Any])?["profiles"]) as? [[String: Any]])?.first
				XCTAssertEqual(profile?["keyID"] as? String, acct.eoa, "\(id): the replica's EOA is the account's")
			} else {
				XCTAssertTrue(store.records.isEmpty, "\(id): replica not applied: no page copy was written")
			}
			if id == "KR-01" {
				XCTAssertEqual(native.keys[acct.eoa], acct.key, "KR-01: the orphan key is not overwritten")
				XCTAssertEqual(native.mnemonic.items.count, 0, "KR-01: nothing is appended to the orphan's account by the reads")
			}
		}
	}
}
#endif
