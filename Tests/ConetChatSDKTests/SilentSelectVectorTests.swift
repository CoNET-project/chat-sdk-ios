import XCTest
@testable import ConetChatSDK

/// Y.163 silent selection, the makeAccount guard and the QA walletExit, driven by account-select-vectors.v2.json
/// (SS-01 to SS-23, CR-01 to CR-07, QS-01 to QS-06). The synthetic store lists the keys the vector names; no key bytes are read.
/// QS-03 needs an unlocked session and is not run here (the G2 answers are covered by their own suites).
final class SilentSelectVectorTests: XCTestCase {
	private var savedStore: BeamioChatWalletKeyStoring?
	private var store = AccountSelectVectorStore()

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeAccountPointer.clear()
	}

	override func tearDown() {
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		BeamioNativeAccountPointer.clear()
		BeamioNativeKeySnapshot.invalidate()
		BeamioResidueProbe.overrideForTests = nil
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func flush() {
		let until = Date().addingTimeInterval(0.1)
		while Date() < until { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
	}

	private func vectorCases() throws -> [String: [String: Any]] {
		let data = try BundledVectorFile.data(resource: "account-select-vectors.v2")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return Dictionary(uniqueKeysWithValues: cases.compactMap { c in (c["id"] as? String).map { ($0, c) } })
	}

	/// Sets the rows, the flags, the pointer and the residue probe of one vector state, and judges the snapshot again.
	private func setState(_ state: [String: Any]) {
		store = AccountSelectVectorStore()
		store.enumOk = !(state["enumOk"] as? Bool == false) && !(state["snapshotNil"] as? Bool ?? false)
		store.unreadableExtra = ["corrupt", "readError", "nonInteractiveDenied", "timeout", "seOtherFailure"].contains { state[$0] as? Bool ?? false }
		store.rows = (state["keys"] as? [[String: Any]] ?? []).map { key in
			AccountSelectVectorStore.Row(eoa: (key["eoa"] as? String ?? "").lowercased(), created: key["createdAt"] as? Int,
			                             valid: key["valid"] as? Bool ?? true, kind: key["kind"] as? String ?? "mnemonic",
			                             legacy: key["legacy"] as? Bool ?? false)
		}
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.clear()
		if let pointer = state["pointer"] as? String { BeamioNativeAccountPointer.set(pointer) }
		BeamioNativeKeySnapshot.invalidate()
		let residue = state["residue"] as? Bool ?? false
		let probeFailed = state["probeFailed"] as? Bool ?? false
		BeamioResidueProbe.overrideForTests = { probeFailed ? .failed : (residue ? .present : .absent) }
	}

	/// One bridge command: its ack.
	private func ack(_ type: String, _ extra: [String: Any] = [:]) -> [String: Any] {
		var sent: [[String: Any]] = []
		var body: [String: Any] = ["type": type, "reqId": 7]
		for (key, value) in extra { body[key] = value }
		BeamioConetChatModule.handleCommand(body, emit: { sent.append(($0["event"] as? [String: Any]) ?? $0) })
		flush()
		return sent.first { $0["type"] as? String == "ack" } ?? [:]
	}

	/// The decision as the vectors name it: code and eoa.
	private func codeOf(_ decision: BeamioNativeSilentSelect.Decision) -> (code: String, eoa: String?) {
		switch decision {
		case .selected(let eoa): return ("ok", eoa)
		case .single(let eoa): return ("unchanged", eoa)
		case .pointerKept(let eoa): return ("ok", eoa)
		case .unreadable: return ("not_ready", nil)
		case .none: return ("none", nil)
		}
	}

	private func runSelect(writeOk: Bool = true, readbackOk: Bool = true) -> BeamioNativeSilentSelect.Decision {
		BeamioNativeSilentSelect.run(store: store, writePointer: { _ in
			guard writeOk else { return .unreadable }
			return readbackOk ? .written : .mismatch
		})
	}

	func testTheVectorPinIsChecked() throws {
		_ = try vectorCases()
	}

	func testSS01ToSS04WalletStatusIsReadOnly() throws {
		for id in ["SS-01", "SS-02", "SS-03", "SS-04"] {
			let c = try XCTUnwrap(vectorCases()[id])
			let input = try XCTUnwrap(c["input"] as? [String: Any])
			setState(try XCTUnwrap(input["state"] as? [String: Any]))
			let result = ack("walletStatus")["result"] as? [String: Any] ?? [:]
			let expect = try XCTUnwrap(c["expect"] as? [String: Any])
			XCTAssertEqual(result["status"] as? String, expect["status"] as? String, id)
			XCTAssertEqual(result["notReadyReason"] as? String, expect["notReadyReason"] as? String, id)
			XCTAssertTrue(BeamioNativeAccountPointer.get().isEmpty, "\(id): walletStatus writes no pointer")
		}
	}

	func testSS05ToSS19InitSilentSelection() throws {
		for id in ["SS-05", "SS-06", "SS-07", "SS-08", "SS-09", "SS-10", "SS-11", "SS-12", "SS-13", "SS-14",
		           "SS-15", "SS-16", "SS-17", "SS-19"] {
			let c = try XCTUnwrap(vectorCases()[id])
			let input = try XCTUnwrap(c["input"] as? [String: Any])
			let state = try XCTUnwrap(input["state"] as? [String: Any])
			setState(state)
			let decision = runSelect(writeOk: state["writeOk"] as? Bool ?? true, readbackOk: state["readbackOk"] as? Bool ?? true)
			let expect = try XCTUnwrap(c["expect"] as? [String: Any])
			let got = codeOf(decision)
			XCTAssertEqual(got.code, expect["code"] as? String, id)
			if let eoa = expect["eoa"] as? String { XCTAssertEqual(got.eoa, eoa, id) }
			if expect["pointerWritten"] as? Bool == false {
				XCTAssertEqual(BeamioNativeAccountPointer.get(), state["pointer"] as? String ?? "", "\(id): no pointer is written")
			}
		}
	}

	func testSS18PointerReadFailureIsUnreadable() {
		let decision = BeamioNativeSilentSelect.decide(inventory: BeamioNativeMnemonicInventory(enumerated: true, accounts: []),
		                                               pointer: "0x2222222222222222222222222222222222222222", pointerReadOk: false, probeFailed: false)
		XCTAssertEqual(decision, .unreadable, "SS-18")
	}

	func testSS20KeysAreNotDeletedBySelection() {
		setState(["keys": [["eoa": "0x1111111111111111111111111111111111111111", "createdAt": 1767225600, "valid": true],
		                   ["eoa": "0x2222222222222222222222222222222222222222", "createdAt": 1767229200, "valid": true]],
		          "enumOk": true])
		_ = runSelect()
		XCTAssertEqual(store.rows.count, 2, "SS-20")
		XCTAssertEqual(store.deleteCalls, 0, "SS-20: no key is deleted, the unselected one included")
	}

	func testSS21SelectionDoesNotDependOnEnumerationOrder() {
		setState(["keys": [["eoa": "0x2222222222222222222222222222222222222222", "createdAt": 1767229200, "valid": true],
		                   ["eoa": "0x1111111111111111111111111111111111111111", "createdAt": 1767225600, "valid": true]],
		          "enumOk": true])
		XCTAssertEqual(runSelect(), .selected("0x1111111111111111111111111111111111111111"), "SS-21")
	}

	func testSS22AndSS23BridgeCommandsAreNotRegistered() {
		for id in ["SS-22", "SS-23"] {
			let type = id == "SS-22" ? "accountCandidates" : "accountSelect"
			let answer = ack(type, ["eoa": "0x1111111111111111111111111111111111111111"])
			XCTAssertNotEqual(answer["ok"] as? Bool, true, "\(id): \(type) is not answered")
		}
	}

	/// The creation is the page's explicit command and only appends (r7 第 12、29 項): keys already held do not refuse it. An unlocked session
	/// (G2, CR-07) is already_exists. Rows are the 170-case final pin (sha 8fe81361).
	func testCR01ToCR07MakeAccountGuard() throws {
		for (id, expectCode) in [("CR-01", "may_create"), ("CR-02", "may_create"), ("CR-03", "not_ready"),
		                         ("CR-04", "may_create"), ("CR-05", "not_ready"), ("CR-06", "not_ready"), ("CR-07", "already_exists")] {
			let c = try XCTUnwrap(vectorCases()[id])
			let state = try XCTUnwrap((c["input"] as? [String: Any])?["state"] as? [String: Any])
			let keys = state["keys"] as? [[String: Any]] ?? []
			let verdict = BeamioNativeSilentSelect.createGuard(
				userExplicit: true,
				enumerated: state["enumOk"] as? Bool ?? true,
				sessionIsG2: (state["gate"] as? String) == "G2",
				g1WithoutKeys: (state["gate"] as? String) == "G1" && keys.isEmpty,
				residue: state["residue"] as? Bool ?? false,
				probeFailed: state["probeFailed"] as? Bool ?? false)
			switch verdict {
			case .mayCreate: XCTAssertEqual(expectCode, "may_create", id)
			case .alreadyExists: XCTAssertEqual(expectCode, "already_exists", id)
			case .unreadable: XCTAssertEqual(expectCode, "not_ready", id)
			case .badRequest: XCTFail("\(id): the page's explicit command is not a bad request")
			}
		}
	}

	/// Pre-r8: a held key does not refuse an explicit creation; the live path appends (the test store cannot read the new key back, so only
	/// the refusal is asserted: it is not already_exists).
	func testMakeAccountDoesNotRefuseWhenKeysAreHeld() {
		setState(["keys": [["eoa": "0x1111111111111111111111111111111111111111", "createdAt": 1767225600, "valid": true]], "enumOk": true])
		if case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: store, entropy: nil, userExplicit: true) {
			XCTAssertNotEqual(code, .alreadyExists, "a held key is not a refusal (r7 第 12 項)")
		}
	}

	/// CR-03 through the live creation: an enumeration that fails is not_ready, not a creation.
	func testMakeAccountIsNotReadyWhenEnumerationFails() {
		setState(["keys": [], "enumOk": false])
		guard case .failed(let code) = BeamioNativeAccountCreate.makeAccount(store: store, entropy: nil, userExplicit: true) else {
			return XCTFail("CR-03: a failed enumeration must not create")
		}
		XCTAssertEqual(code, .notReady)
	}

	func testQS01ToQS05WalletExitIsTheReplyOfTheCall() throws {
		for id in ["QS-01", "QS-02", "QS-04", "QS-05"] {
			let c = try XCTUnwrap(vectorCases()[id])
			let state = try XCTUnwrap((c["input"] as? [String: Any])?["state"] as? [String: Any])
			setState(state)
			let answer = ack("walletStatus")
			let label = BeamioConetChatModule.qaStatusLabel(answer["result"] as? [String: Any] ?? [:])
			let expect = try XCTUnwrap(c["expect"] as? [String: Any])
			XCTAssertEqual(label, expect["walletExit"] as? String, id)
		}
	}

	func testQS06NoReplyWritesNone() {
		let line = BeamioConetChatModule.qaStateLine(keychainWalletEntries: 1, pointerSet: false, keyState: "normal", snapshotKnown: true,
		                                             gate: "g1", walletExit: "none", shellExit: "none")
		XCTAssertTrue(line.contains("walletStatusExit=none"), "QS-06")
	}

	func testPutKeepsTheCreationTimeOfAnExistingItem() {
		let service = "silent-select-test", account = "walletKey:0x1111111111111111111111111111111111111111"
		BeamioChatWalletTestMemory.put(service, account, Data([1]))
		let first = BeamioChatWalletTestMemory.created(service, account)
		BeamioChatWalletTestMemory.put(service, account, Data([2]))
		XCTAssertEqual(BeamioChatWalletTestMemory.created(service, account), first, "an in-place value change keeps the creation time")
		BeamioChatWalletTestMemory.remove(service, account)
	}
}
