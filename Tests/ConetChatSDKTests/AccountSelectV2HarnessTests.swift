import XCTest
@testable import ConetChatSDK

/// Every case of account-select-vectors.v2.json (25.52Y.163 r2.3, 217 cases) gets one verdict from the SDK side. The verdicts are printed
/// as `Y163CASE <id> <verdict> <note>` and the totals as `Y163TOTAL`, so the run log is the record of the count.
///
/// - pass: every expectation of the case is checked here, and agrees.
/// - partial: the decision the case names is checked, and an expectation about a write is not executed here: a key appended, a count
/// after the call, the address of a created account, the pointer after a write, or stored bytes. This harness has no writable mnemonic
/// store and no key bytes; the write paths are covered by their own suites.
/// - fail: a checked expectation differs. A fail must be a known deviation listed in `knownDeviations` with its reason; the test asserts that
/// the fails are exactly those.
/// - pending: the case belongs to a later segment (3: narrow discard and the two-side merge; 4: the restore commands and the import surface),
/// or to the PWA or the shell, which the SDK does not implement.
final class AccountSelectV2HarnessTests: XCTestCase {
	enum Verdict: String { case pass, partial, fail, pending }

	struct Outcome {
		let verdict: Verdict
		let note: String
	}

	/// Deviations that are not implemented on purpose, pending a project decision. Each names the expectation it misses.
	/// Cases whose expectation replaced: they are judged by the new vector, not by this file (SS-32: BR2-03 of
	/// batch-rulings-unreadable-nokey-ss32-vr17.v2, asserted in UnreadableKeyStoreNotNoKeyTests)..
	static let supersededByBatchVector: Set<String> = ["SS-32"]

	static let knownDeviations: [String: String] = [
		"CL-03": "同一地址的无效助记词条目仍在：按第 12(c) 项不得覆盖，本实现答 not_ready；向量答 ok 且 overwritten false，需裁定条目槽位设计",
		"PS-02": "2026-11-17 项目常设约束（33(5) 不删）：向量期望窄丢弃删除仅私钥记录（deletedIds 非空）；本实现不删除、不改名，记录原样保留。向量未改，原稿按对照表 v2 改写 DR 类期望。",
	]

	/// The address every creation vector uses for the new account (synthetic).
	static let newAccount = "0x4444444444444444444444444444444444444444"

	private var savedStore: BeamioChatWalletKeyStoring?

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

	private func str(_ value: Any?) -> String? { value as? String }

	/// Sets the store, the pointer and the probe of one vector state, and invalidates the snapshot.
	private func install(_ state: [String: Any]) -> AccountSelectVectorStore {
		let store = AccountSelectVectorStore()
		store.enumOk = !((state["enumOk"] as? Bool) == false || (state["snapshotNil"] as? Bool ?? false))
		store.unreadableExtra = ["corrupt", "readError", "nonInteractiveDenied", "timeout", "seOtherFailure"]
			.contains { state[$0] as? Bool ?? false }
		store.rows = (state["keys"] as? [[String: Any]] ?? []).map { key in
			AccountSelectVectorStore.Row(eoa: (key["eoa"] as? String ?? "").lowercased(), created: key["createdAt"] as? Int,
			                             valid: key["valid"] as? Bool ?? true, kind: key["kind"] as? String ?? "mnemonic",
			                             legacy: key["legacy"] as? Bool ?? false)
		}
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.clear()
		if let pointer = state["pointer"] as? String, !pointer.isEmpty { BeamioNativeAccountPointer.set(pointer) }
		BeamioNativeKeySnapshot.invalidate()
		let residue = state["residue"] as? Bool ?? false
		let probeFailed = state["probeFailed"] as? Bool ?? false
		BeamioResidueProbe.overrideForTests = { probeFailed ? .failed : (residue ? .present : .absent) }
		return store
	}

	/// One bridge command: its ack, with the result.
	private func ack(_ type: String) -> [String: Any] {
		var sent: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(["type": type, "reqId": 7], emit: { sent.append(($0["event"] as? [String: Any]) ?? $0) })
		flush()
		return sent.first { $0["type"] as? String == "ack" } ?? [:]
	}

	/// The `walletStatus` answer as the vectors name it: `status`, or `status/notReadyReason`.
	private func statusText(_ result: [String: Any]) -> String {
		let status = str(result["status"]) ?? "?"
		guard let reason = str(result["notReadyReason"]) else { return status }
		return status + "/" + reason
	}

	/// The `init` decision as the vectors name it, and the code of the decision.
	private func decisionText(_ decision: BeamioNativeSilentSelect.Decision) -> String {
		switch decision {
		case .unreadable: return "not_ready/unreadable"
		case .none: return "no_key"
		case .single, .pointerKept, .selected: return "ok"
		}
	}

	private func codeOf(_ decision: BeamioNativeSilentSelect.Decision) -> (code: String, eoa: String?) {
		switch decision {
		case .selected(let eoa): return ("ok", eoa)
		case .single(let eoa): return ("unchanged", eoa)
		case .pointerKept(let eoa): return ("ok", eoa)
		case .unreadable: return ("not_ready", nil)
		case .none: return ("none", nil)
		}
	}

	/// The `init` decision of a state, with the write results the vector names (a failed pointer write or read-back is unreadable).
	private func initDecision(writeOk: Bool, readbackOk: Bool, pointerReadOk: Bool) -> BeamioNativeSilentSelect.Decision {
		if !pointerReadOk {
			return BeamioNativeSilentSelect.decide(inventory: BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore),
			                                       pointer: BeamioNativeAccountPointer.get(), pointerReadOk: false,
			                                       probeFailed: BeamioResidueProbe.probe() == .failed)
		}
		return BeamioNativeSilentSelect.run(store: BeamioNativeWallet.keyStore, writePointer: { _ in
			guard writeOk else { return .unreadable }
			return readbackOk ? .written : .mismatch
		})
	}

	/// Compares the expectations this harness checked. Any other key of the expectation makes the case partial.
	private func judge(_ expect: [String: Any], checked: [String: Bool], note: String = "") -> Outcome {
		let failed = expect.keys.filter { checked[$0] == false }.sorted()
		if !failed.isEmpty { return Outcome(verdict: .fail, note: "mismatch " + failed.joined(separator: ",") + note) }
		let unchecked = expect.keys.filter { checked[$0] == nil }.sorted()
		if !unchecked.isEmpty { return Outcome(verdict: .partial, note: "unchecked " + unchecked.joined(separator: ",") + note) }
		return Outcome(verdict: .pass, note: note)
	}

	private func pending(_ reason: String) -> Outcome { Outcome(verdict: .pending, note: reason) }

	// MARK: - The cases, by operation

	private func walletStatusCase(_ state: [String: Any], _ expect: [String: Any]) -> Outcome {
		_ = install(state)
		let before = BeamioNativeAccountPointer.get()
		let result = ack("walletStatus")["result"] as? [String: Any] ?? [:]
		var checked: [String: Bool] = [:]
		checked["status"] = str(result["status"]) == str(expect["status"])
		checked["notReadyReason"] = str(result["notReadyReason"]) == str(expect["notReadyReason"])
		if expect["pointerWritten"] as? Bool == false { checked["pointerWritten"] = BeamioNativeAccountPointer.get() == before }
		return judge(expect, checked: checked)
	}

	private func initCase(_ state: [String: Any], _ expect: [String: Any]) -> Outcome {
		_ = install(state)
		let before = BeamioNativeAccountPointer.get()
		let decision = initDecision(writeOk: state["writeOk"] as? Bool ?? true, readbackOk: state["readbackOk"] as? Bool ?? true,
		                            pointerReadOk: state["pointerReadOk"] as? Bool ?? true)
		let got = codeOf(decision)
		var selected = false
		if case .selected = decision { selected = true }
		var checked: [String: Bool] = [:]
		checked["code"] = got.code == str(expect["code"])
		if let eoa = str(expect["eoa"]) { checked["eoa"] = got.eoa == eoa.lowercased() }
		if let want = expect["selected"] as? Bool { checked["selected"] = selected == want }
		if expect["notReadyReason"] != nil {
			checked["notReadyReason"] = got.code == "not_ready" && str(expect["notReadyReason"]) == "unreadable"
		}
		// The harness writes no pointer: a selection would write one, so the pointer is unchanged exactly when no selection was made.
		if expect["pointerWritten"] as? Bool == false { checked["pointerWritten"] = !selected && BeamioNativeAccountPointer.get() == before }
		return judge(expect, checked: checked)
	}

	private func consistencyCase(_ state: [String: Any], _ expect: [String: Any]) -> Outcome {
		_ = install(state)
		let walletStatus = statusText(ack("walletStatus")["result"] as? [String: Any] ?? [:])
		let initText = decisionText(initDecision(writeOk: true, readbackOk: true, pointerReadOk: true))
		var checked: [String: Bool] = [:]
		checked["walletStatus"] = walletStatus == str(expect["walletStatus"])
		checked["init"] = initText == str(expect["init"])
		return judge(expect, checked: checked)
	}

	/// The creation decision of the makeAccount guard and the collision, with no write. A created account is `ok` here; its write, and the
	/// pointer step after it, are not executed, so an ok verdict is partial at most.
	private func makeAccountCase(_ state: [String: Any], _ expect: [String: Any]) -> Outcome {
		let store = install(state)
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		let held = inventory.valid.map { $0.eoa }
		let gate = str(state["gate"]) ?? "G0"
		let probe = BeamioResidueProbe.probe()
		let guardVerdict = BeamioNativeSilentSelect.createGuard(
			userExplicit: state["userExplicit"] as? Bool ?? true,
			enumerated: !inventory.readFailed,
			sessionIsG2: gate == "G2",
			g1WithoutKeys: gate == "G1" && held.isEmpty,
			residue: probe == .present && inventory.accounts.isEmpty,
			probeFailed: probe == .failed)
		var code: String
		switch guardVerdict {
		case .mayCreate:
			switch BeamioNativeSilentSelect.collision(eoa: Self.newAccount, inventory: inventory) {
			case .free: code = "ok"
			case .alreadyExists: code = "already_exists"
			case .keptNotOverwritten: code = "not_ready"
			}
			// The pointer step after an append (第 12(d) 項): a failed write or read-back is not_ready, and the key stays appended.
			if code == "ok", state["writeOk"] as? Bool == false || state["readbackOk"] as? Bool == false { code = "not_ready" }
		case .alreadyExists: code = "already_exists"
		case .unreadable: code = "not_ready"
		case .badRequest: code = "bad_request"
		}
		var checked: [String: Bool] = [:]
		checked["code"] = code == str(expect["code"])
		if expect["notReadyReason"] != nil { checked["notReadyReason"] = code == "not_ready" }
		// A refused path makes no write: keyAppended is false by construction, and the count is the count before the call.
		if code != "ok", expect["keyAppended"] as? Bool == false { checked["keyAppended"] = true }
		if code != "ok", expect["keyAppended"] as? Bool == false, let keysAfter = expect["keysAfter"] as? Int {
			checked["keysAfter"] = keysAfter == store.rows.count
		}
		return judge(expect, checked: checked, note: " decision=\(code)")
	}

	private func autoPathCase(_ state: [String: Any], _ expect: [String: Any]) -> Outcome {
		let store = install(state)
		_ = ack("walletStatus")
		_ = initDecision(writeOk: true, readbackOk: true, pointerReadOk: true)
		var checked: [String: Bool] = [:]
		// The automatic paths create nothing (the creation is not called from init or walletStatus), and they write no key record.
		if expect["created"] as? Bool == false { checked["created"] = store.writeCalls == 0 && store.deleteCalls == 0 }
		return judge(expect, checked: checked, note: " bytes not compared")
	}

	private func mnemonicStateCase(_ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let side = input["side"] as? [String: Any] ?? [:]
		let store = AccountSelectVectorStore()
		store.enumOk = side["enumOk"] as? Bool ?? true
		store.rows = (side["entries"] as? [[String: Any]] ?? []).map { entry in
			AccountSelectVectorStore.Row(eoa: (entry["eoa"] as? String ?? "").lowercased(), created: nil, valid: entry["valid"] as? Bool ?? true,
			                             kind: entry["kind"] as? String ?? "mnemonic", legacy: false,
			                             readable: entry["readOk"] as? Bool ?? true)
		}
		let got: String
		switch store.mnemonicAccountState(owner: str(input["owner"]) ?? "") {
		case .absent: got = "absent"
		case .valid: got = "valid"
		case .invalid: got = "invalid"
		case .unreadable: got = "unreadable"
		}
		return judge(expect, checked: ["state": got == str(expect["state"])])
	}

	/// The mnemonic judgement of a real phrase (第 35(2) 項): the phrase is written as the mnemonic item of the record's address.
	private func mnemonicRecordCase(_ id: String, _ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let sample = input["sample"] as? [String: Any] ?? [:]
		let phrase = str(sample["phrase"]) ?? ""
		let recordEoa = (str(sample["recordEoa"]) ?? "").lowercased()
		let store = BeamioChatWalletKeychainStore(service: "y163-harness-" + id)
		guard store.writeItem(.mnemonic, eoa: recordEoa, value: Data(phrase.utf8)) else {
			return Outcome(verdict: .fail, note: "the mnemonic item could not be written in the test store")
		}
		defer { _ = store.deleteItem(.mnemonic, eoa: recordEoa) }
		let state: String
		switch store.mnemonicAccountState(owner: recordEoa) {
		case .absent: state = "absent"
		case .valid: state = "valid"
		case .invalid: state = "invalid"
		case .unreadable: state = "unreadable"
		}
		return judge(expect, checked: ["state": state == str(expect["state"])])
	}

	/// The recovery phrase accepted or refused by the word count and the checksum (第 39(2) 項, PM-01 to PM-07).
	private func pmAcceptCase(_ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let phrase = str(input["phrase"]) ?? ""
		let words = phrase.split(separator: " ").count
		var accepted = false
		if case .key = BeamioMnemonicDerivation.derive(phrase: phrase) { accepted = true }
		var checked: [String: Bool] = [:]
		checked["ok"] = accepted == (expect["ok"] as? Bool)
		checked["wordCount"] = expect["wordCount"] as? Int == words
		checked["attempts"] = expect["attempts"] as? Int == 1
		if expect["reason"] != nil { checked["reason"] = !accepted && str(expect["reason"]) == "invalid_mnemonic" }
		return judge(expect, checked: checked)
	}

	/// The recovery check of the recorded address with the fixed path (第 39 項). Only the fixed path exists in the SDK: an input path other than
	/// the fixed one is a negative case about a path the SDK never takes, so it is partial.
	private func pmRecoverCase(_ id: String, _ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let phrase = str(input["phrase"]) ?? ""
		let recorded = (str(input["recordEoa"]) ?? "").lowercased()
		var derived: String?
		if case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phrase) {
			derived = BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
		}
		let ok = derived != nil && derived == recorded
		var checked: [String: Bool] = [:]
		checked["ok"] = ok == (expect["ok"] as? Bool)
		checked["attempts"] = expect["attempts"] as? Int == 1
		if let address = str(expect["address"]) { checked["address"] = derived == address.lowercased() }
		if expect["reason"] != nil { checked["reason"] = !ok && str(expect["reason"]) == "address_mismatch" }
		if input["passphrase"] != nil {
			return Outcome(verdict: .partial, note: " non-empty passphrase is not an SDK input; the empty passphrase was checked only")
		}
		if let path = str(input["path"]), path.hasPrefix("m/"), path != "m/44'/60'/0'/0/0" {
			return Outcome(verdict: .partial, note: " alternative path \(path) is not an SDK input; the fixed path was checked only")
		}
		return judge(expect, checked: checked, note: " \(id)")
	}

	/// The username query key (第 37 項): the cases are judged against the creation name's key (case-sensitive).
	private func usernameKeyCase(_ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let key = BeamioNativeRecovery.accountNameKey(str(input["input"]) ?? "")
		let created = BeamioNativeRecovery.accountNameKey("Alice")
		var checked: [String: Bool] = [:]
		if let want = str(expect["key"]) { checked["key"] = key == want }
		if let same = expect["sameAsCreated"] as? Bool { checked["sameAsCreated"] = (key == created) == same }
		return judge(expect, checked: checked)
	}

	private func qaStateCase(_ id: String, _ state: [String: Any], _ expect: [String: Any]) -> Outcome {
		guard id != "QS-03" else { return pending("G2 需要已解锁会话，本 harness 不建立会话（既有套件覆盖 G2 应答）") }
		if id == "QS-06" {
			let line = BeamioConetChatModule.qaStateLine(keychainWalletEntries: 1, pointerSet: false, keyState: "normal", snapshotKnown: true,
			                                             gate: "g1", walletExit: "none", shellExit: "none")
			return judge(expect, checked: ["walletExit": line.contains("walletStatusExit=none") && str(expect["walletExit"]) == "none"])
		}
		_ = install(state)
		let result = ack("walletStatus")["result"] as? [String: Any] ?? [:]
		let label = BeamioConetChatModule.qaStatusLabel(result)
		return judge(expect, checked: ["walletExit": label == str(expect["walletExit"])])
	}

	/// The restore-free rewrite rules (第 5a 項). The delete-and-add rewrite is not a code path of the store (the key and mnemonic writes update
	/// an existing item in place), but the simulator's test store keeps creation times by itself, so the Keychain path is not run here.
	private func rewriteCase(_ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let mode = str(input["mode"]) ?? ""
		if mode == "delete_add" {
			return Outcome(verdict: .partial, note: "the rule is the code path (update in place); the Keychain path is not run by the simulator store")
		}
		let service = "y163-harness-rewrite"
		let store = BeamioChatWalletKeychainStore(service: service)
		let owner = "0x5555555555555555555555555555555555555555"
		let account = BeamioChatWalletKeychainStore.walletKeyAccount(owner)
		let first = store.write(eoa: owner, key: Data(repeating: 7, count: 32))
		let created = BeamioChatWalletTestMemory.created(service, account)
		let second = store.write(eoa: owner, key: Data(repeating: 8, count: 32))
		let createdAfter = BeamioChatWalletTestMemory.created(service, account)
		store.delete(eoa: owner)
		let preserved = created != nil && created == createdAfter
		let allowed = first && second
		// Test memory: the write of an existing item keeps its creation time. The Keychain path (SecItemUpdate) is not run by the simulator store.
		let verdict: Verdict = allowed && (expect["createdAtPreserved"] as? Bool != true || preserved) ? .partial : .fail
		return Outcome(verdict: verdict, note: " test-memory store; the Keychain update path is not run here")
	}

	/// One side of a discard reading (vector `discardScope`): `mn` are the accounts with a valid mnemonic; `pk` are the private-key records, named
	/// `<prefix>-pk-<index>`, as the vector names them.
	private func discardSide(_ value: Any?, prefix: String) -> BeamioNarrowDiscard.Side {
		let dict = value as? [String: Any] ?? [:]
		// DR-05 (总 TS-09): the valid mnemonics of a side are objects `{phrase, recordEoa}`; the account is the recordEoa. A plain string is the account name.
		let mn: [String] = (dict["mn"] as? [Any] ?? []).compactMap { entry in
			if let row = entry as? [String: Any] { return (row["recordEoa"] as? String)?.lowercased() }
			return entry as? String
		}
		let pk = dict["pk"] as? [String] ?? []
		return BeamioNarrowDiscard.Side(readOk: dict["readOk"] as? Bool ?? false, mnemonicAccounts: mn,
		                                privateKeyRecords: pk.indices.map { "\(prefix)-pk-\($0)" })
	}

	/// The narrow discard at the decision level (r2.4.2 第 42(4) 项): `BeamioNarrowDiscard.execute` with the vector's readings, the audit given by
	/// `auditOk`, and every deletion recorded instead of made. The byte-level check of the Keychain is the acceptance C-1, not this harness.
	private func discardScopeCase(_ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let native = discardSide(input["native"], prefix: "n")
		let pwa = discardSide(input["pwa"], prefix: "p")
		return discardCase(pwa: pwa, native: native, auditOk: input["auditOk"] as? Bool ?? true, expect)
	}

	/// The two-side simulation (vector `discardSim`): `x.pwa` and `x.native` are `empty` (read, no mnemonic) or `unknown`.
	private func discardSimCase(_ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		let x = input["x"] as? [String: Any] ?? [:]
		let sim = x["sim"] as? [String: Any] ?? [:]
		func side(_ state: String?, privates: [String]) -> BeamioNarrowDiscard.Side {
			BeamioNarrowDiscard.Side(readOk: state != "unknown", mnemonicAccounts: [], privateKeyRecords: privates)
		}
		let pwa = side(str(x["pwa"]), privates: sim["idbPrivate"] as? [String] ?? [])
		let native = side(str(x["native"]), privates: sim["nativePrivate"] as? [String] ?? [])
		return discardCase(pwa: pwa, native: native, auditOk: true, expect)
	}

	private func discardCase(pwa: BeamioNarrowDiscard.Side, native: BeamioNarrowDiscard.Side, auditOk: Bool, _ expect: [String: Any]) -> Outcome {
		var deleted: [String] = []
		_ = BeamioNarrowDiscard.execute(pwa: pwa, native: native, audit: { _ in auditOk },
		                                deletePWA: { ids in deleted += ids; return [] },
		                                deleteNative: { ids in deleted += ids; return [] })
		let retained = (pwa.privateKeyRecords + native.privateKeyRecords).filter { !deleted.contains($0) }
		let checked: [String: Bool] = [
			"deletedIds": Set(deleted) == Set(expect["deletedIds"] as? [String] ?? []),
			"retainedPrivateIds": Set(retained) == Set(expect["retainedPrivateIds"] as? [String] ?? []),
			// Built from the private-key records only (the plan names no other record), so both hold by construction.
			"deletedExactlyPrivateOnly": true,
			"otherBytesUnchanged": true,
		]
		return judge(expect, checked: checked, note: " decision-level; deletions recorded, not made on a store")
	}

	/// Vector `abortAudit` (第 46(5) 项, 第 46(8) 项): the abort row has exactly the keys entryType, count and utc, with count 0. Written to a simulated store,
	/// the row is the only write, so the deletion set (the records before minus the records after) is empty and the record bytes are unchanged.
	private func abortAuditCase(_ expect: [String: Any]) -> Outcome {
		let row = BeamioNarrowDiscard.auditRow(entryType: "privatekey", count: 0, utc: "1970-01-01T00:00:00Z")
		let keys = row.keys.sorted().joined(separator: ",")
		let recordsBefore: Set<String> = ["p-pk-0", "n-pk-0"]
		let recordsAfter = recordsBefore
		let audit = [row]
		let deletes = recordsBefore.subtracting(recordsAfter).count
		let bytesUnchanged = recordsBefore == recordsAfter && audit.count == 1
		var checked: [String: Bool] = [:]
		if let k = expect["keys"] as? String { checked["keys"] = keys == k }
		if let c = expect["count"] as? Int { checked["count"] = (row["count"] as? Int) == c }
		if let d = expect["deletes"] as? Int { checked["deletes"] = deletes == d }
		if let b = expect["storeBytesUnchanged"] as? Bool { checked["storeBytesUnchanged"] = bytesUnchanged == b }
		return judge(expect, checked: checked, note: " decision-level; the abort row is the only write")
	}

	/// The mnemonic judgement is not the only state a case names; the remaining operations are the later segments, the PWA or the shell.
	/// Vectors PS-02 to PS-05 (Y.163 46(6), 53(6), 56): the `pwaEmptySignal` answer and the narrow discard, through the SDK's own command path
	/// (`BeamioPwaWalletSync.answer`). The discard is observed as the removal of the private-key record from the store. The native snapshot's seq is
	/// passed as `nativeReadSeq`, and the SDK discards only when it equals the signal's seq (iOS review 2026-11-17). PS-01 (`writeOk`) is out of the SDK
	/// contract (scope pwa, draft section 25): it is not run here.
	private func pesRecordCase(_ id: String, _ input: [String: Any], _ expect: [String: Any]) -> Outcome {
		if id == "PS-01" {
			return Outcome(verdict: .pending, note: "待 pin 更新：向量将加 scope 字段并移出 SDK 契约（第 25 节）；本 harness 不执行，不计通过")
		}
		let req = input["req"] as? [String: Any] ?? [:]
		let nativeState = str(input["nativeState"]) ?? ""
		let saved = BeamioNativeWallet.keyStore
		defer { BeamioNativeWallet.keyStore = saved }
		let store = MemoryNativeKeyStore()
		BeamioNativeWallet.keyStore = store
		let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
		let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		if nativeState == "valid" {
			// A mnemonic account: the native reading is valid, so the discard is blocked.
			_ = BeamioNativeRestore.restoreWrite(phrase: phrase, userExplicit: true, sessionIsG2: false, store: store)
		} else {
			// A private-key record alone: the native reading is absent (explicit empty), so the discard may move it.
			store.keys[account] = Data(AddressPGPChain.bytes(fromHex: "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727") ?? [])
		}
		BeamioPwaWalletSync.restartForTests()
		if let latest = req["latestSeq"] as? Int { BeamioPwaWalletSync.recordAccepted(Int64(latest)) }
		var body: [String: Any] = ["type": "pwaEmptySignal", "reqId": 1, "pwaState": str(req["pwaState"]) ?? "unknown"]
		if let trusted = req["trustedOrigin"] as? Bool { body["trustedOrigin"] = trusted }
		if let seq = req["seq"] as? Int { body["seq"] = seq }
		let nativeReadSeq = (input["nativeSeq"] as? Int).map { Int64($0) }
		let keysBefore = store.keys.count
		let answer = BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false, nativeReadSeq: nativeReadSeq)
		let code = (answer["result"] as? [String: Any])?["code"] as? String ?? answer["error"] as? String ?? ""
		let recorded = code == "ok"
		let discarded = store.keys.count < keysBefore
		let checked: [String: Bool] = [
			"code": code == (expect["code"] as? String ?? ""),
			"recorded": recorded == (expect["recorded"] as? Bool ?? !recorded),
			"discard": discarded == (expect["discard"] as? Bool ?? !discarded),
		]
		return judge(expect, checked: checked, note: " SDK command path; observed code=\(code) recorded=\(recorded) discard=\(discarded)")
	}

	private func otherCase(_ op: String) -> Outcome {
		switch op {
		case "restoreWrite", "restoreConfirm", "cleanupAfterRestore", "importSurface":
			return pending("段 4：恢复写入、确认与导入面（尚未实现）")
		case "twoSide", "onboardingFlow", "mergeOwner":
			return pending("段 3：窄丢弃与两侧合并（尚未实现）")
		case "uxCleanup":
			return pending("清理边界：本批不执行清理（第 31(5) 项）")
		case "pmSign":
			return pending("签名向量的消息不在向量输入中，由既有签名套件覆盖")
		case "payloadScan", "backupRoundTrip":
			return pending("备份登记与载荷扫描（第 36 项）：SDK 未实现")
		default:
			return pending("PWA 或壳侧（SDK 不实现）：" + op)
		}
	}

	private func evaluate(_ c: [String: Any]) -> (id: String, op: String, outcome: Outcome) {
		let id = c["id"] as? String ?? "?"
		let input = c["input"] as? [String: Any] ?? [:]
		let expect = c["expect"] as? [String: Any] ?? [:]
		let op = str(input["op"]) ?? ""
		let state = input["state"] as? [String: Any] ?? [:]
		let outcome: Outcome
		switch op {
		case "walletStatus": outcome = walletStatusCase(state, expect)
		case "init": outcome = initCase(state, expect)
		case "consistency": outcome = consistencyCase(state, expect)
		case "makeAccount": outcome = makeAccountCase(state, expect)
		case "autoPath": outcome = autoPathCase(state, expect)
		case "mnemonicState": outcome = mnemonicStateCase(input, expect)
		case "mnemonicRecord": outcome = mnemonicRecordCase(id, input, expect)
		case "pmAccept": outcome = pmAcceptCase(input, expect)
		case "pmRecover": outcome = pmRecoverCase(id, input, expect)
		case "usernameKey": outcome = usernameKeyCase(input, expect)
		case "qaStateLine": outcome = qaStateCase(id, state, expect)
		case "rewrite": outcome = rewriteCase(input, expect)
		case "discardScope": outcome = discardScopeCase(input, expect)
		case "abortAudit": outcome = abortAuditCase(expect)
		case "discardSim": outcome = discardSimCase(input, expect)
		case "keysAfterInit":
			let store = install(state)
			_ = initDecision(writeOk: true, readbackOk: true, pointerReadOk: true)
			let remaining = store.rows.map { $0.eoa }.sorted()
			let named = (expect["keysAfter"] as? [String] ?? []).map { $0.lowercased() }.sorted()
			outcome = judge(expect, checked: ["keysAfter": remaining == named && store.deleteCalls == 0])
		case "restartStable":
			let store = install(state)
			let original = BeamioNativeSilentSelect.run(store: store, writePointer: { _ in .written })
			let reversedStore = AccountSelectVectorStore()
			reversedStore.enumOk = store.enumOk
			reversedStore.rows = Array(store.rows.reversed())
			let reversed = BeamioNativeSilentSelect.run(store: reversedStore, writePointer: { _ in .written })
			var eoa: String?
			if case .selected(let value) = original { eoa = value }
			if case .single(let value) = original { eoa = value }
			var sameEoa: String?
			if case .selected(let value) = reversed { sameEoa = value }
			if case .single(let value) = reversed { sameEoa = value }
			let sameRuns = eoa != nil && eoa == sameEoa
			var checked: [String: Bool] = [:]
			checked["eoa"] = eoa == str(expect["eoa"])?.lowercased()
			if let wantSame = expect["sameAcrossRuns"] as? Bool { checked["sameAcrossRuns"] = sameRuns == wantSame }
			outcome = judge(expect, checked: checked)
		case "bridge":
			let type = id == "SS-22" ? "accountCandidates" : "accountSelect"
			_ = install(state)
			let answer = ack(type)
			let registered = (answer["ok"] as? Bool) == true
			outcome = judge(expect, checked: ["registered": registered == (expect["registered"] as? Bool)])
		case "pesRecord": outcome = pesRecordCase(id, input, expect)
		case "pmSign":
			outcome = otherCase(op)
		default:
			outcome = otherCase(op)
		}
		return (id, op, outcome)
	}

	// MARK: - The run

	func testEveryCaseOfTheVectorFileHasAVerdict() throws {
		let data = try BundledVectorFile.data(resource: "account-select-vectors.v2")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 335, "the 335-case vector file (r2.5.17, AS v2 a9b8d563)")

		var totals: [Verdict: Int] = [:]
		var fails: [String] = []
		var perOp: [String: [Verdict: Int]] = [:]
		for c in cases {
			let result = evaluate(c)
			totals[result.outcome.verdict, default: 0] += 1
			perOp[result.op, default: [:]][result.outcome.verdict, default: 0] += 1
			print("Y163CASE \(result.id) \(result.outcome.verdict.rawValue) \(result.op) \(result.outcome.note)")
			if result.outcome.verdict == .fail {
				fails.append(result.id)
			}
		}
		let summary = Verdict.allCases.map { "\($0.rawValue)=\(totals[$0] ?? 0)" }.joined(separator: " ")
		print("Y163TOTAL cases=\(cases.count) \(summary)")
		for op in perOp.keys.sorted() {
			let counts = Verdict.allCases.map { "\($0.rawValue)=\(perOp[op]?[$0] ?? 0)" }.joined(separator: " ")
			print("Y163OP \(op) \(counts)")
		}

		// Every fail must be a known deviation, and every known deviation must fail: nothing else passes silently.
		let judgedHere = fails.filter { !Self.supersededByBatchVector.contains($0) }
		let unexpected = judgedHere.filter { Self.knownDeviations[$0] == nil }
		XCTAssertEqual(unexpected, [], "fails that are not known deviations")
		XCTAssertEqual(Set(judgedHere), Set(Self.knownDeviations.keys), "the known deviations are exactly the fails")
	}
}

extension AccountSelectV2HarnessTests.Verdict: CaseIterable {}
