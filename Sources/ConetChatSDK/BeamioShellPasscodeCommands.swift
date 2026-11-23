import Foundation

/// The six shell passcode bridge commands of PROTOCOL-shell-passcode-v1 (frozen, SHA-256 adb8b71a…): `passcodeProvision`, `passcodeUnlock`,
/// `passcodeChange`, `passcodeDisable`, `nativeRepairProvide` and the read-only `passcodeStatus` fields.
///
/// - Each command has its own allowed field set (§1.6). Any other field is `bad_request`; a private-key field is `key_over_bridge_refused`.
/// - The commands are answered on their own route before the gate: they are reachable at G0 and while locked (§12).
/// - The shell has judged the sender (trusted main frame) before this code runs; credentials enter only from there.
/// - The work runs on one serial background queue (PBKDF2 is slow, and writes must not interleave). The answer goes out through `emit`.
/// - A wrong passcode is never counted here (§3.2, §5.3). The codes are the frozen table's (§4). Nothing is logged but type, reqId and code.
public enum BeamioShellPasscodeCommands {
	public static let names: Set<String> = [
		"passcodeProvision", "passcodeUnlock", "passcodeChange", "passcodeDisable", "nativeRepairProvide",
	]

	/// The allowed fields of each command (§1.6). `type` and `reqId` are always allowed.
	static let allowedFields: [String: Set<String>] = [
		"passcodeProvision": ["type", "reqId", "eoa", "phrase", "passcode"],
		"passcodeUnlock": ["type", "reqId", "eoa", "passcode", "callId"],
		"nativeIdentityCheck": ["type", "reqId", "eoa"],
		"passcodeChange": ["type", "reqId", "eoa", "oldPasscode", "newPasscode"],
		"passcodeDisable": ["type", "reqId", "eoa", "passcode"],
		"nativeRepairProvide": ["type", "reqId", "eoa", "phrase", "passcode", "requestReqId"],
	]

	/// The credential field names of this protocol. Only the commands above may carry them.
	static let credentialFields: Set<String> = ["phrase", "passcode", "oldPasscode", "newPasscode"]

	/// The page's reqId range of these commands, and the native repair request range (§2).
	static let pageReqIdRange: Range<Int> = 7_000_000_000_000 ..< 7_500_000_000_000
	static let nativeReqIdBase = 7_500_000_000_000
	static let nativeReqIdLimit = 7_600_000_000_000
	static let pendingLifetime: TimeInterval = 60

	/// The first protocol credential field that a command outside this set carries, or nil. Names only.
	static func strayCredentialField(type: String, body: [String: Any]) -> String? {
		guard !names.contains(type) else { return nil }
		return credentialFields.sorted().first { body[$0] != nil }
	}

	// MARK: - State (native, in memory)

	private static let queue = DispatchQueue(label: "beamio.shell-passcode")
	private static let stateLock = NSLock()
	private static var repairCounter = 0
	private struct Pending {
		var reqId: Int
		var eoa: String
		var expires: Date
	}
	private static var pending: Pending?
	/// The finished repair by `requestReqId`: a second `nativeRepairProvide` for the same request answers the same way (§3.4, idempotent).
	private static var finished: [Int: [String: Any]] = [:]
	static var now: () -> Date = { Date() }

	/// Test hook: forgets the pending request, the finished repairs and the counter.
	static func resetForTests() {
		stateLock.lock()
		pending = nil
		finished = [:]
		repairCounter = 0
		stateLock.unlock()
	}

	// MARK: - Entry

	/// Answers one command. `emit` receives the bare payloads (ack and events); the module wraps them as `chatModuleEvent`.
	static func handle(_ body: [String: Any], emit: @escaping ([String: Any]) -> Void) {
		let type = String(body["type"] as? String ?? "")
		guard let allowed = allowedFields[type] else { return }
		guard let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"]) else {
			emit(BeamioChatRouteRegister.ackEnvelope(reqId: NSNull(), result: nil, error: "bad_request"))
			return
		}
		func fail(_ code: String, _ reason: String? = nil) {
			var payload = BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: nil, error: code)
			if let reason { payload["reason"] = reason }
			NSLog("[BeamioShellPasscode] %@ reqId=%@ code=%@", type, String(describing: echo), code)
			emit(payload)
		}
		if body.keys.contains(where: { BeamioConetChatModule.pageCredentialFields.contains($0) }) {
			fail("key_over_bridge_refused")
			return
		}
		if body.keys.contains(where: { !allowed.contains($0) }) {
			fail("bad_request")
			return
		}
		var callId: String?
		if body["callId"] != nil {
			guard let valid = validCallId(body["callId"]) else { return fail("bad_request") }
			callId = valid
		}
		guard let reqInt = echo as? Int, pageReqIdRange.contains(reqInt),
		      let eoaRaw = body["eoa"] as? String, let eoa = normalizedEoa(eoaRaw) else {
			fail("bad_request")
			return
		}
		// the same-phrase check (supplement 2.6): only the public address comes in; the answer is a yes or no; nothing is changed
		if type == "nativeIdentityCheck" {
			switch nativeIdentityMatch(eoa: eoa) {
			case .some(let match): emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: ["match": match], error: nil))
			case .none: fail("not_ready")
			}
			return
		}
		var secrets: [String: [UInt8]] = [:]
		for field in credentialFields.intersection(allowed) {
			guard let text = body[field] as? String, !text.isEmpty, text.utf8.count <= 1024 else {
				fail("bad_request")
				return
			}
			secrets[field] = Array(text.utf8)
		}
		var requestReqId = 0
		if type == "nativeRepairProvide" {
			guard let n = body["requestReqId"] as? NSNumber, CFGetTypeID(n as CFTypeRef) != CFBooleanGetTypeID(),
			      n.doubleValue == n.doubleValue.rounded(.towardZero), n.doubleValue >= 0 else {
				fail("bad_request")
				return
			}
			requestReqId = n.intValue
		}
		queue.async {
			defer { for key in Array(secrets.keys) { BeamioNativeWallet.wipe(&secrets[key, default: []]) } }
			run(type: type, eoa: eoa, secrets: secrets, requestReqId: requestReqId, callId: callId, echo: echo, emit: emit, fail: fail)
		}
	}

	/// The address the unlocked native key derives, compared with `eoa`. nil while the native session is not unlocked (or cannot be read). The key is
	/// held only for the derivation and then overwritten.
	static func nativeIdentityMatch(eoa: String) -> Bool? {
		guard case .value(let pointed) = BeamioNativeAccountPointer.read() else { return nil }
		let session = BeamioPasscodeSession.shared
		var key: [UInt8]
		switch session.appState(eoa: pointed) {
		case .unlocked:
			guard let bundle = session.bundle(eoa: pointed) else { return nil }
			key = [UInt8](bundle)
		case .noPasscode:
			guard let data = BeamioNativeWallet.keyStore.read(eoa: pointed) else { return nil }
			key = [UInt8](data)
		default:
			return nil
		}
		defer { BeamioNativeWallet.wipe(&key) }
		guard let derived = BeamioNativeEthSigner.address(privateKey: key)?.lowercased() else { return nil }
		return derived == eoa
	}

	/// The answer of an unlock whose call does not match. The code table is in force (effective notice v2, 2026-11-20): `call_mismatch`, non-terminal.
	/// With the switch off the answer is `bad_request`, as before the table (addendum 22 s1); tests use that to keep the old path covered.
	static var callMismatchEffective = true
	static var callMismatchCode: String { callMismatchEffective ? "call_mismatch" : "bad_request" }

	/// A call id: 8 to 128 characters of letters, digits, `_` and `-` (addenda 19, 25). Anything else (also a non-string) is not a call id.
	static func validCallId(_ raw: Any?) -> String? {
		guard let text = raw as? String, (8 ... 128).contains(text.utf8.count),
		      text.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2D })
		else { return nil }
		return text
	}

	static func normalizedEoa(_ raw: String) -> String? {
		let lower = raw.lowercased()
		guard lower.hasPrefix("0x"), lower.utf8.count == 42, lower.dropFirst(2).allSatisfy({ $0.isHexDigit }) else { return nil }
		return lower
	}

	// MARK: - Commands

	private static func run(type: String, eoa: String, secrets: [String: [UInt8]], requestReqId: Int, callId: String?, echo: Any,
	                        emit: @escaping ([String: Any]) -> Void, fail: (String, String?) -> Void) {
		guard let vault = BeamioPasscodeSession.shared.vault else { return fail("not_ready", nil) }
		let session = BeamioPasscodeSession.shared
		func ok(_ result: [String: Any]) { emit(BeamioChatRouteRegister.ackEnvelope(reqId: echo, result: result, error: nil)) }
		func finish(_ result: BeamioShellPasscodeResult, success: () -> [String: Any]) {
			switch result {
			case .ok: ok(success())
			case .fail(let code, let reason): fail(code, reason)
			}
		}
		func announceState() {
			emit(session.statePayload(eoa: eoa, reason: nil))
		}
		/// Opens the record that was just written, so the native session is unlocked as the user is. A failure here only leaves the account locked.
		func installSession(_ passcode: [UInt8]) {
			// a session only for the account the pointer names (r2k)
			guard BeamioNativeAccountPointer.read() == .value(eoa) else { return }
			if case .success(let unlocked) = vault.shellUnlock(eoa: eoa, passcode: passcode) {
				session.install(eoa: eoa, bundle: unlocked.bundle, mnemonicKey: unlocked.pKey)
				unlocked.wipe()
			}
		}

		// An unlock from an incoming call (addendum 13): the call is compared before the passcode is looked at. A call that is not bound, or that was
		// bound for another account, is refused here: no passcode check, no unlock, no signature. The call stays bound (not terminal).
		if type == "passcodeUnlock", let callId {
			// the account first (addenda 14, 16): the request's account must be the current native account and, for a bound call, the bound account;
			// then the call (a call that is not bound, or another one, is a mismatch of the call).
			let bound = session.incomingCall(callId: callId)
			guard BeamioNativeAccountPointer.read() == .value(eoa), bound == nil || bound?.eoa == eoa else { return fail("account_mismatch", nil) }
			guard bound != nil else { return fail(callMismatchCode, nil) }
		}

		// A staged copy left by an interrupted write is reconciled before the record is read (frozen protocol §9.1). A record that cannot be read while
		// the staged copy can: neither is touched, and the unlock answers `write_failed` / `rollback_pending`.
		if type == "passcodeUnlock", vault.shellReconcileStaging(eoa: eoa) == "rollback_pending" { return fail("write_failed", "rollback_pending") }

		if let refusal = accountRefusal(type: type, eoa: eoa) {
			fail(refusal, nil)
			// an empty pointer with an unlock: the page may be offered the repair that creates the first record (r2l)
			if type == "passcodeUnlock", refusal == "no_record" { requestRepair(eoa: eoa, cause: "no_record", emit: emit) }
			return
		}

		switch type {
		case "passcodeProvision":
			let result = vault.shellProvision(eoa: eoa, phrase: secrets["phrase"] ?? [], passcode: secrets["passcode"] ?? [])
			if case .ok(let address) = result {
				if BeamioNativeAccountPointer.get().isEmpty { BeamioNativeAccountPointer.set(eoa) }
				installSession(secrets["passcode"] ?? [])
				BeamioShellMnemonicItem.migrate(eoa: eoa)
				announceState()
				ok(["passcode": "set", "eoa": eoa, "verifiedAddress": address])
			} else {
				finish(result) { [:] }
			}
		case "passcodeUnlock":
			switch vault.shellUnlock(eoa: eoa, passcode: secrets["passcode"] ?? []) {
			case .success(let unlocked):
				session.install(eoa: eoa, bundle: unlocked.bundle, mnemonicKey: unlocked.pKey)
				unlocked.wipe()
				session.markUiUnlocked(eoa: eoa, callId: callId)
				announceState()
				ok(["unlocked": true, "eoa": eoa])
			case .failure(let result):
				finish(result) { [:] }
				if case .fail(let code, _) = result, let cause = repairCause(code) { requestRepair(eoa: eoa, cause: cause, emit: emit) }
			}
		case "passcodeChange":
			let result = vault.shellChange(eoa: eoa, oldPasscode: secrets["oldPasscode"] ?? [], newPasscode: secrets["newPasscode"] ?? [])
			if case .ok = result {
				// the record has a new passcode: the old session keys are wiped and the session is rebuilt from the new record (the user has just entered
				// both passcodes; no second passcodeUnlock is asked for). The pointer is checked again by installSession.
				session.lockAll(reason: .passcodeChange)
				installSession(secrets["newPasscode"] ?? [])
				announceState()
				ok(["changed": true, "eoa": eoa])
			} else {
				finish(result) { [:] }
			}
		case "passcodeDisable":
			let result = vault.shellDisable(eoa: eoa, passcode: secrets["passcode"] ?? [], restorePhrase: { BeamioShellMnemonicItem.restoreDeviceBound(eoa: eoa, phrase: $0) })
			if case .ok = result {
				session.lockAll(reason: .passcodeDisable)
				announceState()
				ok(["disabled": true, "eoa": eoa])
			} else {
				finish(result) { [:] }
			}
		case "nativeRepairProvide":
			repair(vault: vault, eoa: eoa, secrets: secrets, requestReqId: requestReqId, echo: echo, emit: emit, fail: fail,
			       installSession: installSession, announceState: announceState)
		default:
			break
		}
	}

	/// The refusal that depends on the account (§10, r2l): judged on the strict pointer read.
	/// - unreadable: `not_ready`; the pointer is neither trusted nor cleared, nothing is unlocked.
	/// - empty: every session is ended at once. `passcodeProvision` (no record of any account) and `nativeRepairProvide` (authorised by a pending
	///   `nativeRepairRequest`) may go on and write the pointer first; every other command answers `no_record`.
	/// - another account: every session is ended, and the command is refused (`eoa_mismatch`; `other_account_present` for a provision).
	/// nil when the account may be used.
	private static func accountRefusal(type: String, eoa: String) -> String? {
		let creating = type == "passcodeProvision"
		switch BeamioNativeAccountPointer.read() {
		case .unreadable:
			return "not_ready"
		case .empty:
			BeamioPasscodeSession.shared.lockAll(reason: .logout)
			if creating {
				guard let owners = BeamioNativeWallet.keyStore.enumerateKeyOwners() else { return "not_ready" }
				return owners.contains { $0.lowercased() != eoa } ? "other_account_present" : nil
			}
			return type == "nativeRepairProvide" ? nil : "no_record"
		case .value(let pointer):
			if pointer == eoa { return nil }
			BeamioPasscodeSession.shared.lockAll(reason: .accountSwitch)
			return creating ? "other_account_present" : "eoa_mismatch"
		}
	}

	/// The repair cause of a failed unlock (§3.3). Not asked for: `backoff`, `eoa_mismatch`, `bad_request`, `not_ready`, `not_set`.
	private static func repairCause(_ code: String) -> String? {
		switch code {
		case "wrong_passcode": return "passcode_mismatch"
		case "no_record": return "no_record"
		case "record_invalid": return "record_invalid"
		default: return nil
		}
	}

	/// Registers a pending repair request and tells the page (§3.3). One pending request at a time; a new one replaces the old.
	private static func requestRepair(eoa: String, cause: String, emit: ([String: Any]) -> Void) {
		stateLock.lock()
		guard nativeReqIdBase + repairCounter < nativeReqIdLimit else {
			stateLock.unlock()
			return
		}
		let reqId = nativeReqIdBase + repairCounter
		repairCounter += 1
		pending = Pending(reqId: reqId, eoa: eoa, expires: now().addingTimeInterval(pendingLifetime))
		stateLock.unlock()
		emit(["type": "nativeRepairRequest", "reqId": reqId, "eoa": eoa, "cause": cause])
	}

	private static func repair(vault: BeamioPasscodeVault, eoa: String, secrets: [String: [UInt8]], requestReqId: Int, echo: Any,
	                           emit: @escaping ([String: Any]) -> Void, fail: (String, String?) -> Void,
	                           installSession: ([UInt8]) -> Void, announceState: () -> Void) {
		stateLock.lock()
		if let done = finished[requestReqId] {
			stateLock.unlock()
			var again = done
			again["reqId"] = echo
			emit(again)
			return
		}
		guard let request = pending, request.reqId == requestReqId, request.eoa == eoa, request.expires > now() else {
			stateLock.unlock()
			return fail("no_request", nil)
		}
		stateLock.unlock()
		let result = vault.shellRepair(eoa: eoa, phrase: secrets["phrase"] ?? [], passcode: secrets["passcode"] ?? [])
		switch result {
		case .ok(let address):
			// the pointer comes before the session: a session exists only for the account the pointer names
			if case .empty = BeamioNativeAccountPointer.read() { BeamioNativeAccountPointer.set(eoa) }
			installSession(secrets["passcode"] ?? [])
			BeamioShellMnemonicItem.migrate(eoa: eoa)
			announceState()
			let answer = BeamioChatRouteRegister.ackEnvelope(
				reqId: echo, result: ["repaired": true, "eoa": eoa, "verifiedAddress": address], error: nil)
			stateLock.lock()
			finished[requestReqId] = answer
			pending = nil
			stateLock.unlock()
			emit(answer)
			emit(["type": "nativeRepairResult", "reqId": requestReqId, "ok": true, "code": "ok"])
		case .fail(let code, let reason):
			fail(code, reason)
			emit(["type": "nativeRepairResult", "reqId": requestReqId, "ok": false, "code": code])
		}
	}
}

/// The mnemonic item `mnemonic:<eoa>` around the passcode record (frozen protocol §7). After a passcode record is written and proven, the item
/// becomes a header without a secret, `{v:3, eoa, mode:"passcode"}`; the phrase lives in the record (`mnemonicBlob`). Disable puts the phrase back.
enum BeamioShellMnemonicItem {
	static func header(eoa: String) -> Data {
		Data("{\"eoa\":\"\(eoa.lowercased())\",\"mode\":\"passcode\",\"v\":3}".utf8)
	}

	/// True when `data` is the header of `owner`. It carries no blob.
	static func isHeader(_ data: Data, owner: String) -> Bool {
		guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
		return obj["mode"] as? String == "passcode" && obj["eoa"] as? String == owner.lowercased() && (obj["v"] as? Int) == 3 && obj["blob"] == nil
	}

	/// After a passcode record is written: the item becomes the header. A failure is not a failure of the write: the old item is still readable and the
	/// new record is valid, so both are consistent and the next start repeats this step (§7.4 step 5).
	static func migrate(eoa: String) {
		guard let store = BeamioNativeWallet.keyStore as? BeamioPasscodeWalletStore else { return }
		_ = store.writeMnemonicHeader(eoa: eoa)
	}

	/// Puts the phrase back into the device-bound item (disable). True only when it reads back as written. A store without items has nothing to restore.
	static func restoreDeviceBound(eoa: String, phrase: Data) -> Bool {
		guard let store = BeamioNativeWallet.keyStore as? BeamioPasscodeWalletStore else { return true }
		return store.writeDeviceBoundMnemonic(eoa: eoa, phrase: phrase)
	}
}
