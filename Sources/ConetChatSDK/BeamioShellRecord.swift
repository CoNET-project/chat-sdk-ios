import CryptoKit
import Foundation
import Security

extension Set where Element == String {
	/// The names of an answer in UTF-8 byte order.
	var utf8Sorted: [String] {
		sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
	}
}

/// The page record of the account, held natively. The page reads and writes the whitelisted fields.
/// The W-class fields (the EOA private key of the account's profile, `mnemonicPhrase`, `recoveryWords`) are kept in the encrypted copy. PGP
/// private material is refused on both sides and never stored here; PGP public fields are refused on write and stripped on read and import.
/// The fixed page commands are `shellRecordRead` (type, reqId) and `shellRecordWrite` (type, reqId, record). `rev` is a top-level integer of the
/// record. Answers reach the page as `ack` envelopes: `result.code` for results, `ok:false` with `error` for envelope-level failures.
///
/// The origin of a sender is the shell's verdict. Without that verdict a command is answered `origin_refused`.
/// `shellRecordMigrationState` is a native read-only query and is not a page command.
public enum BeamioShellRecord {
	/// Request and answer limit in UTF-8 bytes: the raw request as received, and the answer envelope.
	static let sizeLimit = 2 * 1024 * 1024
	/// The largest request the record commands accept: the same 2 MiB as the answer limit (one record, at most the size the page may keep).
	static let requestLimit = 2 * 1024 * 1024
	static let revKey = "rev"
	/// The workspace of the account key, `<eoa>:default`.
	static let workspace = "default"
	/// The format version: the first byte of the encrypted file and the last byte of the authenticated data.
	static let formatVersion: UInt8 = 0x01

	/// The device-level state, kept by the SDK. It is not secret and is kept apart from the encrypted copy.
	/// `accountEstablished` is the account pointer: set at the first successful native write, never cleared. `legacyUnreadable` is the
	/// marker `legacy_store_unreadable`. `legacyConfirmedAbsent` records that the shell confirmed an absent or empty legacy store.
	struct DeviceState: Equatable {
		var accountEstablished = false
		var legacyUnreadable = false
		var legacyConfirmedAbsent = false
		/// The shell's reader found a non-empty legacy record that is not imported yet. Device-level: no account and no content.
		var legacyFound = false
		/// The most recent legacy report value (`found`, `absent` or `unreadable`), saved for every report (PY.15 6). Empty before any report.
		var legacyReportValue = ""
	}

	/// The device-level state store. The production store keeps a file; tests inject their own.
	protocol DeviceStateStore: AnyObject {
		func load() -> DeviceState
		/// Applies the change and writes it. Returns true only when the stored state reads back equal to the new state (PY.15 write check).
		@discardableResult func update(_ change: (inout DeviceState) -> Void) -> Bool
	}

	/// The production device state: one small file next to the encrypted copy, complete file protection, not in backup.
	final class FileDeviceStateStore: DeviceStateStore {
		#if BEAMIO_TEST_HOOKS
		/// Test only: runs between the write and the read back, so a test can change the stored file (a tampered read back).
		static var afterWriteHook: ((URL) -> Void)?
		#endif
		private let url: URL?

		init(url: URL?) {
			self.url = url
		}

		func load() -> DeviceState {
			guard let url, let data = try? Data(contentsOf: url),
			      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
			else { return DeviceState() }
			var state = DeviceState()
			state.accountEstablished = object["accountEstablished"] as? Bool ?? false
			state.legacyUnreadable = object["legacyUnreadable"] as? Bool ?? false
			state.legacyConfirmedAbsent = object["legacyConfirmedAbsent"] as? Bool ?? false
			state.legacyFound = object["legacyFound"] as? Bool ?? false
			state.legacyReportValue = object["legacyReportValue"] as? String ?? ""
			return state
		}

		@discardableResult
		func update(_ change: (inout DeviceState) -> Void) -> Bool {
			guard let url else { return false }
			var state = load()
			change(&state)
			let object: [String: Any] = [
				"accountEstablished": state.accountEstablished,
				"legacyUnreadable": state.legacyUnreadable,
				"legacyConfirmedAbsent": state.legacyConfirmedAbsent,
				"legacyFound": state.legacyFound,
				"legacyReportValue": state.legacyReportValue,
			]
			guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return false }
			let directory = url.deletingLastPathComponent()
			let temp = directory.appendingPathComponent(UUID().uuidString + ".tmp")
			do {
				try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
				try FileDeviceStateStore.excludeFromBackup(directory)
				try data.write(to: temp, options: [.completeFileProtection])
				try FileDeviceStateStore.excludeFromBackup(temp)
				if FileManager.default.fileExists(atPath: url.path) {
					_ = try FileManager.default.replaceItemAt(url, withItemAt: temp)
				} else {
					try FileManager.default.moveItem(at: temp, to: url)
				}
				try FileDeviceStateStore.excludeFromBackup(url)
			} catch {
				// The previous state stays in place when the new one is not written; the temporary file is removed. Nothing is logged.
				try? FileManager.default.removeItem(at: temp)
				return false
			}
			// Read back: the file must hold exactly the new state, otherwise the write is not confirmed.
			#if BEAMIO_TEST_HOOKS
			FileDeviceStateStore.afterWriteHook?(url)
			#endif
			return load() == state
		}

		/// Excludes a file or directory from backup (D2).
		private static func excludeFromBackup(_ url: URL) throws {
			var target = url
			var values = URLResourceValues()
			values.isExcludedFromBackup = true
			try target.setResourceValues(values)
		}
	}

	/// The production device state store.
	static var productionDevice: DeviceStateStore {
#if BEAMIO_TEST_HOOKS
		if let override = testDeviceOverride { return override }
#endif
		return FileDeviceStateStore(url: deviceStateURL())
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: a device state store in place of the file, for the tests of the device marker (item 4).
	static var testDeviceOverride: DeviceStateStore? = nil
#endif

	/// The per-account view the answers need. Tests replace parts of it; the shell reaches `production` through `handle`.
	struct Environment {
		var account: () -> String?
		var store: ShellRecordStore
		var device: DeviceStateStore
		var originAllowed: Bool
		var migrating: (String) -> Bool
		var firstRun: (String) -> FirstRunState
		var locked: (String) -> Bool
		var walletCopyApproved: Bool
		/// The native-key gate of the device. G0: no native key. G1: a native key, no session. G2: a session for the account.
		var gate: () -> BeamioConetChatModule.NativeGate = { .g2 }
		/// item 3: whether a write for `account` is the first page write of a creation transaction. The default is no transaction.
		var creationTransaction: (String) -> Bool = { _ in false }
		/// item 6: how the native keys decide the account of this command. The default is normal.
		var keyState: () -> KeyState = { .normal }
		/// items 1, 3, 4: the user chose to create an account. A read answers for the pending account, not for an existing one.
		var creationMode: () -> Bool = { false }
		/// 25.52Y.75 (takeover item 1): whether the native-key snapshot is known. Unknown: every record command answers not_ready, once.
		var snapshotKnown: () -> Bool = { true }
		/// 25.52Y.83 (takeover): a storage-derived lock (marker_missing or record_missing). Every record command answers not_ready, once.
		var storageLocked: () -> Bool = { false }
	}

	/// The creation transaction of this process (item 3). It opens when a key is generated for an account whose shell read was absent
	/// (BeamioNativeAccountCreate), and it ends with the first page write of that account. It is not kept across processes: a residual key with no
	/// transaction is migrating (AK-37).
	enum CreationTransactionState {
		private static let lock = NSLock()
		private static var open: String?
		/// Opens the transaction when the device has answered absent (confirmed, and neither found nor unreadable) before the key is generated.
		static func openIfAbsent(account: String) {
			let device = BeamioShellRecord.productionDevice.load()
			guard device.legacyConfirmedAbsent, !device.legacyFound, !device.legacyUnreadable else { return }
			lock.lock(); open = account.lowercased(); lock.unlock()
		}
		static func end(account: String) { lock.lock(); if open == account.lowercased() { open = nil }; lock.unlock() }
		static func cancel() { lock.lock(); open = nil; lock.unlock() }
		static func isOpen(account: String) -> Bool { lock.lock(); defer { lock.unlock() }; return open == account.lowercased() }
	}
	/// The state of the native keys for the account of a command. `ambiguous`: several keys and no pointer; nothing is chosen.
	/// `pointerKeyMissing`: the pointer names an account whose key is missing; nothing falls back to the enumeration.
	enum KeyState: Equatable {
		case normal
		case ambiguous
		case pointerKeyMissing
	}
	/// The creation mode (items 1, 3): the user chose to create an account, which is an open creation page.
	enum CreationModeState {
		static var isOn: Bool { BeamioConetChatModule.accountCreatePageOpen() }
	}

	/// What the first-run import has established for an account. `absent` is answered only under the conditions of.
	enum FirstRunState: Equatable {
		case notRun
		case confirmedAbsent
		case legacyUnreadable
		case importNotDone
	}

	/// What the store holds for an account. `unreadable` is a record that exists but cannot be opened. It is never reported as `absent`.
	enum ShellRecordRead: Equatable {
		case absent
		case unreadable
		case record([String: Any])

		static func == (lhs: ShellRecordRead, rhs: ShellRecordRead) -> Bool {
			switch (lhs, rhs) {
			case (.absent, .absent), (.unreadable, .unreadable):
				return true
			case let (.record(a), .record(b)):
				return (try? JSONSerialization.data(withJSONObject: a, options: [.sortedKeys]))
					== (try? JSONSerialization.data(withJSONObject: b, options: [.sortedKeys]))
			default:
				return false
			}
		}
	}

	/// The enumeration of the page copies of all accounts. A failed or incomplete enumeration is `failed`, never `absent`.
	enum PageCopyEnumeration: Equatable {
		case absent
		case present
		case failed
	}

	/// The facts of one legacy entry, as the reader sees it.
	struct LegacyFileFacts: Equatable {
		var readable: Bool
		var crcOk: Bool
		var truncated: Bool
		var validRecords: Int
		/// The verified records that are wallet records (LR-12 to LR-14): an entry holding only other documents has none.
		var walletRecords: Int
	}

	/// The judgement of the legacy store (item 11; vectors LR-01 to LR-11). `absent` only when the directory is missing, or it is readable and
	/// holds no entry. Any unreadable, CRC-failed, truncated or record-less entry makes the store `unreadable`, whatever the other entries are: never
	/// `absent`, and never `found` (LR-09).
	enum LegacyStoreJudgement: Equatable {
		case absent
		case found
		case unreadable
	}

	static func judgeLegacyStore(dirExists: Bool, listOk: Bool, files: [LegacyFileFacts]) -> LegacyStoreJudgement {
		guard dirExists else { return .absent }
		guard listOk else { return .unreadable }
		if files.isEmpty { return .absent }
		if files.contains(where: { !$0.readable || !$0.crcOk || $0.truncated || $0.validRecords < 1 }) { return .unreadable }
		// All entries are readable and verified. Only a wallet record makes the store found; other documents alone are absent.
		return files.contains(where: { $0.walletRecords > 0 }) ? .found : .absent
	}

	/// The facts of one entry of the production store. A sealed record is at least a 12-byte nonce and a 16-byte tag, so a shorter entry is truncated
	/// (and holds no record). The authentication (the CRC-equivalent) is per account, on read: the file name is a digest of the account, so the
	/// enumeration cannot check it; `crcOk` is therefore true here.
	static func legacyFileFacts(at url: URL) -> LegacyFileFacts {
		guard let data = try? Data(contentsOf: url) else {
			return LegacyFileFacts(readable: false, crcOk: true, truncated: false, validRecords: 0, walletRecords: 0)
		}
		let truncated = data.count < 28
		// Which record is a wallet record is not known without the account's key, so an intact record is counted as a wallet record here (the
		// conservative reading: import not done, never absent). Other-document-only entries are judged by the vectors, not by this enumeration.
		return LegacyFileFacts(readable: true, crcOk: true, truncated: truncated, validRecords: truncated ? 0 : 1, walletRecords: truncated ? 0 : 1)
	}

	/// The record of one account, stored as a whole. The write replaces the record, so a read returns what was written.
	protocol ShellRecordStore {
		func read(account: String) -> ShellRecordRead
		@discardableResult func write(account: String, _ record: [String: Any]) -> Bool
		/// Whether any account's record is stored (item 3). It is asked when the account's own record is absent, known account or not.
		func hasAnyRecord() -> Bool
		/// The enumeration of the page copies of all accounts. The default follows hasAnyRecord (no failure is seen).
		func pageCopyEnumeration() -> PageCopyEnumeration
		/// The page copies of all accounts, for the account of a copy that holds an EOA private key (item 1, (a)). nil: the store has
		/// no index of its copies (the copies are encrypted per account), so the account cannot be named.
		func copyRecords() -> [[String: Any]]?
	}

	/// The W-class copy. Kept only for `schemaVersion` 2. `schemaVersion` 1 is the legacy path and is refused.
	static let walletCopyApproved = true

	/// The forbidden PGP private paths. Exact matches; a forbidden path is refused, never stored.
	/// True when a path is the prefix or sits under it (`prefix.` followed by a key).
	static func isUnder(_ path: String, _ prefix: String) -> Bool {
		path == prefix || path.hasPrefix(prefix + ".")
	}

	/// The forbidden names of a write, by leaf path (item 1; PR-02, PR-04, TR-07). The legacy `profiles[*].pgpKey` is the PGP class
	/// whole, so every leaf under it is named. A leaf of `profiles[*].chatManager.pgpKey` is named only when it is a forbidden path (a private
	/// field). Its public fields are not forbidden and stay bad_request by path (TR-15).
	static func forbiddenNames(_ nodes: Set<String>) -> Set<String> {
		let legacyChildren = nodes.filter { $0 != "profiles[*].pgpKey" && isUnder($0, "profiles[*].pgpKey") }
		return nodes.filter { node in
			if forbiddenPaths.contains(node) { return true }
			// The object itself is not named when a leaf under it is (the leaf is the path that is refused).
			if node == "profiles[*].pgpKey" { return legacyChildren.isEmpty }
			return isUnder(node, "profiles[*].pgpKey")
		}
	}

	static let forbiddenPaths: Set<String> = [
		"profiles[*].chatManager.pgpKey.privateKey",
		"profiles[*].chatManager.pgpKey.privateKeyArmor",
		"profiles[*].chatManager.pgpKey.privateKeyArmorWrap",
		"profiles[*].pgpKey.privateKey",
		"profiles[*].pgpKey.privateKeyArmor",
		"profiles[*].pgpKey.privateKeyArmorWrap",
		"pgpPassphrase",
		"profiles[*].chats[*].chatData.privateArmored",
	]

	/// The PGP public paths inside a whitelisted container: refused on write (TR-37, TR-38).
	static let pgpPublicInContainers: Set<String> = [
		"profiles[*].chats[*].chatData.publicArmored",
		"profiles[*].chats[*].chatData.routePgpKeyID",
		"profiles[*].chats[*].chatData.routersArmoreds",
	]

	/// The W-class exact paths: the EOA private key of the profile whose keyID is the account, the top-level `mnemonicPhrase`,
	/// and the top-level `recoveryWords`.
	static let walletPaths: Set<String> = ["profiles[*].privateKeyArmor", "mnemonicPhrase", "recoveryWords"]

	/// The key-shaped names: a key with one of these names, or one of these prefixes, is key-shaped content unless it is a
	/// W-class exact path.
	static let keyShapeNames: Set<String> = [
		"privateKeyHex", "privateKeyArmored", "walletPrivateKey", "seed", "recoveryCode", "recoveryPhrase", "duplicatePassword",
		"duplicateMnemonicPhrase", "_duplicateCode",
	]
	static let keyShapePrefixes: [String] = ["privateKey", "mnemonic", "pgpPassphrase", "pgpPrivate", "duplicateCode"]

	/// The exact whitelisted paths (the list of 108 is the ceiling): the top-level scalars, the profile scalars, the chatManager router, the
	/// public armor of the account, and the 15 exact keys of `beamio`. `chatManager.keyID`, `chatManager.routes` and `passcode.status` are not on the list.
	static let whitelistedExact: Set<String> = {
		var set: Set<String> = [
			"schemaVersion", "rev", "isReady", "ver", "nonce", "upgradev2", "webFilter",
			"profiles[*].publicKeyArmor", "profiles[*].chatManager.router",
		]
		for key in profileScalarKeys {
			set.insert("profiles[*].\(key)")
		}
		for key in beamioKeys {
			set.insert("beamio.\(key)")
		}
		return set
	}()

	/// The profile scalars.
	static let profileScalarKeys: Set<String> = [
		"isPrimary", "emailAddr", "hdPath", "index", "isNode", "referrer", "nodeID", "nodeIP_address", "nodeRegion", "vpnTimeUsedInMin",
		"webFilter", "aaAccount", "keyID", "type",
	]

	/// The 15 exact keys of `beamio`.
	static let beamioKeys: Set<String> = [
		"accountName", "image", "darkTheme", "isUSDCFaucet", "isETHFaucet", "initialLoading", "firstName", "lastName", "createdAt", "language",
		"currency", "address", "payme", "tax", "localeCurrencyConfigured",
	]

	/// The whitelisted container subtrees: the whole subtree is allowed, and every key inside must pass the key-shape scan.
	static let whitelistedContainers: [String] = [
		"preferences", "fx168Order", "cardRedeems", "ChannelPartners", "referrals", "fragmentClass", "search",
		"profiles[*].tokens", "profiles[*].spClub", "profiles[*].SpClubPoints", "profiles[*].spChannel", "profiles[*].airdropEvent",
		"profiles[*].data", "profiles[*].activePassport", "profiles[*].silentPassPassports", "profiles[*].chats", "profiles[*].phoneCalls",
		"profiles[*].issuedCards",
	]

	static let pgpHeader = "BEGIN PGP PRIVATE KEY"

	// MARK: not_ready reasons and the persistence limit (interface spec v159 section 179)

	static let notReadyStorageLocked = "storage_locked"
	static let notReadyG1Uninitialized = "g1_uninitialized"
	static let notReadyAmbiguousAccounts = "ambiguous_accounts"
	static let notReadyUnreadable = "unreadable"
	/// a passcode record whose bundle the UI has not provided gives no key. That is a real storage state, reported as not_ready with this
	/// reason (retryable: the UI provides the passcode), never as no_key, locked or storage_locked.
	static let notReadyPasscodeNotProvided = "passcode_not_provided"
	/// The same reason this many times in a row, in one process, and the answer becomes `error` / `not_ready_persistent` (still with the reason).
	static let notReadyPersistenceLimit = 10

	/// A `not_ready` answer of the record commands: always with its reason and whether a retry can help. `storage_locked` and `ambiguous_accounts` need
	/// the user (false); `g1_uninitialized` ends when the session is established (true); `unreadable` may be transient, for instance a keychain that is not
	/// available before the first unlock (true; the persistence limit ends it for a cause a retry never cures, such as a missing entitlement).
	static func notReadyAnswer(reason: String, retryable: Bool, reqId: Any) -> [String: Any] {
		["code": "not_ready", "notReadyReason": reason, "retryable": retryable, "reqId": reqId]
	}

	private static let streakLock = NSLock()
	private static var streakReason: String?
	private static var streakCount = 0

	/// Test only: forgets the streak.
	static func resetNotReadyStreakForTests() {
		streakLock.lock(); streakReason = nil; streakCount = 0; streakLock.unlock()
	}

	/// Counts the consecutive not_ready answers of one reason for `shellRecordRead`, and answers `not_ready_persistent` once the limit is passed. Any other
	/// answer ends the streak.
	static func applyPersistenceLimit(_ answer: [String: Any]) -> [String: Any] {
		let reason = answer["code"] as? String == "not_ready" ? answer["notReadyReason"] as? String : nil
		streakLock.lock()
		defer { streakLock.unlock() }
		guard let reason else {
			streakReason = nil; streakCount = 0
			return answer
		}
		if streakReason == reason { streakCount += 1 } else { streakReason = reason; streakCount = 1 }
		// only an unreadable reason a retry never cures (retryable false: the cause entitlement or other) is final at once. Every other
		// reason, storage_locked and ambiguous_accounts included, waits for the limit.
		let retryable = answer["retryable"] as? Bool ?? false
		if (reason == notReadyUnreadable && !retryable) || streakCount > notReadyPersistenceLimit { return persistentAnswer(answer, reason: reason) }
		return answer
	}

	private static func persistentAnswer(_ answer: [String: Any], reason: String) -> [String: Any] {
		var persistent: [String: Any] = ["code": "error", "sub": "not_ready_persistent", "notReadyReason": reason, "retryable": answer["retryable"] as? Bool ?? false, "reqId": answer["reqId"] ?? NSNull()]
		if let cause = answer["unreadableCause"] as? String { persistent["unreadableCause"] = cause }
		return persistent
	}

	// MARK: Answers

	/// The answer to one command of the fixed set. Only the store and the device state are touched. `rawByteCount` is the size of
	/// the request as the shell received it; without it the size is taken from the re-serialized request.
	static func answer(
		_ body: [String: Any],
		env: Environment,
		nativeWrite: Bool = false,
		rawByteCount: Int? = nil
	) -> [String: Any] {
		var result = answerCore(body, env: env, nativeWrite: nativeWrite, rawByteCount: rawByteCount)
		if body["type"] as? String == "shellRecordRead" {
			result = applyPersistenceLimit(result)
			// v162 section 182: the read's not_ready (with or without a reason) is ok:true with the answer in `result`, never an envelope failure
			if result["code"] as? String == "not_ready" { result["inResult"] = true }
		}
		#if BEAMIO_QA_BUILD
		if body["type"] as? String == "shellRecordRead" {
			let sub = (result["result"] as? [String: Any])?["sub"] as? String ?? (result["sub"] as? String)
			let code = (result["result"] as? [String: Any])?["code"] as? String ?? (result["code"] as? String) ?? "?"
			BeamioConetChatModule.qaStateDiagnose(walletExit: nil, shellExit: sub.map { "\(code)/\($0)" } ?? code)
			let line = BeamioConetChatModule.qaShellReadLine(reqId: echoedReqId(body), answer: result)
			NSLog("[BeamioQAShellRead] %@", line)
			BeamioConetChatModule.qaStateSink?("\(ISO8601DateFormatter().string(from: Date())) [BeamioQAShellRead] \(line)")
		}
		#endif
		return result
	}

#if BEAMIO_QA_BUILD || BEAMIO_TEST_HOOKS
	/// The integer the page sent as reqId, or nil (a QA diagnostic only; never a string, so no page text can enter the line).
	static func echoedReqId(_ body: [String: Any]) -> Int? {
		if let n = body["reqId"] as? Int { return n }
		if let n = body["reqId"] as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() { return n.intValue }
		return nil
	}
#endif

	private static func answerCore(
		_ body: [String: Any],
		env: Environment,
		nativeWrite: Bool,
		rawByteCount: Int?
	) -> [String: Any] {
		let type = body["type"] as? String ?? ""
		let echo = BeamioChatRouteRegister.reqIdEcho(body["reqId"])
		let reqId: Any = echo ?? NSNull()

		guard env.originAllowed else { return ["code": "origin_refused", "reqId": reqId] }
		// v171 section 191: the order is origin, envelope size, reqId, allow-list, PGP, rev. A request over the limit is a bad_request in the envelope
		// (too_large is for an answer over the limit only); the limit is `requestLimit`.
		if let requestSize = rawByteCount ?? jsonSize(body), requestSize > requestLimit { return ["code": "bad_request", "reqId": reqId] }
		guard let echo else { return ["code": "bad_request", "reqId": NSNull()] }
		// v172 section 192: a write judges its content before the state gate: allow-list, PGP private key, then (below) the state gate and the rev.
		if type == "shellRecordWrite", let refusal = recordRefusal(body, reqId: reqId, env: env, rawByteCount: rawByteCount) { return refusal }
		// 25.52Y.75 (takeover item 1), v171 section 191: with the native-key snapshot unknown, the answer is not_ready with the existing reason
		// g1_uninitialized (a retry can help), for a read and a write alike. A read counts toward the persistence limit; a write is never converted.
		guard env.snapshotKnown() else { return notReadyAnswer(reason: notReadyG1Uninitialized, retryable: true, reqId: reqId) }
		// 25.52Y.83 (takeover): a storage-derived lock answers not_ready once. No payload is read and nothing is written or generated.
		// A write that meets the device-level storage lock is the envelope write_failed with reason internal_state (the project lead ruling, the same word as
		// pwaWalletSync's storage-locked write): nothing is written, current does not move. The storage lock comes before any rev conflict. A read keeps not_ready storage_locked.
		// A write is answered below, in the write path, AFTER the guards (the device marker and the unreadable latch answer migrating first, vector AK-39) and before the
		// passcode check and the rev (AK-38, AK-46); only a read is answered here.
		if env.storageLocked(), type != "shellRecordWrite" {
			return notReadyAnswer(reason: notReadyStorageLocked, retryable: false, reqId: reqId)
		}
		// PY.15 11: while the last legacy report is not written, every read entry answers migrating, before the gate (G1 included),
		// the creation mode, G0 with no account, G0 with no copy and the account branch. A read never answers absent or starts a creation then.
		if type == "shellRecordRead", isLegacyReportWriteFailed {
			return migratingAnswer(reason: "legacy_report_write_failed", reqId: reqId)
		}
		// the in-memory unreadable state is re-judged at each entry: once the copy matches the keychain account, it is cleared.
		if isSessionUnreadable {
			let pointer = BeamioNativeAccountPointer.get()
			if !pointer.isEmpty, pageCopyState(eoa: pointer, store: env.store) == .readable(eoaMatchesKeychain: true) {
				setSessionUnreadable(false)
			}
		}
		// step 2: a native key but no session answers not_ready (G1). The same for both channels.
		let gate = env.gate()
		if gate == .g1 {
			// Y.163 20h: a snapshot that could not be read is unreadable, with its reason; it is not a plain G1 not_ready.
			if let snapshot = BeamioNativeKeySnapshot.current(), snapshot.unreadable {
				// v161 section 181: an unreadable snapshot names its cause (a class only) and is retryable only when the cause is transient.
				// The cause is the one the snapshot kept, not a global that a later read may have changed.
				let cause = snapshot.unreadableCause
				var answer = notReadyAnswer(reason: notReadyUnreadable, retryable: BeamioKeychainFailureNote.retryable(cause), reqId: reqId)
				answer["unreadableCause"] = cause
				return answer
			}
			return notReadyAnswer(reason: notReadyG1Uninitialized, retryable: true, reqId: reqId)
		}
		// item 6: several keys and no pointer: nothing is chosen. A read is not_ready (a result, AK-55); a write is migrating (AK-58).
		// The pointer's account has no key: a read goes to the pointer answer (account_record_missing, AK-54); a write is migrating (AK-57).
		switch env.keyState() {
		case .ambiguous:
			if type == "shellRecordRead" {
				var answer = notReadyAnswer(reason: notReadyAmbiguousAccounts, retryable: false, reqId: reqId)
				answer["inResult"] = true
				return answer
			}
			return ["code": "migrating", "reqId": reqId]
		case .pointerKeyMissing where type != "shellRecordRead":
			return ["code": "migrating", "reqId": reqId]
		case .pointerKeyMissing, .normal:
			break
		}
		// items 1, 3, 4: in the creation mode a read answers for the pending account, which has no key and no copy yet (only the legacy store decides).
		// A write is accepted only in a creation transaction, once the key exists (AK-42, AK-43); before the key it is migrating (AK-59).
		if env.creationMode() {
			if type == "shellRecordRead" { return creationModeReadAnswer(env: env, reqId: reqId) }
			// PY.18 (b), AK-43: a creation transaction admits a write only for the first account. With the pointer already set, a second
			// account's creation is not supported in this version: the write is migrating, nothing is written.
			guard BeamioNativeAccountPointer.get().isEmpty, let pending = env.account(), env.creationTransaction(pending) else { return ["code": "migrating", "reqId": reqId] }
			_ = pending
		}
		guard let account = env.account() else {
			guard type == "shellRecordRead" else {
				// a page copy that exists, or an enumeration that failed, makes a write with no account known migrating.
				// (table, "native record empty"): with every page copy absent, the write is allowed only when the legacy store is confirmed empty, the account
				// pointer is empty and no native record exists. Any other case is migrating. write_failed is not used for this case.
				// The allowed case is not stored yet: a record is keyed by account, and no account is known here (the account source, P or N, is pending).
				// ok would acknowledge a write that is not stored, so it is answered migrating (fail closed) until that is decided. Flagged to the interface.
				// item 5: with no native key a write is migrating, but the content is judged first (AK-12, AK-13, AK-14).
				if let refusal = recordRefusal(body, reqId: reqId, env: env, rawByteCount: rawByteCount) { return refusal }
				return ["code": "migrating", "reqId": reqId]
			}
			return emptyStoreAnswer(env: env, account: nil, reqId: reqId, isRead: true)
		}
		// step 3: without a native key and without an imported copy, the reader decides. No payload is read.
		// 25.52Y.156 (PNK-07, PNK-10; 25.52U.4): a read at G0 of a page copy that is not an imported copy is judged by the copy's schema.
		// A schema-2 copy without the key is `error` with sub `needs_native_recovery`, with no field. Any other copy is read as usual
		// (the wallet fields redacted below). An absent or unreadable record, and every write, keep the empty-store answer.
		if gate == .g0, !importedCopyHeld(env: env, account: account) {
			guard type == "shellRecordRead", case .record(let record) = env.store.read(account: account) else {
				return emptyStoreAnswer(env: env, account: account, reqId: reqId, isRead: type == "shellRecordRead")
			}
			if integerValue(record["schemaVersion"]) == 2 {
				return ["code": "error", "sub": "needs_native_recovery", "reqId": reqId]
			}
		}

		var result: [String: Any]
		switch type {
		case "shellRecordRead":
			result = read(body, reqId: reqId, account: account, env: env)
		case "shellRecordWrite":
			result = write(body, reqId: reqId, account: account, env: env, nativeWrite: nativeWrite, rawByteCount: rawByteCount)
		default:
			return ["code": "bad_request", "reqId": reqId]
		}
		// 25.52Y.151 第 6 项: with the native key absent (G0, no_key), a read answer carries no privateKeyArmor, mnemonicPhrase or
		// recoveryWords. The redaction is of the answer only: the page copy is neither deleted nor changed. walletStatus is not affected.
		if type == "shellRecordRead", gate == .g0, result["code"] as? String == "ok", let record = result["record"] as? [String: Any] {
			result["record"] = withoutWalletFields(record)
		}
		// The answer envelope counts toward the limit, not only the record.
		if result["code"] as? String == "ok", let size = jsonSize(result), size > sizeLimit {
			return ["code": "too_large", "reqId": reqId]
		}
		return result
	}

	/// A write that failed (the record is not written, current and the stored record are unchanged): SRP-04 option A: the envelope
	/// `{ok:false, error:"write_failed"}`, never `ok:true` with `result.code`. The read, absent and retry answers keep their shapes.
	/// `reason` (optional, top level next to ok and error) comes from the closed set internal_state, storage_write, rollback_pending, old_copy_unverified; it never changes the error code.
	static let writeFailedReasons: Set<String> = ["internal_state", "storage_write", "rollback_pending", "old_copy_unverified"]

	static func writeFailedAnswer(reqId: Any, reason: String? = nil) -> [String: Any] {
		var answer: [String: Any] = ["code": "write_failed", "reqId": reqId, "envelopeFailure": true]
		if let reason, writeFailedReasons.contains(reason) { answer["reason"] = reason }
		return answer
	}

	/// The envelope the page reads. A result is `ok:true` with the result in `result` (the code is `result.code`). An envelope-level failure
	/// is `ok:false` with `error`: `origin_refused`, and a `bad_request` for a missing `reqId`, a missing `record`, or a `rev` that is not
	/// an integer.
	static func ackEnvelope(for answer: [String: Any]) -> [String: Any] {
		let code = answer["code"] as? String ?? ""
		let reqId: Any = answer["reqId"] ?? NSNull()
		// v165 section 185, v166 section 186: the envelope failures are the rejections (origin_refused, bad_request, pgp_private_in_payload) and the size of
		// the envelope itself (too_large, AK-14). The status answers (absent, ok, migrating, not_ready, conflict, write_failed, an answer over the
		// limit as too_large) and the storage answers (error + sub) are ok:true with the answer in `result`. A failure names its code only: nothing of the
		// payload (no record, no field name, no value, no path) is echoed.
		// AK-22 (main spec 25.52T.2): a bad_request of a CONTENT category (a path outside the allow-list, a typed or derivation mismatch, an unknown top-level field)
		// is a result: ok:true with result.code = bad_request and the names. It is decided by the category the answer is tagged with (`contentLevel`), never by whether names exist.
		// The envelope-level bad_request is only: reqId not valid, record missing, rev not an integer (their internal answers carry names that are never echoed), and the request over the
		// limit; those stay ok:false with the code only.
		let contentLevelBadRequest = code == "bad_request" && answer["contentLevel"] as? Bool == true
		let envelopeFailure = code == "origin_refused" || (code == "bad_request" && !contentLevelBadRequest) || code == "pgp_private_in_payload"
		if envelopeFailure {
			return ["type": "ack", "reqId": reqId, "ok": false, "error": code]
		}
		// SRP-02: a write that waits for the passcode is `ok:false` with its reason and retryable flag at the top level (no payload is echoed).
		if answer["envelopeFailure"] as? Bool == true {
			var failure: [String: Any] = ["type": "ack", "reqId": reqId, "ok": false, "error": code]
			if let reason = answer["notReadyReason"] { failure["notReadyReason"] = reason }
			if code == "write_failed", let reason = answer["reason"] as? String, writeFailedReasons.contains(reason) { failure["reason"] = reason }
			if let retryable = answer["retryable"] { failure["retryable"] = retryable }
			return failure
		}
		var result = answer
		result.removeValue(forKey: "reqId")
		result.removeValue(forKey: "inResult")
		result.removeValue(forKey: "contentLevel")
		return ["type": "ack", "reqId": reqId, "ok": true, "result": result]
	}

	/// the SDK holds an imported copy of the account when the native record exists and the profile whose keyID is the account holds
	/// `privateKeyArmor` (the W-class copy). Only the existence of the copy is judged here; no payload leaves this function.
	static func importedCopyHeld(env: Environment, account: String) -> Bool {
		guard case let .record(record) = env.store.read(account: account),
		      let profiles = record["profiles"] as? [[String: Any]]
		else { return false }
		return profiles.contains { ($0["keyID"] as? String)?.lowercased() == account.lowercased() && $0["privateKeyArmor"] != nil }
	}

	/// The answer when the store holds no record: `absent` only when there is no account pointer, the legacy store is confirmed
	/// empty, and the native record is empty. Any other state is an error, never absent.
	/// item 3: the creation mode reads the pending account. It has no key and no copy, and no other account's copy is read. The legacy
	/// store decides: a found record not imported is import_not_done; an unreadable store is legacy_store_unreadable; a confirmed absence is absent; a store
	/// that has not been read is migrating.
	static func creationModeReadAnswer(env: Environment, reqId: Any) -> [String: Any] {
		let device = env.device.load()
		// AK-50 (option B; item 3, §25.52Y.54/Y.56): the creation-mode read of a found, not imported legacy record is error/import_not_done, like the normal read.
		// KR-04 (v2.1) create_write is the page write inside a creation transaction, not this read. That write is NOT answered migrating by the write guard today (observed ok with a copy; see the report).
		if device.legacyFound { return ["code": "error", "sub": "import_not_done", "reqId": reqId] }
		if device.legacyUnreadable { return legacyStoreUnreadableAnswer(reqId: reqId) }
		if unreadableLatched(device) { return migratingAnswer(reason: "legacy_unreadable", reqId: reqId) }
		// PY.18: absent is admitted only when every condition of the creation admission holds. The report value alone never admits it.
		if device.legacyConfirmedAbsent {
			// a native key on the device is judged before any absent. A readable key of the account builds the copy from the key
			// (replicaAnswer), an unreadable key needs the native recovery, and a key with no known account is migrating. Never absent, never a creation.
			// PY.19 第 1 项 (interface 5.59 ruling): the creation read has no account context. Any native key, readable or not, is migrating here.
			// replicaAnswer is never called from the creation mode, and no needs_native_recovery or ok answer leaves this branch.
			if BeamioNativeWallet.hasAnyRecord() {
				return migratingAnswer(reason: "creation_native_key_present", reqId: reqId)
			}
			if let reason = creationRefusal(device: device, store: env.store) {
				return migratingAnswer(reason: reason, reqId: reqId)
			}
			return ["code": "absent", "reqId": reqId]
		}
		return ["code": "migrating", "reqId": reqId]
	}

	/// PY.18: a creation is admitted only when (a) the legacy store is confirmed empty, (b) the account pointer is empty, (c) no native key
	/// exists, (d) no page copy exists, and (e) no legacy report write failure is latched. Returns the internal diagnostic reason of a refusal, or nil.
	/// The reason is a diagnostic code only; it is never a page-visible code.
	static func creationRefusal(device: DeviceState, store: ShellRecordStore) -> String? {
		if device.legacyFound { return "legacy_found" }
		if unreadableLatched(device) { return "legacy_unreadable" }
		if !device.legacyConfirmedAbsent { return "legacy_not_confirmed_empty" }
		if isLegacyReportWriteFailed { return "report_write_failed" }
		if !BeamioNativeAccountPointer.get().isEmpty { return "pointer_set" }
		if BeamioNativeWallet.hasAnyRecord() { return "native_key_present" }
		if store.pageCopyEnumeration() != .absent { return "page_copy_present" }
		return nil
	}

	/// the account has its native key and no page copy. The native side builds the copy from that key, in the canonical form
	/// (Q1), stores it and answers the record, so the state moves on. The page never writes this copy. A failed store answers
	/// `migrating`, and the next read retries. The copy holds the EOA key only; other page fields are not created here.
	/// True when every valid mnemonic account of the device has a key record that reads and derives its account (or has none), and the accounts can be listed. Reads no copy and writes nothing.
	static func nativeAccountsReadable() -> Bool {
		let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
		guard inventory.enumerated, !inventory.readFailed else { return false }
		for account in inventory.valid {
			switch BeamioNativeWallet.keyStore.keyRecordState(eoa: account.eoa) {
			case .unreadable: return false
			case .absent: continue
			case .present:
				guard case .success = BeamioNativeWallet.withAccountKeyUnchecked(eoa: account.eoa, { _ in true }) else { return false }
			}
		}
		return true
	}

	/// The `migrating` answer with a diagnostic reason code. The code names only, never account, key or content. The wire answer is unchanged.
	static func migratingAnswer(reason: String, reqId: Any) -> [String: Any] {
		NSLog("[ShellRecord] migrating reason=%@", reason)
		return ["code": "migrating", "reqId": reqId]
	}

	static func replicaAnswer(env: Environment, account: String, reqId: Any) -> [String: Any] {
		let owner = account.lowercased()
		// A page copy is written for a valid mnemonic account only (v227 section 247.2, v229 section 249.2, Y.163 item 32 ruling A). A key with no valid mnemonic is an orphan: it is not read,
		// not derived and not written into a copy. No mnemonic item at all (a key-only orphan) is no account: absent. A mnemonic that cannot be verified is migrating (the next read decides).
		switch BeamioNativeWallet.keyStore.mnemonicAccountState(owner: owner) {
		case .valid: break
		case .absent: return ["code": "absent", "reqId": reqId]
		case .invalid, .unreadable: return migratingAnswer(reason: "mnemonic_not_verified", reqId: reqId)
		}
		// 10633 key-level check before any key is read: a mismatch is the native recovery; an unknown check is migrating (fail closed).
		if let refusal = BeamioNativeWallet.keyAccountGate(eoa: owner) {
			if case .rejected = refusal { return ["code": "error", "sub": "needs_native_recovery", "reqId": reqId] }
			return migratingAnswer(reason: "key_check_unavailable", reqId: reqId)
		}
		let armorResult: Result<String, BeamioNativeWallet.Failure> = BeamioNativeWallet.withAccountKeyUnchecked(eoa: owner) { key in
			"0x" + key.map { String(format: "%02x", $0) }.joined()
		}
		// PY.15: a native key record that cannot be read needs the native recovery; it is never a creation. An absent record is migrating.
		guard case .success(let armor) = armorResult else {
			if BeamioNativeWallet.hasRecord(eoa: owner) {
				return ["code": "error", "sub": "needs_native_recovery", "reqId": reqId]
			}
			return migratingAnswer(reason: "key_read_failed", reqId: reqId)
		}
		let profile: [String: Any] = ["keyID": owner, "privateKeyArmor": armor]
		var record: [String: Any] = ["rev": 1, "schemaVersion": 2, "profiles": [profile]]
		// an account that has its phrase natively gets the top-level `mnemonicPhrase` too. A legacy key-only account gets none.
		// The phrase state is judged first: absent is a key-only account (no phrase); present and readable is written;
		// present but unreadable is migrating, so nothing is written and the next read retries.
		if let items = BeamioNativeWallet.keyStore as? BeamioChatMnemonicKeyStoring {
			switch items.itemState(.mnemonic, eoa: owner) {
			case .absent:
				break
			case .present, .unreadable:
				guard let phrase = items.readItem(.mnemonic, eoa: owner), let text = String(data: phrase, encoding: .utf8) else {
					return migratingAnswer(reason: "phrase_unreadable", reqId: reqId)
				}
				record["mnemonicPhrase"] = text
			}
		}
		// PY.18 (d) and the interface ruling 5.60: replicaAnswer only builds a copy where none exists. Read before write: a readable or
		// unreadable existing copy is never overwritten (migrating; the next read decides).
		guard case .absent = env.store.read(account: owner) else { return migratingAnswer(reason: "copy_present_no_rebuild", reqId: reqId) }
		guard env.store.write(account: owner, record) else { return migratingAnswer(reason: "store_write_failed", reqId: reqId) }
		adoptRecord(env: env, account: owner, record: record)
		return ["code": "ok", "schemaVersion": 1, "record": readCopy(record, account: owner), "reqId": reqId]
	}

	/// `readPath`: the answer is a read. A flag repair that fails on the read path is not reported as success: the answer is
	/// `record_unreadable` (25.52Y.99 第 4 项). The write path keeps its own answers and is not changed by this.
	/// E9.11.29 r2 (§25.52K.3, IM-03): a read of an unreadable legacy store is `error` with sub `legacy_store_unreadable`. It is never absent,
	/// never a new wallet, and it is retried at the next start (the next report replaces the marker). Writes keep `migrating`.
	/// requirement (KR-05, PWA baseline): this answer stays; the keystore-replica vector is corrected to it.
	static func legacyStoreUnreadableAnswer(reqId: Any) -> [String: Any] {
		["code": "error", "sub": "legacy_store_unreadable", "reqId": reqId]
	}

	/// The "native key present" input of the read mapping (Android `nativeKeyPresent`). With an account: its key record exists, readable or not (`unreadable` counts as present,
	/// fail closed). With no account known: any key record on the device, or an enumeration that cannot say (fail closed). A key-only record counts; `hasAnyRecord()` does not (Y.163 items 31, 32).
	static func nativeKeyPresent(account: String?) -> Bool {
		let keys = BeamioNativeWallet.keyStore
		if let account { return keys.keyRecordState(eoa: account) != .absent }
		if keys.hasAnyKeyRecord() { return true }
		guard let owners = keys.enumerateKeyOwners() else { return true }
		return !owners.isEmpty
	}

	static func emptyStoreAnswer(env: Environment, account: String?, reqId: Any, creating: Bool = false, readPath: Bool = false, isRead: Bool = false) -> [String: Any] {
		let device = env.device.load()
		// R-1: a native key record on this device, for any account, is checked at device level. An account pointer is not needed:
		// an EOA key on the device means that an account exists. While such a record exists, no answer is `absent`.
		let nativeRecord = BeamioNativeWallet.hasAnyRecord()
		// R-2: a confirmed absence is stale once a native record exists. The flag is cleared, so it cannot answer `absent` later either.
		if nativeRecord, device.legacyConfirmedAbsent {
			let repaired = env.device.update { $0.legacyConfirmedAbsent = false }
			if readPath, !repaired {
				return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
			}
		}
		if device.accountEstablished {
			// item 4: another account's page copy is not this account's. With no account known, the enumeration decides
			// as in the rule below (AK-35): a page copy that exists is account_mismatch; a failed enumeration is record_unreadable.
			if account == nil {
				switch env.store.pageCopyEnumeration() {
				case .failed: return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
				case .present: return ["code": "error", "sub": "account_mismatch", "reqId": reqId]
				case .absent: break
				}
			}
			// item 6(b) and B: the account's own key exists, but its copy is missing. A write is migrating, never absent.
			// 25.52Y.110 第 2 条 (b) (AK-60): the read path is superseded by 第 57(1) 项 (r2.5.12): with the pointer set and the page record missing, a read
			// is error/account_record_missing whether or not the native key exists. Migrating is for a write, or a read with the pointer empty.
			// With the pointer empty (the 8a replica path) or a found legacy record, the creating read is unchanged.
			if let account, BeamioNativeWallet.hasKey(eoa: account) {
				let pointerSet = !BeamioNativeAccountPointer.get().isEmpty
				if creating && (!pointerSet || device.legacyFound) { return replicaAnswer(env: env, account: account, reqId: reqId) }
				if readPath && pointerSet { return ["code": "error", "sub": "account_record_missing", "reqId": reqId] }
				return migratingAnswer(reason: "account_copy_pending", reqId: reqId)
			}
			return ["code": "error", "sub": "account_record_missing", "reqId": reqId]
		}
		// import_not_done is for a found legacy record that has not been imported. The device-level finding holds
		// for any account, known or not. The import failure keeps it; a successful import clears it; an absence or unreadable report replaces it.
		if device.legacyFound {
			return ["code": "error", "sub": "import_not_done", "reqId": reqId]
		}
		// U.6: an unreadable legacy store answers migrating, never an error. The device marker stays for the write guard.
		// A per-account first-run value does not answer it. The next launch re-reports (PY.15 12 to 14).
		if unreadableLatched(device) {
			// group A (KR-05 exception of 2026-11-21): a read answers the unreadable legacy store as error/legacy_store_unreadable only when a native key is held
			// (the account's key, or, with no account known, any key record on the device). With no native key it stays migrating (U.6; AK-04, AK-06, AK-07, IM-03, IM-08).
			// A write stays migrating (no creation either way).
			if (readPath || isRead) && device.legacyUnreadable && nativeKeyPresent(account: account) { return legacyStoreUnreadableAnswer(reqId: reqId) }
			return migratingAnswer(reason: "legacy_unreadable", reqId: reqId)
		}
		// with no account known, the enumeration of the page copies decides, before the absence and the migrating answer.
		// A failed enumeration is record_unreadable (not absent, not account_mismatch, no marker). A page copy that exists is account_mismatch.
		if account == nil {
			switch env.store.pageCopyEnumeration() {
			case .failed: return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
			case .present: return ["code": "error", "sub": "account_mismatch", "reqId": reqId]
			case .absent: break
			}
		}
		// The confirmed absence is device-level: the last reader report, not a per-account state.
		if device.legacyConfirmedAbsent {
			// `absent` opens the write gate, so it is answered only when this device holds no native wallet record at all. A record that exists,
			// even one the shell does not hold, is an error, never absent.
			// item 2 (B): the account's own key exists, but its copy is missing: migrating (a read is not absent).
			if let account, BeamioNativeWallet.hasKey(eoa: account) {
				return creating ? replicaAnswer(env: env, account: account, reqId: reqId) : migratingAnswer(reason: "absent_key_copy_pending", reqId: reqId)
			}
			if nativeRecord {
				// §25.52U.6 row 6 and §25.52U.4 (KR-02 and KR-08): `account_record_missing` is for a pointer that is set. With the pointer empty and the legacy store confirmed empty,
				// the answer is `absent` when the native accounts are readable (the creation read, not this one, is what keeps a new account from being made: it answers migrating), and
				// `needs_native_recovery` when a native key cannot be read.
				if account == nil {   // the pointer is empty: no account is named
					return nativeAccountsReadable() ? ["code": "absent", "reqId": reqId] : ["code": "error", "sub": "needs_native_recovery", "reqId": reqId]
				}
				return ["code": "error", "sub": "account_record_missing", "reqId": reqId]
			}
			// item 4: the page copies of other accounts are not read here. The native key is judged by item 2 above.
			return ["code": "absent", "reqId": reqId]
		}
		// An upgraded device: its native key exists, but neither the device state nor the legacy store was read. The creating read builds the
		// copy from the key (the legacy import judgements above have already returned for found and unreadable).
		if creating, let account, BeamioNativeWallet.hasKey(eoa: account) {
			return replicaAnswer(env: env, account: account, reqId: reqId)
		}
		return migratingAnswer(reason: "legacy_not_read", reqId: reqId)
	}

	private static func read(_ body: [String: Any], reqId: Any, account: String, env: Environment) -> [String: Any] {
		let unknown = Set(body.keys).subtracting(["type", "reqId"])
		guard unknown.isEmpty else { return ["code": "bad_request", "names": unknown.utf8Sorted, "contentLevel": true, "reqId": reqId] }
		// Migrating comes before the record, so a page never reads a half-made record.
		if env.migrating(account) {
			return migratingAnswer(reason: "env_migrating", reqId: reqId)
		}
		if env.locked(account) {
			return notReadyAnswer(reason: notReadyPasscodeNotProvided, retryable: true, reqId: reqId)
		}
		switch env.store.read(account: account) {
		case .absent:
			return emptyStoreAnswer(env: env, account: account, reqId: reqId, creating: true, readPath: true)
		case .unreadable:
			return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
		case .record(let record):
			// A record without an integer rev is not answered (fail closed).
			guard integerValue(record[revKey]) != nil else {
				return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
			}
			// A PGP private header left on an unstripped path: not answered, the record is not returned (TR-47).
			// The copy the page reads (第 4 項): PGP fields never leave, and the W-class fields stay only on their exact paths.
			let copy = readCopy(record, account: account)
			// A PGP private header left on any path: not answered, the record is not returned (TR-47, 第 4 項).
			guard !containsPGPHeader(copy) else {
				return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
			}
			// A valid record is the source of truth: it clears the marker and repairs an empty account pointer. A repair that does not
			// persist is not a success, and the record is kept (25.52Y.99 第 4 至 5 项).
			guard adoptRecord(env: env, account: account, record: record) else {
				return ["code": "error", "sub": "record_unreadable", "reqId": reqId]
			}
			let answerOK: [String: Any] = ["code": "ok", "schemaVersion": 1, "record": copy, "reqId": reqId]
			// The size of the answer is checked first (TR-19), then a version-2 copy without an EOA private key needs the native recovery (TR-31).
			if let size = jsonSize(answerOK), size > sizeLimit {
				return ["code": "too_large", "reqId": reqId]
			}
			if integerValue(record["schemaVersion"]) == 2 {
				// The record is judged by the profile whose keyID is the account: none is account_mismatch; one without privateKeyArmor needs the native recovery.
				let owner = account.lowercased()
				let owned = (record["profiles"] as? [Any] ?? []).filter { profileMatches($0, owner) }
				if owned.isEmpty {
					return ["code": "error", "sub": "account_mismatch", "reqId": reqId]
				}
				if !owned.contains(where: { ($0 as? [String: Any])?["privateKeyArmor"] != nil }) {
					return ["code": "error", "sub": "needs_native_recovery", "reqId": reqId]
				}
			}
			return answerOK
		}
	}

	/// The write checks in the order of and: PGP private, then key-shaped names, then W placement and schema, then PGP public
	/// fields and the whitelist; then the replacement of the whole record. A successful write sets the account pointer.
	/// The content checks of a record write (TR-*), before any account or copy is judged. nil: the content is accepted.
	/// A write with no account (item 5) takes the same refusals first, so a refused content is answered as refused, not as migrating.
	static func recordRefusal(_ body: [String: Any], reqId: Any, env: Environment, rawByteCount: Int?) -> [String: Any]? {
		// the request size is judged first, in `answerCore` (v171 section 191)
		let unknown = Set(body.keys).subtracting(["type", "reqId", "record"])
		guard unknown.isEmpty else { return ["code": "bad_request", "names": unknown.utf8Sorted, "contentLevel": true, "reqId": reqId] }
		guard let record = body["record"] as? [String: Any] else {
			return ["code": "bad_request", "names": ["record"], "reqId": reqId]
		}
		// The header is refused wherever it is, and its path is not named.
		if containsPGPHeader(record) {
			return ["code": "pgp_private_in_payload", "names": [], "reqId": reqId]
		}
		var paths: [String] = []
		leafPaths(record, prefix: "", into: &paths)
		let nodes = Set(paths)
		let forbidden = forbiddenNames(nodes)
		if !forbidden.isEmpty {
			return ["code": "pgp_private_in_payload", "names": forbidden.utf8Sorted, "reqId": reqId]
		}
		// v166 section 186: a PGP private key is refused before any other judgement of the record, a missing rev included.
		guard integerValue(record[revKey]) != nil else {
			return ["code": "bad_request", "names": [revKey], "reqId": reqId]
		}
		// Key-shaped names outside the W exact paths, each named at the key where it matches (TR-16, TR-21, TR-25, TR-26, TR-29).
		let keyShaped = Set(paths.compactMap { keyShapeName($0) }).subtracting(walletPaths)
		if !keyShaped.isEmpty {
			return ["code": "key_shaped_content", "names": keyShaped.utf8Sorted, "reqId": reqId]
		}
		// The W-class paths are kept only for schemaVersion 2, once approved (TR-08b, TR-34).
		let wallet = nodes.intersection(walletPaths)
		if !wallet.isEmpty {
			guard env.walletCopyApproved, integerValue(record["schemaVersion"]) == 2 else {
				return ["code": "wallet_copy_not_approved", "names": wallet.utf8Sorted, "reqId": reqId]
			}
			// The W-class values are strings. A device-key wrapper object (`{ct, eoa, iv, kdf, mode, salt, v}`) is not an approved form.
			let typed = walletTypeNames(record)
			guard typed.isEmpty else {
				return ["code": "bad_request", "names": typed, "contentLevel": true, "reqId": reqId]
			}
		}
		// Not on the whitelist, and the PGP public fields inside containers: a bad request naming the paths (TR-09, TR-15, TR-30, TR-37).
		let outside = outsideNames(record).union(nodes.intersection(pgpPublicInContainers))
		if !outside.isEmpty {
			return ["code": "bad_request", "names": outside.utf8Sorted, "contentLevel": true, "reqId": reqId]
		}
		return nil
	}

	private static func write(
		_ body: [String: Any],
		reqId: Any,
		account: String,
		env: Environment,
		nativeWrite: Bool,
		guardWrites: Bool = true,
		rawByteCount: Int?
	) -> [String: Any] {
		if let refusal = recordRefusal(body, reqId: reqId, env: env, rawByteCount: rawByteCount) { return refusal }
		guard let record = body["record"] as? [String: Any], let rev = integerValue(record[revKey]) else {
			return ["code": "bad_request", "names": ["record"], "reqId": reqId]
		}
		if env.migrating(account) {
			return ["code": "migrating", "reqId": reqId]
		}
		// while the device marker is set, a write is refused whatever the store holds, the native record included.
		// The write gate reads the device marker only. A per-account first-run value is not read here: it could outlive the marker.
		// PY.19: the unreadable latch blocks writes only on a device whose account is not established.
		if guardWrites, unreadableLatched(env.device.load()), !env.device.load().accountEstablished {
			return ["code": "migrating", "reqId": reqId]
		}
		// the device-level storage lock: the envelope write_failed with reason internal_state; nothing is written, current does not move; it comes before the rev conflict
		if env.storageLocked() { return writeFailedAnswer(reqId: reqId, reason: "internal_state") }
		// a write while the passcode bundle has not been provided: not_ready with the reason passcode_not_provided, nothing is written.
		// The import's own write is exempt (guardWrites false).
		if guardWrites, env.locked(account) {
			// SRP-02 (shell-record-passcode-not-provided.v1): a write while the passcode bundle is not provided is an envelope-level answer:
			// {ok:false, error:not_ready, notReadyReason:passcode_not_provided, retryable:true}. A read stays a result (SRP-01).
			var answer = notReadyAnswer(reason: notReadyPasscodeNotProvided, retryable: true, reqId: reqId)
			answer["envelopeFailure"] = true
			return answer
		}
		// A record that cannot be opened, or whose rev is not an integer, is not overwritten (fail closed).
		var creating = false
		let currentRev: Int
		var stored: [String: Any]?
		switch env.store.read(account: account) {
		case .absent:
			// Review 5018e1f (blocker): a page write stays closed while a native key record exists on the device, whatever the flags and the first-run
			// state say. A confirmed first-run absence held by this process is stale then, so it is cleared. The import's own write is exempt.
			// item 2 (B): a native key on the device belongs to the native record. A key with no page copy is migrating, except the first write
			// of a creation transaction (item 3). A residual key is not a transaction (AK-37). The key check is kept (review 5018e1f).
			creating = env.creationTransaction(account)
			if guardWrites, !creating, BeamioNativeWallet.hasAnyRecord() {
				return ["code": "migrating", "reqId": reqId]
			}
			// (KR-04 create_write = migrating): inside a creation transaction a found legacy record that is not imported yet, or a legacy store that cannot be read
			// (fail closed), makes the page write migrating and nothing is written: a new copy would block the import (copy_present_no_rebuild). The import's own write is exempt.
			if guardWrites, creating {
				let device = env.device.load()
				if device.legacyFound || unreadableLatched(device) { return migratingAnswer(reason: "creation_write_legacy_pending", reqId: reqId) }
			}
			// PY.18 (b), AK-43: a creation transaction for a second account (the pointer names another account) is not supported: migrating,
			// nothing is written, no pointer is switched and no key is deleted.
			let pointerAccount = BeamioNativeAccountPointer.get()
			if creating, !pointerAccount.isEmpty, pointerAccount != account.lowercased() {
				return ["code": "migrating", "reqId": reqId]
			}
			let device = env.device.load()
			// The creation transaction may write with the pointer set: the pointer is set by the first write, and a second account has it.
			let confirmedAbsent = device.legacyConfirmedAbsent
			// Inside a creation transaction the absence was answered before the key was kept (item 3). R-2 may clear the flag after the key
			// exists, so the transaction does not read it again.
			if guardWrites, (unreadableLatched(device) && !device.accountEstablished) || (!creating && (!confirmedAbsent || device.accountEstablished)) {
				return ["code": "migrating", "reqId": reqId]
			}
			currentRev = 0
		case .unreadable:
			return writeFailedAnswer(reqId: reqId)
		case .record(let current):
			guard let existingRev = integerValue(current[revKey]) else {
				return writeFailedAnswer(reqId: reqId)
			}
			stored = current
			currentRev = existingRev
		}
		guard rev == currentRev else {
			return ["code": "conflict", "currentRev": currentRev, "reqId": reqId]
		}
		// A stored copy with W fields takes only schemaVersion 2 writes, whether or not the request carries W fields.
		if let stored, containsWallet(stored), integerValue(record["schemaVersion"]) != 2 {
			return ["code": "wallet_copy_not_approved", "names": leafWalletPaths(stored).utf8Sorted, "reqId": reqId]
		}
		// A page write whose profile carries privateKeyArmor under another keyID is refused as a conflict; nothing is written.
		// The native write (creation or recovery) does not apply this rule. It is a W-merge conflict (step 8), so it follows the rev check.
		if !nativeWrite, carriesForeignKey(record, owner: account.lowercased()) {
			return ["code": "conflict", "currentRev": currentRev, "reason": "w_account_unmatched",
			        "names": ["profiles[*].privateKeyArmor"], "reqId": reqId]
		}
		var next = record
		// The W-class fields of the stored copy: an omitted field keeps the stored value, a differing one conflicts.
		if let stored, !nativeWrite {
			if let names = mergeWallet(into: &next, stored: stored, account: account) {
				return [
					"code": "conflict", "currentRev": currentRev, "reason": mergeConflictReason(record, stored: stored, account: account),
					"names": names, "reqId": reqId,
				]
			}
		}
		// The derivation check (Q1, step 9): the EOA key that will be stored derives the account.
		// It applies to page and native writes alike, and to the merged value, not to the request alone.
		if let names = derivationMismatch(next, account: account) {
			return ["code": "bad_request", "names": names, "contentLevel": true, "reqId": reqId]
		}
		if containsWallet(next), integerValue(next["schemaVersion"]) != 2 {
			return ["code": "wallet_copy_not_approved", "names": leafWalletPaths(next).utf8Sorted, "reqId": reqId]
		}
		// A version-2 copy must hold the EOA private key once merged (TR-35).
		if integerValue(next["schemaVersion"]) == 2, !anyProfileHoldsPrivateKey(next) {
			return ["code": "wallet_fields_missing", "names": ["profiles[*].privateKeyArmor"], "reqId": reqId]
		}
		next[revKey] = currentRev + 1
		guard env.store.write(account: account, next) else {
			return writeFailedAnswer(reqId: reqId)
		}
		// item 3: the creation transaction ends with its first page write.
		if creating { CreationTransactionState.end(account: account) }
		// The first successful write sets the account pointer and clears the marker.
		env.device.update { state in
			state.accountEstablished = true
			state.legacyUnreadable = false
		}
		return ["code": "ok", "rev": currentRev + 1, "reqId": reqId]
	}

	// MARK: W-class fields 

	/// The W-class merge. The stored EOA key belongs to the profile whose keyID equals the account, matched by keyID and never by
	/// position. Returns the conflicting names, or nil when none. `mnemonicPhrase` and `recoveryWords` are top-level exact fields.
	static func mergeWallet(into next: inout [String: Any], stored: [String: Any], account: String) -> [String]? {
		var conflicts: Set<String> = []
		let owner = account.lowercased()
		var nextProfiles = next["profiles"] as? [Any] ?? []
		let storedProfiles = stored["profiles"] as? [Any] ?? []

		// A stored key that no profile of the account matches cannot be merged. The write is refused rather than replacing the record without it.
		for element in storedProfiles where !profileMatches(element, owner) {
			if let profile = element as? [String: Any], profile["privateKeyArmor"] != nil {
				conflicts.insert("profiles[*].privateKeyArmor")
			}
		}
		if let storedProfile = storedProfiles.first(where: { profileMatches($0, owner) }) as? [String: Any],
		   let storedKey = storedProfile["privateKeyArmor"] {
			if let index = nextProfiles.firstIndex(where: { profileMatches($0, owner) }),
			   var nextProfile = nextProfiles[index] as? [String: Any] {
				if let nextKey = nextProfile["privateKeyArmor"] {
					if !sameValue(nextKey, storedKey) { conflicts.insert("profiles[*].privateKeyArmor") }
				} else {
					nextProfile["privateKeyArmor"] = storedKey
					nextProfiles[index] = nextProfile
				}
			} else {
				conflicts.insert("profiles[*].privateKeyArmor")
			}
		}
		if next["profiles"] != nil {
			next["profiles"] = nextProfiles
		}

		for key in ["mnemonicPhrase", "recoveryWords"] {
			guard let storedValue = stored[key] else { continue }
			if let nextValue = next[key] {
				if !sameValue(nextValue, storedValue) { conflicts.insert(key) }
			} else {
				next[key] = storedValue
			}
		}
		return conflicts.isEmpty ? nil : conflicts.utf8Sorted
	}

	/// A readable record clears the device marker, and sets the account pointer when it is empty and the record holds a profile of the account.
	/// Returns false when the device state that must change could not be written.
	@discardableResult
	static func adoptRecord(env: Environment, account: String, record: [String: Any]) -> Bool {
		let owner = account.lowercased()
		let owns = (record["profiles"] as? [Any] ?? []).contains { profileMatches($0, owner) }
		let device = env.device.load()
		guard device.legacyUnreadable || (!device.accountEstablished && owns) else { return true }
		return env.device.update { state in
			state.legacyUnreadable = false
			if !state.accountEstablished && owns {
				state.accountEstablished = true
			}
		}
	}

	/// The reason of a W-class conflict (WM-02). `w_account_unmatched` when the stored account key has no profile in the request;
	/// `w_differs` when a value differs. A request key under another keyID is refused as `bad_request` before the merge (WM-08, WM-09).
	static func mergeConflictReason(_ request: [String: Any], stored: [String: Any], account: String) -> String {
		let owner = account.lowercased()
		let requestProfiles = request["profiles"] as? [Any] ?? []
		let storedOwnerKey = (stored["profiles"] as? [Any] ?? []).contains { element -> Bool in
			guard profileMatches(element, owner), let profile = element as? [String: Any] else { return false }
			return profile["privateKeyArmor"] != nil
		}
		let ownerInRequest = requestProfiles.contains { profileMatches($0, owner) }
		return storedOwnerKey && !ownerInRequest ? "w_account_unmatched" : "w_differs"
	}

	/// True when a profile's `keyID` equals the account (case-insensitive).
	static func profileMatches(_ element: Any, _ owner: String) -> Bool {
		guard let profile = element as? [String: Any], let keyID = profile["keyID"] as? String else { return false }
		return keyID.lowercased() == owner
	}

	/// True when a request profile carries `privateKeyArmor` (a null counts as carried) under a keyID that is not the account.
	static func carriesForeignKey(_ record: [String: Any], owner: String) -> Bool {
		(record["profiles"] as? [Any] ?? []).contains { element -> Bool in
			guard let profile = element as? [String: Any], profile["privateKeyArmor"] != nil else { return false }
			return !profileMatches(element, owner)
		}
	}

	/// The derivation check (Q1). A profile whose keyID is the account carries a `privateKeyArmor` that must be the canonical form
	/// (`0x` and 64 lowercase hex digits) and must derive the account. Returns the W path when a value does not; nil when all do.
	static func derivationMismatch(_ record: [String: Any], account: String) -> [String]? {
		let owner = account.lowercased()
		for element in record["profiles"] as? [Any] ?? [] {
			guard profileMatches(element, owner), let armor = (element as? [String: Any])?["privateKeyArmor"] as? String else { continue }
			guard isCanonicalArmor(armor), productionAddress(armor)?.lowercased() == owner else {
				return ["profiles[*].privateKeyArmor"]
			}
		}
		return nil
	}

	/// The read rule of a legacy key on import (Q1): a 64-digit hex key with or without `0x` becomes `0x` and 64 lower-case digits.
	/// nil when the text is not 64 hex digits. The key is not changed, only its form.
	static func normalizedImportArmor(_ text: String) -> String? {
		var body = Substring(text)
		if body.hasPrefix("0x") || body.hasPrefix("0X") { body = body.dropFirst(2) }
		guard body.count == 64, body.allSatisfy({ $0.isHexDigit }) else { return nil }
		return "0x" + body.lowercased()
	}

	/// The canonical form of a `privateKeyArmor` on write: `0x` and 64 lowercase hex digits (Q1).
	static func isCanonicalArmor(_ text: String) -> Bool {
		guard text.count == 66, text.hasPrefix("0x") else { return false }
		return text.dropFirst(2).allSatisfy { ("0" ... "9").contains($0) || ("a" ... "f").contains($0) }
	}

	/// True when some profile of the record holds an EOA private key.
	static func anyProfileHoldsPrivateKey(_ record: [String: Any]) -> Bool {
		(record["profiles"] as? [Any] ?? []).contains { element -> Bool in
			(element as? [String: Any])?["privateKeyArmor"] != nil
		}
	}

	/// The copy of a record without its PGP fields (read and import): the PGP object of a chat manager (an empty chat
	/// manager removed), the profile's PGP object, the top-level passphrase, a chat's private and public PGP armor, and the PGP public fields of `beamio`
	/// (an empty `beamio` removed). The W-class fields stay.
	static func stripPGPFields(_ record: [String: Any]) -> [String: Any] {
		var out = record
		out.removeValue(forKey: "pgpPassphrase")
		if let profiles = record["profiles"] as? [Any] {
			out["profiles"] = profiles.map { element -> Any in
				guard var profile = element as? [String: Any] else { return element }
				profile.removeValue(forKey: "pgpKey")
				// 1: the profile-level PGP private armor. `chatManager.pgpKey` (with its `privateKeyObj`) is removed whole below.
				profile.removeValue(forKey: "pgpPrivateKeyArmored")
				if var manager = profile["chatManager"] as? [String: Any] {
					manager.removeValue(forKey: "pgpKey")
					if manager.isEmpty {
						profile.removeValue(forKey: "chatManager")
					} else {
						profile["chatManager"] = manager
					}
				}
				if let chats = profile["chats"] as? [Any] {
					profile["chats"] = chats.map { chat -> Any in
						guard var chat = chat as? [String: Any], var chatData = chat["chatData"] as? [String: Any] else { return chat }
						for key in ["privateArmored", "publicArmored", "routePgpKeyID", "routersArmoreds"] {
							chatData.removeValue(forKey: key)
						}
						chat["chatData"] = chatData
						return chat
					}
				}
				return profile
			}
		}
		if var beamio = record["beamio"] as? [String: Any] {
			beamio.removeValue(forKey: "pgpPublicKeyArmor")
			beamio.removeValue(forKey: "pgpPublicKeyID")
			if beamio.isEmpty {
				out.removeValue(forKey: "beamio")
			} else {
				out["beamio"] = beamio
			}
		}
		return out
	}

	/// The copy a read answers (第 4 項): PGP fields are stripped, and the W-class fields are carried only on their exact paths.
	/// `profiles[*].privateKeyArmor` stays only in the profile whose keyID is the account; the other profiles lose it. `mnemonicPhrase`
	/// and `recoveryWords` are top-level only, so a copy inside a profile is removed. Every other field is read as before.
	/// The read path logs no value (第 5 項): it writes no log line, so no field value reaches a log.
	static func readCopy(_ record: [String: Any], account: String) -> [String: Any] {
		var out = stripPGPFields(record)
		let owner = account.lowercased()
		if let profiles = out["profiles"] as? [Any] {
			out["profiles"] = profiles.map { element -> Any in
				guard var profile = element as? [String: Any] else { return element }
				if !profileMatches(profile, owner) { profile.removeValue(forKey: "privateKeyArmor") }
				profile.removeValue(forKey: "mnemonicPhrase")
				profile.removeValue(forKey: "recoveryWords")
				return profile
			}
		}
		return out
	}

	/// The copy of a record without its W-class fields: the EOA key of each profile, `mnemonicPhrase`, and `recoveryWords`, used for
	/// the unregister and for the native observer (D11).
	static func withoutWalletFields(_ record: [String: Any]) -> [String: Any] {
		var out = record
		if let profiles = record["profiles"] as? [Any] {
			out["profiles"] = profiles.map { element -> Any in
				guard var profile = element as? [String: Any] else { return element }
				profile.removeValue(forKey: "privateKeyArmor")
				return profile
			}
		}
		out.removeValue(forKey: "mnemonicPhrase")
		out.removeValue(forKey: "recoveryWords")
		return out
	}

	/// The answer as the native observer may see it: the W-class fields are removed from the record. The WebView keeps the full answer.
	public static func observerView(_ answer: [String: Any]) -> [String: Any] {
		guard let record = answer["record"] as? [String: Any] else { return answer }
		var out = answer
		out["record"] = withoutWalletFields(record)
		return out
	}

	/// The ack envelope as the native observer may see it: the W-class fields are removed from its result record. The WebView keeps the full envelope.
	public static func observerEnvelope(_ ack: [String: Any]) -> [String: Any] {
		guard let result = ack["result"] as? [String: Any] else { return ack }
		var out = ack
		out["result"] = observerView(result)
		return out
	}

	/// True when a record carries a W-class field.
	static func containsWallet(_ record: [String: Any]) -> Bool {
		!leafWalletPaths(record).isEmpty
	}

	/// The W-class values that are objects or arrays: `mnemonicPhrase`, `recoveryWords` and `profiles[*].privateKeyArmor`. A device-key
	/// wrapper (`{ct, eoa, iv, kdf, mode, salt, v}`, in either key order) is an object, so it is refused with `bad_request` naming the path; the value is
	/// not echoed or stored. Strings, numbers, booleans and null are not judged here: they follow the W merge rules. Returns the path
	/// names in UTF-8 order.
	static func walletTypeNames(_ record: [String: Any]) -> [String] {
		func isObjectOrArray(_ value: Any) -> Bool {
			value is [String: Any] || value is [Any] || value is NSDictionary || value is NSArray
		}
		var names: Set<String> = []
		for key in ["mnemonicPhrase", "recoveryWords"] {
			if let value = record[key], isObjectOrArray(value) {
				names.insert(key)
			}
		}
		for profile in record["profiles"] as? [Any] ?? [] {
			if let armor = (profile as? [String: Any])?["privateKeyArmor"], isObjectOrArray(armor) {
				names.insert("profiles[*].privateKeyArmor")
			}
		}
		return names.utf8Sorted
	}

	static func leafWalletPaths(_ record: [String: Any]) -> Set<String> {
		var paths: [String] = []
		leafPaths(record, prefix: "", into: &paths)
		return Set(paths).intersection(walletPaths)
	}

	/// Equal JSON values; a null is never equal to a value.
	static func sameValue(_ a: Any, _ b: Any) -> Bool {
		if a is NSNull || b is NSNull { return false }
		if let x = a as? String, let y = b as? String { return x == y }
		let left = try? JSONSerialization.data(withJSONObject: [a], options: [.sortedKeys])
		let right = try? JSONSerialization.data(withJSONObject: [b], options: [.sortedKeys])
		return left != nil && left == right
	}

	/// Removes the W-class fields of an account's record and replaces it with rev + 1 (rule 5). Returns false when the record cannot be
	/// read or written.
	static func removeWalletFields(account: String, store: ShellRecordStore) -> Bool {
		switch store.read(account: account) {
		case .absent:
			return true
		case .unreadable:
			return false
		case .record(let record):
			guard containsWallet(record) else { return true }
			guard let rev = integerValue(record[revKey]) else { return false }
			var out = withoutWalletFields(record)
			out[revKey] = rev + 1
			return store.write(account: account, out)
		}
	}

	// MARK: Scan

	/// Every node path of the record: each object key at any depth (an empty object included) and each leaf, with `[*]` for each array element.
	static func leafPaths(_ value: Any, prefix: String, into out: inout [String]) {
		if let dict = value as? [String: Any] {
			for (key, child) in dict {
				let path = prefix.isEmpty ? key : prefix + "." + key
				out.append(path)
				leafPaths(child, prefix: path, into: &out)
			}
		} else if let array = value as? [Any] {
			for child in array {
				leafPaths(child, prefix: prefix + "[*]", into: &out)
			}
		}
	}

	/// The key-shaped name of a node path: the path cut at its first key-shaped component, or nil when no component is key-shaped.
	static func keyShapeName(_ path: String) -> String? {
		var cut: [Substring] = []
		for component in path.split(separator: ".", omittingEmptySubsequences: false) {
			cut.append(component)
			let name = component.replacingOccurrences(of: "[*]", with: "")
			if keyShapeNames.contains(name) || keyShapePrefixes.contains(where: { name.hasPrefix($0) }) {
				return cut.joined(separator: ".")
			}
		}
		return nil
	}

	/// The non-whitelisted names of a record. A non-whitelisted object is named by its direct keys; a non-whitelisted leaf by its path.
	/// An object that holds whitelisted keys is checked key by key, and a whitelisted scalar is an exact path (an object under it names its keys).
	static func outsideNames(_ record: [String: Any]) -> Set<String> {
		var out: Set<String> = []
		collectOutside(record, prefix: "", into: &out)
		return out
	}

	static func collectOutside(_ value: Any, prefix: String, into out: inout Set<String>) {
		if let dict = value as? [String: Any] {
			for (key, child) in dict {
				let path = prefix.isEmpty ? key : prefix + "." + key
				if walletPaths.contains(path) || isInContainer(path) { continue }
				// A whitelisted scalar is an exact path: an object under it is not a scalar, so its keys are named.
				if isWhitelisted(path) {
					if let object = child as? [String: Any], !object.isEmpty {
						for childKey in object.keys {
							out.insert(path + "." + childKey)
						}
					}
					continue
				}
				if hasWhitelistedDescendant(path) {
					collectOutside(child, prefix: path, into: &out)
				} else if let object = child as? [String: Any], !object.isEmpty {
					for childKey in object.keys {
						out.insert(path + "." + childKey)
					}
				} else {
					out.insert(path)
				}
			}
		} else if let array = value as? [Any] {
			for element in array {
				collectOutside(element, prefix: prefix + "[*]", into: &out)
			}
		}
	}

	/// True when a path is an exact whitelisted path.
	static func isWhitelisted(_ path: String) -> Bool {
		whitelistedExact.contains(path)
	}

	/// True when a path is a whitelisted container, or lies inside one (its subtree is checked by the key-shape scan).
	static func isInContainer(_ path: String) -> Bool {
		whitelistedContainers.contains { path == $0 || path.hasPrefix($0 + ".") || path.hasPrefix($0 + "[*]") }
	}

	/// True when some whitelisted path lies below `path`, so that `path` is a structural object (for example `profiles`, `beamio`).
	static func hasWhitelistedDescendant(_ path: String) -> Bool {
		whitelistedExact.contains { $0.hasPrefix(path + ".") || $0.hasPrefix(path + "[*]") }
			|| whitelistedContainers.contains { $0.hasPrefix(path + ".") || $0.hasPrefix(path + "[*]") }
	}

	/// True when a string at any depth holds the PGP private key header. The test runs on the normalized text N: the header
	/// is found whatever its case, width, combining marks, format characters or separators. Read, import and write all use this one function.
	static func containsPGPHeader(_ value: Any) -> Bool {
		if let text = value as? String { return normalizedForDetection(text).contains(normalizedPGPHeader) }
		if let dict = value as? [String: Any] { return dict.values.contains { containsPGPHeader($0) } }
		if let array = value as? [Any] { return array.contains { containsPGPHeader($0) } }
		return false
	}

	/// The header in the normalized form: `BEGIN PGP PRIVATE KEY` after N is `BEGINPGPPRIVATEKEY`.
	static let normalizedPGPHeader = "BEGINPGPPRIVATEKEY"

	/// The normalized text N for detection: NFKD; then remove the set S (White_Space, U+FEFF, U+200B to U+200D, U+2060, U+00AD); then remove
	/// the general categories Mn, Me and Cf; then keep only letters and digits, in upper case. The original value is never rewritten.
	static func normalizedForDetection(_ text: String) -> String {
		let extraSpace: Set<UInt32> = [0xFEFF, 0x200B, 0x200C, 0x200D, 0x2060, 0x00AD]
		var out = String.UnicodeScalarView()
		for scalar in text.decomposedStringWithCompatibilityMapping.unicodeScalars {
			if scalar.properties.isWhitespace || extraSpace.contains(scalar.value) { continue }
			switch scalar.properties.generalCategory {
			case .nonspacingMark, .enclosingMark, .format:
				continue
			default:
				break
			}
			if scalar.properties.isAlphabetic || scalar.properties.numericType != nil {
				out.append(scalar)
			}
		}
		return String(out).uppercased()
	}

	/// An integer from a JSON value. Booleans and fractions are not integers.
	static func integerValue(_ value: Any?) -> Int? {
		guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
		let double = number.doubleValue
		guard double.isFinite, double == double.rounded(), abs(double) < 9.0e15 else { return nil }
		return number.intValue
	}

	static func jsonSize(_ value: Any) -> Int? {
		guard JSONSerialization.isValidJSONObject(value) else { return nil }
		return (try? JSONSerialization.data(withJSONObject: value))?.count
	}

	// MARK: Canonical JSON

	/// The canonical JSON of a record: UTF-8, object keys in UTF-8 byte order, no whitespace, strings escaped by the JSON rules, arrays in their order.
	/// The plaintext of the encrypted copy is these bytes.
	static func canonicalJSON(_ value: Any) -> Data? {
		canonicalText(value).map { Data($0.utf8) }
	}

	static func canonicalText(_ value: Any) -> String? {
		if value is NSNull { return "null" }
		if let number = value as? NSNumber {
			if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
			let double = number.doubleValue
			if double.isFinite, double == double.rounded(), abs(double) < 9.0e15 {
				return String(number.int64Value)
			}
			guard let data = try? JSONSerialization.data(withJSONObject: [number], options: []),
			      let text = String(data: data, encoding: .utf8), text.hasPrefix("["), text.hasSuffix("]")
			else { return nil }
			return String(text.dropFirst().dropLast())
		}
		if let text = value as? String { return jsonString(text) }
		if let array = value as? [Any] {
			var parts: [String] = []
			for element in array {
				guard let part = canonicalText(element) else { return nil }
				parts.append(part)
			}
			return "[" + parts.joined(separator: ",") + "]"
		}
		if let dict = value as? [String: Any] {
			let keys = dict.keys.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
			var parts: [String] = []
			for key in keys {
				guard let element = dict[key], let part = canonicalText(element) else { return nil }
				parts.append(jsonString(key) + ":" + part)
			}
			return "{" + parts.joined(separator: ",") + "}"
		}
		return nil
	}

	/// A JSON string literal: quotes, backslashes and control characters escaped; other characters, and "/", as they are.
	static func jsonString(_ text: String) -> String {
		var out = "\""
		for scalar in text.unicodeScalars {
			switch scalar {
			case "\"": out += "\\\""
			case "\\": out += "\\\\"
			case "\n": out += "\\n"
			case "\r": out += "\\r"
			case "\t": out += "\\t"
			case "\u{08}": out += "\\b"
			case "\u{0C}": out += "\\f"
			default:
				if scalar.value < 0x20 {
					out += String(format: "\\u%04x", scalar.value)
				} else {
					out.unicodeScalars.append(scalar)
				}
			}
		}
		return out + "\""
	}

	// MARK: Native state

	private static let stateLock = NSLock()
	private static var migratingAccounts: Set<String> = []
	private static var firstRunStates: [String: FirstRunState] = [:]

	/// The shell calls this before the pre-WebView steps (page record initialization, PGP migration) of an account.
	/// While it is set, page reads and writes answer `migrating`.
	public static func beginPreWebViewMigration(eoa rawEoa: String) {
		stateLock.lock()
		defer { stateLock.unlock() }
		migratingAccounts.insert(rawEoa.lowercased())
	}

	/// The shell calls this when the pre-WebView steps of an account have finished.
	public static func finishPreWebViewMigration(eoa rawEoa: String) {
		stateLock.lock()
		defer { stateLock.unlock() }
		migratingAccounts.remove(rawEoa.lowercased())
	}

	static func isMigrating(_ eoa: String) -> Bool {
		stateLock.lock()
		defer { stateLock.unlock() }
		return migratingAccounts.contains(eoa.lowercased())
	}

	static func firstRunState(_ eoa: String) -> FirstRunState {
		stateLock.lock()
		defer { stateLock.unlock() }
		return firstRunStates[eoa.lowercased()] ?? .notRun
	}

	static func setFirstRunState(_ eoa: String, _ state: FirstRunState) {
		stateLock.lock()
		defer { stateLock.unlock() }
		firstRunStates[eoa.lowercased()] = state
	}

	/// The migration state name of an account, for native callers (`shellRecordMigrationState`, read only).
	public static func migrationStateName(eoa rawEoa: String) -> String {
		BeamioPgpMigrationImport.state(eoa: rawEoa).rawValue
	}

	/// What the shell's reader found in the legacy store, when there is no account pointer. `absent` clears the marker;
	/// `unreadable` sets it. Both are ignored once the account pointer is set.
	public enum LegacyReport {
		case absent
		case unreadable
		/// A non-empty legacy record was found. Device-level: no account is needed and no content is passed.
		case found
	}

	/// The answer of a legacy report (PY.15 items 4, 11, 16;, project ruling). `ok`: saved and read back, whatever the native record or the account
	/// pointer. `write_failed`: the write is not confirmed. `bad_request`: a parameter outside found, absent, unreadable (not produced by this entry
	/// for a valid `LegacyReport`; kept as the spec code for the wire).
	public enum LegacyReportResult: String, Equatable {
		case ok
		case badRequest = "bad_request"
		case writeFailed = "write_failed"
	}

	/// Set when the last applicable report was not written. While it is set, a read answers `migrating` (fail closed); a later written report clears it.
	/// Memory only: a new process starts clear, and the shell re-reports at launch (PY.15).
	private static let reportLock = NSLock()
	private static var reportWriteFailed = false
	/// the unreadable state of a pointer-set device whose keychain account cannot be named (locked or not yet readable).
	/// It is held in memory only, never persisted, and is re-judged at each read or write entry (cleared once the copy matches the keychain).
	private static var sessionUnreadable = false
	static var isSessionUnreadable: Bool { reportLock.lock(); defer { reportLock.unlock() }; return sessionUnreadable }
	static func setSessionUnreadable(_ value: Bool) { reportLock.lock(); sessionUnreadable = value; reportLock.unlock() }

	/// The unreadable latch as the readers see it: the persisted device marker or the in-memory session state.
	static func unreadableLatched(_ device: DeviceState) -> Bool { device.legacyUnreadable || isSessionUnreadable }

	static var isLegacyReportWriteFailed: Bool { reportLock.lock(); defer { reportLock.unlock() }; return reportWriteFailed }
	static func setLegacyReportWriteFailed(_ value: Bool) { reportLock.lock(); reportWriteFailed = value; reportLock.unlock() }

	/// The shell reports the legacy store. Stored in the device state; the SDK ignores it once the account pointer is set.
	@discardableResult
	public static func reportLegacyStore(_ report: LegacyReport) -> LegacyReportResult {
		reportLegacyStore(report, device: productionDevice, store: EncryptedShellRecordStore.production)
	}

	/// The device-level entry of the reader (item 3). A report is device-level: no account and no page copy is read here, because
	/// another account's copy is not visible to this account (item 4, A). The native key is judged where the answer is given (R-1, R-2).
	@discardableResult
	static func reportLegacyStore(_ report: LegacyReport, device: DeviceStateStore, store: ShellRecordStore? = nil, creation: Bool = CreationModeState.isOn) -> LegacyReportResult {
		// PY.15 4, 6, 8 (ruling): every report is saved as the recent report and answers ok when written and read back, whatever the
		// native record and the account pointer say. The admission of a read or a write is decided by the reader and the write guards (W.4, T.3, U.6),
		// not by this report. A report never changes the resolved account state (accountEstablished) and never imports.
		// PY.19: an established account (the pointer is set, its page copy is readable and its EOA matches the keychain) does not latch on an
		// unreadable report. The latch is for a device that has not established its account yet. The value is saved in both cases.
		var establishedNow = false
		var indeterminate = false
		if case .unreadable = report, let store {
			let pointer = BeamioNativeAccountPointer.get()
			if !pointer.isEmpty, pageCopyState(eoa: pointer, store: store) == .readable(eoaMatchesKeychain: true) {
				establishedNow = true
			} else if !pointer.isEmpty, keychainCurrentEoa().isEmpty {
				// The keychain account cannot be named now (locked or not readable): not a verdict on the account. Held in memory, not persisted.
				indeterminate = true
			}
		}
		if case .unreadable = report, indeterminate {
			setSessionUnreadable(true)
		} else {
			setSessionUnreadable(false)
		}
		let written = device.update { state in
			state.legacyReportValue = { switch report { case .absent: return "absent"; case .unreadable: return "unreadable"; case .found: return "found" } }()
			switch report {
			case .absent:
				state.legacyConfirmedAbsent = true
				state.legacyUnreadable = false
				state.legacyFound = false
			case .unreadable:
				state.legacyUnreadable = !establishedNow && !indeterminate
				state.legacyConfirmedAbsent = false
				state.legacyFound = false
			case .found:
				state.legacyFound = true
				state.legacyConfirmedAbsent = false
				state.legacyUnreadable = false
			}
		}
		guard written else {
			setLegacyReportWriteFailed(true)
			return .writeFailed
		}
		setLegacyReportWriteFailed(false)
		return .ok
	}

	/// The category of a directory for a diagnostic: `tmp` (under the temporary directory), `application_support` (under Application Support) or `other`. Never the path itself.
	static func pathCategory(_ path: String) -> String {
		let resolved = URL(fileURLWithPath: path).standardizedFileURL.path
		let tmp = FileManager.default.temporaryDirectory.standardizedFileURL.path
		if resolved.hasPrefix(tmp) || resolved.hasPrefix("/private" + tmp) || resolved.hasPrefix("/tmp/") || resolved.hasPrefix("/private/tmp/") { return "tmp" }
		if resolved.contains("/Application Support/") || resolved.hasSuffix("/Application Support") { return "application_support" }
		return "other"
	}

	/// Whether a file exists, as a state that can fail: true or false when the file system answered, nil when it answered with an error other than "no such file" (a permission
	/// error, an I/O error). `FileManager.fileExists` returns false for both, which would turn an unreadable place into "absent"; this does not.
	static func fileExistence(at path: String) -> Bool? {
		do {
			_ = try FileManager.default.attributesOfItem(atPath: path)
			return true
		} catch let error as NSError {
			let noSuchFile = (error.domain == NSCocoaErrorDomain && (error.code == NSFileNoSuchFileError || error.code == NSFileReadNoSuchFileError))
				|| (error.domain == NSPOSIXErrorDomain && error.code == Int(ENOENT))
				|| ((error.userInfo[NSUnderlyingErrorKey] as? NSError).map { $0.domain == NSPOSIXErrorDomain && $0.code == Int(ENOENT) } ?? false)
			return noSuchFile ? false : nil
		}
	}

	/// The name of the device state file. It sits beside the page copies, so the page-copy enumeration must skip it by this name.
	static let deviceStateFileName = "device-state.json"

	#if BEAMIO_TEST_HOOKS
	/// Test build only: where the device state file is (the isolated directory).
	static var testDeviceStateURLForTests: URL? { deviceStateURL() }
	#endif

	private static func deviceStateURL() -> URL? {
#if BEAMIO_TEST_HOOKS
		// The test build keeps the device state in the isolated test directory, never in Application Support (no host residue).
		return EncryptedShellRecordStore.testIsolatedDirectory.appendingPathComponent(deviceStateFileName)
#else
		guard let base = try? FileManager.default.url(
			for: .applicationSupportDirectory,
			in: .userDomainMask,
			appropriateFor: nil,
			create: true
		) else { return nil }
		return base.appendingPathComponent("beamio-shell-record", isDirectory: true).appendingPathComponent(deviceStateFileName)
#endif
	}

	// MARK: First-run import 

	/// The legacy store as the shell's reader found it. `found` carries the record bytes; the SDK zeroes them after use.
	public enum LegacyWalletRead {
		case absent
		case found(LegacyWalletRecord)
		case unreadable
	}

	/// The record bytes of the legacy store, zeroed by the SDK after the import.
	public final class LegacyWalletRecord {
		private(set) var bytes: [UInt8]

		public init(bytes: [UInt8]) {
			self.bytes = bytes
		}

		public func zeroize() {
			for index in bytes.indices {
				bytes[index] = 0
			}
			bytes = []
		}
	}

	/// The result codes of the first-run import.
	public enum FirstRunImportCode: String {
		case importOk = "import_ok"
		case exists
		case absent
		case legacyUnreadable = "legacy_unreadable"
		case importFailed = "import_failed"
		case addressMismatch = "address_mismatch"
	}

	/// The first-run import of an account with the store, the device state and the address check injected. The legacy record is
	/// stripped of PGP fields before it is written. The address must match the profile whose keyID is the account. A confirmed
	/// absence or an unreadable legacy store, with no account pointer, sets the device state.
	static func importFirstRun(
		eoa rawEoa: String,
		legacy: LegacyWalletRead,
		store: ShellRecordStore,
		device: DeviceStateStore,
		addressOf: (String) -> String?,
		setState: (String, FirstRunState) -> Void,
		nativeStore: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore
	) -> FirstRunImportCode {
		let account = rawEoa.lowercased()
		// A native copy that exists is never replaced by an import (step 1).
		switch store.read(account: account) {
		case .record:
			return .exists
		case .unreadable:
			// An unreadable page copy is record_unreadable on read. It sets no import_not_done, no found and no marker.
			return .importFailed
		case .absent:
			break
		}
		switch legacy {
		case .absent:
			// (low): an absence is not reported while a native key record exists on the device (R-1). Nothing is set or reported.
			if BeamioNativeWallet.hasAnyRecord() { return .exists }
			reportLegacyStore(.absent, device: device)
			return .absent
		case .unreadable:
			// the report sets the device marker only when the account pointer is empty (guarded in reportLegacyStore) and the page copy is
			// empty (checked above: the store read is absent). No per-account value is set.
			reportLegacyStore(.unreadable, device: device)
			return .legacyUnreadable
		case .found(let source):
			defer { source.zeroize() }
			reportLegacyStore(.found, device: device)
			guard var record = (try? JSONSerialization.jsonObject(with: Data(source.bytes))) as? [String: Any] else {
				return .importFailed
			}
			if record.isEmpty {
				// (low): the same guard as the absent case above.
				if BeamioNativeWallet.hasAnyRecord() { return .exists }
				reportLegacyStore(.absent, device: device)
				return .absent
			}
			record = stripPGPFields(record)
			// A PGP private header left on an unstripped path is refused: nothing is imported, the legacy store is kept (IM-10).
			guard !containsPGPHeader(record) else {
				return .importFailed
			}
			guard let profile = (record["profiles"] as? [Any])?.first(where: { profileMatches($0, account) }) as? [String: Any] else {
				return .addressMismatch
			}
			// the legacy key is normalized by the read rule of Q1 before the write checks (a bare 64-hex key gets `0x`, and the hex is
			// lower case). The key itself does not change. A value that cannot be normalized is import_failed; a derivation that does not match
			// the account is address_mismatch. Nothing is written in either case.
			guard let armorRaw = profile["privateKeyArmor"] as? String, let armor = normalizedImportArmor(armorRaw) else {
				return .importFailed
			}
			guard let derived = addressOf(armor) else {
				return .importFailed
			}
			guard derived.lowercased() == account else {
				return .addressMismatch
			}
			// item 3: the EOA key of the copy goes to the native key store, so the native record and walletState agree. A key that cannot
			// be stored fails the import before anything is written (fail closed).
			guard let keyData = BeamioChatLocalCrypto.bytes(fromHex: String(armor.dropFirst(2))) else { return .importFailed }
			var keyBytes = [UInt8](keyData)
			switch BeamioNativeKeyImport.storeDerivedKey(&keyBytes, expectedEoa: account, store: nativeStore) {
			case .imported, .alreadyPresent: break
			default: return .importFailed
			}
			record["profiles"] = ((record["profiles"] as? [Any]) ?? []).map { element -> Any in
				guard profileMatches(element, account), var dict = element as? [String: Any] else { return element }
				dict["privateKeyArmor"] = armor
				return dict
			}
			record["schemaVersion"] = 2
			record[revKey] = 0
			let env = Environment(
				account: { account },
				store: store,
				device: device,
				originAllowed: true,
				migrating: { _ in false },
				firstRun: { _ in .notRun },
				locked: { _ in false },
				walletCopyApproved: walletCopyApproved
			)
			let answer = write(
				["type": "shellRecordWrite", "reqId": "import", "record": record],
				reqId: "import",
				account: account,
				env: env,
				nativeWrite: true,
				guardWrites: false,
				rawByteCount: nil
			)
			guard answer["code"] as? String == "ok" else {
				return .importFailed
			}
			device.update { $0.legacyFound = false }
			return .importOk
		}
	}

	/// The address of an armored EOA key (hex, with or without `0x`), EIP-55 checksummed. The key bytes are zeroed after use.
	static func productionAddress(_ armor: String) -> String? {
		var text = armor.trimmingCharacters(in: .whitespacesAndNewlines)
		if text.hasPrefix("0x") || text.hasPrefix("0X") { text = String(text.dropFirst(2)) }
		guard text.count == 64 else { return nil }
		var key: [UInt8] = []
		key.reserveCapacity(32)
		var index = text.startIndex
		while index < text.endIndex {
			let next = text.index(index, offsetBy: 2)
			guard let byte = UInt8(text[index ..< next], radix: 16) else { return nil }
			key.append(byte)
			index = next
		}
		defer {
			for position in key.indices {
				key[position] = 0
			}
		}
		return BeamioNativeEthSigner.address(privateKey: key)
	}

	// MARK: Entry points

	/// The answer for a command from the shell, or nil when the origin is refused: a refused origin is not processed and gets no reply.
	/// `originAllowed` is the shell's verdict on the sender. `rawByteCount` is the request size as the shell received it.
	public static func handle(_ body: [String: Any], originAllowed: Bool, rawByteCount: Int? = nil) -> [String: Any]? {
		var env = activeEnvironment
		env.originAllowed = originAllowed
		return boundary(body, env: env, rawByteCount: rawByteCount)
	}

	#if DEBUG
	/// Test seam (test builds only, the same form as `BeamioConetChatModule.pgpMigrationEnvironmentOverride`): replaces the production environment of
	/// the record commands, so that a test can run the chat channel against an in-memory store. A Release build has no such variable, and the
	/// shipped code reads `production` only.
	static var environmentOverride: Environment?
	#endif

	/// The environment the entry points read: the test override when one is set (test builds only), otherwise `production`.
	static var activeEnvironment: Environment {
		#if DEBUG
		if let environmentOverride { return environmentOverride }
		#endif
		return production
	}

	/// The native boundary of a record command. The origin is checked here. A refused origin is not processed and nil is returned,
	/// so there is no reply. Otherwise the command is answered once.
	static func boundary(_ body: [String: Any], env: Environment, rawByteCount: Int? = nil) -> [String: Any]? {
		// a refused origin is not processed and gets one `origin_refused` answer. The origin
		// is judged first, then the reqId: a legal reqId is echoed, an illegal one is null.
		guard env.originAllowed else {
			return ["code": "origin_refused", "reqId": BeamioChatRouteRegister.reqIdEcho(body["reqId"]) ?? NSNull()]
		}
		return answer(body, env: env, rawByteCount: rawByteCount)
	}

	/// The production environment: the device account pointer, the encrypted store, the device state, and the native states.
	static var production: Environment {
		// 25.52Y.70 第 4 項 (takeover item 1): the session start establishes the snapshot if it is unknown. A command reads the snapshot only.
		BeamioNativeKeySnapshot.sessionStartIfNeeded()
		let judgement = nativeJudgement()
		return Environment(
			account: { judgement.account },
			store: EncryptedShellRecordStore.production,
			device: productionDevice,
			originAllowed: false,
			migrating: { isMigrating($0) },
			firstRun: { firstRunState($0) },
			// the passcode lock of the judged account comes from the snapshot (25.52Y.70 第 4 項 (b)); another account is judged live.
			locked: { $0 == judgement.account ? judgement.accountLocked : BeamioPasscodeSession.shared.isLocked(eoa: $0) },
			walletCopyApproved: walletCopyApproved,
			gate: { judgement.gate },
			creationTransaction: { CreationTransactionState.isOpen(account: $0) },
			keyState: { judgement.keyState },
			creationMode: { CreationModeState.isOn },
			snapshotKnown: { BeamioNativeKeySnapshot.isKnown },
			storageLocked: { BeamioNativeKeySnapshot.current()?.storageLock != nil }
		)
	}

	/// item 6 and: the account of a shell-record command, and how the native keys decide it. Read from the session snapshot (25.52Y.70 第 4 項),
	/// never from the store. No key list (the enumeration cannot be completed): no account, not_ready. A pointer with its key: that account. A pointer
	/// without its key: that account, with keyState pointerKeyMissing and no fallback. No pointer: exactly one key is the account; several keys are
	/// ambiguous; none is no account.
	struct NativeJudgement {
		let account: String?
		let keyState: KeyState
		let gate: BeamioConetChatModule.NativeGate
		/// The judged account is under a passcode lock (judged at the last event, not per command).
		let accountLocked: Bool
	}
	/// item 1 ((a), `copyKeysOf`): with no native key, a page copy whose profile holds an EOA private key (`privateKeyArmor`) names the
	/// account, which is that profile's keyID. Only the copies are read; a native key never gives way to them. nil when no copy holds a key, or when the
	/// copies cannot be listed (the store has no index), or when two accounts' keys are named.
	/// init may write the account pointer only when the pointer is empty, the native enumeration holds exactly one valid key, and
	/// that key is the init EOA. With the pointer set, no key, or several keys, init does not write it (AD-30, AD-31).
	static func initMayWritePointer(eoa: String) -> Bool {
		guard BeamioNativeAccountPointer.get().isEmpty else { return false }
		let judged = BeamioNativeWalletStateResolver.current()
		return judged.state == .present && judged.account == eoa.lowercased()
	}
	static func accountOfCopyWithKey(store: ShellRecordStore) -> String? {
		guard let records = store.copyRecords() else { return nil }
		var accounts = Set<String>()
		for record in records {
			for element in record["profiles"] as? [Any] ?? [] {
				guard let profile = element as? [String: Any], let keyID = profile["keyID"] as? String, profile["privateKeyArmor"] != nil else { continue }
				accounts.insert(keyID.lowercased())
			}
		}
		return accounts.count == 1 ? accounts.first : nil
	}
	static func nativeJudgement() -> NativeJudgement {
		// 25.52Y.70 第 4 項 (takeover item 1): read the session snapshot. The store is not enumerated for a command.
		// Unknown: no account, not_ready (the record answers not_ready before it reads any judgement, see `answer`).
		guard let entry = BeamioNativeKeySnapshot.current() else {
			return NativeJudgement(account: nil, keyState: .normal, gate: .g1, accountLocked: false)
		}
		return NativeJudgement(account: entry.account, keyState: entry.keyState, gate: BeamioNativeKeySnapshot.gate(of: entry),
		                       accountLocked: entry.accountLocked)
	}

	/// Whether an account's page record holds W-class fields, or cannot be read (a readable absence is false). The unregister uses it for the recovery
	/// check.
	public static func walletFieldsPresent(eoa rawEoa: String) -> Bool {
		switch EncryptedShellRecordStore.production.read(account: rawEoa.lowercased()) {
		case .absent:
			return false
		case .unreadable:
			return true
		case .record(let record):
			return containsWallet(record)
		}
	}

	/// The state of an account's page wallet copy (PY.15 item 15). Returns the state only: never a key, a phrase, record content or a log line.
	/// `readable(eoaMatchesKeychain:)`: the copy has exactly one profile of this account with a key, and that key equals the native key of the account.
	/// Not a bridge command. The input is the lowercase EOA.
	public enum PageCopyState: Equatable {
		case absent
		case unreadable
		case readable(eoaMatchesKeychain: Bool)
	}

	public static func pageCopyState(eoa rawEoa: String) -> PageCopyState {
		pageCopyState(eoa: rawEoa, store: EncryptedShellRecordStore.production)
	}

	static func pageCopyState(eoa rawEoa: String, store: ShellRecordStore) -> PageCopyState {
		let previous = BeamioKeyJudgementDiagnostics.enter(.timeout)
		defer { BeamioKeyJudgementDiagnostics.leave(previous) }
		BeamioKeyJudgementDiagnostics.note(.timeoutJudgements)
		let account = rawEoa.lowercased()
		// PY.17: the input is judged against the keychain's current account too. An empty input fails closed (never absent, never readable).
		if account.isEmpty { return .unreadable }
		switch store.read(account: account) {
		case .absent:
			return .absent
		case .unreadable:
			return .unreadable
		case .record(let record):
			guard integerValue(record[revKey]) != nil else { return .unreadable }
			let owned = (record["profiles"] as? [Any] ?? []).filter { profileMatches($0, account) }
			guard owned.count == 1,
			      let profile = owned[0] as? [String: Any],
			      let armor = profile["privateKeyArmor"] as? String
			else {
				return .readable(eoaMatchesKeychain: false)
			}
			_ = armor
			// PY.17 (超时判定): only public values are compared here. The copy's EOA (keyID) equals the input, and the input equals the
			// keychain state's current account from the record attributes. The key-level check is not part of this judgement (it is made at the
			// session start or the first signing).
			let keychainEoa = keychainCurrentEoa()
			return .readable(eoaMatchesKeychain: !keychainEoa.isEmpty && keychainEoa == account)
		}
	}

	/// The keychain state's current account (PY.17, PV.2 第 2 项): the single valid mnemonic account of the device (Y.163 items 31 and 32: a key record alone is no account).
	/// The accounts are named from the mnemonic items; to tell a valid one the inventory reads each phrase once and wipes it (a mnemonic read, decided 2026-11-21: compliant). No key
	/// record content is read, no key is unwrapped (no Secure Enclave call), and no session is needed.
	/// Empty when there is no valid account, when the records do not name exactly one, or when an item cannot be read (fail closed).
	static func keychainCurrentEoa() -> String {
		// Y.163 第 31、32 項: the owners are the valid mnemonic accounts; a private-key record is not an owner.
		let inventory = BeamioNativeMnemonicInventory.read(store: BeamioNativeWallet.keyStore)
		guard inventory.enumerated, !inventory.readFailed else { return "" }
		let set = Set(inventory.valid.map { $0.eoa })
		return set.count == 1 ? (set.first ?? "") : ""
	}

	/// Removes the W-class fields of an account's page record (unregister). Returns false when the record cannot be changed.
	public static func removeWalletFields(eoa rawEoa: String) -> Bool {
		removeWalletFields(account: rawEoa.lowercased(), store: EncryptedShellRecordStore.production)
	}

	// MARK: Encrypted store

	/// The result of reading one key from the key storage.
	enum KeyRead {
		case found(Data)
		case notFound
		case failed
	}

	/// The key of the encrypted copy: one 256-bit key per account.
	protocol KeyStorage {
		func readKey(account: String) -> KeyRead
		@discardableResult func writeKey(account: String, _ key: Data) -> Bool
		/// True when the key is gone afterwards (deleted, or it was not there). Default: false (a storage that cannot delete never says it did).
		func deleteKey(account: String) -> Bool
	}


	/// The Keychain item of the key (D1, D11): a generic password, `AfterFirstUnlockThisDeviceOnly`, never synchronized, not exported.
	/// No extra wrapping. Items are only ever added, never updated, so an existing key is not replaced.
	final class KeychainKeyStorage: KeyStorage {
		static let service = "com.beamio.beamio.shell-record-key"

		/// The attributes that identify an item. `kSecAttrSynchronizable` is false, so only local items are matched.
		static func itemAttributes(account: String) -> [String: Any] {
			[
				kSecClass as String: kSecClassGenericPassword,
				kSecAttrService as String: service,
				kSecAttrAccount as String: account,
				kSecAttrSynchronizable as String: false,
			]
		}

		/// The attributes of a new item: the key, `AfterFirstUnlockThisDeviceOnly`, never synchronized.
		static func addAttributes(account: String, key: Data) -> [String: Any] {
			var attributes = itemAttributes(account: account)
			attributes[kSecValueData as String] = key
			attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
			return attributes
		}

		func readKey(account: String) -> KeyRead {
			var query = Self.itemAttributes(account: account)
			query[kSecReturnData as String] = true
			query[kSecMatchLimit as String] = kSecMatchLimitOne
			var item: CFTypeRef?
			let status = SecItemCopyMatching(query as CFDictionary, &item)
			if status == errSecSuccess, let data = item as? Data { return .found(data) }
			if status == errSecItemNotFound { return .notFound }
			return .failed
		}

		@discardableResult
		func writeKey(account: String, _ key: Data) -> Bool {
			// Add only: an existing item is never overwritten. A duplicate fails the write.
			SecItemAdd(Self.addAttributes(account: account, key: key) as CFDictionary, nil) == errSecSuccess
		}

		/// Removes the key of one account (the cleanup of an old account, v199 section 219). Gone or never there is true; any other status is false.
		func deleteKey(account: String) -> Bool {
			let status = SecItemDelete(Self.itemAttributes(account: account) as CFDictionary)
			return status == errSecSuccess || status == errSecItemNotFound
		}
	}

	/// The page record of an account as an AES-GCM sealed file. The file is `version byte ‖ nonce ‖ ciphertext ‖ tag`, with complete file
	/// protection, excluded from backup. The authenticated data is the account key (`<eoa>:default`) and the version byte. Nothing is logged.
	/// Without a directory the store fails closed.
	final class EncryptedShellRecordStore: ShellRecordStore {
		private let directory: URL?
		private let keys: KeyStorage

		init(directory: URL?, keys: KeyStorage) {
			self.directory = directory
			self.keys = keys
		}

		#if BEAMIO_TEST_HOOKS
		/// Test only: a page-copy store in a test directory with test key storage, in place of the Application Support copy and the Keychain
		/// keys. The gate tests use it, so no test writes a real copy on the host.
		static var testProductionOverride: EncryptedShellRecordStore?

		/// Test build only: the directory every test without an override uses. A fresh temporary directory of this process, never
		/// Application Support. No test writes the host copy of the shell record (the residue of 2026-11-15 is kept, not removed).
		static let testIsolatedDirectory: URL = {
			let url = FileManager.default.temporaryDirectory.appendingPathComponent(
				"beamio-shell-record-test-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString)",
				isDirectory: true
			)
			try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
			return url
		}()

		/// Test build only: the keys of the isolated store, in memory. Never the Keychain. Like the Keychain item, a key is added, never replaced.
		static let testIsolatedKeys = TestOnlyMemoryKeyStorage()

		/// The in-memory key store of the test build (see `testIsolatedKeys`).
		final class TestOnlyMemoryKeyStorage: KeyStorage {
			private var keys: [String: Data] = [:]

			func readKey(account: String) -> KeyRead {
				guard let key = keys[account] else { return .notFound }
				return .found(key)
			}

			@discardableResult
			func writeKey(account: String, _ key: Data) -> Bool {
				if keys[account] != nil { return false }
				keys[account] = key
				return true
			}

			func deleteKey(account: String) -> Bool {
				keys[account] = nil
				return true
			}
		}
		#endif

		/// The production store. When the Application Support directory is not available there is no fallback to a temporary directory.
		static var production: EncryptedShellRecordStore {
			#if BEAMIO_TEST_HOOKS
			if let testProductionOverride { return testProductionOverride }
			return EncryptedShellRecordStore(directory: testIsolatedDirectory, keys: testIsolatedKeys)
			#endif
			let base = try? FileManager.default.url(
				for: .applicationSupportDirectory,
				in: .userDomainMask,
				appropriateFor: nil,
				create: true
			)
			return EncryptedShellRecordStore(
				directory: base?.appendingPathComponent("beamio-shell-record", isDirectory: true),
				keys: KeychainKeyStorage()
			)
		}

		func read(account: String) -> ShellRecordRead {
			guard let directory else { return .unreadable }
			let url = fileURL(in: directory, account)
			guard FileManager.default.fileExists(atPath: url.path) else { return .absent }
			guard let sealed = try? Data(contentsOf: url),
			      sealed.first == BeamioShellRecord.formatVersion,
			      let key = loadKey(account, create: false),
			      let box = try? AES.GCM.SealedBox(combined: Data(sealed.dropFirst())),
			      let plain = try? AES.GCM.open(box, using: key, authenticating: aad(account)),
			      let object = try? JSONSerialization.jsonObject(with: plain) as? [String: Any]
			else { return .unreadable }
			return .record(object)
		}

		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			guard let directory else { return false }
			guard let plain = BeamioShellRecord.canonicalJSON(record),
			      let key = loadKey(account, create: true),
			      let combined = try? AES.GCM.seal(plain, using: key, authenticating: aad(account)).combined
			else { return false }
			let url = fileURL(in: directory, account)
			let temp = directory.appendingPathComponent(UUID().uuidString + ".tmp")
			do {
				try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
				try EncryptedShellRecordStore.excludeFromBackup(directory)
				try (Data([BeamioShellRecord.formatVersion]) + combined).write(to: temp, options: [.completeFileProtection])
				try EncryptedShellRecordStore.excludeFromBackup(temp)
				if FileManager.default.fileExists(atPath: url.path) {
					_ = try FileManager.default.replaceItemAt(url, withItemAt: temp)
				} else {
					try FileManager.default.moveItem(at: temp, to: url)
				}
				try EncryptedShellRecordStore.excludeFromBackup(url)
				return true
			} catch {
				// A diagnostic of the failure: the error domain and code only (for example the Cocoa 513 of a protected-file write that the system refused), never a path or a content.
				let ns = error as NSError
				NSLog("[BeamioShellRecord] page copy write failed domain=%@ code=%ld place=%@", ns.domain, ns.code, BeamioShellRecord.pathCategory(directory.path))
				// The previous copy stays in place when the new one is not in place (the temporary file is removed).
				try? FileManager.default.removeItem(at: temp)
				return false
			}
		}

		/// Excludes a file or directory from backup (D2).
		private static func excludeFromBackup(_ url: URL) throws {
			var target = url
			var values = URLResourceValues()
			values.isExcludedFromBackup = true
			try target.setResourceValues(values)
		}

		/// Whether a failed read of `account` is deterministic (E9.3.1-2, 2026-11-17): the file exists and its key loads, so the failure is in the record
		/// (format or authentication). A missing key (a locked keychain) is transient.
		func readFailureIsDeterministic(account: String) -> Bool {
			guard let directory else { return false }
			let url = fileURL(in: directory, account)
			// The bytes must be read: a read that itself fails (a file-protection lock, I/O) is transient, never deterministic (review 2026-11-17).
			guard (try? Data(contentsOf: url)) != nil else { return false }
			// The key must load; a missing key while the record exists is transient (E9.1.2-1 (b)).
			return loadKey(account, create: false) != nil
		}

		private func loadKey(_ account: String, create: Bool) -> SymmetricKey? {
			switch keys.readKey(account: account) {
			case .found(let data):
				return data.count == 32 ? SymmetricKey(data: data) : nil
			case .failed:
				return nil
			case .notFound:
				// A key is created only when none exists: a failed read never replaces a key.
				guard create else { return nil }
				let fresh = SymmetricKey(size: .bits256)
				let data = fresh.withUnsafeBytes { Data($0) }
				guard keys.writeKey(account: account, data) else { return nil }
				return fresh
			}
		}

		/// Whether any account's record file is in the directory (item 3). A missing directory holds none. A directory that cannot be listed,
		/// and the absence of a directory, count as a record: the answer is then an error, never absent (fail closed).
		func hasAnyRecord() -> Bool {
			pageCopyEnumeration() != .absent
		}

		/// a missing directory holds no page copy. A directory that cannot be listed, or no directory, is failed (fail closed).
		func pageCopyEnumeration() -> PageCopyEnumeration {
			guard let directory else { return .failed }
			guard FileManager.default.fileExists(atPath: directory.path) else { return .absent }
			guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return .failed }
			// The device state file lives in this directory too (BeamioShellRecord.deviceStateFileName). It is not a page copy, so it is not
			// enumerated: counting it made a fresh install answer account_mismatch (E9.11.29 r2). Only that exact name is excluded.
			let pageNames = names.filter { $0 != BeamioShellRecord.deviceStateFileName }
			// item 11: each entry is judged by its facts. Any unreadable, empty or truncated entry makes the store failed, never absent.
			let files = pageNames.map { BeamioShellRecord.legacyFileFacts(at: directory.appendingPathComponent($0)) }
			switch BeamioShellRecord.judgeLegacyStore(dirExists: true, listOk: true, files: files) {
			case .absent: return .absent
			case .found: return .present
			case .unreadable: return .failed
			}
		}

		/// Whether anything of the page copy of `account` remains: its file, or its key. A file that is gone while its key is still there is still present, so a cleanup
		/// that deleted the file but could not delete the key lists it again at the next run and never reports success. nil when the directory is unknown or the key cannot
		/// be read (fail closed: unknown).
		func pageCopyExists(account: String) -> Bool? {
			guard let directory else { return nil }
			let fileState = BeamioShellRecord.fileExistence(at: fileURL(in: directory, account).path)
			guard let fileExists = fileState else { return nil }
			switch keys.readKey(account: account) {
			case .found: return true
			case .failed: return nil
			case .notFound: return fileExists
			}
		}

		/// Deletes the page copy file of `account` and its key. True only when both are gone afterwards; a failure of either leaves the other as it is
		/// and answers false (the cleanup reports clear_incomplete). The file name is recomputed from the account, so only that account's copy goes.
		func deletePageCopy(account: String) -> Bool {
			guard let directory else { return false }
			let url = fileURL(in: directory, account)
			if BeamioShellRecord.fileExistence(at: url.path) == true { try? FileManager.default.removeItem(at: url) }
			// both are attempted whatever the first answered, and both must be gone: the file by the file system's own answer, the key by its delete
			let fileGone = BeamioShellRecord.fileExistence(at: url.path) == false
			let keyGone = keys.deleteKey(account: account)
			return fileGone && keyGone
		}

		func fileURL(in directory: URL, _ account: String) -> URL {
			let digest = SHA256.hash(data: Data(BeamioShellRecord.accountKey(account).utf8)).map { String(format: "%02x", $0) }.joined()
			return directory.appendingPathComponent(digest + ".bin")
		}

		/// The authenticated data: the account key, then the format version byte.
		func aad(_ account: String) -> Data {
			Data(BeamioShellRecord.accountKey(account).utf8) + Data([BeamioShellRecord.formatVersion])
		}
	}

	/// The account key of the encrypted copy: the lowercase EOA and the workspace.
	static func accountKey(_ account: String) -> String {
		account.lowercased() + ":" + workspace
	}
}

extension BeamioShellRecord.ShellRecordStore {
	func copyRecords() -> [[String: Any]]? { nil }
	/// A store that does not enumerate its records reports none. The production store overrides this and fails closed.
	func hasAnyRecord() -> Bool { false }
	func pageCopyEnumeration() -> BeamioShellRecord.PageCopyEnumeration { hasAnyRecord() ? .present : .absent }
}
#if BEAMIO_TEST_HOOKS
// Test build only: this file's Keychain calls are answered from the test store (BeamioTestKeychainStore), never the real Keychain.
fileprivate func SecItemCopyMatching(_ query: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.copyMatching(query, result)
}
fileprivate func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus {
	BeamioTestKeychainStore.add(attributes, result)
}
fileprivate func SecItemDelete(_ query: CFDictionary) -> OSStatus {
	// the key deletion of the cleanup (KeychainKeyStorage.deleteKey) must not reach the real Keychain in a test build either
	BeamioTestKeychainStore.delete(query)
}
#endif

extension BeamioShellRecord.KeyStorage {
	/// A key storage that does not implement deletion never says that it deleted a key.
	func deleteKey(account: String) -> Bool { false }
}
