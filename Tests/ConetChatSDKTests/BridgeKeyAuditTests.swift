import XCTest
@testable import ConetChatSDK

/// T-103 (payload audit of `identity.provision` and `init`, spec) and T-50 (bridge command parameter audit, spec 2c, as
/// extended by).
///
/// T-50 is a table of command × exact path. The guard scans `Sources/ConetChatSDK` for a subscript read, `forKey:` or `contains(` with one of the
/// twelve T-50 names, records for each hit the file, the enclosing function, the enclosing `for` header and the line text, and compares the hits
/// with the table. A hit that is not in the table fails. Each table row gives its command, its path, and a status:
/// b accepted under: a page-record W path inside shellRecord, with an exact (command, path) pair in `acceptedPairs`;
/// bAE1 accepted by name in (the three lines the ruling lists); the access is inside shellRecord but its path is not an exact
/// pair syntactically (it checks other profiles only to name a conflict or to type-check; it never merges or echoes a value);
/// d stripping: the row only removes a value; it carries nothing, echoes nothing, logs nothing and no copy crosses the bridge;
/// e accepted under: the top-level `privateKeyArmor` of an `ok` result event, at one of the three positions in the
/// result functions listed in `eFunctions` (the intake check, the refusal that names the field, the assembly for delivery);
/// open not accepted yet; the row names the ruling it waits for.
/// The test fails while any row is open. The failure message gives file, line and function of each open hit. Synthetic data only.
final class BridgeKeyAuditTests: XCTestCase {
	private let eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
	/// T-103 names: the 16 CRED names of the spec. Written out here and
	/// not read from the module, so the test checks the module against the spec and runs in every build configuration.
	private let forbidden = [
		"privateKeyHex", "privateKeyArmored", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey", "mnemonic",
		"recoveryCode", "pin", "password", "accountPassword", "encrypKeyArmored", "privateKeyArmor", "privateKeyArmorWrap",
		"mnemonicPhrase", "recoveryWords", "passphrase",
	]
	/// T-50 names.
	static let t50Names = [
		"privateKeyHex", "privateKeyArmored", "privateKeyArmor", "pgpPrivateKeyArmored", "pgpPassphrase", "walletPrivateKey",
		"mnemonic", "recoveryCode", "pin", "password", "accountPassword", "encrypKeyArmored",
	]

	/// The accepted (command, path) pairs for status b (items 1 and 2).
	private let acceptedPairs: Set<String> = [
		"shellRecordRead|profiles[*].privateKeyArmor",
		"shellRecordWrite|profiles[*].privateKeyArmor",
		"shellRecordWrite|mnemonicPhrase",
		"shellRecordRead|mnemonicPhrase",
		"walletCredential|mnemonic",
		"shellRecord first-run import|profiles[*].privateKeyArmor",
		// The project authorization: rows 18 and 20 of BeamioShellRecordQAHook.swift, removeEOAPrivateKey.
		"QA hook (not a bridge command)|profiles[*].privateKeyArmor",
		// 25.52Y.77: the K record is local storage; the check is presence only (decodeK), the armor never leaves the store.
		"K record (local store)|privateKeyArmor presence",
	]

	private struct Row {
		let file: String
		let function: String
		let context: String
		let text: String
		let command: String
		let path: String
		let status: String
		let note: String
		var key: String { file + "|" + function + "|" + context + "|" + text }
	}

	/// The stripping functions accepted as status d.
	private let dFunctions: Set<String> = ["stripPGPFields", "withoutWalletFields", "emitResultEvent", "readCopy"]

	/// The result functions where the top-level `privateKeyArmor` of an `ok` result event may stand, status e (item 2).
	private let eFunctions: Set<String> = ["deliverAccountCreateResult", "finishAccountCreate", "finishRecovery"]

	/// The exact path of status e (item 1): the top-level field of an `ok` result event, and nothing else.
	static let eResultPath = "none: no result carries a wallet field (25.52Y.148, 25.52Y.152)"

	/// The lines lists by name as accepted (status bAE1), by file and function.
	private let ae1Listed: Set<String> = ["BeamioShellRecord.swift|anyProfileHoldsPrivateKey", "BeamioShellRecord.swift|isObjectOrArray", "BeamioShellRecord.swift|carriesForeignKey", "BeamioShellRecord.swift|mergeWallet"]

	/// The table (command × exact path). Keyed by file, enclosing function, enclosing `for` header and trimmed line.
	private let table: [Row] = [
		Row(file: "BeamioChatPgpKeychain.swift", function: "decodeK", context: "", text: "(object[\"privateKeyArmor\"] ?? \"\").contains(\"BEGIN PGP PRIVATE KEY\")", command: "K record (local store)", path: "privateKeyArmor presence", status: "b", note: "25.52Y.77 K item: a presence check that opens the record; no armor is returned"),
		Row(file: "BeamioShellRecord.swift", function: "importedCopyHeld", context: "", text: "return profiles.contains { ($0[\"keyID\"] as? String)?.lowercased() == account.lowercased() && $0[\"privateKeyArmor\"] != nil }", command: "shellRecordRead", path: "profiles[*].privateKeyArmor", status: "b", note: "stored record, keyID = account; G0 gate existence check, no value"),
		Row(file: "BeamioShellRecord.swift", function: "read", context: "", text: "if !owned.contains(where: { ($0 as? [String: Any])?[\"privateKeyArmor\"] != nil }) {", command: "shellRecordRead", path: "profiles[*].privateKeyArmor", status: "b", note: "stored record, keyID = account (ownership of the answer)"),
		Row(file: "BeamioShellRecord.swift", function: "mergeWallet", context: "for element in storedProfiles where !profileMatches(element, owner) {", text: "if let profile = element as? [String: Any], profile[\"privateKeyArmor\"] != nil {", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "and: defensive read of a stored profile whose keyID is not the account; only decides a conflict; never returned, never written"),
		Row(file: "BeamioShellRecord.swift", function: "mergeWallet", context: "for element in storedProfiles where !profileMatches(element, owner) {", text: "let storedKey = storedProfile[\"privateKeyArmor\"] {", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "stored profile matched by keyID; W value used as the merge source"),
		Row(file: "BeamioShellRecord.swift", function: "mergeWallet", context: "for element in storedProfiles where !profileMatches(element, owner) {", text: "if let nextKey = nextProfile[\"privateKeyArmor\"] {", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "request profile matched by keyID; merge check"),
		Row(file: "BeamioShellRecord.swift", function: "mergeWallet", context: "for element in storedProfiles where !profileMatches(element, owner) {", text: "nextProfile[\"privateKeyArmor\"] = storedKey", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "request profile matched by keyID; stored value written when the request omits it"),
		Row(file: "BeamioShellRecord.swift", function: "mergeConflictReason", context: "", text: "return profile[\"privateKeyArmor\"] != nil", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "stored profile matched by keyID; conflict reason"),
		Row(file: "BeamioShellRecord.swift", function: "carriesForeignKey", context: "", text: "guard let profile = element as? [String: Any], profile[\"privateKeyArmor\"] != nil else { return false }", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "and: read-only presence check that decides a conflict; deletes nothing, returns no value"),
		Row(file: "BeamioShellRecord.swift", function: "derivationMismatch", context: "for element in record[\"profiles\"] as? [Any] ?? [] {", text: "guard profileMatches(element, owner), let armor = (element as? [String: Any])?[\"privateKeyArmor\"] as? String else { continue }", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "b", note: "Q1,: the exact pair (shellRecordWrite, profiles[*].privateKeyArmor) with keyID = account; reads the merged value to check that it derives the account; returns only the path, never the value"),
		Row(file: "BeamioShellRecord.swift", function: "accountOfCopyWithKey", context: "for element in record[\"profiles\"] as? [Any] ?? [] {", text: "guard let profile = element as? [String: Any], let keyID = profile[\"keyID\"] as? String, profile[\"privateKeyArmor\"] != nil else { continue }", command: "shellRecordRead", path: "profiles[*].privateKeyArmor", status: "b", note: "item 1 ((a)): presence check of the copy's W path, read only when no native key exists; the keyID names the account; no value leaves"),
		Row(file: "BeamioShellRecord.swift", function: "pageCopyState", context: "", text: "let armor = profile[\"privateKeyArmor\"] as? String", command: "shellRecordRead", path: "profiles[*].privateKeyArmor", status: "b", note: "PY.15 item 15 (r3rz): compare only for the state readable(eoaMatchesKeychain:); the armor never leaves the function, is not logged and not returned"),
		Row(file: "BeamioShellRecord.swift", function: "anyProfileHoldsPrivateKey", context: "", text: "(element as? [String: Any])?[\"privateKeyArmor\"] != nil", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "bAE1", note: "named in; presence check reached only after the conflict and foreign key checks"),
		Row(file: "BeamioShellRecord.swift", function: "stripPGPFields", context: "", text: "profile.removeValue(forKey: \"pgpPrivateKeyArmored\")", command: "shellRecordRead (answer) and shellRecord first-run import", path: "profiles[*].pgpPrivateKeyArmored (removal)", status: "d", note: "1: the spec list names the profile-level PGP private armor; stripped on read, no value leaves"),
		Row(file: "BeamioShellRecord.swift", function: "stripPGPFields", context: "", text: "out.removeValue(forKey: \"pgpPassphrase\")", command: "shellRecordRead (answer) and shellRecord first-run import", path: "pgpPassphrase (removal)", status: "d", note: "stripping: removes the name only; no carry, no echo, no log"),
		Row(file: "BeamioConetChatModule.swift", function: "walletCredentialBlobOutcome", context: "", text: "guard base.ok, var result = base.result, let phrase = result[\"mnemonic\"] as? String else { return base }", command: "walletCredential", path: "mnemonic", status: "b", note: "and PV: the get answer carries the mnemonic to the page; the phrase is read only to seal the blob"),
		Row(file: "BeamioShellRecord.swift", function: "readCopy", context: "", text: "if !profileMatches(profile, owner) { profile.removeValue(forKey: \"privateKeyArmor\") }", command: "shellRecordRead", path: "profiles[*].privateKeyArmor (removal)", status: "d", note: "第 4 項: a read drops the W path of every profile whose keyID is not the account; no value leaves, no log"),
		Row(file: "BeamioShellRecord.swift", function: "withoutWalletFields", context: "", text: "profile.removeValue(forKey: \"privateKeyArmor\")", command: "shellRecordRead and shellRecordWrite (observer copy)", path: "profiles[*].privateKeyArmor (removal)", status: "d", note: "stripping: removes W paths from the observer copy only; the copy goes to the native observer, not the WebView bridge; no log"),
		Row(file: "BeamioShellRecord.swift", function: "isObjectOrArray", context: "for profile in record[\"profiles\"] as? [Any] ?? [] {", text: "if let armor = (profile as? [String: Any])?[\"privateKeyArmor\"], isObjectOrArray(armor) {", command: "shellRecordWrite", path: "profiles[*].privateKeyArmor", status: "bAE1", note: "named in; object or array check inside walletTypeNames, no merge"),
		Row(file: "BeamioShellRecord.swift", function: "importFirstRun", context: "", text: "guard let armorRaw = profile[\"privateKeyArmor\"] as? String, let armor = normalizedImportArmor(armorRaw) else {", command: "shellRecord first-run import", path: "profiles[*].privateKeyArmor", status: "b", note: ": the legacy key is read and normalized in form only (Q1); the key is not changed; no value is returned"),
		Row(file: "BeamioShellRecord.swift", function: "importFirstRun", context: "", text: "dict[\"privateKeyArmor\"] = armor", command: "shellRecord first-run import", path: "profiles[*].privateKeyArmor", status: "b", note: ": the normalized form of the same key is written into the legacy profile before the write checks"),
		Row(file: "BeamioShellRecordQAHook.swift", function: "removeEOAPrivateKey", context: "for index in profiles.indices {", text: "profiles[index][\"privateKeyArmor\"] != nil", command: "QA hook (not a bridge command)", path: "profiles[*].privateKeyArmor", status: "b", note: "b，2026-11-14 在本会话授权；仅在 BEAMIO_SHELL_RECORD_QA 下编译，Release 产物中无该符号（nm）（,, ）"),
		Row(file: "BeamioShellRecordQAHook.swift", function: "removeEOAPrivateKey", context: "for index in profiles.indices {", text: "profiles[index].removeValue(forKey: \"privateKeyArmor\")", command: "QA hook (not a bridge command)", path: "profiles[*].privateKeyArmor", status: "b", note: "b，2026-11-14 在本会话授权；仅在 BEAMIO_SHELL_RECORD_QA 下编译，Release 产物中无该符号（nm）（,, ）"),
		Row(file: "BeamioConetChatModule.swift", function: "emitResultEvent", context: "", text: "observed.removeValue(forKey: \"privateKeyArmor\")", command: "nativeAccountCreateResult / nativeRecoveryResult (observer copy)", path: "observer copy of a result event: privateKeyArmor (removal)", status: "d", note: "position (c) and item 3: removal from the native observer copy, which is stripping; no copy crosses the bridge"),
	]

	private let readPattern = #"(?:\[\s*"(?:privateKeyHex|privateKeyArmored|privateKeyArmor|pgpPrivateKeyArmored|pgpPassphrase|walletPrivateKey|mnemonic|recoveryCode|pin|password|accountPassword|encrypKeyArmored)"\s*\]|forKey:\s*"(?:privateKeyHex|privateKeyArmored|privateKeyArmor|pgpPrivateKeyArmored|pgpPassphrase|walletPrivateKey|mnemonic|recoveryCode|pin|password|accountPassword|encrypKeyArmored)"|\.contains\(\s*"(?:privateKeyHex|privateKeyArmored|privateKeyArmor|pgpPrivateKeyArmored|pgpPassphrase|walletPrivateKey|mnemonic|recoveryCode|pin|password|accountPassword|encrypKeyArmored)"\s*\))"#

	/// T-103: every forbidden name, in every letter case and every placement, is refused before the store is read.
	func testT103EveryForbiddenKeyIsRefusedInEveryPlacementAndCase() {
		var failures: [String] = []
		for name in forbidden {
			let spellings = [name, name.uppercased(), name.prefix(1).uppercased() + name.dropFirst()]
			for spelling in spellings {
				let placements: [(String, [String: Any], BeamioConetChatModule.IdentityRoute)] = [
					("provision top", ["eoa": eoa, spelling: "x"], .provision),
					("init top", ["eoa": eoa, spelling: "x"], .initNested),
					("init identity", ["eoa": eoa, "identity": ["eoa": eoa, spelling: "x"]], .initNested),
					("nested object", ["eoa": eoa, "nodes": [["meta": [spelling: "x"]]]], .provision),
					("array element", ["eoa": eoa, "items": [[spelling: "x"]]], .provision),
				]
				for (place, payload, route) in placements {
					let out = BeamioConetChatModule.identityProvisionOutcome(
						payload: payload, route: route,
						readyFor: { _ in XCTFail("store read for a refused request"); return false }
					)
					if out["error"] as? String != "key_over_bridge_refused" { failures.append("\(place) \(spelling)") }
				}
			}
		}
		XCTAssertEqual(failures, [], "refused placements")
	}

	/// The CRED list is one source: the command check and the payload check hold the 16 names of the spec.
	func testTheCREDNamesAreOneSourceAndMatchTheSpec() {
		XCTAssertEqual(forbidden.count, 16, "the spec has 16 CRED names")
		XCTAssertEqual(Set(forbidden).count, 16, "no name is repeated")
		XCTAssertEqual(BeamioConetChatModule.credentialFieldNames, Set(forbidden), "the command check holds the spec names")
		XCTAssertEqual(Set(BeamioConetChatModule.identityForbiddenKeys), Set(forbidden), "the payload check holds the spec names")
	}

	/// the bare `passphrase` is a CRED name. It is refused in a provision or init payload, at the top, nested and in an
	/// array, with the store not read.
	func testT103PassphraseIsRefusedInEveryPlacement() {
		let placements: [(String, [String: Any], BeamioConetChatModule.IdentityRoute)] = [
			("provision top", ["eoa": eoa, "passphrase": "synthetic"], .provision),
			("init identity", ["eoa": eoa, "identity": ["eoa": eoa, "passphrase": "synthetic"]], .initNested),
			("nested object", ["eoa": eoa, "nodes": [["meta": ["passphrase": "synthetic"]]]], .provision),
			("array element", ["eoa": eoa, "items": [["passphrase": "synthetic"]]], .provision),
		]
		for (place, payload, route) in placements {
			let out = BeamioConetChatModule.identityProvisionOutcome(
				payload: payload, route: route,
				readyFor: { _ in XCTFail("store read for a refused request (\(place))"); return false }
			)
			XCTAssertEqual(out["error"] as? String, "key_over_bridge_refused", place)
		}
	}

	/// at the command layer: `init` with a bare `passphrase` is refused before the gate (step 2), with one answer and no event.
	func testAnInitWithAPassphraseIsRefusedAtTheCommandLayer() {
		var events: [[String: Any]] = []
		// The refusal is answered through the emit closure of the command, as the other command answers are.
		BeamioConetChatModule.handleCommand(["type": "init", "reqId": 4401, "payload": ["identity": ["eoa": eoa, "passphrase": "synthetic"]]]) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		// The answer is posted on the main queue: let it run before the check.
		let deadline = Date().addingTimeInterval(5)
		while events.filter({ $0["reqId"] as? Int == 4401 }).isEmpty && Date() < deadline {
			RunLoop.current.run(until: Date().addingTimeInterval(0.05))
		}
		let answers = events.filter { $0["reqId"] as? Int == 4401 }
		XCTAssertEqual(answers.count, 1, "one answer")
		XCTAssertEqual(answers.first?["error"] as? String, "key_over_bridge_refused")
	}

	/// T-103 control: a payload with public material only is not refused.
	func testT103ValidPublicPayloadIsAccepted() {
		let out = BeamioConetChatModule.identityProvisionOutcome(
			payload: ["eoa": eoa], route: .provision, readyFor: { _ in false }
		)
		XCTAssertNotEqual(out["error"] as? String, "key_over_bridge_refused")
	}

	/// T-50: every hit in the sources is a table row, the counts agree, and every row is accepted (status b).
	func testT50CommandByExactPathTable() throws {
		let root = sourceRoot
		XCTAssertTrue(hasSwiftFiles(root), "no Swift sources readable under \(root.path)")
		let hits = try scan(root: root)
		var listed: [String: [Row]] = [:]
		for row in table { listed[row.key, default: []].append(row) }
		var found: [String: [(Int, String)]] = [:]
		for hit in hits { found[hit.key, default: []].append((hit.line, hit.file)) }

		let unlisted = found.keys.filter { listed[$0] == nil }.sorted().flatMap { key -> [String] in
			found[key]!.map { "\($0.1):\($0.0) \(key)" }
		}
		XCTAssertEqual(unlisted, [], "T-50: hits not in the table (classify each, see)")

		let stale = listed.keys.filter { (found[$0]?.count ?? 0) != listed[$0]!.count }.sorted()
		XCTAssertEqual(stale, [], "T-50: table rows whose count differs from the source")

		let open = table.filter { $0.status == "open" }.map { "\($0.file):\(lines(for: $0, in: hits)) \($0.function) [\($0.command) / \($0.path)] \($0.note)" }
		XCTAssertEqual(open, [], "T-50 open (not accepted yet): rows wait for a ruling or proof")

		for row in table where row.status == "b" {
			XCTAssertTrue(acceptedPairs.contains(row.command + "|" + row.path), "T-50: b row outside the exact pairs: \(row.command) / \(row.path)")
		}
		for row in table where row.status == "d" {
			XCTAssertTrue(dFunctions.contains(row.function), "T-50: d row outside the stripping functions: \(row.function)")
		}
		for row in table where row.status == "e" {
			XCTAssertTrue(eFunctions.contains(row.function) && row.file == "BeamioConetChatModule.swift" && row.path == BridgeKeyAuditTests.eResultPath, "T-50: e row outside the positions: \(row.function)")
		}
		for row in table where row.status == "bAE1" {
			XCTAssertTrue(ae1Listed.contains(row.file + "|" + row.function), "T-50: bAE1 row not named in: \(row.function)")
		}
	}

	private func lines(for row: Row, in hits: [Hit]) -> String {
		hits.filter { $0.key == row.key }.map { String($0.line) }.joined(separator: ",")
	}

	/// The guard itself: planted reads of each form are found, so a silent scan cannot pass.
	func testT50GuardFindsPlantedReads() throws {
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("t50-guard-\(UUID().uuidString)")
		try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(at: dir) }
		let planted = [
			"func planted() {",
			"    let x = body[\"mnemonic\"]",
			"    let y = req.removeValue(forKey: \"recoveryCode\")",
			"    let z = keys.contains(\"pin\")",
			"}",
		]
		try planted.joined(separator: "\n").write(to: dir.appendingPathComponent("Planted.swift"), atomically: true, encoding: .utf8)
		let hits = try scan(root: dir)
		XCTAssertEqual(hits.map { $0.text }, ["let x = body[\"mnemonic\"]", "let y = req.removeValue(forKey: \"recoveryCode\")", "let z = keys.contains(\"pin\")"])
		XCTAssertEqual(Set(hits.map { $0.function }), ["planted"])
	}

	/// The fail-closed rule: a directory with no Swift files is not a clean scan.
	func testT50EmptySourceIsNotACleanScan() throws {
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("t50-empty-\(UUID().uuidString)")
		try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(at: dir) }
		XCTAssertFalse(hasSwiftFiles(dir))
	}

	/// The source tree to scan: T50_SOURCE_ROOT when set (a copy outside protected folders), else the worktree next to this file.
	private var sourceRoot: URL {
		if let p = ProcessInfo.processInfo.environment["T50_SOURCE_ROOT"], !p.isEmpty {
			return URL(fileURLWithPath: p)
		}
		return URL(fileURLWithPath: #filePath)
			.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
			.appendingPathComponent("Sources/ConetChatSDK")
	}

	private func hasSwiftFiles(_ root: URL) -> Bool {
		(FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)?.contains { ($0 as? URL)?.pathExtension == "swift" }) ?? false
	}

	private struct Hit {
		let file: String
		let line: Int
		let function: String
		let context: String
		let text: String
		var key: String { file + "|" + function + "|" + context + "|" + text }
	}

	/// Walks each file in order, tracking the current function and the last `for` header since that function began.
	private func scan(root: URL) throws -> [Hit] {
		let readRegex = try NSRegularExpression(pattern: readPattern, options: [.caseInsensitive])
		let funcRegex = try NSRegularExpression(pattern: #"\bfunc (\w+)"#)
		var out: [Hit] = []
		let files = (FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)?.compactMap { $0 as? URL } ?? [])
			.filter { $0.pathExtension == "swift" }
			.sorted { $0.path < $1.path }
		for file in files {
			// Both sides are resolved: the enumerator returns /private/tmp paths for a /tmp root (a symlink), and an unresolved prefix never matches.
			let rel = file.resolvingSymlinksInPath().path.replacingOccurrences(of: root.resolvingSymlinksInPath().path + "/", with: "")
			var function = ""
			var context = ""
			for (index, raw) in try String(contentsOf: file, encoding: .utf8).components(separatedBy: "\n").enumerated() {
				let trimmed = raw.trimmingCharacters(in: .whitespaces)
				let range = NSRange(trimmed.startIndex..., in: trimmed)
				if let m = funcRegex.firstMatch(in: trimmed, range: range), let r = Range(m.range(at: 1), in: trimmed) {
					function = String(trimmed[r])
					context = ""
				}
				if trimmed.hasPrefix("for ") { context = trimmed }
				if readRegex.firstMatch(in: trimmed, range: range) != nil {
					out.append(Hit(file: rel, line: index + 1, function: function, context: context, text: trimmed))
				}
			}
		}
		return out
	}
}
