import XCTest
@testable import ConetChatSDK

/// shellRecordRead at native G0 (no_key) redacts privateKeyArmor, mnemonicPhrase and recoveryWords from the answer (25.52Y.151 第 6 项).
/// The basis is page-copy-nokey-vectors.v1.json (PNK-06 to PNK-09, pinned 4b0963b3). The page copy is neither deleted nor changed.
final class ShellRecordNoKeyRedactTests: XCTestCase {
	private final class Store: BeamioShellRecord.ShellRecordStore {
		var records: [String: [String: Any]] = [:]
		func read(account: String) -> BeamioShellRecord.ShellRecordRead {
			records[account].map { .record($0) } ?? .absent
		}
		@discardableResult
		func write(account: String, _ record: [String: Any]) -> Bool {
			records[account] = record
			return true
		}
	}

	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState()
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private let account = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let armor = "0x" + String(repeating: "ab", count: 32)
	private let phrase = "synthetic phrase for the redaction test"
	private let words = "synthetic recovery words"
	private var store = Store()

	private func env(_ gate: BeamioConetChatModule.NativeGate) -> BeamioShellRecord.Environment {
		BeamioShellRecord.Environment(
			account: { self.account },
			store: store,
			device: Device(),
			originAllowed: true,
			migrating: { _ in false },
			firstRun: { _ in .confirmedAbsent },
			locked: { _ in false },
			walletCopyApproved: BeamioShellRecord.walletCopyApproved,
			gate: { gate }
		)
	}

	private func read(_ gate: BeamioConetChatModule.NativeGate) -> [String: Any] {
		BeamioShellRecord.answer(["type": "shellRecordRead", "reqId": "pnk-\(gate)"], env: env(gate))
	}

	/// The page copy the vector names: each listed field is placed where the record keeps it.
	private func copy(_ fields: [String], schemaVersion: Int = 2) -> [String: Any] {
		var profile: [String: Any] = ["keyID": account, "chats": [] as [Any]]
		var out: [String: Any] = ["rev": 1, "schemaVersion": schemaVersion, "profiles": [profile]]
		for field in fields {
			switch field {
			case "privateKeyArmor": profile["privateKeyArmor"] = armor
			case "mnemonicPhrase": out["mnemonicPhrase"] = phrase
			case "recoveryWords": out["recoveryWords"] = words
			case "keyID": out["keyID"] = account
			default: out[field] = "default"
			}
		}
		out["profiles"] = [profile]
		return out
	}

	private func profileArmor(_ record: [String: Any]?) -> String? {
		((record?["profiles"] as? [[String: Any]])?.first)?["privateKeyArmor"] as? String
	}

	private func vectorCases() throws -> [String: [String: Any]] {
		let data = try BundledVectorFile.data(resource: "page-copy-nokey-vectors.v1")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		return Dictionary(uniqueKeysWithValues: cases.compactMap { c in (c["id"] as? String).map { ($0, c) } })
	}

	/// PNK-06: at G0 the three W-class fields are redacted; the other fields are returned; the page copy is unchanged.
	func testPNK06G0RedactsTheWalletFieldsAndKeepsTheRest() throws {
		let c = try XCTUnwrap(vectorCases()["PNK-06"])
		let input = try XCTUnwrap(c["input"] as? [String: Any])
		let fields = try XCTUnwrap(input["copyFields"] as? [String])
		store.records[account] = copy(fields)
		let answer = read(.g0)
		XCTAssertEqual(answer["code"] as? String, "ok")
		let returned = answer["record"] as? [String: Any] ?? [:]
		XCTAssertEqual(returned["keyID"] as? String, account)
		XCTAssertEqual(returned["workspace"] as? String, "default")
		XCTAssertNil(returned["mnemonicPhrase"], "mnemonicPhrase is redacted at G0")
		XCTAssertNil(returned["recoveryWords"], "recoveryWords is redacted at G0")
		XCTAssertNil(profileArmor(returned), "privateKeyArmor is redacted at G0")
		// the page copy is neither deleted nor changed by the answer
		XCTAssertEqual(store.records[account]?["mnemonicPhrase"] as? String, phrase)
		XCTAssertEqual(store.records[account]?["recoveryWords"] as? String, words)
		XCTAssertEqual(profileArmor(store.records[account]), armor)
	}

	/// PNK-08: at G2 (the key is held) the W-class fields are not redacted (Y.41 第 4 項).
	func testPNK08G2ReturnsTheWalletFieldsUnchanged() throws {
		let c = try XCTUnwrap(vectorCases()["PNK-08"])
		let input = try XCTUnwrap(c["input"] as? [String: Any])
		let fields = try XCTUnwrap(input["copyFields"] as? [String])
		store.records[account] = copy(fields)
		let answer = read(.g2)
		XCTAssertEqual(answer["code"] as? String, "ok")
		let returned = answer["record"] as? [String: Any] ?? [:]
		XCTAssertEqual(returned["mnemonicPhrase"] as? String, phrase)
		XCTAssertEqual(returned["keyID"] as? String, account)
		XCTAssertEqual(profileArmor(returned), armor)
	}

	/// PNK-09 (25.52Y.154): at G1 (a native key, no session) the read is not_ready and answers no field, the wallet fields included.
	func testPNK09G1AnswersNotReadyWithNoField() throws {
		let c = try XCTUnwrap(vectorCases()["PNK-09"])
		let expect = try XCTUnwrap(c["expect"] as? [String: Any])
		XCTAssertEqual(expect["code"] as? String, "not_ready")
		store.records[account] = copy(["privateKeyArmor"])
		let answer = read(.g1)
		XCTAssertEqual(answer["code"] as? String, "not_ready")
		XCTAssertNil(answer["record"], "no record is answered at G1")
		XCTAssertFalse(String(describing: answer).contains(armor), "the armor does not appear in the answer")
	}

	/// PNK-07 (25.52Y.156): a schema-2 page copy without the key, read at G0, is `error` with sub `needs_native_recovery` and no field.
	func testPNK07G0Schema2CopyWithoutKeyNeedsNativeRecovery() throws {
		let c = try XCTUnwrap(vectorCases()["PNK-07"])
		let expect = try XCTUnwrap(c["expect"] as? [String: Any])
		store.records[account] = copy(["keyID", "workspace"], schemaVersion: 2)
		let answer = read(.g0)
		XCTAssertEqual(answer["code"] as? String, expect["code"] as? String)
		XCTAssertEqual(answer["sub"] as? String, expect["sub"] as? String)
		XCTAssertNil(answer["record"], "no field is returned")
		XCTAssertEqual(store.records[account]?["schemaVersion"] as? Int, 2, "the page copy is not changed")
	}

	/// PNK-10 (25.52Y.156): a non-schema-2 copy with only non-wallet fields, read at G0, is ok and returns those fields.
	func testPNK10G0Schema1CopyIsReadAsUsual() throws {
		let c = try XCTUnwrap(vectorCases()["PNK-10"])
		let expect = try XCTUnwrap(c["expect"] as? [String: Any])
		store.records[account] = copy(["keyID", "workspace"], schemaVersion: 1)
		let answer = read(.g0)
		XCTAssertEqual(answer["code"] as? String, expect["code"] as? String)
		let returned = answer["record"] as? [String: Any] ?? [:]
		for field in (expect["fieldsReturned"] as? [String]) ?? [] {
			XCTAssertNotNil(returned[field], "\(field) is returned")
		}
	}
}
