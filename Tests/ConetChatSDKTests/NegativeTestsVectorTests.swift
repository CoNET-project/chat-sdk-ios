import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The negative tests of `protocol/negative-tests-v1.json`, run on iOS where the SDK can answer them.
/// Each case is asserted against the vector's own expectation. A case the vector expects and the SDK does not give is a failure here, and it is
/// listed in the receipt; it is not skipped and not re-expected. Cases the spec marks as not applicable are skipped with the
/// reason. The vector expectations that the spec has not yet mapped are printed as pending. Sections the SDK cannot run are not run,
/// and the reason is in the receipt: `bridgeSource` and `shellOrigin` (the shell judges the origin, the SDK receives a verdict); `logScan` T-132
/// (no WebView console capture on the simulator); `logScan` T-131-control (the named patterns are given as labels only, no values in the file).
/// Synthetic data only.
final class NegativeTestsVectorTests: XCTestCase {
	/// The digest of the file as registered in (spec; the nativeOnly refusal is the fixed code pgp_locked).
	static let expectedSHA256 = "86b836ef90586a665acfe1d935e5b3e10236a4cad07e7f93ef252ef4ef82aaef"  // negative-tests-v2.json, the interface spec's current value

	private final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class IdentityHardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private let account = PgpMigrationTestSupport.eoa

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["NEGATIVE_TESTS"] else {
			throw XCTSkip("set NEGATIVE_TESTS to interface/protocol/negative-tests-v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		// The digest is compared without printing it: XCTAssertEqual would print both digests into the log (LS-G1).
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
		              "the negative-tests file differs from the registered digest (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	private func section(_ root: [String: Any], _ name: String) throws -> [String: Any] {
		try XCTUnwrap(root[name] as? [String: Any], name)
	}

	/// Sets a native key for the account with the session ready (G2), and a passcode when `locked` is true with nothing unlocked. Restored by the
	/// returned closure. The chain transport and configuration are not touched here.
	private func arrange(locked: Bool) -> () -> Void {
		let savedStore = BeamioNativeWallet.keyStore
		let savedVault = BeamioPasscodeSession.shared.vault
		NativeAccountPointerIsolation.begin()
		let store = Store()
		store.keys[account] = Data(repeating: 0x11, count: 32)
		BeamioNativeWallet.keyStore = store
		let records = MemoryRecords()
		if locked {
			let passcode = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
			records.data[account] = (try? JSONEncoder().encode(passcode)) ?? Data()
		}
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: records, hardware: IdentityHardware())
		BeamioPasscodeSession.shared.lockAll()
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		return {
			BeamioPasscodeSession.shared.lockAll()
			BeamioPasscodeSession.shared.vault = savedVault
			BeamioNativeWallet.keyStore = savedStore
			BeamioConetChatSignBroker.clearSigner()
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			NativeAccountPointerIsolation.end()
		}
	}

	/// Sends one command and returns the answer with its reqId, after the main queue has drained.
	private func answer(_ body: [String: Any], reqId: Int) -> [String: Any]? {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body) { payload in
			if let event = payload["event"] as? [String: Any] { events.append(event) }
		}
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 2)
		return events.first { $0["reqId"] as? Int == reqId }
	}

	// MARK: - pgpFixedDomain (T-125, T-126, T-126b; T-control-sign)

	func testPgpFixedDomainRefusals() throws {
		let section = try section(try vectorRoot(), "pgpFixedDomain")
		for case_ in try XCTUnwrap(section["cases"] as? [[String: Any]]) {
			let id = case_["id"] as? String ?? "?"
			guard case_["expect"] as? Bool == false else { continue }
			let req = case_["req"] as? [String: Any] ?? [:]
			let sigType = UInt8(String((req["sigType"] as? String ?? "0x00").dropFirst(2)), radix: 16) ?? 0xFF
			let result = BeamioNativeWallet.pgpSign(eoa: account, purposeId: req["purposeId"] as? String ?? "", sigType: sigType, data: Data([1]))
			if case .success = result { XCTFail("\(id): a signature was produced, the vector expects a refusal") }
		}
	}

	/// T-control-sign (vector: expect null, domainTagCheck true; 25.52Y.135). Not skipped. The domain tag bytes are checked and must match, the
	/// vector's domain tag check is true, and the refusal matrix applies to the unregistered purpose: the signature is refused, so no signing
	/// output is produced. Only the signing-output assertion is not made, because the vector expects null there (signing output not applicable).
	func testPgpControlSignDomainTagIsCheckedAndSigningIsNotApplicable() throws {
		let section = try section(try vectorRoot(), "pgpFixedDomain")
		let control = try XCTUnwrap((section["cases"] as? [[String: Any]])?.first { $0["id"] as? String == "T-control-sign" })
		XCTAssertEqual(control["domainTag"] as? String, BeamioPGPPurpose.candidateDomainTags["chatEnvelope"], "the domain tag bytes match the vector")
		XCTAssertEqual(control["domainTagCheck"] as? Bool, true, "the vector's domain tag check is true")
		XCTAssertTrue(control["expect"] == nil || control["expect"] is NSNull, "the vector expects no signing output (null)")
		let req = control["req"] as? [String: Any] ?? [:]
		let sigType = UInt8(String((req["sigType"] as? String ?? "0x00").dropFirst(2)), radix: 16) ?? 0xFF
		let result = BeamioNativeWallet.pgpSign(eoa: account, purposeId: req["purposeId"] as? String ?? "", sigType: sigType, data: Data([1]))
		if case .success = result { XCTFail("T-control-sign: a signature was produced for an unregistered purpose") }
	}

	// MARK: - importPolicy (T-127, T-127b, T-127c, T-127d)

	func testImportPolicy() throws {
		let section = try section(try vectorRoot(), "importPolicy")
		let cases = try XCTUnwrap(section["cases"] as? [[String: Any]])
		let restore = arrange(locked: false)
		defer { restore() }
		for case_ in cases {
			let id = case_["id"] as? String ?? "?"
			let command = case_["command"] as? String ?? ""
			let expect = case_["expect"] as? String ?? ""
			let reqId = 7100 + cases.firstIndex { ($0["id"] as? String) == id }!
			var body: [String: Any] = ["type": command, "reqId": reqId]
			if case_["carriesKey"] as? Bool == true {
				body["payload"] = ["identity": ["eoaAddress": account, "privateKeyHex": "SYNTHETIC-KEY-FIELD"]]
				if command == "provisionIdentity" { body = ["type": command, "reqId": reqId, "eoa": account, "privateKeyHex": "SYNTHETIC-KEY-FIELD"] }
				if command == "walletTransferOnce" { body = ["type": command, "reqId": reqId, "privateKeyHex": "SYNTHETIC-KEY-FIELD"] }
			}
			let event = answer(body, reqId: reqId)
			switch expect {
			case "key_over_bridge_refused":
				XCTAssertEqual(event?["error"] as? String, expect, id)
			case "not_supported":
				// walletTransferOnce is retired (T-141;): not_supported in every state, with no bytes returned.
				XCTAssertEqual(event?["error"] as? String, "not_supported", id)
				XCTAssertEqual(event?["ok"] as? Bool, false, id)
			default:
				XCTFail("\(id): no expectation this runner knows (\(expect))")
			}
		}
	}

	// MARK: - passcodeLocked (T-130-01 to T-130-16)

	/// The bridge families of the vector (`cases`, status `bridge`). The C4 family is native only (`nativeOnly`) and is run below. The
	/// families with status `pending-mapping` (`commands` null) are not run, and they are printed as pending.
	func testPasscodeLockedBridgeFamilies() throws {
		let section = try section(try vectorRoot(), "passcodeLocked")
		let cases = try XCTUnwrap(section["cases"] as? [[String: Any]])
		let restore = arrange(locked: true)
		defer { restore() }
		XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: account), .locked, "the account is locked before the family is sent")
		for case_ in cases {
			let id = case_["id"] as? String ?? "?"
			let family = case_["family"] as? String ?? ""
			let expect = case_["expect"] as? String ?? ""
			let reqId = 9100 + cases.firstIndex { ($0["id"] as? String) == id }!
			guard let name = (case_["commands"] as? [String])?.first else {
				print("VECTOR-PENDING \(id) family \(family): commands is null (;); not run")
				continue
			}
			var body: [String: Any] = ["type": name, "reqId": reqId]
			if let field = case_["credentialField"] as? String { body[field] = "SYNTHETIC-CREDENTIAL" }
			let event = answer(body, reqId: reqId)
			XCTAssertEqual(event?["error"] as? String, expect, "\(id) (\(family) as \(name))")
		}
	}

	/// T-130-04 (native only): the wallet-layer C4 function, called directly, signs nothing while the account is locked.
	func testPasscodeLockedNativeOnlyC4DoesNotSign() throws {
		let section = try section(try vectorRoot(), "passcodeLocked")
		let nativeOnly = try XCTUnwrap(section["nativeOnly"] as? [[String: Any]])
		let restore = arrange(locked: true)
		defer { restore() }
		for case_ in nativeOnly {
			let id = case_["id"] as? String ?? "?"
			let expect = try XCTUnwrap(case_["expect"] as? [String: Any], id)
			XCTAssertEqual(expect["signatureOutput"] as? Bool, false, id)
			let result = BeamioNativeWallet.pgpSign(eoa: account, purposeId: "chatEnvelope", sigType: 0x00, data: Data([1]))
			if case .success = result { XCTFail("\(id): C4 signed while locked") }
			guard case let .failure(failure) = result else { continue }
			// the refusal is the fixed code of the vector, and the locked account is refused first.
			XCTAssertEqual(failure.refusalCode, expect["refusal"] as? String, "\(id): the locked refusal is the fixed code")
			XCTAssertEqual(failure, .locked, "\(id): the locked account is refused first")
		}
	}
}
