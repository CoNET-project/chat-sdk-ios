import CryptoKit
import XCTest
@testable import ConetChatSDK

/// mnemonic-derivation-vectors.v1.json: the 14 derivation cases (MD-1 to MD-14)
/// and the 8 recovery-phrase import cases (MI-1 to MI-8). Public BIP-39 test phrases only. Runs with
/// MNEMONIC_DERIVATION_VECTORS=<path to the file>; skipped without it. The expectations are the vector file's, never
/// adjusted to the code. Phrases and keys are not printed by these tests.
final class MnemonicDerivationVectorTests: XCTestCase {
	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
	}

	static let expectedSHA256 = "3ddfa20649b283e8dc40cd054097b19e7648ca28ad82dd94ef4d24fb91136a0d"  // the registry value

	/// In-memory native store with the failure injections of the import vectors (writeFail, readbackFail).
	final class Store: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var failWrite = false
		var corruptReadBack = false
		func write(eoa: String, key: Data) -> Bool {
			if failWrite { return false }
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? {
			guard let k = keys[eoa.lowercased()] else { return nil }
			return corruptReadBack ? Data(repeating: 0xEE, count: k.count) : k
		}
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["MNEMONIC_DERIVATION_VECTORS"] else {
			throw XCTSkip("set MNEMONIC_DERIVATION_VECTORS to interface/protocol/mnemonic-derivation-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256, "vector file sha256 differs from the published value (the digest is not printed, so a failure leaves no digest in the log)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// The account of a derived key (lower case), or nil for an invalid phrase.
	private func account(of phrase: String) -> (eoa: String, key: [UInt8])? {
		guard case .key(let key) = BeamioMnemonicDerivation.derive(phrase: phrase),
		      let address = BeamioNativeEthSigner.address(privateKey: key)
		else { return nil }
		return (address.lowercased(), key)
	}

	func testDerivationCasesMatchTheVectors() throws {
		let cases = try vectorUnwrap { try vectorRoot()["derivation"] as? [[String: Any]] }
		XCTAssertEqual(cases.count, 14, "MD-1 to MD-14")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? String ?? ""
			let expect = c["expect"] as? [String: Any] ?? [:]
			let result = BeamioMnemonicDerivation.derive(phrase: input)
			if expect["code"] as? String == "ok" {
				guard case .key(let key) = result else {
					XCTFail("\(id): expected a key")
					continue
				}
				XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), expect["eoa"] as? String, id)
			} else {
				// MD-13 carries a private key in hex: it must give no key at all (the negative control,).
				guard case .invalidMnemonic = result else {
					XCTFail("\(id): expected invalid_mnemonic with no key")
					continue
				}
				XCTAssertEqual(expect["code"] as? String, "invalid_mnemonic", id)
			}
		}
	}

	func testImportCasesMatchTheVectors() throws {
		let cases = try vectorUnwrap { try vectorRoot()["importMnemonicMode"] as? [[String: Any]] }
		XCTAssertEqual(cases.count, 8, "MI-1 to MI-8")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? String ?? ""
			let ctx = c["ctx"] as? [String: Any] ?? [:]
			let expect = c["expect"] as? [String: Any] ?? [:]
			let code = expect["code"] as? String ?? ""
			let derived = account(of: input)

			let store = Store()
			store.failWrite = ctx["writeFail"] as? Bool ?? false
			store.corruptReadBack = ctx["readbackFail"] as? Bool ?? false
			let existing = Data(repeating: 0x22, count: 32)
			if ctx["nativeRecord"] as? Bool == true, let eoa = derived?.eoa { store.keys[eoa] = existing }

			let outcome: BeamioNativeKeyImport.Outcome = (ctx["cancelled"] as? Bool == true)
				? .cancelled
				: BeamioNativeKeyImport.importRecoveryPhrase(text: input, expectedEoa: ctx["expectedEoa"] as? String ?? "", store: store)
			XCTAssertEqual(outcome.code, code, id)

			if code == "ok", let derived {
				XCTAssertEqual(expect["eoa"] as? String, derived.eoa, id)
				XCTAssertEqual(store.keys[derived.eoa], Data(derived.key), "\(id): the derived key is written and read back")
				XCTAssertEqual(BeamioPasscodeSession.shared.appState(eoa: derived.eoa), .noPasscode, "\(id): NO_PASSCODE")
			}
			if let after = expect["nativeRecordAfter"] as? String {
				if let eoa = derived?.eoa {
					XCTAssertEqual(store.keys[eoa] != nil, after == "present", "\(id): the native record after the import")
					if ctx["nativeRecord"] as? Bool == true {
						XCTAssertEqual(store.keys[eoa], existing, "\(id): an existing record is not overwritten")
					}
				} else {
					XCTAssertTrue(store.keys.isEmpty, "\(id): an invalid phrase writes nothing")
				}
			}
			// The phrase is never stored: only 32-byte derived keys may be in the store (mnemonicPersisted: false).
			XCTAssertTrue(store.keys.values.allSatisfy { $0.count == 32 }, "\(id): nothing but a derived key is stored")
		}
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

}
