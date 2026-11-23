import CryptoKit
import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// `chatRouteRegister` checks before the vault and the signature: the gate state, the
/// native lock, the capability, and the request shape. Synthetic values only. The vector rows are run in
/// ChatRouteRegisterVectorTests. The vault and the signing steps are not implemented and are not tested here.
final class ChatRouteRegisterStageTests: XCTestCase {
	/// In-memory native store (the wallet module's store in tests).
	final class Store: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		var writes = 0
		func write(eoa: String, key: Data) -> Bool {
			writes += 1
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
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

	/// Memory records and hardware for a passcode vault, so that the account reads as set (LOCKED when not unlocked).
	private final class MemoryRecords: BeamioPasscodeRecordStoring {
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		var data: [String: Data] = [:]
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class MemoryHardware: BeamioPasscodeHardwareKeyStoring {
		var keys: [String: SymmetricKey] = [:]
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { keys[eoa.lowercased()] != nil }
		func createKey(eoa: String) -> Bool { keys[eoa.lowercased()] = SymmetricKey(size: .bits256); return true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data {
			guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
			return try BeamioPasscodeWrap.seal(plain, key: k, aad: aad)
		}
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data {
			guard let k = keys[eoa.lowercased()] else { throw BeamioPasscodeError.hardwareUnavailable }
			return try BeamioPasscodeWrap.open(blob, key: k, aad: aad)
		}
		func deleteKey(eoa: String) { keys[eoa.lowercased()] = nil }
	}

	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let keyBytes = Data(repeating: 0x11, count: 32)
	private var store: Store!
	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	private let session = BeamioPasscodeSession.shared

	private let declared = [BeamioChatRouteRegister.capability]

	/// A well-formed request (the values are synthetic: 3 bytes of base64 and a fixed keyID and route).
	private var valid: [String: Any] {
		[
			"type": "chatRouteRegister", "reqId": 1,
			"keyID": "6629DED57B806861", "publicKeyArmored": "QUJD", "routeKeyID": "SYN-ROUTE-KEYID-0001",
		]
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = Store()
		BeamioNativeWallet.keyStore = store
		BeamioConetChatSignBroker.clearSigner()
		savedVault = session.vault
		// An empty in-memory vault: no passcode is set, so the account is not LOCKED and the host Keychain is not read.
		session.vault = BeamioPasscodeVault(records: MemoryRecords(), hardware: MemoryHardware())
		session.lockAll()
	}

	override func tearDown() {
		session.lockAll()
		session.vault = savedVault
		NativeAccountPointerIsolation.end()
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		super.tearDown()
	}

	private func stage(_ body: [String: Any], gate: BeamioConetChatModule.NativeGate = .g2,
	                   locked: Bool = false, capabilities: [String]? = nil) -> BeamioChatRouteRegister.Stage {
		BeamioChatRouteRegister.testStage(body: body, gate: gate, locked: locked, capabilities: capabilities ?? declared)
	}

	// MARK: - Order

	func testG0AnswersNoKeyWhateverThePayloadIs() {
		var body = valid
		body["wallet"] = eoa
		XCTAssertEqual(stage(body, gate: .g0), .answer("no_key"))
	}

	func testG1AnswersNotReadyWhateverThePayloadIs() {
		var body = valid
		body["keyID"] = 12
		XCTAssertEqual(stage(body, gate: .g1), .answer("not_ready"))
	}

	func testLockedIsCheckedBeforeTheCapabilityAndTheShape() {
		var body = valid
		body["wallet"] = eoa
		XCTAssertEqual(stage(body, locked: true, capabilities: []), .answer("locked"))
	}

	func testWithoutTheCapabilityAWellFormedRequestAnswersNativeUnavailable() {
		// The expectation follows the build's own declaration: the shipped list declares the route capability only in the QA configuration.
		let shippedDeclares = BeamioConetChatProtocol.capabilities.contains(BeamioChatRouteRegister.capability)
		let shipped = stage(valid, capabilities: BeamioConetChatProtocol.capabilities)
		if shippedDeclares {
			guard case .proceed = shipped else { return XCTFail("declared: the request proceeds to the signing stage") }
		} else {
			XCTAssertEqual(shipped, .answer("native_unavailable"))
		}
		XCTAssertEqual(stage(valid, capabilities: []), .answer("native_unavailable"))
	}

	func testTheShippedCapabilityListDeclaresTheRouteCapabilityOnlyInTheQAConfiguration() {
#if BEAMIO_QA_BUILD
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains(BeamioChatRouteRegister.capability))
#else
		XCTAssertFalse(BeamioConetChatProtocol.capabilities.contains(BeamioChatRouteRegister.capability))
#endif
		XCTAssertEqual(BeamioChatRouteRegister.capability, "identity.route-register.native.v1")
	}

	// MARK: - Request shape

	func testEveryForbiddenFieldIsBadRequestInAnyCase() {
		for field in ["wallet", "message", "signature", "timestamp", "nonce", "encrypKeyArmored", "privateKeyHex", "pgpPrivateKeyArmored"] {
			var body = valid
			body[field] = "synthetic"
			XCTAssertEqual(stage(body), .answer("bad_request"), field)
			var upper = valid
			upper[field.uppercased()] = "synthetic"
			XCTAssertEqual(stage(upper), .answer("bad_request"), "\(field) in capitals")
		}
	}

	func testAMissingRequiredFieldIsBadRequest() {
		for field in ["keyID", "publicKeyArmored", "routeKeyID"] {
			var body = valid
			body.removeValue(forKey: field)
			XCTAssertEqual(stage(body), .answer("bad_request"), field)
		}
	}

	func testANonStringRequiredFieldIsBadRequest() {
		var body = valid
		body["keyID"] = 6_629_880_000_000_000
		XCTAssertEqual(stage(body), .answer("bad_request"))
	}

	func testACarriageReturnOrLineFeedIsBadRequestBeforeTrimming() {
		// NR-10: a trailing CR on the keyID is refused, not trimmed away.
		var keyCR = valid
		keyCR["keyID"] = "6629DED57B806861\r"
		XCTAssertEqual(stage(keyCR), .answer("bad_request"))
		var routeLF = valid
		routeLF["routeKeyID"] = "SYN-ROUTE-KEYID-0001\n"
		XCTAssertEqual(stage(routeLF), .answer("bad_request"))
		var keyCRLF = valid
		keyCRLF["keyID"] = "6629DED57B806861\r\n"
		XCTAssertEqual(stage(keyCRLF), .answer("bad_request"))
		var publicKeyLF = valid
		publicKeyLF["publicKeyArmored"] = "QUJ\nD"
		XCTAssertEqual(stage(publicKeyLF), .answer("bad_request"))
	}

	func testTheKeyIDIsSixteenUpperCaseHex() {
		for keyID in ["6629ded57b806861", "6629DED57B80686", "6629DED57B8068611", "G629DED57B806861", ""] {
			var body = valid
			body["keyID"] = keyID
			XCTAssertEqual(stage(body), .answer("bad_request"), keyID)
		}
	}

	func testAnEmptyRouteKeyIDIsBadRequest() {
		var body = valid
		body["routeKeyID"] = "   "
		XCTAssertEqual(stage(body), .answer("bad_request"))
	}

	func testThePublicKeyMustBeStandardBase64() {
		for text in ["AB!D", "QUJ", "QU=D", "QUJD=", "QUJ=QUJD", "", "   "] {
			var body = valid
			body["publicKeyArmored"] = text
			XCTAssertEqual(stage(body), .answer("bad_request"), text)
		}
		XCTAssertEqual(BeamioChatRouteRegister.isStandardBase64("QUJD"), true)
		XCTAssertEqual(BeamioChatRouteRegister.isStandardBase64("QUI="), true)
	}

	func testSpacesAroundTheFieldsAreTrimmedAndAWellFormedRequestProceeds() {
		var body = valid
		body["keyID"] = "  6629DED57B806861 "
		body["publicKeyArmored"] = " QUJD "
		body["routeKeyID"] = " SYN-ROUTE-KEYID-0001\t"
		XCTAssertEqual(stage(body), .proceed(BeamioChatRouteRegister.Request(
			keyID: "6629DED57B806861", publicKeyArmored: "QUJD", routeKeyID: "SYN-ROUTE-KEYID-0001")))
	}

	// MARK: - The bridge answer (the handler maps.proceed to native_unavailable: the signing stage is not implemented)

	private func send(_ body: [String: Any]) -> [String: Any]? {
		var ack: [String: Any]?
		let done = expectation(description: "ack")
		BeamioConetChatModule.handleCommand(body, emit: { event in
			let inner = (event["event"] as? [String: Any]) ?? event
			if inner["type"] as? String == "ack" {
				ack = inner
				done.fulfill()
			}
		})
		wait(for: [done], timeout: 5)
		return ack
	}

	func testTheBridgeAnswersNoKeyOnAFreshDevice() {
		let ack = send(valid)
		XCTAssertEqual(ack?["ok"] as? Bool, false)
		XCTAssertEqual(ack?["error"] as? String, "no_key")
		XCTAssertNil(ack?["result"])
	}

	func testTheBridgeAnswersNotReadyBeforeInit() {
		store.keys[eoa] = keyBytes
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		XCTAssertEqual(send(valid)?["error"] as? String, "not_ready")
	}

	func testTheBridgeAnswersNativeUnavailableForAWellFormedRequestAfterInit() {
		store.keys[eoa] = keyBytes
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		let ack = send(valid)
		XCTAssertEqual(ack?["ok"] as? Bool, false)
		// Undeclared: native_unavailable. Declared (the QA configuration): the capability passes and the signer check refuses this test's
		// request, since no signer is set here. Either way the request is refused, with no signature and no write.
		let shippedDeclares = BeamioConetChatProtocol.capabilities.contains(BeamioChatRouteRegister.capability)
		XCTAssertEqual(ack?["error"] as? String, shippedDeclares ? "signer_mismatch" : "native_unavailable")
		XCTAssertNil(ack?["result"], "no signature, no data")
		XCTAssertEqual(store.writes, 0, "nothing is written")
	}

	/// order: the capability is checked before the shape. Without the capability a request with a forbidden field answers
	/// native_unavailable; with it (the QA configuration) the shape refuses it. The shape rules are tested with the capability declared,
	/// in testEveryForbiddenFieldIsBadRequestInAnyCase. Nothing is echoed back.
	func testTheBridgeAnswersBeforeTheShapeAccordingToTheDeclaration() {
		store.keys[eoa] = keyBytes
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		var body = valid
		body["privateKeyHex"] = "11"
		let ack = send(body)
		let shippedDeclares = BeamioConetChatProtocol.capabilities.contains(BeamioChatRouteRegister.capability)
		XCTAssertEqual(ack?["error"] as? String, shippedDeclares ? "bad_request" : "native_unavailable")
		XCTAssertNil(ack?["field"], "the field name is not echoed")
		XCTAssertNil(ack?["result"])
	}

	/// the route registration is not answered `locked`; with the passcode bundle not provided it is `not_ready` with the reason `passcode_not_provided`.
	func testTheBridgeAnswersNotReadyWithItsReasonWhenThePasscodeIsSetAndNotProvided() {
		store.keys[eoa] = keyBytes
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		let records = MemoryRecords()
		let hardware = MemoryHardware()
		let vault = BeamioPasscodeVault(records: records, hardware: hardware)
		records.data[eoa.lowercased()] = try! JSONEncoder().encode(BeamioPasscodeRecord(
			mode: "passcode", salt: Data(repeating: 0x22, count: 16), blob: Data([0x00])))
		session.vault = vault
		XCTAssertEqual(session.appState(eoa: eoa), .locked, "the fixture is LOCKED")
		let ack = send(valid)
		XCTAssertEqual(ack?["error"] as? String, "not_ready")
		XCTAssertEqual(ack?["reason"] as? String, "passcode_not_provided")
	}
}
#endif
