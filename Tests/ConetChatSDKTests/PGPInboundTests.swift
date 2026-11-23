import XCTest
@testable import ConetChatSDK

/// `pgpDecryptInbound` (spec): the order of checks and the answers, with the native decrypt injected, so it runs
/// without the X-19 framework. Packets are built by hand (synthetic). The full decrypt with a real key is in
/// PGPInboundVectorTests (needs the framework and the vector file).
final class PGPInboundTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let subkey = "6629DED57B806861"
	private let otherKey = "F0AE129663D80FC9"

	private func keyBytes(_ hex: String) -> [UInt8] {
		stride(from: 0, to: hex.count, by: 2).map { i in
			let s = hex.index(hex.startIndex, offsetBy: i)
			return UInt8(hex[s ..< hex.index(s, offsetBy: 2)], radix: 16) ?? 0
		}
	}

	/// PKESK v3 (new format, tag 1) for `keyID` (16 hex digits; zeros are anonymous).
	private func pkesk(_ keyID: String) -> [UInt8] {
		let body: [UInt8] = [3] + keyBytes(keyID) + [1, 0x00, 0x01, 0x02]
		return [0xC1, UInt8(body.count)] + body
	}

	/// SEIPD (new format, tag 18), version 1, with a dummy body.
	private func seipd() -> [UInt8] {
		let body: [UInt8] = [1] + Array(repeating: 0xAB, count: 8)
		return [0xD2, UInt8(body.count)] + body
	}

	private func armor(_ packets: [[UInt8]]) -> String {
		"-----BEGIN PGP MESSAGE-----\n\n" + Data(packets.flatMap { $0 }).base64EncodedString() + "\n-----END PGP MESSAGE-----\n"
	}

	private func encrypted(to keyID: String) -> String { armor([pkesk(keyID), seipd()]) }

	private func request(_ armored: String, extra: [String: Any] = [:]) -> [String: Any] {
		var body: [String: Any] = [
			"type": "pgpDecryptInbound", "reqId": "t-1", "accountKey": account + ":default", "armoredMessage": armored,
		]
		for (k, v) in extra { body[k] = v }
		return body
	}

	private func context(
		locked: Bool = false, native: Bool = true, decrypt: @escaping (Data) -> Result<Data, BeamioNativeWallet.Failure> = { _ in
			.success(Data("{\"type\":\"voice_call_offer_v1\",\"callId\":\"c-1\",\"sessionId\":\"s-1\",\"proto\":3}".utf8))
		}
	) -> BeamioPGPInbound.Context {
		BeamioPGPInbound.Context(
			unlockedAccountKey: account + ":default", locked: locked, subkeyKeyID: subkey, nativeAvailable: native, decrypt: decrypt
		)
	}

	private func error(_ answer: BeamioPGPInbound.Answer) -> String? {
		if case .error(let code) = answer { return code }
		return nil
	}

	// MARK: - Shape and order

	func testAnOfferForTheAccountIsDecryptedAndClassified() {
		let answer = BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context())
		guard case .ok(let plaintext, let signal, _) = answer else { return XCTFail("expected ok, got \(answer)") }
		XCTAssertTrue(plaintext.contains("voice_call_offer_v1"))
		XCTAssertEqual(signal?["kind"], "offer")
		XCTAssertEqual(signal?["callId"], "c-1")
	}

	func testAPlainChatLineHasANullSignalNotAnError() {
		let answer = BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context(decrypt: { _ in
			.success(Data("{\"sendId\":\"msg-1\",\"from\":\"peer\",\"text\":\"hello\"}".utf8))
		}))
		guard case .ok(_, let signal, _) = answer else { return XCTFail("expected ok") }
		XCTAssertNil(signal)
	}

	func testALockedAccountIsRefusedBeforeTheArmorIsRead() {
		XCTAssertEqual(error(BeamioPGPInbound.run(request("not armor at all"), context: context(locked: true))), "locked")
	}

	func testAnOversizedArmorIsRefusedBeforeItIsParsed() {
		let big = String(repeating: "A", count: BeamioPGPInbound.maxArmorBytes + 1)
		XCTAssertEqual(error(BeamioPGPInbound.run(request(big), context: context())), "payload_too_large")
	}

	func testAForbiddenFieldIsRefusedAndTheArmorIsNotRead() {
		let body = request("not armor", extra: ["privateKeyHex": "11"])
		XCTAssertEqual(error(BeamioPGPInbound.run(body, context: context())), "key_over_bridge_refused")
	}

	func testAnUnknownFieldIsBadRequest() {
		let body = request(encrypted(to: subkey), extra: ["extra": 1])
		XCTAssertEqual(error(BeamioPGPInbound.run(body, context: context())), "bad_request")
	}

	func testAnotherAccountIsAccountMismatch() {
		let body = request(encrypted(to: subkey), extra: ["accountKey": "0x0000000000000000000000000000000000000001:default"])
		XCTAssertEqual(error(BeamioPGPInbound.run(body, context: context())), "account_mismatch")
	}

	func testWithoutTheNativeLibraryTheAnswerIsNotSupported() {
		XCTAssertEqual(error(BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context(native: false))), "not_supported")
	}

	// MARK: - Message shape and recipient

	func testASignatureOnlyMessageIsNotAnOpenPGPMessage() {
		let signedOnly = armor([[0xC2, 2, 0x04, 0x00]])
		XCTAssertEqual(error(BeamioPGPInbound.run(request(signedOnly), context: context())), "not_openpgp_message")
	}

	func testAPrivateKeyBlockIsNotAnOpenPGPMessage() {
		let keyBlock = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nAAAA\n-----END PGP PRIVATE KEY BLOCK-----\n"
		XCTAssertEqual(error(BeamioPGPInbound.run(request(keyBlock), context: context())), "not_openpgp_message")
	}

	func testAnotherRecipientIsRefusedBeforeDecrypt() {
		var decrypted = false
		let answer = BeamioPGPInbound.run(request(encrypted(to: otherKey)), context: context(decrypt: { _ in
			decrypted = true
			return .success(Data())
		}))
		XCTAssertEqual(error(answer), "recipient_mismatch")
		XCTAssertFalse(decrypted, "a recipient mismatch must be refused before the decrypt")
	}

	func testAnonymousRecipientIsRecipientMismatch() {
		let anonymous = armor([pkesk("0000000000000000"), seipd()])
		XCTAssertEqual(error(BeamioPGPInbound.run(request(anonymous), context: context())), "recipient_mismatch")
	}

	// MARK: - Decrypt and plaintext

	func testDecryptFailuresMapToTheirCodes() {
		XCTAssertEqual(error(BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context(decrypt: { _ in
			.failure(.rejected("pgp_decrypt_failed"))
		}))), "decrypt_failed")
		XCTAssertEqual(error(BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context(decrypt: { _ in
			.failure(.rejected("no_pgp_key"))
		}))), "pgp_source_unavailable")
		XCTAssertEqual(error(BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context(decrypt: { _ in
			.failure(.pending("pgp_native_pending"))
		}))), "not_supported")
	}

	func testANonUTF8PlaintextIsRefused() {
		let answer = BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context(decrypt: { _ in
			.success(Data([0xFF, 0xFE, 0x00]))
		}))
		XCTAssertEqual(error(answer), "plaintext_not_utf8")
	}

	func testTheAnswerCarriesOnlyPlaintextAndSignal() {
		let answer = BeamioPGPInbound.run(request(encrypted(to: subkey)), context: context())
		guard case .ok(_, let signal, _) = answer else { return XCTFail("expected ok") }
		let keys = Set(signal?.keys.map { $0 } ?? [])
		XCTAssertTrue(keys.isSubset(of: ["kind", "type", "callId", "sessionId", "rejectReason"]))
	}

	// MARK: - Packet scan

	func testAPartialBodyLengthIsParsed() {
		// Tag 18 with a partial length of 1 octet (0xE0), one data octet, then a final length of 3 and three octets.
		let partial: [UInt8] = [0xD2, 0xE0, 0x41, 0x03, 0x42, 0x43, 0x44]
		guard let packets = BeamioPGPInbound.packets(in: Data(partial)) else { return XCTFail("partial lengths must parse") }
		XCTAssertEqual(packets.count, 1)
		XCTAssertEqual(packets.first?.tag, 18)
		XCTAssertEqual(Array(packets.first?.body ?? Data()), [0x41, 0x42, 0x43, 0x44])
	}

	func testATruncatedPacketIsNotParsed() {
		XCTAssertNil(BeamioPGPInbound.packets(in: Data([0xC1, 0x10, 0x03])))
	}
}

/// The bridge command through the module entry point: string reqIds are echoed on the gate answers.
final class PGPInboundCommandTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		var events: [[String: Any]] = []
		BeamioConetChatModule.handleCommand(body, emit: { event in
			events.append((event["event"] as? [String: Any]) ?? event)
		})
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return events
	}

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	func testWithoutAKeyTheStringReqIdIsEchoedWithNoKey() {
		let events = dispatch(["type": "pgpDecryptInbound", "reqId": "a1-06", "accountKey": account + ":default", "armoredMessage": "x"])
		XCTAssertEqual(events.count, 1)
		XCTAssertEqual(events.first?["reqId"] as? String, "a1-06")
		XCTAssertEqual(events.first?["error"] as? String, "no_key")
		XCTAssertNil(events.first?["result"])
	}

	/// Without a record the gate answers first; an invalid reqId cannot be echoed there, so nothing is answered (as before).
	func testWithoutAKeyAnInvalidReqIdIsBadRequestWithNull() {
		let events = dispatch(["type": "pgpDecryptInbound", "reqId": ["x": 1], "accountKey": account + ":default", "armoredMessage": "x"])
		XCTAssertEqual(events.count, 1, "one answer")
		XCTAssertEqual(events.first?["error"] as? String, "bad_request")
		XCTAssertTrue(events.first?["reqId"] is NSNull, "reqId is null")
	}
}
