#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The call-control gate (2026): a signal reaches the shell only when the outer signer, the envelope
/// `from` and the inner `from` are the same address. Synthetic addresses; the one-time PWA vector is read from the environment and is not in the repository.
final class CallControlGateTests: XCTestCase {
	private let peer = "0x00000000000000000000000000000000000000aa"
	private let other = "0x00000000000000000000000000000000000000bb"

	private func envelope(type: String = "voice_end_v1", inner: [String: Any]? = nil, outerFrom: String? = nil, signMessage: String? = "0x00") -> String {
		var signal: [String: Any] = inner ?? ["type": type, "callId": "call-gate-01", "sessionId": "sess-gate-01", "from": peer]
		if inner == nil { signal["type"] = type }
		let text = String(data: try! JSONSerialization.data(withJSONObject: signal, options: [.sortedKeys]), encoding: .utf8)!
		var outer: [String: Any] = ["timestamp": 1, "text": text]
		if let outerFrom { outer["from"] = outerFrom }
		if let signMessage { outer["signMessage"] = signMessage }
		return String(data: try! JSONSerialization.data(withJSONObject: outer, options: [.sortedKeys]), encoding: .utf8)!
	}

	private typealias Verdict = BeamioConetChatCallControl.Verdict

	func testAnEnvelopeWhoseThreeAddressesAgreeIsDeliveredWithTheVerifiedFrom() {
		let line = envelope(outerFrom: peer.uppercased().replacingOccurrences(of: "0X", with: "0x"))
		XCTAssertEqual(BeamioConetChatCallControl.admit(plaintext: line, signer: peer),
		               .deliver(type: "voice_end_v1", callId: "call-gate-01", sessionId: "sess-gate-01", from: peer))
		// the timeout signal too
		XCTAssertEqual(BeamioConetChatCallControl.admit(plaintext: envelope(type: "voice_call_timeout_v1", outerFrom: peer), signer: peer),
		               .deliver(type: "voice_call_timeout_v1", callId: "call-gate-01", sessionId: "sess-gate-01", from: peer))
	}

	func testEveryOtherShapeIsDropped() {
		let gate = BeamioConetChatCallControl.admit
		// a bare signal (history, cache): not an envelope
		XCTAssertEqual(gate(#"{"type":"voice_end_v1","callId":"call-gate-01","sessionId":"sess-gate-01","from":"\#(peer)"}"#, peer), .drop("not_envelope"))
		XCTAssertEqual(gate(envelope(outerFrom: peer, signMessage: nil), peer), .drop("not_envelope"))
		XCTAssertEqual(gate("not json", peer), .drop("not_envelope"))
		// no envelope from, or one that is not an address
		XCTAssertEqual(gate(envelope(outerFrom: nil), peer), .drop("no_envelope_from"))
		XCTAssertEqual(gate(envelope(outerFrom: "0x12"), peer), .drop("no_envelope_from"))
		// unverified, or another signer
		XCTAssertEqual(gate(envelope(outerFrom: peer), nil), .drop("unverified"))
		XCTAssertEqual(gate(envelope(outerFrom: peer), ""), .drop("unverified"))
		XCTAssertEqual(gate(envelope(outerFrom: peer), other), .drop("signer_mismatch"))
		XCTAssertEqual(gate(envelope(outerFrom: other), peer), .drop("signer_mismatch"), "a claimed from that is not the signer")
		// inner from missing, empty, or another address
		XCTAssertEqual(gate(envelope(inner: ["type": "voice_end_v1", "callId": "call-gate-01", "sessionId": "sess-gate-01"], outerFrom: peer), peer), .drop("no_inner_from"))
		XCTAssertEqual(gate(envelope(inner: ["type": "voice_end_v1", "callId": "call-gate-01", "sessionId": "sess-gate-01", "from": ""], outerFrom: peer), peer), .drop("no_inner_from"))
		XCTAssertEqual(gate(envelope(inner: ["type": "voice_end_v1", "callId": "call-gate-01", "sessionId": "sess-gate-01", "from": other], outerFrom: peer), peer), .drop("inner_from_mismatch"))
		// not a control kind: an offer, a chat line, an empty call
		XCTAssertEqual(gate(envelope(type: "voice_call_offer_v1", outerFrom: peer), peer), .drop("not_control"))
		XCTAssertEqual(gate(envelope(inner: ["hello": "world", "from": peer], outerFrom: peer), peer), .drop("not_control"))
		XCTAssertEqual(gate(envelope(inner: ["type": "voice_end_v1", "from": peer], outerFrom: peer), peer), .drop("not_control"), "no callId and no sessionId")
	}

	// MARK: - the one-time PWA vector (environment only)

	func testThePwaVectorOfTheVoiceEndEnvelope() throws {
		guard let path = ProcessInfo.processInfo.environment["BEAMIO_VOICE_END_VECTOR"], !path.isEmpty else {
			throw XCTSkip("BEAMIO_VOICE_END_VECTOR is not set: the one-time PWA vector is not in the repository")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(digest, "5d5ee2454527e311c827388f4eb39a6fca70b3f95af7e7ffe06773494fdae919", "the vector is the one that was announced")
		let v = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
		let text = try XCTUnwrap(v["envelopeText"] as? String)
		let sig = try XCTUnwrap(v["signMessage"] as? String)
		let full = try XCTUnwrap(v["fullEnvelopeJson"] as? String)
		let expectedSigner = try XCTUnwrap(v["expectedOuterSigner"] as? String).lowercased()
		let textDigest = SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(textDigest, v["envelopeTextUtf8Sha256"] as? String)
		// the signature really recovers to the announced signer (native EIP-191 recovery)
		let recovered = try XCTUnwrap(BeamioNativeEthSigner.recoverEip191AddressForTests(message: text, signature: sig))
		XCTAssertEqual(recovered, expectedSigner)
		// accept_full_envelope
		XCTAssertEqual(BeamioConetChatCallControl.admit(plaintext: full, signer: recovered),
		               .deliver(type: "voice_end_v1", callId: "vt-end-call-0001", sessionId: "vt-end-session-0001", from: expectedSigner))
		// bare_text_refused: the signed text alone is not an envelope
		XCTAssertEqual(BeamioConetChatCallControl.admit(plaintext: text, signer: recovered), .drop("not_envelope"))
		// outer_signature_by_other_key_refused: the signature recovers to another address
		XCTAssertEqual(BeamioConetChatCallControl.admit(plaintext: full, signer: other), .drop("signer_mismatch"))
		// inner_from_missing_refused: the same envelope with the inner from taken out
		var outer = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(full.utf8)) as? [String: Any])
		var inner = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
		inner.removeValue(forKey: "from")
		outer["text"] = String(data: try JSONSerialization.data(withJSONObject: inner), encoding: .utf8)
		let stripped = String(data: try JSONSerialization.data(withJSONObject: outer), encoding: .utf8)!
		XCTAssertEqual(BeamioConetChatCallControl.admit(plaintext: stripped, signer: recovered), .drop("no_inner_from"))
	}
}
#endif
