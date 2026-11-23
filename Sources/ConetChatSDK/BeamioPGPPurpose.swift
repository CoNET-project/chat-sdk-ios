import Foundation

/// C4 `pgpSign` purpose rules. `registered` is empty: every request is refused.
///
/// Order: the signature type is checked first, then the purpose. Neither check reads a key. The domain tag is
/// added by native code only, and a caller can never supply it. A purpose is registered only by a
/// spec revision that the project approves; nothing here adds one.
public enum BeamioPGPPurpose {
	/// REGISTERED_PURPOSES: the empty set.
	public static let registered: Set<String> = []

	/// Signature types that may be produced at all. Everything else is refused, whatever the purpose.
	public static let allowedSigTypes: Set<UInt8> = [0x00, 0x01]

	/// Reserved candidate domain tags. Not registered: kept so the vector check can reproduce the bytes.
	public static let candidateDomainTags: [String: String] = [
		"chatEnvelope": "beamio.pgp.chatEnvelope.v1\n",
		"groupMessage": "beamio.pgp.groupMessage.v1\n",
		"voiceSignal": "beamio.pgp.voiceSignal.v1\n",
	]

	/// The refusal codes.
	public enum Refusal: String, Equatable {
		case sigTypeNotAllowed = "sig_type_not_allowed"
		case purposeNotRegistered = "purpose_not_registered"
	}

	/// The refusal for a request, or nil when the request may proceed. While `registered` is empty this is never nil.
	public static func refusal(purposeId: String, sigType: UInt8) -> Refusal? {
		guard allowedSigTypes.contains(sigType) else { return .sigTypeNotAllowed }
		guard isWellFormed(purposeId), registered.contains(purposeId) else { return .purposeNotRegistered }
		return nil
	}

	/// ASCII, first byte a letter, then letters or digits, 1 to 32 bytes. A malformed id is
	/// refused with the same code as an unregistered one.
	public static func isWellFormed(_ purposeId: String) -> Bool {
		let bytes = Array(purposeId.utf8)
		guard (1...32).contains(bytes.count), bytes.allSatisfy({ $0 < 0x80 }) else { return false }
		guard let first = bytes.first, isLetter(first) else { return false }
		return bytes.dropFirst().allSatisfy { isLetter($0) || isDigit($0) }
	}

	private static func isLetter(_ b: UInt8) -> Bool {
		(b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
	}

	private static func isDigit(_ b: UInt8) -> Bool {
		b >= 0x30 && b <= 0x39
	}
}
