import CryptoKit
import Foundation

/// `chatRouteRegister`: the native half of `regiestChatRoute` inside the native shell.
///
/// This file holds the checks that run before the vault and the signature: the gate state, the native lock, the
/// capability, and the request shape (steps 1 to 4). The vault and the signing steps are not here. They wait for
/// the interface rulings: the ack shape, the reqId type, and the format of the EOA private key string. Until then a
/// request that passes the shape check answers `native_unavailable`, which allows for "命令未实现". The page never
/// falls back to a page signature.
///
/// The capability `identity.route-register.native.v1` is not declared. It is declared only after the three ends implement
/// the command and pass `chat-route-register-vectors.v1.json`.
enum BeamioChatRouteRegister {
	/// The capability that marks a shell able to answer `chatRouteRegister`.
	static let capability = "identity.route-register.native.v1"

	/// Fields a request may not carry. A key is compared case-insensitively. The value is never read back.
	static let forbiddenFields: Set<String> = [
		"wallet", "message", "signature", "timestamp", "nonce", "encrypKeyArmored", "privateKeyHex", "pgpPrivateKeyArmored",
	]
	private static let forbiddenLowercased = Set(forbiddenFields.map { $0.lowercased() })

	/// What the checks before the signature decide.
	enum Stage: Equatable {
		/// A refusal, by its code. Nothing else is answered and no data is returned.
		case answer(String)
		/// The request is well formed and the shell has the capability. The signing stage is not implemented yet.
		case proceed(Request)
	}

	/// The checked request. `keyID` and `routeKeyID` are trimmed. `publicKeyArmored` is the base64 text, trimmed.
	struct Request: Equatable {
		let keyID: String
		let publicKeyArmored: String
		let routeKeyID: String
	}

	/// The shipped hello list is `BeamioConetChatProtocol.capabilities`: the production answer.
	static func stage(body: [String: Any], gate: BeamioConetChatModule.NativeGate, locked: Bool, storageUnreadable: Bool = false) -> Stage {
		stage(body: body, gate: gate, locked: locked, storageUnreadable: storageUnreadable, capabilities: BeamioConetChatProtocol.capabilities)
	}

#if BEAMIO_TEST_HOOKS
	/// Test hook only: the stage with a given hello list. Not compiled into a release or store build.
	static func testStage(body: [String: Any], gate: BeamioConetChatModule.NativeGate, locked: Bool, storageUnreadable: Bool = false,
	                      capabilities: [String]) -> Stage {
		stage(body: body, gate: gate, locked: locked, storageUnreadable: storageUnreadable, capabilities: capabilities)
	}
#endif

	/// The order of: the gate state (the payload is not read), then the native lock, then the capability, then the
	/// payload shape. `locked` is the native lock of the record account. `capabilities` is the shell's `hello` list.
	private static func stage(
		body: [String: Any],
		gate: BeamioConetChatModule.NativeGate,
		locked: Bool,
		storageUnreadable: Bool = false,
		capabilities: [String]
	) -> Stage {
		switch gate {
		case .g0:
			return .answer("no_key")
		case .g1:
			return .answer("not_ready")
		case .g2:
			break
		}
		// Test seam only: no production call passes `locked: true` (the SDK keeps no application-level lock). The branch is not compiled
		// into a release or store build; it stays only so that the pinned route-register vectors can still be run.
		#if BEAMIO_TEST_HOOKS
		if locked { return .answer("locked") }
		#endif
		// the key record exists and cannot be read: not_ready, before the parameters.
		if storageUnreadable { return .answer("not_ready") }
		guard capabilities.contains(capability) else { return .answer("native_unavailable") }
		return shape(body)
	}

	/// The request shape: no forbidden field, the three required string fields, no CR or LF in any of
	/// them (checked before trimming), the keyID form, a non-empty routeKeyID, and standard base64 for the public key.
	static func shape(_ body: [String: Any]) -> Stage {
		if body.keys.contains(where: { forbiddenLowercased.contains($0.lowercased()) }) {
			return .answer("bad_request")
		}
		guard let rawKeyID = body["keyID"] as? String,
		      let rawPublicKey = body["publicKeyArmored"] as? String,
		      let rawRouteKeyID = body["routeKeyID"] as? String else {
			return .answer("bad_request")
		}
		// Checked before trimming: a trailing CR is a refusal, not a space to trim away (NR-10).
		for raw in [rawKeyID, rawPublicKey, rawRouteKeyID] where hasLineBreak(raw) {
			return .answer("bad_request")
		}
		let keyID = rawKeyID.trimmingCharacters(in: .whitespacesAndNewlines)
		let publicKey = rawPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)
		let routeKeyID = rawRouteKeyID.trimmingCharacters(in: .whitespacesAndNewlines)
		guard isUpperHex16(keyID), !routeKeyID.isEmpty, isStandardBase64(publicKey) else {
			return .answer("bad_request")
		}
		return .proceed(Request(keyID: keyID, publicKeyArmored: publicKey, routeKeyID: routeKeyID))
	}

	/// True when the text holds a CR or a LF. Checked per Unicode scalar, because "\r\n" is one Character.
	static func hasLineBreak(_ text: String) -> Bool {
		text.unicodeScalars.contains { $0 == "\r" || $0 == "\n" }
	}

	/// Sixteen characters, each `0`–`9` or `A`–`F` (the PGP keyID form).
	static func isUpperHex16(_ text: String) -> Bool {
		let scalars = Array(text.unicodeScalars)
		guard scalars.count == 16 else { return false }
		return scalars.allSatisfy { ("0"..."9").contains($0) || ("A"..."F").contains($0) }
	}

	/// Standard base64 with padding (RFC 4648 alphabet, `=` only at the end, length a multiple of four).
	static func isStandardBase64(_ text: String) -> Bool {
		let scalars = Array(text.unicodeScalars)
		guard !scalars.isEmpty, scalars.count % 4 == 0 else { return false }
		let padding = scalars.reversed().prefix { $0 == "=" }.count
		guard padding <= 2 else { return false }
		let body = scalars.dropLast(padding)
		let alphabet: Set<Unicode.Scalar> = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".unicodeScalars)
		guard body.allSatisfy({ alphabet.contains($0) }) else { return false }
		return Data(base64Encoded: text) != nil
	}

	// MARK: - reqId, password, ack envelope ((3)(4)(5); decision vectors A, B, C)

	/// reqId: a string of 1 to 64 bytes in 0x20–0x7E (not trimmed), or an integer 0 to 2^53−1. Any other
	/// value is refused with `bad_request` and reqId null. Returns the value to echo, or nil.
	static func reqIdEcho(_ raw: Any?) -> Any? {
		if let text = raw as? String {
			let bytes = Array(text.utf8)
			guard (1...64).contains(bytes.count), bytes.allSatisfy({ (0x20...0x7E).contains($0) }) else { return nil }
			return text
		}
		return bridgeInteger(raw)
	}

	/// The one numeric rule of a bridge field that is a non-negative integer (reqId, inboundGeneration, and any other): an NSNumber that is not a
	/// boolean, whose double value is finite, has no fractional part and lies in 0 to 2^53-1. The Objective-C type does not decide: a JS number
	/// crosses WKScriptMessage as a double ("d") and is accepted when it is a whole number. A string, a decimal, a negative, NaN, infinity,
	/// a boolean or a value out of range is nil.
	static func bridgeInteger(_ raw: Any?) -> Int? {
		guard let number = raw as? NSNumber else { return nil }
		if CFGetTypeID(number as CFTypeRef) == CFBooleanGetTypeID() { return nil }
		let value = number.doubleValue
		guard value.isFinite, value == value.rounded(.towardZero), value >= 0, value <= 9_007_199_254_740_991 else { return nil }
		return Int(value)
	}

	/// The EOA private key string used as the backup password: "0x" + 64 lowercase hex, nothing else.
	static func passwordString(privateKey: [UInt8]) -> String {
		"0x" + hexLower(privateKey)
	}

	/// Random bytes for the backup IV and the nonce. Uses the system generator.
	static func randomBytes(_ count: Int) -> [UInt8] {
		var bytes = [UInt8](repeating: 0, count: count)
		_ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
		return bytes
	}

	/// The canonical password form (decision vector C-1): ASCII "0x" followed by 64 lowercase hex characters.
	static func isCanonicalPassword(_ text: String) -> Bool {
		let bytes = Array(text.utf8)
		guard bytes.count == 66, bytes[0] == 0x30, bytes[1] == 0x78 else { return false }
		return bytes[2...].allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
	}

	static func hexLower(_ bytes: [UInt8]) -> String {
		bytes.map { String(format: "%02x", $0) }.joined()
	}

	/// The ack envelope ((3)): success carries `result`, failure carries `error`. No `code`, no top-level data.
	static func ackEnvelope(reqId: Any, result: [String: Any]?, error: String?) -> [String: Any] {
		if let result {
			return ["type": "ack", "reqId": reqId, "ok": true, "result": result]
		}
		return ["type": "ack", "reqId": reqId, "ok": false, "error": error ?? "error"]
	}

	// MARK: - Vault and signing 

	/// The backup: base64(iv ‖ ct ‖ tag), AES-256-GCM, key = SHA-256(UTF-8(password)). The plaintext is the PGP
	/// private armor. The IV is 12 bytes: random in production, fixed in the vectors.
	static func backupBase64(privateArmor: String, password: String, iv: [UInt8]) -> String? {
		guard iv.count == 12 else { return nil }
		let key = SymmetricKey(data: Data(SHA256.hash(data: Data(password.utf8))))
		guard let nonce = try? AES.GCM.Nonce(data: Data(iv)),
		      let box = try? AES.GCM.seal(Data(privateArmor.utf8), using: key, nonce: nonce) else { return nil }
		return (Data(iv) + box.ciphertext + box.tag).base64EncodedString()
	}

	/// The eight-line message. Lines joined with LF, no trailing LF. The two hashes are keccak256 of the UTF-8 base64
	/// text of the public key and of the backup.
	static func registrationMessage(wallet: String, keyID: String, publicKeyBase64: String, encrypKeyBase64: String,
	                                routeKeyID: String, timestamp: Int64, nonce: String) -> String {
		let publicHash = "0x" + hexLower(BeamioNativeEthSigner.keccak256(Array(publicKeyBase64.utf8)))
		let backupHash = "0x" + hexLower(BeamioNativeEthSigner.keccak256(Array(encrypKeyBase64.utf8)))
		return [
			"Beamio regiestChatRoute",
			"wallet:\(wallet.lowercased())",
			"keyID:\(keyID)",
			"publicKeyArmoredHash:\(publicHash)",
			"encrypKeyArmoredHash:\(backupHash)",
			"routeKeyID:\(routeKeyID)",
			"timestamp:\(timestamp)",
			"nonce:\(nonce)",
		].joined(separator: "\n")
	}

	/// Compares two armored keys without line-ending or edge whitespace differences.
	static func normalizedArmor(_ text: String) -> String {
		text.replacingOccurrences(of: "\r", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
	}

	/// A refusal from the vault and signing stages, by its code.
	struct RouteRegisterRefusal: Error, Equatable {
		let code: String
	}

	/// The vault and signing stages. Returns the ack `result`, or the refusal code. The PGP record must belong to the account and
	/// its public key must match the request (sig_rejected). The EOA key is used inside `withAccountKey` and wiped there.
	static func register(account rawAccount: String, request: Request, secrets: BeamioChatPgpKeychain.Secrets?,
	                     timestamp: Int64, iv: [UInt8], nonce: [UInt8]) -> Result<[String: Any], RouteRegisterRefusal> {
		let account = rawAccount.lowercased()
		guard let record = secrets, record.hasUserPrivate, record.eoa.lowercased() == account else {
			return .failure(RouteRegisterRefusal(code: "no_pgp_key"))
		}
		guard let publicData = Data(base64Encoded: request.publicKeyArmored),
		      let publicArmor = String(data: publicData, encoding: .utf8) else {
			return .failure(RouteRegisterRefusal(code: "bad_request"))
		}
		guard normalizedArmor(publicArmor) == normalizedArmor(record.publicKeyArmor) else {
			return .failure(RouteRegisterRefusal(code: "sig_rejected"))
		}
		return signedRegistration(account: account, privateArmor: record.privateKeyArmor, request: request, timestamp: timestamp, iv: iv, nonce: nonce)
	}

	/// The signing stage on its own: the PGP private armor may come from a record or from a new identity that is still pending. The EOA key is used inside `withAccountKey` and wiped there.
	static func signedRegistration(account rawAccount: String, privateArmor: String, request: Request, timestamp: Int64, iv: [UInt8], nonce: [UInt8]) -> Result<[String: Any], RouteRegisterRefusal> {
		let account = rawAccount.lowercased()
		guard nonce.count == 16 else { return .failure(RouteRegisterRefusal(code: "bad_request")) }
		let nonceText = "0x" + hexLower(nonce)
		let outcome = BeamioNativeWallet.withAccountKey(eoa: account) { key -> [String: Any]? in
			let password = passwordString(privateKey: key)
			guard let backup = backupBase64(privateArmor: privateArmor, password: password, iv: iv) else { return nil }
			let message = registrationMessage(wallet: account, keyID: request.keyID, publicKeyBase64: request.publicKeyArmored,
			                                  encrypKeyBase64: backup, routeKeyID: request.routeKeyID,
			                                  timestamp: timestamp, nonce: nonceText)
			guard let signature = BeamioNativeEthSigner.signEip191(privateKey: key, message: message) else { return nil }
			return [
				"wallet": account,
				"keyID": request.keyID,
				"publicKeyArmored": request.publicKeyArmored,
				"encrypKeyArmored": backup,
				"routeKeyID": request.routeKeyID,
				"timestamp": Int(timestamp),
				"nonce": nonceText,
				"signature": signature,
			]
		}
		switch outcome {
		case .success(let result):
			return .success(result)
		case .failure(.locked):
			return .failure(RouteRegisterRefusal(code: "locked"))
		// a G2 signing with no account key (walletKeyMissing), or a record that cannot be read now (storageUnreadable),
		// answers not_ready, not no_key (no_key is G0 only).
		case .failure(.walletKeyMissing), .failure(.storageUnreadable):
			return .failure(RouteRegisterRefusal(code: "not_ready"))
		case .failure:
			return .failure(RouteRegisterRefusal(code: "sig_rejected"))
		}
	}
}
