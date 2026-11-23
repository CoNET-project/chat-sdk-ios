import CryptoKit
import XCTest
@testable import ConetChatSDK

#if BEAMIO_TEST_HOOKS

/// `identity.provision` and `init` against identity-native-keys-vectors.v1 (interface notice, 17th batch). The vector file
/// is read from IDENTITY_VECTORS and its SHA256 is checked. All cases use the declared capability list, because the vectors
/// describe the `identity.native-keys.v1` answer. The production list does not declare it (the PWA and Android have not passed).
final class IdentityVectorTests: XCTestCase {
	private static let expectedSHA = "7aa7b4dbd93d0d42b594ab18f1d70e85a7d4b9dbba484bd7d6aba4e3851864b9"
	private let declared = BeamioConetChatProtocol.capabilities + [BeamioConetChatModule.identityNativeKeysCapability]

	private func loadVectors() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["IDENTITY_VECTORS"] else {
			throw XCTSkip("set IDENTITY_VECTORS to interface/protocol/identity-native-keys-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		let sha = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(sha, Self.expectedSHA, "vector file hash")
		return try Self.parseVectorFile(data)
	}

	/// Foundation's JSON parser drops U+FEFF (a literal one, and the \ufeff escape alike), so the loader moves it to a
	/// placeholder before parsing and restores it in every string and key afterwards. The placeholder (U+E000) must not
	/// occur in the file; the other characters of S (U+200B, U+00A0, U+2028, U+000B, …) survive the parser unchanged.
	static func parseVectorFile(_ data: Data) throws -> [String: Any] {
		let placeholder = Data([0xEE, 0x80, 0x80]) // U+E000
		XCTAssertNil(data.range(of: placeholder), "the vector file must not contain the placeholder U+E000")
		var bytes = data
		bytes = bytes.replacingAll(Data([0xEF, 0xBB, 0xBF]), with: placeholder)                  // literal U+FEFF
		bytes = bytes.replacingAll(Data("\\ufeff".utf8), with: Data("\\ue000".utf8))         // \ufeff escape
		bytes = bytes.replacingAll(Data("\\uFEFF".utf8), with: Data("\\ue000".utf8))         // \uFEFF escape
		let parsed = try JSONSerialization.jsonObject(with: bytes)
		return try XCTUnwrap(restoreBOM(parsed) as? [String: Any])
	}

	private static func restoreBOM(_ value: Any) -> Any {
		if let text = value as? String {
			return text.replacingOccurrences(of: "\u{E000}", with: "\u{FEFF}")
		}
		if let dict = value as? [String: Any] {
			var out: [String: Any] = [:]
			for (key, nested) in dict {
				out[key.replacingOccurrences(of: "\u{E000}", with: "\u{FEFF}")] = restoreBOM(nested)
			}
			return out
		}
		if let list = value as? [Any] {
			return list.map { restoreBOM($0) }
		}
		return value
	}

	/// Whether a loaded value holds the scalar anywhere in a string or key.
	private static func holdsScalar(_ value: Any, _ scalar: UInt32) -> Bool {
		if let text = value as? String { return text.unicodeScalars.contains { $0.value == scalar } }
		if let dict = value as? [String: Any] {
			return dict.keys.contains { $0.unicodeScalars.contains { $0.value == scalar } } || dict.values.contains { holdsScalar($0, scalar) }
		}
		if let list = value as? [Any] { return list.contains { holdsScalar($0, scalar) } }
		return false
	}

	/// Cases named `accept-init-*` and `reject-init-*` use the `init` placement (identity nested under payload.identity);
	/// the rest use the flat `provisionIdentity` placement.
	private func route(for name: String) -> BeamioConetChatModule.IdentityRoute {
		name.hasPrefix("accept-init") || name.hasPrefix("reject-init") ? .initNested : .provision
	}

	/// The 53 request cases: refusal codes, the `field` for a refused key, and the error codes.
	func testRequestCasesMatchTheVectors() throws {
		let vectors = try loadVectors()
		let cases = try XCTUnwrap(vectors["requestCases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 53)
		for c in cases {
			let name = c["name"] as? String ?? "?"
			let input = try XCTUnwrap(c["input"] as? [String: Any], name)
			let expect = try XCTUnwrap(c["expect"] as? [String: Any], name)
			let accepted = (expect["ok"] as? Bool) == true
			let out = BeamioConetChatModule.testIdentityProvisionOutcome(
				payload: input,
				route: route(for: name),
				readyFor: { _ in
					if !accepted { XCTFail("the store was read for a refused request: \(name)") }
					return false
				},
				capabilities: declared
			)
			for (key, value) in expect {
				if let flag = value as? Bool {
					XCTAssertEqual(out[key] as? Bool, flag, "\(name): \(key)")
				} else {
					XCTAssertEqual(out[key] as? String, value as? String, "\(name): \(key)")
				}
			}
		}
	}

	/// responseShape: the result body carries only `ready` and `eoa`; `ok` belongs to the ack envelope (I-3).
	func testAcceptedAnswerHasOnlyTheAllowedKeys() throws {
		let vectors = try loadVectors()
		let shape = try XCTUnwrap(vectors["responseShape"] as? [String: Any])
		let allowed = Set(try XCTUnwrap(shape["allowedKeys"] as? [String]))
		XCTAssertEqual(allowed, ["ready", "eoa"])
		let envelope = try XCTUnwrap(shape["ackEnvelope"] as? [String: Any])
		XCTAssertEqual(Set(envelope.keys), ["type", "reqId", "ok", "error"])
		let cases = try XCTUnwrap(vectors["requestCases"] as? [[String: Any]])
		let accept = try XCTUnwrap(cases.first { $0["name"] as? String == "accept-provision-public-only" })
		let input = try XCTUnwrap(accept["input"] as? [String: Any])
		let out = BeamioConetChatModule.testIdentityProvisionOutcome(payload: input, readyFor: { _ in false }, capabilities: declared)
		// The result body is the outcome without `ok`.
		let body = Set(out.keys).subtracting(["ok"])
		XCTAssertEqual(body, allowed)
	}

	/// The three ready variants, on the vector's own account. `has_key_readback_ok` uses the public test key P of
	/// spec 23.2 (`sha256("chat-local-test-private-key-v1")`, which derives the vector eoa). P is test material: it is used
	/// only here, and no assertion message, log line or receipt carries it.
	func testReadyVariantsMatchTheVectors() throws {
		let vectors = try loadVectors()
		let variants = try XCTUnwrap(vectors["readyVariants"] as? [[String: Any]])
		XCTAssertEqual(variants.count, 3)
		let eoa = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
		let store = ChatLocalWalletBoundaryTests.MemoryWalletKeyStore()
		BeamioConetChatSignBroker.keyStore = store

		// no_key → ready false
		XCTAssertFalse(BeamioConetChatModule.identityKeyReady(eoa: eoa))

		// key_address_mismatch → ready false: a key that derives another address, stored under the vector account
		store.keys[eoa] = Data(repeating: 0, count: 31) + Data([1])
		XCTAssertFalse(BeamioConetChatModule.identityKeyReady(eoa: eoa))

		// has_key_readback_ok → ready true, on the vector account itself (spec 23.2 test key P)
		let p = try XCTUnwrap(Self.publicTestKeyP())
		XCTAssertEqual(hexKeyAddress(Self.publicTestKeyPHex)?.lowercased(), eoa, "P derives the vector account (23.2)")
		store.keys[eoa] = p
		XCTAssertTrue(BeamioConetChatModule.identityKeyReady(eoa: eoa))
		let out = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: ["eoa": eoa], readyFor: BeamioConetChatModule.identityKeyReady, capabilities: declared
		)
		XCTAssertEqual(out["ready"] as? Bool, true)
		XCTAssertEqual(out["eoa"] as? String, eoa)
	}

	/// spec 23.2 public test key P. Test material only.
	private static let publicTestKeyPHex = "78c08ce2d2b3fcc5674235d61587b11daebeb0bd4b44a263b827f0ba7743b0bd"

	private static func publicTestKeyP() -> Data? {
		var out = Data()
		var index = publicTestKeyPHex.startIndex
		while index < publicTestKeyPHex.endIndex {
			let next = publicTestKeyPHex.index(index, offsetBy: 2)
			guard let byte = UInt8(publicTestKeyPHex[index ..< next], radix: 16) else { return nil }
			out.append(byte)
			index = next
		}
		return out
	}

	/// fieldPlacement: the public identity of `init` lives under payload.identity; a top-level copy is not an identity.
	func testFieldPlacementFollowsTheVectors() throws {
		let vectors = try loadVectors()
		let placement = try XCTUnwrap(vectors["fieldPlacement"] as? [String: Any])
		XCTAssertNotNil(placement["init"] as? String)
		let cases = try XCTUnwrap(vectors["requestCases"] as? [[String: Any]])
		let top = try XCTUnwrap(cases.first { $0["name"] as? String == "reject-init-top-level-public-fields" })
		let input = try XCTUnwrap(top["input"] as? [String: Any])
		let out = BeamioConetChatModule.testIdentityProvisionOutcome(payload: input, route: .initNested,
		                                                         readyFor: { _ in false }, capabilities: declared)
		XCTAssertEqual(out["error"] as? String, "missing_identity")
	}

	/// The key names of the vector are the lower-cased forms of the production list (case-insensitive matching).
	func testForbiddenKeyNamesMatchTheVectorList() throws {
		let vectors = try loadVectors()
		let listed = try XCTUnwrap(vectors["forbiddenKeysCaseInsensitive"] as? [String])
		// the identity vector checks a subset of the CRED set; the module refuses the whole CRED set. Every name the vector
		// lists must be refused by the module, and the module's list must be the full CRED (16 names,).
		let refused = Set(BeamioConetChatModule.identityForbiddenKeys.map { $0.lowercased() })
		XCTAssertTrue(Set(listed).isSubset(of: refused), "the vector's names are all refused")
		XCTAssertEqual(refused.count, 16, "the CRED set of provisionIdentity and init is 16 names")
	}

	/// valueShapeRules: a PGP private key block anywhere, or 64 hex digits with an optional 0x, is refused.
	func testValueShapeRules() {
		XCTAssertTrue(BeamioConetChatModule.identityValueLooksLikeKeyMaterial("x -----BEGIN PGP PRIVATE KEY BLOCK-----"))
		XCTAssertTrue(BeamioConetChatModule.identityValueLooksLikeKeyMaterial("0x" + String(repeating: "ab", count: 32)))
		XCTAssertTrue(BeamioConetChatModule.identityValueLooksLikeKeyMaterial(String(repeating: "ab", count: 32)))
		XCTAssertFalse(BeamioConetChatModule.identityValueLooksLikeKeyMaterial(String(repeating: "ab", count: 31)))
		XCTAssertFalse(BeamioConetChatModule.identityValueLooksLikeKeyMaterial("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"))
		XCTAssertFalse(BeamioConetChatModule.identityValueLooksLikeKeyMaterial("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
	}

	/// Key names are matched case-insensitively, and the refused field is reported as the name the payload used.
	func testKeyNameIsMatchedCaseInsensitively() {
		let eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
		let out = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: ["eoa": eoa, "PRIVATEKEYHEX": "x"],
			readyFor: { _ in XCTFail("store read for a refused request"); return false }, capabilities: declared
		)
		XCTAssertEqual(out["error"] as? String, "key_over_bridge_refused")
		XCTAssertEqual(out["field"] as? String, "PRIVATEKEYHEX")
	}

	/// valueShapeRules 2 and 3: the 64-hex rule is exempt only at the exact path payload.nodes (its whole subtree). Nested
	/// `nodes` keys are not exempt, and a multi-line string is not judged by the 64-hex rule.
	func testHex64RuleSkipsTheExactNodesPathOnly() {
		let hex = "0x" + String(repeating: "ab", count: 32)
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["nodes": [["specHash": hex]]]))
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["identity": ["nodes": ["x": hex]]]), "x")
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["extra": ["nodes": ["x": hex]]]), "x")
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["extra": [["tag": hex]]]), "tag")
		// A trailing line break is whitespace: after the trim the value is one line, so it is refused (F-1).
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["note": hex + "\n"]), "note")
		// rule 1 applies under payload.nodes too
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["nodes": [["armoredPublicKey": "-----BEGIN PGP PRIVATE KEY BLOCK-----"]]]),
		               "armoredPublicKey")
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["nodes": [["privateKeyHex": "00"]]]), "privateKeyHex")
	}

	/// A private-key field inside an array of objects is refused at any depth, and the store is not read.
	func testPrivateKeyInsideAnArrayIsRefused() {
		let eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
		let nested: [String: Any] = ["eoa": eoa, "nodes": [["region": "test", "meta": ["walletPrivateKey": "x"]]]]
		let out = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: nested, readyFor: { _ in XCTFail("store read for a refused request"); return false }, capabilities: declared
		)
		XCTAssertEqual(out["error"] as? String, "key_over_bridge_refused")
		XCTAssertEqual(out["field"] as? String, "walletPrivateKey")

		let listTop: [String: Any] = ["eoa": eoa, "items": [["privateKeyHex": "00"]]]
		let out2 = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: listTop, readyFor: { _ in XCTFail("store read for a refused request"); return false }, capabilities: declared
		)
		XCTAssertEqual(out2["field"] as? String, "privateKeyHex")
	}

	/// A key field with a null value is still a key field (present, not nil in the payload).
	func testNullKeyFieldIsRefused() {
		let eoa = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
		let out = BeamioConetChatModule.testIdentityProvisionOutcome(
			payload: ["eoa": eoa, "mnemonic": NSNull()],
			readyFor: { _ in XCTFail("store read for a refused request"); return false }, capabilities: declared
		)
		XCTAssertEqual(out["field"] as? String, "mnemonic")
	}

	/// The account format (23rd batch): the canonical form only, lower-case 0x + 40 lower-case hex digits. EIP-55 mixed case,
	/// upper-case digits, a 0X prefix, a BOM and full-width forms are refused.
	func testAccountFormat() {
		XCTAssertEqual(BeamioConetChatModule.identityEoa("0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"),
		               "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa", "canonical form is accepted")
		XCTAssertNil(BeamioConetChatModule.identityEoa("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), "EIP-55 mixed case is not canonical")
		XCTAssertNil(BeamioConetChatModule.identityEoa("0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED"), "all upper-case")
		XCTAssertNil(BeamioConetChatModule.identityEoa("0X39581c72b8c7d0de85ff22cf3ae178ae813957aa"), "0X prefix")
		XCTAssertNil(BeamioConetChatModule.identityEoa("\u{FEFF}0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"), "BOM")
		XCTAssertNil(BeamioConetChatModule.identityEoa("0x1234"))
	}

	/// F-1 (review 25): rule 2 matches the value without its surrounding whitespace, line breaks included. A padded 64-hex
	/// value is refused outside `nodes`; rule 3 exempts only a string that is still multi-line after the trim.
	func testHex64IsMatchedAfterTrimmingSurroundingWhitespace() {
		let hex = String(repeating: "cd", count: 32)
		let padded: [String] = [
			"\n0x" + hex + "\n",          // line feeds around the value
			"\r\n0x" + hex + "\r\n",    // CRLF around the value
			"   0x" + hex + "   ",          // spaces
			"\t0x" + hex + "\t",          // tabs
			(" \t\n") + hex + ("\n\t "),  // mixed whitespace, without 0x
		]
		for value in padded {
			XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["memo": value]), "memo",
			               "padded 64-hex must be refused: \(value.debugDescription.count) chars")
			XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["extra": [["tag": value]]]), "tag")
			XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["identity": ["hint": value]]), "hint")
		}
		// Inside payload.nodes the 64-hex rule is exempt, padding or not.
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["nodes": [["specHash": "\n" + hex + "\n"]]]))
		// Rule 3: a string that is still multi-line after the trim is not judged by rule 2.
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["memo": "0x" + hex + "\n" + hex]))
		// 63 hex digits with whitespace are not 64 hex digits.
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["memo": " \n" + String(repeating: "cd", count: 31) + "c \t"]))
	}

	/// Notice 26: every character of S is deleted before a comparison (key names and values). S is Unicode White_Space plus
	/// U+FEFF, U+200B–U+200D, U+2060 and U+00AD. Matching does not depend on the platform trim.
	func testWhitespaceSetIsDeletedBeforeEveryComparison() {
		let hex = String(repeating: "ef", count: 32)
		let bom = "\u{FEFF}"
		let zwsp = "\u{200B}"
		let nbsp = "\u{00A0}"
		let ls = "\u{2028}"
		let vt = "\u{000B}"
		// refused: 64 hex digits once S is deleted
		for value in [bom + hex, bom + "0x" + hex, hex + nbsp, ls + hex, vt + hex, String(hex.prefix(32)) + zwsp + String(hex.suffix(32))] {
			XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["memo": value]), "memo")
		}
		// accepted: 63 or 65 hex digits, even with a BOM
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["memo": bom + String(repeating: "ef", count: 31) + "e"]))
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["memo": bom + hex + "a"]))
		// a zero-width character inside the PRIVATE KEY BLOCK marker
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["note": "PRIVATE" + zwsp + " KEY BLOCK"]), "note")
		// a zero-width character inside a forbidden key name; the field is reported as the name the payload used
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["priv\u{200B}ateKeyHex": "x"]), "priv\u{200B}ateKeyHex")
		// nodes is exempt only as the exact string "nodes": a zero-width character breaks the exemption
		XCTAssertEqual(BeamioConetChatModule.identityForbiddenField(in: ["no\u{200B}des": [["specHash": "0x" + hex]]]), "specHash")
		// nodes is still exempt as the exact string, with the 64-hex rule skipped there
		XCTAssertNil(BeamioConetChatModule.identityForbiddenField(in: ["nodes": [["specHash": "0x" + hex]]]))
	}

	/// Review 28: the loader keeps the U+FEFF that the vector file carries inside its strings. Without it the BOM cases would
	/// test nothing.
	func testLoaderKeepsTheByteOrderMarkInsideVectorStrings() throws {
		guard let path = ProcessInfo.processInfo.environment["IDENTITY_VECTORS"] else {
			throw XCTSkip("set IDENTITY_VECTORS to interface/protocol/identity-native-keys-vectors.v1.json")
		}
		let bytes = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertNotNil(bytes.range(of: Data([0xEF, 0xBB, 0xBF])), "the vector file carries U+FEFF inside its strings")
		let vectors = try loadVectors()
		let cases = try XCTUnwrap(vectors["requestCases"] as? [[String: Any]])
		let bomCase = try XCTUnwrap(cases.first { $0["name"] as? String == "reject-hex64-bom-prefix" })
		let input = try XCTUnwrap(bomCase["input"] as? [String: Any])
		let memo = try XCTUnwrap(input["memo"] as? String)
		XCTAssertTrue(memo.unicodeScalars.contains { $0.value == 0xFEFF }, "the loaded memo string must contain U+FEFF")
		XCTAssertEqual(memo.unicodeScalars.count, 65, "BOM plus 64 hex digits")
		let withBOM = cases.filter { Self.holdsScalar($0["input"] ?? [:], 0xFEFF) }
		XCTAssertEqual(withBOM.count, 6, "six request cases carry U+FEFF after loading")
		// The other characters of S survive the parser too.
		let zwsp = cases.first { $0["name"] as? String == "reject-hex64-zero-width-inside" }
		XCTAssertTrue(Self.holdsScalar(zwsp?["input"] ?? [:], 0x200B), "U+200B survives loading")
	}

	/// Review 29 (E-1): the canonical eoa is checked per Unicode scalar. A combining mark after a hex digit is an extra
	/// scalar, so the value is refused even though it has 42 Characters.
	func testEoaIsCheckedPerUnicodeScalar() {
		let canonical = "0x39581c72b8c7d0de85ff22cf3ae178ae813957aa"
		XCTAssertEqual(BeamioConetChatModule.identityEoa(canonical), canonical, "the canonical form is accepted")
		let combiningAfterFirstDigit = "0x" + "3\u{0301}" + String(canonical.dropFirst(3))
		XCTAssertEqual(combiningAfterFirstDigit.count, 42, "the combining mark is part of a Character, so the Character count is 42")
		XCTAssertEqual(combiningAfterFirstDigit.unicodeScalars.count, 43)
		XCTAssertNil(BeamioConetChatModule.identityEoa(combiningAfterFirstDigit), "an extra scalar is refused")
		XCTAssertNil(BeamioConetChatModule.identityEoa(String(canonical.dropLast()) + "a\u{0301}"), "a combining mark on the last digit")
		XCTAssertNil(BeamioConetChatModule.identityEoa(canonical + "\u{0301}"), "a trailing combining mark")
		XCTAssertNil(BeamioConetChatModule.identityEoa(String(canonical.dropLast()) + "\u{0301}"), "41 scalars with a combining mark")
		XCTAssertNil(BeamioConetChatModule.identityEoa("0x" + String(repeating: "a", count: 39)), "39 digits")
	}

	/// Notice 30: N is NFKD, then S is deleted, then Mn, Me and Cf are deleted; the key whitelist is ASCII letters, digits and
	/// underscore after N, and the original key must equal N of itself.
	func testNormalisationDeletesMarksAndFormatCharactersAndKeysAreWhitelisted() {
		XCTAssertEqual(BeamioConetChatModule.identityNormalized("PRIVATE\u{0301} KEY BLOCK").uppercased(), "PRIVATEKEYBLOCK")
		XCTAssertEqual(BeamioConetChatModule.identityNormalized("PRIVAT\u{00C9} KEY BLOCK").uppercased(), "PRIVATEKEYBLOCK")
		XCTAssertEqual(BeamioConetChatModule.identityNormalized("a\u{200E}b\u{202E}c"), "abc", "LRM and RLO are Cf")
		XCTAssertEqual(BeamioConetChatModule.identityNormalized("0x\u{FE0F}ab"), "0xab", "variation selector is Mn")
		XCTAssertTrue(BeamioConetChatModule.identityKeyIsCanonical("memo"))
		XCTAssertTrue(BeamioConetChatModule.identityKeyIsCanonical("my_key1"))
		XCTAssertFalse(BeamioConetChatModule.identityKeyIsCanonical("memo-1"), "hyphen")
		XCTAssertFalse(BeamioConetChatModule.identityKeyIsCanonical("memo\u{0301}"), "combining mark: N differs from the original")
		XCTAssertFalse(BeamioConetChatModule.identityKeyIsCanonical("\u{FF50}rivate"), "full-width letter: N differs from the original")
		XCTAssertEqual(BeamioConetChatModule.identityNonCanonicalKeyField(in: ["a": ["b-c": 1]]), "b-c", "nested keys are checked")
	}

	/// The capability is declared only in the QA configuration: absent from the production list.
	/// 25.52Y.121: the shipped list declares it in every build (not a QA-only switch).
	func testTheCapabilityIsInTheShippedListInEveryBuild() {
		XCTAssertTrue(BeamioConetChatProtocol.capabilities.contains(BeamioConetChatModule.identityNativeKeysCapability))
	}
}

private extension Data {
	/// Replaces every occurrence of `pattern` with `replacement`.
	func replacingAll(_ pattern: Data, with replacement: Data) -> Data {
		var out = Data()
		var index = startIndex
		while let found = range(of: pattern, in: index ..< endIndex) {
			out.append(self[index ..< found.lowerBound])
			out.append(replacement)
			index = found.upperBound
		}
		out.append(self[index ..< endIndex])
		return out
	}
}
#endif
