import CryptoKit
import XCTest
@testable import ConetChatSDK

/// `count` copies of `word`, the last one replaced by `last`: a test phrase built from a public word.
private func wordPhrase(_ word: String, _ count: Int, then last: String) -> String {
	(Array(repeating: word, count: count - 1) + [last]).joined(separator: " ")
}

/// Native recovery-phrase import (P-MNEMONIC, spec): English list, no passphrase, m/44'/60'/0'/0/0, account 0.
///
/// Only public test phrases: the BIP-39 "abandon" phrases, the Hardhat "test … junk" phrase, and phrases built from all-zero
/// and all-0xFF entropy. The expected accounts and keys are ethers v6 `Wallet.fromPhrase` output (not from this code).
/// No user material. Phrases are never printed by these tests.
final class BeamioMnemonicImportTests: XCTestCase {
	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
	}

	/// Store with failure injection for the write and read-back paths.
	final class InjectedStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var failWrite = false
		var corruptReadBack = false
		var deletes = 0
		func write(eoa: String, key: Data) -> Bool {
			if failWrite { return false }
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? {
			guard let k = keys[eoa.lowercased()] else { return nil }
			return corruptReadBack ? Data(repeating: 0xEE, count: k.count) : k
		}
		func delete(eoa: String) { deletes += 1; keys[eoa.lowercased()] = nil }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private let twelveZero = wordPhrase("abandon", 12, then: "about")
	private let twelveZeroAccount = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let twelveZeroKey = "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"

	/// (phrase, lower-case account, private key hex). Reference: ethers v6 `Wallet.fromPhrase`, path m/44'/60'/0'/0/0.
	private var vectors: [(name: String, phrase: String, account: String, key: String)] {
		[
			("12 words, zero entropy", twelveZero, twelveZeroAccount, twelveZeroKey),
			("12 words, Hardhat test phrase", "test test test test test test test test test test test junk",
			 "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
			 "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
			("15 words, zero entropy", wordPhrase("abandon", 15, then: "address"),
			 "0x54be88525b024a20229fe7f6f62dc0884e4aaa0a",
			 "89fe6cf31a686f718017d664b08f75a51b706edc85edd6c67b1d2b56da628964"),
			("18 words, zero entropy", wordPhrase("abandon", 18, then: "agent"),
			 "0x197a1bee163923815ba58ead0f14b3fcd8c5926d",
			 "7baa95e968e65395b2b4cc341885bcfbc0d820571af180c65cc9c5019551c669"),
			("21 words, zero entropy", wordPhrase("abandon", 21, then: "admit"),
			 "0x15cc2210a0afbb1a2d80dd3d585aa94eba6c10e0",
			 "01a17b608fed85bf7a3ce6ffc0f8f9edd862bda09d1395eb0335edb336d9acae"),
			("24 words, zero entropy", wordPhrase("abandon", 24, then: "art"),
			 "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb",
			 "1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f"),
			("12 words, 0xFF entropy", wordPhrase("zoo", 12, then: "wrong"),
			 "0xfc2077ca7f403cbeca41b1b0f62d91b5ea631b5e",
			 "7af65ba4dd53f23495dcb04995e96f47c243217fc279f10795871b725cd009ae"),
			("24 words, 0xFF entropy", wordPhrase("zoo", 24, then: "vote"),
			 "0x1959f5f4979c5cd87d5cb75c678c770515cb5e0e",
			 "105434ca932be16664cb5e44e5b006728577dd757440d068e6d15ef52c15a82f"),
		]
	}

	private func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

	private func keyData(_ keyHex: String) -> Data {
		var out: [UInt8] = []
		var i = keyHex.startIndex
		while i < keyHex.endIndex {
			let j = keyHex.index(i, offsetBy: 2)
			out.append(UInt8(keyHex[i ..< j], radix: 16) ?? 0)
			i = j
		}
		return Data(out)
	}

	/// The derived key of a phrase, or the derivation result when it is not a key.
	private func derive(_ phrase: String) -> BeamioMnemonicDerivation.Derivation {
		BeamioMnemonicDerivation.derive(phrase: phrase)
	}

	private func expectInvalidMnemonic(_ phrase: String, _ note: String, file: StaticString = #filePath, line: UInt = #line) {
		guard case .invalidMnemonic = derive(phrase) else {
			return XCTFail("\(note): expected invalidMnemonic", file: file, line: line)
		}
	}

	// MARK: - The wordlist and the derivation

	func testTheWordlistIsTheBip39EnglishList() {
		let words = BeamioBip39Wordlist.english
		XCTAssertEqual(words.count, 2048)
		XCTAssertEqual(words.first, "abandon")
		XCTAssertEqual(words.last, "zoo")
		let joined = Data((words.joined(separator: "\n") + "\n").utf8)
		XCTAssertEqual(SHA256.hash(data: joined).map { String(format: "%02x", $0) }.joined(),
		               "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda")
	}

	func testEachReferenceVectorDerivesTheEthersAccountAndKey() {
		for v in vectors {
			XCTAssertTrue(BeamioMnemonicDerivation.validWordCounts.contains(v.phrase.split(separator: " ").count), v.name)
			guard case .key(let key) = derive(v.phrase) else {
				XCTFail("\(v.name): expected a key")
				continue
			}
			XCTAssertEqual(hex(key), v.key, "\(v.name): private key")
			XCTAssertEqual(BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), v.account, "\(v.name): account")
		}
	}

	func testWhitespaceAndLineBreaksDoNotChangeTheKey() {
		let messy = "  " + twelveZero.replacingOccurrences(of: " ", with: "\t \n") + "\n"
		guard case .key(let key) = derive(messy) else {
			return XCTFail("expected a key for the messy spacing")
		}
		XCTAssertEqual(hex(key), twelveZeroKey)
	}

	/// ethers lower-cases the whole phrase before the words are checked (spec), so upper case is accepted.
	func testUpperCaseWordsAreAcceptedLikeEthers() {
		guard case .key(let key) = derive(twelveZero.uppercased()) else {
			return XCTFail("expected a key for the upper-case phrase")
		}
		XCTAssertEqual(hex(key), twelveZeroKey)
	}

	/// Outer ASCII white space is removed; a Unicode space at either end is not (spec, the one relaxation).
	func testOuterAsciiWhiteSpaceIsRemovedButAUnicodeSpaceAtTheEndIsNot() {
		guard case .key = derive(" \t" + twelveZero + "\r\n") else { return XCTFail("ASCII outer space is removed") }
		expectInvalidMnemonic("\u{00A0}" + twelveZero, "leading NBSP")
		expectInvalidMnemonic(twelveZero + "\u{00A0}", "trailing NBSP")
	}

	/// A full-width word is NFKD-normalised after the split (MD-4).
	func testFullWidthWordIsNormalised() {
		guard case .key(let key) = derive("ａｂａｎｄｏｎ abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") else {
			return XCTFail("expected a key for the full-width first word")
		}
		XCTAssertEqual(hex(key), twelveZeroKey)
	}

	func testTheWordCountMustBeTwelveFifteenEighteenTwentyOneOrTwentyFour() {
		expectInvalidMnemonic(wordPhrase("abandon", 11, then: "about"), "11 words")
		expectInvalidMnemonic(wordPhrase("abandon", 13, then: "about"), "13 words")
		expectInvalidMnemonic("", "empty")
		expectInvalidMnemonic("   \n\t ", "whitespace only")
	}

	func testAWordOutsideTheListIsRefused() {
		expectInvalidMnemonic(wordPhrase("abandon", 12, then: "xyzzy"), "a word outside the list")
	}

	func testABadChecksumIsRefused() {
		expectInvalidMnemonic(wordPhrase("abandon", 12, then: "abandon"), "12 words, checksum")
		expectInvalidMnemonic(wordPhrase("abandon", 12, then: "zoo"), "12 words, other checksum")
		expectInvalidMnemonic(wordPhrase("abandon", 15, then: "abandon"), "15 words, checksum")
		expectInvalidMnemonic(wordPhrase("abandon", 24, then: "abandon"), "24 words, checksum")
	}

	// MARK: - Import (spec, the same rules as a private key)

	func testImportWritesTheAccountOfThePhrase() {
		let store = InjectedStore()
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: twelveZero, expectedEoa: twelveZeroAccount, store: store),
		               .imported)
		XCTAssertEqual(store.keys[twelveZeroAccount], keyData(twelveZeroKey), "the record is written and read back")
	}

	func testWithoutAnAccountTheDerivedAccountIsUsed() {
		let store = InjectedStore()
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: twelveZero, expectedEoa: "", store: store), .imported)
		XCTAssertEqual(store.keys[twelveZeroAccount], keyData(twelveZeroKey))
	}

	func testAMismatchedExpectedAccountWritesNothing() {
		let store = InjectedStore()
		let other = "0x1111111111111111111111111111111111111111"
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: twelveZero, expectedEoa: other, store: store),
		               .addressMismatch)
		XCTAssertTrue(store.keys.isEmpty)
		XCTAssertEqual(store.deletes, 0)
	}

	func testAnExistingRecordIsNotOverwritten() {
		let store = InjectedStore()
		let existing = Data(repeating: 0x22, count: 32)
		store.keys[twelveZeroAccount] = existing
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: twelveZero, expectedEoa: twelveZeroAccount, store: store),
		               .alreadyPresent)
		XCTAssertEqual(store.keys[twelveZeroAccount], existing)
	}

	func testAWriteFailureLeavesNothing() {
		let store = InjectedStore()
		store.failWrite = true
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: twelveZero, expectedEoa: twelveZeroAccount, store: store),
		               .writeFailed)
		XCTAssertTrue(store.keys.isEmpty)
	}

	func testAFailedReadBackDeletesTheWrite() {
		let store = InjectedStore()
		store.corruptReadBack = true
		XCTAssertEqual(BeamioNativeKeyImport.importRecoveryPhrase(text: twelveZero, expectedEoa: twelveZeroAccount, store: store),
		               .readBackFailed)
		XCTAssertNil(store.keys[twelveZeroAccount], "the write is removed when the read-back does not match")
		XCTAssertEqual(store.deletes, 1)
	}

	func testFormatProblemsAreReportedWithTheVectorCodeAndWriteNothing() {
		let store = InjectedStore()
		let outcome = BeamioNativeKeyImport.importRecoveryPhrase(text: wordPhrase("abandon", 12, then: "abandon"),
		                                                         expectedEoa: twelveZeroAccount, store: store)
		XCTAssertEqual(outcome, .invalidMnemonic)
		XCTAssertEqual(outcome.code, "invalid_mnemonic")
		XCTAssertTrue(store.keys.isEmpty)
	}

	func testTheFormatMessageDoesNotRepeatTheInput() {
		let message = BeamioNativeKeyImport.userMessage(for: .invalidMnemonic) ?? ""
		XCTAssertFalse(message.contains("abandon"))
		XCTAssertFalse(message.contains(twelveZeroAccount))
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

}
