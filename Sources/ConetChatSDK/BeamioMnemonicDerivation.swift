import CommonCrypto
import CryptoKit
import Foundation

/// BIP-39 recovery phrase to the native account key.
///
/// Rules: the English wordlist; no passphrase; BIP-32 path m/44'/60'/0'/0/0 (the ethers v6 default, the same derivation as
/// the PWA's `ethers.Wallet.fromPhrase`); account index 0. Word counts 12, 15, 18, 21 or 24. The phrase is handled only in
/// this process: it is never logged, never returned over the bridge, and never echoed in an error.
enum BeamioMnemonicDerivation {
	/// The result of a derivation. The error cases carry no detail, so a phrase is never echoed back.
	enum Derivation {
		case key([UInt8])
		/// Wrong word count, a word outside the list, an empty or blank text, or a checksum mismatch (import code
		/// `invalid_mnemonic`, spec).
		case invalidMnemonic
		/// The derived key is out of range, or a fixed-parameter step failed (import code `invalid_key`). Not reachable with
		/// the fixed parameters in practice.
		case invalidKey
	}

	static let validWordCounts: Set<Int> = [12, 15, 18, 21, 24]
	private static let hardenedOffset: UInt32 = 0x8000_0000
	/// m/44'/60'/0'/0/0
	private static let path: [UInt32] = [
		44 + hardenedOffset, 60 + hardenedOffset, 0 + hardenedOffset, 0, 0,
	]
	private static let pbkdf2Iterations = 2048
	private static let wordIndex: [String: Int] = {
		var index: [String: Int] = [:]
		for (i, word) in BeamioBip39Wordlist.english.enumerated() { index[word] = i }
		return index
	}()

	/// Derives the account key from a phrase (spec). Accepts what ethers 6.17 `Mnemonic.fromPhrase` accepts, with one
	/// deliberate relaxation: outer ASCII whitespace is removed before the check.
	static func derive(phrase text: String) -> Derivation {
		let words = phraseWords(text)
		guard validWordCounts.contains(words.count) else { return .invalidMnemonic }
		var indexes: [Int] = []
		indexes.reserveCapacity(words.count)
		for word in words {
			guard let i = wordIndex[word] else { return .invalidMnemonic }
			indexes.append(i)
		}
		guard var entropy = checkedEntropy(indexes: indexes, wordCount: words.count) else { return .invalidMnemonic }
		BeamioNativeWallet.wipe(&entropy)  // only the checksum mattered here: the seed below comes from the sentence
		var sentence = Array(words.joined(separator: " ").utf8)  // BIP-39: single spaces; every word is ASCII
		defer { BeamioNativeWallet.wipe(&sentence) }
		guard var seed = pbkdf2Sha512(password: sentence, salt: Array("mnemonic".utf8), iterations: pbkdf2Iterations, length: 64)
		else { return .invalidKey }
		defer { BeamioNativeWallet.wipe(&seed) }
		guard let key = accountKey(seed: seed) else { return .invalidKey }
		return .key(key)
	}

	/// The words of a phrase, in the order of spec and ethers 6.17: outer ASCII whitespace (space, tab, LF, FF, CR)
	/// removed; lower-cased; split at runs of JavaScript `\s` (so NBSP and the other Unicode spaces separate words); each word
	/// NFKD-normalised. A Unicode space at either end leaves an empty word, which is refused by the count or the list. An
	/// empty or blank text gives one empty word.
	static func phraseWords(_ text: String) -> [String] {
		var scalars = Array(text.unicodeScalars)
		while let first = scalars.first, isAsciiTrim(first.value) { scalars.removeFirst() }
		while let last = scalars.last, isAsciiTrim(last.value) { scalars.removeLast() }
		let lowered = Array(String(String.UnicodeScalarView(scalars)).lowercased().unicodeScalars)
		var parts: [[Unicode.Scalar]] = [[]]
		var inRun = false
		for s in lowered {
			if isJavaScriptSpace(s.value) {
				if !inRun {
					parts.append([])
					inRun = true
				}
			} else {
				inRun = false
				parts[parts.count - 1].append(s)
			}
		}
		return parts.map { part in
			String(String.UnicodeScalarView(part)).decomposedStringWithCompatibilityMapping
		}
	}

	/// ASCII whitespace removed at the ends of a phrase: space, tab, LF, FF, CR (the same set as the key path).
	private static func isAsciiTrim(_ v: UInt32) -> Bool {
		v == 0x20 || v == 0x09 || v == 0x0A || v == 0x0C || v == 0x0D
	}

	/// JavaScript `\s` (the set ethers splits on): ASCII white space, NBSP, the Unicode Zs spaces, line and paragraph
	/// separators, and U+FEFF.
	private static func isJavaScriptSpace(_ v: UInt32) -> Bool {
		switch v {
		case 0x09 ... 0x0D, 0x20, 0xA0, 0x1680, 0x2000 ... 0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
			return true
		default:
			return false
		}
	}

	/// The entropy of the words, once the checksum is verified. nil when the checksum does not match.
	static func checkedEntropy(indexes: [Int], wordCount: Int) -> [UInt8]? {
		let checksumBits = wordCount / 3
		let entropyBits = wordCount * 11 - checksumBits
		var bits: [UInt8] = []
		bits.reserveCapacity(wordCount * 11)
		for i in indexes {
			for shift in stride(from: 10, through: 0, by: -1) { bits.append(UInt8((i >> shift) & 1)) }
		}
		defer { BeamioNativeWallet.wipe(&bits) }
		var entropy = [UInt8](repeating: 0, count: entropyBits / 8)
		for j in 0 ..< entropyBits where bits[j] == 1 {
			entropy[j / 8] |= UInt8(0x80 >> (j % 8))
		}
		let digest = Array(SHA256.hash(data: Data(entropy)))
		for j in 0 ..< checksumBits {
			let expected = (digest[j / 8] >> (7 - j % 8)) & 1
			guard bits[entropyBits + j] == expected else {
				BeamioNativeWallet.wipe(&entropy)
				return nil
			}
		}
		return entropy
	}

	/// BIP-32 master key from the seed (HMAC-SHA512 keyed "Bitcoin seed"), then each step of `path`. nil when a step is
	/// invalid.
	static func accountKey(seed: [UInt8]) -> [UInt8]? {
		var master = hmacSha512(key: Array("Bitcoin seed".utf8), data: seed)
		defer { BeamioNativeWallet.wipe(&master) }
		var key = Array(master[0 ..< 32])
		var chain = Array(master[32 ..< 64])
		var valid = BeamioNativeEthSigner.isValidKey(key)
		for index in path where valid {
			var data: [UInt8]
			if index >= hardenedOffset {
				let prefix: [UInt8] = [0x00]
				data = prefix + key + serialize32(index)
			} else {
				guard let pub = BeamioNativeEthSigner.compressedPublicKey(privateKey: key) else {
					valid = false
					break
				}
				data = pub + serialize32(index)
			}
			var child = hmacSha512(key: chain, data: data)
			BeamioNativeWallet.wipe(&data)
			var tweak = Array(child[0 ..< 32])
			chain = Array(child[32 ..< 64])
			BeamioNativeWallet.wipe(&child)
			valid = BeamioNativeEthSigner.tweakAddPrivateKey(&key, tweak: tweak)
			BeamioNativeWallet.wipe(&tweak)
		}
		guard valid, BeamioNativeEthSigner.isValidKey(key) else {
			BeamioNativeWallet.wipe(&key)
			return nil
		}
		return key
	}

	private static func hmacSha512(key: [UInt8], data: [UInt8]) -> [UInt8] {
		Array(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: key)))
	}

	private static func serialize32(_ value: UInt32) -> [UInt8] {
		[UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
	}

	/// PBKDF2-HMAC-SHA512 (CommonCrypto `CCKeyDerivationPBKDF`), as BIP-39 specifies. nil on a CommonCrypto failure.
	static func pbkdf2Sha512(password: [UInt8], salt: [UInt8], iterations: Int, length: Int) -> [UInt8]? {
		var out = [UInt8](repeating: 0, count: length)
		let status = password.withUnsafeBufferPointer { pw in
			out.withUnsafeMutableBufferPointer { outBuf in
				salt.withUnsafeBufferPointer { saltBuf in
					pw.withMemoryRebound(to: CChar.self) { pwChars in
						CCKeyDerivationPBKDF(
							CCPBKDFAlgorithm(kCCPBKDF2),
							pwChars.baseAddress, pwChars.count,
							saltBuf.baseAddress, saltBuf.count,
							CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
							UInt32(iterations),
							outBuf.baseAddress, length
						)
					}
				}
			}
		}
		guard status == Int32(kCCSuccess) else {
			BeamioNativeWallet.wipe(&out)
			return nil
		}
		return out
	}
}
