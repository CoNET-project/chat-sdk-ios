import CryptoKit
import Foundation
import Security

/// The native account creation `nativeAccountCreateOpen`.
///
/// The bridge side (to,): the G0 gate, the input check, the ack, and the result event. The creation
/// (steps 2 to 4 and 6) is `create(store:)`, a synchronous call the shell makes from a background queue after the
/// user's explicit "create" on the native page. It makes a 12-word BIP-39 phrase from the device random source, derives
/// m/44'/60'/0'/0/0, writes only the 32-byte key through the native key store, reads it back, rolls back on failure, and
/// sets the account pointer. Only the public address (`eoa`) leaves the SDK, in the `ok` result event. The phrase and the key are never sent,
/// never logged, and are not stored outside the key store. `create` sends the one `nativeAccountCreateResult` itself: the shell does not report a result, so no
/// host can report `ok` without a key. The shell cancels with `close`.
public enum BeamioNativeAccountCreate {
	/// Set by the shell. Presents the native creation page and returns true when the page is open.
	public static var onCreateRequired: (() -> Bool)?

	/// The codes of a failed creation. `notAvailable` is for a call with no page open; it is not sent to the page.
	public enum ResultCode: String, Equatable {
		case alreadyExists = "already_exists"
		/// Y.163 第 12 項: a read failed, the residue probe failed or found residue, or the account pointer is set. No eoa.
		case notReady = "not_ready"
		/// r7 第 29 項: a creation that is not the page's explicit command.
		case badRequest = "bad_request"
		case writeFailed = "write_failed"
		case readBackFailed = "readback_failed"
		case notAvailable = "not_available"
	}

	/// The outcome of one creation. `ok` carries the public address (lower-case); nothing else leaves the SDK.
	public enum CreateOutcome: Equatable {
		case ok(eoa: String)
		case failed(ResultCode)
	}

	/// Creates the account of this device (steps 2 to 4). Synchronous; call it from a background queue. The page stays
	/// open after a failure for a retry, and an `ok` closes it. Without an open page nothing is generated.
	public static func create(store: BeamioChatWalletKeyStoring = BeamioNativeWallet.keyStore) -> CreateOutcome {
		createAccount(store: store, entropy: nil)
	}

	/// The page is closed by the user: `cancelled` when no result was produced for this page, nothing otherwise.
	@discardableResult
	public static func close() -> Bool {
		BeamioConetChatModule.closeAccountCreatePage()
	}

	/// The result of one creation before its result event (internal; the public outcome is `CreateOutcome`).
	enum Made {
		case made(Material)
		case failed(ResultCode)
	}

	/// The account of one successful creation: the public address and the W fields of the `ok` result. Internal:
	/// `CreateOutcome` stays the public address only.
	struct Material: Equatable {
		let eoa: String
		let privateKeyArmor: String
		let mnemonicPhrase: String
	}

	/// `create` with the entropy given (tests: 16 bytes of known value). nil takes the device random source.
	static func createAccount(store: BeamioChatWalletKeyStoring, entropy: [UInt8]?) -> CreateOutcome {
		guard BeamioConetChatModule.accountCreatePageOpen() else { return .failed(.notAvailable) }
		switch makeAccount(store: store, entropy: entropy, userExplicit: true) {
		case .made(let material):
			// 2(b): the result carries the address only. The phrase and the key stay in the native store.
			BeamioConetChatModule.finishAccountCreate(code: "ok", eoa: material.eoa)
			return .ok(eoa: material.eoa)
		case .failed(let code):
			// Y.163 第 12 項: no failure of the creation page carries an eoa (the eoa of the page is for the recovery and import pages only).
			BeamioConetChatModule.finishAccountCreate(code: code.rawValue, eoa: nil)
			return .failed(code)
		}
	}

	/// The W form of a key: `0x` and 64 lower-case hex digits. Shared with the recovery result.
	static func walletArmor(_ key: [UInt8]) -> String {
		"0x" + key.map { String(format: "%02x", $0) }.joined()
	}

	/// steps 2 to 4. Only the page's explicit command creates (`userExplicit`, r7 第 12、29 項); automatic paths never reach this.
	/// It appends a key and never overwrites or deletes one (r7 第 12 項 (b)). An unreadable enumeration, residue or a failed probe is not_ready;
	/// an unlocked session or an address that collides with a held entry is already_exists.
	static func makeAccount(store: BeamioChatWalletKeyStoring, entropy: [UInt8]?, userExplicit: Bool) -> Made {
		// Y.163 第 31、32 項: the accounts are the valid mnemonics. A private-key record is neither held nor a residue.
		let inventory = BeamioNativeMnemonicInventory.read(store: store)
		let held = Set(inventory.valid.map { $0.eoa })
		let probe = BeamioResidueProbe.probe()
		// A residue (a mnemonic-channel item) blocks a creation only when no account is named at all: an account that is named, valid or not, is
		// judged by its own state (CR-01, CR-11), and a read that failed is `readFailed` (CR-03).
		let residueBlocks = probe == .present && inventory.accounts.isEmpty
		switch BeamioNativeSilentSelect.createGuard(userExplicit: userExplicit, enumerated: !inventory.readFailed,
		                                            sessionIsG2: BeamioConetChatModule.nativeGate() == .g2,
		                                            g1WithoutKeys: BeamioConetChatModule.nativeGate() == .g1 && held.isEmpty,
		                                            residue: residueBlocks, probeFailed: probe == .failed) {
		case .mayCreate: break
		case .alreadyExists: return .failed(.alreadyExists)
		case .unreadable: return .failed(.notReady)
		case .badRequest: return .failed(.badRequest)
		}
		var ent: [UInt8]
		if let entropy {
			ent = entropy
		} else {
			ent = [UInt8](repeating: 0, count: 16)
			guard SecRandomCopyBytes(kSecRandomDefault, ent.count, &ent) == errSecSuccess else { return .failed(.writeFailed) }
		}
		defer { BeamioNativeWallet.wipe(&ent) }
		guard let words = phrase(entropy: ent),
		      case .key(var key) = BeamioMnemonicDerivation.derive(phrase: words),
		      let eoa = BeamioNativeEthSigner.address(privateKey: key)?.lowercased()
		else { return .failed(.writeFailed) }
		// The W form is taken before the shared tail wipes `key`. It leaves the SDK only with `ok`, after the read-back.
		let armor = walletArmor(key)
		// r7 第 12 项 (b): a held address is never replaced. A colliding address is already_exists, and nothing is written.
		switch BeamioNativeSilentSelect.collision(eoa: eoa, inventory: inventory) {
		case .free: break
		case .alreadyExists: BeamioNativeWallet.wipe(&key); return .failed(.alreadyExists)
		// 12(c): the mnemonic item is named by its address, so an item of this address that does not judge valid cannot be appended beside
		// it. It is kept, never overwritten: the creation is not_ready.
		case .keptNotOverwritten: BeamioNativeWallet.wipe(&key); return .failed(.notReady)
		}
		// item 3: the creation transaction opens before the key is kept, when the device has answered absent (see the shell record).
		BeamioShellRecord.CreationTransactionState.openIfAbsent(account: eoa)
		// 2(b) and (b): the phrase is kept in the native store with the key (intent, mnemonic, key, commit).
		var phraseBytes = Array(words.utf8)
		defer { BeamioNativeWallet.wipe(&phraseBytes) }
		switch BeamioNativeKeyImport.storeDerivedKey(&key, expectedEoa: eoa, store: store, mnemonic: phraseBytes, setPointer: false) {
		case .imported:
			// Y.163 第 12(d) 項: the pointer is set with the checked write and read back. A failed write or read-back is not_ready; the new
			// key is kept (appended, never deleted), and nothing continues to init.
			switch BeamioNativeAccountPointer.writeChecked(eoa) {
			case .written: return .made(Material(eoa: eoa, privateKeyArmor: armor, mnemonicPhrase: words))
			case .mismatch, .unreadable: BeamioShellRecord.CreationTransactionState.cancel(); return .failed(.notReady)
			}
		case .alreadyPresent: BeamioShellRecord.CreationTransactionState.cancel(); return .failed(.alreadyExists)
		case .readBackFailed: BeamioShellRecord.CreationTransactionState.cancel(); return .failed(.readBackFailed)
		default: BeamioShellRecord.CreationTransactionState.cancel(); return .failed(.writeFailed)  // the derived key is valid and unmismatched here; any other result is a write failure
		}
	}

	/// A BIP-39 English phrase of 12 words for 16 bytes of entropy (checksum: the first 4 bits of SHA-256). Nil for any other size.
	static func phrase(entropy: [UInt8]) -> String? {
		guard entropy.count == 16 else { return nil }
		let checksum = Array(SHA256.hash(data: Data(entropy)))[0]
		let bits = entropy + [checksum]
		var words: [String] = []
		for group in 0..<12 {
			var index = 0
			for offset in 0..<11 {
				let bit = group * 11 + offset
				index = (index << 1) | Int((bits[bit / 8] >> UInt8(7 - bit % 8)) & 1)
			}
			words.append(BeamioBip39Wordlist.english[index])
		}
		return words.joined(separator: " ")
	}
}
