import Foundation

/// Native wallet boundary for the local chat library.
///
/// - `localRoot`: derives R_db from the wallet key held in the native store. The key exists only inside this call
/// and its byte copy is zeroed. Missing key → nil → the library stays locked (M-K3, no transfer over the bridge).
/// - `migrateOnce`: the one-time migration for an account on this device: address check,
/// write, read-back check, marker. On any failure the stored state is rolled back, and the caller keeps its copy.
public enum BeamioChatWalletBoundary {
	public enum MigrationResult: String, Equatable {
		/// Stored and verified. The caller may now clear its own old copy.
		case migrated
		/// A key already exists for this account. Nothing was written.
		case alreadyPresent
		/// The one-time migration already ran on this device. Nothing was written.
		case alreadyMigrated
		/// The key is not a 32-byte hex private key.
		case invalidKey
		/// The derived address is not the account address. Nothing was written.
		case addressMismatch
		/// The write or the marker failed. Nothing is left behind.
		case writeFailed
		/// The read-back did not match. The write was removed.
		case readBackFailed
		/// A key is already stored, but it does not derive this account. Refused and kept; nothing is deleted (6.6, 25.6).
		case recordMismatch = "record_mismatch"
	}

	/// R_db for the account, or nil when the native store has no key for it.
	public static func localRoot(eoa rawEoa: String, store: BeamioChatWalletKeyStoring) -> Data? {
		let eoa = rawEoa.lowercased()
		guard var key = store.read(eoa: eoa) else { return nil }
		defer { BeamioNativeWallet.wipe(&key) }
		// A stored key that does not derive the account is never used: the library stays locked (25.6).
		var keyBytes = [UInt8](key)
		defer { BeamioNativeEthSigner.wipe(&keyBytes) }
		guard BeamioNativeEthSigner.address(privateKey: keyBytes)?.lowercased() == eoa else { return nil }
		return BeamioChatLocalCrypto.localRoot(privateKey: key, eoa: eoa, workspace: "default")
	}

	/// One-time migration. `privateKey` is the 32-byte key; the caller owns the array and
	/// wipes it after the call. Phases: `none` → `running` (before the write) → `complete` (after the read-back and the
	/// address check) → `switched` (set by `markSwitched`, after the PWA copy is cleared). Any failure rolls back to `none`
	/// and removes the written key. The PWA copy may be cleared only once the result is `complete`.
	public static func migrateOnce(eoa rawEoa: String, privateKey: [UInt8], store: BeamioChatWalletKeyStoring,
	                               addressOf: ([UInt8]) -> String?) -> MigrationResult {
		let eoa = rawEoa.lowercased()
		let phase = store.migrationPhase(eoa: eoa)
		if let existing = store.read(eoa: eoa) {
			// The stored key must derive this account. If not, the record is refused and kept (6.6, 25.6).
			guard addressOf([UInt8](existing))?.lowercased() == eoa else { return .recordMismatch }
			// A crash after the write but before `complete`: the key is verified above, so record `complete` now.
			if phase == .running {
				_ = store.setMigrationPhase(eoa: eoa, .complete)
			}
			return .alreadyPresent
		}
		if phase == .complete || phase == .switched { return .alreadyMigrated }
		guard BeamioNativeEthSigner.isValidKey(privateKey) else { return .invalidKey }
		guard addressOf(privateKey)?.lowercased() == eoa else { return .addressMismatch }
		guard store.setMigrationPhase(eoa: eoa, .running) else { return .writeFailed }
		var data = Data(privateKey)
		defer { BeamioNativeWallet.wipe(&data) }
		func rollBack(_ result: MigrationResult) -> MigrationResult {
			store.delete(eoa: eoa)
			_ = store.setMigrationPhase(eoa: eoa, .none)
			return result
		}
		guard store.write(eoa: eoa, key: data) else { return rollBack(.writeFailed) }
		// Read-back: the stored bytes must equal the input and derive the same address.
		guard var back = store.read(eoa: eoa), back == data,
		      addressOf([UInt8](back))?.lowercased() == eoa
		else {
			if var b = store.read(eoa: eoa) { BeamioNativeWallet.wipe(&b) }
			return rollBack(.readBackFailed)
		}
		BeamioNativeWallet.wipe(&back)
		guard store.setMigrationPhase(eoa: eoa, .complete) else { return rollBack(.writeFailed) }
		return .migrated
	}

	/// The PWA has cleared its copy (25.6 condition 8). Only `complete` may move to `switched`.
	public static func markSwitched(eoa rawEoa: String, store: BeamioChatWalletKeyStoring) -> Bool {
		let eoa = rawEoa.lowercased()
		switch store.migrationPhase(eoa: eoa) {
		case .switched: return true  // idempotent: the PWA may confirm twice
		case .complete: return store.setMigrationPhase(eoa: eoa, .switched)
		case .none, .running: return false
		}
	}

	/// Hex form, kept for existing callers and tests. Parses straight to bytes; the hex string is not kept.
	public static func migrateOnce(eoa rawEoa: String, privateKeyHex: String, store: BeamioChatWalletKeyStoring,
	                               addressOf: (String) -> String?) -> MigrationResult {
		var keyData = BeamioChatLocalCrypto.bytes(fromHex: BeamioChatWalletKeychain.normalizeKey(privateKeyHex)) ?? Data()
		var key = [UInt8](keyData)
		BeamioNativeWallet.wipe(&keyData)
		defer { BeamioNativeWallet.wipe(&key) }
		return migrateOnce(eoa: rawEoa, privateKey: key, store: store,
		                   addressOf: { addressOf(BeamioChatLocalCrypto.hex(Data($0))) })
	}
}
