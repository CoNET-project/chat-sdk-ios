import Foundation

/// PGP identity restore for a migrated account. The source of the
/// backup is decided by P-IMP-PGP (plan A proposed: the EOA-encrypted on-chain backup). This module takes the backup and
/// the old public key as inputs and fetches neither. It stores the record only when the restored private key and the old
/// public key have the same primary fingerprint and subkey key ID (checked by the X-19 wrapper, which is required).
///
/// Steps: idempotent when complete; phase `restoring`; password from the EOA key (not kept); decrypt (P-IMP-PGP);
/// identity check; save to the PGP keychain record; read back; phase `complete`. A failure at any step leaves the phase at
/// `restoring`, and a retry runs the steps again. The phase marker is a flag per account. It holds no key material.
///
/// The PGP keychain holds one record per device, so restoring a second account replaces the first. This is a limit to
/// settle with the before a multi-account device is supported.
public enum BeamioPGPMigration {
	public enum Phase: String, Equatable {
		case restoring
		case complete
	}

	/// The result of a restore: restored, or refused with the code that stopped it (the phase stays `restoring`).
	public enum Outcome: Equatable {
		case restored
		case refused(String)
	}

	static func phaseKey(_ eoa: String) -> String {
		"beamio.pgp.migration.v1." + eoa.lowercased()
	}

	public static func phase(eoa: String) -> Phase? {
		BeamioNativeAccountPointer.defaults.string(forKey: phaseKey(eoa)).flatMap(Phase.init(rawValue:))
	}

	static func setPhase(_ value: Phase?, eoa: String) {
		if let value {
			BeamioNativeAccountPointer.defaults.set(value.rawValue, forKey: phaseKey(eoa))
		} else {
			BeamioNativeAccountPointer.defaults.removeObject(forKey: phaseKey(eoa))
		}
	}

	/// Restores the PGP record of `eoa` from `backupBase64` and checks it against `oldPublicArmor`.
	public static func restore(eoa rawEoa: String, backupBase64: String, oldPublicArmor: String) -> Outcome {
		let eoa = rawEoa.lowercased()
		if phase(eoa: eoa) == .complete { return .restored }
		setPhase(.restoring, eoa: eoa)

		let password: String
		switch BeamioNativeWallet.withAccountKey(eoa: eoa, { BeamioChatRouteRegister.passwordString(privateKey: $0) }) {
		case .success(let value):
			password = value
		case .failure(.locked):
			return .refused("locked")
		case .failure(.walletKeyMissing):
			return .refused("no_key")
		case .failure:
			return .refused("account_mismatch")
		}

		let armor: String
		switch BeamioPGPBackup.decrypt(base64: backupBase64, passwordString: password) {
		case .success(let value):
			armor = value
		case .failure:
			return .refused("decrypt_failed")
		}

		// Identity: the restored private key and the old public key must be the same PGP key. The check needs X-19.
		guard let restored = BeamioPGPBackup.keyIdentity(armor: armor),
		      let old = BeamioPGPBackup.keyIdentity(armor: oldPublicArmor)
		else {
			return .refused("identity_unverified")
		}
		guard restored.fingerprint == old.fingerprint, restored.subkeyKeyID == old.subkeyKeyID else {
			return .refused("identity_mismatch")
		}

		let record = BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: armor, publicKeyArmor: oldPublicArmor, pgpKeyId: old.subkeyKeyID,
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa
		)
		guard BeamioChatPgpKeychain.save(record) else {
			return .refused("save_failed")
		}
		guard let back = BeamioChatPgpKeychain.load(eoa: eoa),
		      back.privateKeyArmor == armor, back.publicKeyArmor == oldPublicArmor, back.eoa.lowercased() == eoa
		else {
			return .refused("readback_mismatch")
		}
		setPhase(.complete, eoa: eoa)
		return .restored
	}
}
