import CryptoKit
import Foundation

/// The shell passcode operations of the frozen protocol PROTOCOL-shell-passcode-v1 (SHA-256 adb8b71a…):
/// provision, unlock, change, disable and repair of one passcode record, on the vault's record and hardware stores.
///
/// - One record per account holds the key bundle (P around H) and the mnemonic (`mnemonicBlob`, P only, AAD `|m|`), under one salt and one P key.
/// - The native layer never counts a wrong passcode and never cools down (§3.2, §5.3): the page owns the backoff. An unlock writes nothing.
/// - A write goes to the staging store first, is read back, opened and compared (bundle, phrase, address), and only then replaces the record
///   (§9.1). Nothing is deleted first. A record that cannot be read is never overwritten.
/// - Results carry codes only. The passcode, the phrase and the keys are byte arrays owned by the caller, who wipes them.
public enum BeamioShellPasscodeResult: Error, Equatable {
	/// `address`: derived natively from the record that was read back (never the caller's `eoa`).
	case ok(address: String)
	case fail(String, reason: String? = nil)
}

/// An unlocked record: the bundle, the P key and the phrase (when the record has one). The holder wipes it.
public final class BeamioShellUnlocked {
	public var bundle: [UInt8]
	public var pKey: [UInt8]
	public var phrase: [UInt8]?

	init(bundle: [UInt8], pKey: [UInt8], phrase: [UInt8]?) {
		self.bundle = bundle
		self.pKey = pKey
		self.phrase = phrase
	}

	public func wipe() {
		BeamioNativeWallet.wipe(&bundle)
		BeamioNativeWallet.wipe(&pKey)
		if phrase != nil { BeamioNativeWallet.wipe(&phrase!) }
		phrase = nil
	}
}

extension BeamioPasscodeVault {
	// MARK: - Reading

	enum ShellRecord {
		case absent
		case unavailable
		case invalid
		case device(BeamioPasscodeRecord)
		case passcode(BeamioPasscodeRecord)
	}

	func shellRecord(eoa: String) -> ShellRecord {
		switch records.readRecordState(eoa: eoa) {
		case .absent: return .absent
		case .unavailable: return .unavailable
		case .present(let raw):
			guard let r = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw) else { return .invalid }
			switch r.mode {
			case "device": return .device(r)
			case "passcode": return r.salt == nil ? .invalid : .passcode(r)
			default: return .invalid
			}
		}
	}

	/// `passcodeStatus`: `set` is true for a passcode record; `known` is false when the record cannot be read now.
	public func shellStatus(eoa rawEoa: String) -> (set: Bool, known: Bool) {
		switch shellRecord(eoa: rawEoa.lowercased()) {
		case .passcode: return (true, true)
		case .device, .absent: return (false, true)
		case .unavailable, .invalid: return (false, false)
		}
	}

	// MARK: - Unlock (uncounted)

	/// Opens the record with `passcode`. Writes nothing and counts nothing, whatever the answer. Failure codes: `not_ready` (the record or H cannot be
	/// read now: retry, no repair), `no_record`, `not_set` (a device record), `record_invalid` (the record is unusable, or H is confirmed missing:
	/// repair may follow), `wrong_passcode`.
	public func shellUnlock(eoa rawEoa: String, passcode: [UInt8]) -> Result<BeamioShellUnlocked, BeamioShellPasscodeResult> {
		let eoa = rawEoa.lowercased()
		switch shellRecord(eoa: eoa) {
		case .absent: return .failure(.fail("no_record"))
		case .unavailable: return .failure(.fail("not_ready"))
		case .invalid: return .failure(.fail("record_invalid"))
		case .device: return .failure(.fail("not_set"))
		case .passcode(let r):
			guard let salt = r.salt, var p = BeamioPasscodeKDF.derive(passcode: passcode, salt: Array(salt)) else {
				return .failure(.fail("not_ready"))
			}
			let pKey = SymmetricKey(data: Data(p))
			// A wrong passcode and a damaged blob look the same here: the tag fails. That is `wrong_passcode`; a repair is then offered by the
			// page only after the UI unlock succeeded (§5.4).
			guard let inner = try? BeamioPasscodeWrap.open(r.blob, key: pKey, aad: BeamioPasscodeWrap.aadP(eoa: eoa)) else {
				BeamioNativeWallet.wipe(&p)
				return .failure(.fail("wrong_passcode"))
			}
			guard var bundle = try? hardware.unwrap(inner, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else {
				BeamioNativeWallet.wipe(&p)
				// The passcode layer opened, so the passcode is right. H: confirmed missing is `record_invalid`; any other failure is not_ready.
				// Missing for certain: record_invalid (repair may follow). Present but not usable now, or unknown: not_ready (retry; no repair, no overwrite).
				return .failure(.fail(hardware.keyState(eoa: eoa) == .absent ? "record_invalid" : "not_ready"))
			}
			var phrase: [UInt8]?
			if let blob = r.mnemonicBlob {
				guard let plain = try? BeamioPasscodeWrap.open(blob, key: pKey, aad: BeamioPasscodeWrap.aadM(eoa: eoa)) else {
					BeamioNativeWallet.wipe(&p)
					BeamioNativeWallet.wipe(&bundle)
					return .failure(.fail("record_invalid"))
				}
				phrase = [UInt8](plain)
			}
			let unlocked = BeamioShellUnlocked(bundle: [UInt8](bundle), pKey: p, phrase: phrase)
			BeamioNativeWallet.wipe(&bundle)
			return .success(unlocked)
		}
	}

	// MARK: - Staged write

	/// A record built for `bundle` and `phrase` under `passcode`: new salt, H around the bundle, P around that, the phrase under P with `|m|`.
	private func buildPasscodeRecord(eoa: String, bundle: Data, phrase: Data?, passcode: [UInt8]) -> BeamioPasscodeRecord? {
		var salt = [UInt8](repeating: 0, count: BeamioPasscodeKDF.saltLength)
		guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess,
		      var p = BeamioPasscodeKDF.derive(passcode: passcode, salt: salt) else { return nil }
		defer { BeamioNativeWallet.wipe(&p) }
		let pKey = SymmetricKey(data: Data(p))
		guard let inner = try? hardware.wrap(bundle, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)),
		      let blob = try? BeamioPasscodeWrap.seal(inner, key: pKey, aad: BeamioPasscodeWrap.aadP(eoa: eoa)) else { return nil }
		var record = BeamioPasscodeRecord(mode: "passcode", salt: Data(salt), blob: blob)
		if let phrase {
			guard let sealed = try? BeamioPasscodeWrap.seal(phrase, key: pKey, aad: BeamioPasscodeWrap.aadM(eoa: eoa)) else { return nil }
			record.mnemonicBlob = sealed
		}
		return record
	}

	/// Opens `record` with `passcode` and returns the address derived from the bundle, when the bundle, and the phrase when `expectPhrase` is given,
	/// are what was written. The readback proof of every write.
	private func verifyPasscodeRecord(_ record: BeamioPasscodeRecord, eoa: String, passcode: [UInt8], bundle: Data, expectPhrase: Data?) -> String? {
		guard let salt = record.salt, var p = BeamioPasscodeKDF.derive(passcode: passcode, salt: Array(salt)) else { return nil }
		defer { BeamioNativeWallet.wipe(&p) }
		let pKey = SymmetricKey(data: Data(p))
		guard let inner = try? BeamioPasscodeWrap.open(record.blob, key: pKey, aad: BeamioPasscodeWrap.aadP(eoa: eoa)),
		      var back = try? hardware.unwrap(inner, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else { return nil }
		defer { BeamioNativeWallet.wipe(&back) }
		guard back == bundle else { return nil }
		if let expectPhrase {
			guard var plain = try? BeamioPasscodeWrap.open(record.mnemonicBlob ?? Data(), key: pKey, aad: BeamioPasscodeWrap.aadM(eoa: eoa)) else { return nil }
			defer { BeamioNativeWallet.wipe(&plain) }
			guard plain == expectPhrase else { return nil }
		}
		return BeamioNativeEthSigner.address(privateKey: [UInt8](back))?.lowercased()
	}

	/// Stages `next`, reads it back and proves it with `prove`, then replaces the record and clears the staging copy (§9.1). A record that cannot
	/// be read is not overwritten (`not_ready`). Any failure leaves the record as it was.
	private func stagedReplace(eoa: String, next: BeamioPasscodeRecord, prove: (BeamioPasscodeRecord) -> String?) -> BeamioShellPasscodeResult {
		guard let data = try? JSONEncoder().encode(next) else { return .fail("write_failed", reason: "internal_state") }
		// the staging copy below belongs to a write in progress until this function ends, on every path (the cleanup must not take it for a leftover)
		BeamioPasscodeWriteMarker.begin(eoa)
		defer { BeamioPasscodeWriteMarker.end(eoa) }
		let old: Data?
		switch records.readRecordState(eoa: eoa) {
		case .unavailable: return .fail("not_ready")
		case .absent: old = nil
		case .present(let raw): old = raw
		}
		guard staging.writeRecord(eoa: eoa, data) else { return .fail("write_failed", reason: "storage_write") }
		guard case .present(let stagedRaw) = staging.readRecordState(eoa: eoa), stagedRaw == data,
		      let stagedRecord = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: stagedRaw),
		      let address = prove(stagedRecord) else {
			staging.deleteRecord(eoa: eoa)
			return .fail("write_failed", reason: "readback_mismatch")
		}
		let replaced = BeamioNativeKeySnapshot.mutate { () -> Bool in
			guard records.writeRecord(eoa: eoa, data), case .present(let back) = records.readRecordState(eoa: eoa), back == data else {
				if let old { _ = records.writeRecord(eoa: eoa, old) } else { records.deleteRecord(eoa: eoa) }
				return false
			}
			return true
		}
		guard replaced else {
			staging.deleteRecord(eoa: eoa)
			return .fail("write_failed", reason: "storage_write")
		}
		staging.deleteRecord(eoa: eoa)
		return .ok(address: address)
	}

	private func ensureHardwareKey(eoa: String) -> Bool? {
		switch hardware.keyState(eoa: eoa) {
		case .present: return true
		case .unknown: return nil
		case .absent: return hardware.createKey(eoa: eoa)
		}
	}

	/// Writes a passcode record for `bundle` / `phrase`. `bundle` must derive `eoa`.
	private func commitPasscode(eoa: String, bundle: Data, phrase: Data?, passcode: [UInt8]) -> BeamioShellPasscodeResult {
		guard BeamioNativeEthSigner.address(privateKey: [UInt8](bundle))?.lowercased() == eoa else { return .fail("address_mismatch") }
		guard let hardwareReady = ensureHardwareKey(eoa: eoa) else { return .fail("not_ready") }
		guard hardwareReady else { return .fail("write_failed", reason: "storage_write") }
		guard let record = buildPasscodeRecord(eoa: eoa, bundle: bundle, phrase: phrase, passcode: passcode) else {
			return .fail("write_failed", reason: "internal_state")
		}
		return stagedReplace(eoa: eoa, next: record) {
			verifyPasscodeRecord($0, eoa: eoa, passcode: passcode, bundle: bundle, expectPhrase: phrase)
		}
	}

	/// The key bundle derived from a phrase, with the checks of §3.1: BIP-39, and the address equals `eoa`.
	private func bundleFromPhrase(_ phrase: [UInt8], eoa: String) -> Result<Data, BeamioShellPasscodeResult> {
		guard case .key(var key) = BeamioMnemonicDerivation.derive(phrase: String(decoding: phrase, as: UTF8.self)) else {
			return .failure(.fail("eoa_mismatch"))
		}
		defer { BeamioNativeWallet.wipe(&key) }
		guard BeamioNativeEthSigner.address(privateKey: key)?.lowercased() == eoa else { return .failure(.fail("eoa_mismatch")) }
		return .success(Data(key))
	}

	// MARK: - Commands

	/// `passcodeProvision` (§3.1). A passcode record of this account already: `already_set`, nothing written. A device record of this account: its
	/// key must be the phrase's key (else `address_mismatch`), and it becomes a passcode record. No record: the record is created from the phrase.
	public func shellProvision(eoa rawEoa: String, phrase: [UInt8], passcode: [UInt8]) -> BeamioShellPasscodeResult {
		let eoa = rawEoa.lowercased()
		if let reason = BeamioPasscodeRules.refusal(passcode) { return .fail("weak_passcode", reason: reason) }
		switch shellRecord(eoa: eoa) {
		case .passcode: return .fail("already_set")
		case .unavailable: return .fail("not_ready")
		case .invalid: return .fail("record_invalid")
		case .absent, .device: break
		}
		switch bundleFromPhrase(phrase, eoa: eoa) {
		case .failure(let result): return result
		case .success(var bundle):
			defer { BeamioNativeWallet.wipe(&bundle) }
			if case .device(let device) = shellRecord(eoa: eoa) {
				// The existing device key must be the same key.
				guard var current = try? hardware.unwrap(device.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else { return .fail("not_ready") }
				defer { BeamioNativeWallet.wipe(&current) }
				guard current == bundle else { return .fail("address_mismatch") }
			}
			return commitPasscode(eoa: eoa, bundle: bundle, phrase: Data(phrase), passcode: passcode)
		}
	}

	/// `nativeRepairProvide` write (§3.4): the record is rebuilt from the verified phrase under the same passcode, whatever the old record held. The
	/// old record is replaced only after the new one is read back and proven; a record that cannot be read now is not overwritten.
	public func shellRepair(eoa rawEoa: String, phrase: [UInt8], passcode: [UInt8]) -> BeamioShellPasscodeResult {
		let eoa = rawEoa.lowercased()
		if let reason = BeamioPasscodeRules.refusal(passcode) { return .fail("weak_passcode", reason: reason) }
		switch bundleFromPhrase(phrase, eoa: eoa) {
		case .failure(let result): return result
		case .success(var bundle):
			defer { BeamioNativeWallet.wipe(&bundle) }
			return commitPasscode(eoa: eoa, bundle: bundle, phrase: Data(phrase), passcode: passcode)
		}
	}

	/// `passcodeChange` (§3.5): the old passcode opens the record (uncounted), the new one rewraps both parts in one record.
	public func shellChange(eoa rawEoa: String, oldPasscode: [UInt8], newPasscode: [UInt8]) -> BeamioShellPasscodeResult {
		let eoa = rawEoa.lowercased()
		if let reason = BeamioPasscodeRules.refusal(newPasscode) { return .fail("weak_passcode", reason: reason) }
		switch shellUnlock(eoa: eoa, passcode: oldPasscode) {
		case .failure(let result): return result
		case .success(let unlocked):
			defer { unlocked.wipe() }
			return commitPasscode(eoa: eoa, bundle: Data(unlocked.bundle), phrase: unlocked.phrase.map { Data($0) }, passcode: newPasscode)
		}
	}

	/// `passcodeDisable` (§3.6): the passcode layer goes, the key and the phrase stay under the device layer. `restorePhrase` puts the phrase back into the
	/// device-bound item first; if it fails nothing is changed. The device record is staged, read back and proven before it replaces the record.
	public func shellDisable(eoa rawEoa: String, passcode: [UInt8], restorePhrase: (Data) -> Bool) -> BeamioShellPasscodeResult {
		let eoa = rawEoa.lowercased()
		switch shellUnlock(eoa: eoa, passcode: passcode) {
		case .failure(let result): return result
		case .success(let unlocked):
			defer { unlocked.wipe() }
			if let phrase = unlocked.phrase {
				guard restorePhrase(Data(phrase)) else { return .fail("write_failed", reason: "storage_write") }
			}
			let bundle = Data(unlocked.bundle)
			guard let blob = try? hardware.wrap(bundle, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else { return .fail("not_ready") }
			let next = BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob)
			return stagedReplace(eoa: eoa, next: next) { record in
				guard var back = try? hardware.unwrap(record.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) else { return nil }
				defer { BeamioNativeWallet.wipe(&back) }
				guard back == bundle else { return nil }
				return BeamioNativeEthSigner.address(privateKey: [UInt8](back))?.lowercased()
			}
		}
	}

	/// The staging copy of an account at start (§9.1). No staging copy: `clean`. A decodable main record: the stale staging copy is removed.
	/// A main record that cannot be decoded while the staging copy can: neither is touched, `rollback_pending`.
	public func shellReconcileStaging(eoa rawEoa: String) -> String {
		// the staging copy is handled here (a stale one is removed): a write of the account for the cleanup's purposes until this returns
		BeamioPasscodeWriteMarker.begin(rawEoa)
		defer { BeamioPasscodeWriteMarker.end(rawEoa) }
		let eoa = rawEoa.lowercased()
		switch staging.readRecordState(eoa: eoa) {
		case .absent: return "clean"
		case .unavailable: return "not_ready"
		case .present(let raw):
			switch shellRecord(eoa: eoa) {
			case .passcode, .device:
				staging.deleteRecord(eoa: eoa)
				return "clean"
			case .absent, .invalid:
				return (try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: raw)) != nil ? "rollback_pending" : "clean"
			case .unavailable:
				return "not_ready"
			}
		}
	}
}
