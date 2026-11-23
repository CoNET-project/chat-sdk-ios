import CommonCrypto
import CryptoKit
import Foundation

/// Native passcode vault.
///
/// Every passcode here is a byte array (ASCII digits). It is never a String, and the caller wipes its own copy with
/// memset_s after the call. The wallet bundle is the 32-byte EOA key. The hardware layer H is a Secure Enclave key
/// (see BeamioPasscodeKeychain.swift); the passcode layer P is derived by PBKDF2.
public enum BeamioPasscodeKDF {
	public static let iterations = 600_000
	public static let saltLength = 16
	public static let keyLength = 32

	/// PBKDF2-HMAC-SHA256 (CommonCrypto `CCKeyDerivationPBKDF`), 32-byte output. `passcode` is the ASCII digit bytes.
	public static func derive(passcode: [UInt8], salt: [UInt8], iterations: Int = BeamioPasscodeKDF.iterations) -> [UInt8]? {
		var out = [UInt8](repeating: 0, count: keyLength)
		let status = passcode.withUnsafeBufferPointer { pw in
			out.withUnsafeMutableBufferPointer { outBuf in
				salt.withUnsafeBufferPointer { saltBuf in
					pw.withMemoryRebound(to: CChar.self) { pwChars in
						CCKeyDerivationPBKDF(
							CCPBKDFAlgorithm(kCCPBKDF2),
							pwChars.baseAddress, pwChars.count,
							saltBuf.baseAddress, saltBuf.count,
							CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
							UInt32(iterations),
							outBuf.baseAddress, keyLength
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

/// The passcode layer P: AES-256-GCM, 96-bit IV, 128-bit tag. The hardware layer is `BeamioPasscodeHardwareKeyStoring`.
public enum BeamioPasscodeWrap {
	public static func aadH(eoa: String) -> Data { Data("beamio-native-wallet-v1|h|\(eoa.lowercased())".utf8) }
	public static func aadP(eoa: String) -> Data { Data("beamio-native-wallet-v1|p|\(eoa.lowercased())|v1".utf8) }
	/// The mnemonic sealed in a passcode record (frozen protocol §7.1). Same on Android.
	public static func aadM(eoa: String) -> Data { Data("beamio-native-wallet-v1|m|\(eoa.lowercased())|v1".utf8) }

	public static func seal(_ plain: Data, key: SymmetricKey, aad: Data) throws -> Data {
		guard let combined = try AES.GCM.seal(plain, using: key, authenticating: aad).combined else {
			throw BeamioPasscodeError.wrapFailed
		}
		return combined
	}

	public static func open(_ combined: Data, key: SymmetricKey, aad: Data) throws -> Data {
		try AES.GCM.open(try AES.GCM.SealedBox(combined: combined), using: key, authenticating: aad)
	}
}

public enum BeamioPasscodeError: Error, Equatable {
	case wrapFailed
	case noRecord
	case wrongPasscode
	case recordInvalid
	case hardwareUnavailable
}

/// Retired (rule 6): nothing in the SDK calls this any more; kept only so that callers still compile. The page owns the retry count and the cooldown.
/// Backoff: consecutive failures f. f ≤ 4 no cooldown; 5: 30 s; 6: 60 s; 7: 300 s; 8: 900 s; 9 and more: 3600 s.
public enum BeamioPasscodeBackoff {
	public static func cooldownSeconds(consecutiveFailures f: Int) -> Int {
		switch f {
		case ...4: return 0
		case 5: return 30
		case 6: return 60
		case 7: return 300
		case 8: return 900
		default: return 3600
		}
	}
}

/// Flow state machine (the table is in `passcode-vectors.v1.json`, stateMachine).
public enum BeamioPasscodeMode: String, Equatable {
	case enable, change, disable, unlock
}

public enum BeamioPasscodeFlowState: String, Equatable {
	case setupNew = "setup_new"
	case setupConfirm = "setup_confirm"
	case verifyOld = "verify_old"
	case verify
	case unlock
	case done
}

public enum BeamioPasscodeEvent: String, Equatable {
	case submitValid = "submit_valid"
	case submitInvalid = "submit_invalid"
	case submitMatch = "submit_match"
	case submitMismatch = "submit_mismatch"
	case submitWrong = "submit_wrong"
	case cooldown
	case cancel
	case internalError = "internal_error"
}

public struct BeamioPasscodeTransition: Equatable {
	public let to: BeamioPasscodeFlowState
	public let result: String?
	public let message: String?
}

public enum BeamioPasscodeFlow {
	/// The transition for a mode, state and event. nil when the table has no such transition.
	public static func next(mode: BeamioPasscodeMode, from: BeamioPasscodeFlowState,
	                        event: BeamioPasscodeEvent) -> BeamioPasscodeTransition? {
		if event == .cancel { return .init(to: .done, result: "cancelled", message: nil) }
		if event == .internalError { return .init(to: .done, result: "error", message: nil) }
		switch (mode, from, event) {
		case (.enable, .setupNew, .submitValid): return .init(to: .setupConfirm, result: nil, message: nil)
		case (.enable, .setupNew, .submitInvalid): return .init(to: .setupNew, result: nil, message: "policy")
		case (.enable, .setupConfirm, .submitMatch): return .init(to: .done, result: "ok", message: nil)
		case (.enable, .setupConfirm, .submitMismatch): return .init(to: .setupNew, result: nil, message: "mismatch")
		case (.change, .setupNew, .submitValid): return .init(to: .setupConfirm, result: nil, message: nil)
		case (.change, .setupNew, .submitInvalid): return .init(to: .setupNew, result: nil, message: "policy")
		case (.change, .verifyOld, .submitMatch): return .init(to: .setupNew, result: nil, message: nil)
		case (.change, .verifyOld, .submitWrong): return .init(to: .verifyOld, result: nil, message: "wrong")
		case (.change, .verifyOld, .cooldown): return .init(to: .done, result: "backoff", message: nil)
		case (.change, .setupConfirm, .submitMatch): return .init(to: .done, result: "ok", message: nil)
		case (.change, .setupConfirm, .submitMismatch): return .init(to: .setupNew, result: nil, message: "mismatch")
		case (.disable, .verify, .submitMatch): return .init(to: .done, result: "ok", message: nil)
		case (.disable, .verify, .submitWrong): return .init(to: .verify, result: nil, message: "wrong")
		case (.disable, .verify, .cooldown): return .init(to: .done, result: "backoff", message: nil)
		case (.unlock, .unlock, .submitMatch): return .init(to: .done, result: "ok", message: nil)
		case (.unlock, .unlock, .submitWrong): return .init(to: .unlock, result: nil, message: "wrong")
		case (.unlock, .unlock, .cooldown): return .init(to: .done, result: "backoff", message: nil)
		default: return nil
		}
	}
}

/// One wallet record per account on this device. `device` holds the bundle wrapped by H only;
/// `passcode` holds it wrapped by P around H. No passcode, no derived key and no plaintext key is in it.
/// The failure count is kept with the record (item 4).
public struct BeamioPasscodeRecord: Codable, Equatable {
	public var version: Int = 1
	public var mode: String
	public var salt: Data?
	public var blob: Data
	public var failures: Int = 0
	public var lastFailureAt: Double?
	/// The mnemonic sealed under the same P key as the key bundle, with the `|m|` AAD (frozen protocol §7.1). nil: no mnemonic in this record
	/// (a record written before the shell passcode protocol, or a device record).
	public var mnemonicBlob: Data?
}

/// A Keychain lookup distinguishes an absent account from a lookup failure. Callers must not use an access error as a missing record.
public enum BeamioPasscodeRecordRead: Equatable {
	case absent
	case present(Data)
	case unavailable
}

/// Where records are kept. Production: Keychain, ThisDeviceOnly (BeamioPasscodeKeychain.swift). Tests: memory.
public protocol BeamioPasscodeRecordStoring: AnyObject {
	func readRecord(eoa: String) -> Data?
	func readRecordState(eoa: String) -> BeamioPasscodeRecordRead
	func writeRecord(eoa: String, _ data: Data) -> Bool
	func deleteRecord(eoa: String)
	/// Whether any record of this store exists, for any account. A store that cannot enumerate answers true (fail closed).
	func hasAnyRecord() -> Bool
	/// The account names of every record of this store. nil: the store cannot list them (fail closed).
	func enumerateRecordOwners() -> [String]?
	/// The creation time of every record of this store (Y.163 第 5 項), from the attributes only. nil: the store cannot list them.
	func enumerateRecordCreations() -> [BeamioChatKeyCreation]?
}

extension BeamioPasscodeRecordStoring {
	/// Legacy test stores that only expose an optional answer cannot report an access error; production stores must override this method.
	public func readRecordState(eoa: String) -> BeamioPasscodeRecordRead {
		if let data = readRecord(eoa: eoa) { return .present(data) }
		return .absent
	}
	/// A store with no records of its own (a test store). The product store overrides it.
	public func hasAnyRecord() -> Bool { false }
	/// A store that cannot list its records answers nil (fail closed). The product store overrides it.
	public func enumerateRecordOwners() -> [String]? { nil }
	public func enumerateRecordCreations() -> [BeamioChatKeyCreation]? { nil }
}

/// The hardware layer H for an account. Production: a Secure Enclave P-256 key that wraps with ECIES, or the Keychain
/// fallback where no Secure Enclave exists (BeamioPasscodeKeychain.swift). The AAD is bound into the wrapped data.
public protocol BeamioPasscodeHardwareKeyStoring: AnyObject {
	/// True for a Secure Enclave key (non-exportable). False for the Keychain fallback, which does not have that property.
	var isSecureEnclave: Bool { get }
	func hasKey(eoa: String) -> Bool
	func createKey(eoa: String) -> Bool
	func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data
	func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data
	func deleteKey(eoa: String)
	/// Whether H of this account exists: `absent` only when the lookup confirmed that there is none. A lookup that failed in any other way is
	/// `unknown` (a locked device, a busy Keychain): not "missing" (keep the data; frozen protocol §3.3).
	func keyState(eoa: String) -> BeamioPasscodeHardwareKeyState
}

public enum BeamioPasscodeHardwareKeyState: Equatable {
	case present
	case absent
	case unknown
}

extension BeamioPasscodeHardwareKeyStoring {
	/// A store that cannot tell a failed lookup from a missing key answers from `hasKey`.
	public func keyState(eoa: String) -> BeamioPasscodeHardwareKeyState { hasKey(eoa: eoa) ? .present : .absent }
}

/// Enable, change, disable and unlock on a record. The passcodes are byte arrays owned by the caller, who wipes them.
public final class BeamioPasscodeVault {
	public enum ProtectionState: Equatable {
		case absent
		case device
		case passcode
		case unavailable
	}
	public enum Outcome: Error, Equatable {
		case ok
		case policy(String)
		case wrong
		case backoff(Int)
		case noRecord
		case unavailable
		case failed
	}

	let records: BeamioPasscodeRecordStoring
	let hardware: BeamioPasscodeHardwareKeyStoring
	/// The staging records of the shell passcode writes (frozen protocol §9.1): a separate store, so that a staged record is never taken for
	/// another account's record when the owners are listed.
	let staging: BeamioPasscodeRecordStoring
	private let now: () -> Date

	public init(records: BeamioPasscodeRecordStoring, hardware: BeamioPasscodeHardwareKeyStoring,
	            staging: BeamioPasscodeRecordStoring = BeamioPasscodeKeychainRecords.staging,
	            now: @escaping () -> Date = { Date() }) {
		self.records = records
		self.hardware = hardware
		self.staging = staging
		self.now = now
	}

	/// `passcodeStatus`: whether a passcode is set. Lock state belongs to `BeamioPasscodeSession`.
	public func isSet(eoa: String) -> Bool {
		protectionState(eoa: eoa) == .passcode
	}

	/// The passcode-record read status; lookup failures stay unavailable rather than looking like no record.
	public func protectionState(eoa: String) -> ProtectionState {
		switch records.readRecordState(eoa: eoa.lowercased()) {
		case .absent: return .absent
		case .unavailable: return .unavailable
		case .present(let data):
			guard let record = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: data) else { return .unavailable }
			switch record.mode {
			case "device": return .device
			case "passcode": return .passcode
			default: return .unavailable
			}
		}
	}

	/// Kept for source compatibility only. rule 6: the SDK keeps no cooldown, so this is always 0 (an attempt may always be made;
	/// the page owns the retry count and the cooldown).
	public func cooldownLeft(eoa: String) -> Int {
		return 0
	}

	/// Enable (device key → passcode). The new record is written, read back and verified before it is kept.
	public func enable(eoa rawEoa: String, passcode: [UInt8]) -> Outcome {
		let eoa = rawEoa.lowercased()
		if let reason = BeamioPasscodeRules.refusal(passcode) { return .policy(reason) }
		let state = records.readRecordState(eoa: eoa)
		guard case .present(let oldRaw) = state else {
			if case .unavailable = state { return .unavailable }
			return .noRecord
		}
		guard let current = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: oldRaw), current.mode == "device",
		      var bundle = unwrapDevice(current, eoa: eoa) else { return .unavailable }
		defer { BeamioNativeWallet.wipe(&bundle) }
		// a passcode change refreshes the native-key snapshot in the same critical section (25.52Y.70 第 4 項).
		return BeamioNativeKeySnapshot.mutate { replace(eoa: eoa, bundle: bundle, passcode: passcode, oldRaw: oldRaw) }
	}

	/// Change: verify the old passcode, then write a record for the new one.
	public func change(eoa rawEoa: String, oldPasscode: [UInt8], newPasscode: [UInt8]) -> Outcome {
		let eoa = rawEoa.lowercased()
		if let reason = BeamioPasscodeRules.refusal(newPasscode) { return .policy(reason) }
		switch unlockBundle(eoa: eoa, passcode: oldPasscode) {
		case .success(var bundle):
			defer { BeamioNativeWallet.wipe(&bundle) }
			let state = records.readRecordState(eoa: eoa)
			guard case .present(let oldRaw) = state else {
				if case .unavailable = state { return .unavailable }
				return .noRecord
			}
			// a passcode change refreshes the native-key snapshot in the same critical section (25.52Y.70 第 4 項).
			return BeamioNativeKeySnapshot.mutate { replace(eoa: eoa, bundle: bundle, passcode: newPasscode, oldRaw: oldRaw) }
		case .failure(let outcome):
			return outcome
		}
	}

	/// Disable: verify, then write a device-key record.
	public func disable(eoa rawEoa: String, passcode: [UInt8]) -> Outcome {
		let eoa = rawEoa.lowercased()
		switch unlockBundle(eoa: eoa, passcode: passcode) {
		case .success(var bundle):
			defer { BeamioNativeWallet.wipe(&bundle) }
			let state = records.readRecordState(eoa: eoa)
			guard case .present(let oldRaw) = state,
			      let blob = try? hardware.wrap(bundle, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))
			else {
				if case .unavailable = state { return .unavailable }
				return .failed
			}
			let next = BeamioPasscodeRecord(mode: "device", salt: nil, blob: blob)
			// a passcode change refreshes the native-key snapshot in the same critical section (25.52Y.70 第 4 項).
			return BeamioNativeKeySnapshot.mutate { writeVerified(eoa: eoa, next: next, bundle: bundle, oldRaw: oldRaw, passcode: nil) }
		case .failure(let outcome):
			return outcome
		}
	}

	/// Unlock. The bundle goes to the caller, who keeps it in memory only and wipes it when locking.
	public func unlock(eoa rawEoa: String, passcode: [UInt8]) -> Result<[UInt8], Outcome> {
		let eoa = rawEoa.lowercased()
		switch unlockBundle(eoa: eoa, passcode: passcode) {
		case .success(let bundle): return .success(Array(bundle))
		case .failure(let outcome): return .failure(outcome)
		}
	}

	// MARK: - Private

	private func load(eoa: String) -> BeamioPasscodeRecord? {
		guard let data = records.readRecord(eoa: eoa) else { return nil }
		return try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: data)
	}

	private func unwrapDevice(_ r: BeamioPasscodeRecord, eoa: String) -> Data? {
		try? hardware.unwrap(r.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))
	}

	/// Unlock for the flows that need the bundle. Applies the cooldown first and counts failures.
	private func unlockBundle(eoa: String, passcode: [UInt8]) -> Result<Data, Outcome> {
		let r: BeamioPasscodeRecord
		switch records.readRecordState(eoa: eoa) {
		case .absent: return .failure(.noRecord)
		case .unavailable: return .failure(.unavailable)
		case .present(let data):
			guard let decoded = try? JSONDecoder().decode(BeamioPasscodeRecord.self, from: data) else { return .failure(.unavailable) }
			r = decoded
		}
		guard r.mode == "passcode", let salt = r.salt else { return .failure(.noRecord) }
		// rule 6: the SDK keeps no retry count and no cooldown; the page owns both. Nothing is read from `failures` or `lastFailureAt`
		// (the fields stay in the record, decodable, unchanged) and a wrong passcode writes nothing.
		guard var p = BeamioPasscodeKDF.derive(passcode: passcode, salt: Array(salt)) else { return .failure(.failed) }
		defer { BeamioNativeWallet.wipe(&p) }
		let pKey = SymmetricKey(data: Data(p))
		if let inner = try? BeamioPasscodeWrap.open(r.blob, key: pKey, aad: BeamioPasscodeWrap.aadP(eoa: eoa)),
		   hardware.keyState(eoa: eoa) != .present || (try? hardware.unwrap(inner, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))) == nil {
			// The passcode layer opened, so the passcode is right: a hardware layer that is missing or cannot be used now is not a wrong passcode,
			// and it is not counted (frozen protocol §3.3).
			return .failure(.unavailable)
		}
		if let inner = try? BeamioPasscodeWrap.open(r.blob, key: pKey, aad: BeamioPasscodeWrap.aadP(eoa: eoa)),
		   let bundle = try? hardware.unwrap(inner, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)) {
			return .success(bundle)
		}
		return .failure(.wrong)
	}

	/// Writes the passcode record for `bundle`, reads it back, and keeps it only if it verifies.
	private func replace(eoa: String, bundle: Data, passcode: [UInt8], oldRaw: Data) -> Outcome {
		var salt = [UInt8](repeating: 0, count: BeamioPasscodeKDF.saltLength)
		guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess,
		      var p = BeamioPasscodeKDF.derive(passcode: passcode, salt: salt)
		else { return .failed }
		defer { BeamioNativeWallet.wipe(&p) }
		guard let inner = try? hardware.wrap(bundle, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa)),
		      let blob = try? BeamioPasscodeWrap.seal(inner, key: SymmetricKey(data: Data(p)), aad: BeamioPasscodeWrap.aadP(eoa: eoa))
		else { return .failed }
		let next = BeamioPasscodeRecord(mode: "passcode", salt: Data(salt), blob: blob)
		// a passcode change refreshes the native-key snapshot in the same critical section (25.52Y.70 第 4 項).
		return BeamioNativeKeySnapshot.mutate { writeVerified(eoa: eoa, next: next, bundle: bundle, oldRaw: oldRaw, passcode: passcode) }
	}

	private func writeVerified(eoa: String, next: BeamioPasscodeRecord, bundle: Data, oldRaw: Data,
	                           passcode: [UInt8]?) -> Outcome {
		guard let nextData = try? JSONEncoder().encode(next), records.writeRecord(eoa: eoa, nextData) else { return .failed }
		// Read back: the record decodes, and it gives back the same bundle (device: H only; passcode: P then H).
		var ok = false
		if let back = load(eoa: eoa) {
			if next.mode == "device" {
				ok = (try? hardware.unwrap(back.blob, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))) == bundle
			} else if let passcode, let salt = back.salt, var p = BeamioPasscodeKDF.derive(passcode: passcode, salt: Array(salt)) {
				let pKey = SymmetricKey(data: Data(p))
				BeamioNativeWallet.wipe(&p)
				if let inner = try? BeamioPasscodeWrap.open(back.blob, key: pKey, aad: BeamioPasscodeWrap.aadP(eoa: eoa)) {
					ok = (try? hardware.unwrap(inner, eoa: eoa, aad: BeamioPasscodeWrap.aadH(eoa: eoa))) == bundle
				}
			}
		}
		if !ok {
			_ = records.writeRecord(eoa: eoa, oldRaw)
			return .failed
		}
		return .ok
	}
}
