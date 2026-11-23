import Foundation

/// The result code of one passcode run: `ok`, `cancelled`, `backoff` (with the seconds left) or `error`.
public enum BeamioPasscodeRunResult: Equatable {
	case ok
	case cancelled
	case backoff(Int)
	case error

	public var code: String {
		switch self {
		case .ok: return "ok"
		case .cancelled: return "cancelled"
		case .backoff: return "backoff"
		case .error: return "error"
		}
	}
}

/// Drives one passcode flow from the digits the native overlay gives it. The digits are byte arrays and are
/// wiped when the run ends. Nothing here returns a passcode, a derived key or a wrapped record.
///
/// enable: setup_new → setup_confirm → (match) write the record.
/// change: verify_old → setup_new → setup_confirm → (match) write the new record.
/// disable: verify → (match) write a device-key record.
/// unlock: unlock → (match) install the bundle in the session.
public final class BeamioPasscodeRunner {
	public struct Step: Equatable {
		public let state: BeamioPasscodeFlowState
		public let message: String?
		public let result: BeamioPasscodeRunResult?
	}

	public let mode: BeamioPasscodeMode
	private let eoa: String
	private let vault: BeamioPasscodeVault
	private let session: BeamioPasscodeSession
	private var state: BeamioPasscodeFlowState
	private var newPasscode: [UInt8]?
	private var oldPasscode: [UInt8]?
	private var finished: BeamioPasscodeRunResult?

	public init(mode: BeamioPasscodeMode, eoa rawEoa: String, vault: BeamioPasscodeVault, session: BeamioPasscodeSession) {
		self.mode = mode
		self.eoa = rawEoa.lowercased()
		self.vault = vault
		self.session = session
		switch mode {
		case .enable: state = .setupNew
		case .change: state = .verifyOld
		case .disable: state = .verify
		case .unlock: state = .unlock
		}
	}

	/// The state the run is in now.
	public var current: BeamioPasscodeFlowState { state }

	/// The user cancelled (or the overlay was dismissed).
	public func cancel() -> Step {
		finish(.cancelled)
	}

	/// The digits the user entered for the current step. The array is copied; the caller wipes its own.
	public func submit(_ digits: [UInt8]) -> Step {
		if finished != nil { return Step(state: .done, message: nil, result: finished) }
		switch state {
		case .setupNew:
			if BeamioPasscodeRules.refusal(digits) != nil {
				return Step(state: .setupNew, message: "policy", result: nil)
			}
			wipeNew()
			newPasscode = digits
			state = .setupConfirm
			return Step(state: .setupConfirm, message: nil, result: nil)

		case .setupConfirm:
			guard let first = newPasscode else { return finish(.error) }
			if Self.sameDigits(first, digits) {
				return commit(first)
			}
			wipeNew()
			state = .setupNew
			return Step(state: .setupNew, message: "mismatch", result: nil)

		case .verifyOld:
			switch vault.unlock(eoa: eoa, passcode: digits) {
			case .success(var bundle):
				BeamioNativeWallet.wipe(&bundle)
				wipeOld()
				oldPasscode = digits
				state = .setupNew
				return Step(state: .setupNew, message: nil, result: nil)
			case .failure(let outcome):
				return failure(outcome, wrongMessage: "wrong")
			}

		case .verify:
			return map(vault.disable(eoa: eoa, passcode: digits), wrongMessage: "wrong")

		case .unlock:
			switch vault.unlock(eoa: eoa, passcode: digits) {
			case .success(let bundle):
				session.install(eoa: eoa, bundle: bundle)
				return finish(.ok)
			case .failure(let outcome):
				return failure(outcome, wrongMessage: "wrong")
			}

		case .done:
			return Step(state: .done, message: nil, result: finished)
		}
	}

	// MARK: - Private

	private func commit(_ passcode: [UInt8]) -> Step {
		let outcome: BeamioPasscodeVault.Outcome
		switch mode {
		case .enable:
			outcome = vault.enable(eoa: eoa, passcode: passcode)
		case .change:
			guard let old = oldPasscode else { return finish(.error) }
			outcome = vault.change(eoa: eoa, oldPasscode: old, newPasscode: passcode)
		case .disable, .unlock:
			return finish(.error)
		}
		switch outcome {
		case .ok: return finish(.ok)
		case .backoff(let s): return finish(.backoff(s))
		case .policy, .wrong, .noRecord, .unavailable, .failed: return finish(.error)
		}
	}

	private func map(_ outcome: BeamioPasscodeVault.Outcome, wrongMessage: String) -> Step {
		switch outcome {
		case .ok: return finish(.ok)
		case .wrong: return Step(state: state, message: wrongMessage, result: nil)
		case .backoff(let s): return finish(.backoff(s))
		case .policy, .noRecord, .unavailable, .failed: return finish(.error)
		}
	}

	private func failure(_ outcome: BeamioPasscodeVault.Outcome, wrongMessage: String) -> Step {
		map(outcome, wrongMessage: wrongMessage)
	}

	private func finish(_ result: BeamioPasscodeRunResult) -> Step {
		finished = result
		wipeNew()
		wipeOld()
		state = .done
		return Step(state: .done, message: nil, result: result)
	}

	private func wipeNew() {
		if var b = newPasscode {
			newPasscode = nil
			BeamioNativeWallet.wipe(&b)
		}
	}

	private func wipeOld() {
		if var b = oldPasscode {
			oldPasscode = nil
			BeamioNativeWallet.wipe(&b)
		}
	}

	/// Equal digits, compared without an early exit.
	static func sameDigits(_ a: [UInt8], _ b: [UInt8]) -> Bool {
		guard a.count == b.count else { return false }
		var diff: UInt8 = 0
		for i in 0 ..< a.count { diff |= a[i] ^ b[i] }
		return diff == 0
	}
}
