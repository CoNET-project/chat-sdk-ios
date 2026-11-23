import Foundation

/// Module-facing adapter over the native wallet. It holds only the session's
/// address, never a key. Signing is done inside the native wallet module; there is no WebView signing path (S-3).
public enum BeamioConetChatSignBroker {
	public enum SignError: Error, Equatable {
		case walletKeyMissing
		case signFailed
		/// F3: the account asked for is not the signer. Nothing is signed.
		case signerChanged
	}

	private static let lock = NSLock()
	private static var signerEoa = ""
#if BEAMIO_TEST_HOOKS
	/// Test build only: how many signatures were asked of the wallet.
	static var testSignAttempts = 0
	/// Test build only: a signature is asked and never answers.
	static var testHangSigning = false
	/// Test build only: the signature the test gives in place of the wallet. The test decides when it answers, and may act meanwhile.
	static var testSignature: ((String, @escaping (Result<String, Error>) -> Void) -> Void)? = nil
#endif

	/// Native key store (the wallet module's). Tests replace it with an in-memory store.
	public static var keyStore: BeamioChatWalletKeyStoring {
		get { BeamioNativeWallet.keyStore }
		set { BeamioNativeWallet.keyStore = newValue }
	}

	/// Called when a session starts for `eoa`. The broker holds only the address, never a key.
	public static func setSignerEoa(_ eoa: String) {
		lock.lock()
		signerEoa = eoa.lowercased()
		lock.unlock()
	}

	public static func clearSigner() {
		lock.lock()
		signerEoa = ""
		lock.unlock()
	}

	public static func currentSignerEoa() -> String {
		lock.lock(); defer { lock.unlock() }
		return signerEoa
	}

	private static func currentEoa() -> String {
		lock.lock(); defer { lock.unlock() }
		return signerEoa
	}

	/// the listen authentication of the background path, for the listen session's own account. Not a page command, not through the
	/// bridge, and nothing is returned to the page. The only caller is the listen session's authentication.
	public static func requestListenAuth(
		eoa: String,
		message: String,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		// the listen authentication is signed for the signer's account only. Another account is refused before any signature.
		let signer = currentEoa()
		guard !signer.isEmpty, signer == eoa.lowercased() else {
			completion(.failure(SignError.signerChanged))
			return
		}
#if BEAMIO_TEST_HOOKS
		testSignAttempts += 1
#endif
		switch BeamioNativeWallet.signListenAuth(eoa: eoa, message: message) {
		case .success(let signature): completion(.success(signature))
		case .failure(.walletKeyMissing): completion(.failure(SignError.walletKeyMissing))
		case .failure: completion(.failure(SignError.signFailed))
		}
	}

	/// The synchronous form. The signer is read once and must be `expectedEoa`; another signer is
	/// refused before any signature is made, and the signature is made for that same account.
	public static func requestEip191Sync(message: String, expectedEoa: String) -> Result<String, Error> {
		let eoa = currentEoa()
		guard !eoa.isEmpty else { return .failure(SignError.walletKeyMissing) }
		guard expectedEoa.lowercased() == eoa else { return .failure(SignError.signerChanged) }
#if BEAMIO_TEST_HOOKS
		testSignAttempts += 1
#endif
		switch BeamioNativeWallet.signEip191(eoa: eoa, message: message) {
		case .success(let signature): return .success(signature)
		case .failure(.walletKeyMissing): return .failure(SignError.walletKeyMissing)
		case .failure: return .failure(SignError.signFailed)
		}
	}

	/// EIP-191 `personal_sign(message)` through the native wallet module. `expectedEoa`: the account the caller means to sign for.
	/// A different signer is refused before any signature is made. The signer is read once, and signed for that same account.
	public static func requestEip191(
		message: String,
		timeout: TimeInterval = 30,
		expectedEoa: String? = nil,
		completion: @escaping (Result<String, Error>) -> Void
	) {
		_ = timeout
		let eoa = currentEoa()
		guard !eoa.isEmpty else {
			completion(.failure(SignError.walletKeyMissing))
			return
		}
		if let expectedEoa, expectedEoa.lowercased() != eoa {
			completion(.failure(SignError.signerChanged))
			return
		}
#if BEAMIO_TEST_HOOKS
		testSignAttempts += 1
#endif
#if BEAMIO_TEST_HOOKS
		if testHangSigning { return }
		if let testSignature {
			testSignature(message, completion)
			return
		}
#endif
		switch BeamioNativeWallet.signEip191(eoa: eoa, message: message) {
		case .success(let signature): completion(.success(signature))
		case .failure(.walletKeyMissing): completion(.failure(SignError.walletKeyMissing))
		case .failure: completion(.failure(SignError.signFailed))
		}
	}
}
