import CArgon2
import Foundation

/// Argon2id (version 0x13) over the vendored official reference implementation (Sources/CArgon2, pinned in PROVENANCE.md). The SDK has no Argon2 code of
/// its own. The derived bytes are the AES-256-GCM key of the mnemonic cipher v3 (m = 32 MiB, t = 3, p = 1, 32-byte output). The caller
/// wipes the password and the output after use. Run it on a background queue: m = 32 MiB takes about a tenth of a second or more.
enum BeamioArgon2id {
	enum Failure: Error, Equatable {
		/// The reference implementation refused the parameters (its error code).
		case refused(Int32)
	}

	static func derive(password: [UInt8], salt: [UInt8], memoryKiB: UInt32, iterations: UInt32, parallelism: UInt32, outputLength: Int) -> Result<[UInt8], Failure> {
		var out = [UInt8](repeating: 0, count: outputLength)
		let code: Int32 = out.withUnsafeMutableBytes { o in
			password.withUnsafeBytes { p in
				salt.withUnsafeBytes { s in
					argon2id_hash_raw(iterations, memoryKiB, parallelism, p.baseAddress, password.count, s.baseAddress, salt.count, o.baseAddress, outputLength)
				}
			}
		}
		guard code == 0 else {
			BeamioNativeWallet.wipe(&out)
			return .failure(.refused(code))
		}
		return .success(out)
	}

	/// The mnemonic cipher v3 parameters: m = 32768 KiB, t = 3, p = 1, 32 bytes.
	static func deriveV3Key(passcode: [UInt8], salt: [UInt8]) -> Result<[UInt8], Failure> {
		derive(password: passcode, salt: salt, memoryKiB: 32768, iterations: 3, parallelism: 1, outputLength: 32)
	}

	#if BEAMIO_TEST_HOOKS
	/// Test only: the full context call with a secret and associated data, for the RFC 9106 known-answer vector (section 5.3).
	static func deriveWithContextForTests(password: [UInt8], salt: [UInt8], secret: [UInt8], associatedData: [UInt8], memoryKiB: UInt32, iterations: UInt32,
	                                      parallelism: UInt32, outputLength: Int) -> Result<[UInt8], Failure> {
		var out = [UInt8](repeating: 0, count: outputLength)
		var pwd = password, sal = salt, sec = secret, ad = associatedData
		let code: Int32 = out.withUnsafeMutableBufferPointer { o in
			pwd.withUnsafeMutableBufferPointer { p in
				sal.withUnsafeMutableBufferPointer { s in
					sec.withUnsafeMutableBufferPointer { k in
						ad.withUnsafeMutableBufferPointer { a in
							var context = argon2_context(
								out: o.baseAddress, outlen: UInt32(outputLength),
								pwd: p.baseAddress, pwdlen: UInt32(password.count),
								salt: s.baseAddress, saltlen: UInt32(salt.count),
								secret: k.baseAddress, secretlen: UInt32(secret.count),
								ad: a.baseAddress, adlen: UInt32(associatedData.count),
								t_cost: iterations, m_cost: memoryKiB, lanes: parallelism, threads: parallelism,
								version: ARGON2_VERSION_13.rawValue, allocate_cbk: nil, free_cbk: nil, flags: 0
							)
							return argon2_ctx(&context, Argon2_id)
						}
					}
				}
			}
		}
		guard code == 0 else { return .failure(.refused(code)) }
		return .success(out)
	}
	#endif
}
