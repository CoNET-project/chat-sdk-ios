import CryptoKit
import Foundation
import XCTest

/// The conformance vector files of the test target. The file is read from the environment path when that variable is set,
/// and otherwise from the copy bundled in this test target. Either way the registered sha256 is checked: a missing file or a different digest
/// fails the test, it never skips. The bundled copies are copies of `interface/protocol/` and are not edited here.
enum BundledVectorFile {
	/// Registered sha256 of each bundled file (SHA256-CURRENT of the interface).
	static let registered: [String: String] = [
		"native-recovery-vectors.v1": "8b4e66c1488504b29a6b04c3ca275f0ef183e8a15259b82292bf47f3946d43b2",
		"chat-route-register-vectors.v1": "634d98c25e7339b7dac18b0c97525700176d42b94e2ab3b784bb9b5503f3e5c5",
		"chat-route-decision-vectors.v1": "47a572c89a4ec7f7e5210fc583c2c231680dd368396c905dce32f6f96f851690",
		"pgp-restore-acceptance-vectors.v1": "826603a16ec6b18a440352563fd94cb987342227d5ce62a4b101a494c82c0c68",
		"pgp-backup-compat-vectors.v1": "d112fe566387a27ca292b0139b6f0648cde1ce919fea5e2ee22738f3dd47b77a",
		// The registrations of: the 65-name table and the voice ephemeral register vectors.
		// Shell passcode protocol v1 vectors (frozen PROTOCOL-shell-passcode-v1 adb8b71a; interface HEAD 8e6b13a2). table-T v2 adds the passcode names.
		"passcode-vectors.v1": "1b2bca82b1d00067365f776b2bce15fcc06d023118832f7c1f67bcc1bb2e4961",
		// versions: the earlier files stay unchanged next to them, and the tests run these.
		// Mnemonic cipher v3 (finalized section 10): the current vector and the test fixture that adds the test-only derived key. Test only, never product.
		// SRP v1: the shellRecordRead and shellRecordWrite answers while the passcode bundle is not provided (test only)
		// SRP v2 (2026-11-22): the storage faults use the existing codes (read record_unreadable, write write_failed, unknown state not_ready/unreadable). v1 stays unchanged.
		// write-fault-shape-independent.v1 (2026-11-22): the cases that hold for any write or read fault shape (the pending shapes are information only)
		// v3 (2026-11-22, SRP-04 option A): the write failure is the envelope write_failed (PS-W-v291 is must-pass); v1 stays unchanged
		"write-fault-shape-independent.v3": "8a23b43dbb730f12fe452d797e7e9bb9f59f4fe23176a13efdf07e8126e833c5",
		"write-fault-shape-independent.v1": "877b65a4e458c6f701d4e4859988dac340aab3e442976ed2dc127fd71bb95e55",
		"shell-record-passcode-not-provided.v2": "0833f6ab0d3f2ea7ca1ec2676e993587310c521671187923e7a692121307227b",
		"shell-record-passcode-not-provided.v1": "c05180134dac9949f16ae138cc36b8c605c9a1ab435e8cc83d34c04f8b13e3b2",
		// preread as the current record, result.code shape: v4 replaces v1 for the answer shape; v1 stays unchanged
		"mnemonic-preread-vectors.v4": "89f2c2a0635b729db412b0a68c180f44fdaedea61bee210954af0182f61bbbdc",
		"preread-returns-current-record-as-is.v1": "aa8d0d708a9d28dde25865ab40e2a64dd9976d10116d59ee3a44ac09d78e263d",
		"mnemonic-cipher-format.v3": "9fc7d40681c51504b7596ef8fa180712f283ebc07fadffa882af1299d8d38842",
		"mnemonic-cipher-format.v4": "4b44afd8f8109473409fb0c3126440551901e9f270dc3330ba6a2c5510fab726",
		"passcode-locked-exemption-vectors.v2": "9972f224c72ee26f0c0a3820b04bf12a00a1e3244773e1ee3a16daaa3b2cc8ba",
		"native-unlock-judgement-vectors.v3": "e5e0b38ad0af33df5e7dab0f85a387c414ac30ebcf2260d6510f5fc744702dcf",
		"voice-ephemeral-register-vectors.v2.4": "83a1fcef6e51584a00423c0968260bcc9906c5eaa9446a7eee8cc0e894c9d025",
		"passcode-locked-exemption-vectors.v1": "112e157d887b3678b8ef6c610896b2601059b53852db50c4d716a6e547098500",
		"table-T.v2": "4088bbbc736998662f668c8068fceb6cbe73ab3482eec3211d15de4b2abe4ed6",
		"table-T.v1": "90fbd75ed1c2741a348c003fe53abf7f7f301bda0db3313e1a5fd139fad2da07",
		"voice-ephemeral-register-vectors.v1": "78d10dbd719a88097bf1ef7bd78ae1f8b1c4db4c4585a6a1b11c3cc72c5d693c",
		//: VR-17 corrected, option B: a lock keeps the voice registration (69e0fa6). The v1 original is unchanged; v2 (d23742db…) is void (its VR-17 steps 2 and 4 were swapped);
		// v2.1 (88a0682d…) is superseded by v2.3 (v2.2 f8e24fc3…, which turned every seal step into unknown_command, is void: a gate that comes before the command body keeps its answer). In v2.3 the seal steps after the gate (G2, unlocked) are unknown_command (alternative A: the shipped seal fails closed) and VR-27/28/29 and VR-31 step 2 keep no_key / not_ready / locked / not_ready. The driver uses v2.3 and no longer enables the retired seal path. Byte copy of interface/protocol.
		"voice-ephemeral-register-vectors.v2.3": "50d15136a59d02f66c0c8ce0e0f37004240b4fe548e8efacd4c041329161bb16",
		// v227/v228 (2026-11-21): keystore replica v2: KR-01 key-only orphan is no account and builds no copy, KR-08 a valid mnemonic account builds one. v2.1 (requirement, KR-05 on the PWA
		// baseline): only KR-05 changes, to legacy_store_unreadable; v2 (b1242244…) is superseded. Byte copy of interface/protocol.
		"keystore-replica-vectors.v2.1": "7ba89af4afe29e021d55137cc4427c2acc6d57e7c6241f4ecdaceb8f605ad18b",
		// v43 s47, v44 s49 (2026-11-20): passcodeStatus.nativeLocked judgement (NL-1..7) and the nativeIdentityCheck ack shape (IC-1..5); increment file, pin 57f245cd.
		"native-unlock-judgement-vectors.v1": "57f245cd14fc9ff20d29a5897b870444ed7a94690d95a7d6cf91c302f3ae2722",
		// v2 of the same (v45 s50; NL-8..NL-11 add the G1 and no-passcode branches), pin 92f47cee; v1 stays.
		"native-unlock-judgement-vectors.v2": "92f47ceeca64aeb60dfa91c8829db6aa8b27b818c2e733f546f0ba9fb37aceb8",
		// The page-copy no-key vectors (Y.151, PNK-01 to PNK-10; PNK-07 and PNK-10 by Y.156, PNK-09 by Y.154), registered by the interface spec (pin 4972aa8c).
		"page-copy-nokey-vectors.v1": "4972aa8c156d630c9e00c9b320eb65bb6c1c5f159c955df8cc284e1fee9d3d93",
		// pgp-migration v2 (25.52Y.155 TS-06 unknown; r2.5.12: AK-60 read is error/account_record_missing, 第 57(1) 项; pin b5ae750a).
		// v3 (2026-11-22, SRP-04 option A): AK-38 and AK-46 expect the envelope {ok:false, error:write_failed}; v2 stays unchanged
		"pgp-migration-vectors.v3": "5a5c3108fc8ee1526770ae50efc54cbd4f1d5a8841efb0b91071054f216c14a4",
		"pgp-migration-vectors.v2": "b5ae750a9f110b23ee29f254cf6f6ca9dfd3a4087833a10bbf8853a2c324af44",
		// account-select vectors (25.52Y.160, AS-01 to AS-23), registered by the interface spec.
		"account-select-vectors.v1": "caa7868037e28ef9f61778742dd1846a78fe33a03733d054e867c9242962453d",
		// account-select vectors v2 (25.52Y.163 r2.5.17, 335 cases; AS v2 a9b8d563, unchanged at r2.5.19; supersedes r2.5.11 c9b15003 (326 cases)).
		"account-select-vectors.v2": "a9b8d563bba51a0adf444aeac252ccc37201928dc614014fa67f80f45b099d1c",
		// r2.5.19 (, 第 60(7) 项): the mnemonic preread vectors, NP-01 to NP-13 (13 cases).
		"mnemonic-preread-vectors.v1": "c90b54897827d303d0b9566595b498685d024cefe3ae062ba39e2bec4e4039f9",
		// r2.5.19 (, 第 59(5) 项): the native-open vectors, 42 cases; nativeImportOpen answers unknown_command (N-01, N-04 to N-06, N-10a, N-11, N-12, N-18).
		"native-open-vectors.v1": "49ceb083343b028bdf1d7d5e5316ce716a60ef4459441ce50ec14d251a22079f",
		// interface spec v160 to v162 (2026-11-21), new files: the shellRecordRead answer shape (11 cases), the not_ready reasons (8) and the unreadable causes (5).
		// Superseded and kept byte-exact next to their successors (the tests run the v3 files, not these): answer-shape v1 (by v3) and unreadable-cause v2 (by v3).
		"shell-record-read-answer-shape.v1": "a3f3f19357534180c5bc8a3637cbc850b58ae13c740b19fa4e638c34ce002617",
		"unreadable-cause.v2": "47db22acc49c7ddd16ea3dac3bd25580900de7f314d95f8f8c5a748e3e0ad9b0",
		"shell-record-read-answer-shape.v3": "764170a6c227c6f441b5994b99a90d3802ae16fb76650e747e99bf749a24e98e",
		// v2 of both (v168 section 188: the answers in the v162 shape; the v1 files, which wrote the old envelope-level ok:false, are superseded and removed).
		"shell-record-read-not-ready-reasons.v2": "0a59252b34be0e08b3b0c289f153f6b72850796e7ed3b2ed435a387a9a06e985",
		"unreadable-cause.v3": "1558d3696753d89979c5c2265fcf6a5d4ba2bf0287986e2cc542e9897e830add",
		// v166 section 186 (draft, v4 batch): the shellRecordWrite refusal of a PGP private key (4 cases); source interface/VECTOR-shellrecordwrite-pgp-private-refusal-v1-2026-11-21.json.
		// v189 section 209 (2026-11-21), v2 of the batch rulings (v1 BR-01..03 had the wrong shape): unreadable is not no_key (BR2-01, 02), SS-32 (BR2-03), VR-17 (BR2-04).
		"batch-rulings-unreadable-nokey-ss32-vr17.v2": "999a19ac29d78496a03bc96cdf5b25a1c8ee498f6e20a31a1b2e826f48120be7",
		// v196 section 216 / v197 section 217 (2026-11-21): accountCleanupOld v3, the ack shape of the silent cleanup (Android qa.8 shape), byte copy, pinned.
		"accountCleanupOld.v3": "20c00809bc0a5952896fb2bce57ab15c76295c6ff71edf590c6e31da850b2df9",
		// v222 (2026-11-21): enumerated accounts of the silent cleanup, EA-01 to EA-14 (final; v1 to v3 are void), byte copy of interface/VECTOR-enumerated-accounts-v4-2026-11-21.json.
		"enumerated-accounts.v4": "15b54fa2be6b2d187ec8be305312e3219c0e0bfa7772fb36cb4df5a71ccdd3b4",
		"shellrecordwrite-pgp-private-refusal.v1": "4409ae0242be74153817bd563084cf10a33aa44d93ea48318f3ff4fd290fba01",
	]

	static func digest(_ data: Data) -> String {
		SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
	}

	/// The bytes of one vector file, with its registered digest checked. `env` overrides the bundled copy when it is set.
	static func data(resource: String, env: String? = nil) throws -> Data {
		let data: Data
		if let env, let path = ProcessInfo.processInfo.environment[env] {
			data = try Data(contentsOf: URL(fileURLWithPath: path))
		} else {
			let url = try XCTUnwrap(Bundle.module.url(forResource: resource, withExtension: "json"), "bundled \(resource).json")
			data = try Data(contentsOf: url)
		}
		let want = try XCTUnwrap(registered[resource], "a registered digest for \(resource)")
		XCTAssertEqual(digest(data), want, "\(resource): the file differs from the registered digest")
		return data
	}
}
