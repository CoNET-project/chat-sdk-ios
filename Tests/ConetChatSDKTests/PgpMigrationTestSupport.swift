import XCTest
@testable import ConetChatSDK

/// Shared fixtures of the PGP migration import tests. Synthetic keys only: two X-19 keys, labelled A and B,
/// generated in the test process. The store is in memory, the chain and the X-19 approval are injected, and nothing here
/// touches the Keychain (except where a test sets the Keychain memory seam itself) or the network.
enum PgpMigrationTestSupport {
	static let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	static let otherEoa = "0x1111111111111111111111111111111111111111"
	static let account = BeamioChatPgpKeychain.accountKey(eoa: eoa)
	static let now = "2026-11-14T00:00:00Z"

	/// Sidecar keys for the derivation check (Q1,). The vectors use abstract placeholders for `privateKeyArmor`. In the
	/// harness, "EOA", "EOA2" and "NEW" are the account's own key (`armorA`), and "OTHER" is a key of another address (`armorOther`).
	/// These are synthetic test keys; their addresses are checked by a test, and they are never printed.
	static let armorA = "0x1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
	static let armorOther = "0x0000000000000000000000000000000000000000000000000000000000000002"
	/// AK-56 fixture keys (25.52Y.112): the private key is keccak256 of the UTF-8 seed; the addresses are in
	/// interface/protocol/ak56-fixture-addresses.json (ethers 6.16.0, 2026-11-16). Public test values, no funds. The keys are made in the test
	/// process and are never written or printed.
	static let ak56Seeds: [String: String] = ["a1": "beamio-ak56-fixture-a1", "a2": "beamio-ak56-fixture-a2"]

	/// The key of a fixture name (`a1` or `a2`), or nil for any other name.
	static func ak56Key(_ name: String) -> [UInt8]? {
		guard let seed = ak56Seeds[name] else { return nil }
		return BeamioNativeEthSigner.keccak256(Array(seed.utf8))
	}

	/// The canonical armor (`0x` and 64 lower-case hex digits) of a fixture name's key, or nil.
	static func ak56Armor(_ name: String) -> String? {
		guard let key = ak56Key(name) else { return nil }
		return "0x" + key.map { String(format: "%02x", $0) }.joined()
	}

	/// The symbolic names of AK-56 and the values they stand for (25.52Y.110 第 1 条, 25.52Y.111 harnessRules). A name whose derivation fails is
	/// left out (so the case cannot pass with an empty value); the test checks that every name is present and non-empty.
	static var ak56Names: [String: String] {
		var names: [String: String] = [:]
		for name in ["a1", "a2"] {
			if let key = ak56Key(name), let address = BeamioNativeEthSigner.address(privateKey: key)?.lowercased(), !address.isEmpty {
				names[name] = address
			}
		}
		if let armor = ak56Armor("a1") { names["EOA"] = armor }
		return names
	}
	private static let sidecarArmors: [String: String] = ["EOA": armorA, "EOA2": armorA, "NEW": armorA, "OTHER": armorOther]
	/// The vectors' account placeholders ("a1", "A1") are the account address; "A2" is an address that is not the account.
	private static let sidecarAddresses: [String: String] = ["a1": eoa, "A1": eoa, "A2": otherEoa]
	private static let sidecarAddressKeys: Set<String> = ["keyID", "eoa", "recordAddr", "derivedAddr"]

	/// Replaces the placeholders of a vector value with sidecar values, at any depth: the `privateKeyArmor` values with the sidecar keys, and the
	/// account placeholders under `keyID`, `eoa`, `recordAddr` and `derivedAddr` with the account address.
	static func sidecar(_ value: Any) -> Any {
		if let dict = value as? [String: Any] {
			var out: [String: Any] = [:]
			for (key, item) in dict {
				if key == "privateKeyArmor", let text = item as? String, let armor = sidecarArmors[text] {
					out[key] = armor
				} else if sidecarAddressKeys.contains(key), let text = item as? String, let address = sidecarAddresses[text] {
					out[key] = address
				} else {
					out[key] = sidecar(item)
				}
			}
			return out
		}
		if let array = value as? [Any] {
			return array.map { sidecar($0) }
		}
		return value
	}

	struct Key {
		let label: String
		let privateArmor: String
		let publicArmor: String
		let fingerprint: String
		let fp16: String
		let keyId: String
	}

	/// The fp labels of the vectors: A and B are two different keys.
	static let keys: [String: Key] = ["A": makeKey("A"), "B": makeKey("B")]

	static func key(_ label: String) -> Key {
		guard let key = keys[label] else { fatalError("unknown fp label \(label)") }
		return key
	}

	private static func makeKey(_ label: String) -> Key {
		guard case .success(let pair) = BeamioPGPNative.generateKeyPair(name: "Beamio migration test \(label)") else {
			fatalError("X-19 key generation failed")
		}
		guard let identity = BeamioPGPBackup.keyIdentity(armor: pair.privateArmor) else {
			fatalError("X-19 identity failed")
		}
		return Key(
			label: label,
			privateArmor: pair.privateArmor,
			publicArmor: pair.publicArmor,
			fingerprint: identity.fingerprint,
			fp16: String(identity.fingerprint.prefix(16)),
			keyId: identity.subkeyKeyID
		)
	}

	/// Skips a test where X-19 is not linked (the macOS test build). The keys and the migration need it.
	static func requireX19() throws {
		guard BeamioPGPNative.linked else { throw XCTSkip("X-19 is not linked in this build (run on the iOS simulator)") }
	}

	// MARK: Store and crypto doubles

	enum ChainFailure: Error { case unavailable }

	/// The store in memory. L, N and M are kept per account; writes are counted; faults are switched per test.
	final class MemoryStore: BeamioPgpMigrationImport.Store {
		var legacyRecords: [String: BeamioPgpMigrationImport.LegacyRecord] = [:]
		var stagedRecords: [String: BeamioPgpMigrationImport.StagedRecord] = [:]
		var markerRecords: [String: BeamioPgpMigrationImport.Marker] = [:]
		var lastCodes: [String: String] = [:]
		var stagedWrites = 0
		var markerWrites = 0
		var failStagedWrite = false
		var failMarkerWrite = false
		/// After a copy is written, reads of it return a record that differs from the one written (a read-back fault).
		var rereadMismatch = false
		private var mismatched: Set<String> = []

		/// A copy of the record on every read, as the Keychain store gives (the run clears what it reads).
		func legacy(eoa: String) -> BeamioPgpMigrationImport.LegacyRecord? {
			legacyRecords[eoa].map {
				BeamioPgpMigrationImport.LegacyRecord(eoa: $0.eoa, privateArmor: $0.privateArmor, publicArmor: $0.publicArmor, keyId: $0.keyId)
			}
		}

		func staged(account: String) -> BeamioPgpMigrationImport.StagedRecord? {
			guard var record = stagedRecords[account] else { return nil }
			if mismatched.contains(account) { record.keyId = "0000000000000000" }
			return record
		}

		@discardableResult
		func writeStaged(account: String, _ record: BeamioPgpMigrationImport.StagedRecord) -> Bool {
			if failStagedWrite { return false }
			stagedWrites += 1
			stagedRecords[account] = record
			if rereadMismatch { mismatched.insert(account) }
			return true
		}

		func lastCode(account: String) -> String? { lastCodes[account] }

		@discardableResult
		func writeLastCode(account: String, _ code: String) -> Bool {
			lastCodes[account] = code
			return true
		}

		func deleteLastCode(account: String) { lastCodes[account] = nil }

		func deleteStaged(account: String) {
			stagedRecords[account] = nil
			mismatched.remove(account)
		}

		func marker(account: String) -> BeamioPgpMigrationImport.Marker? { markerRecords[account] }

		@discardableResult
		func writeMarker(account: String, _ marker: BeamioPgpMigrationImport.Marker) -> Bool {
			if failMarkerWrite { return false }
			markerWrites += 1
			markerRecords[account] = marker
			return true
		}

		func deleteMarker(account: String) { markerRecords[account] = nil }
	}

	/// The real X-19 functions, with three switches: a passphrase-protected key (its armor is named), a challenge fault, and a
	/// verifier that accepts a one-bit change of the signed message (the negative check of must then fail the challenge).
	final class Crypto: BeamioPgpMigrationImport.Crypto {
		private let x19 = BeamioPgpMigrationImport.X19Crypto()
		var encryptedPrivateArmor: String?
		var verifyFails = false
		var acceptsOneBitChange = false
		private var lastSigned: Data?

		var available: Bool { x19.available }

		func identity(armor: String) -> (fingerprint: String, subkeyKeyID: String)? {
			x19.identity(armor: armor)
		}

		func passphraseFree(privateArmor: String) -> Bool {
			privateArmor != encryptedPrivateArmor && x19.passphraseFree(privateArmor: privateArmor)
		}

		func sign(privateArmor: String, data: Data) -> String? {
			lastSigned = data
			return x19.sign(privateArmor: privateArmor, data: data)
		}

		func verify(publicArmor: String, data: Data, signature: String) -> Bool {
			if acceptsOneBitChange, let signed = lastSigned, data != signed {
				return true
			}
			return !verifyFails && x19.verify(publicArmor: publicArmor, data: data, signature: signature)
		}
	}

	// MARK: Environment and records

	/// The page record of the account as the unregister sees its W-class fields. The probe records each removal.
	final class WalletProbe {
		var present: Bool
		var removes: Bool
		var removals = 0

		init(present: Bool = false, removes: Bool = true) {
			self.present = present
			self.removes = removes
		}
	}

	/// The environment of one run. The chain registers `registeredArmor` (nil: nothing registered), unless it is unavailable.
	static func environment(
		store: MemoryStore,
		crypto: Crypto,
		registeredArmor: String?,
		chainUnavailable: Bool = false,
		chainBackupRegistered: Bool = false,
		sourcePReadable: Bool = false,
		wallet: WalletProbe = WalletProbe(),
		x19Approved: Bool = true,
		interrupt: BeamioPgpMigrationImport.Checkpoint? = nil
	) -> BeamioPgpMigrationImport.Environment {
		var env = BeamioPgpMigrationImport.Environment(
			store: store,
			crypto: crypto,
			chainPublicArmor: { _ in chainUnavailable ? .failure(ChainFailure.unavailable) : .success(registeredArmor) },
			chainBackupRegistered: { _ in chainBackupRegistered },
			sourcePReadable: { _ in sourcePReadable },
			shellWalletPresent: { _ in wallet.present },
			shellWalletRemove: { _ in
				guard wallet.removes else { return false }
				wallet.removals += 1
				wallet.present = false
				return true
			},
			x19Approved: { x19Approved },
			randomBytes: { count in (0 ..< count).map { _ in UInt8.random(in: 0 ... 255) } },
			now: { now }
		)
		#if DEBUG
		// An interruption at the named stage; the other stages continue. The checkpoint exists in test builds only.
		env.checkpoint = { point in
			if point == interrupt { throw BeamioPgpMigrationImport.CheckpointInterrupt() }
		}
		#endif
		return env
	}

	/// The record L of the account, built from a private key and a public key (the public one may belong to another key).
	static func legacy(
		privateKey: Key,
		publicKey: Key,
		eoa stored: String = eoa,
		privateArmor: String? = nil
	) -> BeamioPgpMigrationImport.LegacyRecord {
		BeamioPgpMigrationImport.LegacyRecord(
			eoa: stored,
			privateArmor: Array((privateArmor ?? privateKey.privateArmor).utf8),
			publicArmor: publicKey.publicArmor,
			keyId: publicKey.keyId
		)
	}

	/// The migrated copy N for `key`, as a run writes it from L.
	static func staged(_ key: Key, source: String = BeamioPgpMigrationImport.Source.legacyPwa) -> BeamioPgpMigrationImport.StagedRecord {
		BeamioPgpMigrationImport.StagedRecord(
			eoa: eoa,
			privateArmor: Array(key.privateArmor.utf8),
			publicArmor: key.publicArmor,
			keyId: key.keyId,
			fingerprint: key.fingerprint,
			fp16: key.fp16,
			source: source
		)
	}

	/// The success marker M for `key`.
	static func marker(_ key: Key) -> BeamioPgpMigrationImport.Marker {
		BeamioPgpMigrationImport.Marker(fp16: key.fp16, source: BeamioPgpMigrationImport.Source.legacyPwa, verifiedAt: now)
	}

	/// Everything the copy and the marker of the account hold, as a comparable value (for "nothing changed" checks).
	static func snapshot(_ store: MemoryStore) -> [String: String] {
		var out: [String: String] = [:]
		for (eoa, l) in store.legacyRecords {
			out["L|" + eoa] = String(decoding: l.privateArmor, as: UTF8.self) + "|" + l.publicArmor + "|" + l.keyId + "|" + l.eoa
		}
		for (account, n) in store.stagedRecords {
			out["N|" + account] = [String(decoding: n.privateArmor, as: UTF8.self), n.publicArmor, n.keyId, n.fingerprint, n.fp16, n.source, n.eoa]
				.joined(separator: "|")
		}
		for (account, m) in store.markerRecords {
			out["M|" + account] = m.fp16 + "|" + m.source + "|" + m.verifiedAt
		}
		return out
	}
}
