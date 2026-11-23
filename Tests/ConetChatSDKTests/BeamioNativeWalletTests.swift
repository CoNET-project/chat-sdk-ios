import XCTest
@testable import ConetChatSDK

/// The native wallet module: EIP-191, the SetPointer EIP-712 command, the protocol master, and the
/// account check. Reference values come from the repo's ethers v6.17.0 (the PWA signing library), generated offline by
/// the script gen-native-wallet-vectors.cjs. Synthetic key 0x11…11 only; never a user key.
final class BeamioNativeWalletTests: XCTestCase {
	/// In-memory key store (same shape as the boundary tests). Keys are stored as given.
	final class MemoryStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds the synthetic account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private let keyHex = String(repeating: "11", count: 32)
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	private let registry = "0x1234567890123456789012345678901234567890"
	private var store: MemoryStore!
	private var savedStore: BeamioChatWalletKeyStoring!

	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = MemoryStore()
		store.keys[eoa] = Data(hexBytes: keyHex)
		BeamioNativeWallet.keyStore = store
		// the wallet functions answer only in G2 for the account. These vector tests are the G2 case.
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
	}

	override func tearDown() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		BeamioNativeWallet.keyStore = savedStore
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	// MARK: - EIP-191

	func testEip191MatchesEthers() {
		let got = try? BeamioNativeWallet.signEip191(eoa: eoa, message: "hello 你好").get()
		XCTAssertEqual(got, "0x5edefc5cd2275b01c9b4ea333a75ec5fb979d1ce7d47cbf352bf3407873c0a071ccbb61227cdae05e164b88b278bf6173eefa3ead53033b0ece4dc7f49d971061b")
	}

	// MARK: - Protocol master (C1)

	func testHistoryMasterMatchesEthersDerivation() throws {
		let master = try XCTUnwrap(BeamioNativeWallet.historyMaster(eoa: eoa, chainId: 224422))
		XCTAssertEqual("0x" + BeamioChatLocalCrypto.hex(master),
		               "0xbec047bc5c977f3028cc0fa046c2fb28cbf51e63e59663e77730ade43eab1c22")
	}

	func testHistoryMasterIsNilWithoutTheKey() {
		store.keys[eoa] = nil
		XCTAssertNil(BeamioNativeWallet.historyMaster(eoa: eoa, chainId: 224422))
	}

	// MARK: - SetPointer EIP-712 (pointerEip712): byte-for-byte with ethers signTypedData

	private struct PointerVector {
		let indexHash: String
		let ts: String
		let seq: String
		let nonce: String
		let digest: String
		let signature: String
	}

	private let pointerVectors: [PointerVector] = [
		PointerVector(
			indexHash: "0x" + String(repeating: "ab", count: 32), ts: "1767225603500", seq: "0", nonce: "0",
			digest: "0xe087aeac91ed641960e5cee8ddab4f79d6e1674ac45b17e45f5dd5490ddf7ad1",
			signature: "0xb367e1725b40de0c30aab69cab301c17a77d9286761d48bb4de9c1fec9225822093cf27b59b356c8254cc2d556c694b02bc4ca6ed74cb7ed7e92b1f9eab74bb01c"
		),
		PointerVector(
			indexHash: "0x" + String(repeating: "01", count: 31) + "ff", ts: "1893456000000", seq: "4294967296",
			nonce: "1606938044258990275541962092341162602522202993782792835301376",
			digest: "0x43bf261213315fb8965e4a8a8df9163c06c73d6fb1a32543cb4ddc8f2bf09b99",
			signature: "0x2095716e93e1f5cb715b64ce0c94374e2ec293941e72977a8fe5445295e98c3c18f6c87ec037bd55903fd0a7e4cb2ae16bab4f87f40fd6e50deb925ef81da1701c"
		),
		PointerVector(
			indexHash: "0x" + String(repeating: "00", count: 32), ts: "18446744073709551615", seq: "1", nonce: "42",
			digest: "0xcbd4389fc57072da5c6574941ed8adaa7fb387f3486e5e6458598a805ea62b54",
			signature: "0x00789d09e7ad591be774debfcb54605faab97a709f3ee05667c5b453ef4ed3dd69d86864157c9696d623eecfdd49a2df46ab646a468f16c0e6564c1c625cec461c"
		),
	]

	func testSetPointerDigestMatchesEthers() throws {
		for v in pointerVectors {
			let owner = try XCTUnwrap(BeamioNativeEip712.bytes(hex: eoa, count: 20))
			let verifying = try XCTUnwrap(BeamioNativeEip712.bytes(hex: registry, count: 20))
			let hash = try XCTUnwrap(BeamioNativeEip712.bytes(hex: v.indexHash, count: 32))
			let nonce = try XCTUnwrap(BeamioNativeEip712.uint256(decimal: v.nonce))
			let digest = BeamioNativeEip712.setPointerDigest(
				chainId: BeamioNativeWallet.registryChainId, verifyingContract: verifying, owner: owner,
				indexHash: hash, ts: UInt64(v.ts)!, seq: UInt64(v.seq)!, nonce: nonce
			)
			XCTAssertEqual("0x" + BeamioChatLocalCrypto.hex(Data(digest)), v.digest, "digest for ts \(v.ts)")
		}
	}

	func testSetPointerSignatureMatchesEthers() {
		for v in pointerVectors {
			let got = try? BeamioNativeWallet.signSetPointer(
				eoa: eoa, registry: registry, indexHash: v.indexHash, ts: v.ts, seq: v.seq, nonce: v.nonce
			).get()
			XCTAssertEqual(got, v.signature, "signature for ts \(v.ts)")
		}
	}

	func testSetPointerRejectsAnAccountTheKeyDoesNotDerive() {
		// The stored key belongs to `eoa`, but the request names another account: rejected, nothing signed.
		let other = "0x1111111111111111111111111111111111111111"
		store.keys[other] = Data(hexBytes: keyHex)
		let v = pointerVectors[0]
		XCTAssertEqual(BeamioNativeWallet.signSetPointer(
			eoa: other, registry: registry, indexHash: v.indexHash, ts: v.ts, seq: v.seq, nonce: v.nonce
		), .failure(.rejected("account_mismatch")))
	}

	func testSetPointerRejectsMalformedValues() {
		let v = pointerVectors[0]
		let short = "0x" + String(repeating: "ab", count: 31)
		XCTAssertEqual(BeamioNativeWallet.signSetPointer(eoa: eoa, registry: registry, indexHash: short,
		                                                 ts: v.ts, seq: v.seq, nonce: v.nonce),
		               .failure(.rejected("set_pointer_shape")), "indexHash must be 32 bytes")
		XCTAssertEqual(BeamioNativeWallet.signSetPointer(eoa: eoa, registry: registry, indexHash: v.indexHash,
		                                                 ts: "-1", seq: v.seq, nonce: v.nonce),
		               .failure(.rejected("set_pointer_shape")), "ts must be a uint64 decimal")
		XCTAssertEqual(BeamioNativeWallet.signSetPointer(eoa: eoa, registry: registry, indexHash: v.indexHash,
		                                                 ts: v.ts, seq: v.seq, nonce: "-1"),
		               .failure(.rejected("set_pointer_shape")), "nonce must be a non-negative decimal")
		let tooBig = "1" + String(repeating: "0", count: 78)  // 10^78 > 2^256
		XCTAssertEqual(BeamioNativeWallet.signSetPointer(eoa: eoa, registry: registry, indexHash: v.indexHash,
		                                                 ts: v.ts, seq: v.seq, nonce: tooBig),
		               .failure(.rejected("set_pointer_shape")), "nonce must fit in uint256")
	}

	func testMissingKeyIsReportedAndNothingIsSigned() {
		store.keys[eoa] = nil
		XCTAssertEqual(BeamioNativeWallet.signEip191(eoa: eoa, message: "x"), .failure(.walletKeyMissing))
		let v = pointerVectors[0]
		XCTAssertEqual(BeamioNativeWallet.signSetPointer(eoa: eoa, registry: registry, indexHash: v.indexHash,
		                                                 ts: v.ts, seq: v.seq, nonce: v.nonce),
		               .failure(.walletKeyMissing))
	}

	// MARK: - PGP stays pending

	func testPgpCommandsArePendingUntilTheLibraryIsApproved() {
		// C4 refuses before the library is reached: the registry is empty.
		XCTAssertEqual(BeamioNativeWallet.pgpSign(eoa: eoa, purposeId: "chatEnvelope", sigType: 0x00, data: Data([1])),
		               .failure(.rejected("purpose_not_registered")))
		let armored = Data("-----BEGIN PGP MESSAGE-----\nAAAA\n-----END PGP MESSAGE-----".utf8)
		// Without the X-19 framework, C3 is pending. With it linked, an account with no PGP record is refused (no_pgp_key).
		let expected: BeamioNativeWallet.Failure = BeamioPGPNative.linked
			? .rejected("no_pgp_key") : .pending("pgp_native_pending")
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: eoa, message: armored), .failure(expected))
	}

	/// C3 accepts only an OpenPGP message: arbitrary text is refused.
	func testPgpDecryptRefusesArbitraryText() {
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: eoa, message: Data([1])), .failure(.rejected("pgp_message_shape")))
		XCTAssertEqual(BeamioNativeWallet.pgpDecrypt(eoa: eoa, message: Data("hello".utf8)), .failure(.rejected("pgp_message_shape")))
	}

	// MARK: - Memory hygiene

	func testWipeZeroesEveryByte() {
		var bytes: [UInt8] = Array(1 ... 64)
		BeamioNativeWallet.wipe(&bytes)
		XCTAssertEqual(bytes, [UInt8](repeating: 0, count: 64))
		var data = Data(repeating: 0xAB, count: 32)
		BeamioNativeWallet.wipe(&data)
		XCTAssertEqual(data, Data(repeating: 0, count: 32))
	}
}

private extension Data {
	/// Test helper: bytes from a hex string (no prefix).
	init(hexBytes hex: String) {
		var out = Data()
		var i = hex.startIndex
		while i < hex.endIndex {
			let j = hex.index(i, offsetBy: 2)
			out.append(UInt8(hex[i ..< j], radix: 16)!)
			i = j
		}
		self = out
	}
}
