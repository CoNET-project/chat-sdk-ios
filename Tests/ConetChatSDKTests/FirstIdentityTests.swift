#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The first-identity judgement (frozen protocol §13): `chain` from two endpoints at one block, `legacy` from every local source, and the native
/// eligibility at the prepare. Mock transport; no test reaches a chain. Synthetic data only.
final class FirstIdentityTests: XCTestCase {
	private let urlA = URL(string: "https://rpc-a.invalid")!
	private let urlB = URL(string: "https://rpc-b.invalid")!
	private let contract = "0x1111111111111111111111111111111111111111"
	private let account = "0x2222222222222222222222222222222222222222"

	private final class Node {
		var height = "0x1f4"
		var chainId = "0x36ca6"
		var malformed = false
		var up = true
		var exists = false
		var armor = ""
		var backup = ""
		var blocks: [String] = []
	}
	private var a = Node()
	private var b = Node()
	private var savedTransport: ((URL, Data) -> Result<Data, Error>)!

	private func word(_ n: Int) -> [UInt8] { [UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) } }
	private func encodedString(_ s: String) -> [UInt8] {
		let d = Array(s.utf8)
		return word(d.count) + d + [UInt8](repeating: 0, count: (32 - d.count % 32) % 32)
	}
	private func encodedKeys(_ armor: String, _ exists: Bool) -> [UInt8] {
		let s1 = encodedString(""), s2 = encodedString(armor), s3 = encodedString("")
		return word(128) + word(128 + s1.count) + word(128 + s1.count + s2.count) + word(exists ? 1 : 0) + s1 + s2 + s3
	}
	private func hex(_ bytes: [UInt8]) -> String { "0x" + bytes.map { String(format: "%02x", $0) }.joined() }

	override func setUp() {
		super.setUp()
		a = Node(); b = Node()
		savedTransport = AddressPGPChain.transport
		AddressPGPChain.configuration = .init(contract: contract, chainId: 224422, rpcURL: urlA)
		AddressPGPChain.transport = { [unowned self] url, body in
			let node = url == self.urlA ? self.a : self.b
			guard node.up, let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let method = o["method"] as? String else {
				return .failure(AddressPGPChain.ReadError.transport("down"))
			}
			func ok(_ r: Any) -> Result<Data, Error> { .success(try! JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": r])) }
			if node.malformed { return .success(Data("not json".utf8)) }
			if method == "eth_chainId" { return ok(node.chainId) }
			if method == "eth_blockNumber" { return ok(node.height) }
			let params = o["params"] as? [Any] ?? []
			node.blocks.append(params.last as? String ?? "")
			let data = ((params.first as? [String: Any])?["data"] as? String) ?? ""
			if data.hasPrefix(self.hex(AddressPGPChain.selector("_pgpKeys(address)"))) { return ok(self.hex(self.encodedKeys(node.armor, node.exists))) }
			return ok(self.hex(self.word(32) + self.encodedString(node.backup)))
		}
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.testUnreadableFields = []
		BeamioFirstIdentity.chainProbe = { AddressPGPChain.chainStatus(eoa: $0) }
		BeamioPGPIdentityCreate.resetInFlightIdentities()
		BeamioPGPIdentityCreate.resetCompletedIdentities()
	}

	override func tearDown() {
		AddressPGPChain.transport = savedTransport
		AddressPGPChain.configuration = nil
		BeamioChatPgpKeychain.memory = nil
		BeamioChatPgpKeychain.testUnreadableFields = []
		BeamioFirstIdentity.chainProbe = { AddressPGPChain.chainStatus(eoa: $0) }
		super.tearDown()
	}

	// MARK: chain (single RPC;)

	private var requests: [String] = []

	func testRegisteredUnregisteredAndEveryFailureAreMappedFromOneRpc() {
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unregistered, "read succeeded, nothing registered")
		a.exists = true; a.armor = "armor"
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .registered)
		a.exists = false; a.armor = ""; a.backup = "AAAA"
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .registered, "a backup alone is a registration")
		a.backup = ""
		a.up = false
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unknown, "timeout or error")
		a.up = true
		a.malformed = true
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unknown, "malformed answer")
		a.malformed = false
		a.chainId = "0x1"
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unknown, "another chain id is a failed read")
		a.chainId = "0x36ca6"
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unregistered)
		AddressPGPChain.configuration = nil
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unknown)
	}

	func testOnlyTheConfiguredEndpointIsAsked() {
		_ = AddressPGPChain.chainStatus(eoa: account)
		XCTAssertFalse(a.blocks.isEmpty)
		XCTAssertTrue(b.blocks.isEmpty, "no second endpoint, no cross-check")
		a.up = false
		XCTAssertEqual(AddressPGPChain.chainStatus(eoa: account), .unknown, "no fallback to another endpoint")
		XCTAssertTrue(b.blocks.isEmpty)
	}

	func testAChainValueOutsideTheEnumerationIsUnknown() {
		XCTAssertEqual(AddressPGPChain.chainStatus(raw: "maybe"), .unknown)
		XCTAssertEqual(AddressPGPChain.chainStatus(raw: nil), .unknown)
		XCTAssertEqual(AddressPGPChain.chainStatus(raw: "registered"), .registered)
	}

	/// Replays RE-01 to RE-10 of the shared pgp-restore vector (`pgpRestoreEvaluateReply`). `display` and `creationEntry` are page-derived; the SDK is checked on
	/// `legacy` and `chain`, and on "no creation unless state first_identity, legacy ABSENT, chain unregistered".
	func testTheSharedVectorCasesRE01ToRE10() throws {
		let url = try XCTUnwrap(Bundle.module.url(forResource: "pgp-restore-acceptance-vectors.v1", withExtension: "json"))
		let root = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
		let section = try XCTUnwrap(root["pgpRestoreEvaluateReply"] as? [String: Any])
		let cases = try XCTUnwrap(section["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.map { $0["id"] as? String }, (1 ... 10).map { String(format: "RE-%02d", $0) })
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let input = c["input"] as? [String: Any] ?? [:]
			let expect = c["expect"] as? [String: Any] ?? [:]
			BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
			BeamioChatPgpKeychain.testUnreadableFields = []
			a = Node()
			// the RPC outcome
			var chain: AddressPGPChain.ChainStatus
			if let raw = input["chainRaw"] as? String {
				chain = AddressPGPChain.chainStatus(raw: raw)
			} else if let rpc = input["rpc"] as? String {
				switch rpc {
				case "registered": a.exists = true; a.armor = "armor"
				case "timeout", "error": a.up = false
				case "malformed": a.malformed = true
				default: break
				}
				chain = AddressPGPChain.chainStatus(eoa: account)
			} else {
				chain = AddressPGPChain.chainStatus(raw: nil)
			}
			// the local state
			var legacy: BeamioFirstIdentity.Legacy?
			switch input["legacy"] as? String {
			case "PRESENT": store(account); legacy = BeamioFirstIdentity.legacy(eoa: account)
			case "UNREADABLE": BeamioChatPgpKeychain.testUnreadableFields = ["userPgpPrivateArmor"]; store("0x4444444444444444444444444444444444444444"); legacy = BeamioFirstIdentity.legacy(eoa: account)
			case "ABSENT": legacy = BeamioFirstIdentity.legacy(eoa: account)
			default: legacy = nil // a missing field is unknown for the page; the SDK always sends one
			}
			if let want = expect["chain"] as? String { XCTAssertEqual(chain.rawValue, want, id) }
			if let want = expect["legacy"] as? String, want != "unknown" { XCTAssertEqual(legacy?.rawValue, want, id) }
			let open = (input["state"] as? String) == "first_identity" && legacy == .absent && chain == .unregistered
			XCTAssertEqual(open ? "open" : "closed", expect["creationEntry"] as? String, id)
			BeamioChatPgpKeychain.testUnreadableFields = []
		}
	}

	// MARK: legacy

	private func store(_ eoa: String) {
		XCTAssertTrue(BeamioChatPgpKeychain.save(.init(privateKeyArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----", publicKeyArmor: "p",
		                                                 pgpKeyId: "", routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)))
	}

	func testLegacyIsAbsentOnlyWhenEverySourceSaysSo() {
		XCTAssertEqual(BeamioFirstIdentity.legacy(eoa: account), .absent)
		store(account)
		XCTAssertEqual(BeamioFirstIdentity.legacy(eoa: account), .present)
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.testUnreadableFields = ["userPgpPrivateArmor"]
		store("0x4444444444444444444444444444444444444444")
		// another account's key is on the device and cannot be assigned to this one: not "none"
		XCTAssertEqual(BeamioFirstIdentity.legacy(eoa: account), .unreadable)
		BeamioChatPgpKeychain.testUnreadableFields = []
		XCTAssertEqual(BeamioFirstIdentity.legacy(eoa: account), .unreadable, "a PGP item that is not this account's still blocks")
	}

	func testAPendingIdentityWithAKeyIsPresentButAPreparedOneIsNot() {
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: account, .init(privateArmor: "", publicArmor: "", idempotencyKey: "k", seen: "s", mode: "first")))
		XCTAssertEqual(BeamioFirstIdentity.legacy(eoa: account), .absent, "a prepared identity has no key: it is the flow's own mark")
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: account, .init(privateArmor: "-----BEGIN PGP PRIVATE KEY BLOCK-----", publicArmor: "p", idempotencyKey: "k", seen: "s", mode: "first")))
		XCTAssertEqual(BeamioFirstIdentity.legacy(eoa: account), .present)
	}

	// MARK: eligibility at the prepare

	private final class Registrar: BeamioPGPIdentityCreate.Registering {
		var calls = 0
		func register(eoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error> { calls += 1; return .success(()) }
	}

	func testThePrepareMakesNoFirstIdentityWithoutTheNativeJudgement() {
		BeamioPGPIdentityCreate.registration = Registrar()
		defer { BeamioPGPIdentityCreate.registration = nil }
		// the chain says nothing, but this device holds the account's old key: not eligible
		store(account)
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "k1"), .failed("not_eligible"))
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account), "nothing is prepared")
		// an empty device and an unregistered chain: eligible
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "k2"), .ready(.first))
		// the chain cannot be read now: the next prepare is refused with the read failure, nothing prepared
		BeamioChatPgpKeychain.clearPending(eoa: account)
		BeamioPGPIdentityCreate.resetInFlightIdentities()
		a.up = false
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "k3"), .failed("pgp_source_unavailable"))
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account))
	}

	func testTheRefusalOrderChainFirstThenTheDevice() {
		// registered on the chain: cas_conflict, whatever the device holds
		a.exists = true; a.armor = "armor"
		XCTAssertEqual(BeamioFirstIdentity.firstIdentityRefusal(eoa: account), "cas_conflict")
		a.exists = false; a.armor = ""
		XCTAssertNil(BeamioFirstIdentity.firstIdentityRefusal(eoa: account))
		store(account)
		XCTAssertEqual(BeamioFirstIdentity.firstIdentityRefusal(eoa: account), "not_eligible")
		a.up = false
		XCTAssertEqual(BeamioFirstIdentity.firstIdentityRefusal(eoa: account), "pgp_source_unavailable")
	}

	// MARK: the guards of the create flow (spec owner's codes)

	private let fixedPair: (privateArmor: String, publicArmor: String) = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\nk\n-----END PGP PRIVATE KEY BLOCK-----", "pub-armor-of-the-new-key")

	func testAConfirmationThatMeetsARegistrationIsACasConflictAndWritesNothing() {
		let registrar = Registrar()
		BeamioPGPIdentityCreate.registration = registrar
		let saved = BeamioPGPIdentityCreate.generateKeyPair
		var generated = 0
		BeamioPGPIdentityCreate.generateKeyPair = { [unowned self] _ in generated += 1; return .success(self.fixedPair) }
		defer { BeamioPGPIdentityCreate.registration = nil; BeamioPGPIdentityCreate.generateKeyPair = saved }
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "g1"), .ready(.first))
		// somebody registered an identity between the prepare and the confirmation
		a.exists = true; a.armor = "someone else's armor"
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "g1"), .casConflict)
		XCTAssertEqual(generated, 0, "no key is generated")
		XCTAssertEqual(registrar.calls, 0, "nothing is written to the chain")
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account))
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.casConflict), "cas_conflict")
	}

	func testTheSameIdentityOnTheChainIsANoOpUnderAnotherKey() {
		let registrar = Registrar()
		BeamioPGPIdentityCreate.registration = registrar
		let saved = BeamioPGPIdentityCreate.generateKeyPair
		BeamioPGPIdentityCreate.generateKeyPair = { [unowned self] _ in
			// the chain already holds the very key that is being generated (an earlier write went through before the record was kept)
			self.a.exists = true; self.a.armor = self.fixedPair.publicArmor
			return .success(self.fixedPair)
		}
		defer { BeamioPGPIdentityCreate.registration = nil; BeamioPGPIdentityCreate.generateKeyPair = saved }
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "g2"), .ready(.first))
		// the chain moved while the key was made, so the first read of the confirmation (before the key) still sees an empty chain
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "g2"), .failed("already_registered_same_key"))
		XCTAssertEqual(registrar.calls, 0, "a no-op: no second registration")
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("already_registered_same_key")), "already_registered_same_key")
	}

	func testAnotherPendingKeyIsPendingExists() {
		BeamioPGPIdentityCreate.registration = Registrar()
		defer { BeamioPGPIdentityCreate.registration = nil }
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "p1"), .ready(.first))
		BeamioPGPIdentityCreate.resetInFlightIdentities()
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "p2"), .failed("pending_exists"))
	}
}
#endif
