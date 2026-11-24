#if BEAMIO_TEST_HOOKS
import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The first identity of a new account and its registration: the agreed read of the two endpoints, the registrar (sign, post, read back), the coordinator
/// (S0 to S6) and the account registration payload. Synthetic data only; the chain, the API and the OpenPGP wrapper are replaced.
final class NewAccountRegistrationTests: XCTestCase {
	private let eoa = "0x00000000000000000000000000000000000000a1"
	private let otherEoa = "0x00000000000000000000000000000000000000b2"
	private let publicA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-a\n-----END PGP PUBLIC KEY BLOCK-----"
	private let privateA = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-a\n-----END PGP PRIVATE KEY BLOCK-----"
	private let publicB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-b\n-----END PGP PUBLIC KEY BLOCK-----"
	private let routeArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-route\n-----END PGP PUBLIC KEY BLOCK-----"

	private var savedMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var savedConfiguration: AddressPGPChain.Configuration?
	private var savedSecond: URL?
	private var savedApi: URL?
	private var savedGenerate: ((String) -> Result<(privateArmor: String, publicArmor: String), Error>)!

	// the world of one test
	private var chain: [AddressPGPChain.Snapshot] = []          // answers of the agreed read, in order; the last one repeats
	private var chainFails = false
	private var reads = 0
	private var posts: [[String: Any]] = []
	private var postStatus: Int? = 200
	private var generated = 0
	private var legacyState: BeamioFirstIdentity.Legacy = .absent
	private var locked = false
	private var signCount = 0

	override func setUp() {
		super.setUp()
		savedMemory = BeamioChatPgpKeychain.memory
		savedConfiguration = AddressPGPChain.configuration
		savedSecond = AddressPGPChain.shellEndpointSecond
		savedApi = BeamioPGPRegistrar.apiBase
		savedGenerate = BeamioPGPIdentityCreate.generateKeyPair
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		AddressPGPChain.configuration = AddressPGPChain.Configuration(contract: "0x" + String(repeating: "1", count: 40), chainId: 224422, rpcURL: URL(string: "https://rpc1.test.invalid")!)
		AddressPGPChain.shellEndpointSecond = URL(string: "https://rpc2.test.invalid")
		BeamioPGPRegistrar.apiBase = URL(string: "https://api.test.invalid")
		chain = [empty]; chainFails = false; reads = 0; posts = []; postStatus = 200; generated = 0; legacyState = .absent; locked = false; signCount = 0
		BeamioPGPRegistrar.pollDelays = [0, 0, 0]
		BeamioPGPRegistrar.sleep = { _ in }
		BeamioPGPRegistrar.readAgreed = { [unowned self] _ in self.nextRead() }
		BeamioFirstIdentityCoordinator.readAgreed = { [unowned self] _ in self.nextRead() }
		BeamioFirstIdentityCoordinator.isLocked = { [unowned self] _ in self.locked }
		BeamioFirstIdentityCoordinator.legacy = { [unowned self] _ in self.legacyState }
		BeamioPGPRegistrar.identityOf = { armor in (String(BeamioChatRouteRegister.normalizedArmor(armor).hashValue.magnitude, radix: 16).uppercased(), "AAAAAAAAAAAAAAAA") }
		BeamioPGPRegistrar.chooseRoute = { [unowned self] in ("node1.test", self.routeArmor) }
		BeamioPGPRegistrar.sign = { [unowned self] account, privateArmor, request, _, _, nonce in
			self.signCount += 1
			return .success(["wallet": account, "keyID": request.keyID, "publicKeyArmored": request.publicKeyArmored, "encrypKeyArmored": "backup", "routeKeyID": request.routeKeyID,
			                 "timestamp": 1, "nonce": "0x" + nonce.map { String(format: "%02x", $0) }.joined(), "signature": "0xsig"])
		}
		BeamioPGPRegistrar.post = { [unowned self] _, body in
			if let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] { self.posts.append(object) }
			return self.postStatus
		}
		BeamioPGPIdentityCreate.generateKeyPair = { [unowned self] _ in self.generated += 1; return .success((self.privateA, self.publicA)) }
		BeamioPGPIdentityCreate.resetInFlightIdentities()
		BeamioPGPIdentityCreate.resetCompletedIdentities()
	}

	override func tearDown() {
		BeamioChatPgpKeychain.memory = savedMemory
		AddressPGPChain.configuration = savedConfiguration
		AddressPGPChain.shellEndpointSecond = savedSecond
		BeamioPGPRegistrar.apiBase = savedApi
		BeamioPGPIdentityCreate.generateKeyPair = savedGenerate
		BeamioPGPRegistrar.post = BeamioPGPRegistrar.defaultPost
		BeamioPGPRegistrar.pollDelays = [2, 4, 8, 16, 32]
		BeamioPGPRegistrar.sleep = { Thread.sleep(forTimeInterval: $0) }
		BeamioPGPRegistrar.readAgreed = { AddressPGPChain.readAgreed(eoa: $0) }
		BeamioPGPRegistrar.identityOf = { BeamioPGPBackup.keyIdentity(armor: $0) }
		BeamioPGPRegistrar.chooseRoute = BeamioPGPRegistrar.defaultChooseRoute
		BeamioPGPRegistrar.sign = { BeamioChatRouteRegister.signedRegistration(account: $0, privateArmor: $1, request: $2, timestamp: $3, iv: $4, nonce: $5) }
		BeamioFirstIdentityCoordinator.readAgreed = { AddressPGPChain.readAgreed(eoa: $0) }
		BeamioFirstIdentityCoordinator.isLocked = { BeamioPasscodeSession.shared.isLocked(eoa: $0) }
		BeamioFirstIdentityCoordinator.legacy = { BeamioFirstIdentity.legacy(eoa: $0) }
		BeamioPGPIdentityCreate.resetInFlightIdentities()
		BeamioPGPIdentityCreate.resetCompletedIdentities()
		super.tearDown()
	}

	private var empty: AddressPGPChain.Snapshot { AddressPGPChain.Snapshot(exists: false, publicArmor: "", backupBase64: "") }
	private func registered(_ armor: String) -> AddressPGPChain.Snapshot { AddressPGPChain.Snapshot(exists: true, publicArmor: armor, backupBase64: "QUJD") }

	private func nextRead() -> Result<AddressPGPChain.Agreed, Error> {
		defer { reads += 1 }
		if chainFails { return .failure(AddressPGPChain.ReadError.transport("down")) }
		let snapshot = chain[min(reads, chain.count - 1)]
		return .success(AddressPGPChain.Agreed(snapshot: snapshot, block: "0x10", blockHash: "0x" + String(repeating: "a", count: 64)))
	}

	private var pendingNow: BeamioChatPgpKeychain.PendingIdentity? { BeamioChatPgpKeychain.loadPending(eoa: eoa) }

	// MARK: - the coordinator

	/// Nothing registered on both endpoints: the key is made once, signed, posted once, found on the chain, and saved with the route it was registered with. The pending key is gone.
	func testAFirstIdentityIsMadeRegisteredAndSavedWithItsRoute() throws {
		chain = [empty, empty, empty, registered(publicA)]   // S1, S3, first read back, second read back
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		XCTAssertEqual(generated, 1)
		XCTAssertEqual(posts.count, 1)
		XCTAssertEqual(posts.first?["routeKeyID"] as? String, "node1.test")
		let record = try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: eoa))
		XCTAssertEqual(record.privateKeyArmor, privateA)
		XCTAssertEqual(record.publicKeyArmor, publicA)
		XCTAssertEqual(record.routePublicKeyArmor, routeArmor, "the record holds the route it was registered with")
		XCTAssertNil(pendingNow, "the pending key is erased")
		XCTAssertNotNil(BeamioChatPgpKeychain.publicRecord(eoa: eoa).flatMap { $0.routePublicKeyArmor.isEmpty ? nil : $0 }, "identityPublic has the three parts")
	}

	/// The chain already holds a registration at S1: the restore flow owns it, nothing is made, nothing is sent.
	func testARegisteredAccountIsLeftToTheRestoreFlow() {
		chain = [registered(publicB)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .registeredElsewhere)
		XCTAssertEqual(generated, 0); XCTAssertTrue(posts.isEmpty); XCTAssertNil(pendingNow)
	}

	/// A backup alone (no record) is a registration too.
	func testABackupAloneIsNotAFirstIdentity() {
		chain = [AddressPGPChain.Snapshot(exists: false, publicArmor: "", backupBase64: "QUJD")]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .registeredElsewhere)
		XCTAssertEqual(generated, 0)
	}

	/// A read that fails or disagrees is never "nothing registered": nothing is made.
	func testAChainReadThatFailsMakesNothing() {
		chainFails = true
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .retryLater("chain_read"))
		XCTAssertEqual(generated, 0); XCTAssertTrue(posts.isEmpty); XCTAssertNil(pendingNow)
	}

	func testAnOldChatKeyOnTheDeviceIsNotAFirstIdentity() {
		legacyState = .present
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .notFirst)
		XCTAssertEqual(generated, 0)
		legacyState = .unreadable
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .notFirst)
		XCTAssertEqual(generated, 0)
	}

	func testALockedAccountMakesNothing() {
		locked = true
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .locked)
		XCTAssertEqual(generated, 0); XCTAssertTrue(posts.isEmpty); XCTAssertEqual(reads, 0)
	}

	/// A pending key is never made again: a run after an interruption goes on from S3 with the same key.
	func testAPendingKeyIsNeverRegeneratedAndTheRunGoesOnFromTheSecondRead() throws {
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: eoa, .init(privateArmor: privateA, publicArmor: publicA, idempotencyKey: "k1", seen: "s", mode: "first")))
		chain = [empty, registered(publicA)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		XCTAssertEqual(generated, 0, "the pending key is used, not replaced")
		XCTAssertEqual(posts.count, 1)
		XCTAssertEqual(try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: eoa)).publicKeyArmor, publicA)
	}

	/// Before the submission the chain shows another key: a conflict. Nothing is sent, the pending key stays.
	func testAnotherKeyBeforeTheSubmissionIsAConflictAndSendsNothing() {
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: eoa, .init(privateArmor: privateA, publicArmor: publicA, idempotencyKey: "k1", seen: "s", mode: "first")))
		chain = [registered(publicB)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .conflict)
		XCTAssertTrue(posts.isEmpty)
		XCTAssertNotNil(pendingNow, "the pending key is kept")
	}

	/// Before the submission the chain already shows this very key (an earlier submission got through): no second post; the record is saved with the route that was kept with the pending key.
	func testThisKeyAlreadyOnTheChainIsActivatedWithoutASecondPost() throws {
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: eoa, .init(privateArmor: privateA, publicArmor: publicA, idempotencyKey: "k1", seen: "s", mode: "first", routeKeyID: "node9.test", routeArmor: routeArmor)))
		chain = [registered(publicA)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		XCTAssertTrue(posts.isEmpty)
		XCTAssertEqual(try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: eoa)).routePublicKeyArmor, routeArmor)
	}

	/// Without a route that was kept, a key found on the chain is not activated on a guess.
	func testAKeyFoundWithoutAKeptRouteIsNotActivatedOnAGuess() {
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: eoa, .init(privateArmor: privateA, publicArmor: publicA, idempotencyKey: "k1", seen: "s", mode: "first")))
		chain = [registered(publicA)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .retryLater("route_unknown"))
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: eoa))
		XCTAssertNotNil(pendingNow)
	}

	/// A 4xx other than 409 is refused: no read back loop, nothing is sent again at once, the pending key stays.
	func testARefusedRequestIsNotReadBackAndKeepsThePendingKey() {
		postStatus = 403
		chain = [empty]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .refused(403))
		XCTAssertEqual(posts.count, 1)
		XCTAssertEqual(reads, 2, "only the two reads before the submission")
		XCTAssertNotNil(pendingNow)
	}

	/// 409, a server failure and no answer all go to the read back; nothing visible in the window is retry_later with the pending key kept, and the next run signs again (a new nonce, the same key).
	func testNothingVisibleInTheWindowIsRetryLaterAndTheNextRunSignsAgain() throws {
		for status in [409, 500, nil] as [Int?] {
			BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
			posts = []; reads = 0; generated = 0
			postStatus = status
			chain = [empty]
			XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .retryLater(status == 409 ? "readback_timeout" : "submit_5xx"), "status \(String(describing: status))")
			XCTAssertEqual(reads, 2 + 3, "the two reads and the three read back steps")
		}
		// the next run: same pending key, one more post with another nonce
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		posts = []; reads = 0; generated = 0; postStatus = 200
		chain = [empty]
		_ = BeamioFirstIdentityCoordinator.run(eoa: eoa)
		let keyBefore = try XCTUnwrap(pendingNow).publicArmor
		let firstNonce = posts.first?["nonce"] as? String
		reads = 0; chain = [empty, empty, registered(publicA)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		XCTAssertEqual(generated, 1, "no second key was made")
		XCTAssertEqual(posts.count, 2)
		XCTAssertNotEqual(posts.last?["nonce"] as? String, firstNonce, "a new signature, a new nonce")
		XCTAssertEqual(try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: eoa)).publicKeyArmor, keyBefore)
	}

	/// After the post the chain shows another key: a conflict, not a registration.
	func testAnotherKeyInTheReadBackWindowIsAConflict() {
		chain = [empty, empty, registered(publicB)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .conflict)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: eoa))
		XCTAssertNotNil(pendingNow)
	}

	/// A local key that was never registered and holds no route is discarded and made again; a record that holds a route is not touched.
	func testAnUnregisteredLocalKeyIsDiscardedAndMadeAgainOnlyWithoutARoute() throws {
		let bare = BeamioChatPgpKeychain.Secrets(privateKeyArmor: privateA, publicKeyArmor: publicA, pgpKeyId: "AAAAAAAAAAAAAAAA", routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)
		XCTAssertTrue(BeamioChatPgpKeychain.save(bare))
		chain = [empty, empty, empty, empty, registered(publicA)]
		BeamioPGPIdentityCreate.generateKeyPair = { [unowned self] _ in self.generated += 1; return .success((self.privateA, self.publicB.replacingOccurrences(of: "synthetic-b", with: "synthetic-a"))) }
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		XCTAssertEqual(generated, 1, "made again")
		// with a route the record stays
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		var routed = bare; routed.routePublicKeyArmor = routeArmor
		XCTAssertTrue(BeamioChatPgpKeychain.save(routed))
		generated = 0; reads = 0; chain = [empty]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .retryLater("record_unregistered"))
		XCTAssertEqual(generated, 0)
		XCTAssertNotNil(BeamioChatPgpKeychain.load(eoa: eoa))
	}

	/// A registered local key with the same key on the chain is the active identity: nothing is made.
	func testTheActiveIdentityIsLeftAlone() throws {
		let record = BeamioChatPgpKeychain.Secrets(privateKeyArmor: privateA, publicKeyArmor: publicA, pgpKeyId: "AAAAAAAAAAAAAAAA", routePublicKeyArmor: routeArmor, entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)
		XCTAssertTrue(BeamioChatPgpKeychain.save(record))
		chain = [registered(publicA)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		XCTAssertEqual(generated, 0); XCTAssertTrue(posts.isEmpty)
	}

	/// One run at a time per account.
	func testASecondRunWhileOneIsRunningIsBusy() {
		XCTAssertTrue(BeamioPGPIdentityCreate.beginWrite(eoa: eoa))
		defer { BeamioPGPIdentityCreate.endWrite(eoa: eoa) }
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .retryLater("busy"))
		XCTAssertEqual(generated, 0)
	}

	/// A lock found before the signature stops the submission: nothing is sent.
	func testALockBeforeTheSignatureSendsNothing() {
		chain = [empty]
		BeamioPGPRegistrar.sign = { [unowned self] _, _, _, _, _, _ in self.locked = true; return .failure(.init(code: "locked")) }
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .locked)
		XCTAssertTrue(posts.isEmpty)
		XCTAssertNotNil(pendingNow)
	}

	/// A lock found at each of the points before the generation, the second read, the signature and the post: nothing is generated, signed or sent from there on, and the pending key stays.
	func testALockAtEachPointStopsTheRun() {
		// the lock is asked at: the start, before the generation, before S3, before the registration, and before the signature
		for lockedAt in 1 ... 5 {
			BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
			posts = []; reads = 0; generated = 0; signCount = 0
			chain = [empty]
			var asked = 0
			BeamioFirstIdentityCoordinator.isLocked = { _ in asked += 1; return asked >= lockedAt }
			XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .locked, "locked at question \(lockedAt)")
			XCTAssertTrue(posts.isEmpty, "locked at question \(lockedAt): nothing is posted")
			XCTAssertEqual(signCount, 0, "locked at question \(lockedAt): nothing is signed")
			XCTAssertEqual(generated, lockedAt <= 1 ? 0 : (lockedAt == 2 ? 0 : 1), "locked at question \(lockedAt)")
			if lockedAt >= 3 { XCTAssertNotNil(pendingNow, "the pending key stays") } else { XCTAssertNil(pendingNow) }
		}
	}

	// MARK: - the scheduler and the QA states

	func testTheSchedulerRunsOnlyWhenTheRegistrationIsConfiguredAndReportsTheStates() {
		BeamioConetChatModule.firstIdentityStatusForTests = []
		BeamioPGPRegistrar.apiBase = nil
		BeamioFirstIdentityScheduler.synchronous = true
		defer { BeamioFirstIdentityScheduler.synchronous = false }
		BeamioFirstIdentityScheduler.kick(eoa: eoa)
		XCTAssertEqual(generated, 0, "not configured: nothing runs")
		XCTAssertTrue(BeamioConetChatModule.firstIdentityStatusForTests.isEmpty)
	}

	// MARK: - the registrar

	func testTheStatusClassesOfThePost() {
		XCTAssertEqual(BeamioPGPRegistrar.classify(200), .accepted)
		XCTAssertEqual(BeamioPGPRegistrar.classify(409), .conflict)
		XCTAssertEqual(BeamioPGPRegistrar.classify(400), .refused(400))
		XCTAssertEqual(BeamioPGPRegistrar.classify(403), .refused(403))
		XCTAssertEqual(BeamioPGPRegistrar.classify(503), .server(503))
		XCTAssertEqual(BeamioPGPRegistrar.classify(nil), .network)
	}

	func testThePostBodyHasExactlyTheEightFieldsAndNoPrivateKey() throws {
		chain = [empty, empty, registered(publicA)]
		XCTAssertEqual(BeamioFirstIdentityCoordinator.run(eoa: eoa), .active)
		let body = try XCTUnwrap(posts.first)
		XCTAssertEqual(Set(body.keys), ["wallet", "keyID", "publicKeyArmored", "encrypKeyArmored", "routeKeyID", "timestamp", "nonce", "signature"])
		XCTAssertFalse("\(body)".contains("PRIVATE KEY"), "no private armor in the request")
		XCTAssertEqual(Data(base64Encoded: body["publicKeyArmored"] as? String ?? "").flatMap { String(data: $0, encoding: .utf8) }, publicA, "the public key goes as the base64 text of its armor")
	}

	// MARK: - the confirmation flow with the product registration

	/// The route a registration chose is in the saved record (identityPublic needs it), and the confirmation is cancelled by a lock.
	func testTheConfirmationSavesTheRouteOfTheRegistration() throws {
		final class Probe: BeamioPGPIdentityCreate.Registering {
			let armor: String
			init(_ armor: String) { self.armor = armor }
			func register(eoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error> { .success(()) }
			func routeArmor(registered eoa: String) -> String { armor }
		}
		let saved = BeamioPGPIdentityCreate.registration
		BeamioPGPIdentityCreate.registration = Probe(routeArmor)
		defer { BeamioPGPIdentityCreate.registration = saved }
		let pending = BeamioChatPgpKeychain.PendingIdentity(privateArmor: privateA, publicArmor: publicA, idempotencyKey: "k1", seen: "s", mode: "first")
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: eoa, pending))
		XCTAssertEqual(BeamioPGPIdentityCreate.activate(eoa: eoa, pending: pending, routeArmor: routeArmor), .ok)
		XCTAssertEqual(try XCTUnwrap(BeamioChatPgpKeychain.load(eoa: eoa)).routePublicKeyArmor, routeArmor)
	}

	func testTheSameKeyIsComparedByNormalizedArmorNotByRawText() {
		XCTAssertTrue(BeamioPGPRegistrar.sameKey(publicA, publicA + "\n"))
		XCTAssertFalse(BeamioPGPRegistrar.sameKey(publicA, publicB))
	}
}
#endif
