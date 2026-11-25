#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The new-account registration protocol (v1): the command `accountCreateRegister` through the bridge (N-01 to N-07, N-10), the event `firstIdentityStatus` (N-11 to N-13)
/// and `identityPublic` (N-14, N-15). Synthetic data only; the chain, the API and the OpenPGP wrapper are replaced.
final class NewAccountProtocolTests: XCTestCase {
	private let phrase = "legal winner thank year wave sausage worth useful legal winner thank yellow"
	private var eoa: String { BeamioPwaWalletSync.derivedAccount(phrase: phrase)!.eoa }

	private final class Records: BeamioPasscodeRecordStoring {
		var data: [String: Data] = [:]
		func enumerateRecordOwners() -> [String]? { Array(data.keys) }
		func readRecord(eoa: String) -> Data? { data[eoa.lowercased()] }
		func writeRecord(eoa: String, _ value: Data) -> Bool { data[eoa.lowercased()] = value; return true }
		func deleteRecord(eoa: String) { data[eoa.lowercased()] = nil }
	}

	private final class Hardware: BeamioPasscodeHardwareKeyStoring {
		var isSecureEnclave: Bool { false }
		func hasKey(eoa: String) -> Bool { true }
		func createKey(eoa: String) -> Bool { true }
		func wrap(_ plain: Data, eoa: String, aad: Data) throws -> Data { plain }
		func unwrap(_ blob: Data, eoa: String, aad: Data) throws -> Data { blob }
		func deleteKey(eoa: String) {}
	}

	private var savedStore: BeamioChatWalletKeyStoring!
	private var savedVault: BeamioPasscodeVault?
	private var savedMemory: BeamioChatPgpKeychain.MemoryRecords?
	private var savedRegistryOwner: ((String) -> Result<AddressPGPChain.RegistryOwner, Error>)!
	private var passcodeRecords: Records!

	override func setUp() {
		super.setUp()
		savedStore = BeamioNativeWallet.keyStore
		savedVault = BeamioPasscodeSession.shared.vault
		savedMemory = BeamioChatPgpKeychain.memory
		savedRegistryOwner = BeamioAccountRegisterPayload.registryOwner
		NativeAccountPointerIsolation.begin()
		let store = MemoryNativeKeyStore()
		XCTAssertTrue(store.writeItem(.mnemonic, eoa: eoa, value: Data(phrase.utf8)))
		BeamioNativeWallet.keyStore = store
		// no passcode on the account: not locked
		passcodeRecords = Records()
		BeamioPasscodeSession.shared.vault = BeamioPasscodeVault(records: passcodeRecords, hardware: Hardware())
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioConetChatSignBroker.setSignerEoa(eoa)
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		BeamioAccountRegisterPayload.registryOwner = { _ in .success(.free) }
		BeamioNewAccountFeature.enabledForTests = true
		BeamioConetChatModule.firstIdentityStatusForTests = []
	}

	override func tearDown() {
		BeamioAccountRegisterPayload.registryOwner = savedRegistryOwner
		BeamioNewAccountFeature.enabledForTests = true
		BeamioChatPgpKeychain.memory = savedMemory
		BeamioPasscodeSession.shared.vault = savedVault
		BeamioNativeWallet.keyStore = savedStore
		BeamioConetChatSignBroker.clearSigner()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// Sends one command and waits for its one answer.
	private func send(_ body: [String: Any], timeout: TimeInterval = 20) -> [String: Any] {
		var answer: [String: Any]?
		let done = expectation(description: "answered")
		let reqId = body["reqId"]
		BeamioConetChatModule.handleCommand(body) { payload in
			guard answer == nil, let event = payload["event"] as? [String: Any], "\(event["reqId"] ?? "")" == "\(reqId ?? "")" else { return }
			answer = event
			done.fulfill()
		}
		wait(for: [done], timeout: timeout)
		return answer ?? [:]
	}

	private func request(_ extra: [String: Any] = [:]) -> [String: Any] {
		var body: [String: Any] = ["type": "accountCreateRegister", "reqId": "page-req-1", "tag": "alice", "password": "a long enough password"]
		for (k, v) in extra { body[k] = v }
		return body
	}

	// MARK: - the command

	/// N-01: only the four keys; a missing or an extra key or a wrong type is bad_request.
	func testN01TheRequestKeysAreAWhitelist() {
		var noTag = request(); noTag.removeValue(forKey: "tag")
		XCTAssertEqual(send(noTag)["error"] as? String, "bad_request")
		var noPassword = request(); noPassword.removeValue(forKey: "password")
		XCTAssertEqual(send(noPassword)["error"] as? String, "bad_request")
		XCTAssertEqual(send(request(["extra": "x"]))["error"] as? String, "bad_request")
		XCTAssertEqual(send(request(["accountName": "alice"]))["error"] as? String, "bad_request", "the old name of the key is not accepted")
		XCTAssertEqual(send(request(["tag": 12]))["error"] as? String, "bad_request")
		XCTAssertEqual(send(request(["password": ["x"]]))["error"] as? String, "bad_request")
	}

	/// N-02 and the code table: a bad tag, an empty password.
	func testN02ABadTagAndAnEmptyPasswordAreAnswered() {
		XCTAssertEqual(send(request(["tag": "ab"]))["error"] as? String, "bad_tag")
		XCTAssertEqual(send(request(["tag": "bad tag"]))["error"] as? String, "bad_tag")
		XCTAssertEqual(send(request(["password": ""]))["error"] as? String, "bad_password")
	}

	/// N-03 and N-06: the answer carries only the whitelisted keys, no plaintext, no password; the wallet is lower case.
	func testN03TheSuccessAnswerIsWhitelistedAndHasNoPlaintext() throws {
		let answer = send(request(["password": "unique-password-777"]))
		XCTAssertEqual(answer["ok"] as? Bool, true)
		XCTAssertEqual(answer["reqId"] as? String, "page-req-1")
		let result = try XCTUnwrap(answer["result"] as? [String: Any])
		XCTAssertEqual(Set(result.keys), ["accountName", "wallet", "signMessage", "recover", "recoverCodeBase58"])
		XCTAssertEqual(result["accountName"] as? String, "alice")
		XCTAssertEqual(result["wallet"] as? String, eoa)
		for entry in try XCTUnwrap(result["recover"] as? [[String: Any]]) { XCTAssertEqual(Set(entry.keys), ["hash", "encrypto"]) }
		let text = "\(answer)"
		XCTAssertFalse(text.contains("unique-password-777"))
		for word in phrase.split(separator: " ") where word.count > 4 { XCTAssertFalse(text.contains(word), "no phrase word in the answer") }
		XCTAssertFalse(text.contains("PRIVATE KEY"))
		// N-10: the records are the ones the native restore reads
		let code = try XCTUnwrap(result["recoverCodeBase58"] as? String)
		XCTAssertEqual(code.count, 22)
		let recover = try XCTUnwrap(result["recover"] as? [[String: String]])
		XCTAssertNotNil(BeamioNativeRecovery.Record(base64JSON: try XCTUnwrap(recover[0]["encrypto"])))
		XCTAssertNotNil(BeamioNativeRecovery.Record(base64JSON: try XCTUnwrap(recover[1]["encrypto"])))
	}

	/// The signature rule: the Cluster checks `ethers.verifyMessage(wallet as sent, signMessage)` and compares the recovered address in lower case, so the signed text must
	/// be character for character the wallet string of the request. The answer of the command verifies the way the server does; another case of the same wallet, or the checksummed form,
	/// does not.
	func testTheSignatureVerifiesAgainstTheWalletStringAsSentAndFailsForAnotherCase() throws {
		let result = try XCTUnwrap(send(request())["result"] as? [String: Any])
		let wallet = try XCTUnwrap(result["wallet"] as? String)
		let signature = try XCTUnwrap(result["signMessage"] as? String)
		XCTAssertEqual(wallet, wallet.lowercased(), "the wallet is sent in lower case")
		// the server's check: recover from the wallet string as sent, compare in lower case
		XCTAssertEqual(BeamioNativeEthSigner.recoverEip191AddressForTests(message: wallet, signature: signature)?.lowercased(), wallet.lowercased(), "verifies against the wallet text as sent")
		// the same wallet in another case is another text: the recovered address is another one, so the check fails
		let checksummed = try XCTUnwrap(BeamioNativeEthSigner.address(privateKey: [UInt8](BeamioPwaWalletSync.derivedAccount(phrase: phrase)!.key)))
		XCTAssertNotEqual(checksummed, wallet, "the checksummed form differs in case")
		XCTAssertNotEqual(BeamioNativeEthSigner.recoverEip191AddressForTests(message: checksummed, signature: signature)?.lowercased(), wallet.lowercased(), "the checksummed text is not what was signed")
		let upper = "0x" + wallet.dropFirst(2).uppercased()
		XCTAssertNotEqual(BeamioNativeEthSigner.recoverEip191AddressForTests(message: upper, signature: signature)?.lowercased(), wallet.lowercased(), "another case fails")
	}

	/// N-05: the whole command with the standard error captured: no password, no recover code, no phrase word in the log.
	func testN05TheLogsHoldNoSecret() throws {
		let path = NSTemporaryDirectory() + "create-log-\(UUID().uuidString).txt"
		FileManager.default.createFile(atPath: path, contents: nil)
		defer { try? FileManager.default.removeItem(atPath: path) }
		let handle = try XCTUnwrap(FileHandle(forWritingAtPath: path))
		let saved = dup(STDERR_FILENO)
		dup2(handle.fileDescriptor, STDERR_FILENO)
		let answer = send(request(["password": "log-secret-password-9"]))
		fflush(stderr)
		dup2(saved, STDERR_FILENO); close(saved)
		try handle.close()
		let log = try String(contentsOfFile: path, encoding: .utf8).lowercased()
		XCTAssertFalse(log.contains("log-secret-password-9"))
		let code = ((answer["result"] as? [String: Any])?["recoverCodeBase58"] as? String ?? "?").lowercased()
		XCTAssertFalse(log.contains(code))
		XCTAssertFalse(phrase.split(separator: " ").contains { $0.count > 4 && log.contains($0) })
	}

	/// The tag held by another account is tag_taken; a registry that cannot be read is not_ready, never tag_taken.
	func testTheRegistryDecidesTagTakenAndAReadFailureIsNotReady() {
		BeamioAccountRegisterPayload.registryOwner = { _ in .success(.owner("0x" + String(repeating: "cd", count: 20))) }
		XCTAssertEqual(send(request())["error"] as? String, "tag_taken")
		BeamioAccountRegisterPayload.registryOwner = { _ in .failure(AddressPGPChain.ReadError.disagreement("answer")) }
		XCTAssertEqual(send(request())["error"] as? String, "not_ready")
	}

	/// N-07: while one command of the account is running, the second answers in_flight; after it ends, the next one runs.
	func testN07ASecondCommandWhileOneRunsIsInFlight() {
		let entered = expectation(description: "the first command reached the registry read")
		let release = DispatchSemaphore(value: 0)
		BeamioAccountRegisterPayload.registryOwner = { _ in
			entered.fulfill()
			_ = release.wait(timeout: .now() + 20)
			return .success(.free)
		}
		// one emit closure for every command (the bridge keeps the last one)
		var answers: [String: [String: Any]] = [:]
		let emit: BeamioConetChatModule.WebEmit = { payload in
			guard let event = payload["event"] as? [String: Any], let id = event["reqId"] as? String else { return }
			answers[id] = event
		}
		func wait(for id: String) {
			let deadline = Date().addingTimeInterval(20)
			while answers[id] == nil && Date() < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.02)) }
		}
		BeamioConetChatModule.handleCommand(request(["reqId": "page-req-A"]), emit: emit)
		self.wait(for: [entered], timeout: 10)
		BeamioConetChatModule.handleCommand(request(["reqId": "page-req-B"]), emit: emit)
		wait(for: "page-req-B")
		XCTAssertEqual(answers["page-req-B"]?["error"] as? String, "in_flight")
		release.signal()
		wait(for: "page-req-A")
		XCTAssertEqual(answers["page-req-A"]?["ok"] as? Bool, true)
		BeamioAccountRegisterPayload.registryOwner = { _ in .success(.free) }
		BeamioConetChatModule.handleCommand(request(["reqId": "page-req-C"]), emit: emit)
		wait(for: "page-req-C")
		XCTAssertEqual(answers["page-req-C"]?["ok"] as? Bool, true, "the account is free again")
	}

	/// A build that does not enable the command answers not_available, whatever the request.
	func testABuildWithoutTheFeatureAnswersNotAvailable() {
		BeamioNewAccountFeature.enabledForTests = false
		XCTAssertEqual(send(request())["error"] as? String, "not_available")
		XCTAssertEqual(send(request(["extra": 1]))["error"] as? String, "not_available", "judged before the request is read")
	}

	/// The Release hello list names neither the first-identity status nor the route registration (QA only until the acceptance).
	func testTheShippedHelloListHasNoQANames() {
		XCTAssertFalse(BeamioConetChatProtocol.capabilities.contains("identity.first.status.v1"))
		XCTAssertFalse(BeamioConetChatProtocol.capabilities.contains("identity.route-register.native.v1"))
	}

	// MARK: - the status event

	private let allowedKeys: Set<String> = ["type", "state", "reason", "attempt", "retryAfterMs"]
	private let allowedStates: Set<String> = ["registering", "registered", "retry_later", "identity_pending", "failed"]
	private let allowedReasons: Set<String> = ["no_record_confirmed", "read_unavailable", "submit_5xx", "submit_4xx", "conflict_other_key", "readback_timeout"]

	private let publicA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-a\n-----END PGP PUBLIC KEY BLOCK-----"
	private let privateA = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-a\n-----END PGP PRIVATE KEY BLOCK-----"
	private let routeArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-route\n-----END PGP PUBLIC KEY BLOCK-----"

	private var chain: [AddressPGPChain.Snapshot] = []
	private var reads = 0
	private var chainFails = false
	private var postStatus: Int? = 200
	private var posts = 0
	private var generated = 0

	/// The registration world: both endpoints, the API and the key generation are replaced; the scheduler runs in the test.
	private func runSchedule(delays: [TimeInterval] = [0, 0, 0]) {
		let savedConfiguration = AddressPGPChain.configuration, savedSecond = AddressPGPChain.shellEndpointSecond, savedApi = BeamioPGPRegistrar.apiBase
		let savedGenerate = BeamioPGPIdentityCreate.generateKeyPair
		AddressPGPChain.configuration = AddressPGPChain.Configuration(contract: "0x" + String(repeating: "1", count: 40), chainId: 224422, rpcURL: URL(string: "https://rpc1.test.invalid")!)
		AddressPGPChain.shellEndpointSecond = URL(string: "https://rpc2.test.invalid")
		BeamioPGPRegistrar.apiBase = URL(string: "https://api.test.invalid")
		BeamioPGPRegistrar.pollDelays = [0, 0]
		BeamioPGPRegistrar.sleep = { _ in }
		BeamioPGPRegistrar.readAgreed = { [unowned self] _ in self.nextRead() }
		BeamioFirstIdentityCoordinator.readAgreed = { [unowned self] _ in self.nextRead() }
		BeamioFirstIdentityCoordinator.isLocked = { _ in false }
		BeamioFirstIdentityCoordinator.legacy = { _ in .absent }
		BeamioPGPRegistrar.identityOf = { armor in (String(BeamioChatRouteRegister.normalizedArmor(armor).hashValue.magnitude, radix: 16).uppercased(), "AAAAAAAAAAAAAAAA") }
		BeamioPGPRegistrar.chooseRoute = { [unowned self] in ("node1.test", self.routeArmor) }
		BeamioPGPRegistrar.sign = { account, _, request, _, _, nonce in
			.success(["wallet": account, "keyID": request.keyID, "publicKeyArmored": request.publicKeyArmored, "encrypKeyArmored": "b", "routeKeyID": request.routeKeyID, "timestamp": 1, "nonce": "0x00", "signature": "0x00"])
		}
		BeamioPGPRegistrar.post = { [unowned self] _, _ in self.posts += 1; return self.postStatus }
		BeamioPGPIdentityCreate.generateKeyPair = { [unowned self] _ in self.generated += 1; return .success((self.privateA, self.publicA)) }
		BeamioFirstIdentityScheduler.delays = delays
		BeamioFirstIdentityScheduler.sleep = { _ in }
		BeamioFirstIdentityScheduler.synchronous = true
		BeamioPGPIdentityCreate.resetInFlightIdentities(); BeamioPGPIdentityCreate.resetCompletedIdentities()
		defer {
			BeamioFirstIdentityScheduler.synchronous = false
			BeamioFirstIdentityScheduler.delays = [0, 30, 60, 120, 300]
			BeamioFirstIdentityScheduler.sleep = { Thread.sleep(forTimeInterval: $0) }
			AddressPGPChain.configuration = savedConfiguration
			AddressPGPChain.shellEndpointSecond = savedSecond
			BeamioPGPRegistrar.apiBase = savedApi
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
			BeamioPGPIdentityCreate.generateKeyPair = savedGenerate
			BeamioPGPIdentityCreate.resetInFlightIdentities(); BeamioPGPIdentityCreate.resetCompletedIdentities()
		}
		BeamioFirstIdentityScheduler.kick(eoa: eoa)
	}

	private func nextRead() -> Result<AddressPGPChain.Agreed, Error> {
		defer { reads += 1 }
		if chainFails { return .failure(AddressPGPChain.ReadError.transport("down")) }
		return .success(AddressPGPChain.Agreed(snapshot: chain[min(reads, chain.count - 1)], block: "0x10", blockHash: "0x" + String(repeating: "a", count: 64)))
	}

	private var empty: AddressPGPChain.Snapshot { AddressPGPChain.Snapshot(exists: false, publicArmor: "", backupBase64: "") }
	private func registered(_ armor: String) -> AddressPGPChain.Snapshot { AddressPGPChain.Snapshot(exists: true, publicArmor: armor, backupBase64: "QUJD") }
	private var events: [[String: Any]] { BeamioConetChatModule.firstIdentityStatusForTests }
	private var states: [String] { events.compactMap { $0["state"] as? String } }

	private func assertEventsAreWhitelisted(file: StaticString = #filePath, line: UInt = #line) {
		for event in events {
			XCTAssertTrue(Set(event.keys).isSubset(of: allowedKeys), "keys \(event.keys)", file: file, line: line)
			XCTAssertTrue(allowedStates.contains(event["state"] as? String ?? "?"), file: file, line: line)
			if let reason = event["reason"] as? String { XCTAssertTrue(allowedReasons.contains(reason), reason, file: file, line: line) }
			XCTAssertFalse("\(event)".contains("BEGIN PGP"), "no armor in an event", file: file, line: line)
		}
	}

	/// N-11: the five states exist with the whitelisted keys; the happy path is registering then registered.
	func testN11TheHappyPathIsRegisteringThenRegistered() {
		chain = [empty, empty, empty, registered(publicA)]; reads = 0; posts = 0; generated = 0; postStatus = 200; chainFails = false
		runSchedule()
		XCTAssertEqual(states, ["registering", "registered"])
		XCTAssertEqual(events.first?["reason"] as? String, "no_record_confirmed")
		XCTAssertEqual(events.first?["attempt"] as? Int, 1)
		assertEventsAreWhitelisted()
	}

	/// N-13: a read failure is retry_later with read_unavailable and nothing is generated, ever; the schedule ends without an identity_pending (nothing was submitted).
	func testN13AReadFailureIsRetryLaterAndNeverGenerates() {
		chain = [empty]; reads = 0; posts = 0; generated = 0; chainFails = true
		runSchedule()
		XCTAssertEqual(generated, 0)
		XCTAssertEqual(posts, 0)
		XCTAssertEqual(states, ["registering", "retry_later", "registering", "retry_later", "registering", "retry_later"])
		XCTAssertTrue(events.filter { $0["state"] as? String == "retry_later" }.allSatisfy { $0["reason"] as? String == "read_unavailable" })
		XCTAssertNotNil(events.first { $0["state"] as? String == "retry_later" }?["retryAfterMs"], "the wait of the next attempt")
		assertEventsAreWhitelisted()
	}

	/// N-12: a refusal (4xx) is failed with submit_4xx, and it is the end: no further attempt, no overwrite by a later state.
	func testN12AFailedStateIsTheEnd() {
		chain = [empty]; reads = 0; posts = 0; generated = 0; postStatus = 403; chainFails = false
		runSchedule()
		XCTAssertEqual(states, ["registering", "failed"])
		XCTAssertEqual(events.last?["reason"] as? String, "submit_4xx")
		XCTAssertEqual(posts, 1)
		assertEventsAreWhitelisted()
	}

	func testAnotherKeyOnTheChainIsFailedWithConflictOtherKey() {
		let other = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-other\n-----END PGP PUBLIC KEY BLOCK-----"
		chain = [empty, empty, registered(other)]; reads = 0; posts = 0; generated = 0; postStatus = 200; chainFails = false
		runSchedule()
		XCTAssertEqual(states, ["registering", "failed"])
		XCTAssertEqual(events.last?["reason"] as? String, "conflict_other_key")
		assertEventsAreWhitelisted()
	}

	/// A submitted registration that is not read back in the whole schedule stays pending (identity_pending with readback_timeout), and nothing is made again.
	func testASubmittedRegistrationThatIsNeverReadBackIsIdentityPending() {
		chain = [empty]; reads = 0; posts = 0; generated = 0; postStatus = 503; chainFails = false
		runSchedule(delays: [0, 0])
		XCTAssertEqual(generated, 1, "the key was made once and kept")
		XCTAssertEqual(states.last, "identity_pending")
		XCTAssertEqual(events.last?["reason"] as? String, "readback_timeout")
		XCTAssertTrue(events.filter { $0["state"] as? String == "retry_later" }.allSatisfy { $0["reason"] as? String == "submit_5xx" })
		assertEventsAreWhitelisted()
	}

	/// An account that is not in the first-identity flow (the chain holds a registration) gets no event.
	func testARegistrationThatIsThereIsLeftToTheRestoreFlowWithoutAnEvent() {
		chain = [registered("-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-other\n-----END PGP PUBLIC KEY BLOCK-----")]; reads = 0; posts = 0; generated = 0; chainFails = false
		runSchedule()
		XCTAssertEqual(states, ["registering"], "no registered, no failed: the restore flow owns it")
		XCTAssertEqual(generated, 0)
	}

	/// The schedule does not start in a build that does not enable it.
	func testTheScheduleDoesNotStartWhereTheFeatureIsOff() {
		BeamioNewAccountFeature.enabledForTests = false
		chain = [empty]; reads = 0; generated = 0
		runSchedule()
		XCTAssertTrue(events.isEmpty)
		XCTAssertEqual(generated, 0)
	}

	// MARK: - identityPublic (N-14, N-15)

	private func identityPublic() -> [String: Any] {
		send(["type": "identityPublic", "reqId": 8801])["result"] as? [String: Any] ?? [:]
	}

	/// N-14 and N-15: pgpReady is true only with the key ID, the public key and the route read back, all three; without the route it is false and no part is returned.
	func testN14AndN15IdentityPublicNeedsAllThreeParts() throws {
		let pointless = BeamioChatPgpKeychain.Secrets(privateKeyArmor: privateA, publicKeyArmor: publicA, pgpKeyId: "AAAAAAAAAAAAAAAA", routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)
		XCTAssertTrue(BeamioChatPgpKeychain.save(pointless))
		let without = identityPublic()
		XCTAssertEqual(without["pgpReady"] as? Bool, false)
		XCTAssertNil(without["pgpPublicKeyArmored"]); XCTAssertNil(without["ownRouteArmoredPublicKey"]); XCTAssertNil(without["pgpKeyID"])
		var complete = pointless; complete.routePublicKeyArmor = routeArmor
		XCTAssertTrue(BeamioChatPgpKeychain.save(complete))
		let ready = identityPublic()
		XCTAssertEqual(ready["pgpReady"] as? Bool, true)
		XCTAssertEqual(ready["pgpKeyID"] as? String, "AAAAAAAAAAAAAAAA")
		XCTAssertEqual(ready["pgpPublicKeyArmored"] as? String, publicA)
		XCTAssertEqual(ready["ownRouteArmoredPublicKey"] as? String, routeArmor)
		XCTAssertFalse("\(ready)".contains("PRIVATE KEY"))
	}

	// MARK: - the gate states of accountCreateRegister

	/// G0, no native account: not_ready (not the gate's no_key); the registry is not read and no payload is made.
	func testG0NoNativeAccountAnswersNotReadyAndReadsNothing() {
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		var registryReads = 0
		BeamioAccountRegisterPayload.registryOwner = { _ in registryReads += 1; return .success(.free) }
		let answer = send(request())
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "not_ready")
		XCTAssertNil(answer["result"])
		XCTAssertEqual(registryReads, 0)
	}

	/// G1, the state right after nativeAccountCreateOpen: the device has the record, the chat session is not started and no signer is set. The command runs.
	func testG1NativeAccountWithoutASessionRunsTheCommand() throws {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		let answer = send(request())
		XCTAssertEqual(answer["ok"] as? Bool, true, "\(answer)")
		let result = try XCTUnwrap(answer["result"] as? [String: Any])
		XCTAssertEqual(result["wallet"] as? String, eoa)
		XCTAssertEqual(Set(result.keys), ["accountName", "wallet", "signMessage", "recover", "recoverCodeBase58"])
	}

	/// G2: unchanged.
	func testG2StillRunsTheCommand() {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: true)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g2)
		XCTAssertEqual(send(request())["ok"] as? Bool, true)
	}

	/// At G1 the registry is read exactly once for an unlocked record account.
	func testG1ReadsTheRegistryOnce() {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		var registryReads = 0
		BeamioAccountRegisterPayload.registryOwner = { _ in registryReads += 1; return .success(.free) }
		XCTAssertEqual(send(request())["ok"] as? Bool, true)
		XCTAssertEqual(registryReads, 1)
	}

	/// A record account whose passcode is set and not unlocked: not_ready, the registry is not read, nothing is made.
	func testALockedRecordAccountAnswersNotReadyAndReadsNothing() throws {
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		BeamioConetChatSignBroker.clearSigner()
		let record = BeamioPasscodeRecord(mode: "passcode", salt: Data(repeating: 1, count: 16), blob: Data(repeating: 2, count: 32))
		XCTAssertTrue(passcodeRecords.writeRecord(eoa: eoa, try JSONEncoder().encode(record)))
		XCTAssertTrue(BeamioPasscodeSession.shared.isLocked(eoa: eoa), "the account is locked")
		var registryReads = 0
		BeamioAccountRegisterPayload.registryOwner = { _ in registryReads += 1; return .success(.free) }
		let answer = send(request())
		XCTAssertEqual(answer["ok"] as? Bool, false)
		XCTAssertEqual(answer["error"] as? String, "not_ready")
		XCTAssertNil(answer["result"])
		XCTAssertEqual(registryReads, 0)
	}

	/// Only the create command is gate-exempt: the other key commands are still refused by the gate (G0 no_key, G1 not_ready).
	func testTheOtherKeyCommandsAreStillRefusedByTheGate() {
		XCTAssertTrue(BeamioConetChatModule.gateExemptCommands.contains("accountCreateRegister"))
		let others = ["historySign", "gossipSign", "walletSignMessage", "walletSignTypedData", "walletTransfer", "deriveSubkeys", "ephemeralSign"]
		for type in others { XCTAssertFalse(BeamioConetChatModule.gateExemptCommands.contains(type), type) }
		BeamioConetChatSignBroker.clearSigner()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		for (index, type) in others.enumerated() {
			let answer = send(["type": type, "reqId": 9000 + index])
			XCTAssertEqual(answer["error"] as? String, "no_key", "\(type) at G0")
		}
		BeamioConetChatModule.setNativeGateForTests(account: eoa, sessionReady: false)
		XCTAssertEqual(BeamioConetChatModule.nativeGate(), .g1)
		for (index, type) in others.enumerated() {
			let answer = send(["type": type, "reqId": 9100 + index])
			XCTAssertEqual(answer["error"] as? String, "not_ready", "\(type) at G1")
		}
	}
}
#endif
