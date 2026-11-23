#if BEAMIO_TEST_HOOKS
import XCTest
@testable import ConetChatSDK

/// The confirmation path of `pgpIdentityCreate`: provenance codes, erase results, event codes and states. Mock chain
/// (no registration anywhere), generated key injected, memory records. Synthetic data only.
final class IdentityCreateConfirmationTests: XCTestCase {
	private let account = "0x2222222222222222222222222222222222222222"
	private let url = URL(string: "https://rpc-a.invalid")!
	private var savedTransport: ((URL, Data) -> Result<Data, Error>)!
	private var savedGenerate: ((String) -> Result<(privateArmor: String, publicArmor: String), Error>)!
	private var generated = 0

	private final class Registrar: BeamioPGPIdentityCreate.Registering {
		var calls = 0
		func register(eoa: String, publicArmor: String, idempotencyKey: String, seen: String) -> Result<Void, Error> { calls += 1; return .success(()) }
	}
	private var registrar = Registrar()

	private func word(_ n: Int) -> [UInt8] { [UInt8](repeating: 0, count: 24) + withUnsafeBytes(of: UInt64(n).bigEndian) { Array($0) } }
	private func str(_ s: String) -> [UInt8] { let d = Array(s.utf8); return word(d.count) + d + [UInt8](repeating: 0, count: (32 - d.count % 32) % 32) }
	private func hex(_ b: [UInt8]) -> String { "0x" + b.map { String(format: "%02x", $0) }.joined() }

	override func setUp() {
		super.setUp()
		savedTransport = AddressPGPChain.transport
		savedGenerate = BeamioPGPIdentityCreate.generateKeyPair
		AddressPGPChain.configuration = .init(contract: "0x1111111111111111111111111111111111111111", chainId: 224422, rpcURL: url)
		AddressPGPChain.transport = { [unowned self] _, body in
			guard let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let method = o["method"] as? String else { return .failure(AddressPGPChain.ReadError.malformed) }
			func ok(_ r: Any) -> Result<Data, Error> { .success(try! JSONSerialization.data(withJSONObject: ["jsonrpc": "2.0", "id": 1, "result": r])) }
			if method == "eth_chainId" { return ok("0x36ca6") }
			if method == "eth_blockNumber" { return ok("0x1f4") }
			let data = (((o["params"] as? [Any])?.first as? [String: Any])?["data"] as? String) ?? ""
			if data.hasPrefix(self.hex(AddressPGPChain.selector("_pgpKeys(address)"))) {
				let s1 = self.str(""), s2 = self.str(""), s3 = self.str("")
				return ok(self.hex(self.word(128) + self.word(128 + s1.count) + self.word(128 + s1.count + s2.count) + self.word(0) + s1 + s2 + s3))
			}
			return ok(self.hex(self.word(32) + self.str("")))
		}
		BeamioChatPgpKeychain.memory = BeamioChatPgpKeychain.MemoryRecords()
		BeamioChatPgpKeychain.testFailDeleteContains = []
		registrar = Registrar()
		BeamioPGPIdentityCreate.registration = registrar
		generated = 0
		BeamioPGPIdentityCreate.generateKeyPair = { [unowned self] _ in
			self.generated += 1
			return .success(("-----BEGIN PGP PRIVATE KEY BLOCK-----\nk\n-----END PGP PRIVATE KEY BLOCK-----", "pub"))
		}
		BeamioPGPIdentityCreate.resetInFlightIdentities()
		BeamioPGPIdentityCreate.resetCompletedIdentities()
		BeamioFirstIdentity.chainProbe = { _ in .unregistered }
	}

	override func tearDown() {
		AddressPGPChain.transport = savedTransport
		AddressPGPChain.configuration = nil
		BeamioPGPIdentityCreate.registration = nil
		BeamioPGPIdentityCreate.generateKeyPair = savedGenerate
		BeamioChatPgpKeychain.testFailDeleteContains = []
		BeamioChatPgpKeychain.memory = nil
		BeamioFirstIdentity.chainProbe = { AddressPGPChain.chainStatus(eoa: $0) }
		super.tearDown()
	}

	// MARK: provenance

	func testNoNativeConfirmationAndANonNativeSourceAreTwoCodesAndGenerateNothing() {
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "m4"), .ready(.first))
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "m4", source: .native, nativeConfirmed: false), .failed("native_confirmation_missing"))
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "m4", source: .webView, nativeConfirmed: true), .failed("confirmation_not_native"))
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "m4", source: .webView, nativeConfirmed: false), .failed("confirmation_not_native"))
		XCTAssertEqual(generated, 0, "M-04: no key without a native confirmation")
		XCTAssertEqual(registrar.calls, 0)
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("native_confirmation_missing")), "native_confirmation_missing")
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("confirmation_not_native")), "confirmation_not_native")
		// native and confirmed: the flow goes on (a key is made and registered; the record check itself needs X-19, which macOS does not link)
		_ = BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "m4", source: .native, nativeConfirmed: true)
		XCTAssertEqual(generated, 1)
		XCTAssertEqual(registrar.calls, 1)
	}

	// MARK: event codes and states

	func testEventCodesAndStates() {
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("already_exists")), "already_exists")
		XCTAssertEqual(BeamioConetChatModule.identityCreateResultState(code: "already_exists"), "ok")
		XCTAssertEqual(BeamioConetChatModule.identityCreateResultState(code: "not_ready"), "undetermined")
		XCTAssertEqual(BeamioConetChatModule.identityCreateResultState(code: "no_identity_yet"), "no_identity_yet")
		for code in ["retry_write", "write_reverted", "cas_conflict", "idempotent", "cancelled", "pending_exists"] {
			XCTAssertNil(BeamioConetChatModule.identityCreateResultState(code: code), "\(code) carries no state")
		}
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("write_reverted")), "write_reverted", "the rollback of a failed save")
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("write_failed")), "retry_write", "not a rollback: unknown, retryable")
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.failed("something_else")), "retry_write")
		XCTAssertNotEqual(BeamioPGPIdentityCreate.eventCode(.failed("write_failed")), "write_failed", "write_failed is not used")
	}

	// MARK: erase results

	func testAnEraseThatFailsInTheFlowIsRetryWriteAndTheKeyIsKept() {
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "e1"), .ready(.first))
		// the chain changed since the prepare, and the prepared state cannot be erased
		BeamioFirstIdentity.chainProbe = { _ in .registered }
		BeamioChatPgpKeychain.testFailDeleteContains = ["ending"]
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "e1"), .retryWrite)
		XCTAssertNotNil(BeamioChatPgpKeychain.loadPending(eoa: account), "the pending state stays")
		XCTAssertEqual(registrar.calls, 0)
		// the erase works again: the same confirmation now ends in the conflict and clears it
		BeamioChatPgpKeychain.testFailDeleteContains = []
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "e1"), .casConflict)
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account))
	}

	func testACancelThatCannotEraseLeavesAFlagAndTheNextStartErasesAgain() {
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "c1"), .ready(.first))
		BeamioChatPgpKeychain.testFailDeleteContains = ["ending"]
		XCTAssertTrue(BeamioPGPIdentityCreate.cancel(eoa: account))
		XCTAssertTrue(BeamioChatPgpKeychain.cleanupPending(eoa: account), "a flag, nothing secret")
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account), "while the erase is owed the pending key is read for nothing (r2x s2)")
		XCTAssertFalse(BeamioChatPgpKeychain.retryCleanup(eoa: account), "still cannot erase: the flag stays")
		XCTAssertTrue(BeamioChatPgpKeychain.cleanupPending(eoa: account))
		BeamioChatPgpKeychain.testFailDeleteContains = []
		XCTAssertTrue(BeamioChatPgpKeychain.retryCleanup(eoa: account))
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account))
		XCTAssertFalse(BeamioChatPgpKeychain.cleanupPending(eoa: account))
	}

	func testASuccessThatCannotEraseThePendingKeyStillSucceedsAndLeavesAFlag() {
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "s1"), .ready(.first))
		BeamioChatPgpKeychain.testFailDeleteContains = ["ending"]
		let outcome = BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "s1")
		// the record could not be written back in this mock (the key is not a real PGP key): the outcome is a failure, never a rollback code
		if outcome == .ok {
			XCTAssertTrue(BeamioChatPgpKeychain.cleanupPending(eoa: account))
		} else {
			XCTAssertNotEqual(BeamioPGPIdentityCreate.eventCode(outcome), "write_failed")
		}
	}

	func testTheNextPrepareErasesWhatWasLeftBehind() {
		XCTAssertTrue(BeamioChatPgpKeychain.markCleanupPending(eoa: account))
		XCTAssertTrue(BeamioChatPgpKeychain.savePending(eoa: account, .init(privateArmor: "", publicArmor: "", idempotencyKey: "old", seen: "s", mode: "first")))
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "new"), .ready(.first), "the old prepared state was erased first")
		XCTAssertFalse(BeamioChatPgpKeychain.cleanupPending(eoa: account))
	}

	// MARK: r2x s2, s3: an owed erase blocks the temporary key and is retried at the start

	func testAFlagBlocksEveryUseOfThePendingKeyUntilTheEraseWorks() {
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "b1"), .ready(.first))
		BeamioChatPgpKeychain.testFailDeleteContains = ["ending"]
		XCTAssertTrue(BeamioPGPIdentityCreate.cancel(eoa: account))
		XCTAssertTrue(BeamioChatPgpKeychain.cleanupPending(eoa: account))
		// no confirmation uses it, no new prepare starts, and both answer retry_write
		XCTAssertEqual(BeamioPGPIdentityCreate.confirm(eoa: account, idempotencyKey: "b1"), .retryWrite)
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "b2"), .failed("retry_write"))
		XCTAssertEqual(BeamioPGPIdentityCreate.eventCode(.retryWrite), "retry_write")
		XCTAssertEqual(registrar.calls, 0)
		XCTAssertEqual(generated, 0, "no key was made behind the flag")
		// the erase works: the flag goes and the account can start again
		BeamioChatPgpKeychain.testFailDeleteContains = []
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "b3"), .ready(.first))
		XCTAssertFalse(BeamioChatPgpKeychain.cleanupPending(eoa: account))
	}

	func testAFlagThatCannotBeReadCountsAsPending() {
		XCTAssertFalse(BeamioChatPgpKeychain.cleanupPending(eoa: account))
		BeamioChatPgpKeychain.testUnreadableFields = ["userPgpCleanupPending"]
		defer { BeamioChatPgpKeychain.testUnreadableFields = [] }
		XCTAssertTrue(BeamioChatPgpKeychain.cleanupPending(eoa: account), "fail closed: a marker that cannot be read is a marker")
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account))
	}

	func testTheStartRetriesTheOwedEraseAndKeepsBlockingWhileItFails() {
		NativeAccountPointerIsolation.begin()
		defer { NativeAccountPointerIsolation.end() }
		BeamioNativeAccountPointer.set(account)
		XCTAssertEqual(BeamioPGPIdentityCreate.prepare(eoa: account, idempotencyKey: "t1"), .ready(.first))
		BeamioChatPgpKeychain.testFailDeleteContains = ["ending"]
		XCTAssertTrue(BeamioPGPIdentityCreate.cancel(eoa: account))
		XCTAssertFalse(BeamioPGPIdentityCreate.retryCleanupAtStart(), "still cannot erase: the start leaves it blocked")
		XCTAssertTrue(BeamioChatPgpKeychain.cleanupPending(eoa: account))
		BeamioChatPgpKeychain.testFailDeleteContains = []
		XCTAssertTrue(BeamioPGPIdentityCreate.retryCleanupAtStart(), "the next start erases it")
		XCTAssertFalse(BeamioChatPgpKeychain.cleanupPending(eoa: account))
		XCTAssertNil(BeamioChatPgpKeychain.loadPending(eoa: account))
	}
}
#endif
