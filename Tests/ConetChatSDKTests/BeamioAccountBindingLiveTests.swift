import Foundation
import XCTest
@testable import ConetChatSDK

/// The pre-create binding lookup against the live current registry. Only read-only `eth_call`s, through the
/// real https transport. Skipped unless the run sets `TEST_RUNNER_BINDING_LIVE=1`.
///
/// The registered account is read from a private fixture file, named by `TEST_RUNNER_BINDING_LIVE_FIXTURE`, which holds `ACCOUNT_EOA=` and
/// `ACCOUNT_TAG=` lines. No address is written in this file, and no assertion prints one. The local sources of an account on the device are
/// not part of what is live here: they are a fixture (no records), so the registry answer is what each test judges.
final class BeamioAccountBindingLiveTests: XCTestCase {
	private var savedLocal: (String) -> (present: Bool, unreadable: Bool) = BeamioAccountBindingLookup.defaultLocalState
	private var savedDeviceK: () -> Bool = BeamioAccountBindingLookup.deviceK

	override func setUpWithError() throws {
		try super.setUpWithError()
		guard ProcessInfo.processInfo.environment["BINDING_LIVE"] == "1" else {
			throw XCTSkip("set TEST_RUNNER_BINDING_LIVE=1 to run the live registry reads")
		}
		NativeAccountPointerIsolation.begin()
		BeamioNativeAccountPointer.clear()
		savedLocal = BeamioAccountBindingLookup.localState
		savedDeviceK = BeamioAccountBindingLookup.deviceK
		BeamioAccountBindingLookup.localState = { _ in (present: false, unreadable: false) }
		BeamioAccountBindingLookup.deviceK = { false }
		BeamioAccountBindingLookup.transport = BeamioAccountBindingLookup.defaultTransport
	}

	override func tearDown() {
		BeamioAccountBindingLookup.localState = savedLocal
		BeamioAccountBindingLookup.deviceK = savedDeviceK
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

	/// A random EOA, as 20 random bytes. It holds no account: the registry must answer AccountNotFound (exact data).
	private func randomEoa() -> String {
		var bytes = [UInt8](repeating: 0, count: 20)
		XCTAssertEqual(SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes), errSecSuccess)
		return AddressPGPChain.hex(bytes)
	}

	/// The private fixture of the registered QA account: its EOA and its BeamioTag, read from the file named by the environment.
	private func fixture() throws -> (eoa: String, tag: String) {
		guard let path = ProcessInfo.processInfo.environment["BINDING_LIVE_FIXTURE"] else {
			throw XCTSkip("set TEST_RUNNER_BINDING_LIVE_FIXTURE to the private fixture file")
		}
		let text = try String(contentsOfFile: path, encoding: .utf8)
		var eoa: String?
		var tag: String?
		for line in text.split(separator: "\n") {
			let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
			guard parts.count == 2 else { continue }
			if parts[0] == "ACCOUNT_EOA" { eoa = parts[1].trimmingCharacters(in: .whitespaces) }
			if parts[0] == "ACCOUNT_TAG" { tag = parts[1].trimmingCharacters(in: .whitespaces) }
		}
		guard let eoa, let tag, case .eoa(let checkedEoa)? = BeamioAccountBindingLookup.parse(eoa),
		      case .tag(let checkedTag)? = BeamioAccountBindingLookup.parse(tag)
		else { throw XCTSkip("the fixture file does not hold a valid ACCOUNT_EOA and ACCOUNT_TAG") }
		return (checkedEoa, checkedTag)
	}

	/// Live: an EOA with no record reverts with AccountNotFound (exact data), so there is no binding.
	func testLiveEoaWithNoRecordIsAccountNotFoundAndNoBinding() {
		let eoa = randomEoa()
		XCTAssertEqual(BeamioAccountBindingLookup.readAccount(eoa, remaining: BeamioAccountBindingLookup.totalBudget), .notFound,
		               "the registry answers AccountNotFound() for an unregistered EOA")
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .noBinding)
	}

	/// Live: a BeamioTag with no record resolves to the zero address, which is a decodable no-record answer.
	func testLiveTagWithNoRecordIsTheZeroOwner() {
		let tag = "binding-live-" + randomEoa().dropFirst(2).prefix(12)
		XCTAssertEqual(BeamioAccountBindingLookup.readOwner(tag, remaining: BeamioAccountBindingLookup.totalBudget), .zero)
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.tag(tag)), .noBinding)
	}

	/// Live: the registered QA account is a valid non-empty record (exists, with an account name). The name is not printed.
	func testLiveRegisteredEoaIsAnExistingRecord() throws {
		let (eoa, _) = try fixture()
		switch BeamioAccountBindingLookup.readAccount(eoa, remaining: BeamioAccountBindingLookup.totalBudget) {
		case .exists(let name):
			XCTAssertFalse(name.isEmpty, "the registered account has a name")
		default:
			XCTFail("the registered account is not an existing record")
		}
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.eoa(eoa)), .alreadyBound)
	}

	/// Live: the BeamioTag of the registered QA account resolves to its EOA. Only the match is asserted, neither value is printed.
	func testLiveRegisteredTagResolvesToTheFixtureEoa() throws {
		let (eoa, tag) = try fixture()
		switch BeamioAccountBindingLookup.readOwner(tag, remaining: BeamioAccountBindingLookup.totalBudget) {
		case .owner(let resolved):
			XCTAssertTrue(resolved == eoa.lowercased(), "the tag resolves to the registered account")
		default:
			XCTFail("the registered tag is not an owned name")
		}
		XCTAssertEqual(BeamioAccountBindingLookup.lookup(.tag(tag)), .alreadyBound)
	}
}
