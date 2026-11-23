import CryptoKit
import XCTest
@testable import ConetChatSDK

/// `native-account-create-vectors.v1.json`, group A: the native result events of the creation page, their forwarding,
/// their drops and the page timing (spec,; T-249). Needs NATIVE_ACCOUNT_CREATE_VECTORS=<path>;
/// skipped without it. Group B is the PWA side and is not run here. The records are synthetic.
final class NativeAccountCreateVectorTests: XCTestCase {
	private let eoa = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private var savedStore: BeamioChatWalletKeyStoring?
	private var store = NativeAccountCreateTests.CreateKeyStore()
	private var events: [[String: Any]] = []

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		store = NativeAccountCreateTests.CreateKeyStore()
		BeamioNativeWallet.keyStore = store
		events = []
		BeamioNativeAccountCreate.onCreateRequired = { true }
		BeamioNativeAccountPointer.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
	}

	override func tearDown() {
		BeamioNativeAccountCreate.onCreateRequired = nil
		BeamioConetChatModule.closeAccountCreatePage()
		_ = drain()
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["NATIVE_ACCOUNT_CREATE_VECTORS"] else {
			throw XCTSkip("set NATIVE_ACCOUNT_CREATE_VECTORS to interface/protocol/native-account-create-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		// The pin is the file's content (as NativeOpenVectorTests): native-account-create-vectors.v1.json, 68788d87.
		let pinned = "68788d872bb324af100318849326bfdaa5e0393fa96ce8e069594c9f5511c668"
		let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
		XCTAssertEqual(digest, pinned, "native-account-create vectors are the pinned file (68788d87)")
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	/// Lets the main queue deliver the events posted asynchronously, then returns the events sent since `from`.
	private func drain(from: Int = 0) -> [[String: Any]] {
		let drained = expectation(description: "main queue drained")
		DispatchQueue.main.async { drained.fulfill() }
		wait(for: [drained], timeout: 5)
		return Array(events.dropFirst(from))
	}

	private func canonical(_ value: Any) -> String {
		let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
		return String(data: data, encoding: .utf8)!
	}

	private func resetCase() {
		// The binding lookup is not under test here: it answers no binding, so the create path is what each case checks.
		BeamioAccountBindingLookup.override = { _ in .noBinding }
		_ = BeamioConetChatModule.closeAccountCreatePage()
		_ = drain()
		events = []
		store = NativeAccountCreateTests.CreateKeyStore()
		BeamioNativeWallet.keyStore = store
		BeamioNativeAccountPointer.clear()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
	}

	/// The device state after a step (`keyAfter`): the record of the account is present or absent.
	private func setKey(_ present: Bool) {
		store.keys[eoa] = present ? Data(repeating: 0x11, count: 32) : nil
	}

	func testGroupAOfTheResultEventsMatchesTheVectors() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let groupA = cases.filter { $0["group"] as? String == "A" }
		XCTAssertEqual(groupA.count, 16, "NC-01 to NC-16")
		for c in groupA {
			try runCase(c)
		}
	}

	private func runCase(_ c: [String: Any]) throws {
		let id = try XCTUnwrap(c["id"] as? String)
		resetCase()
		let input = try XCTUnwrap(c["input"] as? [String: Any], id)
		var drops: [[String: Any]] = []
		for step in try XCTUnwrap(input["steps"] as? [[String: Any]], id) {
			switch step["op"] as? String {
			case "open":
				let reqId = try XCTUnwrap(step["reqId"] as? String, id)
				var openRequest: [String: Any] = ["type": "nativeAccountCreateOpen", "reqId": reqId]
					// The open carries the vector's account. The runner passes it through, unchanged.
					if let account = step["account"] { openRequest["account"] = account }
					let answer = dispatch(openRequest)
				XCTAssertEqual(answer.first?["ok"] as? Bool, true, "\(id): the page opens")
			case "native":
				let ev = try XCTUnwrap(step["ev"] as? [String: Any], id)
				let delivery = BeamioConetChatModule.deliverAccountCreateResult(ev)
				if !delivery.forwarded {
					var item: [String: Any] = ["reason": delivery.reason ?? ""]
					if !delivery.fields.isEmpty { item["fields"] = delivery.fields }
					drops.append(item)
				}
				if let keyAfter = step["keyAfter"] as? Bool { setKey(keyAfter) }
				_ = drain()
			case "close":
				BeamioConetChatModule.closeAccountCreatePage()
				_ = drain()
			default:
				XCTFail("\(id): unknown step")
			}
		}

		let expect = try XCTUnwrap(c["expect"] as? [String: Any], id)
		let forwardedWant = try XCTUnwrap(expect["forwarded"] as? [[String: Any]], id)
		let forwardedGot = events.filter { $0["type"] as? String == "nativeAccountCreateResult" }
		XCTAssertEqual(forwardedGot.map { canonical($0) }, forwardedWant.map { canonical($0) }, "\(id): forwarded")

		let droppedWant = try XCTUnwrap(expect["dropped"] as? [[String: Any]], id)
		XCTAssertEqual(drops.count, droppedWant.count, "\(id): number of drops")
		for (got, want) in zip(drops, droppedWant) {
			XCTAssertEqual(got["reason"] as? String, want["reason"] as? String, "\(id): drop reason")
			let wantFields = (want["fields"] as? [String]) ?? []
			let gotFields = (got["fields"] as? [String]) ?? []
			XCTAssertEqual(gotFields.sorted(), wantFields.sorted(), "\(id): dropped field names")
		}

		XCTAssertEqual(BeamioConetChatModule.accountCreatePageOpen(), expect["pageOpenAfter"] as? Bool, "\(id): page open")
		XCTAssertEqual(store.keys[eoa] != nil, expect["keyPresentAfter"] as? Bool, "\(id): key present")
	}

	/// One bridge command through the entry point, with the events it produced since the call started.
	private func dispatch(_ body: [String: Any]) -> [[String: Any]] {
		let from = events.count
		BeamioConetChatModule.handleCommand(body, emit: { [weak self] event in
			self?.events.append((event["event"] as? [String: Any]) ?? event)
		})
		return drain(from: from)
	}
}
