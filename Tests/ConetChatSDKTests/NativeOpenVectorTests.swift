import CryptoKit
import XCTest
@testable import ConetChatSDK

/// The page commands `nativeImportOpen`, `nativeRecoveryOpen` and `nativeAccountCreateOpen` (spec,): the 42 cases
/// of `native-open-vectors.v1.json` through the bridge entry point, with the host states and the key state (G0, G1, G2) of
/// each case.
/// The `recoveryResult` steps are the page's result, sent with `BeamioNativeRecovery.finish`. The Android-shell cases (N-09, N-26) are not run
/// here: 40 of the 42 cases execute. Reads NATIVE_OPEN_VECTORS when set, else the bundled copy; the file must be the pinned 49ceb083 (r2.5.19). No credential.
final class NativeOpenVectorTests: XCTestCase {
	private var savedStore: BeamioChatWalletKeyStoring?
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	/// The completion of the binding query held in flight by a `queryStart` step.
	private var pendingQuery: ((BeamioAccountBindingLookup.Outcome) -> Void)?

	/// An in-memory key store for the key states G1 and G2 (the gate reads whether a record exists for the pointer account).
	final class OpenKeyStore: BeamioChatWalletKeyStoring {
		var keys: [String: Data] = [:]
		var phases: [String: BeamioChatMigrationPhase] = [:]
		func write(eoa: String, key: Data) -> Bool { keys[eoa.lowercased()] = key; return true }
		func read(eoa: String) -> Data? { keys[eoa.lowercased()] }
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		func delete(eoa: String) { keys[eoa.lowercased()] = nil }
		// Since the mnemonic ownership rule (Y.163 items 31 and 32) the account check lists mnemonic items; this double holds each key's account as a valid one.
		func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? { enumerateKeyOwners()?.map { BeamioChatKeyCreation(owner: $0, created: nil) } }
		func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState { (enumerateKeyOwners() ?? []).contains { $0.lowercased() == owner.lowercased() } ? .valid : .absent }
		func migrationMarkerExists(eoa: String) -> Bool { migrationPhase(eoa: eoa) == .complete }
		func setMigrationMarker(eoa: String) -> Bool { setMigrationPhase(eoa: eoa, .complete) }
		func migrationPhase(eoa: String) -> BeamioChatMigrationPhase { phases[eoa.lowercased()] ?? .none }
		func setMigrationPhase(eoa: String, _ phase: BeamioChatMigrationPhase) -> Bool {
			phases[eoa.lowercased()] = phase == .none ? nil : phase
			return true
		}
	}

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		savedStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = OpenKeyStore()
		// The binding lookup is not under test here: it answers no binding (its own vectors cover it).
		BeamioAccountBindingLookup.override = { _ in .noBinding }
	}

	override func tearDown() {
		BeamioAccountBindingLookup.override = nil
		resetHosts()
		BeamioNativeWallet.keyStore = savedStore ?? BeamioPasscodeWalletStore.standard
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func resetHosts() {
		BeamioNativeRecovery.onRecoveryRequired = nil
		BeamioNativeAccountCreate.onCreateRequired = nil
		_ = BeamioNativeRecovery.finish(.cancelled)
	}

	/// G0: no record on the device. G1: a record, and the session has not run `init`. G2: a record, and `init` is done.
	private func applyKeyState(_ state: String?) {
		let store = BeamioNativeWallet.keyStore as? OpenKeyStore
		store?.keys = [:]
		BeamioNativeAccountPointer.clear()
		switch state {
		case "G1", "G2":
			store?.keys[account] = Data(repeating: 0x11, count: 32)
			BeamioNativeAccountPointer.set(account)
			BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: state == "G2")
		default:
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		}
	}

	private func accountHostAnswer(_ state: String?) -> (() -> Bool)? {
		switch state {
		case "open": return { true }
		case "refuse": return { false }
		default: return nil
		}
	}

	/// The binding lookup's answer for the case: none is no binding, and the lookup is not under test here beyond it.
	private func bindingOverride(_ state: String?) -> (BeamioAccountBindingLookup.Account) -> BeamioAccountBindingLookup.Outcome {
		switch state {
		case "already_bound": return { _ in .alreadyBound }
		case "lookup_unavailable": return { _ in .unavailable("rpc") }
		default: return { _ in .noBinding }
		}
	}

	/// The recovery host's answer for the case: open answers true, refuse answers false, none leaves the host unset.
	private func hostAnswer(_ state: String?) -> ((String) -> Bool)? {
		switch state {
		case "open": return { _ in true }
		case "refuse": return { _ in false }
		default: return nil
		}
	}

	private func canonical(_ value: Any) -> String {
		let data = try! JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
		return String(data: data, encoding: .utf8)!
	}

	/// Collects the events of one case. The emit closure keeps the sink, not a local, so it outlives the call.
	final class Sink {
		var events: [[String: Any]] = []
	}

	/// Sends one command and waits until the sink holds `count` events (acks and results are posted on the main queue).
	private func send(_ body: [String: Any], count: Int, sink: Sink) {
		BeamioConetChatModule.handleCommand(body, emit: { event in
			sink.events.append((event["event"] as? [String: Any]) ?? event)
		})
		let deadline = Date().addingTimeInterval(5)
		while sink.events.count < count, Date() < deadline {
			RunLoop.main.run(until: Date().addingTimeInterval(0.02))
		}
	}

	func testTheNativeOpenVectors() throws {
		// The file is the NATIVE_OPEN_VECTORS path when it is set, otherwise the bundled copy. Either way the registered digest is checked
		// (BundledVectorFile): the pin is the file's content, not its path. r2.5.19: native-open vectors, 49ceb083, 42 cases.
		let raw = try BundledVectorFile.data(resource: "native-open-vectors.v1", env: "NATIVE_OPEN_VECTORS")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(cases.count, 42, "the pinned file has 42 cases")
		// Android-shell cases (N-09, N-26) are not run by the iOS runner; they are counted, so the executed number is exact.
		var executed: [String] = []
		var androidSkipped: [String] = []
		for c in cases {
			let id = c["id"] as? String ?? "?"
			let env = (c["env"] as? [String: Any]) ?? [:]
			if (env["platform"] as? String) == "android" { androidSkipped.append(id); continue }
			executed.append(id)
			print("NATIVE_OPEN_CASE executed \(id)")
			resetHosts()
			applyKeyState(env["keyState"] as? String)
			BeamioNativeRecovery.onRecoveryRequired = hostAnswer(env["recoveryHost"] as? String)
			BeamioNativeAccountCreate.onCreateRequired = accountHostAnswer(env["accountHost"] as? String)
			BeamioAccountBindingLookup.override = bindingOverride(env["binding"] as? String)
			let expect = try XCTUnwrap(c["expect"] as? [[String: Any]], id)
			let sink = Sink()
			for step in (c["steps"] as? [[String: Any]]) ?? [] {
				switch step["op"] as? String {
				case "open":
					let req = try XCTUnwrap(step["req"] as? [String: Any], id)
					send(req, count: sink.events.count + 1, sink: sink)
				case "recoveryResult":
					let code = try XCTUnwrap(step["code"] as? String, id)
					let resultCode = try XCTUnwrap(BeamioNativeRecovery.ResultCode(rawValue: code), id)
					let before = sink.events.count
					XCTAssertTrue(BeamioNativeRecovery.finish(resultCode, eoa: step["eoa"] as? String, cooldownSec: step["cooldownSec"] as? Int), id)
					let deadline = Date().addingTimeInterval(5)
					while sink.events.count < before + 1, Date() < deadline {
						RunLoop.main.run(until: Date().addingTimeInterval(0.02))
					}
				case "queryStart":
					// A binding query starts with this open and stays in flight until `queryAnswer`.
					let reqId = try XCTUnwrap(step["reqId"] as? String, id)
					BeamioAccountBindingLookup.deferred = { [weak self] _, completion in self?.pendingQuery = completion }
					BeamioConetChatModule.handleCommand(["type": "nativeAccountCreateOpen", "reqId": reqId, "account": "alice"], emit: { event in
						sink.events.append((event["event"] as? [String: Any]) ?? event)
					})
					BeamioAccountBindingLookup.deferred = nil
				case "queryAnswer":
					// The in-flight query is answered: `none` opens the first screen (one event), a binding result sends the ack and the result.
					let completion = try XCTUnwrap(pendingQuery, id)
					pendingQuery = nil
					let outcome: BeamioAccountBindingLookup.Outcome
					switch step["binding"] as? String {
					case "already_bound": outcome = .alreadyBound
					case "lookup_unavailable": outcome = .unavailable("rpc")
					default: outcome = .noBinding
					}
					let before = sink.events.count
					let expected = outcome == .noBinding ? 1 : 2
					completion(outcome)
					let deadline = Date().addingTimeInterval(5)
					while sink.events.count < before + expected, Date() < deadline {
						RunLoop.main.run(until: Date().addingTimeInterval(0.02))
					}
				case "pageClose":
					// The user closes the page: `cancelled` is sent when no result was produced for it.
					let before = sink.events.count
					BeamioConetChatModule.closeAccountCreatePage()
					let window = Date().addingTimeInterval(0.3)
					while sink.events.count <= before, Date() < window {
						RunLoop.main.run(until: Date().addingTimeInterval(0.02))
					}
				case "accountResult":
					// The page's result, through the same intake a native result uses.
					let reqId = try XCTUnwrap(step["reqId"] as? String, id)
					let code = try XCTUnwrap(step["code"] as? String, id)
					var raw: [String: Any] = ["type": "nativeAccountCreateResult", "reqId": reqId, "code": code]
					if let eoa = step["eoa"] as? String { raw["eoa"] = eoa }
					let before = sink.events.count
					XCTAssertTrue(BeamioConetChatModule.deliverAccountCreateResult(raw).forwarded, id)
					let deadline = Date().addingTimeInterval(5)
					while sink.events.count < before + 1, Date() < deadline {
						RunLoop.main.run(until: Date().addingTimeInterval(0.02))
					}
				default:
					XCTFail("unknown step in \(id)")
				}
			}
			let want = expect.compactMap { $0["detail"] as? [String: Any] }.compactMap { ($0["event"] as? [String: Any]) }
			XCTAssertEqual(sink.events.count, want.count, "\(id): number of events")
			for (got, exp) in zip(sink.events, want) {
				XCTAssertEqual(canonical(got), canonical(exp), id)
			}
			for key in (c["forbiddenKeys"] as? [String]) ?? [] {
				for event in sink.events {
					XCTAssertNil(event[key], "\(id): result must not carry \(key)")
				}
			}
			// A page left open by this case is closed now, while this case's sink still receives its event. The drain keeps that event out of
			// the next case's sink, and no page carries over into the next case.
			// A query still in flight at the end of the case is answered `lookup_unavailable`, after the checks above.
			if let completion = pendingQuery {
				pendingQuery = nil
				completion(.unavailable("case_end"))
			}
			_ = BeamioNativeRecovery.finish(.cancelled)
			_ = BeamioConetChatModule.closeAccountCreatePage()
			let drained = Date().addingTimeInterval(0.2)
			while Date() < drained { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
		}
		// Exact accounting: 42 cases in the pinned file; the iOS runner executes 40, and the two Android-shell cases are not run here.
		XCTAssertEqual(executed.count, 40, "the iOS runner executes 40 cases: 42 less the Android-shell cases")
		XCTAssertEqual(androidSkipped, ["N-09", "N-26"], "the Android-shell cases are exactly N-09 and N-26")
		print("NATIVE_OPEN_SUMMARY pinned=49ceb083 cases=\(cases.count) executed=\(executed.count) android_not_run=\(androidSkipped.joined(separator: ","))")
	}
}
