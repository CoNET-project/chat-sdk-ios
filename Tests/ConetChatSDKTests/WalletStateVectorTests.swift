import CryptoKit
import XCTest
@testable import ConetChatSDK

/// walletstate-vectors. The page side (IndexedDB, the route) belongs to the PWA.
/// iOS checks the native side: for each native input the `walletState` the native layer reports (,, GY).
/// The vector file is read from WALLET_STATE_VECTORS; the test is skipped without it. A native `entries` item is the vector's model of one key record:
/// `parseable` says the key can be read, and `derived` is the address the key derives. Its address must be its account.
/// `not_reported` (old shells, AD-19, AD-21, AD-22) and the page-side cases are not native results of iOS, which always reports `walletState`.
final class WalletStateVectorTests: XCTestCase {
	static let expectedSHA256 = "4eb78f3f6d314bd3e69928cbae22a48df1643eccbabd402c1716332283d2e2e4"  // registration (34 cases, 38 steps; AD-01..34; AD-30 names a2; AD-34 overlay)

	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["WALLET_STATE_VECTORS"] else {
			throw XCTSkip("set WALLET_STATE_VECTORS to interface/protocol/walletstate-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		XCTAssertTrue(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() == Self.expectedSHA256,
					"vector file sha256 differs from the published value (the digest is not printed)")
		return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
	}

	/// The store's key records for one native input, as the native enumeration reports them. nil: the enumeration cannot be completed.
	private func entries(_ native: [String: Any]) -> [BeamioChatKeyEntryCheck]? {
		if (native["enumerate"] as? String) == "notready" { return nil }
		let locked = native["locked"] as? Bool == true
		var out: [BeamioChatKeyEntryCheck] = []
		for item in native["entries"] as? [[String: Any]] ?? [] {
			let account = (item["account"] as? String) ?? (item["eoa"] as? String) ?? ""
			guard item["parseable"] as? Bool == true, let derived = item["derived"] as? String, derived == account else {
				out.append(.corrupt)
				continue
			}
			out.append(locked ? .locked(eoa: account) : .valid(eoa: account))
		}
		return out
	}

	/// The `walletState` of one native input, through the resolver the passcodeStatus answer uses. `pointer` is an account name (AD-26 to AD-28).
	/// `copyOverlay` is a page copy that holds an EOA private key (item 3, AD-34); its migration state does not change the answer.
	private func walletState(_ native: [String: Any]) -> String {
		let pointer = (native["pointer"] as? String) ?? ""
		let copyOverlay = native["copyOverlay"] as? [String: Any]
		let overlay = copyOverlay?["eoa"] as? String
		// AD-35: the copy enumeration itself failed (copyOverlay.enumerate "failed").
		let failed = copyOverlay?["enumerate"] as? String == "failed"
		return BeamioNativeWalletStateResolver.resolve(pointer: pointer, entries: entries(native),
			markerWithoutRecord: native["markerWithoutRecord"] as? Bool == true, pageCopyKey: overlay,
			pageCopyEnumerationFailed: failed).state.rawValue
	}

	func testTheNativeWalletStateOfEveryVectorCaseMatches() throws {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		var checked = 0
		for c in cases {
			let id = c["id"] as? String ?? "?"
			if let native = c["native"] as? [String: Any], (native["kind"] as? String) == "walletState" {
				let expect = c["expect"] as? [String: Any] ?? [:]
				if let want = expect["walletState"] as? String {
					XCTAssertEqual(walletState(native), want, "\(id): walletState")
					checked += 1
				}
			}
			// AD-10 is a sequence of native inputs: each step has its own expectation.
			for step in c["steps"] as? [[String: Any]] ?? [] {
				guard let native = step["native"] as? [String: Any], (native["kind"] as? String) == "walletState" else { continue }
				let want = (step["expect"] as? [String: Any])?["walletState"] as? String ?? ""
				XCTAssertEqual(walletState(native), want, "\(id) step: walletState")
				checked += 1
			}
		}
		XCTAssertEqual(checked, 30, "the 29 walletState inputs of the file (AD-05 to AD-34, AD-10, AD-33 and AD-34 steps) are all checked")
	}

	/// AD-16: the keys of the passcodeStatus answer are exactly the vector's set (the wiring is in NativeWalletStateTests).
	func testThePasscodeStatusKeySetIsTheVectorSet() throws {
		let root = try vectorRoot()
		let ad16 = try XCTUnwrap((root["cases"] as? [[String: Any]])?.first { ($0["id"] as? String) == "AD-16" })
		let keys = ((ad16["expect"] as? [String: Any])?["keys"] as? [String]) ?? []
		XCTAssertEqual(Set(keys), ["set", "locked", "hasKey", "walletState"])
	}
}
