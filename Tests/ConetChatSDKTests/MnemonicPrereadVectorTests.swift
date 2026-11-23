import XCTest
@testable import ConetChatSDK

/// The mnemonic preread vectors NP-01 to NP-13 of the v4 file (the result.code shape); NP-14 to NP-20 are the eoa and PWA-side cases, covered by
/// MnemonicSetsTests and the PWA): the seq rule of `nativeMnemonicPreread`, run through the command
/// with the native reading of each case. The file is the bundled copy, checked against its registered digest. Synthetic values only; no key material.
final class MnemonicPrereadVectorTests: XCTestCase {
	private let eoa = "0x1111111111111111111111111111111111111111"
	private let phrase = "SYNTHETIC-TEST-PHRASE-NOT-A-WALLET"

	override func setUp() {
		super.setUp()
		BeamioPwaWalletSync.restartForTests()
	}

	override func tearDown() {
		BeamioPwaWalletSync.restartForTests()
		super.tearDown()
	}

	func testTheThirteenPrereadCasesAnswerTheVectors() throws {
		let raw = try BundledVectorFile.data(resource: "mnemonic-preread-vectors.v4")
		let root = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
		let all = try XCTUnwrap(root["cases"] as? [[String: Any]])
		XCTAssertEqual(all.count, 20, "NP-01 to NP-20")
		// the executable cases are those whose steps are request objects (NP-01 to NP-13); NP-14 to NP-20 describe their steps in words
		let cases = all.filter { ($0["steps"] as? [[String: Any]]) != nil }
		XCTAssertEqual(cases.count, 13, "NP-01 to NP-13")
		for c in cases {
			let id = c["id"] as? String ?? "?"
			run(c, id: id)
		}
	}

	/// One case: the highest accepted seq, then each step (a request with its native reading) against its expectation, in order.
	private func run(_ c: [String: Any], id: String) {
		BeamioPwaWalletSync.restartForTests()
		if let highest = c["highest"] as? Int {
			BeamioPwaWalletSync.recordAccepted(Int64(highest))
		}
		let steps = (c["steps"] as? [[String: Any]]) ?? []
		let expects = (c["expect"] as? [[String: Any]]) ?? []
		XCTAssertEqual(steps.count, expects.count, "\(id): one expectation per step")
		for (step, expect) in zip(steps, expects) {
			var body: [String: Any] = ["type": "nativeMnemonicPreread", "reqId": 1]
			if step["trusted"] as? Bool == true { body["trustedOrigin"] = true }
			if let text = step["seqText"] as? String {
				// The literal is parsed as JSON would parse it, so `1.0` stays a floating-point number and 2^53 stays an integer.
				guard let number = try? JSONSerialization.jsonObject(with: Data(text.utf8), options: [.fragmentsAllowed]) as? NSNumber else {
					XCTFail("\(id): the seq literal \(text) is not a JSON number")
					return
				}
				body["seq"] = number
			}
			let reading: BeamioPwaWalletSync.Reading
			switch step["state"] as? String {
			case "valid": reading = BeamioPwaWalletSync.Reading(state: .valid, eoa: nil, phrase: phrase)
			case "absent": reading = BeamioPwaWalletSync.Reading(state: .absent, eoa: nil, phrase: nil)
			default: reading = .unknown
			}
			let answer = BeamioPwaWalletSync.answer(body, snapshotKnown: true, storageLocked: false, reading: reading)
			let text = String(describing: answer)
			if expect["ok"] as? Bool == true {
				XCTAssertEqual(answer["ok"] as? Bool, true, "\(id): ok")
				XCTAssertEqual(canonical(answer["result"]), canonical(expect["result"]), "\(id): result")
			} else {
				XCTAssertEqual(answer["ok"] as? Bool, false, "\(id): ok false")
				XCTAssertEqual(answer["error"] as? String, expect["error"] as? String, "\(id): error")
				XCTAssertNil(answer["result"], "\(id): a refused preread carries no result")
				XCTAssertFalse(text.contains(phrase), "\(id): a refused preread never carries the phrase")
			}
		}
	}

	private func canonical(_ value: Any?) -> String {
		guard let value, let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) else { return "nil" }
		return String(decoding: data, as: UTF8.self)
	}
}
