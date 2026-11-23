import XCTest
@testable import ConetChatSDK

/// The nativeRecoveryResult answers of the open recovery page (25.52Y.152): the ok answer is the flat {type, reqId, code, eoa?}; no
/// answer carries privateKeyArmor, mnemonicPhrase or recoveryWords, or any PGP field, whatever its code.
final class NativeRecoveryResultShapeTests: XCTestCase {
	private let account = "0x9858effd232b4033e47d90003d41ec34ecaeda94"

	override func setUp() {
		super.setUp()
		AdmittedCreationDevice.install()
		NativeAccountPointerIsolation.begin()
		BeamioNativeWallet.keyStore = NativeAccountCreateTests.CreateKeyStore()
		BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
		BeamioNativeRecovery.onRecoveryRequired = { _ in true }
	}

	override func tearDown() {
		BeamioNativeRecovery.onRecoveryRequired = nil
		_ = BeamioNativeRecovery.finish(.cancelled)
		BeamioConetChatModule.closeRecoveryPage()
		flush()
		NativeAccountPointerIsolation.end()
		AdmittedCreationDevice.remove()
		super.tearDown()
	}

	private func flush() {
		let until = Date().addingTimeInterval(0.1)
		while Date() < until { RunLoop.main.run(until: Date().addingTimeInterval(0.02)) }
	}

	private static let walletFields = ["privateKeyArmor", "mnemonicPhrase", "recoveryWords", "pgpKeyId", "privateKeyHex"]

	func testNoRecoveryAnswerCarriesAWalletFieldAndTheOkAnswerIsFlat() {
		let cases: [(BeamioNativeRecovery.ResultCode, String?, Int?)] = [
			(.ok, account, nil), (.cancelled, nil, nil), (.backoff, nil, 60), (.badPin, nil, nil), (.alreadyExists, nil, nil),
			(.notFound, nil, nil), (.writeFailed, nil, nil),
		]
		for (index, (code, eoa, cooldown)) in cases.enumerated() {
			var sent: [[String: Any]] = []
			let reqId = 300 + index
			BeamioConetChatModule.handleCommand(["type": "nativeRecoveryOpen", "reqId": reqId], emit: { payload in
				sent.append((payload["event"] as? [String: Any]) ?? payload)
			})
			flush()
			XCTAssertTrue(BeamioNativeRecovery.finish(code, eoa: eoa, cooldownSec: cooldown), "\(code.rawValue): the page takes its result")
			flush()
			let result = sent.last { $0["type"] as? String == "nativeRecoveryResult" }
			XCTAssertEqual(result?["code"] as? String, code.rawValue)
			XCTAssertEqual(result?["reqId"] as? Int, reqId)
			for field in Self.walletFields {
				XCTAssertNil(result?[field], "\(code.rawValue): the answer carries no \(field)")
			}
			if code == .ok {
				XCTAssertEqual(Set((result ?? [:]).keys), ["type", "reqId", "code", "eoa"], "the ok answer is flat: code and eoa only")
				XCTAssertEqual(result?["eoa"] as? String, account)
			}
			if code == .backoff {
				XCTAssertEqual(result?["cooldownSec"] as? Int, 60, "backoff keeps its cooldown")
			}
			BeamioConetChatModule.closeRecoveryPage()
			flush()
		}
	}
}
