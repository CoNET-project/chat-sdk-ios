import XCTest
@testable import ConetChatSDK

/// Y.44 第 4 项 and Y.49 第 2 项 (a): an origin or frame mismatch answers `origin_refused` once; a package or capability failure answers `not_trusted`.
final class ShellWindowTrustTests: XCTestCase {
	private func ack(_ run: (@escaping ([String: Any]) -> Void) -> Void) -> [[String: Any]] {
		var sent: [[String: Any]] = []
		run { sent.append($0) }
		return sent
	}

	func testAnOriginRefusalIsOriginRefusedOnceForWalletCredential() {
		let sent = ack { emit in BeamioWindowWallet.walletCredential(["type": "walletCredential", "reqId": "W-1"], trust: .originRefused, emit: emit) }
		XCTAssertEqual(sent.count, 1, "the envelope is sent exactly once")
		XCTAssertEqual(sent.first?["error"] as? String, "origin_refused")
	}

	func testAPackageOrCapabilityFailureIsNotTrustedForWalletCredential() {
		let sent = ack { emit in BeamioWindowWallet.walletCredential(["type": "walletCredential", "reqId": "W-2"], trust: .notTrusted, emit: emit) }
		XCTAssertEqual(sent.count, 1)
		XCTAssertEqual(sent.first?["error"] as? String, "not_trusted")
	}

	func testAnOriginRefusalIsOriginRefusedForWalletEoaAddress() {
		let sent = ack { emit in BeamioWindowWallet.walletEoaAddress(reqId: "W-4", trust: .originRefused, emit: emit) }
		XCTAssertEqual(sent.count, 1)
		XCTAssertEqual(sent.first?["error"] as? String, "origin_refused")
	}

	func testAPackageFailureIsNotTrustedForWalletEoaAddress() {
		let sent = ack { emit in BeamioWindowWallet.walletEoaAddress(reqId: "W-5", trust: .notTrusted, emit: emit) }
		XCTAssertEqual(sent.first?["error"] as? String, "not_trusted")
	}

	func testAnOriginRefusalIsOriginRefusedForShellRecordRead() {
		let sent = ack { emit in BeamioWindowWallet.shellRecordRead(["reqId": "W-6"], trust: .originRefused, emit: emit) }
		XCTAssertEqual(sent.count, 1)
		XCTAssertEqual(sent.first?["error"] as? String, "origin_refused")
	}

	/// v163 section 183: a package or capability failure of a record command is origin_refused, in the envelope; not_trusted belongs to walletCredential.
	func testAPackageFailureIsOriginRefusedForShellRecordRead() {
		let sent = ack { emit in BeamioWindowWallet.shellRecordRead(["reqId": "W-7"], trust: .notTrusted, emit: emit) }
		XCTAssertEqual(sent.count, 1)
		XCTAssertEqual(sent.first?["ok"] as? Bool, false)
		XCTAssertEqual(sent.first?["error"] as? String, "origin_refused")
	}
}
