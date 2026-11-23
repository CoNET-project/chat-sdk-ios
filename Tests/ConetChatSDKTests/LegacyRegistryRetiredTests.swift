import Foundation
import XCTest
@testable import ConetChatSDK

///: the pre-migration registry endpoint is retired. The legacy read makes no request and never answers "no record".
final class LegacyRegistryRetiredTests: XCTestCase {
	private var savedTransport: (URL, Data, TimeInterval) -> Result<Data, Error> = { _, _, _ in .failure(LegacyRegistryRetired()) }

	override func setUp() {
		super.setUp()
		savedTransport = BeamioRecoveryRegistry.transport
		BeamioRecoveryRegistry.transport = { url, _, _ in
			XCTFail("no request may be made to a retired legacy endpoint: \(url.host ?? "")")
			return .failure(LegacyRegistryRetired())
		}
	}

	override func tearDown() {
		BeamioRecoveryRegistry.transport = savedTransport
		super.tearDown()
	}

	/// The legacy lookup fails closed: a failure, not `.success("")` (which would read as no record).
	func testLegacyLookupFailsClosedWithoutARequest() {
		let result = BeamioRecoveryRegistry().legacyRecordByAccountName("syn_any_name")
		switch result {
		case .success(let value):
			XCTFail("legacy lookup must not answer a value, got \(value.count) characters")
		case .failure(let error):
			XCTAssertEqual(error as? LegacyRegistryRetired, LegacyRegistryRetired())
		}
	}

	/// The current registry is read from its one CoNET RPC, and no other endpoint is listed.
	func testTheRegistryIsReadFromTheOneCurrentRpc() {
		XCTAssertEqual(BeamioRecoveryRegistry.endpoint.host, "rpc1.conet.network")
	}
}
