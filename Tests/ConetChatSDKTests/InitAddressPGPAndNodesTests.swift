import Foundation
import XCTest
@testable import ConetChatSDK

/// (option B, main line). `init` sets the AddressPGP source from a usable configuration: the contract (`addressPgpContractAddress`) and the chain
/// (`chainId`) from the payload, and the one RPC only from the shell's native build configuration (`AddressPGPChain.shellEndpoint`), never from the
/// payload. An empty node list is "not provided": it never replaces a list the session already has, and the SI list of
/// the keychain fills a session that has none. Synthetic values, no network.
final class InitAddressPGPAndNodesTests: XCTestCase {
	private let contract = "0x684b0ac760cEE9c9b85de36d69746420648Cf9e2"
	private let shell = "https://rpc.example.invalid/"
	private var savedConfiguration: AddressPGPChain.Configuration?
	private var savedShellEndpoint: URL?

	override func setUp() {
		super.setUp()
		savedConfiguration = AddressPGPChain.configuration
		savedShellEndpoint = AddressPGPChain.shellEndpoint
		AddressPGPChain.configuration = nil
		AddressPGPChain.shellEndpoint = URL(string: shell)
	}

	override func tearDown() {
		AddressPGPChain.configuration = savedConfiguration
		AddressPGPChain.shellEndpoint = savedShellEndpoint
		super.tearDown()
	}

	/// The init fields of the AddressPGP source. A nil argument leaves the field out. `rpc` is a PWA field that must be ignored.
	private func payload(contract: String?, chainId: Any?, rpc: String? = nil) -> [String: Any] {
		var out: [String: Any] = [:]
		if let contract { out["addressPgpContractAddress"] = contract }
		if let chainId { out["chainId"] = chainId }
		if let rpc { out["conetRpcUrl"] = rpc }
		return out
	}

	private func node(_ ip: String) -> BeamioConetChatModule.Node {
		BeamioConetChatModule.Node(ip: ip, domain: "", region: "", armoredPublicKey: "")
	}

	// MARK: - AddressPGP configuration from init

	func testTheShellEndpointIsTheConfiguredRPC() {
		XCTAssertTrue(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: contract, chainId: 224422)))
		XCTAssertEqual(
			AddressPGPChain.configuration,
			AddressPGPChain.Configuration(contract: contract, chainId: 224422, rpcURL: URL(string: shell)!)
		)
	}

	/// The RPC never comes from the PWA: a payload RPC is ignored, and the shell's endpoint is what is set.
	func testAPayloadRPCIsIgnored() {
		XCTAssertTrue(BeamioConetChatModule.configureAddressPGPChain(
			from: payload(contract: contract, chainId: 224422, rpc: "https://attacker.invalid/")
		))
		XCTAssertEqual(AddressPGPChain.configuration?.rpcURL, URL(string: shell))
	}

	func testTheChainIdMayArriveAsANumber() {
		XCTAssertTrue(BeamioConetChatModule.configureAddressPGPChain(
			from: payload(contract: contract, chainId: NSNumber(value: 224422))
		))
		XCTAssertEqual(AddressPGPChain.configuration?.chainId, 224422)
	}

	/// No shell endpoint: nothing is configured, whatever the payload says (fail closed).
	func testWithoutTheShellEndpointNothingIsConfigured() {
		AddressPGPChain.shellEndpoint = nil
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: contract, chainId: 224422, rpc: shell)))
		XCTAssertNil(AddressPGPChain.configuration)
	}

	/// An endpoint that is not https is not usable: the source stays as it was.
	func testAnHttpShellEndpointChangesNothing() {
		let before = AddressPGPChain.Configuration(contract: contract, chainId: 224422, rpcURL: URL(string: shell)!)
		AddressPGPChain.configuration = before
		AddressPGPChain.shellEndpoint = URL(string: "http://rpc.example.invalid/")
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: contract, chainId: 224422)))
		XCTAssertEqual(AddressPGPChain.configuration, before)
	}

	/// N-3 (confirmed intentional, 2026-11-16): a later init that cannot configure keeps the source an earlier init set from the shell's endpoint.
	func testAMissingFieldKeepsTheEarlierConfiguration() {
		XCTAssertTrue(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: contract, chainId: 224422)))
		let earlier = AddressPGPChain.configuration
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: nil, chainId: 224422)))
		XCTAssertEqual(AddressPGPChain.configuration, earlier, "a later init without the contract keeps the earlier source")
	}

	/// A malformed contract (no `0x`, or the wrong length) is not usable: nothing is set.
	func testAnUnusableContractChangesNothing() {
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(
			from: payload(contract: String(contract.dropFirst(2)), chainId: 224422)
		))
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: "0x123", chainId: 224422)))
		XCTAssertNil(AddressPGPChain.configuration)
	}

	/// A payload without the contract or the chain sets nothing.
	func testAMissingFieldChangesNothing() {
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: nil, chainId: 224422)))
		XCTAssertFalse(BeamioConetChatModule.configureAddressPGPChain(from: payload(contract: contract, chainId: nil)))
		XCTAssertNil(AddressPGPChain.configuration)
	}

	// MARK: - Node list: an empty list never replaces the session's list

	/// The session already has its list: an empty supplied list keeps it, and the keychain is not consulted for it.
	func testAnEmptyNodeListDoesNotReplaceTheSessionsList() {
		var keychainRead = false
		let result = BeamioConetChatModule.resolvedNodes(supplied: [], current: [node("10.0.0.1")]) {
			keychainRead = true
			return [self.node("10.0.0.2")]
		}
		XCTAssertEqual(result.map(\.ip), ["10.0.0.1"])
		XCTAssertFalse(keychainRead, "a session with a list does not read the keychain's SI list")
	}

	/// An empty session takes the SI list of the keychain.
	func testAnEmptySessionTakesTheKeychainList() {
		let result = BeamioConetChatModule.resolvedNodes(supplied: [], current: []) { [self.node("10.0.0.2")] }
		XCTAssertEqual(result.map(\.ip), ["10.0.0.2"])
	}

	/// A non-empty supplied list replaces the session's list.
	func testSuppliedNodesReplaceTheSessionsList() {
		let result = BeamioConetChatModule.resolvedNodes(supplied: [node("10.0.0.3")], current: [node("10.0.0.1")]) { [] }
		XCTAssertEqual(result.map(\.ip), ["10.0.0.3"])
	}

	/// Nothing supplied, nothing held, nothing in the keychain: the list is empty.
	func testWithNothingAtAllTheListIsEmpty() {
		XCTAssertTrue(BeamioConetChatModule.resolvedNodes(supplied: [], current: []) { [] }.isEmpty)
	}
}
