import XCTest
@testable import ConetChatSDK

/// Native signer vs ethers.js. Vectors (Resources/eth-sign-vectors.json) were made
/// with ethers v6 `Wallet.signMessage`, `Wallet.address` and `keccak256`, including
/// the voice v3 pay / listen texts and non-ASCII messages.
final class BeamioNativeEthSignerTests: XCTestCase {
	private struct Vectors: Decodable {
		struct K: Decodable { let `in`: String; let out: String }
		struct S: Decodable { let key: String; let address: String; let message: String; let sig: String }
		let keccak: [K]
		let sign: [S]
	}

	private func load() throws -> Vectors {
		let url = try XCTUnwrap(Bundle.module.url(forResource: "eth-sign-vectors", withExtension: "json"))
		return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
	}

	func testKeccakMatchesEthers() throws {
		for k in try load().keccak {
			let got = "0x" + BeamioNativeEthSigner.keccak256(Array(k.in.utf8)).map { String(format: "%02x", $0) }.joined()
			XCTAssertEqual(got, k.out)
		}
	}

	func testSignaturesAndAddressesMatchEthersByteForByte() throws {
		let v = try load()
		XCTAssertEqual(v.sign.count, 15)
		for (i, s) in v.sign.enumerated() {
			XCTAssertEqual(BeamioNativeEthSigner.address(privateKeyHex: s.key), s.address, "address \(i)")
			XCTAssertEqual(BeamioNativeEthSigner.signEip191(privateKeyHex: s.key, message: s.message), s.sig, "sig \(i)")
		}
	}
}
