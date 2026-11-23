import CryptoKit
import Foundation
import XCTest
@testable import ConetChatSDK

/// W4 fragment keys. The vectors of `derivation-vectors.v1.json`:
/// D-04 and D-05 (one key each, through `BeamioFragmentKeys.key`, the production derivation), D-11 (a batch of 64, in input order), D-12
/// (65 pairs, refused as a whole with `batch_too_large`) and D-13 (no pairs, `bad_batch`). Needs DERIVATION_VECTORS; skipped without it.
///
/// The read point is also exercised: a fragment sealed under a vector key must open through `BeamioConetChatLocalStore.fetchVerifiedBody`
/// (BeamioConetChatLocalStore+Sync.swift), which calls the same derivation.
final class FragmentKeyBatchTests: XCTestCase {
	private func vectorRoot() throws -> [String: Any] {
		guard let path = ProcessInfo.processInfo.environment["DERIVATION_VECTORS"] else {
			throw XCTSkip("set DERIVATION_VECTORS to interface/protocol/derivation-vectors.v1.json")
		}
		let data = try Data(contentsOf: URL(fileURLWithPath: path))
		return try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
	}

	private func hexString(_ bytes: [UInt8]) -> String {
		bytes.map { String(format: "%02x", $0) }.joined()
	}

	private func hexString(_ data: Data) -> String {
		hexString([UInt8](data))
	}

	private func expectOf(_ cases: [[String: Any]], _ id: String) throws -> [String: Any] {
		let found = try XCTUnwrap(cases.first { $0["id"] as? String == id }, "case \(id) is missing")
		return try XCTUnwrap(found["expect"] as? [String: Any], "case \(id) has no expect")
	}

	/// R_proto from the vector inputs (D-01): the same derivation as DerivationVectorTests.
	private func rProto(_ root: [String: Any]) throws -> Data {
		let inputs = try XCTUnwrap(root["inputs"] as? [String: Any])
		let privateKey = try XCTUnwrap(AddressPGPChain.bytes(fromHex: try XCTUnwrap(inputs["P"] as? String)))
		let eoa = try XCTUnwrap(inputs["eoa"] as? String)
		let chainId = try XCTUnwrap(inputs["chainId"] as? Int)
		let domain = "beamio.chat.history.v1|\(chainId)|" + eoa
		let signature = try XCTUnwrap(BeamioNativeEthSigner.signEip191(privateKey: privateKey, message: domain))
		return Data(BeamioNativeEthSigner.keccak256(Array(signature.utf8)))
	}

	private func pairs(_ expect: [String: Any]) throws -> [(seq: Int, prevCid: String)] {
		try XCTUnwrap(expect["pairs"] as? [[String: Any]]).map { pair in
			(seq: try XCTUnwrap(pair["seq"] as? Int), prevCid: try XCTUnwrap(pair["prevCid"] as? String))
		}
	}

	private struct Chain {
		let root: [String: Any]
		let cases: [[String: Any]]
		let master: Data
		let genesisCid: String
	}

	private func chain() throws -> Chain {
		let root = try vectorRoot()
		let cases = try XCTUnwrap(root["cases"] as? [[String: Any]])
		let master = try rProto(root)
		let genesisCid = "0x" + hexString([UInt8](BeamioConetChatHistoryStore.hkdf(master: master, info: "frag-genesis", length: 32)))
		XCTAssertEqual(genesisCid, try expectOf(cases, "D-03")["genesisCid"] as? String)
		return Chain(root: root, cases: cases, master: master, genesisCid: genesisCid)
	}

	private func context(_ master: Data) -> BeamioConetChatLocalStore.SyncContext {
		BeamioConetChatLocalStore.SyncContext(
			master: master, dek: SymmetricKey(size: .bits256), idKey: SymmetricKey(size: .bits256), idxKey: SymmetricKey(size: .bits256)
		)
	}

	private func record(seq: Int, cid: String, prevCid: String) -> BeamioConetChatLocalStore.RawIndexRecord {
		BeamioConetChatLocalStore.RawIndexRecord(
			seq: seq, cid: cid, prevCid: prevCid, ts: 0, peer: "", dir: "", sendId: "", revision: 0, deleted: false
		)
	}

	/// D-04 and D-05: the production derivation gives the vector keys.
	func testD04AndD05MatchTheProductionDerivation() throws {
		let c = try chain()
		let d04 = try expectOf(c.cases, "D-04")
		XCTAssertEqual(d04["prevCid"] as? String, c.genesisCid, "fragment 0 is keyed on the genesis CID (25.43.5)")
		XCTAssertEqual(hexString(BeamioFragmentKeys.key(master: c.master, seq: 0, prevCid: c.genesisCid)), d04["fragKey"] as? String)

		let d05 = try expectOf(c.cases, "D-05")
		let prev1 = try XCTUnwrap(d05["prevCid"] as? String)
		XCTAssertEqual(hexString(BeamioFragmentKeys.key(master: c.master, seq: 1, prevCid: prev1)), d05["fragKey"] as? String)
	}

	/// D-11 (T-373): 64 pairs derive, in input order, each to its vector key.
	func testD11BatchOf64DerivesInInputOrder() throws {
		let c = try chain()
		let expect = try expectOf(c.cases, "D-11")
		let batch = try pairs(expect)
		XCTAssertEqual(batch.count, 64)
		XCTAssertEqual(expect["batchSize"] as? Int, 64)
		let keys = try BeamioFragmentKeys.batch(master: c.master, pairs: batch).get()
		XCTAssertEqual(keys.map { hexString($0) }, try XCTUnwrap(expect["keys"] as? [String]))
		XCTAssertEqual(Set(keys.map { hexString($0) }).count, 64, "the 64 keys are distinct")
		// The first two are D-04 and D-05.
		XCTAssertEqual(keys[0], BeamioFragmentKeys.key(master: c.master, seq: 0, prevCid: c.genesisCid))
	}

	/// D-12 (T-374): 65 pairs are refused as a whole with `batch_too_large`. Nothing is truncated or derived.
	func testD12BatchOf65IsRefusedAsAWhole() throws {
		let c = try chain()
		let expect = try expectOf(c.cases, "D-12")
		XCTAssertEqual(expect["maxBatch"] as? Int, BeamioFragmentKeys.maxBatch)
		var batch = try pairs(try expectOf(c.cases, "D-11"))
		batch.append((seq: 64, prevCid: "bafySYN00000000000000000000000000000000000000000000000000000064"))
		XCTAssertEqual(batch.count, expect["batchSize"] as? Int)
		let result = BeamioFragmentKeys.batch(master: c.master, pairs: batch)
		XCTAssertEqual(result.failureValue, BeamioFragmentKeys.BatchError(rawValue: try XCTUnwrap(expect["error"] as? String)))
		XCTAssertEqual(result.failureValue, .batchTooLarge)
		XCTAssertNil(try? result.get(), "no key is returned for a refused batch")
	}

	/// D-13 (T-375): no pairs is `bad_batch`, and no key is derived.
	func testD13EmptyBatchIsBadBatch() throws {
		let c = try chain()
		let expect = try expectOf(c.cases, "D-13")
		XCTAssertEqual(expect["batchSize"] as? Int, 0)
		let result = BeamioFragmentKeys.batch(master: c.master, pairs: [])
		XCTAssertEqual(result.failureValue, BeamioFragmentKeys.BatchError(rawValue: try XCTUnwrap(expect["error"] as? String)))
		XCTAssertEqual(result.failureValue, .badBatch)
	}

	/// The read point: fragments sealed under the vector keys open through `fetchVerifiedBody`, which calls the same derivation.
	func testFragmentsOpenThroughTheProductionReadPoint() throws {
		let c = try chain()
		let ctx = context(c.master)
		let key0 = BeamioFragmentKeys.key(master: c.master, seq: 0, prevCid: c.genesisCid)
		let prev1 = try XCTUnwrap(try expectOf(c.cases, "D-05")["prevCid"] as? String)
		let key1 = BeamioFragmentKeys.key(master: c.master, seq: 1, prevCid: prev1)

		let body0 = "synthetic fragment zero"
		let cipher0 = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: key0, plaintext: Data(body0.utf8))
		let rec0 = record(seq: 0, cid: Keccak256.hexUtf8(cipher0), prevCid: c.genesisCid)
		XCTAssertEqual(BeamioConetChatLocalStore.fetchVerifiedBody(rec0, ctx: ctx, fetchCipher: { _ in cipher0 }), body0)

		let body1 = "synthetic fragment one"
		let cipher1 = try BeamioConetChatHistoryStore.aesGcmEncrypt(key: key1, plaintext: Data(body1.utf8))
		let rec1 = record(seq: 1, cid: Keccak256.hexUtf8(cipher1), prevCid: prev1)
		XCTAssertEqual(BeamioConetChatLocalStore.fetchVerifiedBody(rec1, ctx: ctx, fetchCipher: { _ in cipher1 }), body1)

		// A key fits only its own fragment: another prevCid or another seq does not open it.
		XCTAssertNil(BeamioConetChatLocalStore.fetchVerifiedBody(record(seq: 1, cid: rec1.cid, prevCid: c.genesisCid), ctx: ctx, fetchCipher: { _ in cipher1 }))
		XCTAssertNil(BeamioConetChatLocalStore.fetchVerifiedBody(record(seq: 0, cid: rec1.cid, prevCid: prev1), ctx: ctx, fetchCipher: { _ in cipher1 }))
	}
}

private extension Result {
	var failureValue: Failure? {
		if case let .failure(error) = self { return error }
		return nil
	}
}
