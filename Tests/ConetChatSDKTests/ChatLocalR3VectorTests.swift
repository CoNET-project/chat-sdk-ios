import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Shared vectors for: the media manifest parser (spec 21, media-manifest-vectors.v1.json) and the M3 import
/// digest (spec 11.1 M3, import-digest-vectors.v1.json). Reads the files from PROTOCOL_VECTORS_DIR; skips without it.
final class ChatLocalR3VectorTests: XCTestCase {
	private func vectorsDir() throws -> URL {
		guard let p = ProcessInfo.processInfo.environment["PROTOCOL_VECTORS_DIR"], !p.isEmpty else {
			throw XCTSkip("set PROTOCOL_VECTORS_DIR to interface/protocol")
		}
		return URL(fileURLWithPath: p, isDirectory: true)
	}

	private func load(_ name: String) throws -> [String: Any] {
		let url = try vectorsDir().appendingPathComponent(name)
		return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any] ?? [:]
	}

	private func bytes(_ hex: String) -> Data {
		var out = Data()
		var i = hex.startIndex
		while i < hex.endIndex {
			let n = hex.index(i, offsetBy: 2)
			out.append(UInt8(hex[i..<n], radix: 16) ?? 0)
			i = n
		}
		return out
	}

	/// Compares the manifest fields named in the vector (21.3). Fields not named are not checked.
	private func checkManifest(_ want: [String: Any], _ got: BeamioChatManifest?, _ name: String) {
		guard let got else {
			XCTFail("\(name): manifest missing")
			return
		}
		for (key, value) in want {
			switch key {
			case "kind": XCTAssertEqual(got.kind.rawValue, value as? String, "\(name): manifest.kind")
			case "mime": XCTAssertEqual(got.mime, value as? String, "\(name): manifest.mime")
			case "sizeBytes": XCTAssertEqual(got.sizeBytes, (value as? NSNumber)?.int64Value, "\(name): manifest.sizeBytes")
			case "name": XCTAssertEqual(got.name, value as? String, "\(name): manifest.name")
			case "blobId": XCTAssertEqual(got.blobId, value as? String, "\(name): manifest.blobId")
			case "mediaKind": XCTAssertEqual(got.mediaKind, value as? String, "\(name): manifest.mediaKind")
			case "isArchive": XCTAssertEqual(got.isArchive, value as? Bool, "\(name): manifest.isArchive")
			case "width": XCTAssertEqual(got.width, (value as? NSNumber)?.intValue, "\(name): manifest.width")
			case "height": XCTAssertEqual(got.height, (value as? NSNumber)?.intValue, "\(name): manifest.height")
			default: XCTFail("\(name): unexpected manifest key \(key)")
			}
		}
	}

	func testMediaManifestVectors() throws {
		let v = try load("media-manifest-vectors.v1.json")
		let cases = v["cases"] as? [[String: Any]] ?? []
		XCTAssertEqual(cases.count, 18)
		for c in cases {
			let name = c["name"] as? String ?? ""
			let expect = c["expect"] as? [String: Any] ?? [:]
			let got = BeamioChatMediaBody.classify(bytes(c["bodyHex"] as? String ?? ""))
			XCTAssertEqual(got.kind.rawValue, expect["kind"] as? String, "\(name): kind")
			if let t = expect["text"] as? String { XCTAssertEqual(got.text, t, "\(name): text") }
			if let st = expect["state"] as? String { XCTAssertEqual(got.media?.state, st, "\(name): state") }
			if let reason = expect["reason"] as? String { XCTAssertEqual(got.reason, reason, "\(name): reason") }
			if expect["parseError"] as? Bool == true { XCTAssertTrue(got.parseError, "\(name): parse error") }
			if expect["dimensionsAbsent"] as? Bool == true {
				XCTAssertNil(got.media?.widthPx, "\(name): no width")
				XCTAssertNil(got.media?.heightPx, "\(name): no height")
			}
			if let m = expect["manifest"] as? [String: Any] { checkManifest(m, got.manifest, name) }
			if expect["estimateAspect"] as? String == "16:9" {
				// 16:9 without dimensions: 280 wide, 157.5 high, plus the 24 pt caption at font scale 1 (8.3).
				let vp = BeamioChatViewport(widthPt: 400, heightPt: 1000, orientation: .portrait)
				let est = BeamioChatLocalLayoutModel.estimate(kind: got.kind, body: nil, media: got.media, viewport: vp)
				XCTAssertEqual(est.hPt, 181.5, accuracy: 0.01, "\(name): 16:9 estimate")
			}
			// Store form: text kinds are stored as plain bodies; every other kind carries its media.
			let parsed = BeamioChatMediaBody.parse(String(decoding: bytes(c["bodyHex"] as? String ?? ""), as: UTF8.self))
			// Invalid UTF-8 never reaches the store (bodies are Strings), so the store form is checked only for valid bodies.
			if got.parseError { continue }
			if got.kind == .text {
				XCTAssertNil(parsed, "\(name): store form for text")
			} else {
				XCTAssertEqual(parsed?.kind, got.kind, "\(name): store kind")
			}
		}
	}

	func testDisplayTextForChatMessage() {
		// `text` field of a ChatMessage is the body shown; the stored bytes are unchanged (R8).
		let raw = #"{"sendId":"s-1","from":"them","text":"你好\n第二行","createdAt":1767225601234}"#
		XCTAssertEqual(BeamioChatMediaBody.displayText(raw), "你好\n第二行")
		XCTAssertNil(BeamioChatMediaBody.parse(raw), "ChatMessage text is stored as a text body")
		XCTAssertEqual(BeamioChatMediaBody.displayText(#"{"foo":1}"#), #"{"foo":1}"#, "R5: whole body")
		XCTAssertEqual(BeamioChatMediaBody.displayText("{hello"), "{hello", "R3: whole body")
	}

	func testImportDigestVectors() throws {
		let v = try load("import-digest-vectors.v1.json")
		let inputs = v["inputs"] as? [String: Any] ?? [:]
		let expected = v["expected"] as? [String: Any] ?? [:]
		let kIdx = SymmetricKey(data: bytes(inputs["K_idx"] as? String ?? ""))
		var rows: [BeamioChatImportDigest.Row] = []
		var rowHex: [String: String] = [:]
		for r in inputs["rows"] as? [[String: Any]] ?? [] {
			let conv = (r["conv"] as? String ?? "").lowercased()
			let sendKey = r["sendKey"] as? String ?? ""
			let convBlind = BeamioChatLocalCrypto.blind(idxKey: kIdx, conv)
			let sid = BeamioChatLocalCrypto.stableId(idxKey: kIdx, sendKey: sendKey)
			let row = BeamioChatImportDigest.Row(convBlind: convBlind, stableId: sid, sendKey: sendKey,
			                                     sortTs: Int64(r["sortTs"] as? String ?? "") ?? 0,
			                                     dir: r["dir"] as? String ?? "", body: Data((r["bodyUtf8"] as? String ?? "").utf8))
			rows.append(row)
		}
		// Per-row digest and stable_id, in the order of the vector file.
		for (i, want) in (expected["rows"] as? [[String: Any]] ?? []).enumerated() {
			XCTAssertEqual(rows[i].stableId, want["stableId"] as? String, "row \(i): stable_id")
			rowHex[String(i)] = BeamioChatLocalCrypto.hex(BeamioChatImportDigest.rowHMAC(kIdx: kIdx, row: rows[i]))
			XCTAssertEqual(rowHex[String(i)], want["rowHmacHex"] as? String, "row \(i): row HMAC")
		}
		let result = BeamioChatImportDigest.compute(kIdx: kIdx, rows: rows)
		XCTAssertEqual(result.rows, rows.count)
		for want in expected["conversations"] as? [[String: Any]] ?? [] {
			let blind = want["convBlind"] as? String ?? ""
			XCTAssertEqual(result.conversations[blind], want["digestRawHex"] as? String, "conversation \(blind): digest")
		}
		XCTAssertEqual(result.global, expected["globalDigestRawHex"] as? String, "global digest")
	}
}
