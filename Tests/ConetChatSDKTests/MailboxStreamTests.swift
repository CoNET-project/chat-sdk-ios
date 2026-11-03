import CryptoKit
import XCTest
@testable import ConetChatSDK

/// Mailbox listen stream frames sealed by CoNET-SI (`mailboxStream.ts`) must
/// open here byte for byte. Vectors were produced by the SI implementation.
final class MailboxStreamTests: XCTestCase {
	private struct Vectors: Decodable {
		struct Frame: Decodable { let sealed: String; let json: String }
		let keyBase64: String
		let frames: [Frame]
		let tampered: String
		let plain: String
	}

	private func load() throws -> Vectors {
		let url = try XCTUnwrap(Bundle.module.url(forResource: "mailbox-stream-vectors.v1", withExtension: "json"))
		return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
	}

	func testOpensFramesSealedByTheMailbox() throws {
		let v = try load()
		let key = SymmetricKey(data: try XCTUnwrap(Data(base64Encoded: v.keyBase64)))
		for frame in v.frames {
			XCTAssertEqual(BeamioConetChatListenSession.openStreamFrame(frame.sealed, key: key), frame.json)
		}
	}

	func testTamperedFrameIsDropped() throws {
		let v = try load()
		let key = SymmetricKey(data: try XCTUnwrap(Data(base64Encoded: v.keyBase64)))
		XCTAssertNil(BeamioConetChatListenSession.openStreamFrame(v.tampered, key: key))
	}

	func testWrongKeyIsDropped() throws {
		let v = try load()
		let other = SymmetricKey(size: .bits256)
		XCTAssertNil(BeamioConetChatListenSession.openStreamFrame(v.frames[0].sealed, key: other))
	}

	func testPlainFrameIsDropped() throws {
		let v = try load()
		XCTAssertNil(BeamioConetChatListenSession.openStreamFrame(v.plain, key: SymmetricKey(size: .bits256)))
	}
}
