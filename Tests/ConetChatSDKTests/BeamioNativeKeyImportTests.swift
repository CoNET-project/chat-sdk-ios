import XCTest
@testable import ConetChatSDK

/// Native key import. Synthetic key 0x11…11 only.
final class BeamioNativeKeyImportTests: XCTestCase {
	override func setUp() {
		super.setUp()
		NativeAccountPointerIsolation.begin()
	}

	/// Store with failure injection for the write and read-back paths.
	final class InjectedStore: BeamioChatWalletKeyStoring {
		func enumerateKeyOwners() -> [String]? { Array(keys.keys) }
		var keys: [String: Data] = [:]
		var failWrite = false
		var corruptReadBack = false
		var deletes = 0
		func write(eoa: String, key: Data) -> Bool {
			if failWrite { return false }
			keys[eoa.lowercased()] = key
			return true
		}
		func read(eoa: String) -> Data? {
			guard let k = keys[eoa.lowercased()] else { return nil }
			return corruptReadBack ? Data(repeating: 0xEE, count: k.count) : k
		}
		func delete(eoa: String) { deletes += 1; keys[eoa.lowercased()] = nil }
		func migrationMarkerExists(eoa: String) -> Bool { false }
		func setMigrationMarker(eoa: String) -> Bool { true }
	}

	private let keyHex = String(repeating: "11", count: 32)
	private let eoa = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

	func testImportsAKeyThatDerivesTheAccount() {
		let store = InjectedStore()
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: keyHex, expectedEoa: eoa, store: store), .imported)
		XCTAssertEqual(store.keys[eoa], Data(repeating: 0x11, count: 32))
	}

	func testAcceptsPrefixAndSurroundingWhitespace() {
		let store = InjectedStore()
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: "  0x\(keyHex)\n", expectedEoa: eoa, store: store), .imported)
	}

	func testRejectsMalformedText() {
		let store = InjectedStore()
		for bad in ["", "zz", String(repeating: "1", count: 63), String(repeating: "g", count: 64), "0x"] {
			XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: bad, expectedEoa: eoa, store: store), .invalidFormat, bad)
		}
		XCTAssertTrue(store.keys.isEmpty)
	}

	func testRefusesAKeyThatDoesNotDeriveTheAccount() {
		let store = InjectedStore()
		let other = "0x1111111111111111111111111111111111111111"
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: keyHex, expectedEoa: other, store: store), .addressMismatch)
		XCTAssertTrue(store.keys.isEmpty, "nothing is written for a mismatched key")
	}

	func testNeverOverwritesAnExistingKey() {
		let store = InjectedStore()
		store.keys[eoa] = Data(repeating: 0x22, count: 32)
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: keyHex, expectedEoa: eoa, store: store), .alreadyPresent)
		XCTAssertEqual(store.keys[eoa], Data(repeating: 0x22, count: 32))
	}

	func testWriteFailureIsReported() {
		let store = InjectedStore()
		store.failWrite = true
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: keyHex, expectedEoa: eoa, store: store), .writeFailed)
		XCTAssertTrue(store.keys.isEmpty)
	}

	func testFailedReadBackDeletesTheWrite() {
		let store = InjectedStore()
		store.corruptReadBack = true
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: keyHex, expectedEoa: eoa, store: store), .readBackFailed)
		XCTAssertNil(store.keys[eoa], "the write is removed when the read-back does not match")
		XCTAssertEqual(store.deletes, 1)
	}

	func testWhitespaceInsideTheTextIsInvalidFormat() {
		let store = InjectedStore()
		let spaced = String(keyHex.prefix(30)) + " " + String(keyHex.dropFirst(30))
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: spaced, expectedEoa: eoa, store: store), .invalidFormat)
		XCTAssertTrue(store.keys.isEmpty)
	}

	func testZeroAndTheCurveOrderAreInvalidKey() {
		let store = InjectedStore()
		let zero = String(repeating: "0", count: 64)
		let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: zero, expectedEoa: eoa, store: store), .invalidKey)
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: order, expectedEoa: eoa, store: store), .invalidKey)
		XCTAssertTrue(store.keys.isEmpty)
	}

	func testWithoutAnAccountTheKeyDerivesItsOwn() {
		let store = InjectedStore()
		XCTAssertEqual(BeamioNativeKeyImport.importPrivateKey(text: keyHex, expectedEoa: "", store: store), .imported)
		XCTAssertNotNil(store.keys[eoa])
	}

	func testTheCancelledResultHasItsCodeAndNoMessage() {
		XCTAssertEqual(BeamioNativeKeyImport.Outcome.cancelled.code, "cancelled")
		XCTAssertNil(BeamioNativeKeyImport.userMessage(for: .cancelled))
	}

	override func tearDown() {
		NativeAccountPointerIsolation.end()
		super.tearDown()
	}

}
