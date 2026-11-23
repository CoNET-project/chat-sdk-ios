import XCTest
@testable import ConetChatSDK

/// The username query key of the recovery path B (`accountNameKey`, the PWA creation normalisation): every `@` removed, trimmed, NFKC, and the
/// zero-width characters removed. Case is kept (the username is case-sensitive).
final class RecoveryAccountNameKeyTests: XCTestCase {
	func testAtSignFullWidthAndZeroWidthGiveTheCreatedName() {
		let created = BeamioNativeRecovery.accountNameKey("Alice")
		XCTAssertEqual(BeamioNativeRecovery.accountNameKey("@Alice"), created, "a leading @ is removed")
		XCTAssertEqual(BeamioNativeRecovery.accountNameKey("Ａlice"), created, "a full-width letter is NFKC-normalised")
		XCTAssertEqual(BeamioNativeRecovery.accountNameKey("Ali\u{200B}ce"), created, "U+200B is removed")
		XCTAssertEqual(BeamioNativeRecovery.accountNameKey("Ali\u{200C}ce\u{200D}"), created, "U+200C and U+200D are removed")
		XCTAssertEqual(BeamioNativeRecovery.accountNameKey("\u{FEFF}@Ａlice"), created, "a BOM, an @ and a full-width letter combine")
		XCTAssertEqual(BeamioNativeRecovery.accountNameKey("  @Alice  "), created, "whitespace at both ends and an @ combine")
	}

	func testCaseIsSignificant() {
		XCTAssertNotEqual(BeamioNativeRecovery.accountNameKey("Alice"), BeamioNativeRecovery.accountNameKey("alice"),
		                  "the username is case-sensitive: Alice and alice are different keys")
	}
}
