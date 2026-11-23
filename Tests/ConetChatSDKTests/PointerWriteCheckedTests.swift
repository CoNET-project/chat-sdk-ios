import XCTest
@testable import ConetChatSDK

/// MS-W2 (write-fault-shape-independent.v1): a pointer write that does not read back as written never switches the account: the previous pointer is put back exactly
/// as it was (value or no value), and the sessions of the old account are not ended. Synthetic addresses only.
final class PointerWriteCheckedTests: XCTestCase {
	/// Defaults whose read-back of the pointer key is wrong: another string (`mismatch`) or a non-string (`unreadable`) after a write of the target.
	private final class FaultyDefaults: BeamioDefaultsStoring {
		enum Fault { case otherString, nonString }
		private let inner = BeamioMemoryDefaults()
		var fault: Fault?
		private var armed = false
		func arm() { armed = true }
		func object(forKey key: String) -> Any? {
			let real = inner.object(forKey: key)
			guard armed, let fault, let text = real as? String, text == "0x2222222222222222222222222222222222222222" else { return real }
			switch fault { case .otherString: return "0x9999999999999999999999999999999999999999"; case .nonString: return NSNumber(value: 7) }
		}
		func string(forKey key: String) -> String? { object(forKey: key) as? String }
		func dictionary(forKey key: String) -> [String: Any]? { inner.dictionary(forKey: key) }
		func integer(forKey key: String) -> Int { inner.integer(forKey: key) }
		func double(forKey key: String) -> Double { inner.double(forKey: key) }
		func bool(forKey key: String) -> Bool { inner.bool(forKey: key) }
		func set(_ value: Any?, forKey key: String) { inner.set(value, forKey: key) }
		func removeObject(forKey key: String) { inner.removeObject(forKey: key) }
		func realValue(_ key: String) -> Any? { inner.object(forKey: key) }
	}

	private let a = "0x1111111111111111111111111111111111111111"
	private let b = "0x2222222222222222222222222222222222222222"
	private var saved: BeamioDefaultsStoring!
	private var faulty: FaultyDefaults!

	override func setUp() {
		super.setUp()
		saved = BeamioNativeAccountPointer.defaults
		faulty = FaultyDefaults()
		BeamioNativeAccountPointer.defaults = faulty
	}

	override func tearDown() {
		BeamioNativeAccountPointer.defaults = saved
		super.tearDown()
	}

	func testAMismatchPutsThePreviousPointerBackAndKeepsTheSession() {
		BeamioNativeAccountPointer.set(a)
		BeamioPasscodeSession.shared.install(eoa: a, bundle: [1, 2, 3])
		defer { BeamioPasscodeSession.shared.lockAll(reason: .logout) }
		let genBefore = BeamioPasscodeSession.shared.generation(eoa: a)
		faulty.fault = .otherString; faulty.arm()
		XCTAssertEqual(BeamioNativeAccountPointer.writeChecked(b), .mismatch)
		XCTAssertEqual(faulty.realValue("beamio.native.account.v1") as? String, a, "the previous pointer is back, byte for byte")
		XCTAssertEqual(BeamioNativeAccountPointer.get(), a)
		XCTAssertEqual(BeamioPasscodeSession.shared.generation(eoa: a), genBefore, "the old account's session is not ended by a failed write")
		XCTAssertNotNil(BeamioPasscodeSession.shared.bundle(eoa: a))
	}

	func testAnUnreadableReadBackPutsThePreviousPointerBack() {
		BeamioNativeAccountPointer.set(a)
		faulty.fault = .nonString; faulty.arm()
		XCTAssertEqual(BeamioNativeAccountPointer.writeChecked(b), .unreadable)
		XCTAssertEqual(faulty.realValue("beamio.native.account.v1") as? String, a)
	}

	func testAFailedFirstWriteLeavesNoPointer() {
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty)
		faulty.fault = .otherString; faulty.arm()
		XCTAssertEqual(BeamioNativeAccountPointer.writeChecked(b), .mismatch)
		XCTAssertNil(faulty.realValue("beamio.native.account.v1"), "there was no pointer, and there is none")
		XCTAssertEqual(BeamioNativeAccountPointer.read(), .empty)
	}

	func testASuccessfulWriteStillSwitchesAndEndsTheOldSession() {
		BeamioNativeAccountPointer.set(a)
		BeamioPasscodeSession.shared.install(eoa: a, bundle: [1, 2, 3])
		defer { BeamioPasscodeSession.shared.lockAll(reason: .logout) }
		XCTAssertEqual(BeamioNativeAccountPointer.writeChecked(b), .written)
		XCTAssertEqual(BeamioNativeAccountPointer.get(), b)
		XCTAssertNil(BeamioPasscodeSession.shared.bundle(eoa: a), "the account switch ended the old account's session")
	}
}
