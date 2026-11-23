import XCTest
@testable import ConetChatSDK

/// 第 4 項 (; 第 7 項 (9)): the copy that `shellRecordRead` answers. The W-class fields
/// stay only on their exact paths, PGP fields never leave, and a PGP private header left anywhere closes the read. Synthetic data only.
final class ShellRecordReadNarrowingTests: XCTestCase {
	private let owner = "0x9858effd232b4033e47d90003d41ec34ecaeda94"
	private let foreign = "0x0000000000000000000000000000000000000abc"

	private func record(_ extra: [String: Any] = [:]) -> [String: Any] {
		var out: [String: Any] = [
			"rev": 3,
			"schemaVersion": 2,
			"preferences": ["theme": "dark"],
			"profiles": [
				["keyID": owner, "privateKeyArmor": "OWN-KEY-BYTES", "pgpKey": "PGP-PRIVATE"],
			],
			"mnemonicPhrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"recoveryWords": "recovery words",
			"pgpPassphrase": "pass",
		]
		for (key, value) in extra { out[key] = value }
		return out
	}

	/// The EOA key, the top-level mnemonic and the recovery words are carried; the PGP fields are gone; other fields are read as before.
	func testTheExactWPathsAreCarriedAndPGPFieldsAreStripped() {
		let copy = BeamioShellRecord.readCopy(record(), account: owner)
		let profile = (copy["profiles"] as? [[String: Any]])?.first
		XCTAssertEqual(profile?["privateKeyArmor"] as? String, "OWN-KEY-BYTES")
		XCTAssertNil(profile?["pgpKey"], "a profile's PGP object is never read")
		XCTAssertNotNil(copy["mnemonicPhrase"])
		XCTAssertNotNil(copy["recoveryWords"])
		XCTAssertNil(copy["pgpPassphrase"], "the top-level passphrase is never read")
		XCTAssertEqual((copy["preferences"] as? [String: Any])?["theme"] as? String, "dark", "other fields are read as before")
		XCTAssertEqual(copy["rev"] as? Int, 3)
	}

	/// A `privateKeyArmor` under a profile whose keyID is another account is not carried (第 4 項).
	func testAForeignProfileKeyIsNotCarried() {
		let rec = record(["profiles": [
			["keyID": owner, "privateKeyArmor": "OWN-KEY-BYTES"],
			["keyID": foreign, "privateKeyArmor": "FOREIGN-KEY-BYTES"],
		]])
		let profiles = BeamioShellRecord.readCopy(rec, account: owner)["profiles"] as? [[String: Any]] ?? []
		XCTAssertEqual(profiles.count, 2, "the profile itself is still read")
		XCTAssertEqual(profiles[0]["privateKeyArmor"] as? String, "OWN-KEY-BYTES")
		XCTAssertNil(profiles[1]["privateKeyArmor"], "the foreign key is not carried")
	}

	/// `mnemonicPhrase` and `recoveryWords` count only at the top level: a copy inside a profile is not carried.
	func testAMnemonicInsideAProfileIsNotCarried() {
		let rec = record(["profiles": [
			["keyID": owner, "privateKeyArmor": "OWN-KEY-BYTES", "mnemonicPhrase": "nested", "recoveryWords": "nested"],
		]])
		let profile = (BeamioShellRecord.readCopy(rec, account: owner)["profiles"] as? [[String: Any]])?.first
		XCTAssertNil(profile?["mnemonicPhrase"])
		XCTAssertNil(profile?["recoveryWords"])
		XCTAssertNotNil(BeamioShellRecord.readCopy(rec, account: owner)["mnemonicPhrase"], "the top-level phrase stays")
	}

	/// A PGP private header left on a path the stripping does not reach still closes the read: the copy holds it, so the check refuses.
	func testAPGPPrivateHeaderLeftAnywhereClosesTheRead() {
		let rec = record(["note": "-----BEGIN PGP PRIVATE KEY BLOCK-----"])
		let copy = BeamioShellRecord.readCopy(rec, account: owner)
		XCTAssertTrue(BeamioShellRecord.containsPGPHeader(copy), "the header is detected in the copy, so the read is refused")
	}

	/// A clean record has no PGP header in its copy, so it is answered.
	func testACleanRecordHasNoPGPHeaderInItsCopy() {
		XCTAssertFalse(BeamioShellRecord.containsPGPHeader(BeamioShellRecord.readCopy(record(), account: owner)))
	}

	/// The read copy never gains a field: the keys of the copy are the keys of the record, less the stripped PGP fields and the removed W paths.
	func testTheCopyAddsNoField() {
		let rec = record()
		let copy = BeamioShellRecord.readCopy(rec, account: owner)
		XCTAssertTrue(Set(copy.keys).isSubset(of: Set(rec.keys)))
	}
}
