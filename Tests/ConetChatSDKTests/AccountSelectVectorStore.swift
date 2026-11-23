import Foundation
@testable import ConetChatSDK

/// The synthetic key store of the account-select vectors (account-select-vectors.v2.json, 25.52Y.163 r8). It lists the records the vector
/// names: mnemonic items carry the vector's `valid` flag as their judgement; private-key and legacy rows are listed but are not accounts.
/// The top-level read flags of the state (corrupt, readError, nonInteractiveDenied, timeout, seOtherFailure) make one extra unreadable account,
/// and a failed listing (enumOk false, snapshotNil) makes the listing nil. No key bytes exist here.
final class AccountSelectVectorStore: BeamioChatWalletKeyStoring {
	struct Row: Equatable {
		let eoa: String
		let created: Int?
		let valid: Bool
		let kind: String
		let legacy: Bool
		/// false: the item is listed but its read fails (MA-04): unreadable, not valid nor invalid.
		var readable: Bool = true
	}

	/// An owner that no vector row names: the one unreadable account a read flag adds.
	static let unreadableOwner = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	var rows: [Row] = []
	var enumOk = true
	/// G0-B GB-04c: only the mnemonic listing fails (the key owners still list).
	var mnemonicEnumFails = false
	var unreadableExtra = false
	var deleteCalls = 0
	var writeCalls = 0

	func write(eoa: String, key: Data) -> Bool {
		writeCalls += 1
		return true
	}

	func read(eoa: String) -> Data? { nil }

	func delete(eoa: String) { deleteCalls += 1 }

	func migrationMarkerExists(eoa: String) -> Bool { false }

	func setMigrationMarker(eoa: String) -> Bool { true }

	func keyRecordState(eoa: String) -> BeamioChatWalletKeyRecordState {
		rows.contains { $0.eoa == eoa.lowercased() } ? .present : .absent
	}

	func hasAnyKeyRecord() -> Bool { !rows.isEmpty }

	func enumerateKeyEntries() -> [BeamioChatKeyEntryCheck]? {
		guard enumOk else { return nil }
		return rows.filter { $0.kind == "mnemonic" && !$0.legacy }.map { $0.valid ? .valid(eoa: $0.eoa) : .corrupt }
	}

	func enumerateKeyOwners() -> [String]? { enumOk ? rows.map { $0.eoa } : nil }

	func enumerateKeyCreations() -> [BeamioChatKeyCreation]? {
		guard enumOk else { return nil }
		return rows.map { BeamioChatKeyCreation(owner: $0.eoa, created: $0.created.map { Date(timeIntervalSince1970: TimeInterval($0)) }) }
	}

	func enumerateMnemonicCreations() -> [BeamioChatKeyCreation]? {
		guard enumOk, !mnemonicEnumFails else { return nil }
		var out = rows.filter { $0.kind == "mnemonic" && !$0.legacy }.map { row in
			BeamioChatKeyCreation(owner: row.eoa, created: row.created.map { Date(timeIntervalSince1970: TimeInterval($0)) })
		}
		if unreadableExtra { out.append(BeamioChatKeyCreation(owner: Self.unreadableOwner, created: nil)) }
		return out
	}

	func mnemonicAccountState(owner: String) -> BeamioMnemonicAccountState {
		let owner = owner.lowercased()
		guard enumOk else { return .unreadable }
		if owner == Self.unreadableOwner { return unreadableExtra ? .unreadable : .absent }
		guard let row = rows.first(where: { $0.kind == "mnemonic" && !$0.legacy && $0.eoa == owner }) else { return .absent }
		guard row.readable else { return .unreadable }
		return row.valid ? .valid : .invalid
	}
}
