import Foundation
@testable import ConetChatSDK

/// The mnemonic, intent and commit items of a test double (25.52Y.163 第 2 至 4 項, 第 31、34(1) 項). It keeps the items the way the product
/// store names them ("kind:owner"), a creation time per item, and the failure switches of the (e) cases. The judgement of a mnemonic is
/// NOT made here: `mnemonicAccountState` is the product's `itemsAccountState` (BIP-39 check and address derivation), so a double that conforms
/// to `BeamioChatMnemonicKeyStoring` answers the judgement exactly as the product does.
///
/// A double that holds key records only has no mnemonic items: it answers `enumerateMnemonicCreations` with an empty list and
/// `mnemonicAccountState` with `absent`. A key record alone is not an account (第 31、32 項).
struct TestMnemonicItems {
	var items: [String: Data] = [:]
	var created: [String: Date] = [:]
	var failWrite: Set<BeamioChatWalletItemKind> = []
	var failDelete: Set<BeamioChatWalletItemKind> = []
	/// Present items whose value cannot be read (itemState stays present, readItem returns nil).
	var failRead: Set<BeamioChatWalletItemKind> = []
	/// Owners whose mnemonic item cannot be read, while the other owners' items read normally (M-5: a per-entry read failure).
	var failReadOwners: Set<String> = []

	static func name(_ kind: BeamioChatWalletItemKind, _ eoa: String) -> String { kind.rawValue + ":" + eoa.lowercased() }

	func itemState(_ kind: BeamioChatWalletItemKind, eoa: String) -> BeamioChatItemState {
		items[Self.name(kind, eoa)] == nil ? .absent : .present
	}

	mutating func writeItem(_ kind: BeamioChatWalletItemKind, eoa: String, value: Data) -> Bool {
		if failWrite.contains(kind) { return false }
		let name = Self.name(kind, eoa)
		if items[name] == nil { created[name] = Date() }
		items[name] = value
		return true
	}

	func readItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Data? {
		if failRead.contains(kind) { return nil }
		if kind == .mnemonic, failReadOwners.contains(eoa.lowercased()) { return nil }
		return items[Self.name(kind, eoa)]
	}

	mutating func deleteItem(_ kind: BeamioChatWalletItemKind, eoa: String) -> Bool {
		if failDelete.contains(kind) { return false }
		let name = Self.name(kind, eoa)
		items[name] = nil
		created[name] = nil
		return true
	}

	func intentOwners() -> [String]? {
		let prefix = BeamioChatWalletItemKind.intent.rawValue + ":"
		return items.keys.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }.sorted()
	}

	/// The creation time of each mnemonic item (attributes only: nothing is read from the value).
	/// Test seam (-59E, 2026-11-17): the enumeration of the mnemonic items fails, so the state is unknown, not absent.
	var enumerationFails = false

	func mnemonicRecordCreations() -> [BeamioChatKeyCreation]? {
		if enumerationFails { return nil }
		let prefix = BeamioChatWalletItemKind.mnemonic.rawValue + ":"
		return items.keys.filter { $0.hasPrefix(prefix) }.sorted().map { name in
			BeamioChatKeyCreation(owner: String(name.dropFirst(prefix.count)), created: created[name])
		}
	}
}
