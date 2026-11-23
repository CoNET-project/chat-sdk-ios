import Foundation

/// The account whose inbox this device holds ((1)). One small file in the inbox folder, excluded from backup and protected until the
/// first unlock, like the inbox itself. It holds a public address only.
enum BeamioInboxOwner {
	enum Owner: Equatable {
		/// No marker: the inbox has no recorded owner yet.
		case absent
		case account(String)
		/// A marker that cannot be read is never assumed to name the account starting now.
		case unknown
	}

	private static var fileURL: URL? {
		BeamioInboxFile.folder?.appendingPathComponent("owner_v1.txt")
	}

	static func read() -> Owner {
		guard let url = fileURL else { return .unknown }
		switch BeamioInboxFile.read(url) {
		case .missing:
			return .absent
		case .unreadable:
			return .unknown
		case .data(let data):
			guard let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !text.isEmpty
			else { return .unknown }
			return .account(text)
		}
	}

	@discardableResult
	static func write(_ account: String) -> Bool {
		guard let url = fileURL else { return false }
		return BeamioInboxFile.replace(url, with: Data(account.lowercased().utf8))
	}

	@discardableResult
	static func remove() -> Bool {
		guard let url = fileURL else { return true }
		return BeamioInboxFile.remove(url)
	}
}
