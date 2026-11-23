#if BEAMIO_TEST_HOOKS
import CryptoKit
import Foundation
import Security

/// Test build only: a snapshot of the product's files under `Application Support` taken the first time a test-build path helper is used, so that a guard test can assert
/// that nothing in them changed while the tests ran. The tests write to a per-process temporary directory (BeamioInboxFile.folder,
/// BeamioConetChatLocalStore.defaultRootDirectory, the page-copy store's isolated directory), never to the product's directories.
///
/// The check compares known file names only (the chat folder's inbox_v1.json, call_signals_v1.json, owner_v1.txt and si_roster_v1.json with their .tmp copies, every file of
/// `ConetChat/local-v1` and of `beamio-shell-record`) by modification time and size; directory times are not compared (a directory changes for reasons that are not this
/// process's). It MUST run while no other process writes the product directories: a test run of another session, or the app itself, on the same machine makes it report
/// a change that is not this process's. The baseline is taken at the first use of a path helper, not at the start of the test bundle (a SwiftPM test bundle has no principal
/// class to register a bundle-start observer from); the isolated paths mean no test reaches the product directories, so nothing is written before that first use.
enum BeamioProductPathGuard {
	struct Fact: Equatable, Comparable {
		let path: String
		let modified: TimeInterval
		let size: Int
		static func < (a: Fact, b: Fact) -> Bool { a.path < b.path }
	}

	static var applicationSupport: URL? { FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first }

	/// The product's roots under Application Support that a test could reach: the chat folder (inbox, call signals, owner, roster) with the local chat library
	/// (`local-v1`, inside it), and the page-copy store `beamio-shell-record`.
	static var productRoots: [URL] {
		guard let base = applicationSupport else { return [] }
		return [base.appendingPathComponent("ConetChat", isDirectory: true), base.appendingPathComponent("beamio-shell-record", isDirectory: true)]
	}

	/// The chat folder (kept for the tests that name it).
	static var productDirectory: URL? { productRoots.first }

	/// The product Keychain services (attributes only: service, account and modification date; no value is read, no authentication UI): every item of a service whose name starts
	/// with `com.beamio.beamio.` in the user's keychain. A test build must not add, remove or change one of them. nil facts when the query cannot be answered.
	static func productKeychainFacts() -> [Fact] {
		let query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword, kSecReturnAttributes as String: true, kSecReturnData as String: false,
			kSecMatchLimit as String: kSecMatchLimitAll, kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
		]
		var out: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &out)
		guard status == errSecSuccess, let rows = out as? [[String: Any]] else { return status == errSecItemNotFound ? [] : [Fact(path: "keychain-query-status:\(status)", modified: 0, size: 0)] }
		var facts: [Fact] = []
		for row in rows {
			guard let service = row[kSecAttrService as String] as? String, service.hasPrefix("com.beamio.beamio.") else { continue }
			let account = (row[kSecAttrAccount as String] as? String) ?? ""
			let modified = (row[kSecAttrModificationDate as String] as? Date)?.timeIntervalSince1970 ?? 0
			// the account name is compared as a short digest: a failure message names the service and says changed, never an account
			facts.append(Fact(path: "keychain:\(service)|\(digest(account))", modified: modified, size: 0))
		}
		return facts
	}

	/// The SDK's own keys in the real defaults domain (`UserDefaults.standard`, which a test build never writes: the SDK uses `BeamioDefaults.standard`, in memory in a test build).
	/// The value of a real key is compared only in memory, as a digest (the `size` of the fact); the key name is the path, so a log or a failure message says which key changed and never what it holds.
	static func productDefaultsFacts() -> [Fact] {
		BeamioDefaults.knownKeys.compactMap { key in
			guard let value = UserDefaults.standard.object(forKey: key) else { return nil }
			return Fact(path: "defaults:\(key)", modified: 0, size: digestNumber(String(describing: value)))
		}
	}

	/// A short stable digest of a string, as text.
	private static func digest(_ text: String) -> String {
		SHA256.hash(data: Data(text.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()
	}

	/// The first eight bytes of the SHA-256 as a number, for comparison only.
	private static func digestNumber(_ text: String) -> Int {
		SHA256.hash(data: Data(text.utf8)).prefix(7).reduce(0) { ($0 << 8) | Int($1) }
	}

	/// The preference files that earlier test builds left in `~/Library/Preferences` (`beamio.test-host.<pid>.plist`, one per test process): a test run must not add one.
	static func preferencesFacts() -> [Fact] {
		guard let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask).first else { return [] }
		let dir = library.appendingPathComponent("Preferences", isDirectory: true)
		let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
		return names.filter { $0.hasPrefix("beamio.test-host.") }.sorted().map { name in
			let values = try? dir.appendingPathComponent(name).resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
			return Fact(path: "preferences:\(name)", modified: values?.contentModificationDate?.timeIntervalSince1970 ?? 0, size: values?.fileSize ?? -1)
		}
	}

	/// The known names at the top of the chat folder.
	static let knownChatFiles: Set<String> = ["inbox_v1.json", "call_signals_v1.json", "owner_v1.txt", "si_roster_v1.json"]

	/// The files that count, with modification time and size: the known chat files (and their .tmp copies), every file under `local-v1`, every file under
	/// `beamio-shell-record`. An absent root contributes nothing. Directories are not compared.
	static func snapshot() -> [Fact] {
		var facts: [Fact] = []
		func add(_ url: URL) {
			let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey, .isDirectoryKey])
			if values?.isDirectory == true { return }
			facts.append(Fact(path: url.path, modified: values?.contentModificationDate?.timeIntervalSince1970 ?? 0, size: values?.fileSize ?? -1))
		}
		for root in productRoots where FileManager.default.fileExists(atPath: root.path) {
			let isChat = root.lastPathComponent == "ConetChat"
			guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil) else { continue }
			for case let url as URL in walker {
				if isChat {
					let relative = url.path.dropFirst(root.path.count + 1)
					let top = relative.split(separator: "/").first.map(String.init) ?? ""
					let name = top.hasSuffix(".tmp") ? String(top.dropLast(4)) : top
					guard top == "local-v1" || knownChatFiles.contains(name) else { continue }
				}
				add(url)
			}
		}
		facts += productKeychainFacts()
		facts += productDefaultsFacts()
		facts += preferencesFacts()
		return facts.sorted()
	}

	/// Removes this process's test directories from the temporary directory when the process exits, whatever created them and whenever: the inbox folder with the local
	/// library, and the page-copy store's isolated directories. Installed once, at the first use of a test-build path helper.
	static let installExitCleanup: Void = {
		atexit {
			let pid = ProcessInfo.processInfo.processIdentifier
			let tmp = FileManager.default.temporaryDirectory
			for name in (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? [] {
				if name == "beamio-conetchat-test-\(pid)" || name.hasPrefix("beamio-shell-record-test-\(pid)-") {
					try? FileManager.default.removeItem(at: tmp.appendingPathComponent(name))
				}
			}
		}
	}()

	/// Removes the test directories of processes that are gone (a run that was killed or ended without its exit handlers leaves them), judged by whether the pid still exists.
	static func removeStaleTestDirectories() {
		let tmp = FileManager.default.temporaryDirectory
		for name in (try? FileManager.default.contentsOfDirectory(atPath: tmp.path)) ?? [] {
			var pid: Int32?
			if name.hasPrefix("beamio-conetchat-test-") { pid = Int32(name.dropFirst("beamio-conetchat-test-".count)) }
			else if name.hasPrefix("beamio-shell-record-test-") {
				pid = Int32(name.dropFirst("beamio-shell-record-test-".count).prefix { $0.isNumber })
			}
			guard let pid, pid != ProcessInfo.processInfo.processIdentifier else { continue }
			// kill(pid, 0) fails with ESRCH when no such process exists; a process that exists (even another user's, EPERM) is left alone
			if kill(pid, 0) != 0, errno == ESRCH { try? FileManager.default.removeItem(at: tmp.appendingPathComponent(name)) }
		}
	}

	/// True once the baseline has been taken. A guard test reads it in its `setUp`: a baseline taken only by the guard test itself compares the directories with themselves.
	private static let state = NSLock()
	private static var taken = false
	static var baselineWasTaken: Bool { state.lock(); defer { state.unlock() }; return taken }

	/// The guard's verdict: nil when the baseline was taken before the guard test began and nothing changed. A baseline taken late (by the guard itself) is a failure.
	static func verdict(baselineTakenBeforeGuard: Bool, changes: [String]) -> String? {
		guard baselineTakenBeforeGuard else {
			return "the baseline was taken too late (by the guard test itself): run the whole suite, not the guard alone; the result compares the directories with themselves"
		}
		return changes.isEmpty ? nil : "a product directory changed while the tests ran: " + changes.joined(separator: ", ")
	}

	/// Taken once, at the first use.
	static let baseline: [Fact] = {
		_ = installExitCleanup; removeStaleTestDirectories()
		let facts = snapshot()
		state.lock(); taken = true; state.unlock()
		return facts
	}()

	/// What changed since the baseline: paths added, removed or modified. Empty when the product directory is as it was.
	static func changes() -> [String] {
		let before = Dictionary(baseline.map { ($0.path, $0) }, uniquingKeysWith: { first, _ in first })
		let after = Dictionary(snapshot().map { ($0.path, $0) }, uniquingKeysWith: { first, _ in first })
		var out: [String] = []
		for (path, fact) in after where before[path] != fact { out.append((before[path] == nil ? "added " : "modified ") + path) }
		for path in before.keys where after[path] == nil { out.append("removed " + path) }
		return out.sorted()
	}
}
#endif
