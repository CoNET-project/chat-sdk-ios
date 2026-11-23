import Foundation

/// The file rules shared by the inbound inbox and the call-signal ledger: one folder under Application Support,
/// excluded from backup, protected until the first unlock. A write replaces the file only after its new bytes are flushed to disk.
enum BeamioInboxFile {
	static var folder: URL? {
		#if BEAMIO_TEST_HOOKS
		// A test build never touches the product's files: its inbox, call-signal, owner and roster files live in a directory of this process under the temporary
		// directory (the same principle as the page-copy store's isolated directory). Tests that name `BeamioInboxFile.folder` follow it.
		_ = BeamioProductPathGuard.baseline
		let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("beamio-conetchat-test-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
		if !FileManager.default.fileExists(atPath: tmp.path) {
			try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
			excludeFromBackup(tmp)
		}
		return tmp
		#else
		guard let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { return nil }
		let f = dir.appendingPathComponent("ConetChat", isDirectory: true)
		if !FileManager.default.fileExists(atPath: f.path) {
			try? FileManager.default.createDirectory(at: f, withIntermediateDirectories: true)
			excludeFromBackup(f)
		}
		return f
		#endif
	}

	/// Missing is an empty store. Unreadable is not: a writer must not replace the file then.
	enum Read {
		case missing
		case data(Data)
		case unreadable
	}

	static func read(_ url: URL) -> Read {
		guard FileManager.default.fileExists(atPath: url.path) else { return .missing }
		guard let data = try? Data(contentsOf: url) else { return .unreadable }
		// Every read sets the protection class again, with no list to depend on: a file whose class could not be set at its write (and a retry list does
		// not survive a restart) is repaired at the next read. Setting the same class twice changes nothing.
		protectUntilFirstUnlock(url)
		return .data(data)
	}

	/// Replaces `url` with `data`. True only when the new bytes are flushed and in place.
	static func replace(_ url: URL, with data: Data) -> Bool {
		let tmp = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".tmp")
		do {
			try? FileManager.default.removeItem(at: tmp)
			try data.write(to: tmp, options: [.completeFileProtectionUntilFirstUserAuthentication])
			let handle = try FileHandle(forWritingTo: tmp)
			try handle.synchronize()
			try handle.close()
			if FileManager.default.fileExists(atPath: url.path) {
				_ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
			} else {
				try FileManager.default.moveItem(at: tmp, to: url)
			}
		} catch {
			try? FileManager.default.removeItem(at: tmp)
			return false
		}
		// `replaceItemAt` swaps the file in: the attributes of the replaced file are not promised to carry over, so the target is set again.
		protectUntilFirstUnlock(url)
		excludeFromBackup(url)
		return true
	}

	private static let protectionLock = NSLock()
	private static var protectionPending: Set<String> = []

	/// Sets the data-protection class of `url` (protected until the first unlock). A failure is not silent: it is logged as a category only (no path, no
	/// content) and the file is kept on a retry list, `retryPendingProtection` sets it again at the next read.
	@discardableResult
	static func protectUntilFirstUnlock(_ url: URL) -> Bool {
		var ok = true
		#if BEAMIO_TEST_HOOKS
		if testFailProtection { ok = false }
		#endif
		if ok {
			do { try FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: url.path) }
			catch { ok = false }
		}
		protectionLock.lock()
		if ok { protectionPending.remove(url.path) } else { protectionPending.insert(url.path) }
		#if BEAMIO_TEST_HOOKS
		if ok { testProtectionSetCount += 1 }
		#endif
		protectionLock.unlock()
		if !ok { NSLog("[BeamioInboxFile] data-protection class not set (category=protection_set_failed), retry pending") }
		return ok
	}

	/// Sets the protection class again for a file whose last attempt failed. True when nothing is pending afterwards.
	@discardableResult
	static func retryPendingProtection(_ url: URL) -> Bool {
		protectionLock.lock()
		let pending = protectionPending.contains(url.path)
		protectionLock.unlock()
		return pending ? protectUntilFirstUnlock(url) : true
	}

	/// Whether the last attempt to protect `url` failed and a retry is pending.
	static func protectionRetryPending(_ url: URL) -> Bool {
		protectionLock.lock(); defer { protectionLock.unlock() }
		return protectionPending.contains(url.path)
	}

	#if BEAMIO_TEST_HOOKS
	/// Test build only: the number of successful protection settings (guarded by the protection lock).
	static var testProtectionSetCount = 0
	/// Test build only: a process restart forgets the in-memory retry list.
	static func forgetProtectionStateForTests() { protectionLock.lock(); protectionPending.removeAll(); protectionLock.unlock() }
	/// Test build only: setting the protection class fails.
	static var testFailProtection = false
	#endif

	static func excludeFromBackup(_ url: URL) {
		var values = URLResourceValues()
		values.isExcludedFromBackup = true
		var u = url
		try? u.setResourceValues(values)
	}

#if BEAMIO_TEST_HOOKS
	/// Test build only: every removal fails.
	static var failRemovals = false
#endif

	/// Removes the file and its temporary copy. True when neither is left: a removal that fails is reported, never swallowed.
	@discardableResult
	static func remove(_ url: URL) -> Bool {
#if BEAMIO_TEST_HOOKS
		if failRemovals { return false }
#endif
		let tmp = url.deletingLastPathComponent().appendingPathComponent(url.lastPathComponent + ".tmp")
		let a = removeIfPresent(url)
		let b = removeIfPresent(tmp)
		return a && b
	}

	private static func removeIfPresent(_ url: URL) -> Bool {
		guard FileManager.default.fileExists(atPath: url.path) else { return true }
		do {
			try FileManager.default.removeItem(at: url)
			return true
		} catch {
			return false
		}
	}
}
