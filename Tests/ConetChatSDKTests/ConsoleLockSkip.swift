#if BEAMIO_TEST_HOOKS
import XCTest
#if canImport(IOKit)
import IOKit
#endif

/// Tests that write a page copy with `.completeFileProtection` cannot pass while the machine's console is locked (macOS refuses the write with Cocoa 513 or 512). This detects the
/// state by the same write the page copy store makes (a probe file in a temporary directory), and skips such a test with a stated reason. The skip is counted in the log
/// (the `skipped` line carries the message below); an unlocked machine runs every test as before. It is never a silent skip.
enum ConsoleLock {
	static let skipMessage = "console locked: completeFileProtection write refused"

	/// The registry's own answer: `IOConsoleLocked` of the I/O Registry root is true while the console (the login session's screen) is locked.
	static func consoleLockedFlag() -> Bool {
		#if canImport(IOKit)
		let root = IORegistryGetRootEntry(kIOMainPortDefault)
		defer { IOObjectRelease(root) }
		guard let value = IORegistryEntryCreateCFProperty(root, "IOConsoleLocked" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() else { return false }
		return (value as? Bool) ?? false
		#else
		// the iOS simulator has no I/O Registry console flag: there is no console lock to report
		return false
		#endif
	}

	/// True when a `.completeFileProtection` write to a fresh temporary file is refused with the Cocoa permission errors of a locked console (513, 512).
	static func writeRefused() -> Bool {
		let dir = FileManager.default.temporaryDirectory.appendingPathComponent("console-lock-probe-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
		try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
		defer { try? FileManager.default.removeItem(at: dir) }
		do {
			try Data([1]).write(to: dir.appendingPathComponent("probe.tmp"), options: [.completeFileProtection])
			return false
		} catch let error as NSError {
			return error.domain == NSCocoaErrorDomain && (error.code == 513 || error.code == 512)
		}
	}

	/// A test is skipped only when BOTH hold: the refused write (512 or 513) and the registry's IOConsoleLocked = true. A 513 on an unlocked console, or a locked console whose write
	/// still works, is not a skip: the test runs and reports.
	static func isLocked() -> Bool { writeRefused() && consoleLockedFlag() }
}

func skipIfConsoleLocked() throws {
	if ConsoleLock.isLocked() {
		NSLog("[ConsoleLock] skipping: %@", ConsoleLock.skipMessage)
		throw XCTSkip(ConsoleLock.skipMessage)
	}
}
#endif
