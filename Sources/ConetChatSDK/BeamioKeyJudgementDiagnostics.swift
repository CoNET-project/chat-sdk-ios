import Foundation

/// Diagnostic counts of the wallet key judgements: how often the timeout judgement and the read gate unlock a key, how many key
/// records are read, and how many judgements fail. Counts only: never an account, a key, a record or a log line of content.
///
/// The counters exist only in DEBUG, QA (`BEAMIO_QA_BUILD`) and test-hook builds. A release build has no counter and `qaSnapshot()` answers nil.
/// The shell reads them through `qaSnapshot()` to write them next to its own reads and page-copy checks (10633 cold-start observation).
public enum BeamioKeyJudgementDiagnostics {
	/// The judgement that is running on this thread. Set by the judgement entry points, so an unlock is attributed to its judgement.
	enum Path: String {
		case none
		case timeout
		case gate
	}

	enum Counter: String, CaseIterable {
		case timeoutJudgements
		case timeoutUnlocks
		case gateJudgements
		case gateUnlocks
		case otherUnlocks
		case keyRecordReads
		case judgementFailures
		case keyAccountMismatches
	}

#if DEBUG || BEAMIO_QA_BUILD || BEAMIO_TEST_HOOKS
	private static let lock = NSLock()
	private static var counts: [Counter: Int] = [:]
	private static let pathKey = "beamio.keyJudgement.path"

	/// Sets the judgement path of this thread and returns the previous one, which `leave` restores.
	static func enter(_ path: Path) -> Path {
		let dictionary = Thread.current.threadDictionary
		let previous = Path(rawValue: dictionary[pathKey] as? String ?? "") ?? .none
		dictionary[pathKey] = path.rawValue
		return previous
	}

	static func leave(_ previous: Path) {
		Thread.current.threadDictionary[pathKey] = previous.rawValue
	}

	static func note(_ counter: Counter) {
		lock.lock()
		counts[counter, default: 0] += 1
		lock.unlock()
	}

	/// An unlock is attributed to the judgement that runs on this thread (none: a signature or another read).
	static func noteUnlock() {
		let raw = Thread.current.threadDictionary[pathKey] as? String ?? Path.none.rawValue
		switch Path(rawValue: raw) ?? .none {
		case .timeout: note(.timeoutUnlocks)
		case .gate: note(.gateUnlocks)
		case .none: note(.otherUnlocks)
		}
	}

	static func reset() {
		lock.lock()
		counts = [:]
		lock.unlock()
	}

	/// QA only: the counts by name. Returns nil in a release build.
	public static func qaSnapshot() -> [String: Int]? {
		lock.lock(); defer { lock.unlock() }
		var out: [String: Int] = [:]
		for counter in Counter.allCases { out[counter.rawValue] = counts[counter] ?? 0 }
		return out
	}
#else
	@inline(__always) static func enter(_ path: Path) -> Path { .none }
	@inline(__always) static func leave(_ previous: Path) {}
	@inline(__always) static func note(_ counter: Counter) {}
	@inline(__always) static func noteUnlock() {}
	static func reset() {}

	/// QA only: the counts by name. Returns nil in a release build.
	public static func qaSnapshot() -> [String: Int]? { nil }
#endif
}
