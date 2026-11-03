import Foundation

/// When the mailbox listen runs and how fast it retries (same rule as Android).
///
/// Rule: the app does not run in the background. The listen stays up only
/// while the app is in the foreground, or a call rings, dials or is up. In the
/// background it is paused, so nothing retries there.
enum BeamioListenPolicy {
	/// First retry after a failed listen (seconds).
	static let retryBase: TimeInterval = 2
	/// Longest wait between retries (network down for a while).
	static let retryMax: TimeInterval = 30
	/// Wait before reopening a listen that worked and then dropped.
	static let relisten: TimeInterval = 0.5

	/// Wait before the next try after `failures` failed tries in a row (1 = the
	/// first failure): 2 s, 4 s, 8 s, 16 s, then 30 s. `jitter` in [0, 1)
	/// spreads it by ±20 %; never above `retryMax`.
	static func retryDelay(failures: Int, jitter: Double) -> TimeInterval {
		let n = min(max(failures, 1), 16)
		let base = min(retryMax, retryBase * pow(2, Double(n - 1)))
		let j = min(max(jitter, 0), 1)
		return min(max(base * (0.8 + 0.4 * j), retryBase / 2), retryMax)
	}

	/// Whether an owed or requested pause applies now. An app in the
	/// foreground keeps its listen; a shell that never reports keeps the old
	/// rule (the page decides).
	static func pauseApplies(lifecycleKnown: Bool, inForeground: Bool, callInProgress: Bool) -> Bool {
		if callInProgress { return false }
		return !(lifecycleKnown && inForeground)
	}

	/// Whether the page's `resume` may open the listen (not in the background, unless a call needs it).
	static func pageResumeApplies(lifecycleKnown: Bool, inForeground: Bool, callInProgress: Bool) -> Bool {
		!lifecycleKnown || inForeground || callInProgress
	}
}
