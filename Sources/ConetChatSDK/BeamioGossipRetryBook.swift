import Foundation

/// The unconfirmed `gossip_delivery_ack`s: per armorHash, the failed attempts so far and the token of the timer that
/// is due. A timer whose token is no longer the due one does nothing. Main queue only. Lost on restart: the mailbox redelivers the frame, and
/// the duplicate path acks it again.
struct BeamioGossipRetryBook {
	private(set) var failures: [String: Int] = [:]
	private(set) var timers: [String: Int] = [:]
	private var sequence = 0

	/// Makes a timer due after a failed attempt. `advance`: a timer-driven attempt counts one more step of the interval sequence. An immediate
	/// retry (: it "does not change the interval sequence") does not, so its failure leaves the next wait where the sequence has it.
	/// Returns the failures so far and the timer's token.
	mutating func recordFailure(_ armorHash: String, advance: Bool = true) -> (failures: Int, token: Int) {
		let current = failures[armorHash] ?? 0
		let n = advance ? current + 1 : max(current, 1)
		failures[armorHash] = n
		sequence += 1
		timers[armorHash] = sequence
		return (n, sequence)
	}

	/// Whether a timer with this token is still the one due for the hash.
	func isDue(_ armorHash: String, token: Int) -> Bool {
		timers[armorHash] == token && failures[armorHash] != nil
	}

	/// The timer fired: it is no longer due.
	mutating func fired(_ armorHash: String) {
		timers[armorHash] = nil
	}

	/// An immediate retry takes the place of the due timer.
	mutating func cancelTimer(_ armorHash: String) {
		timers[armorHash] = nil
	}

	/// Confirmed by the mailbox: nothing more to retry.
	mutating func confirm(_ armorHash: String) {
		failures[armorHash] = nil
		timers[armorHash] = nil
	}

	/// The identity was cleared by the user: nothing is retried any more.
	mutating func clear() {
		failures = [:]
		timers = [:]
	}

	var pendingHashes: [String] {
		failures.keys.sorted()
	}
}
