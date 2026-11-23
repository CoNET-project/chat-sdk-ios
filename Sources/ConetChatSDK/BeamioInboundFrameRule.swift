import Foundation

/// What one inbound mailbox frame does. Pure: decided from
/// the facts alone. The module applies the outcome, and the vector file runs through this same function.
enum InboundFrameRule {
	enum Decrypt: String {
		case ok
		case blocked
		case invalid
	}

	/// The local inbox read: a missing file is an empty inbox; a read that fails is not.
	enum InboxRead: String {
		case ok
		case notFound
		case readFailed
	}

	enum Persist: String {
		case ok
		case fail
	}

	/// the decrypted content is a JSON object (`ok`) or is not (`fail`). A row that is not JSON is a dropped frame.
	/// a JSON object without `signMessage` or without `text` (`jsonMissingField`) is a signature failure: no marker, no ack.
	/// valid JSON that is not an object (`jsonNotObject`: an array, a number, a string, a boolean) has no signature to check; it is
	/// a signature failure in the same way.
	enum Parse: String {
		case ok
		case fail
		case jsonMissingField
		case jsonNotObject
	}

	/// A frame the client drops on purpose: it records only its marker, and shows nothing.
	enum Drop: String {
		case none = ""
		case expiredSignal = "expired-signal"
		case voiceControl = "voice-control"
	}

	/// The mailbox's answer to a `gossip_delivery_ack`: HTTP status (nil: no answer) and the decoded body.
	struct AckAnswer {
		var status: Int?
		var body: Any?
	}

	/// One record of the inbox as the fixture describes it: `confirmed` means the mailbox acked it.
	struct RecordFact {
		var armorHash: String
		var confirmed: Bool
		var armorPresent: Bool
	}

	struct Input {
		var decrypt: Decrypt = .ok
		/// evaluated after a successful decrypt. A row that is not JSON is never verified, so this is checked before the signature.
		var parse: Parse = .ok
		var signatureValid: Bool = true
		var inboxRead: InboxRead = .ok
		/// Evaluated only for a new frame that is readable (or for a dropped frame's marker).
		var persist: Persist = .ok
		/// A record for this armorHash exists.
		var dedupeKnown: Bool = false
		/// `callId|sessionId` for an end or timeout call signal, nil otherwise.
		var callSignalKey: String? = nil
		/// The call signal key was already handed to the call layer (/).
		var callSignalDelivered: Bool = false
		/// The page sent ackInbound for this message: this is that event, not a frame.
		var pageAckInbound: Bool = false
		var ackAnswer: AckAnswer? = nil
		var drop: Drop = .none
		/// The inbox before this frame, for the eviction; nil when the case does not test it.
		var records: [RecordFact]? = nil
		/// The record limit: 50000 in production; a test parameter in the vectors.
		var capacity: Int = 50000
	}

	struct Outcome: Equatable {
		/// Messages shown to the page: 0 or 1.
		var displayed: Int
		/// Successful inbox writes: 0 or 1.
		var inboxWrites: Int
		/// armorHash values sent to the mailbox as `gossip_delivery_ack`.
		var ackSent: [String]
		/// A dedupe record was written for this frame.
		var dedupeRecordWritten: Bool
		/// A dedupe record for this frame existed before (and is kept).
		var dedupeRecordKept: Bool
		/// The client never deletes a frame on the server; the mailbox deletes it after a valid ack.
		var frameRetainedOnServer: Bool = true
		/// `callId|sessionId` keys handed to the call layer now.
		var callSignalDelivered: [String]
		/// The OpenPGP armor stays in the local inbox until the page's ackInbound.
		var armorRetainedLocally: Bool
		/// the ack was confirmed (HTTP 200 and body ok true). Nil when no answer was given.
		var ackConfirmed: Bool? = nil
		/// the record may now be evicted (only a confirmed ack allows it).
		var recordEvictable: Bool? = nil
		/// the ack must be sent again (redelivery of the frame brings the retry, with a new timestamp,).
		var retryAck: Bool? = nil
		/// the marker of a dropped frame was written (armorHash only).
		var markerWritten: Bool? = nil
		/// the armorHashes evicted by the limit, oldest first. Nil when the case does not test the eviction.
		var evicted: [String]? = nil
		/// the number of records after this frame and the eviction. Nil when not tested.
		var recordCountAfter: Int? = nil
	}

	static func decide(armorHash: String, _ i: Input) -> Outcome {
		// the page's ackInbound clears the local armor. It sends no gossip_delivery_ack.
		if i.pageAckInbound {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: i.dedupeKnown,
				callSignalDelivered: [], armorRetainedLocally: false
			)
		}
		// (IC-01): a decrypted row that is not JSON cannot be verified. It is a dropped frame: marker first, ack after the
		// marker is committed; never shown, no armor. Checked before the signature, which such a row does not have.
		if i.parse == .fail, i.decrypt == .ok {
			return unparsedOutcome(armorHash: armorHash, i)
		}
		// : a frame that did not verify does nothing; a call signal waits for a verified frame.
		// (IC-03, IC-04): a JSON object missing `signMessage` or `text` does not verify.
		guard i.signatureValid, i.decrypt == .ok, i.parse != .jsonMissingField, i.parse != .jsonNotObject else {
			// (IC-02): no marker is written for a frame that did not verify.
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: i.dedupeKnown,
				callSignalDelivered: [], armorRetainedLocally: false, markerWritten: false
			)
		}
		// a call end or timeout is handed over right after verification, not after the store.
		let callNow: [String] = {
			guard let key = i.callSignalKey, !i.callSignalDelivered else { return [] }
			return [key]
		}()
		// an unreadable inbox is not written, shown or acked.
		guard i.inboxRead != .readFailed else {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: false,
				callSignalDelivered: callNow, armorRetainedLocally: false
			)
		}
		// a dropped frame writes its marker (armorHash only) and acks; it is not shown and keeps no armor.
		if i.drop != .none {
			if i.dedupeKnown {
				return Outcome(
					displayed: 0, inboxWrites: 0, ackSent: [armorHash], dedupeRecordWritten: false, dedupeRecordKept: true,
					callSignalDelivered: callNow, armorRetainedLocally: false, markerWritten: false
				)
			}
			guard i.persist == .ok else {
				return Outcome(
					displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: false,
					callSignalDelivered: callNow, armorRetainedLocally: false, markerWritten: false
				)
			}
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [armorHash], dedupeRecordWritten: true, dedupeRecordKept: false,
				callSignalDelivered: callNow, armorRetainedLocally: false, markerWritten: true
			)
		}
		// already stored. Not shown, not written again, acked (the copy is durable).
		if i.dedupeKnown {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [armorHash], dedupeRecordWritten: false, dedupeRecordKept: true,
				callSignalDelivered: callNow, armorRetainedLocally: true, ackConfirmed: ackConfirmed(i), recordEvictable: ackConfirmed(i),
				retryAck: retry(i)
			)
		}
		// : a new frame is stored first. A failed write shows nothing, acks nothing and records nothing.
		guard i.persist == .ok else {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: false,
				callSignalDelivered: callNow, armorRetainedLocally: false
			)
		}
		var outcome = Outcome(
			displayed: 1, inboxWrites: 1, ackSent: [armorHash], dedupeRecordWritten: true, dedupeRecordKept: false,
			callSignalDelivered: callNow, armorRetainedLocally: true, ackConfirmed: ackConfirmed(i), recordEvictable: ackConfirmed(i),
			retryAck: retry(i)
		)
		// above the limit, the oldest confirmed records go, with their armor. Unconfirmed records are never dropped.
		if let records = i.records {
			let evicted = evictionOrder(records: records, adding: armorHash, capacity: i.capacity)
			outcome.evicted = evicted
			outcome.recordCountAfter = records.count + 1 - evicted.count
		}
		return outcome
	}

	/// (IC-01): a row that is not JSON. Its marker is written first, and the ack follows only a committed marker. An unreadable
	/// inbox writes nothing and acks nothing; a failed write writes no marker and acks nothing, so the frame stays on the server.
	private static func unparsedOutcome(armorHash: String, _ i: Input) -> Outcome {
		guard i.inboxRead != .readFailed else {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: false,
				callSignalDelivered: [], armorRetainedLocally: false, markerWritten: false
			)
		}
		if i.dedupeKnown {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [armorHash], dedupeRecordWritten: false, dedupeRecordKept: true,
				callSignalDelivered: [], armorRetainedLocally: false, markerWritten: false
			)
		}
		guard i.persist == .ok else {
			return Outcome(
				displayed: 0, inboxWrites: 0, ackSent: [], dedupeRecordWritten: false, dedupeRecordKept: false,
				callSignalDelivered: [], armorRetainedLocally: false, markerWritten: false
			)
		}
		return Outcome(
			displayed: 0, inboxWrites: 0, ackSent: [armorHash], dedupeRecordWritten: true, dedupeRecordKept: false,
			callSignalDelivered: [], armorRetainedLocally: false, markerWritten: true
		)
	}

	/// The armorHashes to drop so that `records` plus the new one fit in `capacity`: the oldest confirmed records first. Pure.
	static func evictionOrder(records: [RecordFact], adding: String, capacity: Int) -> [String] {
		var excess = records.count + 1 - capacity
		guard excess > 0 else { return [] }
		var out: [String] = []
		for r in records where excess > 0 && r.confirmed {
			out.append(r.armorHash)
			excess -= 1
		}
		return out
	}

	/// confirmed only with HTTP 200 and an explicit `ok: true`, whatever `removed` says.
	static func isConfirmed(status: Int?, body: Any?) -> Bool {
		guard status == 200, let object = body as? [String: Any] else { return false }
		return (object["ok"] as? Bool) == true
	}

	static func confirmed(_ i: Input) -> Bool {
		guard let answer = i.ackAnswer else { return false }
		return isConfirmed(status: answer.status, body: answer.body)
	}

	/// The confirmation as the outcome reports it: nil when no answer is given.
	static func ackConfirmed(_ i: Input) -> Bool? {
		i.ackAnswer == nil ? nil : confirmed(i)
	}

	/// an unconfirmed ack is retried (by the redelivery). Nil when no answer is given.
	static func retry(_ i: Input) -> Bool? {
		guard i.ackAnswer != nil else { return nil }
		return !confirmed(i)
	}
}

/// the retry of an unconfirmed `gossip_delivery_ack`. The first retry 30 seconds after the
/// failure, doubling each time, at most 600 seconds. `failures` counts the unconfirmed attempts so far.
enum GossipRetrySchedule {
	static func delay(failures: Int) -> TimeInterval {
		min(30 * pow(2, Double(max(0, failures))), 600)
	}
}
