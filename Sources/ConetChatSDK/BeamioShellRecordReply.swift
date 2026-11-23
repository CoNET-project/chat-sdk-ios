import Foundation

/// The reply rules of the record bridge. The page adapter owns the Promise. Replies come back through the
/// injected object's `onmessage` (or the chat-module event on iOS), and they are matched by `reqId`. This is the reference of those rules, and the
/// vectors RP-01 to RP-08b run against it. The page adapter itself is in the PWA.
enum BeamioShellRecordReply {
	/// A request with no valid reply after this many milliseconds is rejected with `timeout`.
	static let timeoutMs: Double = 10_000

	/// The page-side correlator. Pending requests are keyed by `reqId`. Each request is completed at most once, by its first valid reply.
	final class Correlator {
		private var pending: [String: Double] = [:]
		/// What the correlator did, in order: `resolve`, `reject`, or `ignore` with the reason.
		private(set) var outcomes: [[String: Any]] = []

		func send(reqId: String, at time: Double) {
			pending[reqId] = time
		}

		/// Rejects the pending requests that have waited for `timeoutMs`. They are removed, so a late reply to them is ignored.
		func tick(at time: Double) {
			let expired = pending.filter { time - $0.value >= BeamioShellRecordReply.timeoutMs }
			for reqId in expired.keys.sorted() {
				pending.removeValue(forKey: reqId)
				outcomes.append(["action": "reject", "reqId": reqId, "error": "timeout"])
			}
		}

		/// Handles one message from the native side. Only an `ack` envelope with a known, pending `reqId` completes a request. Anything else is
		/// ignored, and the request stays pending.
		func reply(_ message: [String: Any], at time: Double) {
			guard message["type"] as? String == "ack" else {
				outcomes.append(["action": "ignore", "why": "not_ack"])
				return
			}
			guard let reqId = message["reqId"] as? String, pending[reqId] != nil else {
				outcomes.append(["action": "ignore", "why": "unknown_reqId"])
				return
			}
			if message["ok"] as? Bool == true {
				guard let result = message["result"] as? [String: Any] else {
					outcomes.append(["action": "ignore", "why": "malformed"])
					return
				}
				pending.removeValue(forKey: reqId)
				outcomes.append(["reqId": reqId, "action": "resolve", "result": result])
			} else {
				guard let error = message["error"] as? String else {
					outcomes.append(["action": "ignore", "why": "malformed"])
					return
				}
				pending.removeValue(forKey: reqId)
				outcomes.append(["reqId": reqId, "action": "reject", "error": error])
			}
		}
	}

	/// The write rule after a write timed out. The state of the write is unknown, so another write waits until a read has
	/// completed (`ok` or `absent`). Returns `allowed` or `blocked`.
	static func writeAfterTimeout(readCompletedSinceTimeout: Bool) -> String {
		readCompletedSinceTimeout ? "allowed" : "blocked"
	}
}
