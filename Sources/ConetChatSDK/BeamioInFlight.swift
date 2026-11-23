import Foundation

/// an operation in flight has one answer. The first result that arrives is delivered. If none arrives within `timeout`, `timeoutValue`
/// is delivered instead, so a send whose callback never comes does not stay open: it goes back to pending (an ack retries) or fails (a page
/// command answers `send_timeout`). A result that arrives later is dropped. The timer runs on the main queue.
final class BeamioInFlightOnce<T> {
	private let lock = NSLock()
	private var finished = false
	private let done: (T) -> Void

	init(timeout: TimeInterval, timeoutValue: T, done: @escaping (T) -> Void) {
		self.done = done
		// A timeout of infinity never answers by itself (the caller's own timeout answers,).
		guard timeout.isFinite else { return }
		DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { [self] in
			finish(timeoutValue)
		}
	}

	/// Same as `finish`, for a call written as a function.
	func callAsFunction(_ value: T) {
		finish(value)
	}

	/// Delivers `value` unless an answer was delivered already. True when this call delivered it.
	@discardableResult
	func finish(_ value: T) -> Bool {
		lock.lock()
		let first = !finished
		finished = true
		lock.unlock()
		if first { done(value) }
		return first
	}
}

/// The answer to a page command whose work is in flight. It is sent once: by `send`, or by the timeout, which answers as a failure
/// (`send_timeout`). The page keeps such a send pending and may send it again.
final class BeamioInFlightReply {
	private struct Answer {
		let ok: Bool
		let result: Any?
		let error: String?
	}

	private let once: BeamioInFlightOnce<Answer>

	/// `isCurrent` is checked when the answer is about to go out, the timeout answer included: an answer whose generation has expired is
	/// silent. The answer goes out once.
	init(
		timeout: TimeInterval,
		isCurrent: @escaping () -> Bool = { true },
		deliver: @escaping (_ ok: Bool, _ result: Any?, _ error: String?) -> Void
	) {
		once = BeamioInFlightOnce(
			timeout: timeout, timeoutValue: Answer(ok: false, result: nil, error: "send_timeout")
		) { answer in
			guard isCurrent() else { return }
			deliver(answer.ok, answer.result, answer.error)
		}
	}

	func send(ok: Bool, result: Any? = nil, error: String? = nil) {
		once.finish(Answer(ok: ok, result: result, error: error))
	}
}
