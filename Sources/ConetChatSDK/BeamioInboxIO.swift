import Foundation

/// The inbox and the call-signal ledger do their file work on one serial queue: never on the main queue. A completion comes
/// back on the main queue. The queue is serial, so the writes happen in the order of the calls.
///
/// Generation. Every identity clear advances the generation. A flow takes the generation when it starts and passes it
/// on. A job is queued only while its generation is still current, and its completion runs only while it still is. A clear is queued behind
/// every job queued before it: a write queued earlier runs before the wipe and is wiped with it, and nothing queued later survives it.
enum BeamioInboxIO {
	private static let queue = DispatchQueue(label: "com.beamio.chat.inbox-io", qos: .userInitiated)
	/// Guards `epoch`, and the queueing that depends on it, so that a check and the queueing cannot be split by a clear.
	private static let gate = NSLock()
	private static var epoch = 0

	/// The generation the current flow starts in.
	static var generation: Int {
		gate.lock(); defer { gate.unlock() }
		return epoch
	}

	/// Queues `work` on the inbox IO queue while `generation` is still current. `done` runs on the main queue after the work, and only while
	/// the generation is still current then. A stale call queues nothing: nothing is written, delivered or re-signed.
	static func perform<T>(generation gen: Int, _ work: @escaping () -> T, then done: @escaping (T) -> Void) {
		gate.lock(); defer { gate.unlock() }
		guard epoch == gen else { return }
		queue.async {
			let value = work()
			DispatchQueue.main.async {
				guard BeamioInboxIO.generation == gen else { return }
				done(value)
			}
		}
	}

	/// The identity clear for an account switch ((1)): advances the generation, and blocks until the wipe has run on the inbox IO queue. A
	/// caller that needs the result before it starts (the chat module for the new account) uses this. Never called from the inbox IO queue.
	static func wipeNow(_ work: @escaping () -> Bool) -> Bool {
		gate.lock()
		epoch += 1
		gate.unlock()
		return queue.sync { work() }
	}

	/// The identity clear: advances the generation and queues `work` (the wipe) behind every job already queued. `done` runs on the main queue
	/// with the wipe's result, whatever later clears do: the reply to a clear is not dropped.
	static func wipe(_ work: @escaping () -> Bool, then done: @escaping (Bool) -> Void) {
		gate.lock(); defer { gate.unlock() }
		epoch += 1
		queue.async {
			let ok = work()
			DispatchQueue.main.async { done(ok) }
		}
	}
}
