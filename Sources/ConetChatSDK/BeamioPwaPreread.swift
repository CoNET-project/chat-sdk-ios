import Foundation

/// The published preread of the native store, with its epoch (25.52Y.163 r2.5.19 第 42(2) 项, 第 49(2) 项, 第 59(3)(f) 项).
///
/// The shell starts a read at start-up, asynchronously (`startAsync`). A preread answers the reading published for the current epoch. While the
/// start-up read is pending, the answer is `unknown`, never an empty answer (第 42(3) 项). Every write moves the epoch on, so a reading that was
/// started under an older epoch is dropped when it arrives (第 49(2) 项). After a write, whatever its outcome, the store is read again and the
/// reading is published at the new epoch (第 59(3)(f) 项).
enum BeamioPwaPreread {
	private static let lock = NSLock()
	private static var epoch = 0
	private static var pending = false
	private static var published: (epoch: Int, reading: BeamioPwaWalletSync.Reading)?

	/// Moves to a new epoch. A reading published under the older epoch is no longer current, and a read of that epoch that is still pending is
	/// not waited for: `pending` says whether the new epoch starts with a read in flight.
	@discardableResult
	static func advance(pending isPending: Bool) -> Int {
		lock.lock(); defer { lock.unlock() }
		epoch += 1
		published = nil
		pending = isPending
		return epoch
	}

	/// Publishes `reading` for `value` only when `value` is still the current epoch. An older reading is dropped (第 49(2) 项). True when published.
	@discardableResult
	static func publish(_ reading: BeamioPwaWalletSync.Reading, epoch value: Int) -> Bool {
		lock.lock(); defer { lock.unlock() }
		guard value == epoch else { return false }
		published = (value, reading)
		pending = false
		return true
	}

	/// The reading an answer uses. The published reading of the current epoch; `unknown` while a start-up read of this epoch is pending
	/// (第 42(3) 项); otherwise the store is read now, and that reading is published at the current epoch.
	static func current(snapshotKnown: Bool, storageLocked: Bool, store: BeamioChatWalletKeyStoring) -> BeamioPwaWalletSync.Reading {
		// An unknown snapshot or a storage lock answers unknown, whatever is published: a published reading can predate the lock (the design of
		// 59(3)(f) publishes the reading after each write; a store that changes without a write is not seen until the next epoch).
		guard snapshotKnown, !storageLocked else { return .unknown }
		lock.lock()
		if let entry = published, entry.epoch == epoch {
			lock.unlock()
			return entry.reading
		}
		if pending {
			lock.unlock()
			return .unknown
		}
		let current = epoch
		lock.unlock()
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: store)
		publish(reading, epoch: current)
		return reading
	}

	/// The start-up read of the shell (第 42(2) 項): started on a background queue. Its result is published only if no write has moved the epoch on.
	/// The snapshot values are judged by the caller, on its own thread; the store is read on the background queue.
	static func startAsync(snapshotKnown: Bool, storageLocked: Bool, store: BeamioChatWalletKeyStoring) {
		let started = advance(pending: true)
		DispatchQueue.global(qos: .utility).async {
			let reading = BeamioPwaWalletSync.reading(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: store)
			publish(reading, epoch: started)
		}
	}

	/// Called before a write (第 49(2) 项): a reading that is still in flight from before the write is no longer published.
	static func beforeWrite() {
		advance(pending: false)
	}

	/// Called after a write, whatever its outcome (第 59(3)(f) 項): the store is read again at the new epoch and that reading is published.
	static func afterWrite(snapshotKnown: Bool, storageLocked: Bool, store: BeamioChatWalletKeyStoring) {
		let current = advance(pending: false)
		let reading = BeamioPwaWalletSync.reading(snapshotKnown: snapshotKnown, storageLocked: storageLocked, store: store)
		publish(reading, epoch: current)
	}

	/// Test seam: a process restart forgets the published reading and the epoch count (第 56(2) 项 analogue for the preread).
	static func restartForTests() {
		advance(pending: false)
	}
}
