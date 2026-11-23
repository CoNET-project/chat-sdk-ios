import Foundation

/// Delivery state of call-control signals, per (callId, sessionId).
///
/// A signal waits as `pending` while no call layer is registered, and is handed over when one registers, or on a later copy or replay. A
/// key handed over is `delivered` and is never handed over again. Handing over is a claim: `claim` takes the right to hand a key over, and
/// is refused while the key is delivered or another path holds the claim (D5). The claim is in memory only; after a restart a key that was
/// being handed over is simply pending again (at least once, and the call layer keeps one signal per key).
///
/// An unreadable ledger answers `none` and cannot be marked: the caller must then not treat the frame as recorded. The ledger is kept
/// with the inbox file rules, and every call runs on the inbox IO queue (`BeamioInboxIO.perform`).
enum BeamioConetChatCallLedger {
	enum State: Equatable {
		case none
		case pending
		case delivered
	}

	struct Pending: Equatable {
		var key: String
		var type: String
		var callId: String
		var sessionId: String
		var from: String
	}

	private static let lock = NSLock()
#if BEAMIO_TEST_HOOKS
	/// Test build only: every write of the call ledger fails.
	static var failWrites = false
#endif

	/// Keys whose hand-over is held right now (memory only).
	private static var inFlight: Set<String> = []

	private static var fileURL: URL? { BeamioInboxFile.folder?.appendingPathComponent("call_signals_v1.json") }

	static func key(callId: String, sessionId: String) -> String {
		callId + "|" + sessionId
	}

	/// The rows, or nil when the file is unreadable. A missing file is no rows.
	private static func load() -> [[String: Any]]? {
		guard let url = fileURL else { return nil }
		switch BeamioInboxFile.read(url) {
		case .missing: return []
		case .unreadable: return nil
		case .data(let data): return try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
		}
	}

	private static func save(_ rows: [[String: Any]]) -> Bool {
#if BEAMIO_TEST_HOOKS
		if failWrites { return false }
#endif
		guard let url = fileURL, let out = try? JSONSerialization.data(withJSONObject: rows) else { return false }
		return BeamioInboxFile.replace(url, with: out)
	}

	/// A row written before `st` existed is a delivered key.
	private static func stateOf(_ row: [String: Any]) -> State {
		(row["st"] as? String) == "pending" ? .pending : .delivered
	}

	private static func stateLocked(_ key: String) -> State {
		guard let rows = load(), let row = rows.first(where: { ($0["k"] as? String) == key }) else { return .none }
		return stateOf(row)
	}

	static func state(_ key: String) -> State {
		lock.lock(); defer { lock.unlock() }
		return stateLocked(key)
	}

	static func delivered(_ key: String) -> Bool {
		state(key) == .delivered
	}

	/// Delivered keys kept at most. Above this, the oldest delivered keys go first (FIFO by delivery time). Pending signals are
	/// never evicted. An evicted key that arrives again is handed over again; the call layer keeps one signal per (callId, sessionId).
	static let maxDelivered = 50000

	/// Drops the oldest delivered rows above `maxDelivered`. Pending rows are kept whatever their age.
	private static func evictDelivered(_ rows: inout [[String: Any]]) {
		var excess = rows.filter { stateOf($0) == .delivered }.count - maxDelivered
		guard excess > 0 else { return }
		rows = rows.filter { row in
			guard excess > 0, stateOf(row) == .delivered else { return true }
			excess -= 1
			return false
		}
	}

	/// What a claim found: a claimed key, a key already delivered, or a key another path holds right now.
	enum Claim: Equatable {
		case claimed
		case delivered
		case held
	}

	/// The claim, with the reason when it is refused.
	static func claimOutcome(_ p: Pending) -> Claim {
		lock.lock(); defer { lock.unlock() }
		if stateLocked(p.key) == .delivered { return .delivered }
		if inFlight.contains(p.key) { return .held }
		inFlight.insert(p.key)
		return .claimed
	}

	/// Takes the right to hand this signal over now. True only when the key is not delivered and no other path holds it. Check and claim are
	/// one step under the lock (D5). The caller gives the claim back with `release`, or completes it with `markPending` or `markDelivered`.
	static func claim(_ p: Pending) -> Bool {
		claimOutcome(p) == .claimed
	}

	/// Gives a claim back: there was no observer, or the record could not be written.
	static func release(_ key: String) {
		lock.lock(); defer { lock.unlock() }
		inFlight.remove(key)
	}

	/// Keeps a signal that no call layer could take yet. Never overrides a delivered key. False when it cannot be written.
	@discardableResult
	static func markPending(_ p: Pending) -> Bool {
		lock.lock(); defer { lock.unlock() }
		guard var rows = load() else { return false }
		if let i = rows.firstIndex(where: { ($0["k"] as? String) == p.key }) {
			if stateOf(rows[i]) == .delivered { return true }
			rows[i] = row(p, state: "pending")
		} else {
			rows.append(row(p, state: "pending"))
		}
		return save(rows)
	}

	/// Marks a key handed over, and ends the claim. Replaces its pending row. False when it cannot be written; the key then stays undelivered
	/// and can be claimed again.
	@discardableResult
	static func markDelivered(_ key: String) -> Bool {
		lock.lock(); defer { lock.unlock() }
		inFlight.remove(key)
		guard var rows = load() else { return false }
		let done: [String: Any] = ["k": key, "st": "delivered", "t": Date().timeIntervalSince1970]
		if let i = rows.firstIndex(where: { ($0["k"] as? String) == key }) {
			if stateOf(rows[i]) == .delivered { return true }
			rows.remove(at: i)
		}
		// FIFO by delivery time: the key goes to the end, then the oldest delivered keys above the cap go (D8).
		rows.append(done)
		evictDelivered(&rows)
		return save(rows)
	}

	/// The signals still waiting for a call layer.
	static func pendingSignals() -> [Pending] {
		lock.lock(); defer { lock.unlock() }
		guard let rows = load() else { return [] }
		return rows.filter { stateOf($0) == .pending }.compactMap { r in
			guard let k = r["k"] as? String else { return nil }
			return Pending(
				key: k, type: (r["type"] as? String) ?? "", callId: (r["callId"] as? String) ?? "",
				sessionId: (r["sessionId"] as? String) ?? "", from: (r["from"] as? String) ?? ""
			)
		}
	}

	private static func row(_ p: Pending, state: String) -> [String: Any] {
		["k": p.key, "st": state, "type": p.type, "callId": p.callId, "sessionId": p.sessionId, "from": p.from,
		 "t": Date().timeIntervalSince1970]
	}

	/// True when the call ledger holds any row, or cannot be read (data of unknown content is data, (2)). A missing file holds none.
	static func hasAnyRow() -> Bool {
		lock.lock(); defer { lock.unlock() }
		guard let rows = load() else { return true }
		return !rows.isEmpty
	}

	/// The identity was cleared: every key, and every claim, goes.
	@discardableResult
	static func clear() -> Bool {
		lock.lock(); defer { lock.unlock() }
		inFlight.removeAll()
		guard let url = fileURL else { return true }
		return BeamioInboxFile.remove(url)
	}
}
