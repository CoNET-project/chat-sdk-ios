import Foundation
import Network
#if canImport(UIKit)
import UIKit
#endif

/// Warm entry pool for one-shot POSTs (`BeamioSiCipherPost.post`).
///
/// Keeps several roster entries that answered a plain `GET /` recently, so a send
/// takes a checked entry at once instead of probing first. Each send takes a
/// random warm entry that differs from the last few sends; the set itself rotates
/// one entry per refresh. One or two TCP connections to warm entries are opened
/// ahead of time (SI closes after one request, so each is used once).
///
/// Runs only while the SDK is active: app in the foreground, or a hold from the
/// shell (ringing, dialing, in a call, push wake). Nothing runs in the background
/// otherwise. Probes are bare `GET /` on port 80: no wallet, no signature, no
/// identity, no call data.
public final class BeamioEntryPool {
	public static let shared = BeamioEntryPool()

	struct Entry {
		var ip: String
		var latencyMs: Int
		var checkedAt: Date
	}

	private struct Hot {
		var conn: NWConnection
		var openedAt: Date
	}

	// Tunables.
	static let targetReady = 8
	static let hotTarget = 2
	static let tickInterval: TimeInterval = 15
	static let maxLatencyMs = 1500
	static let probeTimeout: TimeInterval = 2
	static let entryMaxAge: TimeInterval = 90
	static let hotMaxAge: TimeInterval = 15
	static let recentAvoid = 3

	private let lock = NSLock()
	private let queue = DispatchQueue(label: "beamio.entrypool")
	private var ready: [String: Entry] = [:]
	private var recent: [String] = []
	private var hot: [String: Hot] = [:]
	private var foreground = false
	private var holds = Set<String>()
	private var timer: DispatchSourceTimer?
	private var tickRunning = false
	private var tickAgain = false

	private init() {
		#if canImport(UIKit)
		let center = NotificationCenter.default
		center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: nil) { [weak self] _ in
			self?.setForeground(true)
		}
		center.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: nil) { [weak self] _ in
			self?.setForeground(false)
		}
		DispatchQueue.main.async { [weak self] in
			self?.setForeground(UIApplication.shared.applicationState != .background)
		}
		#endif
	}

	// MARK: - Activity

	/// True while warming runs (foreground or any hold).
	public var isActive: Bool {
		lock.lock()
		defer { lock.unlock() }
		return foreground || !holds.isEmpty
	}

	/// Keep warming while `reason` holds (e.g. `"call"`, `"incomingCall"`).
	public func hold(_ reason: String) {
		lock.lock()
		let inserted = holds.insert(reason).inserted
		lock.unlock()
		if inserted { activityChanged() }
	}

	public func release(_ reason: String) {
		lock.lock()
		let removed = holds.remove(reason) != nil
		lock.unlock()
		if removed { activityChanged() }
	}

	/// Refresh now (push wake, node table change). No-op while inactive.
	public func warmNow() {
		queue.async { [weak self] in self?.tick() }
	}

	private func setForeground(_ on: Bool) {
		lock.lock()
		let changed = foreground != on
		foreground = on
		lock.unlock()
		if changed { activityChanged() }
	}

	private func activityChanged() {
		queue.async { [weak self] in
			guard let self else { return }
			if self.isActive {
				if self.timer == nil {
					let t = DispatchSource.makeTimerSource(queue: self.queue)
					t.schedule(deadline: .now(), repeating: Self.tickInterval, leeway: .seconds(2))
					t.setEventHandler { [weak self] in self?.tick() }
					self.timer = t
					t.resume()
				}
			} else {
				self.timer?.cancel()
				self.timer = nil
				self.closeAllHot()
			}
		}
	}

	// MARK: - Use

	/// A random warm entry inside `allowed`, outside `excluding`, preferably not one
	/// of the last few used. Returns its pre-opened connection when one is ready.
	func take(allowed: Set<String>, excluding: Set<String>) -> (ip: String, conn: NWConnection?)? {
		lock.lock()
		let now = Date()
		let usable = ready.values.filter {
			allowed.contains($0.ip) && !excluding.contains($0.ip)
				&& now.timeIntervalSince($0.checkedAt) < Self.entryMaxAge * 2
		}.map(\.ip)
		guard !usable.isEmpty else {
			lock.unlock()
			return nil
		}
		let fresh = usable.filter { !recent.contains($0) }
		let pool = fresh.isEmpty ? usable : fresh
		// Prefer an entry whose connection is already open: still random among those.
		let hotIps = pool.filter { ip in
			guard let h = hot[ip] else { return false }
			return now.timeIntervalSince(h.openedAt) < Self.hotMaxAge && h.conn.state == .ready
		}
		let ip = (hotIps.randomElement() ?? pool.randomElement())!
		let conn = hot.removeValue(forKey: ip)?.conn
		recent.append(ip)
		if recent.count > Self.recentAvoid { recent.removeFirst(recent.count - Self.recentAvoid) }
		lock.unlock()
		warmNow()  // replace the used connection
		if let conn, conn.state == .ready { return (ip, conn) }
		conn?.cancel()
		return (ip, nil)
	}

	/// A send through `ip` failed: drop it until a later probe brings it back.
	func reportFailure(ip: String) {
		lock.lock()
		ready.removeValue(forKey: ip)
		let h = hot.removeValue(forKey: ip)
		lock.unlock()
		h?.conn.cancel()
	}

	/// Node table changed: removed IPs leave the pool now; new ones are probed first.
	public func nodesChanged(removed: Set<String>) {
		lock.lock()
		var dropped: [NWConnection] = []
		for ip in removed {
			ready.removeValue(forKey: ip)
			if let h = hot.removeValue(forKey: ip) { dropped.append(h.conn) }
		}
		lock.unlock()
		dropped.forEach { $0.cancel() }
		warmNow()
	}

	/// For QA logs: warm entries and open connections.
	public var stats: (ready: Int, hot: Int) {
		lock.lock()
		defer { lock.unlock() }
		return (ready.count, hot.count)
	}

	// MARK: - Refresh

	private func rosterIps() -> [String] {
		var seen = Set<String>()
		return BeamioChatPgpKeychain.loadSiNodes().compactMap { node in
			guard let ip = BeamioSiCipherPost.normalizeIp(node.ip),
			      !BeamioSiCipherPost.isMarkedUnreachable(ip),
			      seen.insert(ip).inserted
			else { return nil }
			return ip
		}
	}

	/// On `queue`. Probes run in parallel on global queues.
	private func tick() {
		guard isActive else { return }
		// The node table check rides on the same activity (no polling while inactive).
		BeamioGuardianNodeWatch.shared.tick()
		if tickRunning {
			tickAgain = true
			return
		}
		tickRunning = true
		defer {
			tickRunning = false
			if tickAgain {
				tickAgain = false
				queue.async { [weak self] in self?.tick() }
			}
		}

		let roster = rosterIps()
		let rosterSet = Set(roster)
		let now = Date()

		// Drop entries that left the roster; re-probe old ones.
		lock.lock()
		for ip in ready.keys where !rosterSet.contains(ip) { ready.removeValue(forKey: ip) }
		var stale = ready.values.filter { now.timeIntervalSince($0.checkedAt) > Self.entryMaxAge }.map(\.ip)
		// Rotate: once full, retire the oldest-checked entry so the set keeps changing.
		if ready.count >= Self.targetReady, let oldest = ready.values.min(by: { $0.checkedAt < $1.checkedAt }) {
			ready.removeValue(forKey: oldest.ip)
			stale.removeAll { $0 == oldest.ip }
		}
		let have = Set(ready.keys)
		lock.unlock()

		let need = max(0, Self.targetReady - have.count + stale.count)
		let fresh = Array(roster.filter { !have.contains($0) }.shuffled().prefix(need + 2))
		let results = probe(stale + fresh)

		lock.lock()
		for (ip, latency) in results {
			if let latency, latency <= Self.maxLatencyMs, rosterSet.contains(ip) {
				ready[ip] = Entry(ip: ip, latencyMs: latency, checkedAt: Date())
			} else {
				ready.removeValue(forKey: ip)
			}
		}
		// Keep at most the target, fastest first.
		if ready.count > Self.targetReady {
			let keep = ready.values.sorted { $0.latencyMs < $1.latencyMs }.prefix(Self.targetReady).map(\.ip)
			ready = ready.filter { keep.contains($0.key) }
		}
		// Retire old or broken pre-opened connections.
		var retired: [NWConnection] = []
		for (ip, h) in hot where Date().timeIntervalSince(h.openedAt) > Self.hotMaxAge || h.conn.state != .ready || ready[ip] == nil {
			retired.append(h.conn)
			hot.removeValue(forKey: ip)
		}
		let openCount = Self.hotTarget - hot.count
		let candidates = ready.keys.filter { hot[$0] == nil && !recent.contains($0) }.shuffled()
		lock.unlock()
		retired.forEach { $0.cancel() }

		guard isActive, openCount > 0 else { return }
		for ip in candidates.prefix(openCount) {
			if let conn = BeamioSiCipherPost.openConnection(ip: ip, timeout: Self.probeTimeout) {
				lock.lock()
				if isActiveLocked() {
					hot[ip] = Hot(conn: conn, openedAt: Date())
					lock.unlock()
				} else {
					lock.unlock()
					conn.cancel()
				}
			}
		}
	}

	private func isActiveLocked() -> Bool { foreground || !holds.isEmpty }

	/// Parallel `GET /` probes. Value: latency in ms, nil when unreachable.
	private func probe(_ ips: [String]) -> [(String, Int?)] {
		guard !ips.isEmpty else { return [] }
		let group = DispatchGroup()
		let resultLock = NSLock()
		var out: [(String, Int?)] = []
		for ip in ips {
			group.enter()
			DispatchQueue.global(qos: .utility).async {
				let r = BeamioSiCipherPost.httpRequest(
					ip: ip, method: "GET", path: "/", body: nil,
					timeout: Self.probeTimeout, stopAfterStatusLine: true
				)
				let ok = r.status > 0
				BeamioSiCipherPost.scoreEntry(ip: ip, reachable: ok, latencyMs: r.ms)
				resultLock.lock()
				out.append((ip, ok ? r.ms : nil))
				resultLock.unlock()
				group.leave()
			}
		}
		_ = group.wait(timeout: .now() + Self.probeTimeout + 1.5)
		resultLock.lock()
		defer { resultLock.unlock() }
		return out
	}

	private func closeAllHot() {
		lock.lock()
		let conns = hot.values.map(\.conn)
		hot.removeAll()
		lock.unlock()
		conns.forEach { $0.cancel() }
	}
}
