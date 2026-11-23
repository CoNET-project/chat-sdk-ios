import CryptoKit
import Foundation
@testable import ConetChatSDK

/// Test-only local root (R_db stand-in). Synthetic; never a wallet key.
let chatTestLocalRoot = Data(SHA256.hash(data: Data("chat-local-test-root-v1".utf8)))

/// Deterministic PRNG (sfc32). The same seed gives the same history on every run.
struct ChatFixtureRandom {
	private var a: UInt32, b: UInt32, c: UInt32, counter: UInt32

	init(seed: UInt32) {
		a = 0x9E37_79B9 ^ seed
		b = 0x243F_6A88 ^ seed
		c = 0xB7E1_5162 ^ seed
		counter = 1
		for _ in 0..<12 { _ = next() }
	}

	mutating func next() -> UInt32 {
		let t = a &+ b &+ counter
		counter &+= 1
		a = b ^ (b >> 9)
		b = c &+ (c << 3)
		c = ((c << 21) | (c >> 11)) &+ t
		return t
	}

	mutating func unit() -> Double { Double(next()) / 4_294_967_296.0 }
	mutating func below(_ n: Int) -> Int { Int(next() % UInt32(n)) }
}

/// Synthetic encrypted history in the v1.1 index shape (chain index + IPFS fragments).
/// Synthetic data only. The master is a test constant, not a user key.
final class ChatSynthHistory {
	struct Msg {
		var convKey: String
		var stableId: String
		var sendKey: String
		var sortTs: Int64
		var dir: String
		var kind: BeamioChatKind
		var body: String?
		var media: BeamioChatMedia?
		var revision: Int64
	}

	let master: Data
	let seed: UInt32
	private(set) var index: [[String: Any]] = []
	private(set) var fragments: [String: String] = [:]
	/// Final visible state per conversation (tombstones removed), ascending by K.
	private(set) var truth: [String: [Msg]] = [:]
	private(set) var messageCount = 0
	private(set) var sameMsCount = 0
	private(set) var mediaCount = 0
	private(set) var emptySendIdCount = 0

	private let idKey: SymmetricKey
	private let idxKey: SymmetricKey

	init(seed: UInt32, messages: Int, convs: [String], master: Data = Data(repeating: 0x5A, count: 32)) {
		self.seed = seed
		self.master = master
		self.idKey = BeamioChatLocalCrypto.idKey(localRoot: chatTestLocalRoot)
		self.idxKey = BeamioChatLocalCrypto.idxKey(localRoot: chatTestLocalRoot)
		var rng = ChatFixtureRandom(seed: seed)
		var prevCid = "0x" + BeamioChatLocalCrypto.hex(BeamioConetChatHistoryStore.hkdf(master: master, info: "frag-genesis", length: 32))
		var seq = 0
		var ts: Int64 = 1_780_000_000_000
		var finals: [String: [Msg]] = [:]
		var lastTs: Int64 = ts
		let sizes: [(Int, Int)] = [(4, 3), (3, 4), (16, 9), (9, 16), (1, 1)]

		func appendRecord(conv: String, sortTs: Int64, dir: String, sendId: String?, body: String?, revision: Int64, deleted: Bool) {
			var cid: String
			if let body, !deleted {
				let key = BeamioConetChatHistoryStore.hkdf(master: master, info: "frag|\(seq)|\(prevCid)", length: 32)
				// swiftlint:disable:next force_try
				let cipher = try! BeamioConetChatHistoryStore.aesGcmEncrypt(key: key, plaintext: Data(body.utf8))
				cid = Keccak256.hexUtf8(cipher)
				fragments[cid] = cipher
			} else {
				cid = "0x" + BeamioChatLocalCrypto.hex(Data(SHA256.hash(data: Data("tomb-\(seed)-\(seq)".utf8))))
			}
			var rec: [String: Any] = [
				"seq": seq, "cid": cid, "prevCid": prevCid,
				"ts": NSNumber(value: sortTs), "peer": conv, "dir": dir,
			]
			if let sendId { rec["sendId"] = sendId }
			if revision > 0 { rec["revision"] = Int(revision) }
			if deleted { rec["deleted"] = true }
			index.append(rec)
			prevCid = cid
			seq += 1
		}

		for n in 0..<messages {
			let conv = convs[rng.below(convs.count)]
			if rng.unit() > 0.33 { ts += Int64(1 + rng.below(2000)) } else { sameMsCount += 1 }
			if ts < lastTs { ts = lastTs }
			lastTs = ts
			let dir = rng.unit() < 0.5 ? "in" : "out"
			// 90%: a deterministic sendId (non-UUID). 10%: no sendId, so the writer's derived sendKey is used (N9).
			let hasSendId = rng.unit() < 0.9
			if !hasSendId { emptySendIdCount += 1 }
			var kind: BeamioChatKind = .text
			var media: BeamioChatMedia?
			var body = "FIXTURE-\(seed)-\(n) " + String(repeating: "lorem ipsum ", count: 1 + rng.below(6))
			if rng.unit() < 0.3 {
				mediaCount += 1
				let pick = rng.unit()
				let (w, h) = sizes[rng.below(sizes.count)]
				kind = pick < 0.7 ? .image : (pick < 0.9 ? .video : .file)
				// Spec 21.1 body: {"v":1,"kind","text","media":{mime,size,blob,width?,height?}}
				let manifest: [String: Any] = kind == .file
					? ["mime": "application/pdf", "size": 9, "blob": "m-\(seed)-\(n)"]
					: ["mime": "image/jpeg", "size": 9, "blob": "m-\(seed)-\(n)", "width": w, "height": h]
				let json: [String: Any] = ["v": 1, "kind": kind.rawValue, "text": "", "media": manifest]
				let data = (try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])) ?? Data()
				body = String(data: data, encoding: .utf8) ?? "{}"
				media = BeamioChatMedia(mime: manifest["mime"] as? String ?? "", widthPx: kind == .file ? nil : w,
				                        heightPx: kind == .file ? nil : h, blob: "m-\(seed)-\(n)")
			}
			let sendId: String? = hasSendId ? "sid-\(seed)-\(n)" : nil
			let sendKey = sendId ?? BeamioChatLocalCrypto.sendKeyDerived(idKey: idKey, peer: conv, dir: dir, ts: ts, body: body)
			// The writer stores the derived sendKey as the index sendId (N9), so the record is deterministic.
			appendRecord(conv: conv, sortTs: ts, dir: dir, sendId: sendKey, body: body, revision: 0, deleted: false)
			var msg = Msg(convKey: conv, stableId: BeamioChatLocalCrypto.stableId(idxKey: idxKey, sendKey: sendKey),
			              sendKey: sendKey, sortTs: ts, dir: dir, kind: kind,
			              body: kind == .text ? body : nil, media: media, revision: 0)
			messageCount += 1

			// 1% revisions of text messages: a later record with the same sendKey and a new body.
			if kind == .text, rng.unit() < 0.01 {
				let newBody = "FIXTURE-\(seed)-\(n)-rev1 " + String(repeating: "edited ", count: 1 + rng.below(3))
				appendRecord(conv: conv, sortTs: ts, dir: dir, sendId: sendKey, body: newBody, revision: 1, deleted: false)
				msg.body = newBody
				msg.revision = 1
			}
			// 0.5% tombstones: a deleted record for the same sendKey.
			if rng.unit() < 0.005 {
				appendRecord(conv: conv, sortTs: ts, dir: dir, sendId: sendKey, body: nil, revision: 2, deleted: true)
				continue
			}
			finals[conv, default: []].append(msg)
		}
		for (conv, list) in finals {
			truth[conv] = list.sorted {
				if $0.sortTs != $1.sortTs { return $0.sortTs < $1.sortTs }
				return $0.stableId.utf8.lexicographicallyPrecedes($1.stableId.utf8)
			}
		}
	}

	/// Thread-safe fetch of ciphertext by cid, with a call counter.
	final class Fetcher {
		private let lock = NSLock()
		private let fragments: [String: String]
		private(set) var calls = 0
		var delay: TimeInterval = 0

		init(_ fragments: [String: String]) { self.fragments = fragments }

		func fetch(_ cid: String) -> String? {
			lock.lock()
			calls += 1
			lock.unlock()
			if delay > 0 { Thread.sleep(forTimeInterval: delay) }
			return fragments[cid]
		}

		func reset() {
			lock.lock()
			calls = 0
			lock.unlock()
		}
	}
}

/// Parser for the synthetic media body shape (the same `{kind, text, manifest}` as the fixtures).
func chatFixtureMediaParser(_ body: String) -> (kind: BeamioChatKind, media: BeamioChatMedia?)? {
	BeamioChatMediaBody.parse(body)
}
