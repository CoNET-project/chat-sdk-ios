import Foundation

// Public types of the local chat library (interface spec v1.1: 6.1, 6.3, 6.6, 8.3).

public enum BeamioChatLocalError: Error, Equatable {
	case locked
	case kcvMismatch
	case schemaNewer
	case cursorInvalid
	case pendingPresent(Int)
	case crypto
	case io
	case sqlite(Int32)
	/// Import (11.2): the batch names another account than the unlocked one.
	case accountMismatch
	/// Import (11.2): more than 200 rows in one call.
	case batchTooLarge
	/// Import (11.2): a row without convKey, dir, ts or body.
	case badRow
}

/// One row of `historyImportBatch` (11.2, M2). `ts` is the sender time and is required.
public struct BeamioChatImportRow {
	public var convKey: String
	public var dir: String
	public var ts: Int64?
	public var sendId: String?
	public var body: String
	/// Not yet published on the old side: `pending_publish = 1` (M2).
	public var pending: Bool

	public init(convKey: String, dir: String, ts: Int64?, sendId: String?, body: String, pending: Bool = false) {
		self.convKey = convKey
		self.dir = dir
		self.ts = ts
		self.sendId = sendId
		self.body = body
		self.pending = pending
	}
}

public struct BeamioChatImportResult: Equatable {
	public var imported: Int
	public var duplicates: Int
	public var sendKeyConflict: Int

	public init(imported: Int, duplicates: Int, sendKeyConflict: Int) {
		self.imported = imported
		self.duplicates = duplicates
		self.sendKeyConflict = sendKeyConflict
	}
}

public enum BeamioChatOrientation: String {
	case portrait
	case landscape
}

public enum BeamioChatKind: String {
	case text
	case image
	case video
	case file
	case system
	case unknown
	/// ChatMessage kinds without media (spec 21.2 R7).
	case voice
	case call
	case payment
	case reply
}

public enum BeamioChatSource: String {
	case local
	case migrating
	case locked
}

public enum BeamioChatSyncState: String {
	case idle
	case running
	case paused
	case error
}

/// `more`: rows remain to scan. `pending`: rows are exhausted but the full sync is not complete,
/// so the end is unknown (6.4). `end`: sync complete and no older rows.
public enum BeamioChatOlderState: String {
	case more
	case pending
	case end
}

/// Container size as measured by the UI. Points, not pixels. The SDK never infers orientation.
public struct BeamioChatViewport: Equatable {
	public var widthPt: Double
	public var heightPt: Double
	public var orientation: BeamioChatOrientation
	public var fontScale: Double
	public var layoutVersion: Int

	public init(widthPt: Double, heightPt: Double, orientation: BeamioChatOrientation, fontScale: Double = 1.0, layoutVersion: Int = 1) {
		self.widthPt = widthPt
		self.heightPt = heightPt
		self.orientation = orientation
		self.fontScale = fontScale
		self.layoutVersion = layoutVersion
	}
}

public struct BeamioChatMedia: Equatable {
	public var mime: String
	public var widthPx: Int?
	public var heightPx: Int?
	/// Local-copy state. This library stores no media bytes, so it is "pending" for now.
	public var state: String
	/// Blob name from the message manifest. Internal: never returned to the UI.
	var blob: String
	/// The manifest says the blob is missing: a local failure (oracle O-3, 88·fs placeholder).
	var blobMissing: Bool

	public init(mime: String, widthPx: Int? = nil, heightPx: Int? = nil, state: String = "pending", blob: String = "", blobMissing: Bool = false) {
		self.mime = mime
		self.widthPx = widthPx
		self.heightPx = heightPx
		self.state = blobMissing ? "failed" : state
		self.blob = blob
		self.blobMissing = blobMissing
	}
}

public struct BeamioChatLayout: Equatable {
	public var wPt: Double
	public var hPt: Double
	public var measured: Bool

	public init(wPt: Double, hPt: Double, measured: Bool) {
		self.wPt = wPt
		self.hPt = hPt
		self.measured = measured
	}
}

public struct BeamioChatItem: Equatable {
	/// Library identity for `reportLayout` and UI de-duplication only (6.1).
	public var stableId: String
	public var sortTs: Int64
	public var dir: String
	public var kind: BeamioChatKind
	/// Only text and system items carry a body.
	public var body: String?
	public var media: BeamioChatMedia?
	public var revision: Int64
	public var layout: BeamioChatLayout

	public init(stableId: String, sortTs: Int64, dir: String, kind: BeamioChatKind, body: String?,
	            media: BeamioChatMedia?, revision: Int64, layout: BeamioChatLayout) {
		self.stableId = stableId
		self.sortTs = sortTs
		self.dir = dir
		self.kind = kind
		self.body = body
		self.media = media
		self.revision = revision
		self.layout = layout
	}
}

public struct BeamioChatPage {
	/// Ascending (oldest first). Tombstones are not included.
	public var items: [BeamioChatItem]
	/// Cursor for the next `loadOlder`. nil only when `olderState` is `end`.
	public var olderCursor: String?
	public var olderState: BeamioChatOlderState
	/// The 2000-row budget ran out with no visible item. The UI must request again (6.3).
	public var scanExhausted: Bool
	public var syncState: BeamioChatSyncState
	public var source: BeamioChatSource
	/// Local data ran out before the viewport was filled (6.2). Not an error.
	public var short: Bool
	/// The safety cap (200 rows) stopped the page early. Normal viewports never reach it.
	public var capped: Bool

	public init(items: [BeamioChatItem], olderCursor: String?, olderState: BeamioChatOlderState,
	            scanExhausted: Bool = false, syncState: BeamioChatSyncState, source: BeamioChatSource,
	            short: Bool = false, capped: Bool = false) {
		self.items = items
		self.olderCursor = olderCursor
		self.olderState = olderState
		self.scanExhausted = scanExhausted
		self.syncState = syncState
		self.source = source
		self.short = short
		self.capped = capped
	}
}

/// Result of `clearLocalCache` (6.3).
public struct BeamioChatClearResult: Equatable {
	public var pendingKept: Int

	public init(pendingKept: Int) {
		self.pendingKept = pendingKept
	}
}

public enum BeamioChatEvent {
	case inserted(convKey: String, items: [BeamioChatItem], position: String)
	case updated(convKey: String, stableId: String, revision: Int64)
	case deleted(convKey: String, stableId: String)
	case cleared(scope: String, convKey: String?, pendingKept: Int)
	case syncProgress(accountKey: String, doneRows: Int, totalRows: Int, state: String)
	/// The UI must clear everything it shows at once (6.5).
	case locked
	/// Older rows arrived for a window that was waiting on sync (6.4).
	case olderAvailable(convKey: String)
}

public struct BeamioChatSyncReport: Equatable {
	public var locked = false
	public var stopped = false
	public var records = 0
	public var fetched = 0
	public var skippedHave = 0
	public var inserted = 0
	public var updated = 0
	public var tombstones = 0
	public var tsMismatch = 0
	/// D16 corrections: a sender-time row replaced a receive-time row with the same sendKey (5.1, rule 4).
	public var tsCorrected = 0
	public var failed = 0
	public var cidUpdated = 0
	/// Same sendKey, different body, same revision: the first one is kept (4.4). Counted only.
	public var sendKeyConflict = 0
	/// Legacy random-UUID records fetched again to derive their sendKey (Q-7). Counted separately.
	public var legacyRefetch = 0
	/// Records folded into an earlier record with the same (peer, dir, ts, body digest) (r1 4.5).
	public var folded = 0

	public init() {}
}

/// Viewport-based layout model (spec 8.1 and 8.3). Estimates only decide how many rows fit a page.
enum BeamioChatLocalLayoutModel {
	static func widthBucket(_ widthPt: Double) -> Int {
		Int((widthPt / 8).rounded()) * 8
	}

	static func fontBucket(_ fontScale: Double) -> Int {
		min(20, max(8, Int((fontScale * 10).rounded())))
	}

	static func orientationOf(_ vp: BeamioChatViewport) -> String {
		vp.orientation.rawValue
	}

	/// Layout key (8.1): width bucket | orientation | font bucket | layout version.
	static func layoutKey(_ vp: BeamioChatViewport) -> String {
		"\(widthBucket(vp.widthPt))|\(orientationOf(vp))|\(fontBucket(vp.fontScale))|\(vp.layoutVersion)"
	}

	/// Unmeasured estimate. Same formula as `chat-layout-oracle.mjs` (estimateHeight, normative), rounded to 0.1.
	/// Text uses per-character widths and wrapping (model A). Media: min(widthPt − 24, 280) wide, the manifest ratio
	/// (4:3 image, 16:9 video without dims), clamped to [min(120, 0.9·heightPt), 0.9·heightPt], plus a 24·fs caption.
	static func estimate(kind: BeamioChatKind, body: String?, media: BeamioChatMedia?, viewport vp: BeamioChatViewport) -> (wPt: Double, hPt: Double) {
		let fs = vp.fontScale
		let hi = 0.9 * vp.heightPt
		let lo = min(120, hi)
		func clamp(_ x: Double) -> Double { min(hi, max(lo, x)) }
		switch kind {
		case .text:
			let lines = textLines(body ?? "", widthPt: vp.widthPt, fs: fs)
			return (vp.widthPt, r1(16 * fs + Double(lines) * 1.4 * 16 * fs))
		case .file, .system, .unknown, .voice, .call, .payment, .reply: // oracle has no entry for these four; 72·fs placeholder (open, 8.3)
			return (vp.widthPt, r1(72 * fs))
		case .image, .video:
			if media?.blobMissing == true { return (vp.widthPt, r1(88 * fs)) }
			let w = min(vp.widthPt - 24, 280)
			var ratio = kind == .video ? 9.0 / 16.0 : 3.0 / 4.0
			if let m = media, let mw = m.widthPx, let mh = m.heightPx, mw > 0, mh > 0 {
				ratio = Double(mh) / Double(mw)
			}
			return (r1(w), r1(clamp(w * ratio) + 24 * fs))
		}
	}

	/// Oracle model A: characters by class, wrapped per character, '\n' forces a line break.
	static func textLines(_ body: String, widthPt: Double, fs: Double) -> Int {
		let fontPt = 16 * fs
		let width = max(1, widthPt - 24)
		var lines = 0
		for logical in body.split(separator: "\n", omittingEmptySubsequences: false) {
			lines += 1
			var cur = 0.0
			for sc in logical.unicodeScalars {
				let a = emWidth(sc) * fontPt
				if cur + a > width && cur > 0 {
					lines += 1
					cur = a
				} else {
					cur += a
				}
			}
		}
		return lines
	}

	static func emWidth(_ sc: Unicode.Scalar) -> Double {
		let cp = sc.value
		if cp == 0x20 { return 0.28 }
		if cp >= 0x30 && cp <= 0x39 { return 0.55 }
		if (cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a) { return 0.52 }
		if cp < 0x80 { return 0.38 }
		return 1.0
	}

	static func r1(_ x: Double) -> Double { (x * 10).rounded() / 10 }
}

/// Media body parser. Input is the stored UTF-8 bytes, never re-serialised (R8).
/// ChatMessage (21.1) is the main form; the `{"v":1,…}` envelope is kept for read compatibility (R4).
struct BeamioChatManifest: Equatable {
	var kind: BeamioChatKind
	var mime: String?
	var sizeBytes: Int64?
	var name: String?
	var blobId: String?
	var mediaKind: String?
	var isArchive: Bool
	var width: Int?
	var height: Int?
}

/// One classification. `text` is the display text: the `text` field of a ChatMessage (the caption for media),
/// or the whole body for plain text (R2, R3, R5). `reason` and `parseError` are set only for `.unknown`.
struct BeamioChatMediaParse: Equatable {
	var kind: BeamioChatKind
	var media: BeamioChatMedia?
	var text: String
	var manifest: BeamioChatManifest?
	var reason: String?
	var parseError: Bool
}

enum BeamioChatMediaBody {
	/// Keys that make a JSON object a ChatMessage (21.1). With no `v`, one of them selects R6 or R7.
	static let chatMessageKeys: Set<String> = [
		"text", "fileMessage", "voiceMessage", "callRecord", "paymentCard", "reply",
		"sendId", "from", "createdAt", "id", "status", "claimedFrom", "quote",
	]

	/// Classifies the stored bytes (R1–R9). Never nil: plain text is `.text` with the whole body as `text`.
	static func classify(_ bytes: Data) -> BeamioChatMediaParse {
		// R1: strict UTF-8.
		guard let text = String(data: bytes, encoding: .utf8) else {
			return failure("utf8", parseError: true)
		}
		// R2, R3: not an object → plain text.
		guard text.utf8.first == UInt8(ascii: "{"),
		      let obj = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any]
		else { return plain(text) }
		// R4: a `v` member makes it the legacy envelope.
		if obj["v"] != nil { return legacy(obj) }
		// R5: no `v` and no ChatMessage key → plain text.
		guard obj.keys.contains(where: { chatMessageKeys.contains($0) }) else { return plain(text) }
		// R6, R7.
		return chatMessage(obj)
	}

	/// Store-facing form: nil for plain text (the store keeps the body as it is); otherwise the stored kind and media.
	static func parse(_ body: String) -> (kind: BeamioChatKind, media: BeamioChatMedia?)? {
		let c = classify(Data(body.utf8))
		return c.kind == .text ? nil : (c.kind, c.media)
	}

	/// Display text of a stored body (21.1): the `text` field of a ChatMessage, or the whole body for plain text.
	static func displayText(_ body: String) -> String {
		classify(Data(body.utf8)).text
	}

	private static func plain(_ text: String) -> BeamioChatMediaParse {
		BeamioChatMediaParse(kind: .text, media: nil, text: text, manifest: nil, reason: nil, parseError: false)
	}

	private static func failure(_ reason: String, parseError: Bool = false) -> BeamioChatMediaParse {
		BeamioChatMediaParse(kind: .unknown, media: BeamioChatMedia(mime: "", state: "failed"), text: "",
		                     manifest: nil, reason: reason, parseError: parseError)
	}

	/// R4: legacy envelope. `v` must be 1; kind, text, media.mime, media.size and media.blob are checked.
	private static func legacy(_ obj: [String: Any]) -> BeamioChatMediaParse {
		guard let v = obj["v"] as? NSNumber, CFGetTypeID(v) != CFBooleanGetTypeID(), v.doubleValue == 1 else {
			return failure("version")
		}
		guard let k = obj["kind"] as? String, let kind = BeamioChatKind(rawValue: k),
		      kind == .image || kind == .video || kind == .file,
		      let text = obj["text"] as? String,
		      let mf = obj["media"] as? [String: Any],
		      let mime = mf["mime"] as? String,
		      let size = integer(mf["size"]),
		      let blob = mf["blob"] as? String
		else { return failure("kind_or_media") }
		// Width and height are carried only as a pair of positive integers (21.3).
		let w = positiveInt(mf["width"])
		let h = positiveInt(mf["height"])
		let width = (w != nil && h != nil) ? w : nil
		let height = (w != nil && h != nil) ? h : nil
		let media = BeamioChatMedia(mime: mime, widthPx: width, heightPx: height, blob: blob,
		                            blobMissing: (mf["blobMissing"] as? Bool) ?? false)
		let manifest = BeamioChatManifest(kind: kind, mime: mime, sizeBytes: size, name: mf["name"] as? String,
		                                  blobId: blob, mediaKind: nil, isArchive: false, width: width, height: height)
		return BeamioChatMediaParse(kind: kind, media: media, text: text, manifest: manifest, reason: nil, parseError: false)
	}

	/// R6, R7: ChatMessage. A non-null `fileMessage` is checked and classified as media or file. Otherwise the
	/// voice, call, payment or reply key decides, and a bare ChatMessage is text.
	private static func chatMessage(_ obj: [String: Any]) -> BeamioChatMediaParse {
		let text = obj["text"] as? String ?? ""
		if present(obj, "fileMessage") {
			guard let f = obj["fileMessage"] as? [String: Any] else { return failure("file_type") }
			guard (f["type"] as? String) == "file_message_v1" else { return failure("file_type") }
			guard let fragment = f["fragmentHash"] as? String, !fragment.isEmpty else { return failure("missing_fragment") }
			guard let size = integer(f["sizeBytes"]), size >= 0 else { return failure("size") }
			guard let name = f["name"] as? String else { return failure("name") }
			let isArchive = jsonBool(f["isArchive"]) == true
			let mediaKind = f["mediaKind"] as? String
			let kind: BeamioChatKind
			if isArchive {
				kind = .file
			} else if mediaKind == "image" {
				kind = .image
			} else if mediaKind == "video" {
				kind = .video
			} else {
				kind = .file
			}
			let w = positiveInt(f["width"])
			let h = positiveInt(f["height"])
			let width = (w != nil && h != nil) ? w : nil
			let height = (w != nil && h != nil) ? h : nil
			let mime = f["mime"] as? String
			let media = BeamioChatMedia(mime: mime ?? "", widthPx: width, heightPx: height, blob: fragment)
			let manifest = BeamioChatManifest(kind: kind, mime: mime, sizeBytes: size, name: name, blobId: fragment,
			                                  mediaKind: mediaKind, isArchive: isArchive, width: width, height: height)
			return BeamioChatMediaParse(kind: kind, media: media, text: text, manifest: manifest, reason: nil, parseError: false)
		}
		let kind: BeamioChatKind
		if present(obj, "voiceMessage") {
			kind = .voice
		} else if present(obj, "callRecord") {
			kind = .call
		} else if present(obj, "paymentCard") {
			kind = .payment
		} else if present(obj, "reply") {
			kind = .reply
		} else {
			kind = .text
		}
		return BeamioChatMediaParse(kind: kind, media: nil, text: text, manifest: nil, reason: nil, parseError: false)
	}

	/// A member that exists and is not JSON null.
	private static func present(_ obj: [String: Any], _ key: String) -> Bool {
		guard let v = obj[key] else { return false }
		return !(v is NSNull)
	}

	/// A JSON boolean only (0 and 1 do not count).
	private static func jsonBool(_ any: Any?) -> Bool? {
		guard let n = any as? NSNumber, CFGetTypeID(n) == CFBooleanGetTypeID() else { return nil }
		return n.boolValue
	}

	/// A JSON integer only: a number without a fraction, not a boolean.
	private static func integer(_ any: Any?) -> Int64? {
		guard let n = any as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() else { return nil }
		let d = n.doubleValue
		guard d == d.rounded(), abs(d) < 9.0e15 else { return nil }
		return n.int64Value
	}

	private static func positiveInt(_ any: Any?) -> Int? {
		guard let n = integer(any), n > 0 else { return nil }
		return Int(n)
	}
}
