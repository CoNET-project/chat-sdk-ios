import Foundation

/// The page transport of the record bridge. The page reaches the record through one adapter. This is the
/// reference of its choice, and the vectors TP-01 to TP-10 and SA-01 to SA-04 run against it. The adapter itself is in the PWA.
enum BeamioShellRecordTransport {
	/// The platform the page runs on.
	enum Platform: String {
		case android
		case ios
		case browser
	}

	/// A channel the page can reach the record through.
	enum Channel: String {
		case window
		case chat
	}

	/// The adapter's choice. `via` is `window`, `chat`, `refused` or `none`. `error` is set only for a refusal.
	struct Choice: Equatable {
		let via: String
		let error: String?
	}

	/// The choice in the order of. An injected `window.BeamioShellRecord` is the only channel when it is present; an origin that is not
	/// allowed is refused, with no fallback. Without injection, iOS falls back to the chat-module channel under the same origin check, Android
	/// answers `not_supported`, and a browser has no channel.
	static func choose(platform: Platform, windowInjected: Bool, chatChannel: Bool, originAllowed: Bool) -> Choice {
		if windowInjected {
			return originAllowed ? Choice(via: "window", error: nil) : Choice(via: "refused", error: "origin_refused")
		}
		switch platform {
		case .android:
			return Choice(via: "refused", error: "not_supported")
		case .ios:
			guard chatChannel else { return Choice(via: "none", error: nil) }
			return originAllowed ? Choice(via: "chat", error: nil) : Choice(via: "refused", error: "origin_refused")
		case .browser:
			return Choice(via: "none", error: nil)
		}
	}

	/// Whether the SDK of the platform accepts the channel (table). Android accepts the window only; iOS accepts both.
	static func sdkAccepts(platform: Platform, channel: Channel) -> Bool {
		switch (platform, channel) {
		case (.android, .window), (.ios, .window), (.ios, .chat):
			return true
		case (.android, .chat), (.browser, _):
			return false
		}
	}
}
