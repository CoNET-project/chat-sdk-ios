import Foundation
import WebKit

/// Runtime guard against WebSocket (AGENTS.md; spec 13, T-9). The vendored ethers bundle contains WebSocket code,
/// and that code is not removed. Instead, every WKWebView the SDK creates replaces the global WebSocket with a
/// constructor that throws before any connection is attempted. Each attempt is counted and logged without the URL.
public enum BeamioWebSocketGuard {
	public static let handlerName = "beamioWsGuard"

	/// Injected at document start, before any page or bundle script runs.
	public static let source = #"""
	(function () {
	  'use strict';
	  var g = typeof globalThis !== 'undefined' ? globalThis : (typeof self !== 'undefined' ? self : this);
	  function report() {
	    try {
	      var h = g.webkit && g.webkit.messageHandlers && g.webkit.messageHandlers.beamioWsGuard;
	      if (h) { h.postMessage('blocked'); }
	    } catch (e) {}
	  }
	  function BeamioBlockedWebSocket() {
	    report();
	    throw new Error('WebSocket is disabled by policy');
	  }
	  BeamioBlockedWebSocket.CONNECTING = 0;
	  BeamioBlockedWebSocket.OPEN = 1;
	  BeamioBlockedWebSocket.CLOSING = 2;
	  BeamioBlockedWebSocket.CLOSED = 3;
	  try {
	    Object.defineProperty(g, 'WebSocket', { value: BeamioBlockedWebSocket, writable: false, configurable: false, enumerable: false });
	  } catch (e) {
	    g.WebSocket = BeamioBlockedWebSocket;
	  }
	  try {
	    Object.defineProperty(g, '__beamioWsGuard', { value: true, writable: false, configurable: false, enumerable: false });
	  } catch (e) {}
	})();
	"""#

	/// Adds the guard to a configuration: the user script at document start and the message handler.
	public static func install(on configuration: WKWebViewConfiguration, handler: WKScriptMessageHandler) {
		configuration.userContentController.addUserScript(
			WKUserScript(source: source, injectionTime: .atDocumentStart, forMainFrameOnly: false)
		)
		configuration.userContentController.add(handler, name: handlerName)
	}
}

/// Counts blocked WebSocket constructions. Logs a fixed line, never the URL or any payload.
public final class BeamioWebSocketGuardHandler: NSObject, WKScriptMessageHandler {
	public static let shared = BeamioWebSocketGuardHandler()

	private let lock = NSLock()
	private var count = 0

	public var blockedCount: Int {
		lock.lock()
		defer { lock.unlock() }
		return count
	}

	public func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
		guard message.name == BeamioWebSocketGuard.handlerName else { return }
		lock.lock()
		count += 1
		let n = count
		lock.unlock()
		NSLog("[BeamioWsGuard] blocked WebSocket construction count=%d", n)
	}
}
