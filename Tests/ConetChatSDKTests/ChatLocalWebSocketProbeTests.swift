import Darwin
import Foundation
import WebKit
import XCTest
@testable import ConetChatSDK

/// T-9 negative probe (spec 13, AGENTS.md). A real WKWebView with the SDK's guard installed, and the vendored ethers
/// bundle loaded. The probe connects only to a listener on 127.0.0.1 that this test owns. Passing means each attempt
/// was refused before a connection was made, and the listener accepted nothing.
final class ChatLocalWebSocketProbeTests: XCTestCase {
	private final class NavDelegate: NSObject, WKNavigationDelegate {
		var finished = false
		var failure: Error?
		func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { finished = true }
		func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { failure = error }
		func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { failure = error }
	}

	/// Listener on 127.0.0.1 with an ephemeral port, non-blocking accept.
	private func openListener() throws -> (fd: Int32, port: UInt16) {
		let fd = socket(AF_INET, SOCK_STREAM, 0)
		guard fd >= 0 else { throw XCTSkip("socket() failed") }
		var addr = sockaddr_in()
		addr.sin_family = sa_family_t(AF_INET)
		addr.sin_port = 0
		addr.sin_addr.s_addr = inet_addr("127.0.0.1")
		let bound = withUnsafePointer(to: &addr) { p -> Int32 in
			p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
		}
		guard bound == 0, listen(fd, 8) == 0 else { close(fd); throw XCTSkip("bind/listen failed") }
		var out = sockaddr_in()
		var len = socklen_t(MemoryLayout<sockaddr_in>.size)
		_ = withUnsafeMutablePointer(to: &out) { p -> Int32 in
			p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
		}
		_ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
		return (fd, UInt16(bigEndian: out.sin_port))
	}

	private func waitUntil(timeout: TimeInterval, _ cond: () -> Bool) {
		let end = Date().addingTimeInterval(timeout)
		while !cond() && Date() < end {
			RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.05))
		}
	}

	/// The vendored ethers bundle is a resource of the SDK module. It is read from the module's bundle inside the test host,
	/// not from a path on the Mac: the iOS Simulator test host cannot read the Mac's source tree (NSCocoaErrorDomain 257).
	private func ethersBundle() throws -> String {
		// `Bundle.module` here would be this test target's bundle. The SDK's resources are the SwiftPM bundle that sits next
		// to the test bundle, so it is located from the test class's own bundle.
		let testBundle = Bundle(for: ChatLocalWebSocketProbeTests.self)
		let resourceBundle = testBundle.url(forResource: "ConetChatSDK_ConetChatSDK", withExtension: "bundle").flatMap { Bundle(url: $0) }
		let candidates = [
			resourceBundle?.url(forResource: "ethers.umd.min", withExtension: "js", subdirectory: "ChatCrypto"),
			resourceBundle?.url(forResource: "ethers.umd.min", withExtension: "js"),
		]
		guard let url = candidates.compactMap({ $0 }).first else {
			throw NSError(domain: "ChatLocalWebSocketProbeTests", code: 1,
			              userInfo: [NSLocalizedDescriptionKey: "ethers.umd.min.js is not in the SDK resource bundle"])
		}
		return try String(contentsOf: url, encoding: .utf8)
	}

	func testWebSocketAttemptsAreRefusedBeforeConnecting() throws {
		let listener = try openListener()
		defer { close(listener.fd) }
		let handler = BeamioWebSocketGuardHandler()
		let config = WKWebViewConfiguration()
		BeamioWebSocketGuard.install(on: config, handler: handler)
		let web = WKWebView(frame: CGRect(x: 0, y: 0, width: 400, height: 300), configuration: config)
		let nav = NavDelegate()
		web.navigationDelegate = nav
		let bundle = try ethersBundle()
		let page = """
		<!doctype html><html><head><meta charset="utf-8">
		<script>window.__early = typeof WebSocket; window.__earlyGuard = window.__beamioWsGuard === true;</script>
		<script>\(bundle)</script>
		</head><body></body></html>
		"""
		web.loadHTMLString(page, baseURL: nil)
		waitUntil(timeout: 20) { nav.finished || nav.failure != nil }
		XCTAssertNil(nav.failure, "page must load")
		XCTAssertTrue(nav.finished)

		let probe = """
		(function () {
		  var url = 'ws://127.0.0.1:\(listener.port)';
		  var out = { early: window.__early, earlyGuard: window.__earlyGuard, guard: window.__beamioWsGuard === true };
		  try { new WebSocket(url); out.direct = 'connected'; } catch (e) { out.direct = 'refused'; }
		  try {
		    if (typeof ethers !== 'undefined' && ethers.WebSocketProvider) {
		      new ethers.WebSocketProvider(url); out.ethers = 'constructed';
		    } else { out.ethers = 'absent'; }
		  } catch (e) { out.ethers = 'refused'; }
		  return JSON.stringify(out);
		})();
		"""
		var result: String?
		var evalError: Error?
		var done = false
		web.evaluateJavaScript(probe) { value, error in
			result = value as? String
			evalError = error
			done = true
		}
		waitUntil(timeout: 20) { done }
		XCTAssertNil(evalError)
		// Give a late connection time to arrive (the unguarded control needs a few seconds).
		let settle = Date().addingTimeInterval(8)
		while Date() < settle { RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.1)) }

		let data = Data((result ?? "{}").utf8)
		let out = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
		XCTAssertEqual(out["early"] as? String, "function", "the guard replaced WebSocket before page scripts ran")
		XCTAssertEqual(out["earlyGuard"] as? Bool, true)
		XCTAssertEqual(out["guard"] as? Bool, true)
		XCTAssertEqual(out["direct"] as? String, "refused", "new WebSocket is refused before a connection")
		XCTAssertNotEqual(out["ethers"] as? String, "connected")
		// Nothing reached the listener: no connection was made.
		let accepted = accept(listener.fd, nil, nil)
		XCTAssertEqual(accepted, -1, "the probe listener must not receive a connection")
		XCTAssertGreaterThanOrEqual(handler.blockedCount, 1, "each refused attempt is logged by the handler")
		print("T9_PROBE result=\(result ?? "nil") blocked=\(handler.blockedCount) accepted=\(accepted)")
	}

	/// Control for the probe: without the guard, the same kind of attempt does reach the listener. This shows the
	/// listener would detect a real connection, so the refusal above is meaningful.
	func testControlWithoutGuardReachesTheListener() throws {
		let listener = try openListener()
		defer { close(listener.fd) }
		let web = WKWebView(frame: CGRect(x: 0, y: 0, width: 400, height: 300), configuration: WKWebViewConfiguration())
		let nav = NavDelegate()
		web.navigationDelegate = nav
		web.loadHTMLString("<!doctype html><html><body></body></html>", baseURL: nil)
		waitUntil(timeout: 20) { nav.finished || nav.failure != nil }
		XCTAssertTrue(nav.finished)
		var done = false
		var value: Any?
		web.evaluateJavaScript("(function(){ try { new WebSocket('ws://127.0.0.1:\(listener.port)'); return 'connected'; } catch (e) { return 'refused:' + e.message; } })();") { v, _ in
			value = v
			done = true
		}
		waitUntil(timeout: 20) { done }
		var accepted: Int32 = -1
		let end = Date().addingTimeInterval(8)
		while accepted < 0 && Date() < end {
			RunLoop.main.run(mode: .default, before: Date().addingTimeInterval(0.1))
			accepted = accept(listener.fd, nil, nil)
		}
		print("T9_CONTROL script=\(String(describing: value)) accepted=\(accepted)")
		XCTAssertGreaterThanOrEqual(accepted, 0, "control: without the guard the listener receives the connection")
		if accepted >= 0 { close(accepted) }
	}
}
