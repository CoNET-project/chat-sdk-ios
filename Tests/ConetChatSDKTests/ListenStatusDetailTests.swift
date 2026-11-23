import Foundation
import XCTest
@testable import ConetChatSDK

/// The detail of a `reconnecting` status is one of the fixed codes this file throws, or nil. Free text from a lower
/// layer is never sent: the shell's whitelist maps an unknown value to `<other>`, and free text must not reach the log at all.
final class ListenStatusDetailTests: XCTestCase {
	private func listenError(_ code: Int, _ description: String) -> NSError {
		NSError(domain: "BeamioConetChatListen", code: code, userInfo: [NSLocalizedDescriptionKey: description])
	}

	func testTheFixedCodesPassThrough() {
		for code in ["missing_own_route", "stream_key", "bad_command", "no_entry_c", "encrypt_route_command_failed", "wrap_timeout", "all_entries_failed"] {
			XCTAssertEqual(BeamioConetChatListenSession.statusDetail(for: listenError(-1, code)), code)
		}
	}

	func testFreeTextIsNotSent() {
		XCTAssertNil(BeamioConetChatListenSession.statusDetail(for: listenError(-4, "The Internet connection appears to be offline.")))
		let lower = NSError(domain: NSURLErrorDomain, code: -1009, userInfo: [NSLocalizedDescriptionKey: "offline"])
		XCTAssertNil(BeamioConetChatListenSession.statusDetail(for: lower))
	}

	func testAnUnknownCodeOfOurDomainIsNotSent() {
		XCTAssertNil(BeamioConetChatListenSession.statusDetail(for: listenError(-9, "some_new_text")))
	}
}
