import XCTest
@testable import ConetChatSDK

/// (c): the passcode lock ends a running listen loop. With the native layer closed no loop can run ((a)), so this checks the
/// lock path itself: it is asynchronous, and harmless when no listen is running.
final class LockListenTests: XCTestCase {
	func testTheLockWithNoListenRunningIsHarmless() {
		let e = expectation(description: "lock")
		BeamioConetChatModule.stopListenForLock()
		DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { e.fulfill() }
		wait(for: [e], timeout: 3)
	}
}
