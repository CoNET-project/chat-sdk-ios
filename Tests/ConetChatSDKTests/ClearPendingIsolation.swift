#if BEAMIO_TEST_HOOKS
import Foundation
@testable import ConetChatSDK

/// Gives a test its own `clear_pending` marker (`BeamioNativeClearPending.defaults`). The marker is kept in the standard defaults otherwise, so an
/// interrupted clear left by one test process would be redone at the first command of the next one. Synthetic state only.
enum ClearPendingIsolation {
	private static var saved: BeamioDefaultsStoring?

	static func begin() {
		saved = BeamioNativeClearPending.defaults
		BeamioNativeClearPending.defaults = BeamioMemoryDefaults()   // in memory: no suite, no domain, no preferences file
	}

	static func end() {
		if let saved { BeamioNativeClearPending.defaults = saved }
		saved = nil
	}
}
#endif
