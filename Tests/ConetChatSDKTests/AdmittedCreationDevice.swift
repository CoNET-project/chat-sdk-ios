#if BEAMIO_TEST_HOOKS
import Foundation
@testable import ConetChatSDK

/// PY.18 (r3rz): a creation page opens only when the creation admission holds. The tests that open it run with a device state that admits it:
/// the legacy store confirmed empty, no latched write failure. The pointer, the native key and the page copies are cleared by each test's own isolation.
enum AdmittedCreationDevice {
	private final class Device: BeamioShellRecord.DeviceStateStore {
		var state = BeamioShellRecord.DeviceState(accountEstablished: false, legacyUnreadable: false, legacyConfirmedAbsent: true, legacyFound: false)
		func load() -> BeamioShellRecord.DeviceState { state }
		@discardableResult func update(_ change: (inout BeamioShellRecord.DeviceState) -> Void) -> Bool { change(&state); return true }
	}

	private static var savedKeyStore: BeamioChatWalletKeyStoring?

	/// Also an empty native key store: the keychain of a device (or a simulator) keeps keys of earlier runs, which would refuse the admission.
	static func install() {
		BeamioShellRecord.testDeviceOverride = Device()
		BeamioShellRecord.setLegacyReportWriteFailed(false)
		savedKeyStore = BeamioNativeWallet.keyStore
		BeamioNativeWallet.keyStore = MemoryNativeKeyStore()
	}

	static func remove() {
		BeamioShellRecord.testDeviceOverride = nil
		BeamioNativeWallet.keyStore = savedKeyStore ?? BeamioPasscodeWalletStore.standard
		savedKeyStore = nil
	}
}
#endif
