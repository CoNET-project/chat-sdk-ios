import XCTest
@testable import ConetChatSDK

/// Test helper: the G2 gate of one account for one test. The wallet functions answer their values only in G2 for the account, so a
/// test that checks a value (a signature, a key-derived password, a master) enters the gate first. The returned closure clears the gate, the signer and
/// the record pointer again. Synthetic data only.
enum WalletG2Gate {
	static func enter(account: String) -> () -> Void {
		BeamioConetChatSignBroker.setSignerEoa(account)
		BeamioConetChatModule.setNativeGateForTests(account: account, sessionReady: true)
		return {
			BeamioConetChatModule.setNativeGateForTests(account: nil, sessionReady: false)
			BeamioConetChatSignBroker.clearSigner()
		}
	}
}
