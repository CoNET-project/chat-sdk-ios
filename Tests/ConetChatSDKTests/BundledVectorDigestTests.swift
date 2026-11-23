import XCTest
@testable import ConetChatSDK

/// The five bundled vector files are checked against their registered sha256 in every run, in every build configuration.
/// This test does not depend on the environment, on X-19, or on the test hooks, and it never skips.
final class BundledVectorDigestTests: XCTestCase {
	func testEveryBundledVectorFileIsTheRegisteredOne() throws {
		for resource in [
			"native-recovery-vectors.v1",
			"chat-route-register-vectors.v1",
			"chat-route-decision-vectors.v1",
			"pgp-restore-acceptance-vectors.v1",
			"pgp-backup-compat-vectors.v1",
			"table-T.v1",
			"table-T.v2",
			"passcode-vectors.v1",
			"passcode-locked-exemption-vectors.v1",
			"passcode-locked-exemption-vectors.v2",
			"shell-record-passcode-not-provided.v1",
			"mnemonic-preread-vectors.v4",
			"preread-returns-current-record-as-is.v1",
			"mnemonic-cipher-format.v3",
			"mnemonic-cipher-format.v4",
			"native-unlock-judgement-vectors.v3",
			"voice-ephemeral-register-vectors.v2.4",
			"voice-ephemeral-register-vectors.v1",
			"voice-ephemeral-register-vectors.v2.3",
			"keystore-replica-vectors.v2.1",
			"native-unlock-judgement-vectors.v1",
			"native-unlock-judgement-vectors.v2",
		] {
			_ = try BundledVectorFile.data(resource: resource)
		}
	}
}
