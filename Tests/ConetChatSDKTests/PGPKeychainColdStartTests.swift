#if BEAMIO_TEST_HOOKS
#if os(iOS)
import XCTest
@testable import ConetChatSDK

/// App-host Keychain and cold-start check. Runs only in an integration build signed with a
/// keychain access group (a provisioned host). The phases run as separate test processes, so `read` is a full process
/// restart after `write`:
/// BEAMIO_KEYCHAIN_PHASE=write xcodebuild test... -only-testing:ConetChatSDKTests/PGPKeychainColdStartTests
/// BEAMIO_KEYCHAIN_PHASE=read (new process, same device and signing)
/// BEAMIO_KEYCHAIN_PHASE=cleanup (removes the synthetic records)
/// Synthetic values only. Skipped without the phase variable. The in-memory seam is not used here: the real Keychain is.
final class PGPKeychainColdStartTests: XCTestCase {
	private let alice = "0xA11CE00000000000000000000000000000000001"
	private let bob = "0xB0B0000000000000000000000000000000000002"
	private let privateA = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-cold-alice\n-----END PGP PRIVATE KEY BLOCK-----"
	private let privateB = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsynthetic-cold-bob\n-----END PGP PRIVATE KEY BLOCK-----"
	private let publicA = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-cold-alice\n-----END PGP PUBLIC KEY BLOCK-----"
	private let publicB = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nsynthetic-cold-bob\n-----END PGP PUBLIC KEY BLOCK-----"
	private let walletA = Data(repeating: 0xA1, count: 32)
	private let walletB = Data(repeating: 0xB2, count: 32)

	override func setUpWithError() throws {
		try XCTSkipIf(ProcessInfo.processInfo.environment["BEAMIO_KEYCHAIN_PHASE"] == nil,
		              "set BEAMIO_KEYCHAIN_PHASE to write, read or cleanup in a signed integration build")
		BeamioChatPgpKeychain.memory = nil
	}

	func testPhase() throws {
		switch ProcessInfo.processInfo.environment["BEAMIO_KEYCHAIN_PHASE"] {
		case "write": write()
		case "read": read()
		case "cleanup": cleanup()
		default: throw XCTSkip("BEAMIO_KEYCHAIN_PHASE must be write, read or cleanup")
		}
	}

	private func record(_ privateArmor: String, _ publicArmor: String, keyId: String, eoa: String) -> BeamioChatPgpKeychain.Secrets {
		BeamioChatPgpKeychain.Secrets(
			privateKeyArmor: privateArmor, publicKeyArmor: publicArmor, pgpKeyId: keyId,
			routePublicKeyArmor: "", entryDomains: [], siNodes: [], mailboxIp: "", eoa: eoa)
	}

	/// Two accounts written one after another; each reads back in this process.
	private func write() {
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateA, publicA, keyId: "cold-keyA", eoa: alice)))
		XCTAssertTrue(BeamioChatPgpKeychain.save(record(privateB, publicB, keyId: "cold-keyB", eoa: bob)))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: alice)?.privateKeyArmor, privateA)
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: bob)?.privateKeyArmor, privateB)
		XCTAssertTrue(BeamioChatWalletKeychainStore.standard.write(eoa: alice, key: walletA))
		XCTAssertTrue(BeamioChatWalletKeychainStore.standard.write(eoa: bob, key: walletB))
	}

	/// After a full process restart: both records and both wallet keys are still there, each its own.
	private func read() {
		let a = BeamioChatPgpKeychain.load(eoa: alice)
		let b = BeamioChatPgpKeychain.load(eoa: bob)
		XCTAssertEqual(a?.privateKeyArmor, privateA, "alice's record survives a restart and is not overwritten")
		XCTAssertEqual(a?.publicKeyArmor, publicA)
		XCTAssertEqual(a?.pgpKeyId, "cold-keyA")
		XCTAssertEqual(b?.privateKeyArmor, privateB, "bob's record survives a restart and is not overwritten")
		XCTAssertEqual(b?.pgpKeyId, "cold-keyB")
		XCTAssertEqual(BeamioChatWalletKeychainStore.standard.read(eoa: alice), walletA)
		XCTAssertEqual(BeamioChatWalletKeychainStore.standard.read(eoa: bob), walletB)
	}

	/// Deleting one account removes only that account's records; the other account stays readable.
	private func cleanup() {
		BeamioChatPgpKeychain.clear(eoa: alice)
		BeamioChatWalletKeychainStore.standard.delete(eoa: alice)
		XCTAssertNil(BeamioChatPgpKeychain.load(eoa: alice))
		XCTAssertNil(BeamioChatWalletKeychainStore.standard.read(eoa: alice))
		XCTAssertEqual(BeamioChatPgpKeychain.load(eoa: bob)?.privateKeyArmor, privateB)
		XCTAssertEqual(BeamioChatWalletKeychainStore.standard.read(eoa: bob), walletB)
		BeamioChatPgpKeychain.clear(eoa: bob)
		BeamioChatWalletKeychainStore.standard.delete(eoa: bob)
	}
}
#endif
#endif
