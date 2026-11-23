// swift-tools-version: 5.9
import PackageDescription
import Foundation

// X-19: the native OpenPGP xcframework (gomobile bind of the audited wrapper, gopenpgp v3.5.2). It is NOT in git.
// Delivery is by hash:
// 1. artifactURL and artifactSHA256 are set in the lock: SwiftPM fetches the zip and refuses it on a hash mismatch.
// 2. otherwise a local Vendor/X19.xcframework (installed with scripts/x19/install-x19.sh) is used, development only.
// 3. otherwise the package builds without X19 and the native C3 path reports pending.
// BEAMIO_REQUIRE_X19=1 turns case 3 into a build error. The 1–3 cases above apply to every iOS build.
// These two values are copied from scripts/x19/X19.artifact.lock. They are literals here, not read from the file, because
// SwiftPM caches the manifest evaluation by manifest content: a lock change would otherwise be ignored. The check script
// scripts/x19/verify-x19-artifact-lock.sh fails when they differ from the lock. Change both in the same commit.
let x19Url = "https://github.com/CoNET-project/chat-sdk-ios/releases/download/v0.1.10/X19.xcframework.zip"
let x19Sha = "fc32fdb365287a663c0f1ee4954d637c7cdd05deedd9609d5809966e89249d62"
let x19Vendor = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Vendor/X19.xcframework").path
let x19Required = ProcessInfo.processInfo.environment["BEAMIO_REQUIRE_X19"] == "1"
// X-19 is linked by default on iOS (the condition below). The environment is not read for the link: the locked zip is fetched from the release
// URL above, and an iOS build without the artifact fails in the SDK with an explicit #error (X19Required.swift). A macOS `swift test` does not
// link X-19 (it is iOS only).
let x19LinkRequested = true

// The test hooks (`#if BEAMIO_TEST_HOOKS`) of the SDK and of its tests. They are defined only when BEAMIO_TEST_HOOKS=1 is set
// for the build, so a release or store build never has them. Test command: BEAMIO_TEST_HOOKS=1 xcodebuild -scheme ConetChatSDK... test
// A build without the variable has no hook code; the tests that need a hook are not compiled then.
let testHooksEnabled = ProcessInfo.processInfo.environment["BEAMIO_TEST_HOOKS"] == "1"
let testHookSettings: [SwiftSetting] = testHooksEnabled ? [.define("BEAMIO_TEST_HOOKS")] : []

var sdkDependencies: [Target.Dependency] = [
	.product(name: "libsecp256k1", package: "swift-secp256k1"),
	// Argon2id of the mnemonic cipher v3: the official Argon2 reference implementation, vendored byte for byte (see Sources/CArgon2/PROVENANCE.md).
	"CArgon2",
]
var extraTargets: [Target] = []
if !x19LinkRequested {
	// No X-19 in this build: the SDK compiles its `canImport(X19)` branches as not available (C3 reports pending).
} else if !x19Url.isEmpty, !x19Sha.isEmpty {
	sdkDependencies.append(.target(name: "X19", condition: .when(platforms: [.iOS])))
	extraTargets.append(.binaryTarget(name: "X19", url: x19Url, checksum: x19Sha))
} else if FileManager.default.fileExists(atPath: x19Vendor) {
	sdkDependencies.append(.target(name: "X19", condition: .when(platforms: [.iOS])))
	extraTargets.append(.binaryTarget(name: "X19", path: "Vendor/X19.xcframework"))
}

let package = Package(
	name: "ConetChatSDK",
	platforms: [
		.iOS(.v15),
	],
	products: [
		.library(
			name: "ConetChatSDK",
			targets: ["ConetChatSDK"]
		),
	],
	dependencies: [
		// Native secp256k1 for the voice v3 channel signatures (EIP-191, same bytes as
		// ethers.js). Only the C library product (bitcoin-core libsecp256k1, MIT) is
		// linked; pinned to an exact tag (0.24.0 = commit bcd6dd8e615c).
		.package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", exact: "0.24.0"),
	],
	targets: [
		.target(
			name: "CArgon2",
			path: "Sources/CArgon2",
			exclude: ["LICENSE", "PROVENANCE.md"],
			publicHeadersPath: "include",
			cSettings: [
				// the portable reference path, no threads (p = 1 in use)
				.define("ARGON2_NO_THREADS"),
			]
		),
		.target(
			name: "ConetChatSDK",
			dependencies: sdkDependencies,
			path: "Sources/ConetChatSDK",
			resources: [
				.process("Resources"),
			],
			swiftSettings: testHookSettings,
			linkerSettings: [
				// Local chat library (BeamioConetChatLocalStore): system SQLite, no new package.
				.linkedLibrary("sqlite3"),
			]
		),
		// ChatDaemon protocol v1 conformance against the shared vectors (run on an iOS simulator:
		// the crypto runs in WKWebView). See scripts/sync-protocol-vectors.sh.
		.testTarget(
			name: "ConetChatSDKTests",
			dependencies: ["ConetChatSDK"],
			path: "Tests/ConetChatSDKTests",
			resources: [
				.copy("Resources/chat-daemon-vectors.v1.json"),
				.copy("Resources/mailbox-stream-vectors.v1.json"),
				.copy("Resources/eth-sign-vectors.json"),
				// Registered vector files, checked by sha256 in every run.
				.copy("Resources/native-recovery-vectors.v1.json"),
				.copy("Resources/chat-route-register-vectors.v1.json"),
				.copy("Resources/chat-route-decision-vectors.v1.json"),
				.copy("Resources/pgp-restore-acceptance-vectors.v1.json"),
				.copy("Resources/pgp-backup-compat-vectors.v1.json"),
				.copy("Resources/table-T.v1.json"),
				.copy("Resources/table-T.v2.json"),
				.copy("Resources/passcode-vectors.v1.json"),
				.copy("Resources/passcode-locked-exemption-vectors.v1.json"),
				.copy("Resources/passcode-locked-exemption-vectors.v2.json"),
				.copy("Resources/native-unlock-judgement-vectors.v1.json"),
				.copy("Resources/native-unlock-judgement-vectors.v2.json"),
				.copy("Resources/native-unlock-judgement-vectors.v3.json"),
				.copy("Resources/voice-ephemeral-register-vectors.v1.json"),
				.copy("Resources/voice-ephemeral-register-vectors.v2.3.json"),
				.copy("Resources/voice-ephemeral-register-vectors.v2.4.json"),
				.copy("Resources/keystore-replica-vectors.v2.1.json"),
				.copy("Resources/page-copy-nokey-vectors.v1.json"),
				.copy("Resources/pgp-migration-vectors.v2.json"),
				.copy("Resources/pgp-migration-vectors.v3.json"),
				.copy("Resources/account-select-vectors.v1.json"),
				.copy("Resources/account-select-vectors.v2.json"),
				.copy("Resources/shell-record-read-answer-shape.v1.json"),
				.copy("Resources/shell-record-read-answer-shape.v3.json"),
				.copy("Resources/shell-record-read-not-ready-reasons.v2.json"),
				.copy("Resources/unreadable-cause.v2.json"),
				.copy("Resources/unreadable-cause.v3.json"),
				.copy("Resources/shellrecordwrite-pgp-private-refusal.v1.json"),
				.copy("Resources/batch-rulings-unreadable-nokey-ss32-vr17.v2.json"),
				.copy("Resources/accountCleanupOld.v3.json"),
				.copy("Resources/shell-record-passcode-not-provided.v1.json"),
				.copy("Resources/shell-record-passcode-not-provided.v2.json"),
				.copy("Resources/write-fault-shape-independent.v1.json"),
				.copy("Resources/write-fault-shape-independent.v3.json"),
				.copy("Resources/mnemonic-preread-vectors.v4.json"),
				.copy("Resources/preread-returns-current-record-as-is.v1.json"),
				.copy("Resources/mnemonic-cipher-format.v3.json"),
				.copy("Resources/mnemonic-cipher-format.v4.json"),
				.copy("Resources/enumerated-accounts.v4.json"),
				// r2.5.19: the mnemonic preread vectors (NP-01 to NP-13) and the native-open vectors (42 cases).
				.copy("Resources/mnemonic-preread-vectors.v1.json"),
				.copy("Resources/native-open-vectors.v1.json"),
			],
			swiftSettings: testHookSettings
		),
	] + extraTargets
)
