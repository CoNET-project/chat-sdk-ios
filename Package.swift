// swift-tools-version: 5.9
import PackageDescription

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
			name: "ConetChatSDK",
			dependencies: [
				.product(name: "libsecp256k1", package: "swift-secp256k1"),
			],
			path: "Sources/ConetChatSDK",
			resources: [
				.process("Resources"),
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
				.copy("Resources/eth-sign-vectors.json"),
			]
		),
	]
)
