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
	targets: [
		.target(
			name: "ConetChatSDK",
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
			]
		),
	]
)
