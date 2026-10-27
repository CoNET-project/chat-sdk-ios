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
	]
)
