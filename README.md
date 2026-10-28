# ConetChatSDK (iOS)

Native CoNET Chat module for iOS apps. Implements the same WorkerCommand / WorkerOutbound surface as [`@conet.project/chat-sdk`](https://github.com/CoNET-project/chat-sdk) (TypeScript), without spawning a Web Worker inside the shell.

**Repository:** https://github.com/CoNET-project/chat-sdk-ios

## What this package owns

| Capability | Native (`ConetChatSDK`) | Host / PWA |
|---|---|---|
| OpenPGP encrypt / decrypt / verify | Yes (`WKWebView` + bundled `openpgp` / `ethers`) | — |
| Mailbox listen SSE (`mailbox_listen`, `listenKind: chat`) | Yes (B route PGP; HTTP via entry **C ≠ B**) | — |
| Send / group / dual delivery receipts | Yes | — |
| Presence / native-wake queries | Yes | — |
| Encrypted IPFS history + `ChatIndexRegistry` | Yes | — |
| **EOA EIP-191 / EIP-712 signing** | Callback only | PWA `chatModuleSignRequest` → `chatModuleSignResponse` |
| Voice media SSE | Delegated | Host voice signaling (no dual SSE) |

Hybrid signing (model **1B**): the SDK never holds the EOA private key. It emits `chatModuleSignRequest`; the host PWA signs and returns via `BeamioConetChatSignBroker.fulfill`.

## Requirements

- iOS 15+
- Swift 5.9+ / Xcode 15+
- Host WebView bridge that can forward `chatModuleCommand` / `chatModuleSignResponse` and emit `chatModuleEvent` / `chatModuleSignRequest` to the PWA (see Beamio Consumer shell)

## Install (Swift Package Manager)

### Xcode

1. **File → Add Package Dependencies…**
2. URL: `https://github.com/CoNET-project/chat-sdk-ios.git`
3. Dependency rule: **Up to Next Major** from `0.1.0` (or branch `main` until the first tag).
4. Add product **ConetChatSDK** to your app target.

### `Package.swift`

```swift
dependencies: [
	.package(url: "https://github.com/CoNET-project/chat-sdk-ios.git", from: "0.1.0"),
],
targets: [
	.target(
		name: "YourApp",
		dependencies: [
			.product(name: "ConetChatSDK", package: "chat-sdk-ios"),
		]
	),
]
```

### Local path (monorepo / development)

```swift
.package(path: "../chat-sdk-ios"),
```

## Quick start (host app)

```swift
import ConetChatSDK

// Wire PWA ↔ native chat commands (CashTreesIOS / evaluateJavaScript).
BeamioConetChatModule.handleCommand(commandBody) { payload in
	// payload.action is "chatModuleEvent" or "chatModuleSignRequest"
	emitToPwa(payload)
}

// When PWA answers a sign request:
BeamioConetChatSignBroker.fulfill(fromWeb: signResponseBody)

// Optional: after chain getAllNodes, refresh SI IPs (do not trust Web roster alone).
BeamioChatPgpKeychain.onRosterUpsertFromWeb = {
	// e.g. BeamioGuardianRoster.kick() in the host app
}
_ = BeamioChatPgpKeychain.storeChainRoster(nodes: nodes, mailboxIp: mailboxIp)
```

Crypto scripts ship inside the SPM target (`Resources/ChatCrypto`). `BeamioOpenPgpHost` loads them from `Bundle.module`, with `Bundle.main` as fallback if you also copy the JS into the app bundle.

## Public API surface

| Type | Role |
|---|---|
| `BeamioConetChatModule` | `handleCommand` — init / send / listen / history / mailbox / pause / destroy |
| `BeamioConetChatSignBroker` | `requestEip191` / `requestEip712` (internal) + `fulfill(fromWeb:)` |
| `BeamioOpenPgpHost` | Shared OpenPGP host (`shared.ensureReady`) |
| `BeamioSiCipherPost` | Plain HTTP/1.1 `/post` and SSE to SI nodes by IP over TCP port 80 (Network.framework, not URLSession: ATS rejects `http://IP` with `-1022`). `getRandomNode` returns only IP-reachable entries, weighted by `scoreEntry`; unreachable IPs are withheld for 120 s |
| `BeamioChatPgpKeychain` | Persist user PGP + route key + SI node roster |
| `BeamioConetChatListenSession` | Mailbox SSE session (used by the module) |
| `BeamioConetChatHistoryStore` | Fragment encrypt + registry pointer updates |

Type names keep the `Beamio*` prefix so existing Consumer shell call sites can switch to `import ConetChatSDK` with minimal renames.

## Protocol notes

- **Send:** encrypt to recipient **user PGP** → POST via healthy entry **A ≠ B**.
- **Listen:** encrypt `mailbox_listen` to mailbox **B route PGP** → HTTP/SSE via entry **C ≠ B**.
- **History:** AES-GCM fragments on IPFS; head pointer on CoNET `ChatIndexRegistry` `0x1511Caa71081C84d8a591490D1b83879088EED72` (chainId `224422`). Keys are derived from PWA EIP-191 signatures through the sign broker.
- Do **not** put signing material, mnemonics, or full PGP armor in logs.

Aligned with Beamio / CoNET rules: `beamio-conet-chat-protocol`, `conet-p2p-mailbox-routing-protocol`, `beamio-chat-history-decentralized-protocol`, and the TypeScript `@conet.project/chat-sdk`.

## Versioning

Semantic versioning. Tag releases as `v0.1.0`, `v0.2.0`, …. Until the first release tag, resolve the package from branch `main`.

## License

MIT — see [LICENSE](./LICENSE).
