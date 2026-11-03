# ConetChatSDK (iOS)

Native CoNET Chat module for iOS apps. Implements the same WorkerCommand / WorkerOutbound surface as [`@conet.project/chat-sdk`](https://github.com/CoNET-project/chat-sdk) (TypeScript), without spawning a Web Worker inside the shell.

**Repository:** https://github.com/CoNET-project/chat-sdk-ios

## What this package owns

| Capability | Native (`ConetChatSDK`) | Host / PWA |
|---|---|---|
| OpenPGP encrypt / decrypt / verify | Yes (`WKWebView` + bundled `openpgp` / `ethers`) | — |
| Mailbox listen SSE (`mailbox_listen`) | Yes, daemon-owned (B route PGP; HTTP via entry **C ≠ B**; sealed stream since 0.1.8) | — |
| Send / group / dual delivery receipts | Yes (wrapped to the recipient's mailbox since 0.1.8) | — |
| Presence / native-wake queries | Yes | — |
| Encrypted IPFS history + `ChatIndexRegistry` | Yes | — |
| Wallet + PGP key custody | Yes since 0.1.7 (`provisionIdentity`; Keychain `AfterFirstUnlockThisDeviceOnly`, not synced; wiped by `clearIdentity`) | Hands the keys over once |
| **EOA EIP-191 / EIP-712 signing** | Local since 0.1.7 when a key is provisioned (`BeamioConetChatSignBroker.hasLocalSigner()`); otherwise callback | PWA `chatModuleSignRequest` → `chatModuleSignResponse` (fallback only) |
| Voice media SSE | Delegated | Host voice signaling (no dual SSE) |

**Key custody (0.1.7).** The page provisions the wallet private key and the user PGP keys once. The module keeps them in the Keychain, never logs them, signs `mailbox_listen`, ACKs and sends itself, and keeps the mailbox SSE as a daemon. The host's call layer drives wake / release: the SSE runs only in the foreground, while a call push is ringing, and during a call, and it stays open for the whole call. Nothing runs after the app exits. Messages received with no page loaded are kept as PGP ciphertext until the page takes them, then ACKed. Since 0.1.8 the shell reports the app state (`appWillEnterForeground` / `appDidEnterBackground`): the listen pauses about 10 s after the app goes to the background unless a call needs it, and reconnects at once in the foreground. The older hybrid model (**1B**, page signs every request through `chatModuleSignRequest`) remains only as a fallback when no key has been provisioned.

## Requirements

- iOS 15+
- Swift 5.9+ / Xcode 15+
- Host WebView bridge that can forward `chatModuleCommand` / `chatModuleSignResponse` and emit `chatModuleEvent` / `chatModuleSignRequest` to the PWA (see Beamio Consumer shell)

## Install (Swift Package Manager)

### Xcode

1. **File → Add Package Dependencies…**
2. URL: `https://github.com/CoNET-project/chat-sdk-ios.git`
3. Dependency rule: **Up to Next Major** from `0.1.8`.
4. Add product **ConetChatSDK** to your app target.

### `Package.swift`

```swift
dependencies: [
	.package(url: "https://github.com/CoNET-project/chat-sdk-ios.git", from: "0.1.8"),
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
| `BeamioNativeEthSigner` | Native EIP-191 `personal_sign` (same bytes as ethers.js), used by the shell for voice channel v3 signatures |

Type names keep the `Beamio*` prefix so existing Consumer shell call sites can switch to `import ConetChatSDK` with minimal renames.

## Protocol notes

- **Send:** encrypt to recipient **user PGP** → POST via one random entry, excluding the recipient's and the own mailbox; next entry only after a clear failure. Since 0.1.8 every send is wrapped as mailbox work to the recipient's mailbox route key (no route key → `recipient_mailbox_unknown`), with an 8 s per-entry timeout.
- **Listen:** encrypt `mailbox_listen` to mailbox **B route PGP** → HTTP/SSE via entry **C ≠ B**. Since 0.1.8 the command carries a fresh 32-byte `streamKey` (nodes refuse a listen without it) and every SSE frame is `base64(iv ‖ AES-256-GCM ciphertext ‖ tag)` that the session opens before parsing.
- **Transport:** plain HTTP/1.1 to entry IPs on port 80 without an extra entry layer (known limitation; a network observer sees the outer key ID, sizes and timing).
- **Listen health (since 0.1.8):** the session reports `listening` only after the mailbox's sealed handshake frame (`kind: "mailbox"`); idle timeout 200 s (above the mailbox's 180 s keepalive bound); after a stream that heard from the mailbox drops, a new command with a new `instanceId` and `streamKey` is signed instead of reusing the old one; `BeamioOpenPgpHost` rebuilds its WebView when the system terminates the content process and retries the call once; an inbound decrypt failure reopens the listen (at most every 30 s); `resumeListen` reopens it when the last sealed frame is more than 45 s old.
- **Background pause and offline backoff (since 0.1.8):** in the background the listen pauses after a 10 s grace (not while a call rings, dials or is up), and nothing retries while paused. A failed listen retries after 2 s, 4 s, 8 s, 16 s, then every 30 s (±20 % jitter) instead of a fixed wait; a dropped listen that worked reopens after 0.5 s. Coming to the foreground or a network coming back (`NWPathMonitor`) retries at once.
- **Own route vs chain (since 0.1.8):** once a listen starts, the module reads its own AddressPGP record (`searchKey`) and compares the route key ID with the one it listens on. A failed read is retried (5 s up to 300 s) and never counts as "no record"; a different chain route wins and the listen reopens on it; no chain route keeps the current listen (registering is the page's job). Logs carry only route key IDs.
- **Entry pool and node table (since 0.1.8):** `BeamioEntryPool` keeps about 8 probed healthy entries warm (refreshed every 15 s) while the daemon is active (probes carry no wallet or signature); `BeamioSiCipherPost.getRandomNode` takes from it first, applying the caller's exclusions, and probes on the spot only when it is empty. The usable IPs are cached on disk (public node data only) for a push-woken process. `BeamioGuardianNodeWatch` follows the `GuardianNodesInfoV6` storage root and pulls the full node table only when it changes.
- **Calls:** call control (cancel, decline, timeout, hang-up) arrives as ordinary Chat messages through the mailbox. Since 0.1.7 the module recognises the caller's cancel itself, so the call layer can stop ringing with no page loaded; the full call-signal classifier comes with protocol v1 in 0.1.8 (below). Since 0.1.8 the wake receipt `voice_call_ringing_v1` is classified as a call signal. Voice commands it forwards are unsigned and carry no wallet; voice media, including voice channel v3, is delegated to the host. Since 0.1.8 `BeamioNativeEthSigner` (EIP-191 over libsecp256k1 from swift-secp256k1, pinned to 0.24.0) gives the shell the v3 channel signatures without a WebView round trip.
- **Presence:** `wallet_online_query` / `wallet_native_wake_query` carry and are signed by the querier's wallet (known limitation, to be solved with `web3://`).
- **History:** AES-GCM fragments on IPFS; head pointer on CoNET `ChatIndexRegistry` `0x1511Caa71081C84d8a591490D1b83879088EED72` (chainId `224422`). Keys are derived from an EIP-191 signature (local when a key is provisioned, otherwise through the sign broker).
  Wire-compatible with the TypeScript worker and `chat-sdk-android` indexes. `init` answers `{ historyApi: 2 }` before the history key is derived (the module logs `[history] ready` when it is); `historyLoad` streams `event:historyBuffer` batches (tail first), `historyRead` answers an array, `historyAppend` is idempotent per `sendId` and syncs the chain head first.
- Do **not** put signing material, mnemonics, or full PGP armor in logs.

Aligned with Beamio / CoNET rules: `beamio-conet-chat-protocol`, `conet-p2p-mailbox-routing-protocol`, `beamio-chat-history-decentralized-protocol`, and the TypeScript `@conet.project/chat-sdk`.

## ChatDaemon protocol v1

The spec lives in `@conet.project/chat-sdk` (`src/protocol.ts`, `spec/`). This
package answers `hello` with `BeamioConetChatProtocol.helloResult()` (protocol 1,
capabilities `identity.provision`, `signing.local`, `lifecycle.daemon`,
`inbound.deferAck`, `history.v2`, `call.control`, `voice.delegated`,
`presence.query`, `mailbox.command`, `send.mailboxWrap`) and answers unknown commands that carry a
positive `reqId` with `unknown_command`. Wire builders: `BeamioConetChatWire`;
call signals: `BeamioConetChatCallSignal.classify`.

Conformance tests read the shared vectors (`Tests/ConetChatSDKTests/Resources/chat-daemon-vectors.v1.json`,
a copy kept in sync with `scripts/sync-protocol-vectors.sh`; never edit it here):

```bash
swift test                     # macOS host (WKWebView runs the bundled openpgp / ethers)
xcodebuild test -scheme ConetChatSDK -destination 'platform=iOS Simulator,name=iPhone 17'
```

## Versioning

Semantic versioning. Releases are tagged `v0.1.x` (latest `v0.1.8`); `BeamioConetChatProtocol.sdkVersion` carries the same version.

## License

MIT — see [LICENSE](./LICENSE).

## Developer knowledge base

Lessons learned across the TypeScript, iOS and Android SDKs (symptom, root cause, rule, how to verify) are kept in one place, in the TypeScript SDK repository: [CoNET-project/chat-sdk docs/knowledge-base](https://github.com/CoNET-project/chat-sdk/tree/main/docs/knowledge-base). iOS specifics: [platform-ios.md](https://github.com/CoNET-project/chat-sdk/blob/main/docs/knowledge-base/platform-ios.md).
