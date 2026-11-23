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

## Test isolation guard

A test build (`BEAMIO_TEST_HOOKS=1`) never reads or writes the product's files under `Application Support`: the inbox, call-signal, owner and roster files and the local chat
library live in `$TMPDIR/beamio-conetchat-test-<pid>`, and the page-copy store in `$TMPDIR/beamio-shell-record-test-<pid>-<uuid>`. `ZZProductPathGuardTests` checks, after the
run, that the known product files (`ConetChat/{inbox_v1.json,call_signals_v1.json,owner_v1.txt,si_roster_v1.json}`, `ConetChat/local-v1/*`, `beamio-shell-record/*`) have the
same modification time and size as at the first use of a test path helper. **Run it only while no other process writes those directories** (another test run on the same
machine, or the app itself): such a write is reported as a change although it is not this process's. Test directories of processes that no longer exist are removed at the
next run; the current process removes its own at exit.

## Passcode write marker (cleanup of an old account)

`BeamioPasscodeWriteMarker` is an in-process counter per account, set around every write or delete of a passcode record or staging copy (`BeamioPasscodeKeychainRecords.writeRecord/deleteRecord`
is the one choke point) and around the two flows in which a staging copy exists (`stagedReplace`, `shellReconcileStaging`). The cleanup of an old account deletes a staging copy only when it
is older than the process and no write of the account is running. **Limits:** it covers one storage call, not the steps between the calls of a multi-step flow; it is valid in this process only.
If an App Extension, a notification service extension or a shared app group or keychain access group is ever added to the shell, the marker must become cross-process in the same change.

## Acceptance note: the inbox owner, inbox and call-signal files (not part of the account cleanup)

`owner_v1.txt`, `inbox_v1.json` and `call_signals_v1.json` (in `Application Support/ConetChat`) are **not deleted by the account cleanup**: while the owner is exactly the
old account they are left alone and, not counted in `keptUnattributed` either. Two other flows do change them and are not the cleanup: `clearInboundState` (the user clears the identity;
BeamioConetChatModule.swift around lines 1674–1676) and `clearAndMark` (an account switch; around lines 1639–1640). Whole-file deletion by the cleanup is suspended until the owner write and the
generation advance are serialized (or the write sites check the owner) and it is explicitly enabled; a delete must then re-read the owner under the same lock.

## Known limits of the test suite

- **Run it unlocked.** The page copy store writes with `.completeFileProtection`; while the machine's console is locked (`ioreg -r -k IOConsoleLocked` shows `Yes`), macOS refuses those writes (Cocoa 513), and about a dozen
  page-copy tests (E9ReviewFixTests, PgpShellRecordTests, ShellEmptyStoreGuardTests, ShellReportLatchTests, ShellReportResultTests, and the page copy cases of AccountCleanupProductionTests when they use the store's write)
  report failures that are not defects. Root cause: reproduced under a locked console, the same probe writes successfully when the console is unlocked. The failure log line is `[BeamioShellRecord] page copy write failed domain=… code=… place=…`. On iOS the same protection means a page copy cannot be written while the device is
  locked: the command answers `write_failed`, never ok, and the previous copy stays.
- **Serial runs only.** `swift test --parallel` shows 7 extra failures; no definite product defect was found, and these seven are **not closed**:
  1. `ZZProductPathGuardTests.testTheTestsNeverTouchTheProductDirectories` (ZZProductPathGuardTests.swift:48): by design; in its own process the guard's baseline is taken by the guard itself and the late-baseline assertion fails.
  2. `ShellReportLatchTests.testACreationReadWithANativeKeyIsNeverAbsentAfterASavedAbsent` (ShellReportLatchTests.swift:164–165), 3. `testAReadableKeyInTheCreationReadIsMigratingAndNeverAbsent` (:268–269),
     4. `testAnUnreadableKeyInTheCreationReadIsMigratingNotNativeRecovery` (:283–284), 5. `ClearIdentityKeyDeletionTests.testAFailedWalletStepAnswersClearIncompleteAndTheRedoCompletes`
     (ClearIdentityKeyDeletionTests.swift:360, :365): they fail both in the serial run (the classes alone) and in parallel; **root cause not investigated**. They are not attributed to a dependence on earlier tests.
  6. `InboundAccountSwitchAndSignerTests.testAGroupRequestWithAStaleOrMissingGenerationIsRefused` (InboundAccountSwitchAndSignerTests.swift:238) and 7. `WalletStatusRulingTests.testSettlementLockStillBlocksFamilyCommandsButNotWalletStatus`
     (WalletStatusRulingTests.swift:130, expects `not_ready`, gets `not_supported`): pass when their class runs alone, fail only in parallel. Recorded as a dependence on static state set up by earlier tests of the same process (**not fully confirmed**); a shared `UserDefaults.standard` or the real Keychain was suspected and is **not confirmed**
     (a read of their sources shows isolated directories, in-memory stores and the in-memory defaults, and no direct access to the real stores, **not confirmed**; the test build now keeps the SDK's defaults in memory, and the
     parallel run still fails them). Fixing the isolation is a follow-up after the cleanup review.
- **`write_failed` coverage.** The store layer (a real `EncryptedShellRecordStore` whose write fails answers false and logs domain, code and place) and the command layer (`shellRecordWrite` answers `write_failed` in `result`)
  are covered end to end by `AccountCleanupProductionTests.testARealPageCopyStoreWriteFailureIsAnsweredWriteFailedByTheCommand` (an unwritable directory under a regular file, through `BeamioShellRecord.answer` and the ack envelope).
- **Side files of a missing library.** `-wal`, `-shm` and `-journal` of an account's local chat library are removed by the cleanup even when the main file is gone, without the pending-publish check: SQLite cannot recover from a
  write-ahead log without its main database file, so such residue can never be read again and holds nothing recoverable.
- **What the guard reads on the real machine.** `ZZProductPathGuardTests` reads, read-only, the attributes (service, account, modification date; never a value, no authentication UI) of the login Keychain items whose service starts with `com.beamio.beamio.`, the SDK's own keys in `UserDefaults.standard`, and the
  `beamio.test-host.*` file names in `~/Library/Preferences`, to prove a test run changed none of them. Everything else the tests touch is a stand-in: the in-memory Keychain, `BeamioMemoryDefaults` (an independent in-memory implementation of
  `BeamioDefaultsStoring`, not a `UserDefaults` subclass, so no uncovered call can fall through to the real domain), and per-process temporary directories.
- **When a test is skipped for the locked console.** Only when both hold: a `.completeFileProtection` probe write is refused with Cocoa 512 or 513, and the I/O Registry reports `IOConsoleLocked = true`. The skip sits immediately before the first write of the test, so
  the assertions before it run either way; the skip reason `console locked: completeFileProtection write refused` is logged for each skipped test.
- **The guard never prints a real value.** It compares the SDK's keys in the real defaults domain only in memory, as a digest; the Keychain accounts are compared as a short digest too. A log line or a failure message names the service or the key and says
  whether it changed (`added`, `removed`, `modified`), and never outputs a value or an account name.
- **`createKey` in a test build (semantics).** `BeamioTestKeychainStore.createRandomKey` always answers nil, whatever the in-memory items are (nil or not): the creation of a Secure Enclave key **fails**, in a test build, on every machine. `BeamioPasscodeKeychainHardware.createKey` then takes
  its Keychain fallback (`SecItemAdd`, answered from the in-memory items, which the first write creates if they are nil), so `createKey` **succeeds by the fallback** and nothing is written to the real Keychain. No test expects a Secure Enclave key to exist. Who depends on what:
  - Direct calls of the real `BeamioPasscodeKeychainHardware.createKey` (test tag prefixes): `BeamioPasscodeFlowTests.swift:220` (class `BeamioPasscodeKeychainTests`, asserts it is true) and `AccountCleanupTests.swift:382` (the marker test; it ignores the result and only reads the marker).
  - `PwaWalletSyncPasscodeStoreTests.swift` has **no direct call** of `createKey`: it depends on it **indirectly**, through the vault and the store (`BeamioPasscodeSession.writeDeviceRecord`, BeamioPasscodeSession.swift:444, creates H with the real hardware class and qa tag prefixes before wrapping the key), so those tests need the fallback to succeed.
  - `BeamioPasscodeFlowTests.swift:79` and `:255` call `createKey` on **test doubles** (`MemoryHardware`, `BeamioPasscodeFlowHardware`), not on the production class; they depend on the double's side effect (the double now holds a key for the account), which the later wrap and unwrap of the test need.
- **Not covered by any test: the Secure Enclave path.** The ACL (`SecAccessControlCreateWithFlags` with `.privateKeyUsage`), the `seTag` (`com.beamio.passcode.h.se.<eoa>`), `createSecureEnclaveKey` and `seKey` (the lookup and the ECIES wrap and unwrap through the key) are never exercised, because the stand-in always fails the SE creation. "`createKey` is true" proves only that the fallback works.
  **Pre-enable item (device):** before the account cleanup is enabled, run on a real device (or a signed build) the creation of H through the Secure Enclave, its `seTag` lookup, its wrap and unwrap, and `deleteKey` (which removes both the SE key and the fallback item), and check that the cleanup's delete-and-confirm of the pair works on both kinds of H.
- **What "the guard passed" does not prove.** The guard compares facts keyed by path (for the Keychain: the service and a 32-bit digest of the account name, with the item's modification date; for the defaults: the key, with a digest of the value; for files: path, modification time and size). It reports
  an item that is added, removed or modified. **It does not report a swap**: if an item A is deleted and an item B is added whose fact is identical (the same service and account digest and the same modification date, for example a delete and a re-add of the same account within the date's resolution, or two accounts whose short digests collide),
  nothing differs and the guard stays silent. This is a miss (a false negative), never a false alarm, so "the guard passed" does **not** mean the Keychain items are identical; it means no addition, removal or modification was visible. A value of a Keychain item is never read or compared.
- **`createKey` in a test build.** The Secure Enclave key creation fails by design (the stand-in always answers nil, whatever the in-memory items are), and `createKey` then succeeds by its in-memory Keychain fallback; nothing reaches the real Keychain. The tests that rely on that success are listed under the `createKey` item above
  (`BeamioPasscodeFlowTests.swift` around lines 211–220 and `PwaWalletSyncPasscodeStoreTests.swift`); none expects a Secure Enclave key to exist.


## Account cleanup command (`accountCleanupOld`, registered 2026-11-21)

The command is registered on the bridge (the silent cleanup of the previous account's data). It judges its own gate: anything that is not a passed gate with a known, readable active account
answers `not_ready` and deletes nothing. The page's `accountKey` must equal the native derived address and the pointer; both are read again before each old account is touched, and a change in the middle answers
`account_mismatch` and stops (what was deleted stays deleted). The old accounts are every account the device holds an item for except `accountKey`, found by an exact address in a name: mnemonic, key and
passcode-record owners, PGP K records, page-copy keys, the account-keyed items of the wallet service (walletKey, mnemonic, intent, commit, phase, migrated, recovery-backup flag, credential K `blobKey`, unconfirmed
restore) and the Secure Enclave tags and H fallback items. Any listing that fails answers `not_ready` before the first deletion. Kept and counted in `keptUnattributed` (answer `ok`): an account-keyed name of those
stores that is not exactly an address, an isolated copy of an overwrite (`wallet.iso.`), and a chat library whose file name (a one-way hash) matches no known account. Not counted: the Secure Enclave key (kept, never
deleted in this version, it only identifies the account) and `owner_v1.txt`, `inbox_v1.json`, `call_signals_v1.json` (kept, not counted). An active account found among the candidates (unreachable after the read-back) is kept
whole and counted. A library with unsent messages (`pending_publish = 1`) is kept in this version and counted in `keptUnattributed`: it is not pending and blocks nothing; a library that cannot be probed is unknown.
An item that cannot be listed, read or deleted (including a Secure Enclave lookup that fails) keeps only itself: the run goes on with the other old accounts and ends `clear_incomplete` with `cleanupPending`
(the page's resend with the same idempotency key retries); only the enumeration (before any deletion) and a change of the active account stop a run. The read-back uses one snapshot of the pointer and the address derived
from it (`activeSnapshot`), also before each old account.
The deletion path stays disabled until it is explicitly enabled.
Vectors driven: `accountCleanupOld.v3` (BR3-05/06/07) and `enumerated-accounts.v4` (EA-01..EA-14, final, pinned by SHA-256). `AccountCleanupSnapshotTests` (SNAP-01..SNAP-07, v225) run over the production environment: a real pointer and key, the production snapshot, listings and deletions; only a Secure Enclave lookup failure (SNAP-04) and a failing page-copy key delete (SNAP-03, SNAP-07) are injected. Not covered: a real device, the Secure Enclave path (the test Keychain holds no keys),
the passcode items in the EA fixtures beyond a double.

## Phrase-only residue, page copies and walletCredential

- **Phrase-only residue** (the pointer names an account whose key record is missing and whose mnemonic is left): walletStatus answers `locked` with `reason: phrase_only` and the accountKey when the phrase is
  readable and verified (BIP-39 checksum passes, it derives the account) and the session is ready; `not_ready` with `g1_uninitialized` when it is verified and the session is not ready; `not_ready` with
  `unreadable` when the phrase is readable but not verified or cannot be read. Never `no_key` (`phraseOnlyAnswer`, v227 section 247.1). Tests: `PhraseOnlyStatusTests` (PHR-01..04).
- **Page copies** are built for a valid mnemonic account only (`BeamioShellRecord.replicaAnswer`): a key with no mnemonic is an orphan (no account: `absent`, not read, not derived, not written);
  a mnemonic that is not verified answers `migrating`. The shell has no other native path that writes a page copy from a native key: the other writers are the page's own `shellRecordWrite` (validated, page content),
  and the removal of wallet fields (`removeWalletFields`). There is no iOS counterpart of Android's `importFound` (v229 section 249.2): the legacy browser store is imported by the page, not read by the SDK.
  Tests: `ReplicaCreationTests` (REP-01, REP-02) and `KeystoreReplicaV2VectorTests` (keystore-replica-vectors.v2.1, driven as the file says).
  Following the interface spec, the shell read answers: an unreadable legacy store keeps `error legacy_store_unreadable` (KR-05: the PWA baseline; keystore-replica v2.1); a creation-mode read
  that meets a found legacy record is `migrating` (the normal read keeps `import_not_done`; `device.legacyFound` is the iOS "found, not imported" state, the same state as Android's import path, and it never writes a page copy);
  with no pointer and the legacy store confirmed empty, a readable valid account gives `absent` and an unreadable native key gives `needs_native_recovery` (`account_record_missing` is for a set pointer).
- **walletCredential** for a key with no mnemonic answers `unavailable`, never `no_key` (`no_key` is the walletStatus word): `walletCredentialOutcome`.
- `keychainCurrentEoa()` reads each mnemonic once to verify it (and wipes it); it unwraps no key and calls no Secure Enclave: compliant, comment updated.
- **Unverifiable mnemonic residue in the silent cleanup** (v230 section 250): a mnemonic item of an old account that reads but does not verify (checksum fails, no key, or it does not derive the account) is not an exact
  attribution, whatever its envelope's eoa says: it is kept, counted in `keptUnattributed` (`unverifiable-mnemonic|<account>`), and is not pending; the account's other exactly attributable items go as usual. One that cannot
  be read is unknown (`clear_incomplete`, retried). Tests: `AccountCleanupSnapshotTests` UNV-01..03.

## Record read answers when the keychain cannot be read (change against the earlier release line)

`shellRecordRead` answers `not_ready` with a `notReadyReason` and a `retryable` flag. Against the earlier release line the **answer shape changed on purpose** for one case: an
`unreadable` reason with `retryable` false (the keychain cause is `entitlement` or `other`, a cause a retry never cures) is no longer answered `not_ready` first. It is answered at once,
on the first read, as `{code: "error", sub: "not_ready_persistent", notReadyReason: "unreadable", retryable: false, unreadableCause}`. Every other reason keeps the count: `storage_locked`,
`ambiguous_accounts`, `g1_uninitialized` and an `unreadable` reason with a transient cause (`device_locked`, retryable true) answer `not_ready` and become `not_ready_persistent` only from the 11th
answer of the same reason in one process. The two earlier vector files (`shell-record-read-answer-shape.v1.json`, `unreadable-cause.v2.json`) stay in the test resources unchanged; the tests run
the v3 files.

QA diagnostics (compiled only for a `BEAMIO_QA_BUILD`): one line per `shellRecordRead` answer and one per `nativeMnemonicPreread` answer, with an integer reqId and closed word sets only.
