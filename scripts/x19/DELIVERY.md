# X-19 delivery by hash (2026)

The native OpenPGP framework `X19.xcframework` is **not in git**. The SDK and the shell take it by hash.

## Files

| File | Role |
|---|---|
| `X19.artifact.lock` | The reviewed lock: `artifactURL` (the https release asset) and `artifactSHA256` (the zip). |
| `X19.xcframework.sha256` | The per-file lock (v4) of the framework inside the zip, plus the MANIFEST. |
| `Package.swift` (`x19Url`, `x19Sha`) | Copies of the two artifact values. Literals on purpose: SwiftPM caches manifest evaluation by content. |
| `verify-x19-artifact-lock.sh` | Fails if `Package.swift` and the lock differ. Run before each commit and in CI. |
| `make-x19-artifact.sh` | Packs a verified framework into the zip, outside the repo. Does not upload. |
| `install-x19.sh` | Development: checks the zip's SHA-256, unpacks into `Vendor/` (git-ignored), runs the per-file check. |
| `verify-x19-xcframework.sh` | Checks an unpacked framework against the per-file lock. |

## How the SDK links X19 (`Package.swift`)

0. X-19 is linked into every iOS build (macOS does not link it). The environment variables `BEAMIO_X19_LINK` and `BEAMIO_REQUIRE_X19` no longer decide the link.
1. `x19Url` and `x19Sha` set: `.binaryTarget(url:checksum:)`. SwiftPM downloads the zip over https and refuses it on a SHA-256 mismatch.
2. Otherwise a local `Vendor/X19.xcframework` (installed by `install-x19.sh`) is linked. Development only.
3. Otherwise X19 is not linked and C3 reports `pgp_native_pending`.
4. `BEAMIO_REQUIRE_X19=1` also turns case 3 into a build error. On iOS case 3 cannot pass anyway: a build without the artifact fails with the explicit `#error` of `X19Required.swift`.
5. Verification: `scripts/x19/verify-no-x19-in-binary.sh <binary | bundle | framework | archive | app>` reports whether a built product holds X-19 symbols. X-19 is linked into every iOS build, so for an iOS build it exits 1 (X-19 present); a macOS build links none. Use a separate `-derivedDataPath` for each configuration: SwiftPM caches the manifest evaluation.

## Steps to publish (done for v0.1.10; the project owner decided the hosting)

1. Build X19 with `scripts/x19/build-x19-xcframework.sh` (or reuse the verified v4 framework), and check it with `verify-x19-xcframework.sh`.
2. `make-x19-artifact.sh <X19.xcframework> <folder outside the repo>` prints the zip's SHA-256.
3. Upload the zip, named `X19.xcframework.zip`, as the asset of the GitHub Release of the version (`releases/download/<tag>/X19.xcframework.zip`). Upload the locked file itself: a re-packed zip has another SHA-256.
4. In one commit: set `artifactURL` in `X19.artifact.lock` and the same value in `Package.swift`, and set `artifactSHA256`. Run `verify-x19-artifact-lock.sh`.
6. Shell: pin the SDK version (tag `v0.1.10`) or its commit; SwiftPM resolves the binary with the same checksum. No environment variable is needed.

## Current artifact: v6 (2026-11-23, clean rebuild of v5)

- Same wrapper source and module set as v5; the functions are the same (`Argon2IDKey`, `GenerateArmoredKey`, `PublicArmor`, `DecryptArmoredText`). v5 was not published: its binaries held build-machine paths (the build script did not pass `-trimpath`).
- Build (`build-x19-xcframework.sh`): `gomobile bind -target=ios -trimpath -ldflags="-s -w -buildid="`, a fixed neutral work folder (`/tmp/x19w`), `ZERO_AR_DATE=1`, the framework version fixed at 0.0.1, `CGO_CFLAGS`/`-ffile-prefix-map`, offline (`GOPROXY=off` or a file proxy over the module cache), `go.mod` and `go.sum` unchanged. `go mod verify` passes.
- Builds from the same inputs are byte-identical in all 15 files: the script also sorts the slices of the top `Info.plist` (gomobile writes them in a changing order). Twelve consecutive builds with `build-x19-xcframework.sh` in a clean folder gave the same files and the same zip (see the results in the review record). The zip is packed by `pack-x19-artifact.py` (fixed order and times, no `__MACOSX`), and two packings are identical.
- Zip (`X19.xcframework.zip`): SHA-256 `fc32fdb365287a663c0f1ee4954d637c7cdd05deedd9609d5809966e89249d62`, 7,172,867 bytes (in `X19.artifact.lock` and `Package.swift`).
- Per-file lock (v6): device slice `0dc30b95…`, simulator slice `b9b4d106…`, Info.plist `2e8ab775…` (unchanged), MANIFEST `471394bd…` (15 files).
- Scan: no `/Users/`, user name, `/private/tmp`, session folder, module-cache or toolchain path in either slice (`strings -a`); `nm`: `X19Argon2IDKey`, `X19GenerateArmoredKey`, `X19PublicArmor`, `X19DecryptArmoredText` present, no websocket, net/http, net.Dial or net.Listen symbols. This is a symbol-level check, not a reachability audit.

- Toolchain: Go 1.27.4 from Homebrew (`go1.27.4 darwin/arm64`), which is not the officially archived toolchain of the earlier builds. A comparison rebuild with the official archive is a follow-up after publication.
- Modules: the module cache passes `go mod verify` against `go.sum`; `go.mod` and `go.sum` are unchanged. For this build three modules (golang.org/x/tools v0.52.0, x/mod v0.42.0, x/sync v0.25.0) and the `go.mod` files of eight older dependency versions were fetched with the checksum database on.
- govulncheck: the result of 2026-11-13 (v5, same source and modules) is carried over; it is rerun after publication.

## Previous artifact: v5 (2026-11-13, not published)

- Change from v4: `Argon2IDKey(password, salt, memoryKB, iterations, parallelism, keyLen)` (`scripts/x19/wrapper/x19/x19.go`):
  Argon2id, version 0x13 (v = 19), the recovery-record KDF of spec 25.42.5 step 6 (PWA `deriveAesKeyFromPassword`). The project lead
  2026-11-13 approved Argon2id through this wrapper, using `golang.org/x/crypto/argon2` (already a requirement of the wrapper
  module, v0.59.0). No new module; `go.mod` and `go.sum` unchanged. The parameters come from the record and are bounded here
  (untrusted chain data): memory 8 MiB to 256 MiB, 1 to 10 passes, 1 to 4 lanes, a 32-byte key, a salt of 8 to 64 bytes.
  Known-answer checks against the PWA output are in the Swift vector tests (`native-recovery-vectors.v1.json`); the Go test
  (`argon2_test.go`) checks determinism, the password dependency and the bounds only.
- Zip (`X19.xcframework.zip`): SHA-256 `c47f55d9158b9a8c993aa49fb8e78b455bbb2d03426181c76e5634f1cac5eee6` (in `X19.artifact.lock`
  and `Package.swift`, verified by `verify-x19-artifact-lock.sh`).
- Per-file lock (v5): device slice `a938eada…`, simulator slice `8a181346…`, Info.plist `2e8ab775…` (unchanged), MANIFEST
  `a898df66…` (15 files).
- Build: Go 1.27.4 (local archive, `GOTOOLCHAIN=local`), the verified module cache copied to a new folder (2026-11-13),
  `GOPROXY=off`. The build's lock check fails by design (new binaries); the lock was written from the output after review.
- Wrapper tests: `go test ./x19/` passes, including `TestArgon2IDKeyDeterministicAndBounded`. `gofmt -l` is clean.
- govulncheck v1.9.0 (cached module, no download), source mode, Go 1.27.4: **No vulnerabilities found.**
- Symbol scan (`nm`, both slices): `X19Argon2IDKey`, `X19GenerateArmoredKey`, `X19PublicArmor`, `X19DecryptArmoredText` present;
  no `websocket`, `net/http`, `net.Dial` or `net.Listen` symbols. This is a symbol-level check, not a reachability audit.

## Previous artifact: v4 (2026-11-13)

- Change from v3: `GenerateArmoredKey(name)` (new PGP key, PWA convention: v4, curve25519 legacy, user ID = name, no
  passphrase; project lead approved 2026-11-13 for pgpIdentityCreate, which generates only after a native user confirmation) and
  `PublicArmor(privateArmor)`. The wrapper tests `keygen_test.go` check a usable v4 key, the public armor holding no secret,
  matching fingerprints, a 40-hex fingerprint and a 16-hex subkey key ID, a round trip, and different keys per call.
- Zip (`X19.xcframework.zip`): SHA-256 `f6f7ae287c2752e17676faf8447cc353df78cb5940577a2a6799fb05c0b6db70` (in `X19.artifact.lock` and `Package.swift`).
- Per-file lock (v4): device slice `d36c6b76…`, simulator slice `a919df9e…`, Info.plist `2e8ab775…`, MANIFEST `ba933b6d…` (15 files).
- Build: as v3 (Go 1.27.4, verified module cache copied, `GOPROXY=off`, `go.sum` unchanged, no new module). The
  build's lock check fails by design; the lock was written from the output after the symbol check.
- Wrapper tests: `go test ./x19/` passes (all 8 cases). `go vet` passes.
- govulncheck v1.9.0 (cached module, no download), source mode, Go 1.27.4: **No vulnerabilities found.**
- Symbol scan: `X19GenerateArmoredKey`, `X19PublicArmor`, `X19DecryptArmoredText` present; no websocket, net/http, net.Dial or net.Listen symbols.

Earlier v3 record (for history): zip `209971ea…`, device `5abd6b38…`, simulator `adc3eb59…`, manifest `12a391b0…`, from commit `1cebd2f`.

## Previous artifact: v3 (2026-11-12)

- Change from v2: `DecryptArmoredText` (`scripts/x19/wrapper/x19/x19.go`). A text literal (format t or u) comes back with CRLF turned into LF; a lone CR is kept. A binary literal (format b) comes back unchanged when valid UTF-8, and fails with `not_utf8` otherwise. Spec 25.34.2 step 6 and 25.32. The literal format is read from the literal data packet (`LiteralMetadata.IsUtf8()`), not guessed from the content. No new dependency: the wrapper's `go.mod` and `go.sum` are unchanged.
- Zip (`X19.xcframework.zip`): SHA-256 `209971ea0d6a184f244a0c5e69ffb47d2b3515c2c7c5408a7c589852c5da74f0` (in `X19.artifact.lock`, and in `Package.swift`).
- Per-file lock (`X19.xcframework.sha256`, v3): device slice `5abd6b38…`, simulator slice `adc3eb59…`, Info.plist `2e8ab775…`, MANIFEST `12a391b0…` (15 files).
- Build: `build-x19-xcframework.sh` with Go 1.27.4 (local verified archive, `GOTOOLCHAIN=local`) and the verified module cache (`gomodcache` of 2026-11-13, copied). Offline: `GOPROXY=off`, no new module. `go.sum` unchanged. The build ends with a lock check that fails by design (new binaries), and the new lock was then written from the output after review of the symbols.
- Wrapper tests: `go test ./x19/ -run DecryptArmoredText` passes (4 cases: CRLF in a text literal, lone CR, binary literal unchanged, binary literal not UTF-8). `go vet` passes.
- govulncheck: `govulncheck -mode source ./...` in the wrapper, v1.9.0 built from the cached module (no download), Go 1.27.4, vulnerability database read online: **No vulnerabilities found.** Source mode checks reachable code only. The framework is a library, not a Go binary, so binary mode does not apply.
- Symbol scan of the framework (`nm`): no `websocket`, no `net/http`, no `net.Dial` or `net.Listen` symbols, in v2 and v3 alike. This is a symbol-level check, not a full reachability audit.
- Older builds were not reproducible; v6 is (see above).

Earlier v2 record (for history, in git at commit 96308fb): device `4e0486e8…`, simulator `fecfec91…`, Info.plist `2e8ab775…`, manifest `4fcaff08…`. Its zip (SHA-256 `6b7dc2b9…`) was packed locally during item 2 and is superseded by v3; it was not kept in the repo.

## Benefits

- The repo stays small; the binary is not in history.
- SwiftPM enforces the hash itself; a changed zip is refused at resolve time.
- Replacing the binary is a reviewed lock change, not a silent file swap.

## Costs and risks

- Needs an https host and a publication step, which is an outward action (needs approval).
- Builds need network access to the host; an offline build must use the development path.
- The zip's SHA-256 depends on the zip bytes. Whoever re-packs the framework must update the lock.
- The trust root is the reviewed framework behind the lock; v6 can be rebuilt byte for byte from the same inputs.
- SwiftPM caches manifest evaluation by content. After a manifest-only change that does not touch `Package.swift`, reset the cache (`swift package reset`) to be sure.

## Not verified here

- SwiftPM's https download and checksum step: this environment cannot serve https with a trusted certificate without changing system trust settings, which is not done. The http variant is refused by SwiftPM ("valid schemes are: https").
- The development path (`install-x19.sh` into `Vendor/`) was verified: wrong zip refused, right zip installed, second install refused.
