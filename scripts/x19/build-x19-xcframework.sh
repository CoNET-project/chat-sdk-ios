#!/bin/bash
# Reproducible build of X19.xcframework (X-19 v2): gomobile bind of scripts/x19/wrapper (gopenpgp v3.5.2, go 1.27.4).
# Inputs (environment, all required unless noted):
#   X19_GO       path to the go 1.27.4 binary (a verified archive, unpacked into a new folder)
#   X19_MODCACHE a module cache folder with the verified modules (it is written to; use a copy)
#   X19_OUT      output path for the framework (for example Vendor/X19.xcframework; must not exist)
#   X19_PROXY    optional: file:// URL of a verified local module proxy, used only by gomobile bind's go mod tidy
# The build runs in a new temporary folder. It does not use the network proxy (GOPROXY=off unless X19_PROXY is set).
# Afterwards the output is checked against scripts/x19/X19.xcframework.sha256 (exit 1 on mismatch).
#
# NOT byte-reproducible yet (2026-11-13): a rebuild in another folder differs from the v2 lock, because the binaries embed
# the build and temporary paths (Go and gomobile work folders, also with -trimpath), and gomobile orders the framework
# slices differently between runs (Info.plist). The lock records the v2 reference build. A mismatch needs review; do not
# re-lock silently. Acceptance of a new build is by the product checks (symbols, bytes, govulncheck), see the X-19 report.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
: "${X19_GO:?set X19_GO to the go 1.27.4 binary}"
: "${X19_MODCACHE:?set X19_MODCACHE to a verified module cache folder}"
: "${X19_OUT:?set X19_OUT to the output .xcframework path (must not exist)}"
X19_PROXY="${X19_PROXY:-}"
if [ -e "$X19_OUT" ]; then echo "refusing: $X19_OUT exists"; exit 2; fi
work="$(mktemp -d)"
cp -R "$here/wrapper" "$work/wrapper"
mkdir -p "$work/bin" "$work/gopath" "$work/gocache"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export GOTOOLCHAIN=local GOTELEMETRY=off GOSUMDB=sum.golang.org GOFLAGS=-mod=mod
export TMPDIR="$work/tmp"; mkdir -p "$TMPDIR"
export GOMODCACHE="$X19_MODCACHE" GOPATH="$work/gopath" GOCACHE="$work/gocache"
export GOPROXY="${X19_PROXY:-off}"
(cd "$work/wrapper" && "$X19_GO" build -o "$work/bin/gomobile" golang.org/x/mobile/cmd/gomobile \
  && "$X19_GO" build -o "$work/bin/gobind" golang.org/x/mobile/cmd/gobind)
(cd "$work/wrapper" && PATH="$work/bin:$(dirname "$X19_GO"):$PATH" \
  "$work/bin/gomobile" bind -target=ios -o "$X19_OUT" ./x19)
"$here/verify-x19-xcframework.sh" "$X19_OUT"
