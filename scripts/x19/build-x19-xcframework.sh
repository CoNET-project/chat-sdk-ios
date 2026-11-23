#!/bin/bash
# Build of X19.xcframework (X-19 v6): gomobile bind of scripts/x19/wrapper (gopenpgp v3.5.2, go 1.27.4), with -trimpath and a neutral work folder, so that
# the binaries carry no path of the build machine, and so that two builds of the same inputs are byte-identical.
# Inputs (environment, all required unless noted):
#   X19_GO       path to the go 1.27.4 binary
#   X19_MODCACHE a module cache folder with the verified modules (read only in practice)
#   X19_OUT      output path for the framework (for example Vendor/X19.xcframework; must not exist)
#   X19_PROXY    optional: file:// URL of a local module proxy (for example file://$X19_MODCACHE/cache/download), used by gomobile bind's go mod tidy
# The build runs in /tmp/x19w (a fixed, neutral folder; the build refuses if it exists), not in the repository. It does not use the network (GOPROXY=off unless X19_PROXY is set).
# gomobile's go mod tidy also loads the test-only dependencies of the dependencies; a cache without them would stop it. The build therefore runs
# `go mod tidy -e` through a small wrapper (it only adds -e; every other go command is unchanged). The compiled packages are the same.
# Determinism: -trimpath; -ldflags "-s -w -buildid="; ZERO_AR_DATE=1 (no member dates in the archive); the framework version that gomobile derives
# from the build time is set to the fixed value 0.0.1; the slices of the top Info.plist are put in a fixed order (gomobile writes them in a changing
# order). The Go build info keeps the module path and versions only.
# Afterwards the output is checked against scripts/x19/X19.xcframework.sha256 (exit 1 on mismatch). A mismatch needs review; do not re-lock silently.
# Check the result for paths with: strings -a <binary> | grep -E '/Users/|/private/|/home/' (no hit expected).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
: "${X19_GO:?set X19_GO to the go 1.27.4 binary}"
: "${X19_MODCACHE:?set X19_MODCACHE to a verified module cache folder}"
: "${X19_OUT:?set X19_OUT to the output .xcframework path (must not exist)}"
X19_PROXY="${X19_PROXY:-}"
if [ -e "$X19_OUT" ]; then echo "refusing: $X19_OUT exists"; exit 2; fi
work="/tmp/x19w"
if [ -e "$work" ]; then echo "refusing: $work exists"; exit 2; fi
mkdir -p "$work/bin" "$work/gopath" "$work/gocache" "$work/tmp" "$work/shim"
trap 'rm -rf "$work"' EXIT   # the folder is ours from here on: removed on success, failure and interrupt
cp -R "$here/wrapper" "$work/wrapper"
cat > "$work/shim/go" <<SHIM
#!/bin/bash
real="$X19_GO"
if [ "\${1:-}" = "mod" ] && [ "\${2:-}" = "tidy" ]; then shift 2; exec "\$real" mod tidy -e "\$@"; fi
exec "\$real" "\$@"
SHIM
chmod +x "$work/shim/go"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export GOTOOLCHAIN=local GOTELEMETRY=off GOSUMDB=sum.golang.org GOFLAGS=-mod=mod
export TMPDIR="$work/tmp" GOMODCACHE="$X19_MODCACHE" GOPATH="$work/gopath" GOCACHE="$work/gocache"
export GOPROXY="${X19_PROXY:-off}"
export ZERO_AR_DATE=1
export CGO_CFLAGS="-ffile-prefix-map=$work=/x19 -ffile-prefix-map=$X19_MODCACHE=/mod -fdebug-prefix-map=$work=/x19 -fdebug-prefix-map=$X19_MODCACHE=/mod"
export CGO_LDFLAGS="-Wl,-no_uuid"
export PATH="$work/shim:$work/bin:$(dirname "$X19_GO"):$PATH"
(cd "$work/wrapper" && "$X19_GO" build -trimpath -o "$work/bin/gomobile" golang.org/x/mobile/cmd/gomobile \
  && "$X19_GO" build -trimpath -o "$work/bin/gobind" golang.org/x/mobile/cmd/gobind)
(cd "$work/wrapper" && "$work/bin/gomobile" bind -target=ios -trimpath -ldflags="-s -w -buildid=" -o "$work/X19.xcframework" ./x19)
# gomobile writes the build time (seconds) as the framework version: fixed value, so that two builds are byte-identical
find "$work/X19.xcframework" -name Info.plist -path "*X19.framework/Info.plist" | while read -r p; do
  python3 -I -c 'import re,sys; p=sys.argv[1]; t=open(p).read(); open(p,"w").write(re.sub(r"0\.0\.[0-9]{9,}","0.0.1",t))' "$p"
done
# gomobile writes the two slices of the xcframework's top Info.plist in a changing order: sort AvailableLibraries by LibraryIdentifier (ios-arm64 first),
# without changing the text of any block, so that the file is the same in every build.
python3 -I - "$work/X19.xcframework/Info.plist" <<'PY'
import re, sys
p = sys.argv[1]
t = open(p).read()
m = re.search(r"(<key>AvailableLibraries</key>\n\t<array>\n)((?:\t\t<dict>\n.*?\n\t\t</dict>\n)+)(\t</array>)", t, re.S)
if not m:
    sys.exit("Info.plist: AvailableLibraries not found in the expected layout")
blocks = re.findall(r"\t\t<dict>\n.*?\n\t\t</dict>\n", m.group(2), re.S)
if "".join(blocks) != m.group(2) or len(blocks) != 2:
    sys.exit("Info.plist: unexpected AvailableLibraries blocks")
ident = lambda b: re.search(r"<key>LibraryIdentifier</key>\n\t\t\t<string>([^<]+)</string>", b).group(1)
blocks.sort(key=ident)
open(p, "w").write(t[:m.start(2)] + "".join(blocks) + t[m.end(2):])
PY
mkdir -p "$(dirname "$X19_OUT")"
cp -R "$work/X19.xcframework" "$X19_OUT"
"$here/verify-x19-xcframework.sh" "$X19_OUT"
