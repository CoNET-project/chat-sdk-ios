#!/bin/bash
# Packs a verified X19.xcframework into the artifact zip (fixed order and times, no __MACOSX entries: the same files give the same zip) and prints the zip's SHA-256. It does not upload anything.
# The framework must match scripts/x19/X19.xcframework.sha256 first. Whoever publishes the zip must put the printed
# SHA-256 into scripts/x19/X19.artifact.lock (artifactSHA256) and the URL into artifactURL, in the same commit.
# Usage: make-x19-artifact.sh <path/to/X19.xcframework> <output folder, must not be inside the repo>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="${1:?usage: make-x19-artifact.sh <X19.xcframework> <output folder>}"
out="${2:?usage: make-x19-artifact.sh <X19.xcframework> <output folder>}"
if [ ! -d "$src" ]; then echo "FAIL no framework at $src"; exit 1; fi
if "$here/verify-x19-xcframework.sh" "$src" > /dev/null; then :; else
  echo "refusing: $src does not match $here/X19.xcframework.sha256"; exit 1
fi
case "$(cd "$out" 2>/dev/null && pwd || echo "$out")" in
  *"/BeamioContract/"*|*"/chat-sdk-ios/"*) echo "refusing: output folder must be outside the repository"; exit 2 ;;
esac
mkdir -p "$out"
work="$(mktemp -d)"
cp -R "$src" "$work/X19.xcframework"
python3 -I "$here/pack-x19-artifact.py" "$work/X19.xcframework" "$out/X19.xcframework.zip"
sha="$(shasum -a 256 "$out/X19.xcframework.zip" | cut -d' ' -f1)"
echo "$sha  X19.xcframework.zip"
echo "written: $out/X19.xcframework.zip"
