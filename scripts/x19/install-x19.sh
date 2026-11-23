#!/bin/bash
# Installs X19.xcframework into Vendor/ (development) from the artifact zip. The zip's SHA-256 must equal
# artifactSHA256 in scripts/x19/X19.artifact.lock, and the unpacked framework must match X19.xcframework.sha256.
# Usage: install-x19.sh <path/to/X19.xcframework.zip>
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
zip="${1:?usage: install-x19.sh <X19.xcframework.zip>}"
lock="$here/X19.artifact.lock"
expected="$(sed -n 's/^artifactSHA256=//p' "$lock")"
if [ -z "$expected" ]; then echo "refusing: artifactSHA256 is empty in $lock"; exit 1; fi
if [ ! -f "$zip" ]; then echo "FAIL no zip at $zip"; exit 1; fi
actual="$(shasum -a 256 "$zip" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then echo "FAIL zip sha256 $actual does not match the lock $expected"; exit 1; fi
dest="$here/../../Vendor"
if [ -e "$dest/X19.xcframework" ]; then echo "refusing: $dest/X19.xcframework already exists"; exit 2; fi
tmp="$(mktemp -d)"
ditto -x -k "$zip" "$tmp"
if [ ! -d "$tmp/X19.xcframework" ]; then echo "FAIL the zip does not contain X19.xcframework/"; exit 1; fi
mkdir -p "$dest"
mv "$tmp/X19.xcframework" "$dest/"
"$here/verify-x19-xcframework.sh" "$dest/X19.xcframework"
echo "installed: $dest/X19.xcframework"
