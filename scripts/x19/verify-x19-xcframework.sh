#!/bin/bash
# Verifies an X19.xcframework against the lock file scripts/x19/X19.xcframework.sha256 (X-19 v2, 2026-11-13).
# Usage: verify-x19-xcframework.sh [path/to/X19.xcframework]   (default: Vendor/X19.xcframework next to Package.swift)
# Exit status 1 on any mismatch, missing file, or manifest difference.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fw="${1:-$here/../../Vendor/X19.xcframework}"
lock="$here/X19.xcframework.sha256"
if [ ! -d "$fw" ]; then
  echo "FAIL no framework at $fw"
  exit 1
fi
status=0
while read -r expected path _; do
  case "$expected" in ""|\#*) continue ;; esac
  if [ "$path" = "MANIFEST" ]; then continue; fi
  if [ -f "$fw/$path" ]; then
    actual="$(shasum -a 256 "$fw/$path" | cut -d' ' -f1)"
  else
    actual="missing"
  fi
  if [ "$actual" = "$expected" ]; then echo "OK   $path"; else echo "FAIL $path ($actual)"; status=1; fi
done < "$lock"
# Manifest: the SHA-256 of the list of every file in the framework (same format as the v2 manifest).
manifest="$(cd "$fw" && find . -type f | sort | while read -r f; do
  echo "$(shasum -a 256 "$f" | cut -c1-64)  X19.xcframework/$f"; done)"
manifest_sha="$(printf '%s\n' "$manifest" | shasum -a 256 | cut -d' ' -f1)"
expected_manifest="$(grep -E '^[0-9a-f]{64}  MANIFEST' "$lock" | cut -d' ' -f1)"
if [ "$manifest_sha" = "$expected_manifest" ]; then echo "OK   MANIFEST"; else echo "FAIL MANIFEST ($manifest_sha)"; status=1; fi
exit $status
