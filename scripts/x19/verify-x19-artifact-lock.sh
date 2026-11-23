#!/bin/bash
# Checks that Package.swift carries the same artifactURL and artifactSHA256 as scripts/x19/X19.artifact.lock, and that
# the lock's SHA-256 has the form SwiftPM accepts. Exit 1 on any difference. Run it before every commit that touches
# either file, and in CI.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/../.."
lock="$here/X19.artifact.lock"
pkg="$root/Package.swift"
lock_url="$(sed -n 's/^artifactURL=//p' "$lock")"
lock_sha="$(sed -n 's/^artifactSHA256=//p' "$lock")"
pkg_url="$(sed -n 's/^let x19Url = "\(.*\)"$/\1/p' "$pkg")"
pkg_sha="$(sed -n 's/^let x19Sha = "\(.*\)"$/\1/p' "$pkg")"
status=0
if [ "$lock_url" != "$pkg_url" ]; then echo "FAIL artifactURL: lock='$lock_url' Package.swift='$pkg_url'"; status=1; fi
if [ "$lock_sha" != "$pkg_sha" ]; then echo "FAIL artifactSHA256: lock='$lock_sha' Package.swift='$pkg_sha'"; status=1; fi
if [ -n "$lock_url" ]; then
  case "$lock_url" in https://*) ;; *) echo "FAIL artifactURL must be https (SwiftPM rule)"; status=1 ;; esac
fi
if [ -n "$lock_sha" ] && ! printf '%s' "$lock_sha" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "FAIL artifactSHA256 is not 64 lowercase hex digits"; status=1
fi
if [ $status -eq 0 ]; then echo "OK   X19 artifact lock matches Package.swift (url='${lock_url:-none}', sha='${lock_sha:-none}')"; fi
exit $status
