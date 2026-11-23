#!/bin/bash
# : scans a built binary, bundle or archive for X-19 (the X19 wrapper and the Go runtime it carries).
# Usage: verify-no-x19-in-binary.sh <binary | .xctest bundle | .framework | .a | .app>
# exit 0: no marker found (a Release build must give this)
# exit 1: at least one marker found
# exit 2: usage or missing input
# Positive control: a QA build made with BEAMIO_X19_LINK=1 must give exit 1 with this same script. Without the control, a 0 proves nothing.
# Markers are the strings and symbols the X19 wrapper and the Go runtime leave in a binary (the shell evidence of found the Go ones).
# Stripped global symbols do not hide the strings, so both are checked. The script prints file and marker names only, never any content.
set -uo pipefail
target="${1:-}"
if [ -z "$target" ] || [ ! -e "$target" ]; then
	echo "usage: $0 <binary | bundle | framework | archive | app>" >&2
	exit 2
fi

markers=(X19Crypto gopenpgp "Go buildinf" go:buildid runtime.goexit)
hits=0

# The path of a file, relative to the target when the target is a directory; the file name when the target is the file itself.
rel() {
	if [ "$1" = "$target" ]; then basename "$1"; else printf '%s' "${1#$target/}"; fi
}

# Regular files only: a bundle's resources are scanned too, which is intended (an X-19 resource is also X-19).
while IFS= read -r file; do
	[ -f "$file" ] || continue
	for marker in "${markers[@]}"; do
		if strings -a "$file" 2>/dev/null | grep -q -F -- "$marker"; then
			echo "FOUND marker '$marker' in $(rel "$file")"
			hits=$((hits + 1))
		fi
	done
	# Defined global symbols (a linked X-19 image or artifact), and undefined references (an object that calls into X-19).
	if nm -gU "$file" 2>/dev/null | grep -q -E 'X19|gopenpgp|runtime\.goexit'; then
		echo "FOUND defined symbol in $(rel "$file")"
		hits=$((hits + 1))
	fi
	if nm -u "$file" 2>/dev/null | grep -q -E 'X19|gopenpgp|runtime\.goexit'; then
		echo "FOUND undefined reference to X-19 in $(rel "$file")"
		hits=$((hits + 1))
	fi
done < <(if [ -d "$target" ]; then find "$target" -type f; else printf '%s\n' "$target"; fi)

if [ "$hits" -eq 0 ]; then
	echo "OK   no X-19 marker in $target"
	exit 0
fi
echo "FAIL $hits X-19 hit(s) in $target"
exit 1
