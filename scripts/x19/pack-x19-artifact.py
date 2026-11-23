# Packs a directory into a zip with a fixed order, fixed times and no macOS resource-fork entries (no __MACOSX), so that the same files give the same zip.
# Usage: pack-x19-artifact.py <path/to/X19.xcframework> <output zip>
import os, sys, zipfile
src, dst = sys.argv[1], sys.argv[2]   # src: path to X19.xcframework, dst: zip path
entries = []
for d, dirs, files in os.walk(src):
    dirs.sort()
    rel = os.path.relpath(d, os.path.dirname(src))
    entries.append((rel + '/', None))
    for f in sorted(files):
        entries.append((os.path.join(rel, f), os.path.join(d, f)))
entries.sort(key=lambda e: e[0])
with zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name, path in entries:
        zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        zi.create_system = 3
        if path is None:
            zi.external_attr = (0o40755 << 16) | 0x10
            z.writestr(zi, b'')
        else:
            zi.external_attr = 0o100644 << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, open(path, 'rb').read(), compresslevel=9)
