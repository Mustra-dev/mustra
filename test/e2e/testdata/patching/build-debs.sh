#!/bin/sh
# Builds mustra-dummy_1.0 and _1.1 (arch all) and a flat apt repo. Run as root on a Debian/Ubuntu host with dpkg-dev.
# Usage: build-debs.sh <outdir>        then: echo "deb [trusted=yes] file:<outdir>/repo ./" > /etc/apt/sources.list.d/mustra-dummy.list
set -eu; umask 022
OUT=${1:-/srv/mustra-dummy}; mkdir -p "$OUT/pool" "$OUT/repo"
for v in 1.0 1.1; do
  d=$(mktemp -d); mkdir -p "$d/DEBIAN" "$d/usr/bin"
  printf 'Package: mustra-dummy\nVersion: %s\nArchitecture: all\nMaintainer: e2e <e2e@example.invalid>\nDescription: mustra patching test fixture %s\n' "$v" "$v" > "$d/DEBIAN/control"
  printf '#!/bin/sh\necho mustra-dummy %s\n' "$v" > "$d/usr/bin/mustra-dummy"; chmod 755 "$d/usr/bin/mustra-dummy"
  dpkg-deb --build --root-owner-group "$d" "$OUT/pool/mustra-dummy_${v}_all.deb" >/dev/null; rm -rf "$d"
done
echo "built: $(ls "$OUT/pool")"
