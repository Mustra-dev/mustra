#!/bin/sh
# build-broken-1.2.sh <outdir>: mustra-dummy 1.2 whose postinst exits 1 (a patch that must be reported as failed)
set -eu; umask 022; OUT=${1:-/srv/mustra-dummy}; d=$(mktemp -d); mkdir -p "$d/DEBIAN" "$d/usr/bin"
printf 'Package: mustra-dummy\nVersion: 1.2\nArchitecture: all\nMaintainer: e2e <e2e@example.invalid>\nDescription: broken postinst fixture\n' > "$d/DEBIAN/control"
printf '#!/bin/sh\necho "mustra-dummy 1.2 postinst failing on purpose" >&2\nexit 1\n' > "$d/DEBIAN/postinst"; chmod 755 "$d/DEBIAN/postinst"
printf '#!/bin/sh\necho mustra-dummy 1.2\n' > "$d/usr/bin/mustra-dummy"; chmod 755 "$d/usr/bin/mustra-dummy"
dpkg-deb --build --root-owner-group "$d" "$OUT/pool/mustra-dummy_1.2_all.deb" >/dev/null; rm -rf "$d"; echo built 1.2
