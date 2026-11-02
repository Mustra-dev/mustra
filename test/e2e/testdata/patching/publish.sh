#!/bin/sh
# publish.sh <outdir> <version>: make only that version visible in the flat repo
set -eu; umask 022; OUT=$1; V=$2
rm -f "$OUT/repo"/*.deb; cp "$OUT/pool/mustra-dummy_${V}_all.deb" "$OUT/repo/"
cd "$OUT/repo" && dpkg-scanpackages --multiversion . /dev/null > Packages 2>/dev/null && gzip -kf Packages
echo "published $V"
