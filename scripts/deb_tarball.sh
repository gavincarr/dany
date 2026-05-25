#!/usr/bin/env bash
# Package the current source tree as a Debian-build tarball:
# pre-built static binaries + debian/ + LICENCE + README, ready for
# `dpkg-buildpackage -b` on a repo machine.
#
# Usage: scripts/deb_tarball.sh
#
# The version is read from debian/changelog (the single source of truth
# established by scripts/release.sh — same as internal/version/VERSION
# after a release). Output: dist/deb/dany_<version>.tar.gz, holding a
# top-level dany-<version>/ directory.
#
# Workflow on the repo/build machine:
#   tar xzf dany_<version>.tar.gz
#   cd dany-<version>
#   dpkg-buildpackage -b -us -uc

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null && pwd)"
cd "$ROOT"

if ! command -v dpkg-parsechangelog >/dev/null; then
    echo "error: dpkg-parsechangelog not found (install dpkg-dev)" >&2
    exit 1
fi

VERSION="$(dpkg-parsechangelog -l debian/changelog -SVersion)"
PKG="dany"
STAGE_NAME="${PKG}-${VERSION}"
STAGE_DIR="dist/deb/${STAGE_NAME}"
TARBALL="dist/deb/${PKG}_${VERSION}.tar.gz"

echo "+ building binaries (CGO_ENABLED=0 via scripts/build_all.sh)"
scripts/build_all.sh

echo "+ staging $STAGE_DIR"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin"

# Copy each binary then strip the copy (leave the dev bin/ tree intact
# with its debug info — the stripped artifacts only live inside the
# tarball).
for bin in bin/dany bin/dnx; do
    name="$(basename "$bin")"
    cp "$bin" "$STAGE_DIR/bin/$name"
    strip --strip-unneeded "$STAGE_DIR/bin/$name"
done

# Packaging metadata + user-facing docs that ship in the source tarball.
cp -r debian "$STAGE_DIR/"
cp LICENCE README.md "$STAGE_DIR/"

echo "+ creating $TARBALL"
tar -C dist/deb -czf "$TARBALL" "$STAGE_NAME"

echo
echo "Tarball: $TARBALL"
echo "Staged tree:"
ls -lh "$STAGE_DIR/bin"
echo
echo "On the build machine:"
echo "  tar xzf $(basename "$TARBALL")"
echo "  cd ${STAGE_NAME}"
echo "  dpkg-buildpackage -b -us -uc"
