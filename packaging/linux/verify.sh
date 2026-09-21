#!/usr/bin/env bash
# Install a built package in a clean container and hold it to what it claims.
#
#   packaging/linux/verify.sh --package dist/cairn_1.4.0-1_amd64.deb \
#       --version v1.4.0 --image debian:12 \
#       [--binary path/to/the/binary/that/was/packaged] [--tagged]
#
# A package that builds is not a package that installs. `dpkg-deb --build` will
# happily produce an archive whose control file names a dependency that does
# not exist, whose compression the target cannot read, or whose binary is for
# another architecture -- and every one of those is discovered by the first
# operator to run `apt install`, after the release is public. So the install
# is run here first, by the distribution's own package manager, in an image
# with nothing else in it.
#
#   --binary   the file that was handed to the builder. When given, the
#              installed /usr/bin/cairn must be byte-identical to it.
#   --tagged   this is a release and not a dry run, so `cairn --version` must
#              report --version too. A dry run packages a real binary under
#              `0.0.0-dispatch.N`, and the binary rightly does not agree.
#
# Needs docker. The container is the whole point: the question is what happens
# on a machine that has never seen this project.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=packaging/version.sh
. "$HERE/../version.sh"
# shellcheck source=packaging/linux/common.sh
. "$HERE/common.sh"

PACKAGE="" VERSION="" IMAGE="" BINARY="" TAGGED=0
while [ $# -gt 0 ]; do
    case "$1" in
        --package) [ $# -ge 2 ] || die "--package needs a value"; PACKAGE="$2"; shift 2 ;;
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
        --image)   [ $# -ge 2 ] || die "--image needs a value";   IMAGE="$2";   shift 2 ;;
        --binary)  [ $# -ge 2 ] || die "--binary needs a value";  BINARY="$2";  shift 2 ;;
        --tagged)  TAGGED=1; shift ;;
        --help|-h) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -f "$PACKAGE" ] || die "no package at '$PACKAGE'"
[ -n "$VERSION" ] || die "--version is required"
[ -n "$IMAGE" ]   || die "--image is required"
command -v docker >/dev/null 2>&1 || die "docker not found; this test is an install into a clean image"

cairn_versions "$VERSION"
case "$PACKAGE" in
    *.deb) FORMAT=deb; EXPECT_PKG_VERSION="$DEB_VERSION" ;;
    *.rpm) FORMAT=rpm; EXPECT_PKG_VERSION="$RPM_VERSION-$RPM_RELEASE" ;;
    *) die "'$PACKAGE' is neither a .deb nor an .rpm" ;;
esac

EXPECT_SHA256=""
if [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] || die "no binary at '$BINARY'"
    if command -v sha256sum >/dev/null 2>&1; then
        EXPECT_SHA256="$(sha256sum "$BINARY" | cut -d' ' -f1)"
    else
        EXPECT_SHA256="$(shasum -a 256 "$BINARY" | cut -d' ' -f1)"
    fi
fi

EXPECT_CAIRN_VERSION=""
[ "$TAGGED" -eq 0 ] || EXPECT_CAIRN_VERSION="$UPSTREAM_VERSION"

PKG_DIR="$(cd "$(dirname "$PACKAGE")" && pwd)"
PKG_FILE="$(basename "$PACKAGE")"

echo "verifying $PKG_FILE in $IMAGE"
# Both mounts read-only. The package under test must not be able to pass by
# editing the repository it is audited against, and `cairn audit` writes
# nothing -- which is itself worth having a test notice if it ever stops
# being true.
docker run --rm \
    -v "$PKG_DIR:/pkg:ro" \
    -v "$REPO:/repo:ro" \
    -e FORMAT="$FORMAT" \
    -e PKG_FILE="$PKG_FILE" \
    -e EXPECT_PKG_VERSION="$EXPECT_PKG_VERSION" \
    -e EXPECT_SHA256="$EXPECT_SHA256" \
    -e EXPECT_CAIRN_VERSION="$EXPECT_CAIRN_VERSION" \
    "$IMAGE" sh /repo/packaging/linux/verify-inside.sh
