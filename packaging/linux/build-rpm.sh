#!/usr/bin/env bash
# Build an .rpm around a cairn binary that already exists.
#
#   packaging/linux/build-rpm.sh \
#       --binary target/x86_64-unknown-linux-musl/release/cairn \
#       --version v1.4.0 --arch amd64 [--out dist]
#
# The same contract as build-deb.sh, which says why: the input is the binary
# release.yml already tested, and the output installs those bytes unchanged.
#
# `--arch` takes Debian's names (amd64, arm64) here too, and this script
# translates. One vocabulary in the workflow matrix rather than two, because
# the place an `aarch64` gets written where an `arm64` was meant is a matrix
# that has to remember which script wanted which.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=packaging/version.sh
. "$HERE/../version.sh"
# shellcheck source=packaging/linux/common.sh
. "$HERE/common.sh"

BINARY="" VERSION="" ARCH="" OUT="dist"
while [ $# -gt 0 ]; do
    case "$1" in
        --binary)  [ $# -ge 2 ] || die "--binary needs a value";  BINARY="$2";  shift 2 ;;
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
        --arch)    [ $# -ge 2 ] || die "--arch needs a value";    ARCH="$2";    shift 2 ;;
        --out)     [ $# -ge 2 ] || die "--out needs a value";     OUT="$2";     shift 2 ;;
        --help|-h) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$BINARY" ]  || die "--binary is required"
[ -n "$VERSION" ] || die "--version is required"
case "$ARCH" in
    amd64) RPM_ARCH=x86_64 ;;
    arm64) RPM_ARCH=aarch64 ;;
    *) die "--arch must be amd64 or arm64, not '$ARCH'" ;;
esac
command -v rpmbuild >/dev/null 2>&1 \
    || die "rpmbuild not found. On Debian and Ubuntu it is in the 'rpm' package; on Fedora, 'rpm-build'."

cairn_versions "$VERSION"
require_arch "$BINARY" "$ARCH"
require_static "$BINARY"
pin_build_time "$REPO"

# rpmbuild resolves the macros below from inside its own build directory, so a
# relative --binary would be looked for there.
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

TOP="$(mktemp -d "${TMPDIR:-/tmp}/cairn-packaging.XXXXXX")"
trap 'rm -rf "$TOP"' EXIT

# `_topdir` keeps the whole build under the temporary directory. Its default is
# ~/rpmbuild, which on a developer's machine is somebody's real work.
#
# The three reproducibility defines go together. rpm stamps a package with the
# time and the host it was built on; without these, two builds of one tag
# differ by the clock and by which runner picked up the job, and every
# release's .rpm would carry the hostname of a machine nobody chose.
rpmbuild -bb --quiet \
    --target "$RPM_ARCH" \
    --define "_topdir $TOP" \
    --define "_buildhost cairn-release" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "cairn_version $RPM_VERSION" \
    --define "cairn_release $RPM_RELEASE" \
    --define "cairn_binary $BINARY" \
    --define "cairn_repo $REPO" \
    --define "cairn_homepage $HOMEPAGE" \
    --define "cairn_maintainer $MAINTAINER" \
    "$HERE/cairn.spec"

BUILT="$TOP/RPMS/$RPM_ARCH/cairn-$RPM_VERSION-$RPM_RELEASE.$RPM_ARCH.rpm"
[ -f "$BUILT" ] || die "rpmbuild reported success and left no package at $BUILT"

# As build-deb.sh does for its archive: the spec asks for gzip, and this
# confirms it got gzip, since nothing in the install test runs an rpm old
# enough to mind.
compressor="$(rpm -qp --qf '%{PAYLOADCOMPRESSOR}' "$BUILT")"
[ "$compressor" = "gzip" ] || die "the payload is compressed with '$compressor', not gzip; see cairn.spec"

# docs/threat-model.md says installing this package runs nothing as root. Held
# to it here: a %post or a trigger added to the spec fails the build until
# somebody also changes that row.
scripts="$(rpm -qp --scripts --triggers "$BUILT")"
[ -z "$scripts" ] || die "the package carries scriptlets or triggers, and is documented as carrying none:
$scripts"

mkdir -p "$OUT"
RPM="$OUT/$(basename "$BUILT")"
cp "$BUILT" "$RPM"

echo "built $RPM"
rpm -qip "$RPM" | sed 's/^/    /'
rpm -qlpv "$RPM" | sed 's/^/    /'
echo "    recommends: $(rpm -qp --recommends "$RPM" | tr '\n' ' ')"
