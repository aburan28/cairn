#!/usr/bin/env bash
# Build a .deb around a cairn binary that already exists.
#
#   packaging/linux/build-deb.sh \
#       --binary target/x86_64-unknown-linux-musl/release/cairn \
#       --version v1.4.0 --arch amd64 [--out dist]
#
# Nothing is compiled here, and that is the design. `release.yml` builds each
# target once, unpacks the tarball it made, and proves *that* binary serves the
# reader and audits the published log. This script wraps those same bytes, so
# what a package installs is what was tested -- `verify.sh` compares the digest
# of /usr/bin/cairn to the input's to hold it to that. A packager that ran its
# own `cargo build` would ship a second binary nothing had exercised.
#
# `dpkg-deb` and nothing else: no debhelper, no cargo-deb, no nfpm. A package
# that is one static file and two documents does not need a build system, and a
# third-party tool fetched at release time is one more thing to pin, and one
# more party whose bytes end up in a release.
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
    amd64|arm64) ;;
    *) die "--arch must be amd64 or arm64, not '$ARCH'" ;;
esac
command -v dpkg-deb >/dev/null 2>&1 \
    || die "dpkg-deb not found. It ships with every Debian and Ubuntu; elsewhere, install dpkg."

cairn_versions "$VERSION"
require_arch "$BINARY" "$ARCH"
require_static "$BINARY"
pin_build_time "$REPO"

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/cairn-packaging.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT

DOC="$STAGE/usr/share/doc/cairn"
install -D -m 0755 "$BINARY" "$STAGE/usr/bin/cairn"
mkdir -p "$DOC" "$STAGE/DEBIAN"

# Policy wants the licence at exactly this path, in this machine-readable form.
# Apache-2.0 is in /usr/share/common-licenses on every Debian system, so the
# file points there rather than carrying eleven kilobytes of it again.
cat >"$DOC/copyright" <<EOF
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: cairn
Source: $HOMEPAGE

Files: *
Copyright: the cairn authors
License: Apache-2.0
 Licensed under the Apache License, Version 2.0 (the "License"); you may not
 use this software except in compliance with the License.
 .
 On Debian systems, the complete text of the Apache License, Version 2.0 can
 be found in /usr/share/common-licenses/Apache-2.0.
EOF

# `-n` keeps gzip from writing the time and the file name into its header. With
# them in, two builds of one tag differ in a changelog nobody edited.
gzip -9n <"$REPO/CHANGELOG.md" >"$DOC/changelog.gz"
chmod 0644 "$DOC/copyright" "$DOC/changelog.gz"

# mktemp makes its directory 0700, and dpkg-deb records the mode of every
# directory it is handed, the root of the tree included. Left alone, the
# package carries `./` as 0700 and every directory under it at whatever the
# caller's umask allowed.
find "$STAGE" -type d -exec chmod 0755 {} +

# What `dpkg --verify cairn` checks an installed copy against. Optional as far
# as dpkg is concerned; not optional for a project whose pitch is that you can
# check things. Sorted, so the file does not depend on directory order.
( cd "$STAGE" && find usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum ) \
    >"$STAGE/DEBIAN/md5sums"

# Recommends, not Depends, for both -- deliberately, and for the same reason.
#
# bubblewrap is the jail objective-authored verifier code runs in, and python3
# is what most pinned verifiers are written in: without it `cairn audit` on the
# published launch log reports four claims it "can no longer re-verify". So a
# node wants both, and apt installs Recommends unless told not to.
#
# But `cairn check` needs no log at all, `prove`, `verify` and `audit
# --no-rerun` never run a verifier, and a light client that only checks proofs
# is a use this project argues for. A hard dependency would make that client
# install an interpreter and a namespace tool it never calls, and would make
# the package uninstallable in a container image that has neither.
#
# No Depends at all, because there is nothing to depend on: `require_static`
# above is what makes that true rather than hopeful.
cat >"$STAGE/DEBIAN/control" <<EOF
Package: cairn
Version: $DEB_VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $(du -sk "$STAGE/usr" | cut -f1)
Recommends: bubblewrap, python3
Section: net
Priority: optional
Homepage: $HOMEPAGE
Description: research network where verified results are the unit of account
 One binary. The CLI, the MCP server (cairn mcp), the p2p daemon (cairn p2p),
 the HTTP publisher (cairn serve) and the complete local node (cairn run,
 which also serves the embedded reader) are subcommands of it.
 .
 Anyone can independently re-derive every settled result from the log alone:
 "cairn audit" re-runs each objective's pinned verifier against the artifact
 that claimed its bounty, and trusts neither the operator nor the server the
 log came from.
 .
 Statically linked, so it has no library dependencies and runs on any release
 of any distribution. It installs no service and creates no user: a node's
 state lives wherever the operator starts it.
EOF

mkdir -p "$OUT"
DEB="$OUT/cairn_${DEB_VERSION}_${ARCH}.deb"

# `-Zxz`, said out loud, because the default is not the same everywhere and the
# difference is invisible on the machine that builds the package.
#
# Ubuntu's dpkg-deb has compressed with zstd since 21.10, and the release
# runner is Ubuntu. Debian's dpkg could not *read* zstd until 1.21.18 --
# bookworm -- so a .deb built here with the default installs on every Ubuntu
# and fails on Debian 11 with "archive uses unknown compression for member
# 'control.tar.zst'". xz has been readable everywhere since 2014, and on seven
# megabytes the difference in size is not worth a support matrix.
#
# `--root-owner-group` records root:root without fakeroot and without sudo;
# otherwise the files would be owned by whatever uid the runner happened to be.
dpkg-deb --root-owner-group -Zxz --build "$STAGE" "$DEB" >/dev/null

# Checked in the artifact, because no image in the install test would notice:
# every distribution still supported reads zstd, so a package that quietly went
# back to it would install everywhere it is tested and fail only where it is
# not. The member names sit in the ar header as plain text.
if ! LC_ALL=C grep -aq 'control\.tar\.xz' "$DEB" || LC_ALL=C grep -aq '\.tar\.zst' "$DEB"; then
    die "$DEB is not xz-compressed throughout; dpkg older than 1.21.18 could not open it"
fi

# docs/threat-model.md says installing this package runs nothing as root, and
# this is what holds it to that. A `postinst` dropped into the staging tree --
# by a later change here, or by a helper that thought it was being useful --
# would otherwise ship without anyone having decided it should.
control_files="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -t | sed 's|^\./||' | grep -v '^$' | LC_ALL=C sort | tr '\n' ' ')"
[ "$control_files" = "control md5sums " ] \
    || die "the control archive holds more than control and md5sums: $control_files"

echo "built $DEB"
dpkg-deb --info "$DEB" | sed 's/^/    /'
dpkg-deb --contents "$DEB" | sed 's/^/    /'
