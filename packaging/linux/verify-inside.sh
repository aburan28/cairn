#!/bin/sh
# Runs *inside* a clean distribution container, as root. verify.sh starts it
# and documents the variables it reads; nothing else should.
#
# POSIX sh, because the images this runs in agree on nothing else.
set -eu

say()  { echo "==> $*"; }
fail() { echo "verify: $*" >&2; exit 1; }

: "${FORMAT:?}" "${PKG_FILE:?}" "${EXPECT_PKG_VERSION:?}"

# -- install, with the command the documentation gives ----------------------
#
# Through the package manager and not `dpkg -i` / `rpm -i`, because those skip
# dependency resolution entirely: a control file naming a package that does not
# exist installs fine that way, and fails for every real user.
say "installing $PKG_FILE"
case "$FORMAT" in
    deb)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq "/pkg/$PKG_FILE" >/dev/null
        got="$(dpkg-query -W -f='${Version}' cairn)"
        ;;
    rpm)
        dnf install -y -q "/pkg/$PKG_FILE" >/dev/null
        got="$(rpm -q --qf '%{VERSION}-%{RELEASE}' cairn)"
        ;;
    *) fail "unknown FORMAT '$FORMAT'" ;;
esac
[ "$got" = "$EXPECT_PKG_VERSION" ] \
    || fail "the package manager says cairn is $got; the file name promised $EXPECT_PKG_VERSION"

# -- what landed, and as whom -----------------------------------------------
[ -x /usr/bin/cairn ] || fail "the package put no executable at /usr/bin/cairn"
found="$(command -v cairn)" || fail "cairn is not on PATH after installing"
# Compared as files, not as strings. Fedora made /usr/sbin a link to /usr/bin
# and still lists sbin first in PATH, so there `command -v cairn` truthfully
# answers /usr/sbin/cairn -- the same file by another name. The first version
# of this check compared the strings and failed a package that was fine.
[ "$(readlink -f "$found")" = "$(readlink -f /usr/bin/cairn)" ] \
    || fail "PATH finds $found, which is not the packaged /usr/bin/cairn"
perms="$(stat -c '%U:%G %a' /usr/bin/cairn)"
[ "$perms" = "root:root 755" ] \
    || fail "/usr/bin/cairn is '$perms', not root:root 755 -- the build recorded the runner's user"

# The property the builders exist to keep: what is installed is the file that
# was tested, not something a packaging step stripped, re-linked or rebuilt.
if [ -n "${EXPECT_SHA256:-}" ]; then
    have="$(sha256sum /usr/bin/cairn | cut -d' ' -f1)"
    [ "$have" = "$EXPECT_SHA256" ] \
        || fail "/usr/bin/cairn is not the binary that was packaged
       packaged  $EXPECT_SHA256
       installed $have"
    say "installed binary is byte-identical to the one that was tested"
fi

case "$FORMAT" in
    deb) [ -s /usr/share/doc/cairn/copyright ] || fail "no copyright file; Debian policy requires one" ;;
    rpm) [ -s /usr/share/licenses/cairn/LICENSE ] || fail "no licence file" ;;
esac

# The package manager's own integrity check, asked about the binary only.
# Container images are configured to skip documentation (dpkg path-excludes on
# Ubuntu, `tsflags=nodocs` on Fedora), so the changelog is legitimately absent
# here and both tools say so. That is the image's doing, not the package's.
case "$FORMAT" in
    deb) drift="$(dpkg --verify cairn 2>/dev/null | grep ' /usr/bin/cairn$' || true)" ;;
    rpm) drift="$(rpm -V cairn 2>/dev/null | grep ' /usr/bin/cairn$' || true)" ;;
esac
[ -z "$drift" ] || fail "the package manager's own check disagrees with the installed binary: $drift"

# -- the weak dependencies are declared --------------------------------------
case "$FORMAT" in
    deb) rec="$(dpkg-query -W -f='${Recommends}' cairn)" ;;
    rpm) rec="$(rpm -q --recommends cairn | tr '\n' ' ')" ;;
esac
for want in bubblewrap python3; do
    case "$rec" in
        *"$want"*) ;;
        *) fail "the package does not recommend $want (it recommends: $rec)" ;;
    esac
done

# -- it runs -----------------------------------------------------------------
say "cairn --version"
cairn --version
# `cairn run` is the first thing the documentation tells a new user to type,
# and it refuses to start in a binary built without the `ui` feature. That
# build compiles, runs and audits perfectly well, so nothing else here would
# notice.
cairn --version | grep -Eq '^[[:space:]]*ui[[:space:]]+embedded' \
    || fail "this binary has no embedded reader, so \`cairn run\` refuses to start. Build with \`--features ui\`."
if [ -n "${EXPECT_CAIRN_VERSION:-}" ]; then
    line="$(cairn --version | head -n 1)"
    # On a tag, the tag and Cargo.toml must be the same number. release-please
    # writes both, so this only fires for a tag pushed by hand over a manifest
    # nobody bumped -- which is exactly the release that should not go out.
    [ "$line" = "cairn $EXPECT_CAIRN_VERSION" ] \
        || fail "the package is $EXPECT_CAIRN_VERSION and the binary inside it says '$line'"
fi

# Recommends are installed by default, but "by default" is the image's to
# change, and some do. Said out loud rather than papered over, because a
# reader of this log should not conclude the package pulled python3 in when
# the test did.
if ! command -v python3 >/dev/null 2>&1; then
    say "this image does not install weak dependencies; installing python3 for the audit"
    case "$FORMAT" in
        deb) apt-get install -y -qq python3 >/dev/null ;;
        rpm) dnf install -y -q python3 >/dev/null ;;
    esac
fi

# One real check and not just a version string: re-derive the published log,
# the way somebody who had just installed this would be told to. A container
# cannot usually create the namespace bubblewrap needs, so expect the node to
# say it is running verifiers unconfined; that is the container, and the audit
# result does not depend on it.
say "auditing the published launch log with the installed binary"
cairn --log /repo/launch/cairn.jsonl --root /repo audit

# -- and it leaves ------------------------------------------------------------
say "removing"
case "$FORMAT" in
    deb) apt-get remove -y -qq cairn >/dev/null ;;
    rpm) dnf remove -y -q cairn >/dev/null ;;
esac
[ ! -e /usr/bin/cairn ] || fail "/usr/bin/cairn survived removal"

say "ok: $PKG_FILE installs, runs, audits the published log, and removes cleanly"
