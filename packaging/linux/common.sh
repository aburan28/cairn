# shellcheck shell=bash
# Sourced by build-deb.sh and build-rpm.sh: the checks both make before they
# put a label on a binary, written once so the two cannot come to disagree
# about what they are willing to package.

die() { echo "packaging: $*" >&2; exit 1; }

# Who a package manager tells the operator to write to. A GitHub address rather
# than a person's, because this string is copied into every machine that
# installs the package and nobody can take it back out. CAIRN_MAINTAINER
# overrides it for a fork, which is somebody else's package and should say so.
#
# Both are read by whichever builder sourced this; shellcheck, looking at this
# file alone, cannot see that.
# shellcheck disable=SC2034
MAINTAINER="${CAIRN_MAINTAINER:-cairn maintainers <aburan28@users.noreply.github.com>}"
# shellcheck disable=SC2034
HOMEPAGE="https://github.com/aburan28/cairn"

# The architecture a binary was built for, in Debian's vocabulary, read out of
# the ELF header rather than out of the path it was found at.
#
# A path is a claim. `target/aarch64-unknown-linux-musl/release/cairn` is
# wherever the caller says it is, and a workflow that downloads the wrong
# artifact produces an `_arm64.deb` that installs cleanly everywhere and runs
# nowhere -- "Exec format error", on the operator's machine, after the release
# is public. e_machine is two little-endian bytes at offset 18, and `od` is in
# POSIX, so this needs neither `file` nor binutils.
elf_arch() {
    local magic machine
    magic="$(od -An -tx1 -N4 "$1" | tr -d ' \n')"
    [ "$magic" = "7f454c46" ] || { echo "not-elf"; return 0; }
    machine="$(od -An -tx1 -j18 -N2 "$1" | tr -d ' \n')"
    case "$machine" in
        3e00) echo amd64 ;;
        b700) echo arm64 ;;
        *)    echo "unknown-$machine" ;;
    esac
}

# Refuse a binary that needs a dynamic loader.
#
# Both packages declare no library dependency at all, and that is only true of
# the musl build. Package the glibc one by mistake and the result installs on
# any distribution and then fails on every one older than the build runner with
# a symbol-version error -- the exact failure shipping musl exists to prevent,
# now hidden behind a package manager that reported success.
#
# PT_INTERP is what makes a binary dynamic, so that is what is looked for. A
# static-pie binary (what x86_64 musl produces) still has a PT_DYNAMIC segment
# and `file` still calls it "pie", so neither of those is the test.
require_static() {
    local bin="$1"
    # On its own account, not because require_arch happens to run first: asked
    # about a file that is not there, `file` prints an error that does not
    # contain the words "dynamically linked", and that would read as a pass.
    [ -f "$bin" ] || die "no binary at $bin"
    if command -v readelf >/dev/null 2>&1; then
        if readelf -lW "$bin" | grep -q 'INTERP'; then
            die "$bin is dynamically linked; these packages declare no dependencies, so they take the musl build"
        fi
    elif command -v file >/dev/null 2>&1; then
        if file -b "$bin" | grep -q 'dynamically linked'; then
            die "$bin is dynamically linked; these packages declare no dependencies, so they take the musl build"
        fi
    else
        # Not skipped. The check is the only thing standing between a wrong
        # artifact and a published package, so a host that cannot run it is a
        # host that cannot build one.
        die "need readelf (binutils) or file to confirm $bin is statically linked"
    fi
}

# Check the binary against the architecture the caller asked for, and say which
# was wrong when they differ.
require_arch() {
    local bin="$1" want="$2" got
    [ -f "$bin" ] || die "no binary at $bin"
    got="$(elf_arch "$bin")"
    [ "$got" = "$want" ] \
        || die "$bin is $got, and --arch says $want. Nothing was packaged."
}

# File times inside a package, pinned to the commit rather than to the clock.
#
# dpkg-deb and rpmbuild both honour SOURCE_DATE_EPOCH. Without it, two builds
# of one tag differ in nothing but their timestamps, and "the checksum changed"
# stops meaning that the contents did. The commit time is the obvious value: it
# is the same on every runner and says when these bytes became what they are.
# Outside a git checkout there is no such time, and the clock is all there is.
pin_build_time() {
    local repo="$1"
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
        SOURCE_DATE_EPOCH="$(git -C "$repo" log -1 --format=%ct 2>/dev/null || date +%s)"
    fi
    export SOURCE_DATE_EPOCH
}
