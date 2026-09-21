#!/usr/bin/env bash
# Open a built disk image the way a user's Mac would and hold it to what it
# claims.
#
#   packaging/macos/verify-dmg.sh --dmg dist/cairn-v1.4.0-macos-universal.dmg \
#       --version v1.4.0 [--tagged] [--install]
#
# Without --install this changes nothing outside a temporary directory, so it
# is safe on a developer's machine: it mounts the image read-only, takes the
# installer apart, and runs the binary it finds inside.
#
#   --tagged    this is a release and not a dry run, so the binary must report
#               --version as well. A dry run packages a real binary under
#               `0.0.0-dispatch.N`, and the binary rightly does not agree.
#   --install   actually install it, with sudo, then remove it again with the
#               commands the README gives. For CI, where the machine is
#               disposable. It is the only test of two claims that cannot be
#               checked any other way: that installing leaves the ownership of
#               /usr/local/bin alone, and that `installer` accepts this package
#               from a terminal when Gatekeeper would refuse a double-click.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=packaging/version.sh
. "$HERE/../version.sh"

say()  { echo "==> $*"; }
fail() { echo "verify: $*" >&2; exit 1; }

IDENTIFIER="org.cairn.cli"
DMG="" VERSION="" TAGGED=0 INSTALL=0
while [ $# -gt 0 ]; do
    case "$1" in
        --dmg)     [ $# -ge 2 ] || fail "--dmg needs a value";     DMG="$2";     shift 2 ;;
        --version) [ $# -ge 2 ] || fail "--version needs a value"; VERSION="$2"; shift 2 ;;
        --tagged)  TAGGED=1; shift ;;
        --install) INSTALL=1; shift ;;
        --help|-h) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[ -f "$DMG" ]     || fail "no disk image at '$DMG'"
[ -n "$VERSION" ] || fail "--version is required"
cairn_versions "$VERSION"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-packaging.XXXXXX")"
MNT="$WORK/mnt"
mkdir -p "$MNT"
cleanup() {
    hdiutil detach -quiet "$MNT" 2>/dev/null || hdiutil detach -quiet -force "$MNT" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# Anything a template left unfilled reaches a user as literal `@VERSION@`.
no_placeholders() {
    if grep -n '@[A-Z_][A-Z_]*@' "$1" >/dev/null; then
        grep -n '@[A-Z_][A-Z_]*@' "$1" >&2
        fail "$2 still has unfilled placeholders"
    fi
}

# -- the image ------------------------------------------------------------------
say "checking the image's own checksum"
hdiutil verify -quiet "$DMG" || fail "hdiutil says the image is damaged"

hdiutil attach -quiet -nobrowse -readonly -noautoopen -mountpoint "$MNT" "$DMG" \
    || fail "the image does not mount"

PKG="$MNT/Install Cairn.pkg"
for want in "Install Cairn.pkg" "README.txt" "LICENSE.txt"; do
    [ -f "$MNT/$want" ] || fail "the image has no '$want'"
done
# Exactly those three. Whatever else is in the staging directory when hdiutil
# runs ships to every user, and a stray file is how a build directory leaks.
extra="$(find "$MNT" -mindepth 1 -maxdepth 1 ! -name '.*' \
    ! -name 'Install Cairn.pkg' ! -name 'README.txt' ! -name 'LICENSE.txt' | head -n 5)"
[ -z "$extra" ] || fail "the image holds something it should not: $extra"

no_placeholders "$MNT/README.txt" "the image's README"
grep -q "$UPSTREAM_VERSION" "$MNT/README.txt" || fail "the README does not name version $UPSTREAM_VERSION"
cmp -s "$MNT/LICENSE.txt" "$REPO/LICENSE" || fail "the image's LICENSE is not the repository's"

# -- the installer, taken apart ---------------------------------------------------
say "expanding the installer"
X="$WORK/expanded"
pkgutil --expand-full "$PKG" "$X" || fail "pkgutil cannot expand the installer"
COMPONENT="$X/cairn-cli.pkg"
BIN="$COMPONENT/Payload/bin/cairn"
[ -f "$X/Distribution" ]       || fail "no Distribution file; this is a bare component, not an installer"
[ -f "$COMPONENT/PackageInfo" ] || fail "no component package named cairn-cli.pkg inside"
[ -x "$BIN" ]                   || fail "the payload has no executable bin/cairn"

no_placeholders "$X/Distribution" "the Distribution file"
for page in welcome.html conclusion.html; do
    [ -f "$X/Resources/$page" ] || fail "the installer is missing its $page"
    no_placeholders "$X/Resources/$page" "$page"
done

grep -q 'install-location="/usr/local/cairn"' "$COMPONENT/PackageInfo" \
    || fail "the payload does not install to /usr/local/cairn"
grep -q "identifier=\"$IDENTIFIER\"" "$COMPONENT/PackageInfo" \
    || fail "the receipt identifier is not $IDENTIFIER"

# The guard for the design decision in `postinstall`. Every directory a payload
# names has its owner and mode forced onto the installed system, so the payload
# may name nothing but its own prefix. `._` entries are how the archive carries
# extended attributes; they are applied to the file beside them and never become
# files themselves, which the `find` below confirms.
paths="$(lsbom -s "$COMPONENT/Bom" | grep -v '/\._' | LC_ALL=C sort | tr '\n' ' ')"
[ "$paths" = ". ./bin ./bin/cairn " ] \
    || fail "the payload names paths outside its own prefix: $paths"
[ -z "$(find "$COMPONENT/Payload" -name '._*' | head -n 1)" ] \
    || fail "AppleDouble files would be installed as real files"

POST="$COMPONENT/Scripts/postinstall"
[ -x "$POST" ] || fail "no executable postinstall; nothing would put cairn on PATH"
sh -n "$POST"  || fail "postinstall does not parse"

# -- postinstall, run for real against a directory that stands in for a volume --
#
# It takes the target volume as $3, so it can be pointed at a scratch tree and
# run without root. The tree is given a /usr/local/bin with a mode no installer
# would choose, because the claim under test is that an *existing* directory is
# left exactly as it was found -- twice, since an upgrade runs it again over
# its own link.
say "running postinstall against a scratch volume"
FAKE="$WORK/volume"
mkdir -p "$FAKE/usr/local/bin"
chmod 0775 "$FAKE/usr/local/bin"
for pass in first upgrade; do
    sh "$POST" "$PKG" /usr/local/cairn "$FAKE" / || fail "postinstall failed on the $pass run"
    [ -L "$FAKE/usr/local/bin/cairn" ] || fail "postinstall made no link ($pass run)"
    [ "$(readlink "$FAKE/usr/local/bin/cairn")" = "/usr/local/cairn/bin/cairn" ] \
        || fail "the link points at $(readlink "$FAKE/usr/local/bin/cairn") ($pass run)"
    [ "$(stat -f '%Lp' "$FAKE/usr/local/bin")" = "775" ] \
        || fail "postinstall changed the mode of an existing /usr/local/bin ($pass run)"
done

# -- the binary -----------------------------------------------------------------
ARCHS="$(lipo -archs "$BIN")"
say "the binary holds: $ARCHS"
declared="$(sed -n 's/.*hostArchitectures="\([^"]*\)".*/\1/p' "$X/Distribution")"
have="$(printf '%s' "$ARCHS" | tr ' ' '\n' | LC_ALL=C sort | paste -sd, -)"
# Claim too few and Installer offers Rosetta to a Mac that does not need it;
# claim too many and it installs a binary the Mac cannot run.
[ "$declared" = "$have" ] \
    || fail "the installer says it supports '$declared' and the binary holds '$have'"
case "$DMG" in
    *-macos-universal.dmg) [ "$have" = "arm64,x86_64" ] || fail "named universal, holds only: $ARCHS" ;;
esac

codesign --verify --strict "$BIN" || fail "the binary's signature does not verify"

say "cairn --version"
"$BIN" --version
# `cairn run` is what the installer's last page tells a new user to type, and
# it refuses to start in a binary built without the `ui` feature. That build
# compiles, runs and audits perfectly well, so nothing else here would notice.
"$BIN" --version | grep -Eq '^[[:space:]]*ui[[:space:]]+embedded' \
    || fail "this binary has no embedded reader, so \`cairn run\` refuses to start. Build with \`make ui-build\`."
if [ "$TAGGED" -eq 1 ]; then
    line="$("$BIN" --version | head -n 1)"
    [ "$line" = "cairn $UPSTREAM_VERSION" ] \
        || fail "the image is $UPSTREAM_VERSION and the binary inside it says '$line'"
fi

# The slice this machine does not run natively. The build job tested each
# architecture on its own runner before lipo touched it, and lipo only prefixes
# a header -- but "only" is the word this test exists to check.
case "$(uname -m):$have" in
    arm64:arm64,x86_64)
        if arch -x86_64 /usr/bin/true 2>/dev/null; then
            arch -x86_64 "$BIN" --version >/dev/null || fail "the x86_64 slice does not run under Rosetta"
            say "the x86_64 slice runs under Rosetta"
        else
            say "NOT CHECKED: no Rosetta on this machine, so the x86_64 slice was not run"
        fi
        ;;
    x86_64:arm64,x86_64)
        say "NOT CHECKED: an Intel Mac cannot run the arm64 slice"
        ;;
esac

say "auditing the published launch log with the binary from the image"
"$BIN" --log "$REPO/launch/cairn.jsonl" --root "$REPO" audit

# -- and, in CI, the real thing ----------------------------------------------------
if [ "$INSTALL" -eq 1 ]; then
    before="absent"
    [ -d /usr/local/bin ] && before="$(stat -f '%Su:%Sg %Lp' /usr/local/bin)"

    # As a browser would leave it. A file fetched with curl carries no
    # quarantine mark, so without this the test would pass on a machine where
    # the command in the README is refused for every real user.
    cp "$PKG" "$WORK/Install Cairn.pkg"
    xattr -w com.apple.quarantine "0083;$(printf '%x' "$(date +%s)");Safari;" "$WORK/Install Cairn.pkg"

    say "installing (sudo installer, on a quarantined copy)"
    sudo installer -pkg "$WORK/Install Cairn.pkg" -target / \
        || fail "\`sudo installer\` refused the package; the README tells users to run exactly that"

    [ -L /usr/local/bin/cairn ] || fail "/usr/local/bin/cairn is not a link after installing"
    [ "$(readlink /usr/local/bin/cairn)" = "/usr/local/cairn/bin/cairn" ] || fail "the link points elsewhere"
    [ "$(stat -f '%Su:%Sg %Lp' /usr/local/cairn/bin/cairn)" = "root:wheel 755" ] \
        || fail "the installed binary is $(stat -f '%Su:%Sg %Lp' /usr/local/cairn/bin/cairn), not root:wheel 755"
    /usr/local/bin/cairn --version >/dev/null || fail "the installed binary does not run"
    pkgutil --pkg-info "$IDENTIFIER" | grep -q "^version: $MACOS_PKG_VERSION\$" \
        || fail "the receipt does not say version $MACOS_PKG_VERSION"

    if [ "$before" != "absent" ]; then
        after="$(stat -f '%Su:%Sg %Lp' /usr/local/bin)"
        [ "$before" = "$after" ] \
            || fail "installing changed /usr/local/bin from '$before' to '$after' -- this is the Homebrew breakage postinstall exists to avoid"
        say "/usr/local/bin is still $after"
    fi

    say "removing, with the commands the README gives"
    sudo rm -rf /usr/local/cairn /usr/local/bin/cairn
    sudo pkgutil --forget "$IDENTIFIER" >/dev/null
    if [ -e /usr/local/cairn ] || [ -L /usr/local/bin/cairn ]; then
        fail "the documented removal left something behind"
    fi
    if pkgutil --pkg-info "$IDENTIFIER" >/dev/null 2>&1; then
        fail "the receipt survived \`pkgutil --forget\`"
    fi
fi

say "ok: $(basename "$DMG") mounts, its installer is well formed, and the binary inside runs and audits the published log"
