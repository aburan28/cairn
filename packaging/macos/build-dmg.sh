#!/usr/bin/env bash
# Build the macOS disk image: cairn binaries and Cairn.app in, one .dmg holding
# an installer package out.
#
#   packaging/macos/build-dmg.sh --version v1.4.0 \
#       --binary target/aarch64-apple-darwin/release/cairn \
#       --binary target/x86_64-apple-darwin/release/cairn \
#       --app gui/macos-app/build/Cairn.app [--out dist]
#
# Give it both architectures and the result is universal: one download for
# every Mac, and nobody has to know which chip they have. Give it one --binary
# (what `make dmg` does, since a laptop builds only its own architecture) and
# the image is named for that architecture and the installer claims no other.
#
# Like the Linux builders, nothing is compiled here. The inputs are the
# binaries release.yml already unpacked and tested, and the app
# gui/macos-app/build.sh built; the app must hold the same architectures as
# the binary it will run. Unlike them, the bytes that
# ship are not quite the bytes that were tested -- lipo wraps the two in a fat
# header and codesign re-signs the result -- so verify-dmg.sh runs the binary
# out of the finished image rather than trusting that.
#
# Why a .pkg inside the .dmg, and not an app to drag
# --------------------------------------------------
# cairn is two things on a Mac: a command, which needs to be on PATH, and
# Cairn.app (gui/macos-app), a window onto a node, which runs that command. A
# bundle dragged to /Applications puts nothing on PATH, and an app that ran a
# copy of the binary inside itself would be a second binary to keep in step
# with the first. So one installer puts both where they belong, as two
# component packages with two receipts -- `pkgutil --pkg-info org.cairn.cli`
# and `org.cairn.app` -- and, as far as anyone has checked, one Gatekeeper
# decision rather than two: Installer does not copy the package's quarantine
# mark onto what it writes, where a dragged app would ask again on its first
# launch. verify-dmg.sh --install checks that the installed app has no mark.
#
# The app is not the launcher in gui/macos. That one drives a source checkout
# (it looks for research/crypto-autoresearcher and bin/cairn under one), so
# shipped alone it would open onto a column of failed setup checks.
#
# Signing
# -------
# With none of the CAIRN_* signing variables set -- which is how every release
# has been built so far -- the binary is ad-hoc signed, the package is
# unsigned, and Gatekeeper will stop a user who double-clicks it. The README in
# the image says so, and says what to do. That is a worse experience than a
# notarized installer, and the honest one: notarization needs a paid Apple
# Developer ID this repository does not have.
#
# Set all five and the binary, the package and the image are signed, and the
# image is notarized and stapled:
#
#   CAIRN_CODESIGN_IDENTITY    "Developer ID Application: NAME (TEAM)"
#   CAIRN_INSTALLER_IDENTITY   "Developer ID Installer: NAME (TEAM)"
#   CAIRN_NOTARY_KEY           path to an App Store Connect API key (.p8)
#   CAIRN_NOTARY_KEY_ID        that key's id
#   CAIRN_NOTARY_ISSUER        the issuer id it belongs to
#
# **That path has never run.** It is Apple's documented sequence, written down
# here so the day a certificate exists is a day of adding secrets rather than
# of writing a release script under pressure -- but nothing has exercised it,
# and it should be dry-run with `workflow_dispatch` before a tag depends on it.
# Setting some of the five and not the rest is refused: a signed package that
# was never notarized is blocked exactly like an unsigned one, and looks done.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
# shellcheck source=packaging/version.sh
. "$HERE/../version.sh"

die() { echo "packaging: $*" >&2; exit 1; }

# The same prefix as the apps in gui/, so the receipts and bundle ids this
# project puts on a Mac sort together. APP_IDENTIFIER is also Cairn.app's
# CFBundleIdentifier, which the check below holds it to.
IDENTIFIER="org.cairn.cli"
APP_IDENTIFIER="org.cairn.app"

BINARIES=() VERSION="" OUT="dist" APP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --binary)  [ $# -ge 2 ] || die "--binary needs a value";  BINARIES+=("$2"); shift 2 ;;
        --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2";     shift 2 ;;
        --out)     [ $# -ge 2 ] || die "--out needs a value";     OUT="$2";         shift 2 ;;
        --app)     [ $# -ge 2 ] || die "--app needs a value";     APP="${2%/}";     shift 2 ;;
        --help|-h) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ "${#BINARIES[@]}" -ge 1 ] || die "--binary is required (once per architecture)"
[ -n "$VERSION" ] || die "--version is required"
# Required rather than optional: an image built without it would be the
# command-line-only installer again, under a README that promises an app.
[ -n "$APP" ] || die "--app is required: build it with gui/macos-app/build.sh (--universal for a universal image)"
[ -x "$APP/Contents/MacOS/Cairn" ] || die "$APP is not a built Cairn.app (no Contents/MacOS/Cairn)"
[ "$(uname -s)" = "Darwin" ] \
    || die "this needs macOS: lipo, pkgbuild, productbuild and hdiutil exist nowhere else"
for bin in "${BINARIES[@]}"; do
    [ -f "$bin" ] || die "no binary at $bin"
done

cairn_versions "$VERSION"

APP_ID="${CAIRN_CODESIGN_IDENTITY:-}"
INSTALLER_ID="${CAIRN_INSTALLER_IDENTITY:-}"
NOTARY_KEY="${CAIRN_NOTARY_KEY:-}"
NOTARY_KEY_ID="${CAIRN_NOTARY_KEY_ID:-}"
NOTARY_ISSUER="${CAIRN_NOTARY_ISSUER:-}"
SIGNED=0
if [ -n "$APP_ID$INSTALLER_ID$NOTARY_KEY$NOTARY_KEY_ID$NOTARY_ISSUER" ]; then
    if [ -z "$APP_ID" ] || [ -z "$INSTALLER_ID" ] || [ -z "$NOTARY_KEY" ] \
        || [ -z "$NOTARY_KEY_ID" ] || [ -z "$NOTARY_ISSUER" ]; then
        die "some signing variables are set and some are not. All five or none; see the header of $0."
    fi
    [ -f "$NOTARY_KEY" ] || die "CAIRN_NOTARY_KEY names no file: $NOTARY_KEY"
    SIGNED=1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-packaging.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"          # the payload, laid out relative to /usr/local/cairn
STAGE="$WORK/dmg"          # what a user sees when the image mounts
mkdir -p "$ROOT/bin" "$WORK/pkgs" "$WORK/scripts" "$WORK/app-scripts" "$WORK/resources" "$STAGE"

# -- one binary ---------------------------------------------------------------
#
# lipo refuses two inputs of the same architecture on its own, in plain words,
# so that mistake is left to it. A single input is copied rather than passed
# through `lipo -create`, which would wrap it in a fat header holding one slice.
if [ "${#BINARIES[@]}" -eq 1 ]; then
    cp "${BINARIES[0]}" "$ROOT/bin/cairn"
else
    lipo -create "${BINARIES[@]}" -output "$ROOT/bin/cairn"
fi
chmod 0755 "$ROOT/bin/cairn"

# Read back from the file rather than assumed from how many inputs there were:
# an input that was already universal is two architectures in one argument.
ARCHS="$(lipo -archs "$ROOT/bin/cairn")" || die "lipo cannot read the result; was --binary a Mach-O executable?"
HOST_ARCHS="$(printf '%s' "$ARCHS" | tr ' ' '\n' | LC_ALL=C sort | paste -sd, -)"
case "$HOST_ARCHS" in
    arm64,x86_64) ARCH_LABEL="universal"; ARCH_SENTENCE="Apple Silicon and Intel Macs" ;;
    arm64)        ARCH_LABEL="arm64";     ARCH_SENTENCE="Apple Silicon Macs" ;;
    x86_64)       ARCH_LABEL="x86_64";    ARCH_SENTENCE="Intel Macs" ;;
    *) die "unexpected architectures in the binary: $ARCHS" ;;
esac

# -- sign it ------------------------------------------------------------------
#
# Not optional even with no certificate. rustc's linker ad-hoc signs an arm64
# binary, because Apple Silicon will not execute unsigned code, and leaves an
# x86_64 one unsigned. Glue the two together and `codesign --verify --strict`
# rejects the result as "not signed at all", since one slice is not. Signing
# after lipo signs every slice.
#
# The identifier is set because the linker's is `cairn-<hash of the build>`,
# which changes every release and is what a user sees if macOS ever asks them
# about this program by name.
if [ "$SIGNED" -eq 1 ]; then
    codesign --force --options runtime --timestamp \
        --identifier "$IDENTIFIER" --sign "$APP_ID" "$ROOT/bin/cairn"
else
    codesign --force --identifier "$IDENTIFIER" --sign - "$ROOT/bin/cairn"
fi
codesign --verify --strict "$ROOT/bin/cairn" \
    || die "the binary does not verify after signing"

# -- the app --------------------------------------------------------------------
#
# A copy, so the version stamp and the signature land on this image's bundle
# and not on the build directory's. Its architectures must be the binary's: an
# arm64-only app beside a universal binary installs on an Intel Mac and does
# not open.
APP_ROOT="$WORK/Cairn.app"
ditto "$APP" "$APP_ROOT"
APP_ARCHS="$(lipo -archs "$APP_ROOT/Contents/MacOS/Cairn" | tr ' ' '\n' | LC_ALL=C sort | paste -sd, -)"
[ "$APP_ARCHS" = "$HOST_ARCHS" ] \
    || die "Cairn.app holds $APP_ARCHS and the binary $HOST_ARCHS; build the app with the same architectures (gui/macos-app/build.sh --universal)"
[ "$(plutil -extract CFBundleIdentifier raw -o - "$APP_ROOT/Contents/Info.plist")" = "$APP_IDENTIFIER" ] \
    || die "Cairn.app's bundle identifier is not $APP_IDENTIFIER"
plutil -replace CFBundleShortVersionString -string "$UPSTREAM_VERSION" "$APP_ROOT/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$MACOS_PKG_VERSION" "$APP_ROOT/Contents/Info.plist"
# Signed after the stamp, since the signature seals Info.plist. The hardened
# runtime needs no entitlements here: the app starts a process and loads
# pages from loopback, and neither is something the runtime restricts.
if [ "$SIGNED" -eq 1 ]; then
    codesign --force --options runtime --timestamp --sign "$APP_ID" "$APP_ROOT"
else
    codesign --force --sign - "$APP_ROOT"
fi
codesign --verify --strict --deep "$APP_ROOT" \
    || die "Cairn.app does not verify after signing"

# -- the component packages -------------------------------------------------------
#
# Installed to /usr/local/cairn, a directory nothing else has an opinion about,
# and *not* to /usr/local/bin. pkgbuild writes `overwrite-permissions="true"`
# into every package it makes and records each directory in the payload as
# root:wheel 0755, so a payload containing usr/local/bin resets that directory
# on every Mac it is installed on. `postinstall` has the rest of that story and
# makes the one link into the shared directory by hand.
cp "$HERE/postinstall" "$WORK/scripts/postinstall"
chmod 0755 "$WORK/scripts/postinstall"

pkgbuild --quiet \
    --root "$ROOT" \
    --install-location /usr/local/cairn \
    --identifier "$IDENTIFIER" \
    --version "$MACOS_PKG_VERSION" \
    --scripts "$WORK/scripts" \
    --ownership recommended \
    "$WORK/pkgs/cairn-cli.pkg"

# The app's payload is the bundle itself, installed *as* /Applications/Cairn.app,
# for the reason the command's is installed as /usr/local/cairn. Rooted at
# /Applications instead, the payload's `.` would be /Applications, recorded
# as root:wheel 0755 under `overwrite-permissions="true"`, and every install
# would take the admin group's write access off the directory -- the
# /usr/local/bin breakage `postinstall` describes, one folder over.
#
# Rooted at the bundle, pkgbuild also sees no bundle to make relocatable. A
# relocatable one is upgraded wherever Installer finds that identifier -- a
# copy in ~/Downloads, a build directory in a checkout -- and nothing lands
# in /Applications. verify-dmg.sh checks the receipt says relocatable="false".
#
# `preinstall` removes the previous version first: installing over it would
# leave behind any file this version no longer has, and a stray file inside a
# bundle breaks its signature.
cp "$HERE/preinstall-app" "$WORK/app-scripts/preinstall"
chmod 0755 "$WORK/app-scripts/preinstall"
pkgbuild --quiet \
    --root "$APP_ROOT" \
    --install-location /Applications/Cairn.app \
    --identifier "$APP_IDENTIFIER" \
    --version "$MACOS_PKG_VERSION" \
    --scripts "$WORK/app-scripts" \
    --ownership recommended \
    "$WORK/pkgs/cairn-app.pkg"

# -- the installer a person double-clicks --------------------------------------
fill() {
    sed -e "s|@VERSION@|$UPSTREAM_VERSION|g" \
        -e "s|@PKG_VERSION@|$MACOS_PKG_VERSION|g" \
        -e "s|@IDENTIFIER@|$IDENTIFIER|g" \
        -e "s|@APP_IDENTIFIER@|$APP_IDENTIFIER|g" \
        -e "s|@HOST_ARCHS@|$HOST_ARCHS|g" \
        -e "s|@ARCH_LABEL@|$ARCH_LABEL|g" \
        -e "s|@ARCH_SENTENCE@|$ARCH_SENTENCE|g" "$1"
}
fill "$HERE/distribution.xml"            >"$WORK/distribution.xml"
fill "$HERE/resources/welcome.html"      >"$WORK/resources/welcome.html"
fill "$HERE/resources/conclusion.html"   >"$WORK/resources/conclusion.html"
cp "$REPO/LICENSE" "$WORK/resources/LICENSE.txt"

SIGN_ARGS=()
[ "$SIGNED" -eq 0 ] || SIGN_ARGS=(--sign "$INSTALLER_ID" --timestamp)
# The `+` form because an empty array is an unbound variable to `set -u` under
# the bash 3.2 that macOS still ships.
productbuild --quiet \
    --distribution "$WORK/distribution.xml" \
    --package-path "$WORK/pkgs" \
    --resources "$WORK/resources" \
    ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} \
    "$STAGE/Install Cairn.pkg"

# -- what else is in the image --------------------------------------------------
#
# The README tells the truth about which of two installers this is. It is
# assembled rather than templated with sed because the note is a block of
# lines, and sed's idea of a multi-line replacement differs between the BSD one
# here and the GNU one a contributor may test against.
if [ "$SIGNED" -eq 1 ]; then NOTE="$HERE/gatekeeper-signed.txt"; else NOTE="$HERE/gatekeeper-unsigned.txt"; fi
while IFS= read -r line; do
    if [ "$line" = "@GATEKEEPER_NOTE@" ]; then cat "$NOTE"; else printf '%s\n' "$line"; fi
done <"$HERE/dmg-README.txt" >"$WORK/README.unfilled"
fill "$WORK/README.unfilled" >"$STAGE/README.txt"
cp "$REPO/LICENSE" "$STAGE/LICENSE.txt"

# -- the image ------------------------------------------------------------------
mkdir -p "$OUT"
DMG="$OUT/cairn-$VERSION-macos-$ARCH_LABEL.dmg"
VOLNAME="Cairn $UPSTREAM_VERSION"

# Retried, because on GitHub's macOS runners `hdiutil create` intermittently
# fails with "Resource busy" for reasons that have nothing to do with its
# arguments, and a release should not need re-running by hand over that. Three
# attempts and then a real failure: a loop that never gives up would turn a
# genuine error into a job that hangs until the runner's timeout.
#
# HFS+ rather than APFS, and UDZO rather than the newer compressed formats:
# both open on every macOS the x86_64 slice still runs on.
attempt=1
until hdiutil create -quiet -ov \
        -volname "$VOLNAME" -srcfolder "$STAGE" \
        -fs HFS+ -format UDZO -imagekey zlib-level=9 "$DMG"; do
    [ "$attempt" -lt 3 ] || die "hdiutil create failed three times; see its output above"
    echo "hdiutil create failed (attempt $attempt of 3); retrying" >&2
    attempt=$((attempt + 1))
    sleep 5
done

# -- sign, notarize and staple the image (never yet run; see the header) --------
if [ "$SIGNED" -eq 1 ]; then
    codesign --force --timestamp --sign "$APP_ID" "$DMG"
    # `notarytool submit --wait` exits 0 once Apple has *answered*, whatever
    # the answer was. The status has to be read, or a rejected image sails on
    # to `stapler`, which fails with an error about a missing ticket and no
    # mention of why there is none.
    status="$(xcrun notarytool submit "$DMG" --wait --output-format json \
        --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" \
        | plutil -extract status raw -o - -)"
    [ "$status" = "Accepted" ] \
        || die "Apple's notary service answered '$status'. \`xcrun notarytool log <submission id>\` says why."
    xcrun stapler staple "$DMG"
fi

echo "built $DMG"
echo "    architectures  $ARCHS"
echo "    installs       /usr/local/cairn/bin/cairn, linked from /usr/local/bin/cairn"
echo "                   /Applications/Cairn.app"
if [ "$SIGNED" -eq 1 ]; then
    echo "    signing        Developer ID, notarized and stapled"
else
    echo "    signing        ad-hoc binary, unsigned package -- Gatekeeper will ask; the README inside says what to do"
fi
