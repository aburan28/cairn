#!/usr/bin/env bash
# Build Cairn.app -- the window onto a local node that the release's .dmg
# installs -- with nothing but the Command Line Tools.
#
#   gui/macos-app/build.sh                  -> gui/macos-app/build/Cairn.app, this Mac's architecture
#   gui/macos-app/build.sh --universal      ...arm64 and x86_64 in one binary, as release.yml builds it
#   gui/macos-app/build.sh --open           ...and launch it
#
# The bundle runs the `cairn` the installer puts at /usr/local/cairn/bin/cairn
# (or $CAIRN_BINARY), so a build from a checkout needs one of those to show
# anything but its own error page. It is ad-hoc signed here; build-dmg.sh
# stamps the release version into it and signs it again for shipping.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/build"
APP="$OUT/Cairn.app"

UNIVERSAL=0 OPEN=0
for arg in "$@"; do
    case "$arg" in
        --universal) UNIVERSAL=1 ;;
        --open)      OPEN=1 ;;
        --help|-h)   sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

cd "$HERE"
# One `swift build` per architecture, joined with lipo, rather than
# `--arch arm64 --arch x86_64`: that form needs Xcode's build system, and this
# has to build where only the Command Line Tools are installed.
if [ "$UNIVERSAL" -eq 1 ]; then ARCHS=(arm64 x86_64); else ARCHS=("$(uname -m)"); fi
SLICES=()
for arch in "${ARCHS[@]}"; do
    triple="$arch-apple-macosx13.0"
    # Progress lines dropped, warnings and errors kept; `pipefail` hands swift
    # build's own status to `rc`, so a failed compile is not packaged as
    # whatever an earlier build left in .build (see gui/macos/build.sh).
    rc=0
    swift build -c release --triple "$triple" 2>&1 | { grep -v '^\[' || true; } || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "swift build failed for $arch (exit $rc); nothing was packaged" >&2
        exit "$rc"
    fi
    bin="$(swift build -c release --triple "$triple" --show-bin-path)/Cairn"
    [ -x "$bin" ] || { echo "build failed: $bin missing" >&2; exit 1; }
    SLICES+=("$bin")
done

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
if [ "${#SLICES[@]}" -eq 1 ]; then
    cp "${SLICES[0]}" "$APP/Contents/MacOS/Cairn"
else
    lipo -create "${SLICES[@]}" -output "$APP/Contents/MacOS/Cairn"
fi
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"

# The same picture as the autoresearcher's, rendered from the same code, so
# nothing binary is committed. A missing icon is a cosmetic loss and does not
# fail the build.
ICONSET="$OUT/AppIcon.iconset"
if swift "$HERE/../macos/Resources/render-icon.swift" "$ICONSET" >/dev/null 2>&1 \
   && iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null; then
    :
else
    echo "note: could not render the icon; the app will use the generic one" >&2
fi

codesign --force --sign - "$APP" >/dev/null
codesign --verify --strict "$APP"
echo "built $APP ($(lipo -archs "$APP/Contents/MacOS/Cairn"))"
if [ "$OPEN" -eq 1 ]; then
    open "$APP"
fi
