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
    bindir="$(swift build -c release --triple "$triple" --show-bin-path)"
    bin="$bindir/Cairn"
    [ -x "$bin" ] || { echo "build failed: $bin missing" >&2; exit 1; }
    SLICES+=("$bin")
    # Sparkle ships as one framework holding both architectures, so any
    # slice's copy is the one to embed.
    SPARKLE="$bindir/Sparkle.framework"
done
[ -d "$SPARKLE" ] || { echo "build failed: no Sparkle.framework beside the binary in $(dirname "$SPARKLE")" >&2; exit 1; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
if [ "${#SLICES[@]}" -eq 1 ]; then
    cp "${SLICES[0]}" "$APP/Contents/MacOS/Cairn"
else
    lipo -create "${SLICES[@]}" -output "$APP/Contents/MacOS/Cairn"
fi
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"
# ditto, not cp -R: the framework's Versions/Current links have to stay links,
# or its signature no longer matches its layout.
mkdir -p "$APP/Contents/Frameworks"
ditto "$SPARKLE" "$APP/Contents/Frameworks/Sparkle.framework"

# Node → Tasks… posts these, so an installed app needs no checkout beside it
# (Sources/Cairn/GuiTasks.swift). The copy keeps the repository-relative
# paths, because each objective pins its checker by such a path and the app
# stages the checker at the same path under the node's root before posting.
# Each pin is checked here: a checker edited without re-pinning its objective
# fails the build, rather than shipping a task the node would refuse.
TASKS="$APP/Contents/Resources/Tasks"
EXAMPLES="$HERE/../../examples/certicom-ecdlp"
mkdir -p "$TASKS/examples/certicom-ecdlp/checkers"
cp "$EXAMPLES"/objective-*.json "$TASKS/examples/certicom-ecdlp/"
cp "$EXAMPLES"/checkers/*.py "$TASKS/examples/certicom-ecdlp/checkers/"
for objective in "$TASKS"/examples/certicom-ecdlp/objective-*.json; do
    checker="$(plutil -extract verifier.checker raw -o - "$objective")" \
        || { echo "build failed: $(basename "$objective") pins no checker" >&2; exit 1; }
    pin="$(plutil -extract verifier.checker_sha256 raw -o - "$objective")"
    [ -f "$TASKS/$checker" ] \
        || { echo "build failed: $(basename "$objective") pins $checker, which is not in examples/" >&2; exit 1; }
    got="$(shasum -a 256 "$TASKS/$checker" | cut -d' ' -f1)"
    [ "$got" = "$pin" ] \
        || { echo "build failed: $checker hashes to $got, but $(basename "$objective") pins $pin" >&2; exit 1; }
done

# The icon is drawn by packaging/macos/icon/make-icon.py and committed as an
# .icns, so the build needs no renderer. The autoresearcher uses the same one.
ICON="$HERE/../../packaging/macos/icon/AppIcon.icns"
[ -f "$ICON" ] || { echo "build failed: $ICON missing" >&2; exit 1; }
cp "$ICON" "$APP/Contents/Resources/AppIcon.icns"

codesign --force --sign - "$APP" >/dev/null
codesign --verify --strict "$APP"
echo "built $APP ($(lipo -archs "$APP/Contents/MacOS/Cairn"))"
if [ "$OPEN" -eq 1 ]; then
    open "$APP"
fi
