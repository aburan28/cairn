#!/usr/bin/env bash
# Build the macOS launcher into an .app bundle with nothing but the Command
# Line Tools: `swift build` produces the executable, and the bundle is
# assembled here by hand rather than by Xcode, which is not required.
#
#   gui/macos/build.sh            -> gui/macos/build/Cairn Autoresearcher.app
#   gui/macos/build.sh --open     ...and launch it
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/build"
APP="$OUT/Cairn Autoresearcher.app"

cd "$HERE"
# Progress lines are dropped; warnings and errors are kept. grep exits 1 when
# every line it read was a progress line, so its `|| true` stays inside the
# braces, where it cannot also excuse the compiler: `pipefail` hands swift
# build's own status to `rc`. The `|| true` once covered the whole pipeline,
# and a failed compile went on to package whatever binary an earlier build had
# left in .build, then printed "built".
rc=0
swift build -c release 2>&1 | { grep -v '^\[' || true; } || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "swift build failed (exit $rc); nothing was packaged" >&2
  exit "$rc"
fi
BIN="$(swift build -c release --show-bin-path)/CairnAutoresearcher"
[ -x "$BIN" ] || { echo "build failed: $BIN missing" >&2; exit 1; }

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/CairnAutoresearcher"
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"
# The icon is rendered from code at build time, so nothing binary is
# committed and the source of the picture is the picture.
ICONSET="$OUT/AppIcon.iconset"
if swift "$HERE/Resources/render-icon.swift" "$ICONSET" >/dev/null 2>&1 \
   && iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns" 2>/dev/null; then
  :
else
  echo "note: could not render the icon; the app will use the generic one" >&2
fi
# Ad-hoc signature: required for a locally built binary to launch on Apple
# silicon at all, and enough for an app that is never distributed.
codesign --force --sign - "$APP" >/dev/null 2>&1 || true
echo "built $APP"
if [ "${1:-}" = "--open" ]; then
  open "$APP"
fi
