#!/usr/bin/env bash
# No reader links to github.com.
#
# The published site, the embedded /ui/ reader, Cairn.app and the iPhone
# reader are the surfaces a stranger meets first, and for a while each of them
# sent that stranger to github.com for the documentation -- a page about a
# network with no operator, pointing at docs hosted by one. The docs travel
# in the repository, while the reader explains the network without listing
# files. A link from the reader to GitHub is a regression, and this script is
# the check.
#
# ui/lib/site.test.ts already fails on an anchor in ui/; this covers the native
# apps as well and needs no Node toolchain. What is allowed is listed by path
# with its reason, so a new exception is a reviewed edit here and never a
# silent one.
set -euo pipefail
cd "$(dirname "$0")/.."

# Files in which github.com is text a reader cannot follow.
ALLOW=(
  # The one constant the reader keeps, so a test can assert it is never used
  # in an href. ui/lib/site.test.ts guards every use of it.
  'ui/lib/site.ts'
  # That test, which spells the host out in the regexes that forbid it.
  'ui/lib/site.test.ts'
  # The install command Cairn.app shows the operator to type, verbatim. A
  # command rather than a link, and the release asset lives nowhere else.
  'gui/macos-app/Sources/Cairn/Updates.swift'
  # A test fixture: a recorded release-feed URL, parsed and never rendered.
  'gui/macos-app/Tests/CairnTests/UpdateFeedFixture.swift'
  # The Sparkle dependency, which SwiftPM fetches from there.
  'gui/macos-app/Package.swift'
  # SUFeedURL: the appcast Sparkle polls for updates. Fetched by the updater,
  # shown to nobody; the release feed is published nowhere else.
  'gui/macos-app/Info.plist'
)

# Every source file a reader is built from.
hits=$(grep -rn \
  --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
  --include='*.html' --include='*.css' --include='*.svg' \
  --include='*.swift' --include='*.storyboard' --include='*.xib' --include='*.strings' \
  --include='*.plist' --include='*.json' \
  --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=out --exclude-dir=.build \
  --exclude-dir=build \
  --exclude='package-lock.json' \
  'github\.com' ui gui 2>/dev/null || true)

status=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  file=${line%%:*}
  allowed=0
  for path in "${ALLOW[@]}"; do
    [ "$file" = "$path" ] && allowed=1
  done
  if [ "$allowed" = 0 ]; then
    echo "github.com in a reader: $line" >&2
    status=1
  fi
done <<<"$hits"

# The HTML the node renders itself (/chain.html and friends) is Rust string
# literals a browser will show, so an href in them counts too.
if grep -rn --include='*.rs' 'href=[^ >]*github\.com' src; then
  echo "an href to github.com in HTML the node renders" >&2
  status=1
fi

if [ "$status" = 0 ]; then
  echo "no reader links to github.com"
fi
exit "$status"
