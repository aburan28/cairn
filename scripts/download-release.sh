#!/usr/bin/env bash
# Install the five release binaries from a GitHub Release -- no Rust
# toolchain, no compile.
#
#   ./scripts/download-release.sh                     # latest release, this machine
#   ./scripts/download-release.sh --version v0.3.0     # a specific tag
#   ./scripts/download-release.sh --target x86_64-unknown-linux-musl
#   ./scripts/download-release.sh --out .local/bin
#
# Mirrors .github/workflows/release.yml exactly: the same five binaries, the
# same tarball name (`proofwork-<tag>-<target>.tar.gz`), the same checksum
# file beside it. This script builds nothing and trusts nothing -- the
# tarball is checked against its published sha256 *before* a single byte of
# it is extracted, the same "verify before write" rule `src/blobs.rs` applies
# to a fetched checker: the whole pitch of this project is that you do not
# have to trust whoever handed you the bytes.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

REPO="${REPO:-aburan28/distributed-researcher}"
VERSION="${VERSION:-latest}"
OUT="${OUT:-target/release}"
TARGET="${TARGET:-}"
BINS="proofwork proofwork-mcp proofwork-p2p proofwork-serve proofwork-gen-bootstrap"

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)    REPO="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --out)     OUT="$2"; shift 2 ;;
    --target)  TARGET="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

say()  { printf '  %s\n' "$1"; }
fail() { printf 'download-release: %s\n' "$1" >&2; exit 1; }

# Absolute, and resolved against the repo root rather than wherever the caller
# happened to be standing -- the same reason mcp-config.sh resolves --log:
# a relative path here would put the binaries somewhere real only by luck.
case "$OUT" in /*) ;; *) OUT="$REPO_ROOT/$OUT" ;; esac

# --- which target triple -----------------------------------------------------
#
# The same six release.yml builds, so a platform this repo does not ship for
# fails here with a clear list instead of a 404 three steps later. Linux
# defaults to glibc, not musl: musl links statically and survives an old
# glibc, but it also changes DNS resolution (a static NSS has no
# /etc/nsswitch.conf to read), and this binary resolves peer addresses -- gnu
# is the closer match to how the rest of the host already resolves names.
# Pass --target explicitly for a musl build on an old distribution or inside
# a minimal container.
if [ -z "$TARGET" ]; then
  case "$(uname -s)" in
    Darwin)
      case "$(uname -m)" in
        arm64)  TARGET=aarch64-apple-darwin ;;
        x86_64) TARGET=x86_64-apple-darwin ;;
        *) fail "unrecognised macOS architecture $(uname -m); pass --target explicitly" ;;
      esac
      ;;
    Linux)
      case "$(uname -m)" in
        x86_64)        TARGET=x86_64-unknown-linux-gnu ;;
        aarch64|arm64) TARGET=aarch64-unknown-linux-gnu ;;
        *) fail "unrecognised Linux architecture $(uname -m); pass --target explicitly" ;;
      esac
      ;;
    *)
      fail "no release is built for $(uname -s). Targets shipped: \
x86_64-unknown-linux-gnu, x86_64-unknown-linux-musl, aarch64-unknown-linux-gnu, \
aarch64-unknown-linux-musl, aarch64-apple-darwin, x86_64-apple-darwin -- no \
Windows target, because the verifier sandbox (src/verifiers/sandbox.rs) is \
Unix-only. Build from source instead: 'make build'."
      ;;
  esac
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/proofwork-download.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# --- locate the release and its two assets -----------------------------------
#
# `gh` first when it is on PATH: it already handles pagination, auth, and
# asset matching, so there is nothing to hand-roll. `curl` + `python3` (a
# project dependency already -- see `PYTHON ?= python3` in the Makefile) is
# the fallback for the machine this script exists for: one with no dev
# tooling installed at all, which is exactly the machine `gh` is least likely
# to be on.
TAG=""
NAME=""

fetch_with_gh() {
  command -v gh >/dev/null 2>&1 || return 1
  if [ "$VERSION" = "latest" ]; then
    gh release view --repo "$REPO" --json tagName >/dev/null 2>&1 || return 1
    TAG="$(gh release view --repo "$REPO" --json tagName --jq .tagName)"
  else
    gh release view "$VERSION" --repo "$REPO" --json tagName >/dev/null 2>&1 || return 1
    TAG="$VERSION"
  fi
  NAME="proofwork-$TAG-$TARGET.tar.gz"
  gh release download "$TAG" --repo "$REPO" \
    --pattern "$NAME" --pattern "$NAME.sha256" --dir "$WORK" --clobber \
    2>/dev/null || return 1
}

fetch_with_curl() {
  local api="https://api.github.com/repos/$REPO/releases/latest"
  [ "$VERSION" = "latest" ] || api="https://api.github.com/repos/$REPO/releases/tags/$VERSION"
  local meta="$WORK/release.json" code
  code=$(curl -sS -o "$meta" -w '%{http_code}' "$api") \
    || fail "could not reach api.github.com -- check the network"
  case "$code" in
    200) ;;
    404) return 1 ;;
    403) fail "api.github.com answered 403, almost certainly the unauthenticated \
rate limit (60 requests/hour/IP). Install the GitHub CLI (gh) and run \
'gh auth login', which lifts it -- this script prefers gh automatically once \
it is on PATH." ;;
    *) fail "$api answered HTTP $code" ;;
  esac
  TAG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tag_name"])' "$meta")"
  NAME="proofwork-$TAG-$TARGET.tar.gz"
  local url shaurl
  url="$(REL="$NAME" python3 - "$meta" <<'PY'
import json, os, sys
assets = json.load(open(sys.argv[1]))["assets"]
match = next((a for a in assets if a["name"] == os.environ["REL"]), None)
print(match["browser_download_url"] if match else "")
PY
)"
  shaurl="$(REL="$NAME.sha256" python3 - "$meta" <<'PY'
import json, os, sys
assets = json.load(open(sys.argv[1]))["assets"]
match = next((a for a in assets if a["name"] == os.environ["REL"]), None)
print(match["browser_download_url"] if match else "")
PY
)"
  [ -n "$url" ] && [ -n "$shaurl" ] || fail "release $TAG has no asset named $NAME -- \
either this platform was not built for that release, or it is still building"
  curl -sSL -o "$WORK/$NAME" "$url"
  curl -sSL -o "$WORK/$NAME.sha256" "$shaurl"
}

if ! fetch_with_gh; then
  fetch_with_curl || fail "no GitHub Release found for $REPO at version '$VERSION'. \
Releases are cut by pushing a v* tag -- see .github/workflows/release.yml -- \
and none has been pushed on this repository yet. Build from source instead: \
'make build' (or 'cargo build --release --bins')."
fi

# --- verify, *then* extract ---------------------------------------------------

cd "$WORK"
say "verifying $NAME against its published sha256..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "$NAME.sha256" >/dev/null \
    || fail "checksum mismatch on $NAME -- refusing to extract it. Delete and \
retry; if it persists, treat the asset as compromised and report it."
else
  shasum -a 256 -c "$NAME.sha256" >/dev/null \
    || fail "checksum mismatch on $NAME -- refusing to extract it. Delete and \
retry; if it persists, treat the asset as compromised and report it."
fi

mkdir -p "$OUT"
tar -xzf "$NAME"
for bin in $BINS; do
  [ -f "$bin" ] || fail "$NAME did not contain $bin -- a broken release build, \
not a network problem"
  chmod 0755 "$bin"
  mv "$bin" "$OUT/$bin"
done

say "installed $TAG ($TARGET) -> $OUT"
for bin in $BINS; do say "  $OUT/$bin"; done
say ""
say "run directly:  $OUT/proofwork --help"
say "or:            export PATH=\"$OUT:\$PATH\""
if [ "$OUT" = "$REPO_ROOT/target/release" ]; then
  say ""
  say "this is the same directory 'make build' compiles into. Running 'make"
  say "mcp', 'make cli', or anything else with 'build' as a prerequisite will"
  say "recompile from source and overwrite what was just installed -- run the"
  say "binaries above directly to use the downloaded ones."
fi
