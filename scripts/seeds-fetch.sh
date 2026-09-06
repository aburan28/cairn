#!/usr/bin/env bash
# Download the published seed list and turn it into --bootstrap files.
#
# This is outside the binary and stays outside it, for the reason
# `scripts/drand-beacon.sh` already gives: `tests/cipher_policy.rs` fails the
# build if a TLS crate enters the dependency tree, and an HTTP client is the
# usual way one arrives. So the shell does the transport and `cairn seeds
# resolve` does the checking -- which is also where the checking is testable.
#
# WHERE THE TRUST IS, AND IT IS NOT HERE. Nothing below is a security check.
# A key file is named for the peer id of the key inside it, a peer id *is*
# sha256 of the transport key, and `cairn seeds resolve` re-derives that id from
# the bytes before it will write anything. So a hostile mirror -- or a GitHub
# Pages account somebody takes -- can withhold a seed, or serve a key that does
# not match its name, and both are refused. What it cannot do is put a
# different key under the same name.
#
# What it *can* do is point you at a machine of its choosing. That machine then
# fails the handshake, because it does not hold the secret half of the key you
# just verified, and the cost is a wasted dial. Same bound as a hostile DNS
# answer in `p2p::discovery::dialable`. That bound is the entire reason this
# list is safe to publish somewhere nobody has to trust.
set -euo pipefail
cd "$(dirname "$0")/.."

CAIRN="${CAIRN_BIN:-./target/release/cairn}"
[ -x "$CAIRN" ] || CAIRN="./target/debug/cairn"
[ -x "$CAIRN" ] || { echo "no cairn binary; run \`make build\`" >&2; exit 2; }

# Overridable, because an anchor you cannot replace without editing the source
# is the anchor `docs/discovery.md` says not to build. Point it at a fork, a
# file:// path, a Tor hidden service, or a copy on a USB stick -- every hint
# source is equal here precisely because none of them is trusted.
SEEDS_URL="${CAIRN_SEEDS_URL:-https://aburan28.github.io/cairn/seeds.json}"
OUT="${CAIRN_SEEDS_DIR:-.local/seeds}"
# An explicit template rather than a bare `mktemp -d`: BSD mktemp ignores
# TMPDIR without one and lands in /var/folders, which a sandboxed or
# read-only-TMPDIR environment refuses.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-seeds.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "fetching $SEEDS_URL" >&2
# `--proto -all,https` refuses a redirect that downgrades to plaintext or
# wanders off into another scheme. Not because the content is secret -- it is
# published -- but because a silent downgrade is the kind of thing nobody
# notices, and this costs one flag.
#
# The failure gets a sentence because curl's does not. `curl: (56)` and exit 56
# is the same output for a URL that does not exist yet, a fork that has never
# deployed its site, a typo in SEEDS_URL, and a renamed repository -- and this
# script hit the last one for real: GitHub does not redirect a renamed
# project's Pages path, so the old URL 404s exactly like a missing file.
if ! curl -fsSL --proto '-all,https,file' --max-time 30 \
     -o "$WORK/seeds.json" "$SEEDS_URL"; then
  cat >&2 <<EOF
could not fetch the seed list from
  $SEEDS_URL

That URL is a default, not an authority -- nothing here trusts it, so pointing
somewhere else costs nothing:

  CAIRN_SEEDS_URL=<a fork, a mirror, or file:///path/to/seeds.json> $0
  make seeds SEEDS_URL=...

A 404 usually means the site has not deployed this file yet (it ships with the
Pages workflow), or the repository moved. Until then, \`make p2p\` falls back to
a placeholder bootstrap key that authenticates nobody -- see docs/p2p.md.
EOF
  exit 2
fi

# The key files sit beside the list. Each is 522 KB of hex, so they are fetched
# per entry rather than bundled into the list itself -- an index a browser reads
# on every page load has no business carrying a megabyte of key material.
BASE="${SEEDS_URL%/*}"
mkdir -p "$WORK/seeds"

# Shape only, and only enough of it to build a URL. `cairn seeds resolve`
# decides whether a key file is the key it claims to be; this refuses to
# interpolate something that is not a peer id into a path.
python3 - "$WORK/seeds.json" > "$WORK/transports" <<'PY'
import json, re, sys
for seed in json.load(open(sys.argv[1])).get("seeds", []):
    transport = seed.get("transport")
    if isinstance(transport, str) and re.fullmatch(r"[0-9a-f]{64}", transport):
        print(transport)
PY

while read -r transport; do
  echo "  key $transport" >&2
  # A missing key file is not fatal: `resolve` refuses that entry by name and
  # every other seed in the list still resolves. One operator who has not
  # published yet must not cost everybody else their bootstrap.
  #
  # The `rm` is not tidiness. `curl -f -o FILE` creates FILE before it learns
  # the response is a 404, and `--fail` then withholds the body -- leaving a
  # zero-byte file that `resolve` reports as a malformed key rather than as a
  # key nobody published. Two different problems should not print the same
  # line.
  curl -fsSL --proto '-all,https,file' --max-time 60 --max-filesize 600000 \
    -o "$WORK/seeds/$transport.key" "$BASE/seeds/$transport.key" \
    || { rm -f "$WORK/seeds/$transport.key"
         echo "  (no key file published for $transport)" >&2; }
done < "$WORK/transports"

mkdir -p "$OUT"
"$CAIRN" seeds resolve --list "$WORK/seeds.json" --keys "$WORK/seeds" --out "$OUT"
