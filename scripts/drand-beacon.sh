#!/usr/bin/env bash
# Fetch the drand round an epoch names, and record it as that epoch's beacon.
#
# This is outside the binary and stays outside it. `tests/cipher_policy.rs`
# fails the build if a TLS crate enters the dependency tree -- and an HTTP
# client is the usual way one arrives, which that test's own docs say in as many
# words. `docs/design/chain-beacon.md` had already put fetching outside the
# rules engine for the better reason: this is a transport, and the rules are
# the rules.
#
# WHERE THE TRUST IS, AND IT IS NOT HERE. `cairn beacon` verifies the pairing
# against the public key pinned in `src/drand.rs` before it will write
# anything, so a relay that lies is refused by the rules engine and this script
# cannot launder a forged value into the log. Nothing below is a security
# check.
#
# Several relays are queried for *availability*: any one of them can be down or
# behind, and the answer is public and identical everywhere. Disagreement is
# reported and stops the run because it means one of them is broken or forked
# and somebody should know -- not because recording the wrong one would be
# dangerous, which it would not be. It would simply be refused.
#
# TIMING. The round an epoch names is published *at that epoch's boundary*, so
# this has to run inside the epoch it is recording and cannot run before it:
# `record_beacon` refuses a beacon drawn outside the epoch it orders, and that
# refusal is the security property rather than an inconvenience.
set -euo pipefail
cd "$(dirname "$0")/.."

CAIRN="${CAIRN_BIN:-./target/release/cairn}"
[ -x "$CAIRN" ] || CAIRN="./target/debug/cairn"

# Independent operators, deliberately. Two hosts run by the same party agreeing
# with each other is one host.
RELAYS=(
  "https://api.drand.sh"
  "https://api2.drand.sh"
  "https://api3.drand.sh"
  "https://drand.cloudflare.com"
)
CHAIN="52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUORUM="${DRAND_QUORUM:-2}"

ORDERS=""
# `--log` and `--root` are cairn's global options and go *before* the
# subcommand, so they are collected rather than forwarded as-is.
GLOBAL=()
GLOBAL_COUNT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --orders) ORDERS="$2"; shift 2 ;;
    --log|--root)
      GLOBAL+=("$1" "$2")
      GLOBAL_COUNT=$((GLOBAL_COUNT + 2))
      shift 2
      ;;
    *) echo "usage: $0 [--orders EPOCH] [--log PATH] [--root DIR]" >&2; exit 2 ;;
  esac
done

# Ask the binary which round, rather than deriving it here. A second derivation
# of a consensus-visible mapping, in bash, in a helper script, would produce an
# unverifiable record on any disagreement and would produce it silently.
# macOS still ships Bash 3.2, where expanding an empty array under `set -u`
# aborts even when the array was explicitly initialized. Keep the zero-argument
# call separate so this operator script works on every platform the CLI does.
if [ "$GLOBAL_COUNT" -eq 0 ]; then
  info=$("$CAIRN" drand-round ${ORDERS:+--orders "$ORDERS"})
else
  info=$("$CAIRN" "${GLOBAL[@]}" drand-round ${ORDERS:+--orders "$ORDERS"})
fi
epoch=$(awk '/^epoch/{print $2}' <<<"$info")
round=$(awk '/^round/{print $2}' <<<"$info")
publishes=$(awk '/^publishes/{print $2}' <<<"$info")

now=$(date -u +%s)
if [ "$publishes" -gt "$now" ]; then
  wait=$((publishes - now + 2))
  echo "round $round publishes in ${wait}s; waiting" >&2
  sleep "$wait"
fi

declare -a sigs=()
SIG_COUNT=0
for relay in "${RELAYS[@]}"; do
  # The v1 path, because it is the one every relay serves -- Cloudflare has no
  # /v2 at all, and a relay that never answers is a relay that never disagrees,
  # which is the worst way to lose a vote.
  sig=$(curl -fsS --max-time 10 "$relay/$CHAIN/public/$round" 2>/dev/null \
        | sed -n 's/.*"signature":"\([0-9a-f]*\)".*/\1/p') || true
  if [ -n "$sig" ]; then
    sigs+=("$sig")
    SIG_COUNT=$((SIG_COUNT + 1))
    echo "  $relay  $sig" >&2
  else
    # Unavailable is never Reject. A relay that did not answer says nothing
    # about the round; it just does not vote.
    echo "  $relay  (no answer)" >&2
  fi
done

if [ "$SIG_COUNT" -eq 0 ] || [ "$SIG_COUNT" -lt "$QUORUM" ]; then
  echo "only $SIG_COUNT relay(s) answered for round $round, need $QUORUM." >&2
  echo "The epoch keeps the fallback ordering. That is legal and weaker;" >&2
  echo "'cairn audit' under CAIRN_REQUIRE_BEACON=1 will say so." >&2
  exit 1
fi

agreed="${sigs[0]}"
for sig in "${sigs[@]}"; do
  if [ "$sig" != "$agreed" ]; then
    # At most one of them can verify, so this is not a safety question -- it is
    # a "something is badly wrong with a public good" question, and stopping is
    # how a human hears about it.
    echo "relays disagree about round $round -- recording nothing." >&2
    printf '%s\n' "${sigs[@]}" >&2
    exit 1
  fi
done

echo "$SIG_COUNT relays agree on round $round; the pairing check is cairn's, below" >&2
if [ "$GLOBAL_COUNT" -eq 0 ]; then
  exec "$CAIRN" beacon --orders "$epoch" --drand-signature "$agreed"
else
  exec "$CAIRN" "${GLOBAL[@]}" beacon --orders "$epoch" --drand-signature "$agreed"
fi
