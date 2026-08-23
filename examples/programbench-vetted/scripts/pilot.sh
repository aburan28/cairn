#!/usr/bin/env bash
# One ProgramBench-shaped task, end to end on a real cairn log.
#
# Four submitters stand in for four model+harness configurations. Each one
# commits, reveals, and is graded by the same pinned evaluator; the board at
# the end is derived from the log by reading the score every verdict
# recorded, which is the property the whole exercise is for -- a leaderboard
# nobody has to be trusted to compute.
set -eo pipefail
cd "$(dirname "$0")/../../.."

CB="${CAIRN_BIN:-./target/release/cairn}"
[ -x "$CB" ] || CB="$(command -v cairn || echo "$HOME/.local/bin/cairn")"
HERE=examples/programbench-vetted
LOG="${LOG:-$HERE/log.jsonl}"
export CAIRN_EPOCH_SECONDS="${CAIRN_EPOCH_SECONDS:-1}"

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

rm -f "$LOG" "$HERE/board-input.jsonl"

rule "the objective, with its evaluator pinned by hash"
OID=$($CB --log "$LOG" --root . post $HERE/objectives/objective-pb-pilot-0001.json | head -1 | awk '{print $2}')
echo "  $OID"

rule "four submitters commit, then reveal"
# The ratchet refuses a claim that does not cite the frontier it is measured
# against, so the frontier is threaded through the loop. That refusal is the
# mechanism working: on a progressive bounty, payment is distance moved, and
# a submission that names no starting point is not a measurable move.
FRONTIER=""
BEST=0
for pair in resolved:opus-5 almost:sol-5.6 partial:sonnet-5 cheating:glimmer-30b hanging:devstral-2; do
  ART="${pair%%:*}"; WHO="${pair##*:}"
  NONCE="nonce-$WHO"
  $CB --log "$LOG" --root . commit "$OID" --submitter "$WHO" \
      --artifact "$HERE/artifacts/$ART.json" --nonce "$NONCE" >/dev/null
  sleep 1.2
  CITES=()
  [ -n "$FRONTIER" ] && CITES=(--cites "$FRONTIER")
  OUT=$($CB --log "$LOG" --root . reveal "$OID" --submitter "$WHO" \
      --artifact "$HERE/artifacts/$ART.json" --nonce "$NONCE" ${CITES[@]:+"${CITES[@]}"} 2>&1 || true)
  CLAIM=$(printf '%s' "$OUT" | grep -o 'sha256:[0-9a-f]\{64\}' | head -1 || true)
  SCORE=$(printf '%s' "$OUT" | grep -o 'score [0-9]\+' | head -1 | awk '{print $2}' || true)
  VERDICT=$(printf '%s' "$OUT" | tr '\n' ' ' | sed 's/.*verdict *//; s/ *pending.*//' | cut -c1-60)
  printf '  %-12s %-46s %s\n' "$WHO" "${VERDICT:-refused}" "${SCORE:-0} bp"
  if [ -n "${SCORE:-}" ] && [ "$SCORE" -gt "$BEST" ]; then BEST=$SCORE; FRONTIER=$CLAIM; fi
  [ -z "$FRONTIER" ] && [ -n "$CLAIM" ] && FRONTIER=$CLAIM
done

rule "settle"
sleep 4
$CB --log "$LOG" --root . settle | sed 's/^/  /'

rule "audit: the log re-derived from nothing but itself"
$CB --log "$LOG" --root . audit | sed 's/^/  /'

rule "the board, derived from the log"
# The store is sealed at rest, so the board reads the plaintext export
# rather than the node's own copy -- which is what a stranger auditing
# this log would be handed anyway.
$CB --log "$LOG" --root . store export --out "$HERE/board-input.jsonl" >/dev/null
python3 $HERE/tools/board.py "$HERE/board-input.jsonl" "$CB"
