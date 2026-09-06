#!/usr/bin/env bash
# The crypto autoresearcher, end to end, from a checkout:
#
#   1. build the release binary and stage it in bin/ (skipped when current);
#   2. post every objective in objectives.txt to the researcher's own log;
#   3. start one node over that log -- MCP on stdio, HTTP, P2P, the reader --
#      and run the contributor loop against it until every objective is
#      solved, declined with a reason, or out of repertoire;
#   4. audit the finished log with the same epoch length the node used, so
#      the reader can see that every settled claim re-verifies.
#
# Runtime state lives in .autoresearcher/ (ignored). Everything is overridable:
#
#   AR_STATE=/elsewhere AR_HTTP=127.0.0.1:8081 CAIRN_EPOCH_SECONDS=10 ./run.sh
#
# Pass --loop to keep sweeping every AR_INTERVAL seconds instead of exiting
# after one pass; any other arguments go to autoresearcher.py unchanged.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${AR_ROOT:-$(cd "$HERE/../.." && pwd)}"
export AR_ROOT="$ROOT"
export AR_STATE="${AR_STATE:-$ROOT/.autoresearcher}"
export AR_LOG="${AR_LOG:-$AR_STATE/cairn.jsonl}"
export CAIRN_EPOCH_SECONDS="${CAIRN_EPOCH_SECONDS:-5}"
export CAIRN_FINALITY_EPOCHS="${CAIRN_FINALITY_EPOCHS:-1}"
CAIRN="${AR_CAIRN:-$ROOT/bin/cairn}"

ONCE=--once
ARGS=()
for a in "$@"; do
  case "$a" in
    --loop) ONCE= ;;
    *) ARGS+=("$a") ;;
  esac
done

# `cairn run` -- the one subcommand that serves MCP on stdio -- refuses to
# start without the embedded reader, so the binary has to be the `ui`
# feature build. The exported site is embedded whole, and its asset path
# is the cheapest proof the feature is in.
needs_build() {
  [ -x "$CAIRN" ] || return 0
  grep -q "_next/static" "$CAIRN" || return 0
  [ -z "$(find "$ROOT/src" "$ROOT/ui/app" -newer "$CAIRN" \( -name '*.rs' -o -name '*.tsx' \) 2>/dev/null | head -1)" ] || return 0
  return 1
}
if needs_build; then
  echo "== building cairn with the embedded reader (make ui-build; needs Node)" >&2
  (cd "$ROOT" && make ui-build) >&2
fi
export AR_CAIRN="$CAIRN"
mkdir -p "$AR_STATE"

echo "== researching (state in $AR_STATE, node on http://${AR_HTTP:-127.0.0.1:8090})" >&2
python3 "$HERE/autoresearcher.py" $ONCE --post "$HERE/objectives.txt" ${ARGS[@]+"${ARGS[@]}"}

echo "== auditing $AR_LOG" >&2
"$CAIRN" --log "$AR_LOG" --root "$ROOT" audit
echo "== balances" >&2
"$CAIRN" --log "$AR_LOG" --root "$ROOT" balances | grep -v '^  *certificate\|^  *evaluator\|^  *!' || true
