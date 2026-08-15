#!/usr/bin/env bash
# Thin bridge between ecdsafail CLI concepts and this cairn example.
#
#   ./examples/ecdsa-fail/adapter.sh map
#   ./examples/ecdsa-fail/adapter.sh score <artifact.json>
#   ./examples/ecdsa-fail/adapter.sh import-score <score.json>
#   ./examples/ecdsa-fail/adapter.sh pull          # ecdsafail benchmark (network)
#
# Does not replace ecdsafail submit. Unavailable tooling exits non-zero without
# claiming the circuit failed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PW="${CAIRN_BIN:-$ROOT/target/release/cairn}"
LOG="${CAIRN_LOG:-/tmp/cairn-ecdsa-adapter.jsonl}"
OID_FILE="${CAIRN_ECDSA_OID_FILE:-/tmp/cairn-ecdsa-adapter.oid}"
EXAMPLE="$ROOT/examples/ecdsa-fail"

usage() {
  sed -n '2,12p' "$0" | tr -d '#'
  exit 2
}

ensure_pw() {
  [ -x "$PW" ] || { echo "building cairn..." >&2; (cd "$ROOT" && cargo build --release); }
}

ensure_objective() {
  ensure_pw
  if [ -f "$OID_FILE" ] && [ -f "$LOG" ]; then
    OID=$(cat "$OID_FILE")
    return
  fi
  rm -f "$LOG" "$OID_FILE"
  OID=$("$PW" --log "$LOG" --root "$ROOT" post "$EXAMPLE/objective.json" | head -1 | awk '{print $2}')
  printf '%s\n' "$OID" > "$OID_FILE"
  echo "posted objective $OID into $LOG" >&2
}

cmd_map() {
  cat <<'EOF'
Concept map (workflow only — not settlement equivalence)

  ecdsafail                          cairn (this MVP)
  -------------------------          ----------------------------------
  ecdsafail login / config           operator funds objective once
  ecdsafail benchmark                get_objective / list_objectives
  ecdsafail clone + edit sources     generate candidate artifact JSON
  ecdsafail setup && run             score_candidate (pinned evaluator)
  score.json                         artifacts/{…}.json via score_to_artifact.py
  ecdsafail submit                   submit_claim (commit) then reveal
  promote if beats best              ratchet frontier + citation
  ecdsafail notes / sync             (still use ecdsafail CLI for swarm)

Real leaderboard submission remains: ecdsafail submit --note-file … --model …
EOF
}

cmd_score() {
  local artifact=${1:?artifact.json required}
  ensure_objective
  ARTIFACT="$artifact" OID="$OID" EXAMPLE="$EXAMPLE" python3 - <<'PY'
import importlib.util, json, os, sys
from pathlib import Path
example = Path(os.environ["EXAMPLE"])
path = example / "evaluators" / "circuit_cost.py"
spec = importlib.util.spec_from_file_location("circuit_cost", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
artifact = json.loads(Path(os.environ["ARTIFACT"]).read_text())
s = mod.score(artifact)
threshold = 100000  # toy MVP objective only
if s == mod.INVALID_SCORE:
    print(f"reject: invalid metrics or score≠qubits*toffoli (score={s})")
    sys.exit(1)
print(f"shape ok: qubits×toffoli = {s}")
if s <= threshold:
    print(f"clears toy MVP threshold {threshold} (minimize) — can commit–reveal on that objective")
else:
    print(
        f"outside toy MVP threshold {threshold}: use ecdsafail run/submit for "
        "real-scale scores; this check only validated the product identity"
    )
print(f"objective: {os.environ['OID']}")
print("Nothing was recorded. This was a local check.")
PY
}

cmd_import_score() {
  local score_json=${1:?score.json required}
  local out="${2:-/tmp/pw-ecdsa-artifact.json}"
  python3 "$EXAMPLE/score_to_artifact.py" "$score_json" -o "$out"
  echo "wrote $out" >&2
  cmd_score "$out"
}

cmd_pull() {
  if ! command -v ecdsafail >/dev/null 2>&1; then
    echo "ecdsafail CLI unavailable — not a rejection of any circuit." >&2
    exit 1
  fi
  ecdsafail benchmark
  echo
  cmd_map
}

case "${1:-}" in
  map) cmd_map ;;
  score) shift; cmd_score "$@" ;;
  import-score) shift; cmd_import_score "$@" ;;
  pull) cmd_pull ;;
  *) usage ;;
esac
