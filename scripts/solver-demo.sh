#!/usr/bin/env bash
# Solver packages end to end: an objective's solver is published to a node,
# and a worker that chooses nothing joins, runs it in the sandbox, and is paid.
#
# What it checks, against the real binary, a real node and the real jail:
#   1. `cairn solver add` refuses nothing it should accept: the example package
#      passes its own known-answer tests, including the objective's pinned
#      checker accepting what it prints, and is filed in the node's store;
#   2. GET /solvers?objective= names it, and GET /objectives says it is ready;
#   3. `cairn work --package auto` fetches it, checks every file against the
#      pin, runs its tests on this machine, runs a round in the sandbox, and
#      the candidate is committed, revealed and paid to the worker;
#   4. a package whose bytes changed on the node is refused by a worker before
#      anything runs: the node is trusted for nothing but the choice.
#
# Needs a sandbox (seatbelt on macOS, bubblewrap on Linux) and a python3 the
# sandbox can run -- not a pyenv/asdf shim; try PATH=/usr/bin:$PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
[ -x "$RUST" ] || { echo "building release binary..." >&2; cargo build --release; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-solver-XXXXXX)
NODE_PID=""
WORKER_PID=""
cleanup() {
  for pid in "$WORKER_PID" "$NODE_PID"; do
    [ -n "$pid" ] || continue
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  [ -n "${KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

export CAIRN_EPOCH_SECONDS=12
export CAIRN_BEACON_PORT=off
export CAIRN_SEEDS=off

await_port() {
  for _ in $(seq 1 100); do
    if python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)
" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}

HTTP=${CAIRN_SOLVER_HTTP:-38290}
P2P=${CAIRN_SOLVER_P2P:-39290}
LOG="$WORK/log.jsonl"
BASE="http://127.0.0.1:$HTTP"
# The node's bundle root: the objective's checker at its pinned path, and
# nothing of this checkout's, so the store lands here rather than in the repo.
ROOT="$WORK/root"
PACKAGE=examples/certicom-ecdlp/solvers/ecc2k-23-orbit
mkdir -p "$ROOT/examples/certicom-ecdlp/checkers"
cp examples/certicom-ecdlp/checkers/ecc2k23_orbit_batch.py "$ROOT/examples/certicom-ecdlp/checkers/"

rule "an objective, and the solver its author publishes for it"
OBJECTIVE=examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json
# The solver first: `cairn post` refuses an objective that ships none.
"$RUST" --log "$LOG" --root "$ROOT" solver add "$PACKAGE" --objective "$OBJECTIVE" | sed 's/^/  /'
PID=$("$RUST" --log "$LOG" --root "$ROOT" solver list | awk 'NR==1 {print $1}')
[ -n "$PID" ] || fail "solver add filed nothing"
OID=$("$RUST" --log "$LOG" --root "$ROOT" post "$OBJECTIVE" | head -1 | awk '{print $2}')
echo "objective $OID"

"$RUST" --log "$LOG" --root "$ROOT" p2p \
  --identity "$WORK/id.json" --root-key "$WORK/rk.json" --checkpoint "$WORK/cp.json" \
  --listen "127.0.0.1:$P2P" --queue "$WORK/queue" --serve "127.0.0.1:$HTTP" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
await_port "$HTTP" || { cat "$WORK/node.log" >&2; fail "the node never bound its HTTP port"; }

rule "the node offers it"
RECOMMENDED=$(curl -s "$BASE/solvers?objective=$OID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["recommended"])')
[ "$RECOMMENDED" = "$PID" ] || fail "GET /solvers recommended $RECOMMENDED, not $PID"
READY=$(curl -s "$BASE/objectives" | python3 -c "
import json,sys
for o in json.load(sys.stdin)['objectives']:
    if o['id']=='$OID': print(o['solver'] and o['solver']['ready'])")
[ "$READY" = "True" ] || fail "GET /objectives does not say the solver is ready"
echo "  $PID is recommended, and the objective row says ready"

rule "a worker that chooses nothing joins, and is paid"
sleep "$(python3 -c 'import os,time; n=int(os.environ["CAIRN_EPOCH_SECONDS"]); print(n - time.time() % n + 0.2)')"
"$RUST" work --node "$BASE" --objective "$OID" --worker garage \
  --rounds 1 --heartbeat 1 --margin 2 --package auto --package-cache "$WORK/cache" \
  >"$WORK/worker.log" 2>&1 &
WORKER_PID=$!
for _ in $(seq 1 90); do
  kill -0 "$WORKER_PID" 2>/dev/null || break
  sleep 1
done
kill -0 "$WORKER_PID" 2>/dev/null && { cat "$WORK/worker.log" >&2; fail "the worker is still running"; }
wait "$WORKER_PID" || { cat "$WORK/worker.log" >&2; fail "the worker exited non-zero"; }
WORKER_PID=""
grep -q "solver ecc2k-23-orbit-walk" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "the worker did not run the published solver"; }
grep -q "committed a candidate" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "nothing committed"; }
grep -q "revealed the candidate" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "nothing revealed"; }
sed 's/^/  /' "$WORK/worker.log"
PAID=""
for _ in $(seq 1 60); do
  PAID=$(curl -s "$BASE/log" | python3 -c '
import json,sys
for line in sys.stdin:
    r=json.loads(line)
    if r["kind"]=="settlement" and r["payload"]["submitter"]=="garage":
        print(r["payload"]["reward"]); break')
  [ -n "$PAID" ] && break
  sleep 1
done
[ -n "$PAID" ] || { cat "$WORK/node.log" >&2; fail "no settlement paid the worker"; }
echo "  garage was paid $PAID"

rule "a package changed on the node is refused before it runs"
STORED="$ROOT/.cairn/solvers/${PID#sha256:}"
# Same length, different bytes: the node's own size check passes it, so what
# refuses it is the worker hashing what it was served against the pin.
chmod u+w "$STORED/orbit_solver.py"
python3 - "$STORED/orbit_solver.py" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[data.index(b"Adapt")] = ord("a")
open(path, "wb").write(bytes(data))
PY
if "$RUST" work --node "$BASE" --objective "$OID" --worker tampered \
  --rounds 1 --heartbeat 1 --package auto --package-cache "$WORK/cache2" >"$WORK/tampered.log" 2>&1; then
  cat "$WORK/tampered.log" >&2
  fail "a worker ran a package whose bytes no longer match its pin"
fi
grep -q "orbit_solver.py: the node served" "$WORK/tampered.log" || { cat "$WORK/tampered.log" >&2; fail "the worker did not refuse the file by its hash"; }
grep -q "committed a candidate" "$WORK/tampered.log" && fail "the tampered package ran a round"
sed 's/^/  /' "$WORK/tampered.log"

printf '\n\033[32mok\033[0m: a worker that chose no program ran the objective'"'"'s published solver in the sandbox and was paid\n'
