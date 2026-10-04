#!/usr/bin/env bash
# `cairn work` end to end: a second machine joins a node over HTTP with nothing
# but the binary and a solver command, and is paid.
#
# What it checks, against the real binary and a real node:
#   1. the worker takes an assignment and shows up on GET /progress as live
#      while its solver runs -- the roster the reader's challenge page draws;
#   2. what the solver prints is committed in one epoch and revealed in a
#      later one, which is the only order the node accepts;
#   3. the node's pinned verifier accepts it and the settlement names the
#      worker -- the worker never grades anything itself.
#
# The "second machine" is a process on this one: the only thing it shares
# with the node is the HTTP address, which is exactly what a LAN worker has.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
[ -x "$RUST" ] || { echo "building release binary..." >&2; cargo build --release; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-work-XXXXXX)
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

# Short epochs so a commit and its reveal fit in a demo, and nothing that
# reaches past this host.
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

HTTP=${CAIRN_WORK_HTTP:-38280}
P2P=${CAIRN_WORK_P2P:-39280}
LOG="$WORK/log.jsonl"
BASE="http://127.0.0.1:$HTTP"

rule "a node with one open objective"
OID=$("$RUST" --log "$LOG" --root . post examples/collatz/objective.json | head -1 | awk '{print $2}')
echo "objective $OID"
"$RUST" --log "$LOG" --root . p2p \
  --identity "$WORK/id.json" --root-key "$WORK/rk.json" --checkpoint "$WORK/cp.json" \
  --listen "127.0.0.1:$P2P" --queue "$WORK/queue" --serve "127.0.0.1:$HTTP" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
await_port "$HTTP" || { cat "$WORK/node.log" >&2; fail "the node never bound its HTTP port"; }

rule "a worker joins with a solver that takes a few seconds"
# The solver reads its assignment from stdin, as every solver may, and prints
# one candidate. The sleep keeps it running long enough to be seen heartbeating.
cat >"$WORK/solver.sh" <<'SH'
#!/bin/sh
read -r assignment
case "$assignment" in *'"epoch"'*) ;; *) echo "no assignment on stdin" >&2; exit 1 ;; esac
[ -n "$CAIRN_OBJECTIVE" ] || { echo "no CAIRN_OBJECTIVE" >&2; exit 1; }
sleep 4
echo '{"n": 626331}'
SH
chmod +x "$WORK/solver.sh"
"$RUST" work --node "$BASE" --objective "$OID" --worker garage --device "demo box" \
  --rounds 1 --heartbeat 1 --margin 2 -- "$WORK/solver.sh" >"$WORK/worker.log" 2>&1 &
WORKER_PID=$!

LIVE=0
for _ in $(seq 1 40); do
  LIVE=$(curl -s "$BASE/progress/$OID" | python3 -c '
import json,sys
r=json.load(sys.stdin)["reported"]["workers"]
print(sum(1 for w in r if w["worker"]=="garage" and w["status"]=="live" and w["device"]=="demo box"))')
  [ "$LIVE" = "1" ] && break
  sleep 0.5
done
[ "$LIVE" = "1" ] || { cat "$WORK/worker.log" >&2; fail "the worker never showed up live on the roster"; }
echo "  garage is on the roster, live, while its solver runs"

rule "it commits, waits out the epoch, reveals, and exits"
for _ in $(seq 1 90); do
  kill -0 "$WORKER_PID" 2>/dev/null || break
  sleep 1
done
kill -0 "$WORKER_PID" 2>/dev/null && { cat "$WORK/worker.log" >&2; fail "the worker is still running"; }
wait "$WORKER_PID" || { cat "$WORK/worker.log" >&2; fail "the worker exited non-zero"; }
WORKER_PID=""
grep -q "committed a candidate" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "nothing committed"; }
grep -q "revealed the candidate" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "nothing revealed"; }
cat "$WORK/worker.log" | sed 's/^/  /'

rule "the node's verifier accepts it and the settlement pays the worker"
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
if [ -z "$PAID" ]; then
  # Say which half failed: a worker problem, or a host that cannot run the
  # checker at all. The second is common on a Mac whose python3 is a pyenv or
  # asdf shim under $HOME, which the verifier's deny-by-default sandbox cannot
  # read -- the checker exits 126 and the verdict is `unavailable`.
  curl -s "$BASE/log" | python3 -c '
import json,sys
for line in sys.stdin:
    r=json.loads(line)
    if r["kind"]=="verdict":
        v=r["payload"]["verdict"]; print("  verdict:", v["status"], "-", v.get("detail",""))' >&2
  fail "no settlement paid the worker (an unavailable verdict is this host's checker, not the worker; try PATH=/usr/bin:\$PATH)"
fi
echo "  garage was paid $PAID"

printf '\n\033[32mok\033[0m: a worker that shares nothing with the node but its address took work, showed up, and was paid\n'
