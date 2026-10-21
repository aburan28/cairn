#!/usr/bin/env bash
# A solver package travels between nodes over p2p, and a worker pointed at the
# node that received it runs it and is paid.
#
# Every Cairn.app user runs their own node, so this is the case that decides
# whether Start works for anybody but the author: the package lives on the
# author's node A, the contributor's node B has never seen it, and B learns the
# objective, its checker and its package from A in its own p2p sessions.
#
# What it checks, against the real binary, two real daemons and the real jail:
#   1. A holds an objective that pins a package, and offers it;
#   2. B, started with an empty log, an empty bundle root and A's address,
#      receives the objective, the pinned checker and every file of the
#      package, re-runs the package's tests itself, and only then offers it;
#   3. the copy B files is byte for byte A's;
#   4. `cairn work --package auto` against B -- not A -- fetches it from B,
#      runs a round in the sandbox, and the candidate is committed, revealed
#      and paid to the worker.
#
# Needs a sandbox (seatbelt on macOS, bubblewrap on Linux) and a python3 the
# sandbox can run -- not a pyenv/asdf shim; try PATH=/usr/bin:$PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
[ -x "$RUST" ] || { echo "building release binary..." >&2; cargo build --release; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-solver-sync-XXXXXX)
A="$WORK/a"
B="$WORK/b"
mkdir -p "$A/root" "$B/root" "$B/queue"
APID=""
BPID=""
WORKER_PID=""
cleanup() {
  for pid in "$WORKER_PID" "$BPID" "$APID"; do
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
# Not an operator's real at-rest key, for the reason scripts/p2p-demo.sh gives.
export CAIRN_KEY="$WORK/no-at-rest-key"

free_port() {
  python3 -c "
import socket
s = socket.socket(); s.bind(('127.0.0.1', 0))
print(s.getsockname()[1]); s.close()"
}
await_port() {
  for _ in $(seq 1 150); do
    if python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)
" 2>/dev/null; then return 0; fi
    sleep 0.1
  done
  return 1
}
A_PORT=$(free_port)
B_PORT=$(free_port)
B_HTTP=$(free_port)
BASE="http://127.0.0.1:$B_HTTP"

rule "A: an objective that pins its solver"
# The example package names the objective it was written for, which makes it
# an approach -- and approaches stay with the operator who chose them. A pin is
# what travels, so the author packs a copy without that field and pins it.
cp -r examples/certicom-ecdlp/solvers/ecc2k-23-orbit "$WORK/package"
python3 - "$WORK/package/solver.json" <<'PY'
import json, sys
path = sys.argv[1]
manifest = json.load(open(path))
manifest.pop("objective", None)
json.dump(manifest, open(path, "w"), indent=2, sort_keys=True)
PY
PID=$("$RUST" solver pack "$WORK/package" | awk 'NR==1 {print $2}')
[ -n "$PID" ] || fail "solver pack printed no id"
python3 - "$PID" examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json "$WORK/objective.json" <<'PY'
import json, sys
pin, source, out = sys.argv[1:]
objective = json.load(open(source))
objective["verifier"]["capabilities"] = {"worker": {"mode": "package", "package": pin}}
json.dump(objective, open(out, "w"), indent=2, sort_keys=True)
PY
mkdir -p "$A/root/examples/certicom-ecdlp/checkers"
cp examples/certicom-ecdlp/checkers/ecc2k23_orbit_batch.py "$A/root/examples/certicom-ecdlp/checkers/"
"$RUST" --log "$A/log.jsonl" --root "$A/root" solver add "$WORK/package" --objective "$WORK/objective.json" | sed 's/^/  /'
OID=$("$RUST" --log "$A/log.jsonl" --root "$A/root" post "$WORK/objective.json" | head -1 | awk '{print $2}')
echo "  objective $OID pins $PID"

"$RUST" --log "$A/log.jsonl" --root "$A/root" p2p \
  --identity "$A/id.json" --root-key "$A/rk.json" --checkpoint "$A/cp.json" \
  --listen "127.0.0.1:$A_PORT" >"$A/daemon.log" 2>&1 &
APID=$!
for _ in $(seq 1 150); do
  [ -s "$A/id.json" ] && break
  sleep 0.2
done
[ -s "$A/id.json" ] || fail "A never wrote its transport identity"
await_port "$A_PORT" || { cat "$A/daemon.log" >&2; fail "A never listened on $A_PORT"; }
python3 -c "
import json
i = json.load(open('$A/id.json'))
json.dump({'addr': '127.0.0.1:$A_PORT', 'public': i['public']}, open('$WORK/a-endpoint.json', 'w'))"
echo "  A listening on 127.0.0.1:$A_PORT"

rule "B: an empty log, an empty root, and A's address"
: > "$B/log.jsonl"
"$RUST" --log "$B/log.jsonl" --root "$B/root" p2p \
  --identity "$B/id.json" --root-key "$B/rk.json" --checkpoint "$B/cp.json" \
  --listen "127.0.0.1:$B_PORT" --bootstrap "$WORK/a-endpoint.json" \
  --queue "$B/queue" --serve "127.0.0.1:$B_HTTP" >"$B/daemon.log" 2>&1 &
BPID=$!
await_port "$B_HTTP" || { cat "$B/daemon.log" >&2; fail "B never bound its HTTP port"; }

# B offers the package only after its own check, which runs on its own thread
# after the session that brought the bytes; poll its offer, not its disk.
RECOMMENDED=""
for _ in $(seq 1 120); do
  RECOMMENDED=$(curl -s "$BASE/solvers?objective=$OID" | python3 -c '
import json,sys
try: print(json.load(sys.stdin).get("recommended") or "")
except Exception: print("")')
  [ "$RECOMMENDED" = "$PID" ] && break
  sleep 0.5
done
[ "$RECOMMENDED" = "$PID" ] || { sed 's/^/  /' "$B/daemon.log" >&2; fail "B never offered $PID (got '${RECOMMENDED:-nothing}')"; }
grep -E "solver packages: [0-9]+ item\(s\) staged" "$B/daemon.log" | head -1 | sed 's/^/  /'
grep -q "solver package $PID from a peer: its tests passed here; offered" "$B/daemon.log" \
  || { sed 's/^/  /' "$B/daemon.log" >&2; fail "B offered the package without saying its own tests passed"; }
echo "  B received $PID from A over p2p, ran its tests, and offers it"

HEX=${PID#sha256:}
for f in $(cd "$A/root/.cairn/solvers/$HEX" && find . -type f ! -name report.json | sort); do
  cmp -s "$A/root/.cairn/solvers/$HEX/$f" "$B/root/.cairn/solvers/$HEX/$f" || fail "$f differs between A and B"
done
[ -z "$(ls -A "$B/root/.cairn/solvers/.incoming" 2>/dev/null | grep -v '^\.' || true)" ] || fail "B left the package staged"
echo "  B's copy is byte for byte A's, and nothing is left staged"

rule "a worker pointed at B runs it, and is paid"
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
grep -q "solver ecc2k-23-orbit-walk" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "the worker did not run the pinned solver"; }
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
[ -n "$PAID" ] || { sed 's/^/  /' "$B/daemon.log" >&2; fail "no settlement on B paid the worker"; }
echo "  garage was paid $PAID by B"

printf '\n\033[32mok\033[0m: a package pinned on A reached B over p2p, passed its tests there, and a worker against B ran it and was paid\n'
