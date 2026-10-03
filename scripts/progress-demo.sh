#!/usr/bin/env bash
# A divided search watched from the outside: three workers, one node, the
# dashboard's two kinds of number.
#
# `orbit-demo.sh` proves the rules -- an orbit paid once, a collision solved,
# a private-rule trail caught -- with one script playing every submitter from
# the same shell. What it cannot show is the thing an operator running the
# real ECC2K-130 search looks at: a fleet of workers that share nothing with
# the node but an address, each taking its slice, walking it, posting what it
# is doing, and submitting batches that the node settles while the others
# keep walking. This script runs that on the 21-bit twin, with
# `examples/certicom-ecdlp/tools/orbit_worker.py` as the worker, and then
# checks `GET /progress/{id}` says what happened:
#
#   - `reported` names every worker as live, with the slice it took and a
#     rate, before anything has settled -- the heartbeat half;
#   - `derived` names the workers the log actually paid, with units and
#     steps summed from their witnesses -- the settled half;
#   - the two halves agree about who the workers are and disagree about
#     nothing, because they measure different things.
#
# It also pins what the heartbeat is not: the log is the same length after a
# heartbeat as before it, and a heartbeat for an objective this node does not
# hold is refused.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
[ -x "$RUST" ] || { echo "building release binary..." >&2; cargo build --release; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-progress-XXXXXX)
NODE_PID=""
WORKER_PIDS=()
cleanup() {
  for pid in "${WORKER_PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
  [ -n "${KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

# Twenty-second epochs: a worker commits in one and reveals in the next, so
# a batch is paid in about a minute. The node drains every five seconds and
# the worker keeps the last eight seconds of an epoch clear of posts.
# No beacons and no seeds, for the reason node-smoke.sh gives: a node here
# must talk to nobody but the workers this script starts.
export CAIRN_EPOCH_SECONDS=20
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

HTTP=${CAIRN_PROGRESS_HTTP:-38180}
P2P=${CAIRN_PROGRESS_P2P:-39180}
LOG="$WORK/log.jsonl"
BASE="http://127.0.0.1:$HTTP"
JOB=examples/certicom-ecdlp/jobs/ecc2k-23.json
WORKER="python3 examples/certicom-ecdlp/tools/orbit_worker.py"

rule "the coordinator posts the divided problem and starts a node"
OID=$("$RUST" --log "$LOG" --root . post examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json \
  | head -1 | awk '{print $2}')
echo "objective $OID"
# `p2p --serve` rather than `run`: the same daemon, the same queue drained by
# the same process, and it starts on a binary built without the embedded
# reader -- which is what CI builds. The dashboard page needs the reader;
# the route it reads does not, and the route is what this script checks.
"$RUST" --log "$LOG" --root . p2p \
  --identity "$WORK/id.json" --root-key "$WORK/rk.json" --checkpoint "$WORK/cp.json" \
  --listen "127.0.0.1:$P2P" --queue "$WORK/queue" --serve "127.0.0.1:$HTTP" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
await_port "$HTTP" || { cat "$WORK/node.log" >&2; fail "the node never bound its HTTP port"; }
kill -0 "$NODE_PID" 2>/dev/null || { cat "$WORK/node.log" >&2; fail "the node exited at startup"; }
echo "node on $BASE"

rule "the dashboard before anybody works: nothing paid, nobody reporting"
curl -sf "$BASE/progress/$OID" > "$WORK/empty.json" || fail "GET /progress answered an error"
python3 - "$WORK/empty.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert p["kind"] == "piecework", p["kind"]
assert p["derived"]["units_paid"] == 0 and p["derived"]["workers"] == [], p["derived"]
assert p["reported"]["live"] == 0 and p["reported"]["workers"] == [], p["reported"]
assert p["derived"]["coverage"] is None, "no worker has declared trail_bits yet"
print("  empty, as it should be")
PY

rule "a heartbeat for an objective this node does not hold is refused"
STATUS=$(curl -s -o "$WORK/stranger.json" -w '%{http_code}' -H 'content-type: application/json' \
  -d '{"objective_id":"sha256:0000","worker":"stranger","steps":1}' "$BASE/progress")
[ "$STATUS" = "404" ] || { cat "$WORK/stranger.json"; fail "a heartbeat against an unknown objective answered $STATUS, want 404"; }
echo "  404, as it should be"

rule "three workers take their slices and start walking"
LINES_BEFORE=$(curl -s "$BASE/log" | wc -l)
for who in alice bob carol; do
  $WORKER --node "$BASE" --job "$JOB" --objective "$OID" --worker "$who" \
    --partitions 3 --batch 4 --heartbeat 3 --max-batches 1 --trails-per-unit 2 \
    --device "demo-$who" >"$WORK/$who.log" 2>&1 &
  WORKER_PIDS+=("$!")
done

# Within a few seconds every worker has posted at least one heartbeat.
for _ in $(seq 1 60); do
  LIVE=$(curl -s "$BASE/progress/$OID" | python3 -c 'import json,sys; print(json.load(sys.stdin)["reported"]["live"])')
  [ "$LIVE" = "3" ] && break
  sleep 0.5
done
[ "$LIVE" = "3" ] || { cat "$WORK"/*.log >&2; fail "only $LIVE of 3 workers are live on the roster"; }
curl -s "$BASE/progress/$OID" > "$WORK/reporting.json"
python3 - "$WORK/reporting.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
r = p["reported"]
names = sorted(w["worker"] for w in r["workers"])
assert names == ["alice", "bob", "carol"], names
for w in r["workers"]:
    assert w["status"] == "live", w
    assert w["units"] and w["units"]["end"] > w["units"]["first"], w
    assert w["client"] == "orbit_worker.py/1" and w["device"] == f"demo-{w['worker']}", w
# Each worker holds one of the three slices of 4096 units. Which one is a
# hash of the epoch beacon and its name, so two workers may share a slice:
# the design calls that a little duplicated compute and not an error, and
# this script must not promise more than the rules do.
thirds = {(0, 1365), (1365, 2730), (2730, 4096)}
ranges = [(w["units"]["first"], w["units"]["end"]) for w in r["workers"]]
assert all(span in thirds for span in ranges), ranges
# The heartbeat declared the seed layout, so the derived half can now bin.
assert p["derived"]["coverage"] is not None and p["derived"]["coverage"]["trail_bits"] == 16
assert p["derived"]["units_paid"] == 0, "nothing can have settled this fast"
print(f"  {r['live']} live: " + ", ".join(f"{w['worker']} on [{w['units']['first']}, {w['units']['end']})" for w in r["workers"]))
PY
LINES_AFTER=$(curl -s "$BASE/log" | wc -l)
[ "$LINES_AFTER" -eq "$LINES_BEFORE" ] || fail "heartbeats changed the log ($LINES_BEFORE -> $LINES_AFTER lines)"
echo "  the log is untouched: a heartbeat is not a record"

rule "each worker commits a batch of four, reveals it next epoch, and is paid"
for pid in "${WORKER_PIDS[@]}"; do
  wait "$pid" || { cat "$WORK"/*.log >&2; fail "a worker exited non-zero"; }
done
WORKER_PIDS=()
cat "$WORK"/alice.log | sed 's/^/  alice: /' | tail -4

# Settlement waits for the reveal epoch to close and the finality delay to
# clear; the daemon settles on its next drain after that.
for _ in $(seq 1 120); do
  CLAIMS=$(curl -s "$BASE/progress/$OID" | python3 -c 'import json,sys; d=json.load(sys.stdin)["derived"]; print(d["claims_paid"] + d["rejected"])')
  [ "$CLAIMS" -ge 3 ] && break
  sleep 1
done
curl -s "$BASE/progress/$OID" > "$WORK/paid.json"
python3 - "$WORK/paid.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
d, r = p["derived"], p["reported"]
# Twelve orbits were submitted in three batches of four. On a 21-bit group
# the whole search is about forty orbits, so two workers reaching one orbit
# is a live possibility here rather than a once-a-year event: the later
# batch then pays for three, and that duplicate is the collision the search
# exists to find. The rules promise the rest.
assert d["claims_paid"] == 3, d
assert d["elements"] == 12, d["elements"]
assert 10 <= d["units_paid"] <= 12, f"{d['units_paid']} units paid, want 12 less any cross-worker collisions"
assert d["reward"] == 100 * d["units_paid"], (d["reward"], d["units_paid"])
assert d["steps"] > 0, "the witness counters sum to the steps walked"
if d["units_paid"] < 12:
    print(f"  ({12 - d['units_paid']} orbit(s) reached by two workers: paid once, as a collision should be)")
paid = {w["submitter"]: w for w in d["workers"]}
assert sorted(paid) == ["alice", "bob", "carol"], sorted(paid)
for name, w in paid.items():
    assert 3 <= w["units_paid"] <= 4 and w["claims_paid"] == 1 and w["in_flight"] == 0 and w["rejected"] == 0, w
    assert w["steps"] > 0 and w["first_paid_at"] and w["last_paid_at"], w
assert d["last_hour"]["units_paid"] == d["units_paid"] and len(d["hourly"]) >= 1, (d["last_hour"], d["hourly"])
cov = d["coverage"]
assert cov["units"] == 4096 and sum(cov["counts"]) == 12 and cov["units_touched"] >= 3, cov
# The reported half still names the same three, each with a rate. On the
# twin a worker is done in seconds, which is shorter than the thirty-second
# span the node insists on before it measures a rate of its own, so what is
# promised here is the worker's reported rate; the measured one appears
# when a worker lives long enough, and the dashboard prefers it.
reported = {w["worker"]: w for w in r["workers"]}
assert sorted(reported) == ["alice", "bob", "carol"], sorted(reported)
for w in reported.values():
    assert w["units_submitted"] == 4, w
    assert w["reported_steps_per_second"] is not None or w["measured_steps_per_second"] is not None, w
assert p["piecework"]["paid_total"] == d["reward"] and p["piecework"]["pool_remaining"] == 8000 - d["reward"], p["piecework"]
print(f"  paid: " + ", ".join(f"{n} {w['units_paid']} orbits / {w['steps']} steps" for n, w in sorted(paid.items())))
print(f"  reported: " + ", ".join(
    f"{n} {w['measured_steps_per_second'] if w['measured_steps_per_second'] is not None else w['reported_steps_per_second']} it/s"
    for n, w in sorted(reported.items())))
PY

rule "the node's own audit agrees with what the dashboard derived"
# The daemon holds the write lock, but reading takes none.
"$RUST" --log "$LOG" --root . audit --no-rerun | tee "$WORK/audit.out" | tail -1
grep -q "chain intact" "$WORK/audit.out" || fail "the log does not audit clean"

if [ -n "${PROGRESS_DEMO_SCREENSHOT:-}" ]; then
  rule "the dashboard, as a browser draws it"
  UI_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/ui/")
  [ "$UI_CODE" = "200" ] || { echo "  (this binary has no embedded reader; build with \`make ui-build\` to see the page)"; UI_CODE=""; }
  CHROME=$(ls /opt/pw-browsers/chromium_headless_shell-*/chrome-linux/headless_shell 2>/dev/null | head -1 || true)
  [ -n "$UI_CODE" ] || CHROME=""
  [ -n "$CHROME" ] || CHROME=$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)
  if [ -n "$CHROME" ] && [ -n "$UI_CODE" ]; then
    "$CHROME" --headless --disable-gpu --no-sandbox --hide-scrollbars --window-size=1360,2000 \
      --virtual-time-budget=8000 --screenshot="$PROGRESS_DEMO_SCREENSHOT" \
      "$BASE/ui/task/?id=$OID" >/dev/null 2>&1 && echo "  wrote $PROGRESS_DEMO_SCREENSHOT" \
      || echo "  (screenshot failed; the dashboard is at $BASE/ui/task/?id=$OID while this node runs)"
  elif [ -n "$UI_CODE" ]; then
    echo "  (no headless browser here; the dashboard is at $BASE/ui/task/?id=$OID while this node runs)"
  fi
fi

printf '\n\033[32mPROGRESS OK: three workers took their slices, reported themselves live, were paid for their orbits, and the dashboard says both -- separately.\033[0m\n'
