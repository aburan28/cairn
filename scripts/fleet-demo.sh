#!/usr/bin/env bash
# A fleet of enrolled members, end to end: a leader that trusts no network, an
# invitation, a join, a member that works from "anywhere" and is never handed
# the leader's key, a settlement that names the leader, and a revocation that
# stops the member at its next request.
#
# What it checks, against the real binary and a real node:
#   1. a leader with CAIRN_FLEET=enrolled refuses a stranger -- loopback
#      included -- that hands it a record naming the leader;
#   2. `cairn fleet invite` mints a token and `cairn fleet join` enrolls with
#      it over HTTP, pinning the leader's key from the token;
#   3. `cairn work --fleet` takes its slice under the member's name, is marked
#      a member on the roster, and commits and reveals records that the
#      leader signs as itself -- and the verifier's settlement pays the leader;
#   4. the leader's journal names the member for each record it signed, and
#      the member's name is reserved against a heartbeat it did not sign;
#   5. `cairn fleet revoke` takes effect at the member's next request.
#
# The member is a process on this machine, sharing nothing with the leader
# but its HTTP address and the token: exactly what a rented GPU has.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
[ -x "$RUST" ] || { echo "building release binary..." >&2; cargo build --release; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-fleet-XXXXXX)
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
# Nothing in this run may fall back to a member file in the caller's home.
unset CAIRN_FLEET_FILE CAIRN_INVITE

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

HTTP=${CAIRN_FLEET_DEMO_HTTP:-38380}
P2P=${CAIRN_FLEET_DEMO_P2P:-39380}
LOG="$WORK/log.jsonl"
BASE="http://127.0.0.1:$HTTP"

rule "a leader that signs for enrolled members and nobody else"
OID=$("$RUST" --log "$LOG" --root . post examples/collatz/objective.json | head -1 | awk '{print $2}')
echo "objective $OID"
"$RUST" identity --out "$WORK/leader.json" >/dev/null
LEADER=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public"])' "$WORK/leader.json")
CAIRN_FLEET=enrolled CAIRN_FLEET_IDENTITY="$WORK/leader.json" \
"$RUST" --log "$LOG" --root . p2p \
  --identity "$WORK/id.json" --root-key "$WORK/rk.json" --checkpoint "$WORK/cp.json" \
  --listen "127.0.0.1:$P2P" --queue "$WORK/queue" --serve "127.0.0.1:$HTTP" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
await_port "$HTTP" || { cat "$WORK/node.log" >&2; fail "the leader never bound its HTTP port"; }
python3 - "$BASE" "$LEADER" <<'PY'
import json, sys, urllib.request
base, leader = sys.argv[1:3]
fleet = json.load(urllib.request.urlopen(base + "/network", timeout=10))["node"]["fleet"]
assert fleet["signs_as"] == leader, fleet
assert fleet["sources"] == ["enrolled"], fleet
assert fleet["members"] == {"enrolled": 0, "live": 0}, fleet
PY
echo "  node.fleet: signs as the leader, for enrolled members, of whom there are none"

STRANGER=$(curl -s -o "$WORK/stranger.json" -w '%{http_code}' -H 'content-type: application/json' \
  -d "{\"type\":\"commitment\",\"objective_id\":\"$OID\",\"submitter\":\"$LEADER\",\"hash\":\"sha256:$(printf '1%.0s' $(seq 1 64))\",\"created_at\":\"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)\"}" \
  "$BASE/submit?kind=commitment")
[ "$STRANGER" = "403" ] || { cat "$WORK/stranger.json" >&2; fail "a stranger's record naming the leader answered $STRANGER, not 403"; }
grep -q '"reason":"not_a_member"' "$WORK/stranger.json" || fail "the refusal carried no not_a_member reason"
echo "  a stranger on loopback asking for the leader's signature -> 403 not_a_member"

rule "an invitation, and a member that joins with it"
"$RUST" --log "$LOG" fleet invite --identity "$WORK/leader.json" --prefix demo --uses 2 \
  --expires 1h --node "$BASE" --json >"$WORK/invite.json"
TOKEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$WORK/invite.json")
case "$TOKEN" in cairn-invite1.$LEADER.*) ;; *) fail "the token does not carry the leader's key" ;; esac
echo "  token minted: cairn-invite1.<leader key>.<invite seed>"
# Through the environment, as a secret store would hand it over.
CAIRN_INVITE="$TOKEN" "$RUST" fleet join --node "$BASE" --out "$WORK/member.json" \
  >"$WORK/join.log" 2>&1 || { cat "$WORK/join.log" "$WORK/node.log" >&2; fail "cairn fleet join failed"; }
NAME=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["name"])' "$WORK/member.json")
case "$NAME" in demo-????????????) ;; *) fail "the member was named $NAME, not demo-<12 hex>" ;; esac
MODE=$(python3 -c 'import os,stat,sys; print(oct(stat.S_IMODE(os.stat(sys.argv[1]).st_mode)))' "$WORK/member.json")
[ "$MODE" = "0o600" ] || fail "the member file is $MODE, not 0600"
"$RUST" --log "$LOG" fleet list | sed 's/^/  /'

rule "the member works: its slice under its own name, its records signed by the leader"
cat >"$WORK/solver.sh" <<'SH'
#!/bin/sh
read -r assignment
case "$assignment" in *'"epoch"'*) ;; *) echo "no assignment on stdin" >&2; exit 1 ;; esac
sleep 4
echo '{"n": 626331}'
SH
chmod +x "$WORK/solver.sh"
sleep "$(python3 -c 'import os,time; n=int(os.environ["CAIRN_EPOCH_SECONDS"]); print(n - time.time() % n + 0.2)')"
# No --node: the member file names its leader. No --submitter: the file pins it.
"$RUST" work --fleet "$WORK/member.json" --objective "$OID" --worker gpu0 --device "rented box" \
  --rounds 1 --heartbeat 1 --margin 2 -- "$WORK/solver.sh" >"$WORK/worker.log" 2>&1 &
WORKER_PID=$!

LIVE=0
for _ in $(seq 1 40); do
  LIVE=$(curl -s "$BASE/progress/$OID" | python3 -c '
import json,sys
want=sys.argv[1]
r=json.load(sys.stdin)["reported"]["workers"]
print(sum(1 for w in r if w["worker"]==want and w["status"]=="live" and w.get("member") is True))' "$NAME/gpu0")
  [ "$LIVE" = "1" ] && break
  sleep 0.5
done
[ "$LIVE" = "1" ] || { cat "$WORK/worker.log" >&2; fail "the member never showed up live, as a member, on the roster"; }
echo "  $NAME/gpu0 is on the roster, live, marked a member"

# Its name is its own: the same heartbeat without its signature is refused.
RESERVED=$(curl -s -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
  -d "{\"objective_id\":\"$OID\",\"worker\":\"$NAME/gpu9\",\"steps\":1}" "$BASE/progress")
[ "$RESERVED" = "403" ] || fail "an unsigned heartbeat under the member's name answered $RESERVED, not 403"
echo "  an unsigned heartbeat under $NAME/… -> 403: the name is reserved"

for _ in $(seq 1 90); do
  kill -0 "$WORKER_PID" 2>/dev/null || break
  sleep 1
done
kill -0 "$WORKER_PID" 2>/dev/null && { cat "$WORK/worker.log" >&2; fail "the member is still running"; }
wait "$WORKER_PID" || { cat "$WORK/worker.log" >&2; fail "the member exited non-zero"; }
WORKER_PID=""
grep -q "committed a candidate" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "nothing committed"; }
grep -q "revealed the candidate" "$WORK/worker.log" || { cat "$WORK/worker.log" >&2; fail "nothing revealed"; }
sed 's/^/  /' "$WORK/worker.log"

rule "the settlement pays the leader, and the journal says which member found it"
PAID=""
for _ in $(seq 1 60); do
  PAID=$(curl -s "$BASE/log" | python3 -c '
import json,sys
leader=sys.argv[1]
for line in sys.stdin:
    r=json.loads(line)
    if r["kind"]=="settlement" and r["payload"]["submitter"]==leader:
        print(r["payload"]["reward"]); break' "$LEADER")
  [ -n "$PAID" ] && break
  sleep 1
done
if [ -z "$PAID" ]; then
  curl -s "$BASE/log" | python3 -c '
import json,sys
for line in sys.stdin:
    r=json.loads(line)
    if r["kind"]=="verdict":
        v=r["payload"]["verdict"]; print("  verdict:", v["status"], "-", v.get("detail",""))' >&2
  cat "$WORK/node.log" >&2
  fail "no settlement paid the leader (an unavailable verdict is this host's checker; try PATH=/usr/bin:\$PATH)"
fi
echo "  the leader was paid $PAID; the member never held its key"
python3 - "$WORK/fleet/journal.jsonl" "$NAME" <<'PY'
import json, sys
path, name = sys.argv[1:3]
lines = [json.loads(line) for line in open(path)]
kinds = sorted(line["kind"] for line in lines if line["name"] == name)
assert kinds == ["claim", "commitment"], f"the journal holds {kinds} for {name}"
PY
echo "  journal.jsonl: one commitment and one claim, both $NAME's"

rule "a revocation stops the member at its next request"
"$RUST" --log "$LOG" fleet revoke "$NAME" --reason "rental over" | sed 's/^/  /'
HB="{\"objective_id\":\"$OID\",\"worker\":\"$NAME/gpu0\",\"steps\":2}"
AUTH=$(printf '%s' "$HB" | "$RUST" fleet sign --member "$WORK/member.json" --target /progress)
REVOKED=$(curl -s -o "$WORK/revoked.json" -w '%{http_code}' -H 'content-type: application/json' \
  -H "authorization: $AUTH" -d "$HB" "$BASE/progress")
[ "$REVOKED" = "401" ] || { cat "$WORK/revoked.json" >&2; fail "a revoked member's request answered $REVOKED, not 401"; }
grep -q '"reason":"member_revoked"' "$WORK/revoked.json" || fail "the refusal did not say member_revoked"
echo "  its signed heartbeat -> 401 member_revoked"

printf '\n\033[32mok\033[0m: an invited machine joined from nothing but a token and an address, worked under its own name, was paid to the leader, and was cut off by one command\n'
