#!/usr/bin/env bash
# Two `proofwork-p2p` daemons: one with a settled log, one with nothing.
#
# The daemon is the largest surface in the repository -- service, sync, code
# transfer, DHT, multicast, populations -- and until this script nothing ran it.
# `--help` was the only thing CI touched. The pattern this session established
# is that bugs live in seams no single component owns, and the only way to reach
# a seam is to run both sides.
#
# What it demonstrates, and what each part is actually checking:
#
#   * B starts with an empty log and ends with A's records, verified on import
#     rather than trusted: every record is content-addressed, so B re-derives
#     each id instead of believing A's.
#   * B fetches the pinned verifier code it does not have, so it can re-run the
#     verdicts rather than take them on faith. A node that syncs records but not
#     code can only replay somebody else's opinion.
#   * B takes an honest gossiped candidate and refuses a lie about the same
#     artifact, because a claimed score is re-derived and never imported.
#   * Both logs audit, and the *independent* implementation audits B's.
#
# That last one is the point. Auditing the node that synced is the case that
# matters -- it is the node with no bundle, no authored objective, and every
# reason to want an independent check -- and it was broken: the reference had no
# content-addressed fallback, so it reported "was settled but can no longer be
# re-verified" for claims that re-verify perfectly.
#
# The two logs' Merkle roots *differ*, and that is correct. A ledger entry's
# timestamp is when this node wrote it, and B settles its own batch against its
# own anchor. Records are content-addressed and agree; the envelope around them
# is local. A checkpoint attests to one node's prefix, never to a root every
# node must share.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
DAEMON="${P2P_BIN:-./target/release/proofwork-p2p}"
SERVE="${SERVE_BIN:-./target/release/proofwork-serve}"
REF="${REF_BIN:-./reference/rust/target/release/proofwork-reference}"
if [ ! -x "$RUST" ] || [ ! -x "$DAEMON" ] || [ ! -x "$SERVE" ]; then
  echo "building release binaries..." >&2
  cargo build --release
fi
if [ ! -x "$REF" ]; then
  echo "building the reference implementation..." >&2
  cargo build --release --locked --manifest-path reference/rust/Cargo.toml
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-p2p-demo-XXXXXX)
A="$WORK/a"
B="$WORK/b"
mkdir -p "$A" "$B"
cleanup() {
  for pid in ${APID:-} ${BPID:-} ${SERVE_PID:-}; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT

# Exported so both daemons and every audit below slice the log at the same
# boundaries. Epochs are derived from record timestamps and never stored, so an
# auditor using a different length reports an honest batch as mis-ordered --
# `proofwork audit` says so itself when every batch faults at once.
export PROOFWORK_EPOCH_SECONDS=1
# Two free ports, taken by binding and releasing rather than guessed: a fixed
# port makes this script fail for whoever is already using it.
free_port() {
  python3 -c "
import socket
s = socket.socket(); s.bind(('127.0.0.1', 0))
print(s.getsockname()[1]); s.close()"
}
A_PORT=$(free_port)
B_PORT=$(free_port)

rule "A authors and settles, with the bundle it authored against"
cp -r examples "$A/"
OID=$("$RUST" --log "$A/log.jsonl" --root "$A" post examples/collatz/objective.json \
  | head -1 | awk '{print $2}')
echo "  objective $OID"
"$RUST" --log "$A/log.jsonl" --root "$A" commit "$OID" \
  --submitter alice --artifact examples/collatz/artifact.json --nonce n1 >/dev/null
sleep 1.1
"$RUST" --log "$A/log.jsonl" --root "$A" reveal "$OID" \
  --submitter alice --artifact examples/collatz/artifact.json --nonce n1 | sed 's/^/  /'
sleep 1.1
"$RUST" --log "$A/log.jsonl" --root "$A" settle | sed 's/^/  /'

# A second objective, left open. The collatz one above has settled, and a plain
# objective settles once -- so a commitment against it is correctly refused, and
# a queue test using it would prove only that the daemon can say no.
OPEN_OID=$("$RUST" --log "$A/log.jsonl" --root "$A" post examples/capset/objective.json \
  | head -1 | awk '{print $2}')
echo "  a second objective, still open: $OPEN_OID"

# A third objective, ratcheted, so gossiped candidates have a score to check.
SCORED_OID=$("$RUST" --log "$A/log.jsonl" --root "$A" post \
  examples/capset_progressive/objective.json | head -1 | awk '{print $2}')
echo "  a ratcheted objective, for the population round: $SCORED_OID"

# A's population: one honest candidate and one lie about the *same* artifact.
# The rule that makes gossip safe at all is that a peer's claimed score is
# re-derived and never imported, so B must end up with the first and not the
# second. Nothing exercised that through the daemon -- only through the library
# -- and `serve_node_and_population` is on the path the accept-thread fix moved.
python3 - <<PY
import json
artifact = json.load(open("examples/capset_progressive/artifact-12.json"))
json.dump({"islands": 1, "capacity": 32, "candidates": [
    {"objective_id": "$SCORED_OID", "artifact": artifact,
     "score": 12, "origin": "honest"},
    {"objective_id": "$SCORED_OID", "artifact": artifact,
     "score": 9999, "origin": "liar"},
]}, open("$A/population.json", "w"))
json.dump({"islands": 1, "capacity": 32, "candidates": []},
          open("$B/population.json", "w"))
PY

# The daemon generates a root key if the file is absent; the CLI's `checkpoint`
# does not, so one is made here rather than relying on which ran first.
python3 -c "
import json, secrets
json.dump({'secret': secrets.token_bytes(32).hex()}, open('$A/rootkey.json', 'w'))"
"$RUST" --log "$A/log.jsonl" --root "$A" checkpoint \
  --root-key "$A/rootkey.json" --out "$A/checkpoint.json" | sed 's/^/  /'
cp "$A/rootkey.json" "$B/rootkey.json"
cp "$A/checkpoint.json" "$B/checkpoint.json"

rule "A serves, with a submission queue"
mkdir -p "$A/queue"
"$DAEMON" --identity "$A/id.json" --root-key "$A/rootkey.json" \
  --checkpoint "$A/checkpoint.json" --listen "127.0.0.1:$A_PORT" \
  --log "$A/log.jsonl" --root "$A" --queue "$A/queue" \
  --population "$A/population.json" > "$A/daemon.log" 2>&1 &
APID=$!
# The identity file appears after ~243 ms of Classic McEliece keygen. Poll for
# it rather than sleeping a guessed amount.
for _ in $(seq 1 150); do
  [ -s "$A/id.json" ] && break
  sleep 0.2
done
[ -s "$A/id.json" ] || fail "A never wrote its transport identity"
python3 -c "
import json
i = json.load(open('$A/id.json'))
# \`localhost\`, not \`127.0.0.1\`, deliberately: this is the one place the
# hostname path is exercised end to end. A bootstrap address that needs the
# resolver used to be refused at parse -- \`invalid socket address syntax\` --
# so an operator naming an EC2 instance by its public DNS name could not
# start a node at all. Safe to accept because the peer id is the hash of the
# key, so a hostile answer costs a failed handshake, never a wrong peer.
json.dump({'addr': 'localhost:$A_PORT', 'public': i['public']},
          open('$WORK/a-endpoint.json', 'w'))"
sed 's/^/  /' "$A/daemon.log"

# Wait for A to accept a connection, rather than assuming it binds the moment
# its identity file appears. `free_port` picks a port by binding zero and
# *closing* it, so between that close and A's bind the port is anyone's. When A
# loses that race B spends the whole sync window on "Connection refused" and the
# run ends at "B did not sync A's log", naming the symptom two hundred lines
# from the cause -- which is exactly how long the v6-first bootstrap bug took to
# find. Fail here instead, where the message is the diagnosis.
for _ in $(seq 1 100); do
  python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', $A_PORT)) == 0 else 1)" && break
  sleep 0.1
done
python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', $A_PORT)) == 0 else 1)" \
  || fail "A never listened on 127.0.0.1:$A_PORT (port taken between free_port and bind?)"
echo "  listening on 127.0.0.1:$A_PORT"

rule "B starts with an empty log and one address"
: > "$B/log.jsonl"
"$DAEMON" --identity "$B/id.json" --root-key "$B/rootkey.json" \
  --checkpoint "$B/checkpoint.json" --listen "127.0.0.1:$B_PORT" \
  --log "$B/log.jsonl" --root "$B" --bootstrap "$WORK/a-endpoint.json" \
  --population "$B/population.json" > "$B/daemon.log" 2>&1 &
BPID=$!

# `grep -c` exits 1 on an empty file, and `|| echo 0` then appends a second
# line to the count it already printed -- which `[` reads as "0\n0" and refuses.
# Counting with `wc -l` has no such failure mode.
entries() { wc -l < "$1" 2>/dev/null | tr -d ' '; }
WANT=$(entries "$A/log.jsonl")
for _ in $(seq 1 200); do
  [ "$(entries "$B/log.jsonl")" -ge "$WANT" ] && break
  sleep 0.5
done
GOT=$(entries "$B/log.jsonl")
echo "  A has $WANT entries, B has $GOT"
[ "$GOT" -ge "$WANT" ] || { sed 's/^/  /' "$B/daemon.log"; fail "B did not sync A's log"; }

rule "B has the verifier code too, not just the records"
"$RUST" --log "$B/log.jsonl" --root "$B" blob need | sed 's/^/  /'
"$RUST" --log "$B/log.jsonl" --root "$B" blob need | grep -q "available locally" \
  || fail "B synced records but not the code they pin, so it can only replay A's opinion"

rule "B took the honest candidate and refused the lie"
# The rule that makes gossip safe: a peer's claimed score is re-derived against
# the objective, never imported. Both candidates name the *same* artifact, so
# only re-scoring can tell them apart -- a node that believed what it was told
# would take the 9999 and let a liar own the frontier of every ratcheted
# objective on the network.
for _ in $(seq 1 60); do
  [ "$(python3 -c "
import json
print(len(json.load(open('$B/population.json'))['candidates']))")" -gt 0 ] && break
  sleep 0.5
done
python3 - <<PY
import json, sys
candidates = json.load(open("$B/population.json"))["candidates"]
for candidate in candidates:
    print(f"  {candidate['origin']}: score {candidate['score']}")
scores = [c["score"] for c in candidates]
if not scores:
    print("  B learned no candidates at all", file=sys.stderr)
    sys.exit(1)
if 9999 in scores:
    print("  B imported a claimed score instead of re-deriving it", file=sys.stderr)
    sys.exit(1)
PY

rule "both logs audit, each on its own terms"
"$RUST" --log "$A/log.jsonl" --root "$A" audit | sed 's/^/  A /'
"$RUST" --log "$A/log.jsonl" --root "$A" audit | grep -q "log verified" \
  || fail "A's own log does not audit"
"$RUST" --log "$B/log.jsonl" --root "$B" audit | sed 's/^/  B /'
"$RUST" --log "$B/log.jsonl" --root "$B" audit | grep -q "log verified" \
  || fail "the synced log does not audit"

rule "and the independent implementation audits the node that synced"
# The case that matters: no bundle, no authored objective, verifier code
# obtained by hash. It was broken -- the reference had no content-addressed
# fallback and called a re-verifiable claim unverifiable.
REF_VIEW=$("$REF" --log "$B/log.jsonl" --root "$B" audit)
echo "$REF_VIEW" | sed 's/^/  /'
echo "$REF_VIEW" | grep -q "log verified" \
  || fail "the reference cannot audit a node that got its verifier over the wire"

rule "a second daemon on the same log is refused, before it costs anything"
# One writer, by enforcement. Checked here as well as by the CLI because the
# daemon reaches the ledger by a different path, and because the *ordering*
# matters: this used to be the last check, after ~243 ms of Classic McEliece
# keygen, an identity file written for a node that could not start, and a bound
# listener. The bound port is the part that bites -- during that window the
# address is taken and released again, so a restart flaps a port somebody is
# watching. It is the cheapest check and the likeliest failure, so it runs first.
SECOND=$("$DAEMON" --identity "$WORK/second-id.json" --root-key "$A/rootkey.json" \
  --checkpoint "$WORK/second-cp.json" --listen "127.0.0.1:0" \
  --log "$A/log.jsonl" --root "$A" 2>&1 || true)
echo "$SECOND" | sed 's/^/  /'
echo "$SECOND" | grep -q "already writing" \
  || fail "a second daemon was allowed onto a log another one holds"
[ ! -f "$WORK/second-id.json" ] \
  || fail "a daemon that could not start still wrote an identity file"

rule "the whole documented topology, on one log"
# `proofwork-serve` beside the daemon, both on A's log. This is the deployment
# `docs/serving.md` describes and nothing ran until now: the server is a reader
# and a spooler, the daemon is the single writer, and a submission crosses from
# one to the other through the queue.
#
# It did not compose. `proofwork drain` wants the write lock the daemon holds,
# so for as long as the daemon was the only thing that could run alongside the
# server, an *online* node could not accept a submission at all.
SERVE_PORT=$(free_port)
"$SERVE" --log "$A/log.jsonl" --root "$A" --listen "127.0.0.1:$SERVE_PORT" \
  --queue "$A/queue" > "$A/serve.log" 2>&1 &
SERVE_PID=$!
for _ in $(seq 1 100); do
  grep -q "listening on" "$A/serve.log" 2>/dev/null && break
  sleep 0.2
done
grep -q "listening on" "$A/serve.log" || fail "proofwork-serve never bound"
sed 's/^/  /' "$A/serve.log"

rule "A's main loop is still running, several ticks in"
# The regression check for a deadlock a unit test cannot reach. The accept
# thread used to take the node's mutex and *then* block on `listener.accept()`,
# so on a node nobody was dialling it held the lock for the life of the process
# and the main loop ran exactly once, at startup. Everything outbound stopped:
# dialling, peer seeding, beacons, the DHT, fetching missing verifier code.
#
# It looked healthy, because one startup pass is all a two-node sync needs --
# which is precisely what the rest of this script exercises. Queueing a
# submission *after* startup is what tells the difference: it can only be
# admitted by a loop that is still going round.
BEFORE=$(entries "$A/log.jsonl")
# Submitted the way a stranger would, over HTTP, rather than by writing the
# spool file directly: that exercises the boundary shape check and the 202 as
# well as the admission.
python3 - <<PY
import hashlib, json, urllib.request
oid = "$OPEN_OID"
inner = json.dumps({"cap": []}, sort_keys=True, separators=(',', ':'))
digest = hashlib.sha256((oid + "|" + inner + "|late|late-nonce").encode()).hexdigest()
record = {"type": "commitment", "objective_id": oid, "submitter": "late",
          "hash": "sha256:" + digest, "created_at": "2026-08-06T09:00:00+00:00"}
request = urllib.request.Request(
    "http://127.0.0.1:$SERVE_PORT/submit?kind=commitment",
    data=json.dumps(record).encode(),
    headers={"Content-Type": "application/json"},
    method="POST")
status = urllib.request.urlopen(request, timeout=10).status
print(f"  POST /submit -> {status} (queued, explicitly not admitted)")
raise SystemExit(0 if status == 202 else 1)
PY
for _ in $(seq 1 40); do
  [ "$(entries "$A/log.jsonl")" -gt "$BEFORE" ] && break
  sleep 0.5
done
AFTER=$(entries "$A/log.jsonl")
echo "  log went from $BEFORE to $AFTER entries"
[ "$AFTER" -gt "$BEFORE" ] || {
  sed 's/^/  /' "$A/daemon.log"
  fail "the daemon never drained: its main loop stopped after the first tick"
}
[ "$(ls "$A/queue" | wc -l)" -eq 0 ] || fail "the drained record was left in the spool"

rule "the roots differ, and that is the design"
A_ROOT=$("$RUST" --log "$A/log.jsonl" --root "$A" audit | awk '/^merkle/ {print $2}')
B_ROOT=$("$RUST" --log "$B/log.jsonl" --root "$B" audit | awk '/^merkle/ {print $2}')
echo "  A $A_ROOT"
echo "  B $B_ROOT"
[ "$A_ROOT" != "$B_ROOT" ] \
  || echo "  (identical this run; entry timestamps happened to coincide)"

# What must match is the part that is content-addressed. Envelope timestamps are
# local and B settles its own batch, so the roots are each node's own -- but the
# *records* are the same records, and a claim id is a function of its bytes.
# Asserted rather than narrated: a check that only prints is not a check.
A_CLAIM=$(python3 -c "
import json, sys
for line in open('$A/log.jsonl'):
    entry = json.loads(line)
    if entry['kind'] == 'claim':
        print(json.dumps(entry['payload'], sort_keys=True, separators=(',', ':')))
        sys.exit(0)
sys.exit(1)")
B_CLAIM=$(python3 -c "
import json, sys
for line in open('$B/log.jsonl'):
    entry = json.loads(line)
    if entry['kind'] == 'claim':
        print(json.dumps(entry['payload'], sort_keys=True, separators=(',', ':')))
        sys.exit(0)
sys.exit(1)")
[ -n "$A_CLAIM" ] || fail "no claim in A's log to compare"
[ "$A_CLAIM" = "$B_CLAIM" ] \
  || fail "the synced claim record is not byte-identical to the one A wrote"
echo "  the claim record is byte-identical on both nodes"

printf '\n\033[32mP2P DEMO OK: an empty node synced, fetched its verifiers, and audits under both implementations.\033[0m\n'
