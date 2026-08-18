#!/usr/bin/env bash
# End-to-end smoke test of cairn-serve as a real process.
#
# The unit tests cover the spool. What they structurally cannot cover is the
# thing this service exists for: a *stranger* -- a process that shares no
# memory with the node, holds no file handle on the log, and was given nothing
# but an address -- fetching the log and re-deriving it themselves. That is the
# whole claim of the project, and until this script existed nothing tested it.
#
# So: post an objective, serve it, fetch it over TCP as a client would, submit
# a commit and a reveal through the queue, drain them with the rules engine,
# and audit the resulting log. Nothing here reaches around the HTTP boundary.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
SERVE="${SERVE_BIN:-./target/release/cairn-serve}"

if [ ! -x "$RUST" ] || [ ! -x "$SERVE" ]; then
  echo "building release binaries..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }
# Ask the *served* log, not the file: on a machine carrying `~/.cairn/key`
# the file is ciphertext and grep finds nothing however well the drain worked.
served_has() { curl -s "http://127.0.0.1:$PORT/log" | grep -q "\"kind\": *\"$1\""; }

WORK=$(mktemp -d /tmp/pw-serve-XXXXXX)
LOG="$WORK/cairn.jsonl"
QUEUE="$WORK/queue"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# One-second epochs: a reveal must land in a strictly later epoch than its
# commitment, and this script would otherwise take ten minutes.
export CAIRN_EPOCH_SECONDS=1

rule "post an objective, then serve the log"
OID=$("$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json \
  | head -1 | awk '{print $2}')
echo "  $OID"

# Port 0 would be ideal, but the client needs to know the number, so pick a
# high one and let the bind fail loudly if it is taken.
PORT=${CAIRN_SERVE_PORT:-38080}
ADDR="127.0.0.1:$PORT"
"$SERVE" --log "$LOG" --root . --listen "$ADDR" --queue "$QUEUE" >"$WORK/serve.out" 2>&1 &
SERVER_PID=$!

# Wait for the listener rather than sleeping a fixed amount.
for _ in $(seq 1 50); do
  if python3 -c "
import socket,sys
s=socket.socket()
s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)
" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
kill -0 "$SERVER_PID" 2>/dev/null || { cat "$WORK/serve.out" >&2; fail "the server exited at startup"; }
echo "  serving on $ADDR"

rule "a stranger fetches the objective list and the log"
python3 - "$PORT" "$OID" "$LOG" <<'PY'
import json, sys, urllib.request

port, oid, logpath = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"

def get(path):
    with urllib.request.urlopen(base + path, timeout=10) as response:
        return response.status, response.read()

status, body = get("/objectives")
assert status == 200, status
listing = json.loads(body)
ids = [o["id"] for o in listing["objectives"]]
assert oid in ids, f"{oid} not in {ids}"
# The warning has to travel with the data: a client rendering this into an
# agent's context needs to know the statement is attacker-written.
assert "untrusted" in json.dumps(listing).lower(), "no untrusted-statement warning"
print(f"  GET /objectives -> {len(ids)} objective(s), statements labelled untrusted")

# The epoch chain, both representations. It is *derived* rather than stored,
# so a bug here is a bug in how a reader would reconstruct settlement order --
# and the head is what two operators compare to find out whether they forked.
status, body = get("/chain")
assert status == 200, status
chain = json.loads(body)
assert chain["links"] == len(chain["chain"]), chain
# Each link must name the one before it, or it is not a chain.
prev = ""
for entry in chain["chain"]:
    assert entry["prev"] == prev, f"link for epoch {entry['epoch']} does not follow its parent"
    prev = entry["link"]
assert chain["head"] == prev, "head is not the last link"
print(f"  GET /chain -> {chain['links']} link(s), each naming its parent")

status, body = get("/chain.html")
assert status == 200, status
page = body.decode()
assert "knowledge chain" in page, "the page is not the chain view"
# Self-contained: a node operator reads this over an SSH tunnel on a box with
# no route out, and a page that fetched a stylesheet would be blank exactly then.
assert "http://" not in page.replace("http://www.w3.org", ""), "the page fetches something external"
assert "https://" not in page, "the page fetches something external"
if chain["head"]:
    assert chain["head"] in page, "the head is not shown on the page"
print("  GET /chain.html -> self-contained page, head shown")

status, body = get(f"/objective/{oid}")
assert status == 200, status
record = json.loads(body)["record"]
assert record["verifier"]["kind"] == "evaluator", record["verifier"]
print("  GET /objective/{id} -> full record with its pinned verifier")

# The whole point of the service: the bytes, unmodified. A re-encode that
# differed by one byte would fail the client's chain check and look like a lie.
#
# Unless the operator's log is sealed at rest, in which case the bytes on disk
# are ciphertext and handing them over would give a stranger nothing they can
# audit. Sealing is a storage concern -- `Codec`'s own docs say so -- so the
# server unseals on the way out and the check becomes "is this usable JSONL".
# Machines with `~/.cairn/key` take this branch; CI takes the other.
status, body = get("/log")
assert status == 200, status
on_disk = open(logpath, "rb").read()
if on_disk.startswith(b"pwenc1:"):
    for line in body.decode().splitlines():
        json.loads(line)
    print(f"  GET /log -> {len(body)} bytes, a sealed log unsealed into plain JSONL")
else:
    assert body == on_disk, "the served log is not byte-identical to the log on disk"
    print(f"  GET /log -> {len(body)} bytes, byte-identical to the operator's file")

status, body = get("/frontier/" + oid)
assert status == 200, status
assert json.loads(body)["frontier"] is None, "a fresh objective has no frontier"
print("  GET /frontier/{id} -> no frontier yet, nothing to cite")

# A path that does not exist must 404 rather than 500.
try:
    get("/nope")
    raise SystemExit("FAIL: /nope did not 404")
except urllib.error.HTTPError as e:
    assert e.code == 404, e.code
print("  GET /nope -> 404")
PY

rule "a stranger submits a commitment, then reveals an epoch later"
ARTIFACT=examples/capset_progressive/artifact-12.json
python3 - "$PORT" "$OID" "$ARTIFACT" <<'PY'
import hashlib, json, sys, urllib.request

port, oid, artifact_path = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
artifact = json.load(open(artifact_path))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

def post(path, body):
    request = urllib.request.Request(
        base + path, data=canonical(body),
        headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, json.loads(response.read())

# The commitment hash, computed exactly as records.rs does it.
submitter, nonce = "stranger", "s3cret"
inner = digest({"objective_id": oid, "artifact": artifact})
commitment_hash = "sha256:" + hashlib.sha256(
    inner.encode() + b"|" + submitter.encode() + b"|" + nonce.encode()).hexdigest()

status, body = post("/submit?kind=commitment", {
    "type": "commitment", "objective_id": oid, "submitter": submitter,
    "hash": commitment_hash, "created_at": "2026-07-28T00:00:00+00:00",
})
assert status == 202, (status, body)
assert "Queued, not admitted" in body["note"], body
print("  POST /submit (commitment) -> 202 queued, explicitly not a receipt")

# A retry must not queue it twice -- the spool is content-addressed.
status, again = post("/submit?kind=commitment", {
    "type": "commitment", "objective_id": oid, "submitter": submitter,
    "hash": commitment_hash, "created_at": "2026-07-28T00:00:00+00:00",
})
assert again["queued"] == body["queued"], (body, again)
print("  a retry is idempotent, not a duplicate")

# Malformed input is refused at the boundary rather than queued to fail later.
try:
    post("/submit?kind=claim", {"type": "claim", "objective_id": oid})
    raise SystemExit("FAIL: a malformed claim was accepted")
except urllib.error.HTTPError as e:
    assert e.code == 400, e.code
print("  a malformed record -> 400, nothing queued")
PY

rule "the operator drains the queue through the rules engine"
"$RUST" --log "$LOG" --root . drain --queue "$QUEUE" | sed 's/^/  /'
served_has commitment || fail "the commitment never reached the log"
[ -z "$(ls -A "$QUEUE" 2>/dev/null)" ] || fail "the queue was not emptied"

rule "reveal in a later epoch, through the queue again"
sleep 1.2
python3 - "$PORT" "$OID" "$ARTIFACT" <<'PY'
import hashlib, json, sys, urllib.request

port, oid, artifact_path = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
artifact = json.load(open(artifact_path))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

request = urllib.request.Request(
    base + "/submit?kind=claim",
    data=canonical({
        "type": "claim", "objective_id": oid, "submitter": "stranger",
        "artifact": artifact, "nonce": "s3cret",
        "created_at": "2026-07-28T00:00:00+00:00", "cites": [],
    }),
    headers={"content-type": "application/json"}, method="POST")
with urllib.request.urlopen(request, timeout=10) as response:
    assert response.status == 202, response.status
print("  POST /submit (claim) -> 202 queued")
PY

"$RUST" --log "$LOG" --root . drain --queue "$QUEUE" | sed 's/^/  /'
served_has claim || fail "the claim never reached the log"

rule "the log a stranger produced audits, and the frontier moved"
# Two waits, not one: an epoch must close *and* wait out the finality delay
# (CAIRN_FINALITY_EPOCHS, default 1) before anything settles.
sleep 2.4
"$RUST" --log "$LOG" --root . settle | sed 's/^/  /'
# `chain intact` rather than `log verified`: under --no-rerun no verifier runs,
# and the clean line now says so instead of claiming a re-verification that did
# not happen. Both branches still say the chain and the rules re-derived.
"$RUST" --log "$LOG" --root . audit --no-rerun | grep -q "chain intact" \
  || fail "the log does not audit"

python3 - "$PORT" "$OID" <<'PY'
import json, sys, urllib.request
port, oid = sys.argv[1], sys.argv[2]
with urllib.request.urlopen(f"http://127.0.0.1:{port}/frontier/{oid}", timeout=10) as r:
    body = json.loads(r.read())
frontier = body["frontier"]
assert frontier is not None, "the frontier did not move"
assert frontier["score"] == 12, frontier
assert frontier["holder"] == "stranger", frontier
assert frontier["pool_remaining"] < 1_100_000, frontier
print(f"  frontier: score {frontier['score']} held by {frontier['holder']}, "
      f"{frontier['pool_remaining']} of the pool left")

# The chain, now that an epoch has actually settled. The check earlier in this
# script runs against an empty chain and can only prove the endpoint's shape;
# this one proves it grows a link when a batch is paid, which is what a reader
# reconstructing settlement order depends on.
with urllib.request.urlopen(f"http://127.0.0.1:{port}/chain", timeout=10) as r:
    chain = json.loads(r.read())
assert chain["links"] >= 1, f"an epoch settled and the chain is still empty: {chain}"
assert chain["head"], "a non-empty chain has no head"
settled = [c for c in chain["chain"] if c["claims"]]
assert settled, f"no link names a settled claim: {chain['chain']}"
print(f"  GET /chain -> {chain['links']} link(s) after settlement, "
      f"head {chain['head'][:15]}...")
PY

rule "a read-only server refuses submissions"
"$SERVE" --log "$LOG" --root . --listen "127.0.0.1:$((PORT+1))" >"$WORK/ro.out" 2>&1 &
RO_PID=$!
for _ in $(seq 1 50); do
  python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$((PORT+1))))==0 else 1)" 2>/dev/null && break
  sleep 0.1
done
python3 - "$((PORT+1))" <<'PY'
import json, sys, urllib.request
port = sys.argv[1]
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/submit", data=b'{"type":"claim"}',
    headers={"content-type": "application/json"}, method="POST")
try:
    urllib.request.urlopen(request, timeout=10)
    raise SystemExit("FAIL: a read-only server accepted a submission")
except urllib.error.HTTPError as e:
    assert e.code == 405, e.code
print("  POST /submit -> 405 on a server started without --queue")
PY
kill "$RO_PID" 2>/dev/null || true

printf '\n\033[32mSERVE SMOKE OK\033[0m\n'
