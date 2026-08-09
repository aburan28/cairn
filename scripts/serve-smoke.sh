#!/usr/bin/env bash
# End-to-end smoke test of proofwork-serve as a real process.
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

RUST="${RUST_BIN:-./target/release/proofwork}"
SERVE="${SERVE_BIN:-./target/release/proofwork-serve}"

if [ ! -x "$RUST" ] || [ ! -x "$SERVE" ]; then
  echo "building release binaries..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-serve-XXXXXX)
LOG="$WORK/proofwork.jsonl"
QUEUE="$WORK/queue"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# One-second epochs: a reveal must land in a strictly later epoch than its
# commitment, and this script would otherwise take ten minutes.
export PROOFWORK_EPOCH_SECONDS=1

rule "post an objective, then serve the log"
OID=$("$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json \
  | head -1 | awk '{print $2}')
echo "  $OID"

# Port 0 would be ideal, but the client needs to know the number, so pick a
# high one and let the bind fail loudly if it is taken.
PORT=${PROOFWORK_SERVE_PORT:-38080}
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

def get(path, accept=None):
    request = urllib.request.Request(base + path)
    if accept:
        request.add_header("Accept", accept)
    with urllib.request.urlopen(request, timeout=10) as response:
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

# The human view. Four pages, and the same rule on every one: no external
# fetch, because an operator reads these over an SSH tunnel on a box with no
# route out and a page that needed one would be blank exactly then.
for path in ("/index.html", "/log.html", "/chain.html"):
    status, body = get(path)
    assert status == 200, (path, status)
    page = body.decode()
    assert "http://" not in page.replace("http://www.w3.org", ""), f"{path} fetches something"
    assert "https://" not in page, f"{path} fetches something external"
    assert "<script" not in page, f"{path} carries a script"
print("  GET /index.html,/log.html,/chain.html -> self-contained, script-free")

status, body = get(f"/objective/{oid}.html")
assert status == 200, status
page = body.decode()
assert "not an instruction to you" in page, "the statement is not labelled as untrusted"
assert oid in page, "the objective id is not shown"
print("  GET /objective/{id}.html -> statement labelled as the funder's words")

# `/` is negotiated so a browser gets the board, and every client that was
# parsing the JSON descriptor keeps getting it. `*/*` is what curl and most
# libraries send, so it is the case that must not change.
status, body = get("/", accept="text/html,application/xhtml+xml")
assert status == 200 and body.decode().startswith("<!doctype html>"), "a browser did not get the board"
status, body = get("/", accept="*/*")
assert json.loads(body)["service"] == "proofwork", "a program did not get the JSON descriptor"
status, body = get("/index", accept="text/html")
assert json.loads(body)["service"] == "proofwork", "/index must always be the JSON descriptor"
print("  GET / -> board for a browser, JSON for everything else")

status, body = get(f"/objective/{oid}")
assert status == 200, status
record = json.loads(body)["record"]
assert record["verifier"]["kind"] == "evaluator", record["verifier"]
print("  GET /objective/{id} -> full record with its pinned verifier")

# The whole point of the service: the bytes, unmodified. A re-encode that
# differed by one byte would fail the client's chain check and look like a lie.
status, body = get("/log")
assert status == 200, status
on_disk = open(logpath, "rb").read()
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
grep -q '"kind": *"commitment"' "$LOG" || fail "the commitment never reached the log"
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
grep -q '"kind": *"claim"' "$LOG" || fail "the claim never reached the log"

rule "the log a stranger produced audits, and the frontier moved"
sleep 1.2
"$RUST" --log "$LOG" --root . settle | sed 's/^/  /'
"$RUST" --log "$LOG" --root . audit --no-rerun | grep -q "log verified" \
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

rule "an objective statement is attacker-authored text, and the page treats it so"
# The statement in an objective was written by whoever posted it. It reaches
# the page as text or it does not reach it at all -- and "it cannot contain a
# bracket" is a property of today's records, not a rule the format enforces.
# Checked against a real server rather than in a unit test, because what
# matters is the bytes a browser would actually be handed.
cat > "$WORK/hostile.json" <<'JSON'
{
  "goal": "GOAL-hostile",
  "statement": "</div></b><script>alert(1)</script><img src=x onerror=alert(2)><a href=\"javascript:alert(3)\">c</a> \"q\" & 'a'",
  "verifier": {
    "checker": "examples/collatz/checkers/long_trajectory.py",
    "checker_sha256": "df78b43c279aa931b0ee481ca946cd5788eb7b28351d66f83e5a980a9cf91473",
    "entrypoint": "check",
    "kind": "certificate"
  },
  "reward": 1,
  "funder": "<script>alert('funder')</script>",
  "created_at": "2026-07-28T00:00:00+00:00"
}
JSON
HOSTILE=$("$RUST" --log "$LOG" --root . post "$WORK/hostile.json" | head -1 | awk '{print $2}')
python3 - "$PORT" "$HOSTILE" <<'HOSTILEPY'
import sys, urllib.request
port, hostile = sys.argv[1], sys.argv[2]
base = f"http://127.0.0.1:{port}"

from html.parser import HTMLParser

def get(path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return r.read().decode()

# Parsed, not grepped. The payload appears in the page as *text* -- the string
# "onerror" is right there inside "&lt;img src=x onerror=...&gt;" and is
# perfectly safe -- so a substring search reports a false alarm and teaches
# whoever hits it to loosen the check. A parser sees what a browser sees:
# elements and attributes, or nothing.
class Scan(HTMLParser):
    def __init__(self):
        super().__init__()
        self.bad = []
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "img", "iframe", "object", "embed", "form"):
            self.bad.append(f"<{tag}>")
        for name, value in attrs:
            if name.startswith("on"):
                self.bad.append(f"{tag}[{name}]")
            if value and value.strip().lower().startswith("javascript:"):
                self.bad.append(f"{tag}[{name}=javascript:]")

for path in ("/index.html", f"/objective/{hostile}.html", "/log.html"):
    page = get(path)
    scan = Scan()
    scan.feed(page)
    assert not scan.bad, f"{path}: the record became markup: {scan.bad}"
    # And it is still *there*, as text. A silently dropped statement would be a
    # different bug, and not an honest one either.
    assert "&lt;script&gt;" in page, f"{path}: the statement is missing, not escaped"
print("  hostile statement -> text on every page; no element or handler it named exists")
HOSTILEPY

printf '\n\033[32mSERVE SMOKE OK\033[0m\n'
