#!/usr/bin/env bash
# End-to-end smoke test of a node running BOTH loops in one process.
#
# `serve-smoke.sh` covers the publisher: a stranger fetches the log over TCP,
# queues a submission, and *the operator* drains it with a separate command.
# That is the split topology, and it is still supported.
#
# What this covers is the thing the split one structurally cannot: a submission
# arriving over HTTP and being admitted by the same process, with nobody
# running `cairn drain` at all. The reason that is not a convenience is
# `Ledger`'s single-writer rule -- whatever admits a record must hold the write
# lock, so a publisher that does not hold it can only ever queue. Before
# `daemon::run`, an operator who wanted both had to run two units and get the
# queue path right in each; a typo produced a server queueing into a directory
# no daemon was watching, and nothing anywhere reported it.
#
# Both entry points are exercised, because both build the same `daemon::Config`
# and a mistake in either one's argument wiring is invisible to the other.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
P2P="${P2P_BIN:-./target/release/cairn-p2p}"
SERVE="${SERVE_BIN:-./target/release/cairn-serve}"

if [ ! -x "$RUST" ] || [ ! -x "$P2P" ] || [ ! -x "$SERVE" ]; then
  echo "building release binaries..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-node-XXXXXX)
NODE_PID=""
cleanup() {
  [ -n "$NODE_PID" ] && kill "$NODE_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# A reveal must land in a strictly later epoch than its commitment, and this
# script would otherwise take ten minutes.
export CAIRN_EPOCH_SECONDS=1

# Wait for a listener rather than sleeping a fixed amount.
await_port() {
  for _ in $(seq 1 60); do
    if python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(0.2)
sys.exit(0 if s.connect_ex(('127.0.0.1',$1))==0 else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

# Queued records are admitted on the daemon's own tick, so the check has to
# wait for one rather than assume it has already happened. Polling and giving
# up loudly beats a `sleep` tuned to one machine.
#
# Over HTTP rather than by grepping the file, because the file may be sealed:
# on any machine carrying `~/.cairn/key` the CLI writes an encrypted log,
# and grep finds nothing in ciphertext however well the daemon is working. That
# is a better check anyway -- it asks the public surface, which is where an
# outside contributor would look.
await_kind() {  # port kind
  for _ in $(seq 1 60); do
    curl -s "http://127.0.0.1:$1/log" | grep -q "\"kind\": *\"$2\"" && return 0
    sleep 0.5
  done
  return 1
}

submit() {  # port oid kind payload-python
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib, json, sys, urllib.request

port, oid, kind = sys.argv[1], sys.argv[2], sys.argv[3]
base = f"http://127.0.0.1:{port}"
artifact = json.load(open("examples/capset_progressive/artifact-12.json"))

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()

submitter, nonce = "stranger", "s3cret"
if kind == "commitment":
    inner = digest({"objective_id": oid, "artifact": artifact})
    body = {
        "type": "commitment", "objective_id": oid, "submitter": submitter,
        "hash": "sha256:" + hashlib.sha256(
            inner.encode() + b"|" + submitter.encode() + b"|" + nonce.encode()).hexdigest(),
        "created_at": "2026-07-28T00:00:00+00:00",
    }
    path = "/submit?kind=commitment"
else:
    body = {
        "type": "claim", "objective_id": oid, "submitter": submitter,
        "artifact": artifact, "nonce": nonce,
        "created_at": "2026-07-28T00:00:00+00:00", "cites": [],
    }
    path = "/submit?kind=claim"

request = urllib.request.Request(
    base + path, data=canonical(body),
    headers={"content-type": "application/json"}, method="POST")
with urllib.request.urlopen(request, timeout=10) as response:
    assert response.status == 202, response.status
print(f"  POST /submit ({kind}) -> 202 queued")
PY
}

# --------------------------------------------------------------------------
# One process, entered through cairn-p2p
# --------------------------------------------------------------------------

A="$WORK/a"; mkdir -p "$A"
LOG="$A/log.jsonl"
HTTP=39080
P2P_PORT=39090

rule "post an objective, then start ONE process that syncs and publishes"
OID=$("$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json \
  | head -1 | awk '{print $2}')
echo "  $OID"

"$P2P" --identity "$A/id.json" --root-key "$A/rk.json" --checkpoint "$A/cp.json" \
  --listen "127.0.0.1:$P2P_PORT" --log "$LOG" --root . \
  --queue "$A/queue" --serve "127.0.0.1:$HTTP" >"$A/node.log" 2>&1 &
NODE_PID=$!
await_port "$HTTP" || { cat "$A/node.log" >&2; fail "the node never bound its HTTP port"; }
kill -0 "$NODE_PID" 2>/dev/null || { cat "$A/node.log" >&2; fail "the node exited at startup"; }
grep -q "publishing over HTTP from this process" "$A/node.log" \
  || fail "the node did not report that it is serving"
echo "  one PID, p2p on $P2P_PORT and HTTP on $HTTP"

rule "every read route answers, from the same process holding the write lock"
for path in /health /objectives /chain /chain.html /checkpoint "/objective/$OID"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP$path")
  [ "$code" = "200" ] || fail "GET $path -> $code"
  echo "  GET $path -> 200"
done

rule "the embedded reader is routed, whether or not it was built in"
# Both outcomes are correct and which one you get is a build flag, so this
# checks the *routing* rather than the feature. What it refuses is the third
# outcome: a generic 404, which is what a missing route looks like and is
# indistinguishable to the operator from a binary built without the reader.
UI_CODE=$(curl -s -o "$WORK/ui.body" -w '%{http_code}' "http://127.0.0.1:$HTTP/ui/")
case "$UI_CODE" in
  200)
    grep -q "knowledge chain" "$WORK/ui.body" || fail "/ui/ 200 but is not the reader"
    # basePath has to survive the export, or every asset 404s and the page
    # renders unstyled -- the exact symptom ui/README.md warns reads as a CSS bug.
    grep -q '/ui/_next/' "$WORK/ui.body" || fail "/ui/ does not reference /ui/_next assets"
    ASSET=$(grep -o '/ui/_next/static/css/[a-z0-9.]*\.css' "$WORK/ui.body" | head -1)
    [ -n "$ASSET" ] || fail "/ui/ names no stylesheet"
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP$ASSET")
    [ "$code" = "200" ] || fail "the reader's stylesheet -> $code"
    echo "  GET /ui/ -> 200, assets under /ui/_next resolve"
    ;;
  404)
    grep -q "built without the embedded reader" "$WORK/ui.body" \
      || fail "/ui/ 404s without naming the feature; that is a missing route, not a missing build"
    echo "  GET /ui/ -> 404 naming --features ui (this binary has no reader)"
    ;;
  *) fail "GET /ui/ -> $UI_CODE" ;;
esac

rule "a submission is admitted by the process that received it"
submit "$HTTP" "$OID" commitment
await_kind "$HTTP" commitment \
  || { cat "$A/node.log" >&2; fail "the daemon never admitted the commitment"; }
echo "  the commitment reached the log with no external drain"
[ -z "$(ls -A "$A/queue" 2>/dev/null)" ] || fail "the queue was not emptied"
echo "  the queue emptied itself"

rule "reveal in a later epoch, same process"
sleep 1.2
submit "$HTTP" "$OID" claim
await_kind "$HTTP" claim \
  || { cat "$A/node.log" >&2; fail "the daemon never admitted the claim"; }
echo "  the claim reached the log with no external drain"

rule "the log audits, and it audits from outside the process"
# Two waits, not one: an epoch must close *and* wait out the finality delay
# before anything settles. The daemon settles on its own tick after a drain.
sleep 2.6
curl -s "http://127.0.0.1:$HTTP/log" >"$WORK/fetched.jsonl"
if head -c 7 "$LOG" | grep -q '^pwenc1:'; then
  # A sealed log is unsealed on the way out -- serving ciphertext would hand a
  # stranger bytes they cannot audit. So the check is that what came out is
  # usable, not that it matches the file byte for byte.
  head -c 1 "$WORK/fetched.jsonl" | grep -q '{' \
    || fail "the log is sealed and GET /log did not serve plaintext JSONL"
  echo "  GET /log unsealed a sealed log into plaintext JSONL"
else
  cmp -s "$WORK/fetched.jsonl" "$LOG" \
    || fail "the served log is not byte-identical to the operator's file"
  echo "  GET /log is byte-identical to the file on disk"
fi
"$RUST" --log "$WORK/fetched.jsonl" --root . audit --no-rerun | grep -q "log verified" \
  || fail "the log a stranger fetched does not audit"
echo "  a stranger's copy re-derives"

kill "$NODE_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true
NODE_PID=""

# --------------------------------------------------------------------------
# The same node, entered through cairn-serve
# --------------------------------------------------------------------------

rule "cairn-serve --p2p-listen is the same daemon, not a second one"
B="$WORK/b"; mkdir -p "$B"
"$SERVE" --log "$B/log.jsonl" --root . --listen "127.0.0.1:$((HTTP + 1))" \
  --p2p-listen "127.0.0.1:$((P2P_PORT + 1))" \
  --identity "$B/id.json" --root-key "$B/rk.json" --checkpoint "$B/cp.json" \
  --queue "$B/queue" >"$B/node.log" 2>&1 &
NODE_PID=$!
await_port "$((HTTP + 1))" || { cat "$B/node.log" >&2; fail "serve --p2p-listen never bound"; }
grep -q "publishing over HTTP from this process" "$B/node.log" \
  || fail "serve --p2p-listen did not start the daemon"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((HTTP + 1))/health")
[ "$code" = "200" ] || fail "serve --p2p-listen: /health -> $code"
echo "  same startup line, same routes, one PID"
kill "$NODE_PID" 2>/dev/null || true
NODE_PID=""

rule "the publisher refuses node flags rather than ignoring them"
# Silently dropping these is how somebody ends up with a process that took no
# lock, dialled nobody and drained nothing while looking like it had started.
if "$SERVE" --log "$B/log.jsonl" --root . --identity "$B/id.json" >/dev/null 2>&1; then
  fail "--identity without --p2p-listen was accepted"
fi
echo "  --identity without --p2p-listen -> refused"
if "$SERVE" --log "$B/log.jsonl" --root . --p2p-listen 127.0.0.1:1 >/dev/null 2>&1; then
  fail "--p2p-listen without --identity was accepted"
fi
echo "  --p2p-listen without --identity -> refused"

printf '\n\033[32mNODE SMOKE OK: one process queued, admitted, settled and published.\033[0m\n'
