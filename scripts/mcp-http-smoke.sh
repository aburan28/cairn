#!/usr/bin/env bash
# End-to-end smoke test of the MCP server over Streamable HTTP, as a real process.
#
# `scripts/mcp-smoke.sh` proves the stdio transport speaks clean JSON-RPC; this
# proves the HTTP one from `cairn mcp --http` does: sessions are minted on
# `initialize`, required afterwards, isolated from each other, and forgotten on
# DELETE, while the tools behind them are the same engine -- the score below
# comes from the Python evaluator in examples/, executed as a subprocess with
# its hash checked first.
set -euo pipefail

# Plaintext, like the stdio smoke test's log: the CLI seals every log it
# creates whenever a key file exists, and this script greps the log's line
# count directly rather than through the sealed codec.
export CAIRN_KEY=/nonexistent/cairn-forces-plaintext
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"

if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

# Fixed port with an override, the way serve-smoke does it: an ephemeral port
# would need the server to report what it bound, which is a feature for the
# test's benefit rather than the operator's.
PORT="${CAIRN_MCP_HTTP_PORT:-38081}"
ADDR="127.0.0.1:$PORT"

LOG="$(mktemp -u /tmp/pw-mcp-http-XXXXXX).jsonl"
ERR="$(mktemp -u /tmp/pw-mcp-http-err-XXXXXX).log"
trap 'rm -f "$LOG" "$ERR" "${LOG%.jsonl}.pending.json"; kill "$SRV" 2>/dev/null || true' EXIT

rule "post an objective with the CLI"
OID=$("$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json \
  | head -1 | awk '{print $2}')
echo "  $OID"

rule "start the HTTP server"
"$RUST" --log "$LOG" --root . mcp --http "$ADDR" >"$ERR" 2>&1 &
SRV=$!
for _ in $(seq 1 100); do
  if python3 -c "import socket,sys; sys.exit(0 if socket.socket().connect_ex(('127.0.0.1',$PORT))==0 else 1)" \
      2>/dev/null; then
    break
  fi
  sleep 0.1
done
python3 -c "import socket,sys; sys.exit(0 if socket.socket().connect_ex(('127.0.0.1',$PORT))==0 else 1)" \
  || fail "the server never bound $ADDR (see $ERR)"
grep -q "Streamable HTTP on $ADDR" "$ERR" || fail "the server did not announce its transport"
echo "  bound $ADDR"

rule "drive it as a Streamable HTTP client"
ARTIFACT=$(python3 -c 'import json;print(json.dumps(json.load(open("examples/capset_progressive/artifact-12.json"))))')
PORT="$PORT" OID="$OID" ARTIFACT="$ARTIFACT" python3 - <<'PY'
import json, os, urllib.request, urllib.error

base = "http://127.0.0.1:%s" % os.environ["PORT"]
oid, artifact = os.environ["OID"], json.loads(os.environ["ARTIFACT"])

def post(payload, session=None, ctype="application/json"):
    req = urllib.request.Request(
        base + "/mcp", data=json.dumps(payload).encode(),
        headers={"Content-Type": ctype, "Accept": "application/json, text/event-stream"},
        method="POST")
    if session:
        req.add_header("Mcp-Session-Id", session)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.headers.get("Mcp-Session-Id"), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Mcp-Session-Id"), e.read().decode()

def get(path, method="GET", session=None):
    req = urllib.request.Request(base + path, method=method)
    if session:
        req.add_header("Mcp-Session-Id", session)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()

# No session, no service -- everything but initialize is behind the handshake.
status, _, body = post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
assert status == 400, (status, body)
assert json.loads(body)["error"]["code"] == -32002, body
status, _, body = post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, session="0" * 64)
assert status == 404, (status, body)
print("  calls without a session are refused (400) or unknown (404)")

init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25"}}
status, first, body = post(init)
assert status == 200, (status, body)
result = json.loads(body)["result"]
assert result["protocolVersion"] == "2025-11-25", result
assert result["serverInfo"]["name"] == "cairn", result
assert first and len(first) == 64, first
status, second, _ = post(init)
assert status == 200 and second and second != first
print("  initialize mints a 256-bit session per handshake")

status, echoed, body = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=first)
assert status == 200, (status, body)
assert echoed == first, "the server echoes the caller's session"
tools = json.loads(body)["result"]["tools"]
assert len(tools) == 15, len(tools)
names = {t["name"] for t in tools}
for required in ("score_candidate", "list_objectives", "submit_claim", "audit"):
    assert required in names, names
assert all(t.get("annotations", {}).get("readOnlyHint") is not None for t in tools)
print("  tools/list answers 15 annotated tools over the session")

score = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "score_candidate",
                    "arguments": {"objective_id": oid, "artifact": artifact}}}
status, _, body = post(score, session=first)
assert status == 200, (status, body)
result = json.loads(body)["result"]
assert result["isError"] is False, result
text = result["content"][0]["text"]
assert "accept" in text and "score: 12" in text, text
assert "Nothing was recorded" in text, text
print("  score_candidate ran the pinned evaluator and returned score 12")

status, _, body = post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session=first)
assert (status, body) == (202, ""), (status, body)
print("  a notification is accepted (202) and answered with nothing")

status, headers, _ = get("/mcp")
assert status == 405, status
allow = headers.get("Allow") or headers.get("allow")
assert allow and "POST" in allow, headers
status, headers, _ = get("/mcp", method="OPTIONS")
assert status == 204, status
assert not any(k.lower() == "access-control-allow-origin" for k in headers), headers
request = urllib.request.Request(
    base + "/mcp", data=json.dumps(init).encode(),
    headers={"Content-Type": "application/json", "Origin": "https://attacker.example"},
    method="POST")
try:
    urllib.request.urlopen(request)
    raise AssertionError("browser origin was admitted")
except urllib.error.HTTPError as error:
    assert error.code == 403, error.code
status, _, body = get("/")
assert status == 200 and "streamable-http" in body, (status, body)
print("  GET /mcp is 405, browser origins are refused, GET / describes the server")

status, _, body = get("/mcp", method="DELETE", session=first)
assert (status, body) == (204, ""), (status, body)
status, _, body = post({"jsonrpc": "2.0", "id": 4, "method": "tools/list"}, session=first)
assert status == 404, (status, body)
status, _, _ = post({"jsonrpc": "2.0", "id": 5, "method": "tools/list"}, session=second)
assert status == 200, "closing one session must not disturb the other"
print("  DELETE forgets exactly the session it names")
PY

rule "the reads wrote nothing to the log"
ENTRIES=$(grep -c . "$LOG")
[ "$ENTRIES" = "1" ] || fail "expected the objective alone in the log, found $ENTRIES entries"
echo "  ledger still holds 1 entry (the objective)"

printf '\n\033[32mMCP HTTP SMOKE OK\033[0m\n'
