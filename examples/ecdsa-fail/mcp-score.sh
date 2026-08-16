#!/usr/bin/env bash
# Smoke the existing cairn-mcp tools against the ecdsa-fail MVP objective.
# No new MCP tools — documents the natural wiring from docs/agents.md.
set -euo pipefail
cd "$(dirname "$0")/../.."

LOG="${1:-/tmp/cairn-ecdsa-mcp.jsonl}"
rm -f "$LOG"
OUT=$(mktemp /tmp/pw-ecdsa-mcp-out-XXXXXX.jsonl)
trap 'rm -f "$OUT"' EXIT

MCP="${CAIRN_MCP_BIN:-./target/release/cairn-mcp}"
PW="${CAIRN_BIN:-./target/release/cairn}"
[ -x "$PW" ] || cargo build --release
[ -x "$MCP" ] || cargo build --release --bin cairn-mcp

OID=$("$PW" --log "$LOG" --root . post examples/ecdsa-fail/objective.json | head -1 | awk '{print $2}')
echo "objective $OID" >&2

ARTIFACT=$(python3 -c 'import json; print(json.dumps(json.load(open("examples/ecdsa-fail/artifacts/mid.json"))))')

{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ecdsa-fail-smoke","version":"0"}}}'
  printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"score_candidate\",\"arguments\":{\"objective_id\":\"$OID\",\"artifact\":$ARTIFACT}}}"
  printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_objectives","arguments":{}}}'
} | "$MCP" --log "$LOG" --root . >"$OUT" 2>/dev/null

python3 - "$OUT" "$OID" <<'PY'
import json, sys
path, oid = sys.argv[1], sys.argv[2]
seen = {}
for line in open(path):
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    seen[msg.get("id")] = msg

score = seen[2]["result"]
assert score["isError"] is False, score
text = score["content"][0]["text"]
assert "accept" in text and "56000" in text, text
assert "Nothing was recorded" in text, text
print(text)

listed = seen[3]["result"]["content"][0]["text"]
assert oid in listed, listed
assert "GOAL-ecdsa-fail" in listed or "ecdsa.fail" in listed or "qubit" in listed, listed
print("---")
print(listed)
PY

echo "mcp-score ok (log $LOG)" >&2
