#!/usr/bin/env bash
# End-to-end smoke test of the MCP server as a real process.
#
# The unit tests in src/bin/mcp.rs call `handle_line` directly, which cannot
# catch the failure mode that actually breaks MCP clients: something writing to
# stdout that is not a JSON-RPC response. One stray `println!`, one library
# banner, one panic message on the wrong stream, and the client sees a corrupt
# frame and blames itself. That is only observable by running the binary and
# reading its stdout, which is what this does.
#
# It also proves the pinned verifier really runs -- the score below comes from
# the Python evaluator in examples/, executed as a subprocess with its hash
# checked first, not from anything Rust-side.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
MCP="${MCP_BIN:-./target/release/proofwork-mcp}"

if [ ! -x "$RUST" ] || [ ! -x "$MCP" ]; then
  echo "building release binaries..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

LOG=$(mktemp -u /tmp/pw-mcp-XXXXXX.jsonl)
OUT=$(mktemp -u /tmp/pw-mcp-out-XXXXXX.jsonl)
trap 'rm -f "$LOG" "$OUT"' EXIT

rule "post an objective with the CLI"
OID=$("$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json \
  | head -1 | awk '{print $2}')
echo "  $OID"

rule "drive the server over a pipe"
ARTIFACT=$(python3 -c 'import json;print(json.dumps(json.load(open("examples/capset_progressive/artifact-12.json"))))')
{
  echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
  echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"score_candidate","arguments":{"objective_id":"%s","artifact":%s}}}\n' \
    "$OID" "$ARTIFACT"
} | "$MCP" --log "$LOG" --root . > "$OUT" 2>/dev/null

python3 - "$OUT" <<'PY'
import json, sys

lines = [l for l in open(sys.argv[1]).read().splitlines() if l.strip()]

# Every single line must be a JSON-RPC response. This is the assertion the unit
# tests structurally cannot make.
seen = {}
for i, line in enumerate(lines, 1):
    try:
        msg = json.loads(line)
    except json.JSONDecodeError as e:
        raise SystemExit(f"FAIL: stdout line {i} is not JSON ({e}): {line[:120]!r}")
    if msg.get("jsonrpc") != "2.0":
        raise SystemExit(f"FAIL: stdout line {i} is not JSON-RPC 2.0: {line[:120]!r}")
    seen[msg.get("id")] = msg

# The notification must not have been answered.
if len(lines) != 3:
    raise SystemExit(f"FAIL: expected 3 responses (a notification gets none), got {len(lines)}")

init = seen[1]["result"]
assert init["protocolVersion"] == "2025-06-18", init
assert init["serverInfo"]["name"] == "proofwork", init

tools = {t["name"] for t in seen[2]["result"]["tools"]}
for required in ("score_candidate", "list_objectives", "submit_claim", "audit"):
    assert required in tools, f"{required} missing from {sorted(tools)}"

score = seen[3]["result"]
assert score["isError"] is False, score
text = score["content"][0]["text"]
assert "accept" in text, text
assert "score: 12" in text, text
# Read-only: it must say so, and the ledger check below proves it.
assert "Nothing was recorded" in text, text

print("  every stdout line is a valid JSON-RPC response")
print(f"  tools advertised: {len(tools)}")
print("  score_candidate ran the pinned evaluator and returned score 12")
PY

rule "score_candidate wrote nothing to the log"
BEFORE=$(grep -c . "$LOG")
[ "$BEFORE" = "1" ] || fail "expected the objective alone in the log, found $BEFORE entries"
echo "  ledger still holds 1 entry (the objective)"

printf '\n\033[32mMCP SMOKE OK\033[0m\n'
