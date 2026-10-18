#!/usr/bin/env bash
# Probe the same authenticated MCP path a remote agent uses. This is read-only.
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 https://cairn-hub.<tailnet>.ts.net:8443/mcp [--allow-loopback-http]" >&2
    exit 2
fi
if [ -z "${CAIRN_MCP_USER:-}" ] || [ -z "${CAIRN_MCP_PASSWORD:-}" ]; then
    echo "set CAIRN_MCP_USER and CAIRN_MCP_PASSWORD in the private environment" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' |
    python3 "$ROOT/scripts/cairn-remote-stdio.py" "$@" |
    python3 -c '
import json, sys
frames = [json.loads(line) for line in sys.stdin if line.strip()]
if len(frames) != 2 or [frame.get("id") for frame in frames] != [1, 2]:
    raise SystemExit("MCP probe did not receive initialize and tools/list responses")
for frame in frames:
    if "error" in frame:
        raise SystemExit("MCP probe failed: " + str(frame["error"]))
if frames[0].get("result", {}).get("protocolVersion") != "2025-06-18":
    raise SystemExit("MCP protocol version mismatch")
names = {tool.get("name") for tool in frames[1].get("result", {}).get("tools", [])}
required = {"list_objectives", "get_objective", "score_candidate", "submit_claim", "pending_reveals"}
missing = required - names
if missing:
    raise SystemExit("MCP endpoint lacks required Cairn tools: " + ", ".join(sorted(missing)))
print(f"Cairn MCP ready: {len(names)} tools through one initialized session")
'
