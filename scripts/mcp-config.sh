#!/usr/bin/env bash
# Point an MCP client at this checkout's proofwork-mcp.
#
#   ./scripts/mcp-config.sh                      # Claude Code -> .mcp.json
#   ./scripts/mcp-config.sh --client opencode    # -> opencode.json
#   ./scripts/mcp-config.sh --client codex       # -> ~/.codex/config.toml
#   ./scripts/mcp-config.sh --print              # show the stanza, write nothing
#
# --identity defaults to .local/node.identity.json and is included in the
# stanza only when that file already exists, so a fresh checkout with no
# signed identity yet still wires up cleanly -- run
# `proofwork identity --out .local/node.identity.json` first if you want a
# submitter name nobody else can claim.
#
# Three clients, three schemas, one set of flags. docs/agents.md carries the
# stanzas as prose for anyone wiring this by hand; the point of doing it here
# too is that a hand-copied stanza drifts from the flags the server actually
# takes, and the failure is silent -- a client that launched the server against
# a path nobody meant looks exactly like a client that found no work to do.
#
# Absolute paths throughout. A client launches this server from a working
# directory nobody chose, so a relative --log does not fail, it quietly creates
# a second empty ledger and every objective you posted appears to be gone.
#
# The config is *merged* into whatever is already in the file. These files
# routinely hold other servers, and rewriting one wholesale to add a single
# stanza silently unwires everything else the user configured.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="$(pwd)"
PYTHON="${PYTHON:-python3}"
CLIENT=claude
# Defaults to the same ledger `make mcp` uses. If the config named a different
# path, starting the server one way and then the other would show two different
# worlds, and neither would look broken.
LOG="${MCP_LOG:-$REPO/.local/proofwork-mcp.jsonl}"
# Same default the Makefile's IDENTITY variable uses. Included only when the
# file exists, so a fresh checkout with no signed identity yet still wires up
# -- an agent that submits unsigned is a worse outcome than one that submits
# under a name someone else can also claim, but neither should be blocked on
# a key-generation step this script has no business forcing.
IDENTITY="${MCP_IDENTITY:-$REPO/.local/node.identity.json}"
OUT=""
PRINT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --client)   CLIENT="$2"; shift 2 ;;
    --log)      LOG="$2"; shift 2 ;;
    --identity) IDENTITY="$2"; shift 2 ;;
    --out)      OUT="$2"; shift 2 ;;
    --print)    PRINT=1; shift ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$CLIENT" in
  claude)   DEFAULT_OUT="$REPO/.mcp.json" ;;
  opencode) DEFAULT_OUT="$REPO/opencode.json" ;;
  codex)    DEFAULT_OUT="$HOME/.codex/config.toml" ;;
  *) echo "unknown client: $CLIENT (claude, opencode, codex)" >&2; exit 2 ;;
esac
OUT="${OUT:-$DEFAULT_OUT}"

# Absolute, and normalised: the log is created on first write, so realpath must
# not require it to exist yet.
case "$LOG" in /*) ;; *) LOG="$REPO/$LOG" ;; esac
MCP_BIN="$REPO/target/release/proofwork-mcp"

say() { printf '  %s\n' "$1"; }

if [ ! -x "$MCP_BIN" ]; then
  say "note: $MCP_BIN is not built yet -- 'make build' before starting a client"
fi

if [ "$PRINT" = "1" ]; then
  MCP_BIN="$MCP_BIN" LOG="$LOG" REPO="$REPO" CLIENT="$CLIENT" IDENTITY="$IDENTITY" "$PYTHON" - <<'PY'
import json, os
b, log, repo, client, identity = (
    os.environ[k] for k in ("MCP_BIN", "LOG", "REPO", "CLIENT", "IDENTITY")
)
args = ["--log", log, "--root", repo]
if os.path.exists(identity):
    args += ["--identity", identity]
if client == "claude":
    print(json.dumps({"mcpServers": {"proofwork": {"command": b, "args": args}}}, indent=2))
elif client == "opencode":
    print(json.dumps({"mcp": {"proofwork": {"type": "local", "command": [b, *args], "enabled": True}}}, indent=2))
else:
    quoted = ", ".join(f'"{a}"' for a in args)
    print(f'[mcp_servers.proofwork]\ncommand = "{b}"\nargs = [{quoted}]')
PY
  exit 0
fi

mkdir -p "$(dirname "$OUT")"

if [ "$CLIENT" = "codex" ]; then
  # TOML, and the standard library can read it but not write it. Appending a
  # section is the one edit that is safe without a round-tripping parser: it
  # cannot disturb what is above it. Refuse when the section already exists
  # rather than appending a duplicate, which TOML rejects outright.
  if [ -f "$OUT" ] && grep -q '^\[mcp_servers\.proofwork\]' "$OUT"; then
    say "[mcp_servers.proofwork] already in $OUT -- leaving it alone"
    say "delete that section and rerun to repoint it, or edit it by hand:"
    "$0" --client codex --log "$LOG" --print | sed 's/^/    /'
    exit 0
  fi
  [ -f "$OUT" ] && cp "$OUT" "$OUT.bak" && say "backed up -> $OUT.bak"
  ARGS_TOML="\"--log\", \"$LOG\", \"--root\", \"$REPO\""
  [ -f "$IDENTITY" ] && ARGS_TOML="$ARGS_TOML, \"--identity\", \"$IDENTITY\""
  {
    printf '\n# proofwork -- written by scripts/mcp-config.sh\n'
    printf '[mcp_servers.proofwork]\n'
    printf 'command = "%s"\n' "$MCP_BIN"
    printf 'args = [%s]\n' "$ARGS_TOML"
  } >>"$OUT"
  say "appended [mcp_servers.proofwork] -> $OUT"
else
  [ -f "$OUT" ] && cp "$OUT" "$OUT.bak" && say "backed up -> $OUT.bak"
  MCP_BIN="$MCP_BIN" LOG="$LOG" REPO="$REPO" CLIENT="$CLIENT" OUT="$OUT" IDENTITY="$IDENTITY" "$PYTHON" - <<'PY'
import json, os, sys

b, log, repo, client, out, identity = (
    os.environ[k] for k in ("MCP_BIN", "LOG", "REPO", "CLIENT", "OUT", "IDENTITY")
)
args = ["--log", log, "--root", repo]
if os.path.exists(identity):
    args += ["--identity", identity]

config = {}
if os.path.exists(out):
    try:
        with open(out) as fh:
            config = json.load(fh)
    except json.JSONDecodeError as exc:
        # Better to stop than to "fix" a file by overwriting it: the .bak is a
        # copy of something already broken, so a clobber here loses the only
        # version with the user's other servers in it.
        sys.exit(f"  {out} is not valid JSON ({exc}); fix or move it, then rerun")
    if not isinstance(config, dict):
        sys.exit(f"  {out} is not a JSON object; fix or move it, then rerun")

if client == "claude":
    section, entry = "mcpServers", {"command": b, "args": args}
else:
    section, entry = "mcp", {"type": "local", "command": [b, *args], "enabled": True}

servers = config.setdefault(section, {})
if not isinstance(servers, dict):
    sys.exit(f"  {out} has a non-object {section!r}; fix or move it, then rerun")

existing = sorted(k for k in servers if k != "proofwork")
replaced = "proofwork" in servers
servers["proofwork"] = entry

with open(out, "w") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")

print(f"  {'updated' if replaced else 'added'} 'proofwork' in {out}")
if existing:
    print(f"  kept alongside: {', '.join(existing)}")
PY
fi

say "log:  $LOG"
say "root: $REPO"
cat <<'NOTE'

  The client spawns its own copy of the server, so do NOT also run `make mcp`
  against this same log: both take the ledger's exclusive lock and whichever
  starts second exits with "another process is already writing".

  Claude Code picks up .mcp.json on restart. Verify with /mcp.
NOTE
