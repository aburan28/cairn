#!/usr/bin/env bash
# Point an MCP client at this checkout's cairn-mcp.
#
#   ./scripts/mcp-config.sh                      # Claude Code -> .mcp.json
#   ./scripts/mcp-config.sh --client opencode    # -> opencode.json
#   ./scripts/mcp-config.sh --client codex       # -> ~/.codex/config.toml
#   ./scripts/mcp-config.sh --print              # show the stanza, write nothing
#
# --identity defaults to .local/node.identity.json and is included in the
# stanza only when that file already exists, so a fresh checkout with no
# signed identity yet still wires up cleanly -- run
# `cairn identity --out .local/node.identity.json` first if you want a
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
LOG="${MCP_LOG:-$REPO/.local/cairn-mcp.jsonl}"
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
MCP_BIN="$REPO/target/release/cairn-mcp"

say() { printf '  %s\n' "$1"; }

if [ ! -x "$MCP_BIN" ]; then
  say "note: $MCP_BIN is not built yet -- 'make build' before starting a client"
fi

# An identity file that exists but is not a cairn identity is worse than no
# identity at all: the stanza wires up, the client launches the server, and
# cairn-mcp exits 2 before the MCP handshake -- which every client reports as
# a bare connection failure with no mention of a key. The default filename is
# one a p2p node key also answers to, and that key is the wrong shape by three
# orders of magnitude. Check for what --identity actually takes, not for a
# filename, because existence was never the property that mattered here.
if [ -f "$IDENTITY" ]; then
  if ! IDENTITY_WHY=$(IDENTITY="$IDENTITY" "$PYTHON" -c '
import json, os, sys
path = os.environ["IDENTITY"]
try:
    with open(path) as fh:
        value = json.load(fh)
except (OSError, ValueError) as exc:
    sys.exit("not usable JSON (%s)" % exc)
if not isinstance(value, dict):
    sys.exit("not a JSON object")
secret = value.get("secret")
if not isinstance(secret, str):
    sys.exit("no \"secret\" field")
if len(secret) != 64:
    sys.exit("\"secret\" must be 32 bytes of hex, got %d characters" % len(secret))
if any(c not in "0123456789abcdefABCDEF" for c in secret):
    sys.exit("\"secret\" is not hex")
' 2>&1); then
    say "ignoring $IDENTITY: $IDENTITY_WHY"
    say "wiring up unsigned instead -- submissions will authenticate nothing."
    say 'write one this takes with: cairn identity --out .local/agent.identity.json'
    say "then rerun with --identity .local/agent.identity.json"
    IDENTITY=""
  fi
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
    print(json.dumps({"mcpServers": {"cairn": {"command": b, "args": args}}}, indent=2))
elif client == "opencode":
    print(json.dumps({"mcp": {"cairn": {"type": "local", "command": [b, *args], "enabled": True}}}, indent=2))
else:
    quoted = ", ".join(f'"{a}"' for a in args)
    print(f'[mcp_servers.cairn]\ncommand = "{b}"\nargs = [{quoted}]')
PY
  exit 0
fi

mkdir -p "$(dirname "$OUT")"

if [ "$CLIENT" = "codex" ]; then
  # TOML, and the standard library can read it but not write it. Appending a
  # section is the one edit that is safe without a round-tripping parser: it
  # cannot disturb what is above it. Refuse when the section already exists
  # rather than appending a duplicate, which TOML rejects outright.
  if [ -f "$OUT" ] && grep -q '^\[mcp_servers\.cairn\]' "$OUT"; then
    say "[mcp_servers.cairn] already in $OUT -- leaving it alone"
    say "delete that section and rerun to repoint it, or edit it by hand:"
    "$0" --client codex --log "$LOG" --print | sed 's/^/    /'
    exit 0
  fi
  [ -f "$OUT" ] && cp "$OUT" "$OUT.bak" && say "backed up -> $OUT.bak"
  ARGS_TOML="\"--log\", \"$LOG\", \"--root\", \"$REPO\""
  [ -f "$IDENTITY" ] && ARGS_TOML="$ARGS_TOML, \"--identity\", \"$IDENTITY\""
  {
    printf '\n# cairn -- written by scripts/mcp-config.sh\n'
    printf '[mcp_servers.cairn]\n'
    printf 'command = "%s"\n' "$MCP_BIN"
    printf 'args = [%s]\n' "$ARGS_TOML"
  } >>"$OUT"
  say "appended [mcp_servers.cairn] -> $OUT"
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

existing = sorted(k for k in servers if k != "cairn")
replaced = "cairn" in servers
servers["cairn"] = entry

with open(out, "w") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")

print(f"  {'updated' if replaced else 'added'} 'cairn' in {out}")
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
