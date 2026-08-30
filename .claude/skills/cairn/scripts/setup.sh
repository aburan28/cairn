#!/usr/bin/env bash
# Operator setup, end to end: build, wire MCP, post starter objectives.
#
# Written as a script rather than a list of steps in the skill because every
# one of these has a way to go subtly wrong -- a relative path in .mcp.json
# that resolves against a directory the agent did not choose, a log the server
# is not actually pointed at, an objective whose pinned checker this node
# cannot resolve. Getting them right once here beats getting them right each
# time from prose.
#
#   setup.sh [--serve] [--port N] [--log PATH] [--demo-epochs]
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
cd "$REPO"

SERVE=0
PORT=8787
LOG="$REPO/cairn.jsonl"
DEMO_EPOCHS=0

while [ $# -gt 0 ]; do
  case "$1" in
    --serve) SERVE=1; shift ;;
    --port) PORT="$2"; shift 2 ;;
    --log) LOG="$2"; shift 2 ;;
    --demo-epochs) DEMO_EPOCHS=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
say()  { printf '  %s\n' "$1"; }

rule "build"
if [ ! -x target/release/cairn ]; then
  cargo build --release --locked
fi
say "cairn (one binary: the CLI, plus the mcp, serve, p2p and run subcommands)"

# The jail matters more than it looks: objectives carry code somebody else
# wrote, and this node runs it. Say plainly whether there is one rather than
# letting the operator assume.
rule "sandbox"
if command -v bwrap >/dev/null 2>&1; then
  say "bubblewrap present -- verifier code runs jailed"
  say "set CAIRN_REQUIRE_SANDBOX=1 to refuse to run unjailed at all"
elif [ "$(uname)" = "Darwin" ] && command -v sandbox-exec >/dev/null 2>&1; then
  say "seatbelt present -- verifier code runs jailed (reads are NOT confined on macOS)"
else
  say "WARNING: no jail mechanism found. Objective-authored code will run"
  say "unconfined. On Linux: apt install bubblewrap. Until then, only post"
  say "objectives whose checkers you have read."
fi

rule "wire Claude Code"
# Delegated to scripts/mcp-config.sh (also `make mcp-setup`) rather than
# written here. This used to `cat > .mcp.json`, which silently unwired every
# other MCP server the user had configured -- that file usually holds several.
# The script merges instead, and keeping one implementation means the stanza
# cannot drift between the two entry points.
./scripts/mcp-config.sh --client claude --log "$LOG"
say "restart Claude Code (or /mcp reconnect) to pick it up"

rule "wire OpenCode"
# Same delegation as Claude Code above, same reason: one implementation that
# merges instead of two that can drift, one of them clobbering.
./scripts/mcp-config.sh --client opencode --log "$LOG"
say "restart OpenCode (or /mcp reconnect) to pick it up"

rule "post starter objectives"
POSTED=0
for objective in \
  examples/reversible-adder/objective.json \
  examples/capset_progressive/objective.json \
  examples/collatz/objective.json
do
  # Already-posted objectives are refused as duplicates -- ids are content
  # addresses, so re-running this script is idempotent rather than additive.
  if out=$(./target/release/cairn --log "$LOG" --root . post "$objective" 2>&1); then
    say "$(printf '%s' "$out" | head -1)  <- $(basename "$(dirname "$objective")")"
    POSTED=$((POSTED + 1))
  else
    case "$out" in
      *duplicate*|*already*) say "already posted: $(basename "$(dirname "$objective")")" ;;
      *) printf '  failed: %s\n' "$out" >&2 ;;
    esac
  fi
done
say "$POSTED newly posted"

if [ "$DEMO_EPOCHS" = "1" ]; then
  rule "demo epochs"
  say "export CAIRN_EPOCH_SECONDS=1 in every shell that touches this log,"
  say "including the one running the MCP server -- epochs are derived from"
  say "record timestamps, so a log written at 1s audits as broken at 600s."
fi

rule "next"
say "Ask Claude: \"list the cairn objectives and improve the frontier on one\""
say "Verify anything the node claims:  ./target/release/cairn --log $LOG --root . audit"

if [ "$SERVE" = "1" ]; then
  rule "serve"
  mkdir -p "$REPO/queue"
  say "http://127.0.0.1:$PORT/objectives   (queue at $REPO/queue)"
  say "admit submissions with: cairn drain --queue $REPO/queue"
  say "Ctrl-C to stop"
  exec ./target/release/cairn --log "$LOG" --root "$REPO" \
    serve --listen "127.0.0.1:$PORT" --queue "$REPO/queue"
fi
