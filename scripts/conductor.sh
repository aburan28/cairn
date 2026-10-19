#!/usr/bin/env bash
# Conductor (conductor.build) workspaces for working on cairn itself.
#
#   ./scripts/conductor.sh setup   # when Conductor creates a workspace
#   ./scripts/conductor.sh run     # the Run button: a node for this workspace
#
# conductor.json calls this, because JSON has nowhere to say why. Each
# Conductor workspace is a git worktree of this repository with an agent in
# it, several at once; everything here keeps one workspace from reaching
# another, or the network.
#
# setup compiles what the gate in AGENTS.md section A runs first, so the
# agent's first `cargo test --all-targets` tests rather than builds, and
# installs the reader's packages when there is a Node toolchain to install
# them with. Each worktree keeps its own target/: a shared one would
# serialise every workspace on cargo's lock and rebuild on each branch switch.
#
# run starts `cairn run` on this workspace's own data and ports, built from
# this workspace's source, with the reader embedded when Node can build it:
#
#   - Data under .local/conductor/ (gitignored), so archiving the workspace
#     removes it and nothing is left outside the worktree to clean up -- which
#     is why there is no archive script.
#   - Ports from the ten Conductor gives each workspace: HTTP and the reader on
#     $CONDUCTOR_PORT, P2P on +1, MCP over HTTP on +2. Cloud workspaces set no
#     CONDUCTOR_PORT, and get 8080 and up.
#   - CAIRN_NETWORK=private: no seeds, no LAN beacon, no port mapping, and no
#     peer accepted. A branch under development must not find the
#     developer's live node on the same segment and sync with it -- the
#     failure `src/daemon.rs` records from the smoke tests -- nor another
#     workspace's node, nor the public network.
#   - --no-mcp: a run script's stdin is not a terminal, and plain `run` stops
#     when stdin closes. Agents reach this node at the MCP HTTP port instead.
set -euo pipefail
cd "${CONDUCTOR_WORKSPACE_PATH:-$(dirname "$0")/..}"

say() { printf '  %s\n' "$1"; }

setup() {
  cargo test --all-targets --no-run
  if command -v npm >/dev/null 2>&1; then
    (cd ui && npm ci --no-audit --no-fund)
  else
    say "no npm: skipping ui/ (the reader); cargo alone builds and tests the node"
  fi
}

run() {
  local port="${CONDUCTOR_PORT:-8080}"
  local p2p=$((port + 1)) mcp=$((port + 2))
  local data="$PWD/.local/conductor"
  mkdir -p "$data"

  # The reader is embedded at compile time from ui/out. Without it /ui/
  # answers 404 and every other route works, which is enough to work on the
  # node; say so rather than fail.
  # Expanded as ${features[@]+...} below: macOS's bash 3.2 calls an empty
  # array unbound under `set -u`.
  local features=()
  if [ -d ui/out ]; then
    features=(--features ui)
  elif command -v npm >/dev/null 2>&1 && [ -d ui/node_modules ]; then
    (cd ui && npm run build)
    features=(--features ui)
  else
    say "no ui/out and no way to build it: the node runs, /ui/ answers 404"
  fi

  say "reader: http://127.0.0.1:$port/ui/"
  say "mcp:    http://127.0.0.1:$mcp/mcp"
  say "data:   $data"
  CAIRN_NETWORK=private exec cargo run ${features[@]+"${features[@]}"} --bin cairn -- \
    --data-dir "$data" --root "$PWD" \
    run --no-mcp \
    --listen "127.0.0.1:$p2p" \
    --serve "127.0.0.1:$port" \
    --mcp-http "127.0.0.1:$mcp"
}

case "${1:-}" in
  setup) setup ;;
  run) run ;;
  *) echo "usage: $0 setup|run" >&2; exit 2 ;;
esac
