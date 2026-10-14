#!/usr/bin/env bash
# Install cairn in a cloud workspace (written for Claude's) and reach out to the
# published seed. Self-contained: it needs no checkout, only curl and tar, so it
# can be fetched on its own as well as run from here.
#
#   scripts/cloud-setup.sh [all|install|start|stop|status] [--require-seed]
#
#   all (default)  install, then start a node that dials the seed, then report
#   install        download + verify + install only. Never touches the network
#                  beyond GitHub, never starts anything, and never fails because
#                  the seed is unreachable -- safe as an environment *setup
#                  script*, where a non-zero exit breaks every new session
#   start          start the node (idempotent) and report who it reached
#   stop / status  what they say
#
#   --require-seed exit 1 if the seed cannot be reached (default: report, exit 0)
#
# Environment (all optional):
#   CAIRN_VERSION    release to install, without the "v" (default: the latest)
#   CAIRN_PREFIX     state and install root            (default: ~/.cairn)
#   CAIRN_LISTEN     p2p address                       (default: 127.0.0.1:9000)
#   CAIRN_SERVE      HTTP address                      (default: 127.0.0.1:8080)
#   CAIRN_SEEDS_URL  where to read the seed list       (default: the Pages copy)
#   CAIRN_LINK       0 = do not symlink into /usr/local/bin
#
# What it does NOT do: it does not post objectives, fund anything, or submit a
# claim. It starts a node and lets the node's own seed list (compiled into the
# binary, ids checked at the handshake) decide who it talks to.
#
# Read this before expecting a connection. This script can only use the network
# the environment allows. A Claude cloud workspace reaches the internet through
# a proxy, and on the "limited" levels only port 443 got through when this was
# written; the seed's p2p port is 9000. The preflight below tells you which of
# those it is, so a blocked port is reported as that and not as "seed down".
set -euo pipefail

PREFIX=${CAIRN_PREFIX:-$HOME/.cairn}
LISTEN=${CAIRN_LISTEN:-127.0.0.1:9000}
SERVE=${CAIRN_SERVE:-127.0.0.1:8080}
SEEDS_URL=${CAIRN_SEEDS_URL:-https://aburan28.github.io/cairn/seeds.json}
FALLBACK_SEED=44.251.117.84:9000   # launch/seeds.json "us-west", used only if the list can't be fetched
REPO=aburan28/cairn

BIN=$PREFIX/bin/cairn
DATA=$PREFIX/node
BUNDLE=$PREFIX/bundle
IDENTITY=$PREFIX/node.identity.json
PIDFILE=$DATA/node.pid
LOGFILE=$DATA/node.log

MODE=all
REQUIRE_SEED=0
for arg in "$@"; do
  case "$arg" in
    all|install|start|stop|status) MODE=$arg ;;
    --require-seed) REQUIRE_SEED=1 ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
  esac
done

say()  { printf '  %s\n' "$*"; }
rule() { printf '\n== %s\n' "$*"; }
warn() { printf '  WARNING: %s\n' "$*" >&2; }
die()  { printf 'cloud-setup: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- install ---

latest_version() {
  # /releases/latest redirects to /releases/tag/vX.Y.Z; reading the redirect
  # needs no API token and no JSON parser.
  local url
  url=$(curl -fsSL -m 30 -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || return 1
  url=${url##*/v}
  [[ $url =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || return 1
  printf '%s\n' "$url"
}

install_cairn() {
  rule "install"
  have curl || die "curl is required"
  have tar  || die "tar is required"

  local arch target
  case "$(uname -m)" in
    x86_64|amd64)  arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) die "unsupported CPU: $(uname -m)" ;;
  esac
  [ "$(uname -s)" = Linux ] || die "this script is for Linux workspaces ($(uname -s) found)"
  target=$arch-unknown-linux-musl   # static: no library dependencies in the container

  local ver=${CAIRN_VERSION:-}
  if [ -z "$ver" ]; then
    ver=$(latest_version) || die "could not read the latest release; set CAIRN_VERSION=x.y.z"
  fi
  ver=${ver#v}

  if [ -x "$BIN" ] && [ "$("$BIN" --version 2>/dev/null | head -1)" = "cairn $ver" ]; then
    say "cairn $ver already installed at $BIN"
  else
    local tarball=cairn-v$ver-$target.tar.gz
    local base=https://github.com/$REPO/releases/download/v$ver
    local work; work=$(mktemp -d)
    say "downloading $tarball"
    curl -fsSL -m 300 -o "$work/$tarball"        "$base/$tarball"        || die "download failed: $base/$tarball"
    curl -fsSL -m 60  -o "$work/$tarball.sha256" "$base/$tarball.sha256" || die "checksum download failed"
    # The checksum comes from the same server as the tarball: it catches a
    # corrupt download, not a malicious server (the release notes say so too).
    ( cd "$work" && sha256sum -c "$tarball.sha256" >/dev/null ) || die "checksum mismatch for $tarball"
    say "sha256 ok"
    tar -xzf "$work/$tarball" -C "$work"
    mkdir -p "$PREFIX/bin"
    install -m 0755 "$work/cairn" "$BIN"
    rm -rf "$work"
  fi
  say "$("$BIN" --version | head -1)"
  "$BIN" --version | grep -q embedded || warn "this build has no embedded reader; 'cairn run' will refuse to start"

  # Put it on PATH where we can; otherwise say how. CAIRN_LINK=0 skips this.
  if [ "${CAIRN_LINK:-1}" = 1 ] && [ -w /usr/local/bin ]; then
    ln -sf "$BIN" /usr/local/bin/cairn
    say "linked /usr/local/bin/cairn"
  else
    say "add to PATH:  export PATH=\"$PREFIX/bin:\$PATH\""
  fi

  # A signing identity. Its public half IS the submitter name, so keep the file.
  umask 077
  if [ ! -f "$IDENTITY" ]; then
    "$BIN" identity --out "$IDENTITY" >/dev/null
    say "created identity $IDENTITY (back it up: losing it loses the name)"
  else
    say "identity present: $IDENTITY"
  fi

  # The bundle: the files an objective's pinned checkers live in. A node runs a
  # checker from a path under --root, so without this every claim it is asked
  # to check comes back "unavailable". Taken from the same tag as the binary.
  # Not fatal: a node that can't verify can still relay.
  if [ ! -d "$BUNDLE/examples" ]; then
    mkdir -p "$BUNDLE"
    if curl -fsSL -m 300 "https://github.com/$REPO/archive/refs/tags/v$ver.tar.gz" \
         | tar -xz -C "$BUNDLE" --strip-components=1; then
      say "bundle fetched into $BUNDLE"
    else
      warn "bundle fetch failed; claims will answer 'unavailable' until $BUNDLE holds the repository"
    fi
  else
    say "bundle present: $BUNDLE"
  fi

  # A node that verifies objectives it did not write must run their code
  # jailed or not at all (docs/configuration.md). bubblewrap is the jail.
  if ! have bwrap; then
    if [ "$(id -u)" = 0 ] && have apt-get; then
      if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bubblewrap >/dev/null 2>&1; then
        say "installed bubblewrap"
      else
        warn "could not install bubblewrap; with CAIRN_REQUIRE_SANDBOX=1 claims will answer 'unavailable'"
      fi
    else
      warn "bubblewrap not found and not installable here; claims will answer 'unavailable'"
    fi
  else
    say "jail: bwrap present"
  fi
}

# ------------------------------------------------------------ seed preflight ---

tcp_ok() { # host port -> 0 if a TCP connection opens within 6s
  timeout 6 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

seed_addresses() {
  local list
  if list=$(curl -fsSL -m 20 "$SEEDS_URL" 2>/dev/null) && [ -n "$list" ]; then
    printf '%s\n' "$list" | grep -o '"addr": *"[^"]*"' | sed 's/.*: *"//; s/"$//'
  fi
}

# Sets SEED_REACHABLE=1/0 and prints what it found. Never exits non-zero.
SEED_REACHABLE=0
preflight_seed() {
  rule "seed preflight"
  local addrs; addrs=$(seed_addresses || true)
  if [ -z "$addrs" ]; then
    warn "could not read $SEEDS_URL; trying the fallback $FALLBACK_SEED"
    addrs=$FALLBACK_SEED
  else
    say "seed list read from $SEEDS_URL"
  fi

  local web_ok=0
  if tcp_ok 1.1.1.1 443; then web_ok=1; fi

  local addr host port
  while IFS= read -r addr; do
    [ -n "$addr" ] || continue
    host=${addr%:*}; port=${addr##*:}
    if tcp_ok "$host" "$port"; then
      say "seed $addr: TCP connect OK"
      SEED_REACHABLE=1
    elif [ "$port" != 443 ] && [ "$web_ok" = 1 ] && ! tcp_ok 8.8.8.8 53 && ! tcp_ok 8.8.8.8 853; then
      warn "seed $addr: no connection, and other live non-443 ports (DNS 53/853) fail too."
      warn "  This environment appears to allow outbound TCP on 443 only, so this says nothing about whether"
      warn "  the seed is up. Widen 'Network access' in the cloud environment's settings, or run this script"
      warn "  on a machine that can reach port $port."
    else
      warn "seed $addr: no connection (other ports work, so the seed may be down or firewalled)"
    fi
  done <<< "$addrs"
}

# --------------------------------------------------------------- node ---------

node_running() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

start_node() {
  rule "node"
  [ -x "$BIN" ] || die "not installed; run: $0 install"
  mkdir -p "$DATA"
  if node_running; then
    say "already running (pid $(cat "$PIDFILE"))"
    return 0
  fi
  # CAIRN_BEACON_PORT=off: a cloud segment drops multicast. PORTMAP is moot on loopback.
  # One simple command is backgrounded, so $! is the node itself and `stop`
  # kills the right process (backgrounding a `cd && cmd` list would record a
  # wrapper subshell instead).
  (
    cd "$DATA"
    CAIRN_REQUIRE_SANDBOX=1 CAIRN_BEACON_PORT=off CAIRN_LOG_LEVEL=info \
      nohup "$BIN" --log "$DATA/cairn.jsonl" --root "$BUNDLE" --data-dir "$DATA" \
        run --no-mcp --listen "$LISTEN" --serve "$SERVE" \
        >"$LOGFILE" 2>&1 < /dev/null &
    echo $! > "$PIDFILE"
  )
  sleep 3
  if ! node_running; then
    warn "node exited at start; last log lines:"
    tail -n 8 "$LOGFILE" >&2 || true
    return 1
  fi
  say "started (pid $(cat "$PIDFILE")), p2p $LISTEN, http $SERVE"
  say "log: $LOGFILE"
}

report() {
  rule "status"
  if ! node_running; then say "node: not running"; return 0; fi
  say "node: running (pid $(cat "$PIDFILE"))"
  local base=http://$SERVE
  # Give the first seed dial a chance: the daemon asks, waits, and asks again every minute.
  sleep 8
  if have python3 && curl -fsS -m 10 "$base/sessions" -o "$DATA/sessions.json" 2>/dev/null; then
    python3 - "$DATA/sessions.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
t = d.get("this_node", {})
print("  peer id            ", t.get("peer_id", "?"))
peers = d.get("peers", [])
print("  peers seen         ", len(peers))
for p in peers:
    print("   ", p.get("status"), p.get("last_direction"), p.get("addr"), str(p.get("peer_id", ""))[:16])
PY
  else
    say "no /sessions answer yet at $base"
  fi
  grep -E 'seeds:|verifier code|verifiers:' "$LOGFILE" | tail -n 4 | sed 's/^/  log: /' || true
  say "log entries: $(wc -l < "$DATA/cairn.jsonl" 2>/dev/null || echo 0)"
}

stop_node() {
  rule "stop"
  if node_running; then
    local pid; pid=$(cat "$PIDFILE")
    kill "$pid"
    # SIGTERM lets the node finish its write; it can take a few seconds. Wait
    # for it rather than report "stopped" early, and never SIGKILL: the log is
    # append-only and a hard kill is the one thing that can tear its tail.
    for _ in $(seq 1 30); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      warn "pid $pid is still shutting down after 30s; not forcing it (see $LOGFILE)"
    else
      rm -f "$PIDFILE"
      say "stopped"
    fi
  else
    say "not running"
  fi
}

# --------------------------------------------------------------- main ---------

case "$MODE" in
  install) install_cairn ;;
  stop)    stop_node ;;
  status)  report ;;
  start)   preflight_seed; start_node; report ;;
  all)     install_cairn; preflight_seed; start_node || true; report ;;
esac

if [ "$REQUIRE_SEED" = 1 ] && [ "$MODE" != install ] && [ "$MODE" != stop ] && [ "$MODE" != status ] \
   && [ "$SEED_REACHABLE" != 1 ]; then
  printf '\ncloud-setup: --require-seed set and the seed was not reachable\n' >&2
  exit 1
fi
exit 0
