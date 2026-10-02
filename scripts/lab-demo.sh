#!/usr/bin/env bash
# Two agents, one research space, no git: the workflow `cairn lab` exists for,
# end to end through the CLI, every step checked rather than printed.
#
# The crypto-autoresearcher program ran its shared state through git and spent
# most of its CLAUDE.md on what that cost: identifier collisions found at merge
# time, conflicts on files nobody edited in the same place, squash merges that
# orphaned recorded SHAs, coordination by polling a merge digest. This is the
# same work on the lab instead (docs/lab.md):
#
#   1. a space with the program's write-once policy, and a second writer
#   2. the research tree committed; a second replica cloned from a directory
#   3. a concurrent edit to a mutable record becomes a visible conflict on both
#      replicas, and a resolve by somebody who saw both sides closes it
#   4. editing an immutable record is refused before anything is signed, and
#      two different first writes of one record id stay a visible conflict
#   5. two agents claim one task at once; one sync later both replicas name the
#      same holder
#   6. a message to a role, read and acknowledged on the other replica
#   7. a revoked writer's concurrent write is excluded everywhere
#   8. a bundle file and the encrypted network carrier reproduce the space
#   9. a run in an environment with its receipt and outputs as one op: under
#      gVisor or bubblewrap when this host has one, otherwise the refusal and
#      an explicitly unconfined run whose receipt says so
#
# Needs python3 (to read JSON) and loopback networking; not root, not git.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release
fi
RUST="$(cd "$(dirname "$RUST")" && pwd)/$(basename "$RUST")"
POLICY="$PWD/examples/lab/crypto-autoresearcher.policy.json"

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }
ok() { printf '  \033[32mok\033[0m %s\n' "$1"; }

WORK=$(mktemp -d /tmp/cairn-lab-demo-XXXXXX)
cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  # runsc keeps one `null-netns` mount in a lab's runtime root; see
  # `exec::Spec::runtime_dir`. Best effort, so the demo leaves no mount behind.
  for lab in "$WORK"/*/; do
    if [ -e "$lab/runtime/null-netns" ]; then
      umount "$lab/runtime/null-netns" 2>/dev/null || true
    fi
  done
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
cd "$WORK"

lab() { "$RUST" lab --lab "$@"; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
expect_exit() {
  local want=$1
  shift
  set +e
  "$@" 2>&1 | sed 's/^/  /'
  local got=${PIPESTATUS[0]}
  set -e
  [ "$got" = "$want" ] || fail "expected exit $want, got $got: $*"
}
# Everything a reader of the space sees, minus nothing: two replicas that hold
# the same ops must print the same bytes.
view() {
  lab "$1" status --json
  lab "$1" ls --json
  lab "$1" conflicts --json
}
same_view() {
  diff <(view "$1") <(view "$2") >/dev/null || fail "replicas $1 and $2 disagree"
}

rule "1. a space with the program's policy, and a second writer"
"$RUST" lab identity --out alice.json >/dev/null
"$RUST" lab identity --out bob.json >/dev/null
BOB=$(json "d['public']" <bob.json)
lab a init --name ecdlp-program --identity alice.json --policy "$POLICY" | sed 's/^/  /'
lab a admit "$BOB" --roles writer --identity alice.json >/dev/null
SPACE=$(lab a status --json | json "d['space']")
lab a members | sed 's/^/  /'

rule "2. the research tree, committed; a replica cloned from a directory"
mkdir -p wa/ledger/goals wa/ledger/evidence wa/knowledge wa/experiments/EXP-ECC-0a1b2c
printf 'id: GOAL-ECC-1a2b3c\nstatus: active\nnext_action: design\n' >wa/ledger/goals/GOAL-ECC-1a2b3c.yaml
printf 'id: EV-ECC-4d5e6f\nclaim: toy rho on a 20-bit curve\n' >wa/ledger/evidence/EV-ECC-4d5e6f.yaml
printf 'curve: p=1000003 a=17 b=3\nseed: 7\n' >wa/experiments/EXP-ECC-0a1b2c/params.txt
printf 'generated; never committed\n' >wa/knowledge/INDEX.md
lab a commit wa --identity alice.json | sed 's/^/  /'
lab a ls knowledge | grep -q INDEX && fail "an ignored path entered the space"
ok "knowledge/INDEX.md is ignored by policy: it never enters the space"
lab b clone --space "$SPACE" --dir a | sed 's/^/  /'
lab b checkout wb >/dev/null
cmp -s wa/ledger/goals/GOAL-ECC-1a2b3c.yaml wb/ledger/goals/GOAL-ECC-1a2b3c.yaml ||
  fail "checkout is not byte-identical"
ok "replica b's checkout is byte-identical"

rule "3. a concurrent edit to a mutable record is a visible conflict, then resolved"
printf 'id: GOAL-ECC-1a2b3c\nstatus: active\nnext_action: run EXP-ECC-0a1b2c\n' \
  >wa/ledger/goals/GOAL-ECC-1a2b3c.yaml
printf 'id: GOAL-ECC-1a2b3c\nstatus: active\nnext_action: design\nimpediments: [gpu quota]\n' \
  >wb/ledger/goals/GOAL-ECC-1a2b3c.yaml
lab a commit wa --identity alice.json >/dev/null
lab b commit wb --identity bob.json >/dev/null
lab a sync --dir b >/dev/null
for r in a b; do
  [ "$(lab $r conflicts --json | json 'len(d)')" = 1 ] || fail "replica $r does not show the conflict"
done
ok "both replicas show one conflict; neither edit was lost"
lab b checkout wb | sed 's/^/  /'
ls wb/ledger/goals/*.lab-conflict-* >/dev/null || fail "no conflict sidecar"
printf 'id: GOAL-ECC-1a2b3c\nstatus: active\nnext_action: run EXP-ECC-0a1b2c\nimpediments: [gpu quota]\n' \
  >wb/ledger/goals/GOAL-ECC-1a2b3c.yaml
lab b commit wb --identity bob.json >/dev/null
lab a sync --dir b >/dev/null
[ "$(lab a conflicts --json | json 'len(d)')" = 0 ] || fail "the resolve did not close the conflict"
same_view a b
ok "bob edited the file with both sides on disk; the conflict is closed on both replicas"

rule "4. immutable records: edits refused before signing; an id collision stays visible"
lab b checkout wb --force >/dev/null
echo 'claim: quietly improved' >>wb/ledger/evidence/EV-ECC-4d5e6f.yaml
expect_exit 2 lab b commit wb --identity bob.json
lab b checkout wb --force >/dev/null
grep -q 'quietly' wb/ledger/evidence/EV-ECC-4d5e6f.yaml && fail "a forced checkout kept the edit"
ok "the edit is refused, and a forced checkout restores the record"
printf 'id: EV-ECC-7a8b9c\nby: alice\n' >wa/ledger/evidence/EV-ECC-7a8b9c.yaml
printf 'id: EV-ECC-7a8b9c\nby: bob\n' >wb/ledger/evidence/EV-ECC-7a8b9c.yaml
lab a commit wa --identity alice.json >/dev/null
lab b commit wb --identity bob.json >/dev/null
lab a sync --dir b >/dev/null
lab a conflicts | sed 's/^/  /'
[ "$(lab a conflicts --json | json 'd[0]["write_once"]')" = True ] || fail "collision not flagged"
ok "two different first writes of one id: both kept, flagged for a human"

rule "5. two agents claim one task at once"
lab a claim TASK-20261001-c0ffee --holder executor-1 --ttl 600 --identity alice.json >/dev/null
lab b claim TASK-20261001-c0ffee --holder executor-2 --ttl 600 --identity bob.json >/dev/null
lab a sync --dir b >/dev/null
HOLDER_A=$(lab a tasks --json | json 'd["TASK-20261001-c0ffee"]["holder"]["holder"]')
HOLDER_B=$(lab b tasks --json | json 'd["TASK-20261001-c0ffee"]["holder"]["holder"]')
[ "$HOLDER_A" = "$HOLDER_B" ] || fail "replicas disagree on the holder: $HOLDER_A vs $HOLDER_B"
lab a tasks | sed 's/^/  /'
ok "after one sync both replicas say $HOLDER_A holds it; the other claim reads contended"

rule "6. a message to a role, acknowledged on the other replica"
lab a send --to executor --from coordinator --subject "run EXP-ECC-0a1b2c" \
  --body "approved; params under experiments/EXP-ECC-0a1b2c" --ref TASK-20261001-c0ffee \
  --identity alice.json >/dev/null
lab b sync --dir a >/dev/null
lab b inbox executor | sed 's/^/  /'
MSG=$(lab b inbox executor --json | json 'd[0]["id"]')
lab b ack "$MSG" --as executor --identity bob.json >/dev/null
lab a sync --dir b >/dev/null
[ "$(lab a inbox executor --json | json 'len(d)')" = 0 ] || fail "the ack did not reach replica a"
ok "read and acknowledged by the executor role; replica a sees the ack"

rule "7. a revoked writer's concurrent write is excluded everywhere"
lab a revoke "$BOB" --identity alice.json >/dev/null
lab b put notes/after.md --text "written without seeing the revocation" --create \
  --identity bob.json >/dev/null
lab a sync --dir b >/dev/null
for r in a b; do
  lab $r ls notes | grep -q after.md && fail "replica $r still shows the revoked writer's op"
done
same_view a b
lab a verify | sed 's/^/  /'
ok "bob's op is excluded on both replicas; his earlier work stands"

rule "8. a bundle file and the network reproduce the space"
lab a bundle --out space.bundle | sed 's/^/  /'
lab c clone --space "$SPACE" --bundle space.bundle >/dev/null
same_view a c
ok "a replica cloned from one file agrees with a"
SERVER_ID=$("$RUST" lab peer-id --peer-identity server.peer.json)
CLIENT_ID=$("$RUST" lab peer-id --peer-identity client.peer.json)
"$RUST" lab peer-id --peer-identity stranger.peer.json >/dev/null
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
lab a serve --listen "127.0.0.1:$PORT" --peer-identity server.peer.json --allow "$CLIENT_ID" \
  >serve.log 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 100); do
  grep -q serving serve.log 2>/dev/null && break
  sleep 0.1
done
grep -q serving serve.log || fail "the server did not start: $(cat serve.log)"
lab d clone --space "$SPACE" --peer "$SERVER_ID@127.0.0.1:$PORT" --peer-identity client.peer.json >/dev/null
same_view a d
ok "a replica cloned over the McEliece+AEAD transport agrees with a"
if lab e clone --space "$SPACE" --peer "$SERVER_ID@127.0.0.1:$PORT" \
  --peer-identity stranger.peer.json >/dev/null 2>&1; then
  fail "a peer nobody listed was served"
fi
ok "a peer nobody listed gets nothing"
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=

rule "9. a run in an environment: receipt and outputs in one op"
# The smallest root filesystem that runs a shell script: /bin/sh and the
# libraries it links. Real environments come from examples/lab/environments/.
mkdir -p rootfs/bin
SH=$(readlink -f /bin/sh)
cp "$SH" rootfs/bin/sh
for lib in $(ldd "$SH" | grep -o '/[^ ]*'); do
  mkdir -p "rootfs$(dirname "$lib")"
  cp -L "$lib" "rootfs$lib"
done
lab a env import tiny --dir rootfs --identity alice.json | sed 's/^/  /'
lab a sandbox | sed 's/^/  /'
# Single quotes on purpose, here and below: the script expands inside the run.
# shellcheck disable=SC2016
SCRIPT='n=0; while read -r line; do n=$((n+1)); done < /work/params.txt; echo "lines=$n" > "$CAIRN_LAB_OUT/summary.txt"'
if lab a sandbox | grep -qE "^auto picks (runsc|bwrap)"; then
  lab a exec --env tiny --identity alice.json --task TASK-20261001-c0ffee \
    --input experiments/EXP-ECC-0a1b2c/params.txt:/work/params.txt \
    --publish runs/RUN-demo-1 --timeout 60 -- /bin/sh -c "$SCRIPT" | sed 's/^/  /'
  [ "$(lab a cat runs/RUN-demo-1/summary.txt)" = "lines=2" ] || fail "wrong output"
  BACKEND=$(lab a runs --json | json 'd[0]["receipt"]["backend"]')
  lab a env verify tiny | sed 's/^/  /'
  ok "ran under $BACKEND; the output and its receipt arrived as one op, and the tree is untouched"
else
  # No sandbox: the default refuses rather than running unconfined.
  expect_exit 3 lab a exec --env tiny --identity alice.json -- /bin/sh -c true
  ok "no sandbox on this host: exec refuses (exit 3, nothing learned)"
  # shellcheck disable=SC2016
  lab a exec --env tiny --identity alice.json --sandbox none --publish runs/RUN-demo-1 \
    --timeout 60 -- /bin/sh -c 'echo "unconfined" > "$CAIRN_LAB_OUT/summary.txt"' | sed 's/^/  /'
  [ "$(lab a cat runs/RUN-demo-1/summary.txt)" = "unconfined" ] || fail "wrong output"
  [ "$(lab a runs --json | json 'd[0]["receipt"]["backend"]')" = none ] || fail "receipt hides it"
  ok "an explicitly unconfined run publishes, and its receipt says backend none"
fi
lab b sync --dir a >/dev/null
lab b cat runs/RUN-demo-1/summary.txt >/dev/null || fail "the run's output did not reach b"
ok "the run reached replica b with its outputs"

rule "every replica verifies every signature and every blob"
for r in a b c d; do
  lab $r verify >/dev/null || fail "replica $r does not verify"
done
ok "a b c d"
echo
echo "lab demo: all checks passed"
