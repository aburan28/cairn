#!/usr/bin/env bash
# End-to-end walkthrough: fund two objectives, solve both, audit, attribute.
#
#   ./scripts/demo.sh
#
# Everything here is re-runnable by anyone with a copy of the log. That is the
# whole point of Stage 0 -- one operator, no consensus, no trust required.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="${1:-/tmp/proofwork-demo.jsonl}"
rm -f "$LOG"
PW="${PROOFWORK_BIN:-./target/release/proofwork}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
pw() { "$PW" --log "$LOG" --root . "$@"; }

# A reveal must land in a strictly later epoch than its commitment, and a batch
# pays only once its epoch is over -- so a demo with the production epoch length
# would take twenty minutes to show one payout. One-second epochs let the same
# rules play out in a script that finishes. The override changes no canonical
# bytes: nothing derived from it enters a record.
export PROOFWORK_EPOCH_SECONDS=1
tick() { sleep 1.1; }

# Two waits, not one: an epoch must close *and* wait out the finality delay
# (PROOFWORK_FINALITY_EPOCHS, default 1) before anything settles.
settle_tick() { tick; local i; for ((i = 0; i < ${PROOFWORK_FINALITY_EPOCHS:-1}; i++)); do tick; done; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

rule "fund an objective (certificate: a long Collatz trajectory)"
COLLATZ=$(pw post examples/collatz/objective.json | head -1 | awk '{print $2}')

rule "commit, then reveal an epoch later -- alice"
pw commit "$COLLATZ" --submitter alice --artifact examples/collatz/artifact.json --nonce n-alice
tick
REVEAL=$(pw reveal "$COLLATZ" --submitter alice --artifact examples/collatz/artifact.json --nonce n-alice)
echo "$REVEAL"
# `reveal` prints the full claim id, which is what --cites needs. No second
# implementation in the loop just to read back an id we were already told.
FIRST_CLAIM=$(echo "$REVEAL" | awk '/^claim /{print $2}')

rule "close the epoch: the batch settles in beacon order, not arrival order"
settle_tick
pw settle

rule "fund a second objective (evaluator: a maximal cap set in F_3^4)"
CAPSET=$(pw post examples/capset/objective.json | head -1 | awk '{print $2}')

rule "bob solves it, citing alice's claim"
pw commit "$CAPSET" --submitter bob --artifact examples/capset/artifact.json --nonce n-bob
tick
pw reveal "$CAPSET" --submitter bob --artifact examples/capset/artifact.json --nonce n-bob \
    --cites "$FIRST_CLAIM"
settle_tick
pw settle

rule "a wrong answer is rejected, and settles nothing"
echo '{"n": 27}' > /tmp/pw-bogus.json
pw commit "$COLLATZ" --submitter mallory --artifact /tmp/pw-bogus.json --nonce n-m 2>/dev/null \
  || echo "(objective already settled -- commitments are closed)"

rule "the log"
pw log

rule "audit: re-derive every settled claim from scratch"
pw audit

rule "attribution: citation flow pays bob and, upstream, alice"
pw attribute
