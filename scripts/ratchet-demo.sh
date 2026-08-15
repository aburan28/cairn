#!/usr/bin/env bash
# Progressive bounty: three participants advance the same objective, each paid
# for the distance they moved and each required to cite the frontier they beat.
#
# The point of this demo is that publishing an improvement is the profitable
# move. Nobody has to hoard, so nobody duplicates anybody else's work.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="${1:-/tmp/cairn-ratchet.jsonl}"
rm -f "$LOG"
PW="${CAIRN_BIN:-./target/release/cairn}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
pw() { "$PW" --log "$LOG" --root . "$@"; }
rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# A reveal must land in a strictly later epoch than its commitment, and a batch
# pays only once its epoch is over. One-second epochs let the same rules play
# out in a script that finishes; they change no canonical bytes.
export CAIRN_EPOCH_SECONDS=1
tick() { sleep 1.1; }

# Two waits, not one: an epoch must close *and* wait out the finality delay
# (CAIRN_FINALITY_EPOCHS, default 1) before anything settles.
settle_tick() { tick; local i; for ((i = 0; i < ${CAIRN_FINALITY_EPOCHS:-1}; i++)); do tick; done; }

# Commit, wait an epoch, reveal, wait another, settle. `reveal` prints the full
# claim id on its first line, so capture it from the command that produced it
# rather than re-deriving it from the log.
step() {
  local who=$1 artifact=$2 nonce=$3; shift 3
  pw commit "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" >/dev/null
  tick
  local out
  out=$(pw reveal "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" "$@")
  echo "$out"
  echo "$out" | awk '/^claim /{print $2}' > /tmp/pw-last-claim
  settle_tick
  pw settle
}
last_claim() { cat /tmp/pw-last-claim; }

rule "fund a progressive objective: cap sets in F_3^4, baseline 9, target 20"
OID=$(pw post examples/capset_progressive/objective.json | head -1 | awk '{print $2}')

rule "alice finds a 12-point cap set"
step alice examples/capset_progressive/artifact-12.json a1
PREV=$(last_claim)

rule "eve resubmits alice's result verbatim -- verifies, earns nothing"
step eve examples/capset_progressive/artifact-12.json e1 --cites "$PREV"

rule "bob improves to 16, citing alice"
step bob examples/capset_progressive/artifact-16.json b1 --cites "$PREV"
PREV=$(last_claim)

rule "carol reaches the target of 20, citing bob"
step carol examples/capset_progressive/artifact-20.json c1 --cites "$PREV"

rule "audit: pool never overspent, frontier never moved backwards"
pw audit

rule "payouts: direct rewards plus citation flow to everyone upstream"
pw attribute
