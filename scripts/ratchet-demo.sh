#!/usr/bin/env bash
# Progressive bounty: three participants advance the same objective, each paid
# for the distance they moved and each required to cite the frontier they beat.
#
# The point of this demo is that publishing an improvement is the profitable
# move. Nobody has to hoard, so nobody duplicates anybody else's work.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="${1:-/tmp/proofwork-ratchet.jsonl}"
rm -f "$LOG"
PW="${PROOFWORK_BIN:-./target/release/proofwork}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
pw() { "$PW" --log "$LOG" --root . "$@"; }
rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# `reveal` prints the full claim id on its first line, so capture it from the
# command that produced it rather than re-deriving it from the log.
reveal_capture() {
  local out
  out=$(pw reveal "$@")
  echo "$out"
  echo "$out" | awk '/^claim /{print $2}' > /tmp/pw-last-claim
}
last_claim() { cat /tmp/pw-last-claim; }

rule "fund a progressive objective: cap sets in F_3^4, baseline 9, target 20"
OID=$(pw post examples/capset_progressive/objective.json | head -1 | awk '{print $2}')

rule "alice finds a 12-point cap set"
pw commit "$OID" --submitter alice --artifact examples/capset_progressive/artifact-12.json --nonce a1 >/dev/null
reveal_capture "$OID" --submitter alice --artifact examples/capset_progressive/artifact-12.json --nonce a1
PREV=$(last_claim)

rule "eve resubmits alice's result verbatim -- verifies, earns nothing"
pw commit "$OID" --submitter eve --artifact examples/capset_progressive/artifact-12.json --nonce e1 >/dev/null
pw reveal "$OID" --submitter eve --artifact examples/capset_progressive/artifact-12.json --nonce e1 --cites "$PREV"

rule "bob improves to 16, citing alice"
pw commit "$OID" --submitter bob --artifact examples/capset_progressive/artifact-16.json --nonce b1 >/dev/null
reveal_capture "$OID" --submitter bob --artifact examples/capset_progressive/artifact-16.json --nonce b1 --cites "$PREV"
PREV=$(last_claim)

rule "carol reaches the target of 20, citing bob"
pw commit "$OID" --submitter carol --artifact examples/capset_progressive/artifact-20.json --nonce c1 >/dev/null
pw reveal "$OID" --submitter carol --artifact examples/capset_progressive/artifact-20.json --nonce c1 --cites "$PREV"

rule "audit: pool never overspent, frontier never moved backwards"
pw audit

rule "payouts: direct rewards plus citation flow to everyone upstream"
pw attribute
