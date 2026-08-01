#!/usr/bin/env bash
# ecdsa.fail-shaped MVP: fund a minimize ratchet, self-check, commit–reveal, settle.
#
#   ./examples/ecdsa-fail/demo.sh [/tmp/proofwork-ecdsa-fail.jsonl]
#
# Does not call the ecdsa.fail API. For the real launch benchmark use
# `ecdsafail` (see adapter.sh and GAP.md).
set -euo pipefail
cd "$(dirname "$0")/../.."

LOG="${1:-/tmp/proofwork-ecdsa-fail.jsonl}"
rm -f "$LOG"
PW="${PROOFWORK_BIN:-./target/release/proofwork}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
pw() { "$PW" --log "$LOG" --root . "$@"; }

export PROOFWORK_EPOCH_SECONDS=1
tick() { sleep 1.1; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

step() {
  local who=$1 artifact=$2 nonce=$3; shift 3
  pw commit "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" >/dev/null
  tick
  local out
  out=$(pw reveal "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" "$@")
  echo "$out"
  echo "$out" | awk '/^claim /{print $2}' > /tmp/pw-ecdsa-last-claim
  tick
  pw settle
}
last_claim() { cat /tmp/pw-ecdsa-last-claim; }

rule "fund ecdsa.fail-shaped progressive objective (minimize qubit×toffoli)"
OID=$(pw post examples/ecdsa-fail/objective.json | head -1 | awk '{print $2}')
echo "objective $OID"

rule "lying score field is rejected (product identity)"
pw commit "$OID" --submitter mallory --artifact examples/ecdsa-fail/artifacts/bogus.json --nonce n-bogus
tick
BOGUS_OUT=$(pw reveal "$OID" --submitter mallory --artifact examples/ecdsa-fail/artifacts/bogus.json --nonce n-bogus)
echo "$BOGUS_OUT"
# Reject is a real verdict and exits 0; unavailable would be code 3 and must
# not be treated as "circuit wrong".
echo "$BOGUS_OUT" | grep -q 'reject:' || {
  echo "expected reject for bogus score, got: $BOGUS_OUT" >&2
  exit 1
}
tick
pw settle

rule "alice opens the frontier at 90000 (baseline is 100000; exact baseline pays zero)"
step alice examples/ecdsa-fail/artifacts/open.json a1
PREV=$(last_claim)

rule "bob improves to 56000, citing alice"
step bob examples/ecdsa-fail/artifacts/mid.json b1 --cites "$PREV"
PREV=$(last_claim)

rule "carol improves to 20000, citing bob"
step carol examples/ecdsa-fail/artifacts/best.json c1 --cites "$PREV"

rule "audit"
pw audit

rule "attribution"
pw attribute

echo
echo "Demo log: $LOG"
echo "Real ecdsa.fail submit still needs: ecdsafail clone && ecdsafail run && ecdsafail submit"
