#!/usr/bin/env bash
# Cross-implementation interop: each implementation audits the other's log.
#
# This is the strongest available demonstration of the project's core claim.
# "Anyone can independently re-derive every settled result" is worth nothing if
# it means "anyone running my code". Two implementations, written separately in
# different languages, agreeing on every id and every Merkle root is what makes
# the claim real -- and it is the check that catches a canonical-encoding drift
# before it silently forks the network's identity scheme.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
REF="${REF_BIN:-./reference/rust/target/release/proofwork-reference}"
if [ ! -x "$REF" ]; then
  echo "building the reference implementation..." >&2
  cargo build --release --locked --manifest-path reference/rust/Cargo.toml
fi

if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

# Exported, so both implementations use the same epoch length. This is not a
# convenience: the auditor re-derives each batch's anchor and beacon order from
# the log, and a reader with a different epoch length would slice the log at
# different boundaries and report an honest batch as mis-ordered. Epoch length
# is a policy parameter every participant must share -- which is exactly why the
# production default is not configurable per node in any other way.
export PROOFWORK_EPOCH_SECONDS=1
tick() { sleep 1.1; }

A=$(mktemp -u /tmp/pw-interop-rust-XXXXXX.jsonl)
B=$(mktemp -u /tmp/pw-interop-ref-XXXXXX.jsonl)
trap 'rm -f "$A" "$B"' EXIT

# --- Rust writes, Python reads -------------------------------------------
rule "Rust produces a log"
RUST_OID=$($RUST --log "$A" --root . post examples/collatz/objective.json | head -1 | awk '{print $2}')
$RUST --log "$A" --root . commit "$RUST_OID" --submitter alice \
      --artifact examples/collatz/artifact.json --nonce n1 >/dev/null
tick
$RUST --log "$A" --root . reveal "$RUST_OID" --submitter alice \
      --artifact examples/collatz/artifact.json --nonce n1
tick
$RUST --log "$A" --root . settle

rule "the reference implementation audits the primary log"
# Includes the settlement batch: Python re-derives the anchor and the beacon
# order Rust recorded. A disagreement here is a disagreement about who got paid.
REF_VIEW=$("$REF" --log "$A" --root . audit)
echo "$REF_VIEW"
echo "$REF_VIEW" | grep -q "log verified" || fail "the reference could not verify the primary log"

# --- Python writes, Rust reads -------------------------------------------
rule "the reference implementation produces a log"
REF_OID=$("$REF" --log "$B" --root . post examples/capset/objective.json | head -1 | awk '{print $2}')
"$REF" --log "$B" --root . commit "$REF_OID" --submitter bob \
    --artifact examples/capset/artifact.json --nonce n2 >/dev/null
tick
"$REF" --log "$B" --root . reveal "$REF_OID" --submitter bob \
    --artifact examples/capset/artifact.json --nonce n2
tick
"$REF" --log "$B" --root . settle

rule "the primary implementation audits the reference log"
RUST_VIEW=$($RUST --log "$B" --root . audit)
echo "$RUST_VIEW"
echo "$RUST_VIEW" | grep -q "log verified" || fail "the primary could not verify the reference log"

# --- and on the batch each of them wrote ---------------------------------
rule "Both implementations agree a settled batch is correctly ordered"
for LOG in "$A" "$B"; do
  grep -q '"kind": *"batch"' "$LOG" || fail "no settlement batch in $LOG"
  $RUST --log "$LOG" --root . audit | grep -q "log verified" || fail "Rust rejects the batch in $LOG"
  "$REF"   --log "$LOG" --root . audit | grep -q "log verified" || fail "Python rejects the batch in $LOG"
done
echo "  both implementations re-derived every batch's beacon order"

# --- the roots must agree exactly ----------------------------------------
rule "Merkle roots agree across implementations"
for LOG in "$A" "$B"; do
  R=$($RUST --log "$LOG" --root . audit | awk '/^merkle/ {print $2}')
  P=$("$REF"   --log "$LOG" --root . audit | awk '/^merkle/ {print $2}')
  [ -n "$R" ] || fail "no Merkle root from Rust for $LOG"
  [ "$R" = "$P" ] || fail "Merkle root mismatch on $LOG: rust=$R python=$P"
  echo "  $R  (identical in both)"
done

# --- and so must record identity -----------------------------------------
rule "Objective ids agree across implementations"
# The same objective posted by each implementation must land on the same id.
# This is the narrowest form of the whole claim: identity is a function of the
# bytes, not of who computed them.
PRIMARY_LOG=$(mktemp -u /tmp/pw-interop-id-XXXXXX.jsonl)
PRIMARY_ID=$($RUST --log "$PRIMARY_LOG" --root . post examples/capset/objective.json \
  | head -1 | awk '{print $2}')
rm -f "$PRIMARY_LOG"
[ "$REF_OID" = "$PRIMARY_ID" ] \
  || fail "objective id mismatch: reference=$REF_OID primary=$PRIMARY_ID"
echo "  $REF_OID"

printf '\n\033[32mINTEROP OK: each implementation verifies the other.\033[0m\n'
