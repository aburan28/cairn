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

# Likewise exported rather than left to the default, and for the same reason:
# both implementations must agree on when an epoch becomes eligible, not just
# on how long one is.
export PROOFWORK_FINALITY_EPOCHS=1

tick() { sleep 1.1; }

# A reveal's epoch has to *close* and then wait out the finality delay before
# anything settles, so a drain needs `FINALITY_EPOCHS + 1` boundaries behind
# it, not one.
#
# This is derived from the exported value rather than written as `tick; tick`.
# The first version of this fix hard-coded two sleeps, which is correct today
# and silently wrong the day the delay changes -- and the symptom would be
# `no settlement batch`, a message that points at the log rather than at the
# clock. That symptom is exactly how this surfaced: the script passed locally
# on a slower machine, where enough wall-clock elapsed between reveal and
# settle by accident, and failed on CI. It was timing-dependent before the
# delay existed; the delay only made the window wide enough to notice.
settle_tick() {
  local i
  for ((i = 0; i <= PROOFWORK_FINALITY_EPOCHS; i++)); do tick; done
}

# Suffix appended after the call, not inside the template: BSD mktemp (macOS)
# only expands `XXXXXX` at the very end, so `-XXXXXX.jsonl` comes back literal
# and `-u` still calls mkstemp -- the first run creates a real file with X's in
# its name and every run after it dies on "File exists". GNU mktemp expands it,
# which is why CI never sees this and a second local run does.
A="$(mktemp -u /tmp/pw-interop-rust-XXXXXX).jsonl"
B="$(mktemp -u /tmp/pw-interop-ref-XXXXXX).jsonl"
C="$(mktemp -u /tmp/pw-interop-min-XXXXXX).jsonl"
D="$(mktemp -u /tmp/pw-interop-lean-XXXXXX).jsonl"
E="$(mktemp -u /tmp/pw-interop-lean2-XXXXXX).jsonl"
F="$(mktemp -u /tmp/pw-interop-rel1-XXXXXX).jsonl"
G="$(mktemp -u /tmp/pw-interop-rel2-XXXXXX).jsonl"
trap 'rm -f "$A" "$B" "$C" "$D" "$E" "$F" "$G"' EXIT

# --- the primary writes, the reference reads ------------------------------
rule "Rust produces a log"
RUST_OID=$($RUST --log "$A" --root . post examples/collatz/objective.json | head -1 | awk '{print $2}')
$RUST --log "$A" --root . commit "$RUST_OID" --submitter alice \
      --artifact examples/collatz/artifact.json --nonce n1 >/dev/null
tick
$RUST --log "$A" --root . reveal "$RUST_OID" --submitter alice \
      --artifact examples/collatz/artifact.json --nonce n1
settle_tick
$RUST --log "$A" --root . settle

rule "the reference implementation audits the primary log"
# Includes the settlement batch: the reference re-derives the anchor and the beacon
# order Rust recorded. A disagreement here is a disagreement about who got paid.
REF_VIEW=$("$REF" --log "$A" --root . audit)
echo "$REF_VIEW"
echo "$REF_VIEW" | grep -q "log verified" || fail "the reference could not verify the primary log"

# --- the reference writes, the primary reads ------------------------------
rule "the reference implementation produces a log"
REF_OID=$("$REF" --log "$B" --root . post examples/capset/objective.json | head -1 | awk '{print $2}')
"$REF" --log "$B" --root . commit "$REF_OID" --submitter bob \
    --artifact examples/capset/artifact.json --nonce n2 >/dev/null
tick
"$REF" --log "$B" --root . reveal "$REF_OID" --submitter bob \
    --artifact examples/capset/artifact.json --nonce n2
settle_tick
"$REF" --log "$B" --root . settle

# --- a minimize objective, which neither had ever run against the other ----
#
# The first two rounds cover `certificate` and an `evaluator` that maximizes.
# `direction` decides who clears a threshold and therefore who gets paid, and
# until now the *minimize* branch of `Direction::clears` had never executed in
# the reference at all: the ratchet vectors pin the arithmetic, but nothing
# drove a real minimize objective end to end through both implementations.
# `statistical` is likewise a verifier kind neither had run for the other.
rule "a minimize objective, verified by the implementation that did not post it"
MIN_OID=$($RUST --log "$C" --root . post examples/permutation/objective.json | head -1 | awk '{print $2}')
$RUST --log "$C" --root . commit "$MIN_OID" --submitter carol \
      --artifact examples/permutation/artifact.json --nonce n3 >/dev/null
tick
$RUST --log "$C" --root . reveal "$MIN_OID" --submitter carol \
      --artifact examples/permutation/artifact.json --nonce n3
settle_tick
$RUST --log "$C" --root . settle

MIN_VIEW=$("$REF" --log "$C" --root . audit)
echo "$MIN_VIEW"
echo "$MIN_VIEW" | grep -q "log verified" \
  || fail "the reference could not verify a minimize objective the primary settled"

# --- a lean rejection, which needs no Lean toolchain to reproduce ----------
#
# `lean` was the last kind the reference implementation did not implement, and
# a kind an implementation lacks answers `Unavailable` for every claim -- which
# is correct, settles nothing, and used to be skipped by the audit in silence.
# So the kind with the least coverage was the one whose absence was hardest to
# notice.
#
# This round closes it without either side needing a proof assistant. A proof
# containing `sorry` is screened *before* the toolchain is ever looked for, so
# both implementations must record and re-derive the same `reject` on any host.
# It is a real cross-implementation check on the kind, not a stand-in: remove
# the `lean` arm from either dispatcher and this fails.
#
# Nothing settles, deliberately. A rejection pays nobody, and an audit that
# only re-checks what was *paid* would let a rejection nobody else can
# reproduce pass in silence -- the same hole one rung down. Both audits now
# report any settled verdict they cannot re-derive, paid or not, which is what
# gives this round its teeth.
rule "a lean rejection: reproduced by the implementation that did not record it"
for pair in "$RUST|$REF|the reference|$D" "$REF|$RUST|the primary|$E"; do
  IFS='|' read -r WRITER READER WHO LOG <<< "$pair"
  LEAN_OID=$("$WRITER" --log "$LOG" --root . post examples/lean/objective.json \
    | head -1 | awk '{print $2}')
  "$WRITER" --log "$LOG" --root . commit "$LEAN_OID" --submitter mallory \
      --artifact examples/lean/hole.json --nonce n4 >/dev/null
  tick
  VERDICT=$("$WRITER" --log "$LOG" --root . reveal "$LEAN_OID" --submitter mallory \
      --artifact examples/lean/hole.json --nonce n4)
  echo "$VERDICT" | grep -q "reject" \
    || fail "a proof containing \`sorry\` was not rejected: $VERDICT"
  LEAN_VIEW=$("$READER" --log "$LOG" --root . audit)
  echo "$LEAN_VIEW"
  echo "$LEAN_VIEW" | grep -q "log verified" \
    || fail "$WHO could not re-derive a lean rejection"
done

# --- a claim carrying typed relations, written by each and read by the other -
#
# `relations` is omitted from the canonical form when empty, so every round
# above exercises only its absence -- and a field that is always absent is a
# field whose encoding nobody has checked. This round writes one in each
# implementation and has the other re-derive the log, which is the only way a
# disagreement about relation bytes shows up before it forks a claim id.
#
# The relation targets a *rejected* claim on purpose. It is the case the two
# implementations could most easily differ on: citations must name accepted
# claims and relations need only name existing ones, so an implementation that
# reused the citation rule here would refuse a record the other admits -- and
# both would audit clean while disagreeing about what is in the log.
rule "typed claim relations survive a round trip through both implementations"
# `n = 1` reaches 1 in no steps at all, so the pinned checker rejects it. Written
# here rather than added to `examples/`, which holds artifacts that are meant to
# *pass*; a decoy shipped alongside them would eventually be mistaken for one.
DECOY="$(mktemp -u /tmp/pw-interop-decoy-XXXXXX).json"
printf '{"n": 1}\n' > "$DECOY"
trap 'rm -f "$A" "$B" "$C" "$D" "$E" "$F" "$G" "$DECOY"' EXIT

for pair in "$RUST|$REF|the reference|$F" "$REF|$RUST|the primary|$G"; do
  IFS='|' read -r WRITER READER WHO LOG <<< "$pair"
  REL_OID=$("$WRITER" --log "$LOG" --root . post examples/collatz/objective.json \
    | head -1 | awk '{print $2}')

  # A claim the pinned checker throws out, so the bounty stays open and there
  # is a rejected claim to speak about.
  "$WRITER" --log "$LOG" --root . commit "$REL_OID" --submitter alice \
      --artifact "$DECOY" --nonce r1 >/dev/null
  tick
  WRONG=$("$WRITER" --log "$LOG" --root . reveal "$REL_OID" --submitter alice \
      --artifact "$DECOY" --nonce r1)
  echo "$WRONG" | grep -q "reject" || fail "the decoy artifact was not rejected: $WRONG"
  WRONG_ID=$(echo "$WRONG" | head -1 | awk '{print $2}')

  "$WRITER" --log "$LOG" --root . commit "$REL_OID" --submitter bob \
      --artifact examples/collatz/artifact.json --nonce r2 >/dev/null
  tick
  "$WRITER" --log "$LOG" --root . reveal "$REL_OID" --submitter bob \
      --artifact examples/collatz/artifact.json --nonce r2 \
      --relates "refutes:$WRONG_ID" >/dev/null
  settle_tick
  "$WRITER" --log "$LOG" --root . settle >/dev/null

  grep -q '"relations"' "$LOG" || fail "$WHO's peer wrote no relations field"
  REL_VIEW=$("$READER" --log "$LOG" --root . audit)
  echo "$REL_VIEW"
  echo "$REL_VIEW" | grep -q "log verified" \
    || fail "$WHO could not re-derive a log containing typed relations"
done

rule "the primary implementation audits the reference log"
RUST_VIEW=$($RUST --log "$B" --root . audit)
echo "$RUST_VIEW"
echo "$RUST_VIEW" | grep -q "log verified" || fail "the primary could not verify the reference log"

# --- and on the batch each of them wrote ---------------------------------
rule "Both implementations agree a settled batch is correctly ordered"
for LOG in "$A" "$B"; do
  grep -q '"kind": *"batch"' "$LOG" || fail "no settlement batch in $LOG"
  $RUST --log "$LOG" --root . audit | grep -q "log verified" || fail "Rust rejects the batch in $LOG"
  "$REF"   --log "$LOG" --root . audit | grep -q "log verified" || fail "the reference rejects the batch in $LOG"
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
PRIMARY_LOG="$(mktemp -u /tmp/pw-interop-id-XXXXXX).jsonl"
PRIMARY_ID=$($RUST --log "$PRIMARY_LOG" --root . post examples/capset/objective.json \
  | head -1 | awk '{print $2}')
rm -f "$PRIMARY_LOG"
[ "$REF_OID" = "$PRIMARY_ID" ] \
  || fail "objective id mismatch: reference=$REF_OID primary=$PRIMARY_ID"
echo "  $REF_OID"

printf '\n\033[32mINTEROP OK: each implementation verifies the other.\033[0m\n'
