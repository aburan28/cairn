#!/usr/bin/env bash
# Piecework: a coordinator divides a problem, peers are paid per verified unit.
#
# The problem is the shared Pollard rho search for the 50-bit nums instance.
# The coordinator posts one objective whose checker pins the walk everyone
# runs; a contributor walks a unit of it to a distinguished point and submits
# the point. Every novel accepted point pays unit_price from the pool, a point
# already paid mints nothing, and the pool -- not a single answer -- is what
# closes the objective. The Python walker here is the contributor with no
# Rust toolchain; `crypto cryptanalysis rho-collab work` runs the same walk.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="${1:-/tmp/cairn-piecework.jsonl}"
rm -f "$LOG"
PW="${CAIRN_BIN:-./target/release/cairn}"
REF="${REF_BIN:-./reference/rust/target/release/cairn-reference}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
[ -x "$REF" ] || { echo "building the reference..." >&2; cargo build --release --manifest-path reference/rust/Cargo.toml; }
pw() { "$PW" --log "$LOG" --root . "$@"; }
rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

JOB=examples/certicom-ecdlp/jobs/nums-50-rho.json
WALK="python3 examples/certicom-ecdlp/tools/rho_dp.py"
WORK=$(mktemp -d /tmp/pw-piecework-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# One-second epochs so commit, reveal and settlement fit in a script; they
# change no canonical bytes.
export CAIRN_EPOCH_SECONDS=1
tick() { sleep 1.1; }
settle_tick() { tick; local i; for ((i = 0; i < ${CAIRN_FINALITY_EPOCHS:-1}; i++)); do tick; done; }

# Commit, wait an epoch, reveal, wait another, settle; echo the settle output
# so the caller can read what the unit earned.
step() {
  local who=$1 artifact=$2 nonce=$3
  pw commit "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" >/dev/null
  tick
  pw reveal "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce"
  settle_tick
  pw settle
}

rule "the coordinator posts the divided problem: 100 per distinguished point, pool 80000"
OID=$(pw post examples/certicom-ecdlp/objective-nums-50-rho.json | head -1 | awk '{print $2}')
echo "objective $OID"
echo "job id    $($WALK job-id --job $JOB)"

rule "three contributors each walk one unit of the shared walk (about 2^16 steps)"
for i in 0 1 2; do
  $WALK walk --job $JOB --walker $i --out "$WORK/dp-$i.json"
done
$WALK verify --job $JOB "$WORK"/dp-*.json

rule "alice submits her point"
step alice "$WORK/dp-0.json" a1 | tee "$WORK/alice.out"
grep -q "reward 100" "$WORK/alice.out" || fail "alice's novel point was not paid the unit price"

rule "bob submits his -- a second unit, a second payment"
step bob "$WORK/dp-1.json" b1 | tee "$WORK/bob.out"
grep -q "reward 100" "$WORK/bob.out" || fail "bob's novel point was not paid the unit price"

rule "eve resubmits alice's point verbatim -- verifies, earns nothing"
step eve "$WORK/dp-0.json" e1 | tee "$WORK/eve.out"
grep -q "duplicate unit" "$WORK/eve.out" || fail "eve's copy was not refused as a duplicate unit"
grep -q "reward 100" "$WORK/eve.out" && fail "eve's copy was paid"

rule "carol submits the third point; the objective stays open -- the pool is what closes it"
step carol "$WORK/dp-2.json" c1 | tee "$WORK/carol.out"
grep -q "reward 100" "$WORK/carol.out" || fail "carol's novel point was not paid the unit price"

rule "the log: three settlements of 100, and the pool has 79700 left"
PAID=$(grep -c '"kind":"settlement"' "$LOG" || true)
[ "$PAID" = 3 ] || fail "expected 3 settlements, found $PAID"

rule "audit: every point re-verified, no unit paid twice, pool never overspent"
pw audit | tee "$WORK/audit.out"
grep -q "log verified" "$WORK/audit.out" || fail "the primary does not verify its own log"

rule "the reference implementation re-derives the same payments from the same log"
"$REF" --log "$LOG" --root . audit | tee "$WORK/ref.out"
grep -q "log verified" "$WORK/ref.out" || fail "the reference rejects the log"

printf '\n\033[32mPIECEWORK OK: three units paid once each, the copy paid nothing, both implementations agree.\033[0m\n'
