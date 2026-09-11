#!/usr/bin/env bash
# Piecework: a coordinator divides a problem, peers are paid per verified unit.
#
# The problem is the shared Pollard rho search for the 50-bit nums instance.
# The coordinator posts one objective whose checker pins the walk everyone
# runs; a contributor walks a unit of it to a distinguished point and submits
# the point. Every novel accepted point pays unit_price from the pool, a point
# already paid mints nothing, and the pool -- not a single answer -- is what
# closes the objective. Then the same at scale: a batch objective, one claim
# per unit of 16 points, paid per novel point, with the walker index and step
# count per point that an auditor re-walks. The Python walker here is the
# contributor with no Rust toolchain; `crypto cryptanalysis rho-collab work`
# runs the same walk.
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

rule "at scale, a claim is a batch: the coordinator posts the batch objective (100 per novel point, up to 64 per claim)"
BOID=$(pw post examples/certicom-ecdlp/objective-nums-50-rho-batch.json | head -1 | awk '{print $2}')
echo "objective $BOID"

rule "dave walks a whole unit (16 walkers) into one batch, with the walker index and step count per point"
$WALK walk --job $JOB --unit 1 --batch --out "$WORK/batch-1.json" --quiet
$WALK verify --job $JOB "$WORK/batch-1.json"
N=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['dps']))" "$WORK/batch-1.json")
echo "  $N points in the batch"
OID_SINGLE=$OID; OID=$BOID
step dave "$WORK/batch-1.json" d1 | tee "$WORK/dave.out"
grep -q "reward $((N * 100))" "$WORK/dave.out" || fail "dave's batch was not paid per point"
grep -q "$N novel unit(s) paid" "$WORK/dave.out" || fail "the note does not count the units"

rule "mallory re-lists two of dave's points under other walker indices plus one new point -- paid for the one"
python3 - "$WORK/batch-1.json" "$JOB" "$WORK/batch-mallory.json" <<'PY'
import json, sys
sys.path.insert(0, "examples/certicom-ecdlp/tools")
import rho_dp
batch = json.load(open(sys.argv[1]))
ctx = rho_dp.Context(rho_dp.load_job(sys.argv[2]))
# A fresh point from a walker outside dave's unit.
i = 2 * ctx.unit_size
rec = ctx.run_walker(i)
while rec is None:
    i += 1
    rec = ctx.run_walker(i)
steps, x, y, a, b = rec
relabelled = [dict(batch["dps"][0], walker=900), dict(batch["dps"][1], walker=901)]
json.dump({"dps": relabelled + [ctx.batch_element(i, steps, x, y, a, b)]}, open(sys.argv[3], "w"), indent=2)
PY
step mallory "$WORK/batch-mallory.json" m1 | tee "$WORK/mallory.out"
grep -q "reward 100" "$WORK/mallory.out" || fail "mallory's one novel point was not paid"
grep -q "2 duplicate(s) in the batch earned nothing" "$WORK/mallory.out" || fail "the relabelled points were paid"
OID=$OID_SINGLE

rule "an auditor re-walks the paid batches from their walker indices"
# `--elements all`, and the exit status captured rather than left to `set -e`.
#
# This step asserted "0 mismatch(es)" while re-walking one element per claim.
# But mallory's batch is in the log by now and is *supposed* to contain two
# points that do not re-walk, so that assertion could only hold when the auditor
# happened not to draw one -- one run in three, her batch being two forged
# points and one real one. The demo therefore passed only when the fraud went
# undetected, and went red the rest of the time (the `rust` job on 80768ea,
# among others). The sampling is not the bug: drawing one element the submitter
# cannot predict is the mechanism, and it stays the default. What was wrong was
# asserting a clean audit of a log built to be dirty.
#
# So: re-walk every element, and assert what the mechanism actually promises --
# dave's honest batch survives intact, both of mallory's relabelled points are
# caught, and the docket carries exactly those two for `cairn attest slash`.
audit_status=0
$WALK audit --job $JOB --log "$LOG" --objective "$BOID" --elements all \
    --docket "$WORK/docket.json" | tee "$WORK/audit-tool.out" || audit_status=$?
[ "$audit_status" -eq 1 ] \
    || fail "the re-walk audit exited $audit_status; want 1, the code that says it found a mismatch"
if grep -q "^FAIL .* dave:" "$WORK/audit-tool.out"; then
    fail "an honest batch was reported as a mismatch"
fi
grep -q "2 mismatch(es)" "$WORK/audit-tool.out" \
    || fail "the re-walk audit did not catch both of the relabelled points"
python3 -c 'import json,sys; sys.exit(0 if len(json.load(open(sys.argv[1]))["entries"]) == 2 else 1)' \
    "$WORK/docket.json" || fail "the docket does not carry the two mismatches attest slash needs"

rule "audit: every point re-verified, no unit paid twice (alone or in a batch), pool never overspent"
pw audit | tee "$WORK/audit.out"
grep -q "log verified" "$WORK/audit.out" || fail "the primary does not verify its own log"

rule "the reference implementation re-derives the same payments from the same log"
"$REF" --log "$LOG" --root . audit | tee "$WORK/ref.out"
grep -q "log verified" "$WORK/ref.out" || fail "the reference rejects the log"

printf '\n\033[32mPIECEWORK OK: three units paid once each, the copy paid nothing, a batch paid per novel point, both implementations agree.\033[0m\n'
