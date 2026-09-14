#!/usr/bin/env bash
# Orbit piecework: paying for a search whose unit is an orbit, not a point.
#
# ECC2K-130's shape, on a 21-bit instance that finishes in a second. The walk
# is Pollard rho on a binary Koblitz curve with the <-1> x <sigma> speed-up,
# so the thing two trails share when they collide is an ORBIT of 2m points,
# and the thing a claim is paid for is therefore an orbit and not a point.
#
# Three rules get exercised here that the prime-field demo cannot reach:
#
#   1. an orbit is one unit however it is spelled, and the second answer to
#      one orbit is a collision -- which is why it mints nothing and why its
#      holder goes and claims the answer objective instead;
#   2. the eight-counter witness is what makes an orbit payable at all. A
#      canonical low-weight bit string is free to invent, so without the
#      witness the cheapest attack on this objective costs nothing;
#   3. the witness still does not prove the trail used the shared iteration
#      rule. That costs a re-walk, so it is sampled and bonded, and the demo
#      shows a private-rule batch passing the checker and failing the audit.
#
# docs/design/orbit-piecework.md is the design.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="${1:-/tmp/cairn-orbit.jsonl}"
rm -f "$LOG"
PW="${CAIRN_BIN:-./target/release/cairn}"
REF="${REF_BIN:-./reference/rust/target/release/cairn-reference}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
[ -x "$REF" ] || { echo "building the reference..." >&2; cargo build --release --manifest-path reference/rust/Cargo.toml; }
pw() { "$PW" --log "$LOG" --root . "$@"; }
rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

JOB=examples/certicom-ecdlp/jobs/ecc2k-23.json
ORBIT="python3 examples/certicom-ecdlp/tools/orbit_dp.py"
WORK=$(mktemp -d /tmp/pw-orbit-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# One-second epochs so commit, reveal and settlement fit in a script; they
# change no canonical bytes.
export CAIRN_EPOCH_SECONDS=1
tick() { sleep 1.1; }
settle_tick() { tick; local i; for ((i = 0; i < ${CAIRN_FINALITY_EPOCHS:-1}; i++)); do tick; done; }

step() {
  local who=$1 artifact=$2 nonce=$3
  pw commit "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" >/dev/null
  tick
  pw reveal "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" >/dev/null
  settle_tick
  pw settle
}

# The verdict is printed at reveal, not at settle: a rejected claim never
# reaches a batch, so `settle` has nothing to say about it.
reveal_verdict() {
  local who=$1 artifact=$2 nonce=$3
  pw commit "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce" >/dev/null
  tick
  pw reveal "$OID" --submitter "$who" --artifact "$artifact" --nonce "$nonce"
  settle_tick
  pw settle >/dev/null
}

rule "the job, and what it asks for"
$ORBIT validate "$JOB"
$ORBIT describe --job "$JOB"

rule "the coordinator posts the divided problem: 100 per novel orbit, pool 8000"
OID=$(pw post examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json | head -1 | awk '{print $2}')
WORK_OID=$OID
echo "objective $OID"

rule "four contributors each walk a unit of the shared walk into a batch of 8 orbits"
for i in 0 1 2 3; do
  $ORBIT walk --job "$JOB" --unit "$i" --count 8 --out "$WORK/batch-$i.json" 2>/dev/null
done
$ORBIT verify --job "$JOB" "$WORK"/batch-*.json

rule "alice's batch: eight novel orbits, eight unit prices"
step alice "$WORK/batch-0.json" a1 | tee "$WORK/alice.out"
grep -q "reward 800" "$WORK/alice.out" || fail "alice's eight novel orbits were not paid 8 x 100"
grep -q "8 novel unit(s) paid" "$WORK/alice.out" || fail "the note does not count the units"

rule "bob's, and carol's"
step bob "$WORK/batch-1.json" b1 | tee "$WORK/bob.out"
grep -q "reward 800" "$WORK/bob.out" || fail "bob's batch was not paid per orbit"
step carol "$WORK/batch-2.json" c1 | tee "$WORK/carol.out"
grep -q "reward 800" "$WORK/carol.out" || fail "carol's batch was not paid per orbit"

rule "eve resubmits alice's batch verbatim -- verifies, earns nothing"
step eve "$WORK/batch-0.json" e1 | tee "$WORK/eve.out"
grep -q "duplicate" "$WORK/eve.out" || fail "eve's copy was not refused as duplicate units"
grep -q "reward 800" "$WORK/eve.out" && fail "eve's copy was paid"

rule "mallory invents an orbit: a canonical low-weight string with a real witness"
python3 - "$WORK/batch-0.json" "$JOB" "$WORK/invented.json" <<'PY'
import json, sys
sys.path.insert(0, "examples/certicom-ecdlp/tools")
import orbit_dp as O
job = O.Job(O.load_job(sys.argv[2]))
batch = json.load(open(sys.argv[1]))
element = dict(batch["dps"][0])
# Any low-weight bit string, rotated to its least rotation, is a syntactically
# perfect orbit name. Nothing but the witness stands between that and a payout.
invented = O.least_rotation((1 << job.dp_max_weight) - 1, job.m)
while O.to_hex(invented) == element["x"]:
    invented = O.least_rotation(invented ^ 1, job.m)
element["x"] = O.to_hex(invented)
json.dump({"dps": [element]}, open(sys.argv[3], "w"), indent=2)
print("invented orbit", element["x"], "weight", bin(invented).count("1"))
PY
if $ORBIT verify --job "$JOB" "$WORK/invented.json"; then fail "the tool accepted an invented orbit"; fi
reveal_verdict mallory "$WORK/invented.json" m1 | tee "$WORK/invented.out"
grep -q "verdict  reject" "$WORK/invented.out" || fail "the checker did not reject an invented orbit"
grep -q "the witness does not reach this orbit" "$WORK/invented.out" \
  || fail "the rejection was not the witness refusing it"

rule "dave's batch contains an orbit bob already reached: seven paid, one duplicate -- that duplicate is the collision"
step dave "$WORK/batch-3.json" d1 | tee "$WORK/dave.out"
grep -q "reward 700" "$WORK/dave.out" || fail "dave was not paid for his seven novel orbits"
grep -q "1 duplicate(s) in the batch earned nothing" "$WORK/dave.out" \
  || fail "the orbit bob already held was paid twice"

rule "two trails, one orbit: dave computes k and claims the answer objective"
$ORBIT collide --job "$JOB" "$WORK/batch-1.json" "$WORK/batch-3.json" > "$WORK/k.json"
cat "$WORK/k.json"
python3 - "$WORK/k.json" "$JOB" "$WORK/answer.json" <<'PY'
import json, sys
sys.path.insert(0, "examples/certicom-ecdlp/tools")
import orbit_dp as O
job = O.Job(O.load_job(sys.argv[2]))
k = O.parse_hex(json.load(open(sys.argv[1]))["k"])
truth = O.parse_hex(json.load(open("examples/certicom-ecdlp/instances/ecc2k-23.json"))["k"])
assert k == truth, f"the collision gave {k}, the instance was minted with {truth}"
width = (job.n.bit_length() + 3) // 4
json.dump({"k": format(k, "0%dx" % width)}, open(sys.argv[3], "w"), indent=2)
PY
AOID=$(pw post examples/certicom-ecdlp/objective-ecc2k-23.json | head -1 | awk '{print $2}')
OID=$AOID
step dave "$WORK/answer.json" d2 | tee "$WORK/answer.out"
grep -q "reward 5000" "$WORK/answer.out" || fail "the recovered logarithm was not paid"
OID=$WORK_OID

rule "the other half: a witness that checks out from a walk nobody else runs"
python3 - "$JOB" "$WORK/private.json" <<'PY'
import json, sys
sys.path.insert(0, "examples/certicom-ecdlp/tools")
import orbit_dp as O
job = O.Job(O.load_job(sys.argv[1]))
# sigma^3 at every step instead of the weight-derived branch: the same cost to
# walk, a witness that verifies, and a trail that merges with nobody.
for unit in range(100, job.units):
    seed = job.seed_of(unit)
    R, degenerate = job.start(seed)
    if degenerate:
        continue
    counts = [0] * job.j_count
    for _ in range(job.step_cap):
        if job.basis.weight(R[0]) <= job.dp_max_weight:
            element = job.element(O.least_rotation(job.basis.to_nb(R[0]), job.m), seed, counts)
            assert O.verify_element(job, element) is None, "the witness should verify"
            assert O.audit_element(job, element) is not None, "the audit should catch it"
            json.dump({"dps": [element]}, open(sys.argv[2], "w"), indent=2)
            print("private-rule orbit", element["x"], "after", sum(counts), "steps")
            sys.exit(0)
        R = job.curve.add(R, job.curve.frob(R, job.j_base))
        if R is None:
            break
        counts[0] += 1
raise SystemExit("no private-rule trail reached a distinguished point")
PY
$ORBIT verify --job "$JOB" "$WORK/private.json" || fail "the witness on a private-rule trail should verify"
step trent "$WORK/private.json" t1 | tee "$WORK/private.out"
grep -q "reward 100" "$WORK/private.out" || fail "the private-rule orbit was not paid: the checker cannot see the rule"

rule "an auditor re-walks the paid batches; only the private-rule trail fails"
audit_status=0
$ORBIT audit --job "$JOB" --log "$LOG" --objective "$WORK_OID" --elements all \
    --rate 1 --docket "$WORK/docket.json" | tee "$WORK/audit-tool.out" || audit_status=$?
[ "$audit_status" -eq 1 ] \
    || fail "the re-walk audit exited $audit_status; want 1, the code that says it found a mismatch"
grep -q "^FAIL .* trent:" "$WORK/audit-tool.out" || fail "the audit did not catch the private-rule trail"
for who in alice bob carol dave; do
  if grep -q "^FAIL .* $who:" "$WORK/audit-tool.out"; then
    fail "an honest batch was reported as a mismatch"
  fi
done
grep -q "1 mismatch(es)" "$WORK/audit-tool.out" || fail "the audit found more or fewer than the one bad trail"
python3 -c 'import json,sys; sys.exit(0 if len(json.load(open(sys.argv[1]))["entries"]) == 1 else 1)' \
    "$WORK/docket.json" || fail "the docket does not carry the mismatch attest slash needs"

rule "audit: every orbit re-verified, no orbit paid twice, pool never overspent"
pw audit | tee "$WORK/audit.out"
grep -q "log verified" "$WORK/audit.out" || fail "the primary does not verify its own log"

rule "the reference implementation re-derives the same payments from the same log"
"$REF" --log "$LOG" --root . audit | tee "$WORK/ref.out"
grep -q "log verified" "$WORK/ref.out" || fail "the reference rejects the log"

printf '\n\033[32mORBIT OK: orbits paid once each, an invented orbit refused, a collision solved and paid, a private-rule trail paid and then caught, both implementations agree.\033[0m\n'
