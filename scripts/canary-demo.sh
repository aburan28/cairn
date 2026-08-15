#!/usr/bin/env bash
# The canary trap, end to end against a real clock and a real verifier.
#
#   ./scripts/canary-demo.sh
#
# `tests/canary_trap.rs` closes the trap around a `Node` through the library.
# This closes it around the *binary*, which is the surface an operator actually
# has, and it does the one thing a unit test structurally cannot: it runs the
# whole thing across real epoch boundaries with the pinned Python checker
# spawning for real.
#
# What this proves that the unit tests cannot:
#
#   1. `canary mint` finds both sides against a real objective in the repo,
#      using nothing but that objective's own pinned verifier. Nothing in the
#      generator knows what a cap set is.
#   2. The canaries survive the trip through `try` -- commitment, epoch wait,
#      reveal -- and the node writes ordinary verdicts about them, because
#      nothing marks them as special.
#   3. `canary check` is clean against an honest log and names the liar against
#      a forged one, running no verifier either time.
#   4. `audit --no-rerun` cannot see the lie. That is the whole reason canaries
#      are worth building: the cheap audit passes a rubber-stamper, the
#      expensive one catches it, and a canary check catches it for the price of
#      the cheap one.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PW="${PROOFWORK_BIN:-./target/release/proofwork}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
LOG="$WORK/log.jsonl"
pw() { "$PW" --log "$LOG" --root . "$@"; }

# One-second epochs, so the same rules play out in a script that finishes.
# Changes no canonical bytes: nothing derived from this enters a record.
export PROOFWORK_EPOCH_SECONDS=1

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null || { echo "python3 required for the pinned checker" >&2; exit 0; }

rule "an objective with a real pinned evaluator"
# Cap sets, not Collatz. A collatz artifact is a single integer, so a
# known-*good* canary does not exist in one edit -- every edit to a lone number
# is a different answer. Known-good canaries are cheap exactly when an artifact
# holds an unordered collection, because reordering a set is the reliable
# validity-preserving edit, and half the trap needs one.
pw post examples/capset/objective.json >/dev/null
OID=$("$PW" decode objective --record examples/capset/objective.json \
        | grep -o 'sha256:[0-9a-f]*' | head -1)
[ -n "$OID" ] || fail "could not read the objective id back"
printf '  %s\n' "$OID"

rule "mint: spend verifier runs now so that checking is free later"
MINT=$(pw canary mint --objective "$OID" --from examples/capset/artifact.json \
         --count 4 --valid-share 1/2 --out "$WORK/canaries")
echo "$MINT" | sed "s|$WORK|WORK|g"
echo "$MINT" | grep -q '2 known-good, 2 known-bad' \
  || fail "the batch did not land on both sides -- half a trap catches half the liars"
[ -f "$WORK/canaries/docket.json" ] || fail "no docket was written"
# The docket is the issuer's private list. It must not name a recipe: a recipe
# plus a parent recognises every canary that seed will ever produce, not just
# the four here.
grep -q 'recipe' "$WORK/canaries/docket.json" && fail "the docket leaks its recipes"

rule "every canary is the same size as the artifact it came from"
python3 - "$WORK/canaries" examples/capset/artifact.json <<'PY'
import glob, json, os, sys
work, real = sys.argv[1], sys.argv[2]
canon = lambda p: json.dumps(json.load(open(p)), sort_keys=True, separators=(",", ":"))
want = len(canon(real))
for path in sorted(glob.glob(os.path.join(work, "a-*.json"))):
    got = len(canon(path))
    if got != want:
        sys.exit(f"{os.path.basename(path)} encodes to {got} bytes, the real one to {want}")
    print(f"  {os.path.basename(path)}  {got} bytes, same as the real submission")
PY

rule "submit them the ordinary way: commit, wait out the epoch, reveal"
# Same naming scheme, same nonce shape, for the real submission and the
# canaries alike. A nonce spelled `canary-0` hands a reader the whole docket for
# free, and that is not a hypothetical -- it is exactly how the first run of the
# equivalent Rust test failed.
#
# Commit everything first, then reveal everything, rather than one `try` per
# artifact: `try` settles, a plain objective settles once, and the submissions
# after the first would be refused. Nothing here calls `settle`, so all five
# reveals are admitted and every one of them gets a verdict -- which is what
# this script is about. Whether they get *paid* is a different mechanism.
SUBS=()
i=0
for f in examples/capset/artifact.json "$WORK"/canaries/a-*.json; do
  i=$((i + 1))
  SUBS+=("$(printf 'sub-%02d|%s' "$i" "$f")")
done
for entry in "${SUBS[@]}"; do
  who="${entry%%|*}"; art="${entry#*|}"
  pw commit "$OID" --submitter "$who" --artifact "$art" --nonce "nonce-$who" >/dev/null
done
sleep 2
for entry in "${SUBS[@]}"; do
  who="${entry%%|*}"; art="${entry#*|}"
  pw reveal "$OID" --submitter "$who" --artifact "$art" --nonce "nonce-$who" >/dev/null \
    || fail "$who's reveal was refused"
done
VERDICTS=$(grep -c '"kind":"verdict"' "$LOG")
[ "$VERDICTS" -eq 5 ] || fail "expected 5 verdicts, got $VERDICTS"
printf '  %s verdicts in the log, one real submission and four canaries\n' "$VERDICTS"

rule "every claim record is the same size, not just every artifact"
# Same-length submitters and same-length nonces, so the records around the
# artifacts are uniform too. A canary that arrived in a longer record is a
# canary you can count without reading it.
python3 - "$LOG" <<'PY'
import json, sys
sizes = set()
for line in open(sys.argv[1]):
    entry = json.loads(line)
    if entry.get("kind") == "claim":
        sizes.add(len(json.dumps(entry["payload"], sort_keys=True, separators=(",", ":"))))
if len(sizes) != 1:
    sys.exit(f"claim record sizes separate the canaries: {sorted(sizes)}")
print(f"  every claim encodes to {sizes.pop()} bytes")
PY

rule "nothing in the log says which claims were canaries"
grep -qi 'canary' "$LOG" && fail "the log names its own canaries"
printf '  the word does not appear\n'

rule "check: clean against an honest log, and no verifier runs"
OUT=$(pw canary check --docket "$WORK/canaries/docket.json")
echo "$OUT" | sed 's/^/  /'
echo "$OUT" | grep -q 'nothing in this log contradicts' || fail "the honest log was accused"

rule "now a node that wrote accept without looking"
# Forge the verdict a rubber-stamper would have written, chained correctly, so
# the tamper-evidence in the log has nothing to complain about. The lie is in
# the *content* of a well-formed record, which is precisely the case a hash
# chain cannot reach.
python3 - "$LOG" "$PW" <<'PY'
import json, os, subprocess, sys, tempfile

path, binp = sys.argv[1], sys.argv[2]
entries = [json.loads(line) for line in open(path)]
victim = None
for entry in entries:
    if entry["kind"] == "verdict" and entry["payload"]["verdict"]["status"] == "reject":
        victim = entry
if victim is None:
    sys.exit("no rejection in the log to overwrite -- nothing to rubber-stamp")

last = entries[-1]
body = {
    "kind": "verdict",
    "payload": {
        "claim_id": victim["payload"]["claim_id"],
        "objective_id": victim["payload"]["objective_id"],
        "verdict": {"status": "accept", "detail": "looks fine to me", "evidence": {}},
    },
    "prev": last["hash"],
    "seq": len(entries),
    "ts": last["ts"],
}
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
    json.dump(body, fh)
    tmp = fh.name
out = subprocess.run([binp, "canon", tmp], capture_output=True, text=True).stdout
os.unlink(tmp)
digest = [word for word in out.split() if word.startswith("sha256:")][-1]
body["hash"] = digest
with open(path, "a") as fh:
    fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
print(f"  forged an accept over claim {victim['payload']['claim_id'][:22]}...")
PY

rule "the cheap audit cannot see it"
CHEAP=$(pw audit --no-rerun)
echo "$CHEAP" | tail -1 | sed 's/^/  /'
echo "$CHEAP" | grep -q 'no verifier was run' \
  || fail "audit --no-rerun claimed a re-verification it did not perform"
echo "$CHEAP" | grep -q 'problem(s)' \
  && fail "the cheap audit found the lie -- then this demo is not showing what it says"

rule "the expensive audit can, at the price of every verifier in the log"
# Captured rather than piped: `audit` exits 1 when it finds a problem, and under
# `pipefail` that would sink the pipeline even though the grep succeeded.
set +e
FULL=$(pw audit 2>&1)
set -e
echo "$FULL" | tail -2 | sed 's/^/  /'
echo "$FULL" | grep -q 're-verification says reject' \
  || fail "the re-running audit did not catch the forged accept"

rule "and the canary check does, running none of them"
set +e
OUT=$(pw canary check --docket "$WORK/canaries/docket.json")
CODE=$?
set -e
echo "$OUT" | sed 's/^/  /'
[ "$CODE" -eq 1 ] || fail "canary check exited $CODE on a log containing a lie"
echo "$OUT" | grep -q 'recorded accept on an artifact the verifier rejects' \
  || fail "the discrepancy was not named"

printf '\n\033[32mCANARY-DEMO OK: the cheap audit passes a rubber-stamper, and a docket does not.\033[0m\n'
