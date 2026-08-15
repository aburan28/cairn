#!/usr/bin/env bash
# A bonded dispute, driven entirely through the CLI, and audited by both
# implementations.
#
#   ./scripts/dispute-demo.sh
#
# `tests/fraud_proofs.rs` closes the trap around a `Node` through the library.
# This closes it around the binary, and does the one thing no in-process test
# can: it hands the finished log to the *other* implementation and asks whether
# it agrees. A second opinion that has never seen a record kind reports "log
# verified" over money it did not look at, which is worse than having no second
# implementation at all -- the differential script says so in its own comments,
# because that is what happened with availability settlements.
#
# What this proves that the unit tests cannot:
#
#   1. A person can actually run a dispute: build a trace, object to somebody
#      else's with a bond, answer what the log asks for, settle it. Five
#      commands, no shared process, no session state -- each one reads the
#      dispute back out of the log.
#   2. The liar loses and the money moves, and the balances say so.
#   3. `reference/rust` audits the finished log clean, which means it accounts
#      for the bond and the slash rather than ignoring records it does not know.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PW="${PROOFWORK_BIN:-./target/release/proofwork}"
REF="${REFERENCE_BIN:-./reference/rust/target/release/proofwork-reference}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
[ -x "$REF" ] || {
  echo "building reference..." >&2
  cargo build --release --manifest-path reference/rust/Cargo.toml
}
LOG="$WORK/log.jsonl"
pw() { "$PW" --log "$LOG" --root "$WORK" "$@"; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null || { echo "python3 required for the pinned stepper" >&2; exit 0; }

# One-second epochs so the challenge window is something a script can wait out.
export PROOFWORK_EPOCH_SECONDS=1

rule "an objective whose computation has a step function"
mkdir -p "$WORK/code"
cat > "$WORK/code/checker.py" <<'PY'
def check(artifact):
    return isinstance(artifact.get("trace_root"), str)
PY
cat > "$WORK/code/stepper.py" <<'PY'
def step(state):
    n = state.get("n")
    i = state.get("i", 0)
    if isinstance(n, bool) or not isinstance(n, int):
        return {"halted": "n is not an integer", "i": i + 1, "n": 0}
    if n == 1:
        return {"n": 1, "i": i + 1}
    return {"n": n // 2 if n % 2 == 0 else 3 * n + 1, "i": i + 1}
PY
CHECKER_SHA=$(sha256sum "$WORK/code/checker.py" | awk '{print $1}')
STEPPER_SHA=$(sha256sum "$WORK/code/stepper.py" | awk '{print $1}')

python3 - "$WORK" "$CHECKER_SHA" "$STEPPER_SHA" <<'PY'
import json, sys
work, checker, stepper = sys.argv[1], sys.argv[2], sys.argv[3]
objective = {
    "created_at": "2026-08-15T00:00:00+00:00",
    "funder": "treasury",
    "goal": "GOAL-dispute-demo",
    "reward": 1000,
    "statement": "Commit to a Collatz trajectory from 27, so a disagreement can be settled by one step.",
    "verifier": {
        "checker": "code/checker.py",
        "checker_sha256": checker,
        "entrypoint": "check",
        "kind": "certificate",
        "stepper": {
            "code": "code/stepper.py",
            "code_sha256": stepper,
            "entrypoint": "step",
        },
    },
}
with open(f"{work}/objective.json", "w") as fh:
    json.dump(objective, fh, indent=2, sort_keys=True)
PY

rule "a declared supply, so a bond costs something"
# Without an issuance record the escrow rules are off and a bond is free, which
# means the mechanism this script demonstrates is not actually running.
"$PW" --log "$LOG" --root "$WORK" identity --out "$WORK/alice.json" >/dev/null
"$PW" --log "$LOG" --root "$WORK" identity --out "$WORK/bob.json" >/dev/null
ALICE=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public'])" "$WORK/alice.json")
BOB=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public'])" "$WORK/bob.json")
pw issue --holder "$ALICE" --units 1000000 >/dev/null
pw issue --holder "$BOB" --units 1000000 >/dev/null
pw issue --holder treasury --units 1000000 >/dev/null
pw post "$WORK/objective.json" >/dev/null
OID=$("$PW" decode objective --record "$WORK/objective.json" | grep -o 'sha256:[0-9a-f]*' | head -1)
printf '  objective %s\n' "$OID"

rule "the honest trace, and a forged one"
echo '{"i": 0, "n": 27}' > "$WORK/start.json"
pw dispute trace --objective "$OID" --from "$WORK/start.json" --steps 32 --out "$WORK/truth.json" \
  | sed 's/^/  /'
# Alice submits a trace that is honest for eleven states and wrong afterwards.
# The divergence has to persist: two traces that rejoin end on the same state,
# and a dispute over them is refused because nothing has been contradicted.
python3 - "$WORK/truth.json" "$WORK/lie.json" <<'PY'
import json, sys
states = json.load(open(sys.argv[1]))
for index in range(11, len(states)):
    states[index] = {"i": index, "n": states[index]["n"] + 1}
with open(sys.argv[2], "w") as fh:
    json.dump(states, fh)
PY
ROOT_LIE=$(pw dispute trace --objective "$OID" --from "$WORK/start.json" --steps 0 2>/dev/null || true)

rule "alice submits the forged trace"
python3 - "$WORK" <<'PY'
import json, hashlib, sys
work = sys.argv[1]
states = json.load(open(f"{work}/lie.json"))


def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value):
    return "sha256:" + hashlib.sha256(canon(value).encode()).hexdigest()


def merkle(leaves):
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        i = 0
        while i + 1 < len(level):
            nxt.append("sha256:" + hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest())
            i += 2
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


root = merkle([digest(s) for s in states])
with open(f"{work}/artifact.json", "w") as fh:
    json.dump({"n": 27, "trace_root": root, "trace_states": len(states)}, fh)
print(f"  committed root {root}")
PY
pw try "$OID" --submitter "$ALICE" --artifact "$WORK/artifact.json" \
     --identity "$WORK/alice.json" >/dev/null 2>&1 || true
CLAIM=$(python3 - "$LOG" <<'PY'
import hashlib, json, sys
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":"))
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "claim":
        print("sha256:" + hashlib.sha256(canon(e["payload"]).encode()).hexdigest())
        break
PY
)
[ -n "$CLAIM" ] || fail "no claim reached the log"
printf '  claim %s\n' "${CLAIM:0:22}..."

rule "bob objects, with a bond"
# `balances` prints `<id> spendable <n> escrowed <n>`, so the number is $3.
spendable_of() { pw balances | awk -v who="${1:0:8}" '$1 == who {print $3}'; }
BOB_BEFORE=$(spendable_of "$BOB")
OUT=$(pw dispute open --claim "$CLAIM" --trace "$WORK/truth.json" --bond 500 \
        --identity "$WORK/bob.json")
echo "$OUT" | sed 's/^/  /'
CID=$(echo "$OUT" | grep -o 'sha256:[0-9a-f]*' | head -1)
[ -n "$CID" ] || fail "the objection was refused"

rule "both sides answer what the log asks them for"
# Neither command knows the search order in advance. Each reads its debt out of
# the log, plays it, and stops -- which is what makes this an interactive
# protocol that no party has to stay online for.
for _ in $(seq 1 12); do
  pw dispute play --id "$CID" --trace "$WORK/lie.json"   --identity "$WORK/alice.json" >/dev/null
  pw dispute play --id "$CID" --trace "$WORK/truth.json" --identity "$WORK/bob.json"   >/dev/null
  if pw dispute status --id "$CID" | grep -q 'narrowed'; then break; fi
done
pw dispute status --id "$CID" | sed 's/^/  /'
pw dispute status --id "$CID" | grep -q 'narrowed' \
  || fail "the search did not narrow to a single step"

rule "one step of execution decides it"
SETTLED=$(pw dispute settle --id "$CID")
echo "$SETTLED" | sed 's/^/  /'
echo "$SETTLED" | grep -q 'challenger wins' \
  || fail "the forged trace was not refuted"

rule "and the money moved"
pw balances | sed 's/^/  /'
BOB_AFTER=$(spendable_of "$BOB")
[ "$BOB_AFTER" -gt "$BOB_BEFORE" ] \
  || fail "the challenger was not paid: $BOB_BEFORE -> $BOB_AFTER"
printf '  challenger %s -> %s\n' "$BOB_BEFORE" "$BOB_AFTER"

rule "both implementations audit the finished log"
set +e
RUST_OUT=$(pw audit --no-rerun 2>&1)
REF_OUT=$("$REF" --log "$LOG" --root "$WORK" audit 2>&1)
set -e
echo "$RUST_OUT" | tail -1 | sed 's/^/  rust: /'
echo "$RUST_OUT" | grep -q 'problem' && fail "the primary reports a problem: $RUST_OUT"
echo "$REF_OUT" | tail -1 | sed 's/^/  ref:  /'
echo "$REF_OUT" | grep -qi 'problem' && fail "the reference reports a problem: $REF_OUT"

rule "and the reference catches a dispute the primary would refuse"
# The point of a second opinion: it must re-derive the rules, not trust the
# writer that applied them. A challenge appended straight into the log agrees
# with the claim it disputes, and both implementations have to say so.
python3 - "$LOG" "$PW" "$CLAIM" "$WORK" <<'PY'
import json, os, subprocess, sys, tempfile

log, binp, claim, work = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
entries = [json.loads(line) for line in open(log)]
artifact = next(e for e in entries if e["kind"] == "claim")["payload"]["artifact"]
bob = json.load(open(f"{work}/bob.json"))["public"]
payload = {
    "type": "challenge",
    "bond": 10,
    "challenger": bob,
    "claim_id": claim,
    "created_at": entries[-1]["ts"],
    "root": artifact["trace_root"],
    "states": artifact["trace_states"],
}
last = entries[-1]
body = {
    "kind": "challenge",
    "payload": payload,
    "prev": last["hash"],
    "seq": len(entries),
    "ts": last["ts"],
}
with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
    json.dump(body, fh)
    tmp = fh.name
out = subprocess.run([binp, "canon", tmp], capture_output=True, text=True).stdout
os.unlink(tmp)
body["hash"] = [w for w in out.split() if w.startswith("sha256:")][-1]
with open(log, "a") as fh:
    fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
print("  appended a challenge that agrees with the claim it disputes")
PY
# Captured, not piped: both `audit` commands exit 1 once they find a problem,
# and under `pipefail` that sinks the pipeline even though the grep succeeded.
set +e
RUST_AUDIT=$(pw audit --no-rerun 2>&1)
REF_AUDIT=$("$REF" --log "$LOG" --root "$WORK" audit 2>&1)
set -e
echo "$RUST_AUDIT" | grep -q 'agrees with the claim' \
  || fail "the primary did not name the bad challenge: $RUST_AUDIT"
printf '  rust: names it\n'
echo "$REF_AUDIT" | grep -q 'agrees with the claim' \
  || fail "the reference did not name the bad challenge: $REF_AUDIT"
printf '  ref:  names it\n'

printf '\n\033[32mDISPUTE-DEMO OK: a liar lost a bonded dispute, and both implementations agree.\033[0m\n'
