#!/usr/bin/env bash
# The validator loop, end to end: a node that re-verifies every claim it holds
# and stands behind what it finds, and a reader that asks what is believed.
#
#   ./scripts/validator-demo.sh
#
# `tests/attestor.rs` closes the loop around a `Node`. This closes it around
# the binary, across real epoch boundaries, with the pinned checker spawning
# for real, and then reads the result back over HTTP the way a page would:
#
#   1. `cairn attest serve --identity V` attests every claim exactly once,
#      with the status the verifier returned HERE -- `accept` for the honest
#      submission, `reject` for the planted-bad one -- and never the claim
#      whose verifier cannot run on this host.
#   2. A second pass attests nothing: one statement per attestor per claim.
#   3. `audit --rerun` agrees with every attestation, because each one is
#      what the pinned verifier says.
#   4. `GET /knowledge/{claim}` reports the claim's standing beside who stood
#      behind its verdict under bond, and `GET /knowledge` tallies the log.
#   5. The `replay` example round-trips: the one objective shape an
#      experiment's run record takes on the network.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PW="${CAIRN_BIN:-./target/release/cairn}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
LOG="$WORK/log.jsonl"
pw() {
  "$PW" --log "$LOG" --key-file "$WORK/no-at-rest-key" --root . "$@"
}
rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null || { echo "python3 required for the pinned checker" >&2; exit 0; }
export CAIRN_EPOCH_SECONDS=1

rule "a funded validator, so a bond costs something"
pw identity --out "$WORK/validator.json" >/dev/null
pw identity --out "$WORK/treasury.json" >/dev/null
pubkey() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public'])" "$1"; }
VALIDATOR=$(pubkey "$WORK/validator.json")
TREASURY=$(pubkey "$WORK/treasury.json")
pw issue --holder "$VALIDATOR" --units 1000000 >/dev/null
pw issue --holder "$TREASURY" --units 1000000 >/dev/null
printf '  validator %s\n' "${VALIDATOR:0:16}"

rule "three objectives: a checker, a replay, and one nothing here can run"
OID=$(pw post examples/collatz/objective.json --identity "$WORK/treasury.json" | head -1 | awk '{print $2}')
RID=$(pw post examples/replay-reproduction/objective.json --identity "$WORK/treasury.json" | head -1 | awk '{print $2}')
LID=$(pw post examples/lean/objective.json --identity "$WORK/treasury.json" | head -1 | awk '{print $2}')
[ -n "$OID" ] && [ -n "$RID" ] && [ -n "$LID" ] || fail "could not read the objective ids back"
printf '  collatz %s\n  replay  %s\n  lean    %s\n' "${OID:0:20}" "${RID:0:20}" "${LID:0:20}"

rule "submit: a good collatz witness, a bad one, the replay figures, a proof nobody here can check"
python3 - examples/collatz/artifact.json "$WORK/bad.json" <<'PY'
import json, sys
art = json.load(open(sys.argv[1]))
# Break the witness in a way that keeps its shape: the checker must reject it.
for key, value in art.items():
    if isinstance(value, list) and value:
        value[-1] = value[-1] + 1 if isinstance(value[-1], int) else value[-1]
        break
    if isinstance(value, int):
        art[key] = value + 1
        break
json.dump(art, open(sys.argv[2], "w"))
PY
if command -v lean >/dev/null 2>&1; then
  echo "  (lean is installed here; the unrunnable arm of this demo is skipped)"
  HAVE_LEAN=1
else
  HAVE_LEAN=0
fi
pw commit "$OID" --submitter good --artifact examples/collatz/artifact.json --nonce n1 >/dev/null
pw commit "$OID" --submitter bad --artifact "$WORK/bad.json" --nonce n2 >/dev/null
pw commit "$RID" --submitter replayer --artifact examples/replay-reproduction/artifact.json --nonce n3 >/dev/null
[ "$HAVE_LEAN" = 1 ] || pw commit "$LID" --submitter prover --artifact examples/lean/artifact.json --nonce n4 >/dev/null
sleep 2
pw reveal "$OID" --submitter good --artifact examples/collatz/artifact.json --nonce n1 >/dev/null || fail "good reveal refused"
pw reveal "$OID" --submitter bad --artifact "$WORK/bad.json" --nonce n2 >/dev/null || fail "bad reveal refused (a reject is still admitted)"
pw reveal "$RID" --submitter replayer --artifact examples/replay-reproduction/artifact.json --nonce n3 >/dev/null || fail "replay reveal refused"
# `reveal` exits 3 when the verdict does not settle: the claim is admitted,
# and "nothing was learned" is the honest code for an unavailable verifier.
if [ "$HAVE_LEAN" = 0 ]; then
  rc=0
  pw reveal "$LID" --submitter prover --artifact examples/lean/artifact.json --nonce n4 >/dev/null || rc=$?
  [ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || fail "lean reveal refused (exit $rc)"
fi
VERDICTS=$(python3 - "$LOG" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "verdict":
        print(e["payload"]["claim_id"], e["payload"]["verdict"]["status"])
PY
)
echo "$VERDICTS" | sed 's/^/  /'
echo "$VERDICTS" | grep -q " accept$" || fail "no accepted claim"
echo "$VERDICTS" | grep -q " reject$" || fail "no rejected claim"
[ "$HAVE_LEAN" = 1 ] || echo "$VERDICTS" | grep -q " unavailable$" || fail "no unavailable claim"

rule "attest serve: one pass, every claim this host can check"
OUT=$(pw attest serve --identity "$WORK/validator.json")
echo "$OUT" | sed 's/^/  /'
EXPECT_POSTED=$([ "$HAVE_LEAN" = 1 ] && echo 3 || echo 3)
echo "$OUT" | grep -q "pass: .* $EXPECT_POSTED attested" || fail "expected $EXPECT_POSTED attestations in the pass line"
[ "$HAVE_LEAN" = 1 ] || echo "$OUT" | grep -q "1 unavailable here" || fail "the lean claim must be set aside, not attested"
echo "$OUT" | grep -q "0 disagreement" || fail "this node's verifier agrees with the admitting node's: it is the same node"
pw attest list | sed 's/^/  /'
pw attest list | grep -q "^$EXPECT_POSTED attestation" || fail "attest list disagrees with the pass"

rule "a second pass attests nothing: one statement per attestor per claim"
# A fresh process retries the claim nobody here could check -- a toolchain
# may have been installed since -- and must still post nothing for it.
OUT2=$(pw attest serve --identity "$WORK/validator.json")
echo "$OUT2" | tail -1 | sed 's/^/  /'
echo "$OUT2" | grep -q "pass: .* 0 attested" || fail "a second pass must find nothing new to stand behind"

rule "audit (re-running every verifier): each attestation is what the pinned verifier says"
pw audit | tail -2 | sed 's/^/  /'
pw audit >/dev/null || fail "audit found a problem with an attestation the loop posted"

rule "GET /knowledge: standing beside who stood behind it"
PORT=${CAIRN_VALIDATOR_PORT:-38084}
"$PW" --log "$LOG" --key-file "$WORK/no-at-rest-key" --root . serve --listen "127.0.0.1:$PORT" >"$WORK/serve.out" 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null; rm -rf "$WORK"' EXIT
for _ in $(seq 1 50); do
  python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(('127.0.0.1',$PORT))==0 else 1)" 2>/dev/null && break
  sleep 0.1
done
ACCEPTED=$(echo "$VERDICTS" | awk '$2=="accept"{print $1; exit}')
REJECTED=$(echo "$VERDICTS" | awk '$2=="reject"{print $1; exit}')
python3 - "$PORT" "$ACCEPTED" "$REJECTED" "$VALIDATOR" <<'PY'
import json, sys, urllib.request
port, accepted, rejected, validator = sys.argv[1:]
def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as r:
        return json.loads(r.read())
a = get(f"/knowledge/{accepted}")
assert a["state"]["standing"] == "accepted", a["state"]
assert a["attestations"]["accept"] == 1 and a["attestations"]["reject"] == 0, a["attestations"]
assert a["attestations"]["attestations"][0]["attestor"] == validator
assert a["policy"]["name"] == "default"
print(f"  accepted claim: standing {a['state']['standing']}, confidence {a['state']['confidence_per_mille']}/1000, 1 attestor under bond")
r = get(f"/knowledge/{rejected}")
assert r["state"]["standing"] == "refuted", r["state"]
assert r["attestations"]["reject"] == 1, r["attestations"]
print(f"  rejected claim: standing {r['state']['standing']}, attested reject by the same validator")
d = get(f"/knowledge/{accepted}?policy=demanding")
assert d["policy"]["name"] == "demanding"
assert d["state"]["confidence_per_mille"] <= a["state"]["confidence_per_mille"]
idx = get("/knowledge")
assert idx["total"] >= 3, idx
assert idx["by_standing"].get("accepted", 0) >= 2 and idx["by_standing"].get("refuted", 0) >= 1, idx["by_standing"]
print(f"  index: {idx['total']} claims, by standing {idx['by_standing']}")
PY

printf '\n\033[32mvalidator demo passed\033[0m\n'
