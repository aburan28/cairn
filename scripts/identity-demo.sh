#!/usr/bin/env bash
# A submitter name that is a key cannot be worn by anyone else.
#
# `submitter` was a free string, so a name was worth nothing: anyone could
# submit as `alice`, and citation flow pays that name. This drives the fix
# through the real binaries -- generate an identity, submit under it, then try
# every way of stealing it and watch each one refused.
#
# The rule needs no registry: a submitter that is 64 lowercase hex characters
# IS an ed25519 public key, so the name and the key are the same fact.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
[ -x "$RUST" ] || { echo "building..." >&2; cargo build --release --locked; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-identity-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/log.jsonl"

# One second per epoch: this script crosses two epoch boundaries and the
# assertions do not race, so the short length is safe here.
export PROOFWORK_EPOCH_SECONDS=1

rule "create two identities"
"$RUST" identity --out "$WORK/alice.json" | sed 's/^/  /'
"$RUST" identity --out "$WORK/mallory.json" >/dev/null
ALICE=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public'])" "$WORK/alice.json")

# The key file holds secret material and must not be world-readable.
MODE=$(stat -c '%a' "$WORK/alice.json" 2>/dev/null || stat -f '%Lp' "$WORK/alice.json")
[ "$MODE" = "600" ] || fail "identity file is mode $MODE, expected 600"
echo "  identity file is mode 600"

rule "post an objective"
OID=$("$RUST" --log "$LOG" --root . post examples/reversible-adder/objective.json \
  | head -1 | awk '{print $2}')
echo "  $OID"

rule "alice submits under her key"
"$RUST" --log "$LOG" --root . commit "$OID" --identity "$WORK/alice.json" \
  --artifact examples/reversible-adder/artifact-cuccaro.json --nonce n1 | sed 's/^/  /'
sleep 1.1
"$RUST" --log "$LOG" --root . reveal "$OID" --identity "$WORK/alice.json" \
  --artifact examples/reversible-adder/artifact-cuccaro.json --nonce n1 | sed 's/^/  /'
grep -q '"signature"' "$LOG" || fail "no signature reached the log"
echo "  the record carries a signature"

rule "mallory wears alice's name with no signature"
if "$RUST" --log "$LOG" --root . commit "$OID" --submitter "$ALICE" \
     --artifact examples/reversible-adder/artifact-truncated.json --nonce n2 >"$WORK/out" 2>&1; then
  fail "an unsigned claim under a key-shaped name was accepted"
fi
grep -q "must carry a signature" "$WORK/out" || fail "wrong refusal: $(cat "$WORK/out")"
sed 's/^/  /' "$WORK/out"

rule "mallory signs with her own key but claims alice's name"
python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
mallory = json.load(open(f"{work}/mallory.json"))
alice = json.load(open(f"{work}/alice.json"))
# Mallory's secret, alice's name. The signature will be real -- just not hers.
json.dump({"secret": mallory["secret"], "public": alice["public"]},
          open(f"{work}/forged.json", "w"))
PY
if "$RUST" --log "$LOG" --root . commit "$OID" --identity "$WORK/forged.json" \
     --artifact examples/reversible-adder/artifact-truncated.json --nonce n3 >"$WORK/out" 2>&1; then
  fail "a mismatched identity file was accepted"
fi
grep -q "does not match" "$WORK/out" || fail "wrong refusal: $(cat "$WORK/out")"
echo "  refused: the file's public half does not match its secret"

rule "a forged signature straight in the log is refused"
# The sharpest version: hand-build a record wearing alice's name, signed by
# mallory, and feed it through the rules engine rather than the CLI.
python3 - "$WORK" "$OID" "$ALICE" <<'PY' > "$WORK/forged-claim.json"
import json, sys
work, oid, alice = sys.argv[1], sys.argv[2], sys.argv[3]
# A signature that is valid for *mallory's* key over this payload. It cannot
# verify under alice's, which is the whole point.
json.dump({"objective_id": oid, "submitter": alice, "artifact": {"qubits": 9, "gates": []},
           "nonce": "n4", "created_at": "2026-08-03T00:00:00+00:00", "cites": [],
           "signature": "ab" * 64}, open("/dev/stdout", "w"))
PY
if "$RUST" --log "$LOG" --root . reveal "$OID" --submitter "$ALICE" \
     --artifact examples/reversible-adder/artifact-truncated.json --nonce n4 >"$WORK/out" 2>&1; then
  fail "an unsigned reveal under a key-shaped name was accepted"
fi
grep -q "must carry a signature" "$WORK/out" || fail "wrong refusal: $(cat "$WORK/out")"
echo "  refused before anything was written"

rule "nicknames still work, unchanged"
"$RUST" --log "$LOG" --root . commit "$OID" --submitter plain-nickname \
  --artifact examples/reversible-adder/artifact-truncated.json --nonce n5 >/dev/null
echo "  a nickname submitter needs no signature -- Stage 0 logs keep working"

rule "an objective that accepts only signed identities"
# Until now the rule protected a name someone chose to sign for. A funder who
# wants *every* claim attributable had to ask in the statement, which is prose
# nothing enforces. `require_signed_submitter` makes it a rule of the bounty.
python3 - "$WORK" <<'PY'
import json, sys
work = sys.argv[1]
objective = json.load(open("examples/reversible-adder/objective.json"))
objective["require_signed_submitter"] = True
objective["statement"] = "Signed-identity-only variant. " + objective["statement"]
json.dump(objective, open(f"{work}/strict.json", "w"), indent=2)
PY
STRICT=$("$RUST" --log "$LOG" --root . post "$WORK/strict.json" | head -1 | awk '{print $2}')
echo "  posted $STRICT"

if "$RUST" --log "$LOG" --root . commit "$STRICT" --submitter alice \
     --artifact examples/reversible-adder/artifact-cuccaro.json --nonce s1 >"$WORK/out" 2>&1; then
  fail "a nickname was accepted by a signed-identity-only objective"
fi
grep -q "only signed identities" "$WORK/out" || fail "wrong refusal: $(cat "$WORK/out")"
grep -q "proofwork identity" "$WORK/out" \
  || fail "the refusal does not tell a contributor how to get an identity"
sed 's/^/  /' "$WORK/out"

"$RUST" --log "$LOG" --root . commit "$STRICT" --identity "$WORK/alice.json" \
  --artifact examples/reversible-adder/artifact-cuccaro.json --nonce s1 >/dev/null
echo "  a signed identity is admitted"

rule "the log audits, and both implementations agree"
sleep 1.1
"$RUST" --log "$LOG" --root . settle >/dev/null 2>&1 || true
"$RUST" --log "$LOG" --root . audit | tail -2 | sed 's/^/  /'
"$RUST" --log "$LOG" --root . audit | grep -q "log verified" || fail "the log does not audit"
PYTHONPATH=reference/python python3 -m proofwork.cli --log "$LOG" --root . audit \
  | grep -q "log verified" || fail "the Python reference does not verify this log"
echo "  the Python reference verified the same signed log"

printf '\n\033[32mIDENTITY OK: a signed name cannot be worn by anyone else\033[0m\n'
