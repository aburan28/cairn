#!/usr/bin/env bash
# Bonded verification, end to end: who ran the checker, and what it costs to lie.
#
#   ./scripts/attestation-demo.sh
#
# `tests/attestations.rs` closes this trap around a `Node` through the library.
# This closes it around the binary, and does the two things no in-process test
# can: it runs the whole mechanism across real epoch boundaries with the pinned
# Python checker spawning for real, and it hands the finished log to the *other*
# implementation and asks whether it agrees about the money.
#
# What this proves that the unit tests cannot:
#
#   1. Two operators stand behind the same verdicts. One paid to look and one
#      did not, and until somebody brings evidence the log cannot tell them
#      apart -- which is the design, not a gap in it.
#   2. A canary docket names the liar for the price of a map lookup, and the
#      slash it points at runs the pinned verifier exactly once.
#   3. The bond moves: the liar is poorer by it and the catcher is richer by it,
#      and `balances` says so.
#   4. `reference/rust` audits the finished log clean. A second opinion that has
#      never seen a record kind certifies the money it did not look at, which is
#      worse than having no second implementation at all.
set -euo pipefail
cd "$(dirname "$0")/.."

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PW="${CAIRN_BIN:-./target/release/cairn}"
REF="${REFERENCE_BIN:-./reference/rust/target/release/cairn-reference}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
[ -x "$REF" ] || {
  echo "building reference..." >&2
  cargo build --release --manifest-path reference/rust/Cargo.toml
}
LOG="$WORK/log.jsonl"
pw() { "$PW" --log "$LOG" --root . "$@"; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

command -v python3 >/dev/null || { echo "python3 required for the pinned checker" >&2; exit 0; }

# One-second epochs, so a commit and its reveal fit in a script that finishes.
# Changes no canonical bytes: nothing derived from this enters a record.
export CAIRN_EPOCH_SECONDS=1

rule "a declared supply, so a bond costs something"
# Without an issuance record the escrow rules are off and a bond is free, which
# would mean the mechanism this script is about is not actually running.
# Issuance is admissible only in the log's opening prefix, so it comes first.
"$PW" --log "$LOG" --root . identity --out "$WORK/honest.json" >/dev/null
"$PW" --log "$LOG" --root . identity --out "$WORK/stamper.json" >/dev/null
pubkey() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public'])" "$1"; }
HONEST=$(pubkey "$WORK/honest.json")
STAMPER=$(pubkey "$WORK/stamper.json")
pw issue --holder "$HONEST" --units 1000000 >/dev/null
pw issue --holder "$STAMPER" --units 1000000 >/dev/null
pw issue --holder treasury --units 1000000 >/dev/null
printf '  honest  %s\n  stamper %s\n' "${HONEST:0:16}" "${STAMPER:0:16}"

rule "an objective with a real pinned verifier"
# Cap sets, as in `canary-demo.sh`, and for the same reason: a known-*good*
# canary needs an artifact holding an unordered collection, because reordering
# a set is the reliable validity-preserving edit and half the trap needs one.
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

rule "submit them the ordinary way: commit, wait out the epoch, reveal"
# Same submitter shape and nonce shape for every submission. A nonce spelled
# `canary-0` hands a reader the whole docket for free.
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
CLAIMS=$(python3 - "$LOG" <<'PY'
import hashlib, json, sys
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":"))
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "claim":
        print("sha256:" + hashlib.sha256(canon(e["payload"]).encode()).hexdigest())
PY
)
[ "$(echo "$CLAIMS" | wc -l)" -eq 5 ] || fail "expected 5 claims in the log"
printf '  5 claims: one real submission and four canaries, indistinguishable\n'

rule "both operators stand behind every verdict, under bond"
# The honest one reads what the node's own run recorded -- it paid to look. The
# stamper writes `accept` across the board without looking. Same record, same
# stake; they differ only in whether what they signed is true.
VERDICT_OF=$(python3 - "$LOG" <<'PY'
import hashlib, json, sys
def canon(v): return json.dumps(v, sort_keys=True, separators=(",", ":"))
status = {}
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "verdict":
        status[e["payload"]["claim_id"]] = e["payload"]["verdict"]["status"]
for claim, verdict in status.items():
    print(f"{claim} {verdict}")
PY
)
while read -r claim status; do
  [ "$status" = "unavailable" ] && continue
  pw attest stand --claim "$claim" --status "$status" --identity "$WORK/honest.json" >/dev/null \
    || fail "the honest attestation was refused"
  pw attest stand --claim "$claim" --status accept --identity "$WORK/stamper.json" >/dev/null \
    || fail "the stamper's attestation was refused"
done <<< "$VERDICT_OF"
pw attest list | tail -1 | sed 's/^/  /'

rule "nothing at admission checked whether any of it was true"
# The point of the whole design, stated as a test. Asking at admission would put
# the verification cost back exactly where the mechanism took it out of.
pw audit --no-rerun >/dev/null || fail "the cheap audit found a problem it should not have"
printf '  audit --no-rerun is clean, and ran no verifier\n'

rule "the docket names the liar, for the price of a map lookup"
set +e
CHECK=$(pw canary check --docket "$WORK/canaries/docket.json")
set -e
echo "$CHECK" | sed 's/^/  /' | tail -4
echo "$CHECK" | grep -q 'stood behind accept' \
  || fail "the docket did not name the stamper"

rule "and the slash takes the bond, running the verifier once per catch"
before_of() { pw balances | awk -v who="${1:0:8}" '$1 == who {print $3}'; }
HONEST_BEFORE=$(before_of "$HONEST")
set +e
SLASH=$(pw attest slash --docket "$WORK/canaries/docket.json" --catcher "$HONEST")
CODE=$?
set -e
echo "$SLASH" | sed 's/^/  /'
[ "$CODE" -eq 0 ] || fail "the slash took nothing"
echo "$SLASH" | grep -q '2 bond(s) taken' \
  || fail "expected both known-bad canaries to name the stamper"

HONEST_AFTER=$(before_of "$HONEST")
# The catcher's gain shows in `spendable`; the stamper's loss does not, and that
# is the point of the `forfeited` column. A live bond and a forfeited one are
# both subtracted from spendable, so an identity that just lost a bond prints
# the number it printed before -- read what was *taken*, not what is left.
FORFEITED=$(pw balances | awk -v who="${STAMPER:0:8}" '$1 == who {print $NF}')
printf '  catcher spendable %s -> %s\n  stamper forfeited %s\n' \
  "$HONEST_BEFORE" "$HONEST_AFTER" "$FORFEITED"
[ "$HONEST_AFTER" -gt "$HONEST_BEFORE" ] || fail "the catcher was not paid"
[ "$FORFEITED" = "100000" ] || fail "the stamper forfeited $FORFEITED, not two bonds"
[ "$((HONEST_AFTER - HONEST_BEFORE))" -eq "$FORFEITED" ] \
  || fail "the catcher was paid something other than what the stamper lost"

rule "the honest attestor kept every bond it staked"
# Half the pair, and the half that would be easy to lose: a mechanism that
# punishes stamping by making everybody poorer has distinguished nothing.
LIST=$(pw attest list)
echo "$LIST" | tail -1 | sed 's/^/  /'
HONEST_LIVE=$(echo "$LIST" | grep -c "${HONEST:0:8}.*\[live\]" || true)
HONEST_SLASHED=$(echo "$LIST" | grep -c "${HONEST:0:8}.*\[slashed\]" || true)
printf '  honest: %s live, %s slashed\n' "$HONEST_LIVE" "$HONEST_SLASHED"
[ "$HONEST_SLASHED" -eq 0 ] || fail "an honest attestation was slashed"
[ "$HONEST_LIVE" -eq 5 ] || fail "the honest attestor holds $HONEST_LIVE live bonds, not 5"

rule "both implementations agree about the money"
pw audit >/dev/null || fail "the primary found a problem in its own log"
"$REF" audit --log "$LOG" | tail -2 | sed 's/^/  /'
"$REF" audit --log "$LOG" >/dev/null \
  || fail "the reference disagrees about a log the primary certified"

printf '\n\033[32mbonded verification: named for a lookup, taken on one run, agreed by both\033[0m\n'
