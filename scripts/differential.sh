#!/usr/bin/env bash
# Do the two implementations classify every record the same way?
#
# `interop.sh` proves they agree on logs that are *valid*. This proves they
# agree on the boundary -- which records are admissible at all, and what id an
# admissible one has. That boundary is where a consensus split actually lives:
# two nodes that disagree about whether a record is legal disagree about what
# was settled, and neither ever errors.
#
# It exists because the previous second implementation was in Python, and a
# meaningful share of the divergences it caught came from the *language*
# differing rather than from anyone testing for it -- arbitrary-precision
# integers caught a reward above u64::MAX, dynamic typing caught `"cites":
# "abc"` decoding into three phantom citations. Two Rust implementations share
# those blind spots. Relying on an accident was always the weaker plan; this
# checks the same boundary on purpose, and keeps checking it whichever
# languages the implementations are written in.
#
# `conformance/adversarial.jsonl` is the corpus: one case per line, each with
# a note saying what would break if the two disagreed about it.
set -euo pipefail

# The reference implementation reads plain JSONL and nothing else -- sealing is
# a storage concern of the primary crate, deliberately outside the format the
# two implementations have to agree on. But the CLI seals every log it creates
# whenever a key file exists, so on any machine that has run `cairn keygen`
# this script handed the reference ciphertext and got "malformed JSON: unexpected
# character at byte 0". It failed there and passed in CI, which is the worst
# place for a check to be wrong.
#
# Pointing CAIRN_KEY at a path that does not exist makes `resolve_codec` choose
# plaintext, which is what this script means: it compares the two
# implementations on the format they share.
export CAIRN_KEY=/nonexistent/cairn-interop-forces-plaintext
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
REF="${REF_BIN:-./reference/rust/target/release/cairn-reference}"
CORPUS="${CORPUS:-conformance/adversarial.jsonl}"

[ -x "$RUST" ] || { echo "building the primary..." >&2; cargo build --release --locked; }
[ -x "$REF" ] || {
  echo "building the reference..." >&2
  cargo build --release --locked --manifest-path reference/rust/Cargo.toml
}

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-differential-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

rule "$CORPUS"

TOTAL=0
AGREED=0
DISAGREED=0

# Read the corpus with python3 rather than jq: jq is not everywhere, and the
# records contain embedded newlines and non-ASCII that line tools mangle.
python3 - "$CORPUS" "$WORK" <<'PY'
import json, sys, pathlib
corpus, work = sys.argv[1], pathlib.Path(sys.argv[2])
cases = []
for index, line in enumerate(open(corpus, encoding="utf-8")):
    line = line.strip()
    if not line:
        continue
    case = json.loads(line)
    # Written back out with ensure_ascii=False: the bytes each implementation
    # reads must be the bytes the corpus holds, or the test is about python's
    # escaping rather than about them.
    path = work / f"case-{index:03d}.json"
    path.write_text(json.dumps(case["record"], ensure_ascii=False), encoding="utf-8")
    cases.append({"file": str(path), "kind": case["kind"], "note": case["note"]})
(work / "cases.json").write_text(json.dumps(cases), encoding="utf-8")
PY

# One line per case per implementation: `ok <id>` or `refused`. The *reason*
# for a refusal is deliberately not compared -- two implementations may phrase
# a rejection differently and still agree completely about admissibility, and
# demanding identical prose would make the check fragile without making it
# stronger.
classify() {
  local binary="$1" kind="$2" file="$3"
  "$binary" decode "$kind" --record "$file" 2>/dev/null | head -1 || true
}

while IFS=$'\t' read -r file kind note; do
  TOTAL=$((TOTAL + 1))
  PRIMARY=$(classify "$RUST" "$kind" "$file")
  REFERENCE=$(classify "$REF" "$kind" "$file")
  if [ "$PRIMARY" = "$REFERENCE" ]; then
    AGREED=$((AGREED + 1))
  else
    DISAGREED=$((DISAGREED + 1))
    printf '\033[31m  DISAGREE\033[0m  %s\n' "$note"
    printf '    primary   %s\n' "${PRIMARY:-<no output>}"
    printf '    reference %s\n' "${REFERENCE:-<no output>}"
  fi
done < <(python3 -c '
import json, sys
for case in json.load(open(sys.argv[1])):
    print("\t".join([case["file"], case["kind"], case["note"]]))
' "$WORK/cases.json")

[ "$TOTAL" -gt 0 ] || fail "the corpus is empty"
echo "  $AGREED/$TOTAL cases classified identically by both implementations"

# A corpus where everything is accepted, or everything refused, would pass
# while testing nothing. Both outcomes have to be represented.
ACCEPTED=0
while IFS=$'\t' read -r file kind _; do
  case "$(classify "$RUST" "$kind" "$file")" in
    ok\ *) ACCEPTED=$((ACCEPTED + 1)) ;;
  esac
done < <(python3 -c '
import json, sys
for case in json.load(open(sys.argv[1])):
    print("\t".join([case["file"], case["kind"], case["note"]]))
' "$WORK/cases.json")
[ "$ACCEPTED" -gt 0 ] || fail "no corpus case was accepted; the harness is not exercising the accept path"
[ "$ACCEPTED" -lt "$TOTAL" ] || fail "every corpus case was accepted; the harness is not exercising the refuse path"
echo "  $ACCEPTED accepted, $((TOTAL - ACCEPTED)) refused -- both paths exercised"

[ "$DISAGREED" -eq 0 ] || fail "$DISAGREED case(s) classified differently"

rule "inclusion proofs"

# The other place a disagreement costs somebody money, and it is not a record
# boundary: a challenger who rejects a proof an honest holder produced slashes
# a node that did its job, and one who accepts a proof the holder could not
# have produced pays a node that stored nothing. So each implementation checks
# what the *other* emitted, in both directions, rather than each checking its
# own -- an implementation that is wrong in a self-consistent way passes the
# second arrangement and fails this one.
#
# `launch/cairn.jsonl` is the corpus because it is a real settled log with
# a published root: 25 entries covers both shapes of the promotion rule at
# every level, and the root is one somebody else already signed.
PROOF_LOG="${PROOF_LOG:-launch/cairn.jsonl}"
PROOF_ROOT=$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["checkpoint"]["root"])
' launch/checkpoint.json)
HEIGHT=$(grep -c . "$PROOF_LOG")
echo "  $HEIGHT entries, root $PROOF_ROOT"

PROVED=0
for seq in $(seq 0 $((HEIGHT - 1))); do
  "$RUST" --log "$PROOF_LOG" prove "$seq" --out "$WORK/primary.json" >/dev/null \
    || fail "the primary could not prove entry $seq"
  "$REF" --log "$PROOF_LOG" prove "$seq" --out "$WORK/reference.json" >/dev/null \
    || fail "the reference could not prove entry $seq"
  # Byte equality is a stronger claim than mutual acceptance and worth making
  # separately: two implementations could accept each other's proofs while
  # emitting different encodings, and then a third reader agrees with only one.
  cmp -s "$WORK/primary.json" "$WORK/reference.json" \
    || fail "entry $seq: the two implementations emit different proof bytes"
  "$RUST" check "$WORK/reference.json" --merkle-root "$PROOF_ROOT" >/dev/null \
    || fail "entry $seq: the primary rejected the reference's proof"
  "$REF" check "$WORK/primary.json" --merkle-root "$PROOF_ROOT" >/dev/null \
    || fail "entry $seq: the reference rejected the primary's proof"
  PROVED=$((PROVED + 1))
done
echo "  $PROVED proofs, byte-identical, each accepted by the other implementation"

# And the refuse path, without which the loop above would pass against two
# implementations that accept everything.
python3 - "$WORK/primary.json" "$WORK/tampered.json" <<'PY'
import json, sys
proof = json.load(open(sys.argv[1]))
# The leaf hash is left alone, so the *path* still reaches the root. Only the
# contents a reader would go on to read are changed: an implementation that
# checked the path and took the entry on trust would accept this.
proof["entry"]["ts"] = "2020-01-01T00:00:00+00:00"
json.dump(proof, open(sys.argv[2], "w"))
PY
"$RUST" check "$WORK/tampered.json" --merkle-root "$PROOF_ROOT" >/dev/null 2>&1 \
  && fail "the primary accepted an edited entry"
"$REF" check "$WORK/tampered.json" --merkle-root "$PROOF_ROOT" >/dev/null 2>&1 \
  && fail "the reference accepted an edited entry"
echo "  both refuse an entry edited under a path that still reaches the root"

rule "availability"

# A real availability log, built by the primary and audited by both. The kinds
# involved -- undertaking, availability, availability_pool,
# availability_settlement -- are the newest place the two can drift, and drift
# here costs money: an auditor that skips a settlement certifies it.
#
# This exists because that is exactly what happened. The reference reported
# `log verified` over a log full of availability settlements it never looked
# at, which is worse than having no second implementation, because a green
# result from one that is not looking gets quoted as agreement.
AVAIL="$WORK/availability"
mkdir -p "$AVAIL"
# The verifier resolves an objective's pinned code relative to `--root`, and the
# funding cycle below actually *runs* it -- the rest of this section only posts
# records. So the examples have to exist under the work root, and copying them
# is better than pointing `--root` at the repository: `post` publishes pinned
# code into the root's blob store, and a differential run must not write into
# the working tree it is testing.
mkdir -p "$AVAIL/examples"
cp -r examples/collatz examples/capset "$AVAIL/examples/"
export CAIRN_EPOCH_SECONDS=2
"$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" identity --out "$AVAIL/alice.json" >/dev/null
"$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" identity --out "$AVAIL/bob.json" >/dev/null
"$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" availability fund \
  --funder treasury --per-epoch 7 --from-epoch 0 --to-epoch 4000000000 >/dev/null

# A reveal must land a strictly later epoch than its commitment, and a batch
# may not settle until the finality window has passed on top of that. Same
# shape as `demo.sh`, and read from the environment for the same reason: a
# hard-coded count is a second copy of a rule that can move.
tick() { sleep 3; }
settle_tick() { tick; local i; for ((i = 0; i < ${CAIRN_FINALITY_EPOCHS:-1}; i++)); do tick; done; }

# A bond has to be backed by units the log says the identity *earned*, so both
# nodes run a real objective/commit/reveal/settle cycle before they can promise
# anything. That is a property worth seeing in a shell script rather than only
# in a unit test: a fresh key cannot stake, which is exactly what makes the
# stake scarce and the sybil weighting worth having. One objective each,
# because a non-ratcheted objective settles once and pays one submitter.
for who in alice bob; do
  case "$who" in
    alice) EXAMPLE=collatz ;;
    bob)   EXAMPLE=capset ;;
  esac
  OBJ=$("$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" \
    post "examples/$EXAMPLE/objective.json" | head -1 | awk '{print $2}')
  "$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" commit "$OBJ" \
    --identity "$AVAIL/$who.json" \
    --artifact "examples/$EXAMPLE/artifact.json" --nonce "n-$who" >/dev/null
  tick
  "$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" reveal "$OBJ" \
    --identity "$AVAIL/$who.json" \
    --artifact "examples/$EXAMPLE/artifact.json" --nonce "n-$who" >/dev/null
  settle_tick
  "$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" settle >/dev/null
  # The bond below is only as real as this payout, so a cycle that silently
  # failed to settle stops the script here rather than fifty lines later at
  # `bonds N units against a balance of 0`, which reads like a bug in the rule
  # rather than a fixture that did not earn.
  KEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public"])' \
    "$AVAIL/$who.json")
  grep -q "\"kind\":\"settlement\".*\"submitter\":\"$KEY\"" "$AVAIL/log.jsonl" \
    || fail "$who was never paid, so its bond would have nothing behind it"
done

# Equal bonds, so the settlement below splits evenly and the two implementations
# are compared on the same arithmetic they would face with unequal ones.
for who in alice bob; do
  "$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" availability undertake \
    --identity "$AVAIL/$who.json" --bond 1000 >/dev/null
done
EPOCH=$("$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" availability status \
  | head -1 | sed 's/epoch \([0-9]*\).*/\1/')
# Alice answers, Bob does not: the settlement must pay one and name the other,
# and both implementations must agree about which is which.
"$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" availability answer \
  --identity "$AVAIL/alice.json" --epoch "$EPOCH" >/dev/null
sleep 3
SETTLED=$("$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" availability settle --epoch "$EPOCH")
echo "  $SETTLED" | head -1
case "$SETTLED" in
  *"1 answered, 1 silent"*) ;;
  *) fail "the primary did not pay one answer and name one silence: $SETTLED" ;;
esac
# Grow the log after the answer. The anchor the sample is drawn from used to
# be taken over the whole log, so every later append moved the index and an
# answer that was right when written became wrong two entries later.
"$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" post examples/collatz/objective.json \
  >/dev/null 2>&1 || true

# The whole-log audit, still at the length this log was actually written under.
# Ordinary claim settlement batches are not epoch-length-portable the way
# availability records are meant to be: a batch's recorded `epoch` is
# `timestamp / epoch_seconds` at write time, so re-deriving it at a different
# length asks whether some claim's `timestamp / other_length` happens to equal
# a number computed at a different scale entirely -- it never does, for any
# log with more than one write-time length in play. That is not a bug in the
# batching rule; it is the reason `avail_findings` below narrows to the
# *availability* records rather than asserting the whole audit is stable
# across lengths.
"$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" audit >/dev/null \
  || fail "the primary does not audit its own availability log"
"$REF" --log "$AVAIL/log.jsonl" --root "$AVAIL" audit >/dev/null \
  || fail "the reference rejects an availability log the primary wrote"

# Both must agree on the root, which is the value a checkpoint signs.
PRIMARY_ROOT=$("$RUST" --log "$AVAIL/log.jsonl" --root "$AVAIL" audit | awk '/merkle/{print $2}')
REFERENCE_ROOT=$("$REF" --log "$AVAIL/log.jsonl" --root "$AVAIL" audit | awk '/merkle/{print $2}')
[ -n "$PRIMARY_ROOT" ] || fail "the primary printed no root"
[ "$PRIMARY_ROOT" = "$REFERENCE_ROOT" ] \
  || fail "roots differ: $PRIMARY_ROOT vs $REFERENCE_ROOT"
echo "  both audit it clean and agree on $PRIMARY_ROOT"

# What the *availability* records say must not move with the reader's epoch
# length, in either implementation. `CAIRN_EPOCH_SECONDS` is a demo
# affordance -- it exists so a shell script can cross an epoch boundary -- and
# `partition`'s own documentation promises that "nothing derived from it enters
# a record". Availability sampling broke that promise by reaching for it to
# place the anchor in time: the same log then audited clean or dirty depending
# on how the auditor happened to be configured, six times out of ten. A rule
# that depends on an environment variable is not a consensus rule, and one that
# fails six times in ten reads as flakiness rather than as a bug, which is the
# worst shape it could have.
#
# Stated as "the findings about these kinds are identical" rather than "the
# whole audit passes", so it keeps testing the anchor rather than the batching
# it sits next to. Compared across both implementations as well as across
# lengths: a value that moved identically in both would still be a consensus
# rule that reads the environment.
avail_findings() {
  CAIRN_EPOCH_SECONDS="$2" "$1" --log "$AVAIL/log.jsonl" --root "$AVAIL" audit 2>&1 \
    | grep -E 'availability|undertaking' | sort || true
}
BASELINE=$(avail_findings "$RUST" 2)
[ -z "$BASELINE" ] \
  || fail "the availability records are not clean to begin with: $BASELINE"
for LENGTH in 2 600 3600; do
  [ "$(avail_findings "$RUST" "$LENGTH")" = "$BASELINE" ] \
    || fail "the primary's availability findings move at epoch length $LENGTH"
  [ "$(avail_findings "$REF" "$LENGTH")" = "$BASELINE" ] \
    || fail "the reference's availability findings move at epoch length $LENGTH"
done
echo "  both read the same availability records at epoch lengths 2, 600 and 3600"
unset CAIRN_EPOCH_SECONDS

# And the refuse path: a promise about a root this log never had must be
# reported by both. Appended by hand-rolling the entry so it never meets
# `post_undertaking`, which is how a concatenated log would carry one.
python3 - "$AVAIL/log.jsonl" "$AVAIL/tampered.jsonl" <<'PY'
import hashlib, json, sys

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

lines = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
# Reuse a real signed undertaking and move it to a root nothing matches. The
# signature no longer covers the payload, so both implementations should refuse
# it -- on the signature if they check that first, on the root if they do not.
promise = next(e["payload"] for e in lines if e["kind"] == "undertaking")
forged = dict(promise, root="sha256:" + "00" * 32)
body = {
    "seq": len(lines),
    "prev": lines[-1]["hash"],
    "kind": "undertaking",
    "payload": forged,
    "ts": lines[-1]["ts"],
}
digest = hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()
entry = dict(body, hash=f"sha256:{digest}")
with open(sys.argv[2], "w", encoding="utf-8") as out:
    for line in lines:
        out.write(canonical(line) + "\n")
    out.write(canonical(entry) + "\n")
PY
"$RUST" --log "$AVAIL/tampered.jsonl" --root "$AVAIL" audit >/dev/null 2>&1 \
  && fail "the primary certified a forged undertaking"
"$REF" --log "$AVAIL/tampered.jsonl" --root "$AVAIL" audit >/dev/null 2>&1 \
  && fail "the reference certified a forged undertaking"
echo "  both refuse a forged promise appended past the admission rules"

printf '\n\033[32mDIFFERENTIAL OK: both implementations agree on every record in the corpus\033[0m\n'
printf '\033[32m  and on every inclusion proof over the published log\033[0m\n'
