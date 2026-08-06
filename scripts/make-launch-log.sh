#!/usr/bin/env bash
# Build the published log in launch/ from the shipped examples.
#
# The project's one claim is that anyone can re-derive every settled result
# from a copy of the log. That is worth nothing without a copy anyone can
# actually get, so one is committed -- and this script is how it was made, so
# nobody has to take the file on faith.
#
# Re-running produces a *different* log with the same content: timestamps come
# from the wall clock and nonces from the OS, so the ids move. That is expected.
# What must not change is that the result audits, that both implementations
# agree on its Merkle root, and that the payouts follow the ratchet.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
OUT="${OUT_DIR:-launch}"

if [ ! -x "$RUST" ]; then
  echo "building release binaries..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# Everything is built in a staging directory and moved into $OUT only once it
# has audited and verified.
#
# The first version deleted the published log and then spent the better part of
# an hour rebuilding it. Any interruption in that window -- a Ctrl-C, a job
# timeout, a failed reveal under `set -e` -- left the repository's one published
# artifact truncated or missing, and the thing it is evidence *for* is that a
# copy of the log is enough to re-derive every settled result. Destroying it to
# regenerate it is the one operation that must not be able to fail halfway.
STAGE=$(mktemp -d /tmp/pw-launch-stage-XXXXXX)
LOG="$STAGE/proofwork.jsonl"
CHECKPOINT="$STAGE/checkpoint.json"
PUBKEY="$STAGE/root-key.pub"
KEY="$STAGE/secret.json"
trap 'rm -rf "$STAGE"' EXIT

# The *default* epoch length, deliberately, even though it makes this script
# take the better part of an hour.
#
# Epochs are derived from record timestamps rather than stored, so a log built
# with PROOFWORK_EPOCH_SECONDS=1 can only be audited by somebody who sets the
# same value: with the default 600 the batch records name epochs the auditor
# recomputes differently, and `proofwork audit` reports anchor and ordering
# faults on a log that is perfectly sound. Both implementations do this, and
# they agree -- it is not a bug, it is what "derived, never stored" means.
#
# For a published artifact that is fatal. A contributor's first act is to run
# `proofwork audit` with no configuration, and seeing it fail would tell them
# the project's central claim is false. So the published log uses the epoch
# length its readers will use.
EPOCH_SECONDS=${PROOFWORK_EPOCH_SECONDS:-600}
export PROOFWORK_EPOCH_SECONDS="$EPOCH_SECONDS"

# Sleep until the next epoch boundary, plus a small margin. Waiting a fixed
# EPOCH_SECONDS would work too and would take twice as long on average.
wait_for_next_epoch() {
  local now remainder
  now=$(date +%s)
  remainder=$((EPOCH_SECONDS - (now % EPOCH_SECONDS) + 2))
  printf '    (waiting %ss for the next epoch)\n' "$remainder"
  sleep "$remainder"
}

# The signing key is generated here and thrown away with the temp file, except
# for the public half, which is written beside the log. A launch artifact needs
# a key readers can pin; it does not need one anybody keeps.
python3 - "$KEY" <<'PY'
import json, secrets, sys
json.dump({"secret": secrets.token_bytes(32).hex()}, open(sys.argv[1], "w"))
PY

# Sets LAST_CLAIM, because the next submission has to cite it: once an
# objective has a frontier, every claim against it must name the holder.
LAST_CLAIM=""
submit() {
  local oid=$1 who=$2 artifact=$3 nonce=$4
  shift 4
  "$RUST" --log "$LOG" --root . commit "$oid" --submitter "$who" \
    --artifact "$artifact" --nonce "$nonce" >/dev/null
  wait_for_next_epoch
  local revealed
  revealed=$("$RUST" --log "$LOG" --root . reveal "$oid" --submitter "$who" \
    --artifact "$artifact" --nonce "$nonce" "$@")
  echo "$revealed" | sed 's/^/  /'
  # The reveal prints `claim sha256:<64 hex>` on its first line. The `log`
  # view shows *entry* hashes, which are a different thing and not citable.
  LAST_CLAIM=$(echo "$revealed" | grep -o 'sha256:[0-9a-f]\{64\}' | head -1)
  wait_for_next_epoch
  "$RUST" --log "$LOG" --root . settle >/dev/null
}

rule "a pass/fail objective, settled"
COLLATZ=$("$RUST" --log "$LOG" --root . post examples/collatz/objective.json \
  | head -1 | awk '{print $2}')
echo "  objective $COLLATZ"
submit "$COLLATZ" alice examples/collatz/artifact.json n-collatz

rule "a progressive objective, ratcheted three times"
CAPSET=$("$RUST" --log "$LOG" --root . post examples/capset_progressive/objective.json \
  | head -1 | awk '{print $2}')
echo "  objective $CAPSET"

submit "$CAPSET" alice examples/capset_progressive/artifact-12.json n-12
CLAIM12="$LAST_CLAIM"

# Every submission to an objective with a frontier must cite the claim holding
# it -- not only improvements. That rule is what makes attribution mechanical,
# so the published log should demonstrate it rather than describe it.
submit "$CAPSET" bob examples/capset_progressive/artifact-16.json n-16 --cites "$CLAIM12"
CLAIM16="$LAST_CLAIM"

submit "$CAPSET" carol examples/capset_progressive/artifact-20.json n-20 --cites "$CLAIM16"

rule "sign it"
"$RUST" --log "$LOG" --root . checkpoint --root-key "$KEY" --out "$CHECKPOINT" \
  | sed 's/^/  /'
# Reads the checkpoint it just wrote. This used to name `launch/checkpoint.json`
# outright while every other path honoured $OUT_DIR, so building anywhere else
# published the *committed* artifact's key beside a log it does not describe.
python3 - "$CHECKPOINT" "$PUBKEY" <<'PY'
import json, sys
# The public half only. The secret dies with the staging directory.
signed = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(signed["public_key"] + "\n")
PY
echo "  public key written to $PUBKEY"

rule "check what was produced"
"$RUST" --log "$LOG" --root . audit | sed 's/^/  /'
"$RUST" --log "$LOG" --root . verify --from "$CHECKPOINT" \
  --root-key "$PUBKEY" --audit | sed 's/^/  /'
"$RUST" --log "$LOG" --root . attribute | sed 's/^/  /'

# Only now is the published copy touched.
rule "publish"
mkdir -p "$OUT"
mv "$LOG" "$OUT/proofwork.jsonl"
mv "$CHECKPOINT" "$OUT/checkpoint.json"
mv "$PUBKEY" "$OUT/root-key.pub"
echo "  $OUT/proofwork.jsonl, checkpoint.json, root-key.pub"

printf '\n\033[32mLAUNCH LOG OK: %s (%s entries)\033[0m\n' \
  "$OUT/proofwork.jsonl" "$(grep -c . "$OUT/proofwork.jsonl")"
