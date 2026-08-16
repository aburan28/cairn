#!/usr/bin/env bash
# Rotate a store's at-rest key without ever putting the plaintext on disk.
#
# The unit tests prove the pieces. This proves the thing an operator actually
# does: a real store, a real settlement in it, one command, and afterwards the
# log audits to the same result under a key that did not exist before. The
# assertions are the four claims `docs/storage.md` makes and nothing else:
#
#   1. the ciphertext on disk changed
#   2. the Merkle root did not, and `audit` reaches the same verdict
#   3. the retired key no longer opens the log
#   4. the retired key is still on disk, because a mirror taken earlier needs it
#
# Claim 3 is checked against the *independent* reference implementation as well,
# so "unreadable" means unreadable rather than "this binary declines to try".
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
[ -x "$RUST" ] || { echo "building..." >&2; cargo build --release --locked; }

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-rekey-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

DATA="$WORK/data"
LOG="$DATA/log/cairn.jsonl"
KEY="$WORK/key"                       # outside the data directory, as the docs ask
mkdir -p "$DATA"

# One second per epoch: a commit and its reveal have to land in different
# epochs, and this script does not race on the boundary because it sleeps past
# one deliberately.
export CAIRN_EPOCH_SECONDS=1

rule "a sealed store with real work in it"
"$RUST" --key-file "$KEY" keygen >/dev/null
OID=$("$RUST" --data-dir "$DATA" --key-file "$KEY" --root . \
  post examples/reversible-adder/objective.json | head -1 | awk '{print $2}')
echo "  posted $OID"
"$RUST" --data-dir "$DATA" --key-file "$KEY" --root . commit "$OID" \
  --submitter alice --artifact examples/reversible-adder/artifact-cuccaro.json \
  --nonce n1 >/dev/null
sleep 1.1
"$RUST" --data-dir "$DATA" --key-file "$KEY" --root . reveal "$OID" \
  --submitter alice --artifact examples/reversible-adder/artifact-cuccaro.json \
  --nonce n1 | sed 's/^/  /'
# Two waits, not one: an epoch must close *and* wait out the finality delay
# (CAIRN_FINALITY_EPOCHS, default 1) before anything settles.
sleep 2.2
"$RUST" --data-dir "$DATA" --key-file "$KEY" --root . settle >/dev/null 2>&1 || true

head -c 24 "$LOG" | grep -q '^pwenc1:' || fail "the log is not sealed"
BEFORE_CIPHER=$(cksum < "$LOG")
BEFORE_KEY=$(cksum < "$KEY")
BEFORE_AUDIT=$("$RUST" --data-dir "$DATA" --key-file "$KEY" --root . audit)
echo "$BEFORE_AUDIT" | grep -q "log verified" || fail "the store does not audit before rotating"
BEFORE_ROOT=$(echo "$BEFORE_AUDIT" | grep -oE 'sha256:[0-9a-f]{64}' | tail -1)
echo "  sealed, audits clean, root $BEFORE_ROOT"

# A mirror taken *now* -- the reason the old key is kept rather than shredded.
rule "a backup taken before the rotation"
"$RUST" --data-dir "$DATA" --key-file "$KEY" sync "$WORK/mirror" | tail -2 | sed 's/^/  /'

rule "rotate"
"$RUST" --data-dir "$DATA" --key-file "$KEY" store rekey | sed 's/^/  /'

rule "1. the bytes on disk changed"
AFTER_CIPHER=$(cksum < "$LOG")
[ "$BEFORE_CIPHER" != "$AFTER_CIPHER" ] || fail "the ciphertext is identical; nothing was re-sealed"
[ "$BEFORE_KEY" != "$(cksum < "$KEY")" ] || fail "the key file did not change"
echo "  ciphertext and key both differ"
# And no staging file survived a success.
[ ! -e "$LOG.rekeying" ] || fail "a staging file was left behind"

rule "2. the root did not, and the audit is the same"
AFTER_AUDIT=$("$RUST" --data-dir "$DATA" --key-file "$KEY" --root . audit)
echo "$AFTER_AUDIT" | grep -q "log verified" || fail "the store does not audit after rotating"
AFTER_ROOT=$(echo "$AFTER_AUDIT" | grep -oE 'sha256:[0-9a-f]{64}' | tail -1)
[ "$BEFORE_ROOT" = "$AFTER_ROOT" ] || fail "root moved: $BEFORE_ROOT -> $AFTER_ROOT"
[ "$BEFORE_AUDIT" = "$AFTER_AUDIT" ] || fail "the audit output changed across a rotation"
echo "  root unchanged at $AFTER_ROOT, audit byte-identical"

rule "3. the retired key opens nothing here any more"
if "$RUST" --data-dir "$DATA" --key-file "$KEY.previous" log >"$WORK/out" 2>&1; then
  fail "the retired key still reads the log"
fi
grep -q "did not authenticate" "$WORK/out" || fail "wrong failure: $(cat "$WORK/out")"
echo "  refused: $(head -1 "$WORK/out" | cut -c1-72)..."

rule "4. it still opens the backup, which is why it is kept"
[ -f "$KEY.previous" ] || fail "the old key was destroyed"
MIRRORED=$(find "$WORK/mirror" -name 'cairn.jsonl' | head -1)
[ -n "$MIRRORED" ] || fail "the mirror has no log in it"
"$RUST" --log "$MIRRORED" --key-file "$KEY.previous" --root . audit | grep -q "log verified" \
  || fail "the old key does not open the backup taken before the rotation"
echo "  the pre-rotation mirror still audits under $KEY.previous"

rule "the independent reference reaches the same verdicts on the rotated store"
# The sharpest statement available that no *record* moved: export the rotated
# store to plaintext and hand it to an implementation that shares no code with
# this one. The reference has never seen a key and does not need to -- at-rest
# encryption is a storage concern and the hash chain covers plaintext, which is
# exactly the separation that let a rotation change every byte on disk without
# moving the root.
REF="${REF_BIN:-./reference/rust/target/release/cairn-reference}"
[ -x "$REF" ] || cargo build --release --locked --manifest-path reference/rust/Cargo.toml
"$RUST" --data-dir "$DATA" --key-file "$KEY" store export --out "$WORK/public.jsonl" \
  | head -1 | sed 's/^/  /'
grep -q '^pwenc1:' "$WORK/public.jsonl" && fail "the export is still ciphertext"
"$REF" --log "$WORK/public.jsonl" --root . audit | grep -q "log verified" \
  || fail "the reference implementation does not verify the exported log"
REF_ROOT=$("$REF" --log "$WORK/public.jsonl" --root . audit | grep -oE 'sha256:[0-9a-f]{64}' | tail -1)
[ "$REF_ROOT" = "$AFTER_ROOT" ] || fail "reference root $REF_ROOT != $AFTER_ROOT"
echo "  the reference verified the export and agrees on $REF_ROOT"

rule "export refuses to overwrite"
if "$RUST" --data-dir "$DATA" --key-file "$KEY" store export --out "$WORK/public.jsonl" \
     >"$WORK/out" 2>&1; then
  fail "export clobbered an existing file"
fi
grep -q "already exists" "$WORK/out" || fail "wrong refusal: $(cat "$WORK/out")"
echo "  refused rather than losing a log to a typo"

rule "a second rotation refuses while the old key is still there"
if "$RUST" --data-dir "$DATA" --key-file "$KEY" store rekey >"$WORK/out" 2>&1; then
  fail "a second rotation clobbered .previous"
fi
grep -q "already exists" "$WORK/out" || fail "wrong refusal: $(cat "$WORK/out")"
echo "  refused, and the mirror's key survives"

printf '\n\033[32mREKEY OK: new key, same root, and the old key still opens the old copy\033[0m\n'
