#!/usr/bin/env bash
# Six holders, none of them holding the blob, and a liar among them.
#
# The unit tests prove the arithmetic. This proves the thing an operator
# actually does: cut a real artifact, hand one shard to each of six directories
# that share nothing, lose two of them, corrupt a third, and still get the file
# back byte for byte -- with the corrupt holder named rather than merely
# outvoted.
#
# It is here because the module has no network caller yet. `docs/storage.md`
# records what that costs: `swarm::tcp` was complete, encrypted and end-to-end
# tested with **no caller in any shipped binary**, and two bugs sat in the seam
# nobody crossed. Until a transfer path exists, this script is the seam --
# separate stores, separate invocations, and a reader who is handed nothing but
# a root.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/cairn}"
if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-shard-demo-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# A real pinned checker rather than random bytes: the address this is filed
# under is the one an objective's `checker_sha256` declares, which is what makes
# a manifest checkable against something the log already fixed.
BLOB=examples/collatz/checkers/long_trajectory.py
[ -f "$BLOB" ] || fail "expected a pinned checker at $BLOB"
# Padded out so the cut has several chunks per shard; a two-kilobyte file would
# make every shard one chunk and prove nothing about the tree.
cat "$BLOB" > "$WORK/artifact.bin"
for _ in $(seq 1 8); do cat "$WORK/artifact.bin" "$WORK/artifact.bin" > "$WORK/grow"; mv "$WORK/grow" "$WORK/artifact.bin"; done
echo "  artifact: $(wc -c < "$WORK/artifact.bin" | tr -d ' ') bytes"

rule "what a (4, 2) cut would cost, before anything is written"
"$RUST" --root "$WORK/plan" shard plan "$WORK/artifact.bin" | sed 's/^/  /'
[ -d "$WORK/plan/.cairn" ] && fail "plan wrote to the store"

rule "six holders, one shard each"
for i in 0 1 2 3 4 5; do
  mkdir -p "$WORK/node-$i"
  "$RUST" --root "$WORK/node-$i" shard encode "$WORK/artifact.bin" --keep "$i" \
    | tail -2 | sed "s/^/  node-$i /"
done
ADDR=$(ls "$WORK/node-0/.cairn/shards")
echo "  address $ADDR"

rule "no holder can rebuild it alone, and each says so rather than failing oddly"
for i in 0 3; do
  OUT=$("$RUST" --root "$WORK/node-$i" shard reconstruct "$ADDR" --out "$WORK/never-$i.bin") \
    && CODE=0 || CODE=$?
  echo "$OUT" | sed "s/^/  node-$i /"
  # Exit 1 is "checked, and the answer is no". A 2 here would be "could not
  # check", and a script fetching shards until a rebuild succeeds has to be
  # able to tell those apart.
  [ "$CODE" = "1" ] || fail "one shard short should exit 1, got $CODE"
  [ -f "$WORK/never-$i.bin" ] && fail "a refused reconstruction wrote a file"
done

rule "a holder proves it has its chunk, to a reader with nothing but a root"
"$RUST" --root "$WORK/node-4" shard prove "$ADDR" --shard 4 --chunk 2 \
  --out "$WORK/proof.json" > "$WORK/prove.out"
sed 's/^/  /' "$WORK/prove.out"
# From the copy-paste line, not from the first digest in the file: with `--out`
# the proof went to a file, but without it the proof itself is on stdout and is
# full of sibling hashes that are not the root.
ROOT=$(grep -o -- '--merkle-root sha256:[0-9a-f]\{64\}' "$WORK/prove.out" | awk '{print $2}')
[ -n "$ROOT" ] || fail "no root printed for a reader to check against"
# Run from a directory with no store at all: the reader is not a node.
(cd "$WORK" && "$OLDPWD/$RUST" shard check proof.json --merkle-root "$ROOT") | sed 's/^/  /' \
  || fail "an honest proof did not check"

rule "and the same proof does not check against a different root"
OTHER=$("$RUST" --root "$WORK/node-1" shard prove "$ADDR" --shard 1 --chunk 0 \
  --out "$WORK/other.json" \
  | grep -o -- '--merkle-root sha256:[0-9a-f]\{64\}' | awk '{print $2}')
# Same blob, so the roots agree -- flip a byte of the root instead, which is the
# only way to get a well-formed root this proof was not made against.
BENT="sha256:$(printf '%s' "${ROOT#sha256:}" | tr '0-9a-f' '1-9a-f0')"
[ "$BENT" != "$ROOT" ] || fail "the bent root is the real one"
"$RUST" shard check "$WORK/proof.json" --merkle-root "$BENT" > "$WORK/bad.out" && CODE=0 || CODE=$?
sed 's/^/  /' "$WORK/bad.out"
[ "$CODE" = "1" ] || fail "a proof against the wrong root should exit 1, got $CODE"
[ "$OTHER" = "$ROOT" ] || fail "two holders of one blob disagree about its root"

rule "one holder burns down, and another starts lying"
# Exactly the parity budget, spent one way each: (4, 2) tolerates two shards
# being unusable, and it does not care whether a shard is unusable because the
# disk is gone or because its holder is dishonest. That equivalence is the
# thing worth seeing.
rm -rf "$WORK/node-5"
# node-2 flips one byte in the middle of a chunk: the subtlest corruption there
# is, and the one a length check would miss.
SHARD="$WORK/node-2/.cairn/shards/$ADDR/002"
printf '\xff' | dd of="$SHARD" bs=1 seek=777 conv=notrunc status=none
echo "  node-5 gone; node-2 corrupted at byte 777"

rule "a reader collects what is left and rebuilds anyway"
READER="$WORK/reader"
mkdir -p "$READER"
# The reader starts with the manifest and no shards -- which is all anyone needs
# in order to check what they are handed.
cp -r "$WORK/node-1/.cairn" "$READER/"
rm -f "$READER/.cairn/shards/$ADDR"/0*
for i in 0 1 2 3 4; do
  cp "$WORK/node-$i/.cairn/shards/$ADDR/00$i" "$READER/.cairn/shards/$ADDR/00$i"
done
OUT=$("$RUST" --root "$READER" shard reconstruct "$ADDR" --out "$WORK/rebuilt.bin")
echo "$OUT" | sed 's/^/  /'
# The point of the Merkle half. Without it this shard enters the linear
# combination and every output byte is wrong, with the blob digest able to
# report only that *somebody* lied.
echo "$OUT" | grep -q "rejected shard(s) 2" \
  || fail "the corrupt holder was not named"

rule "byte for byte"
cmp "$WORK/artifact.bin" "$WORK/rebuilt.bin" \
  || fail "the rebuilt file differs from the original"
echo "  $(wc -c < "$WORK/rebuilt.bin" | tr -d ' ') bytes, identical"

rule "and the store already dropped the shard that lied"
# Deleted on the read that caught it, rather than left to shadow the real one:
# `held` would go on reporting the index as present, so the fetch that would
# replace it would never be attempted.
# By field, not by substring: the summary line at the end of `ls` also says
# "held", and counting it would make this assertion pass for the wrong reason.
LEFT=$("$RUST" --root "$READER" shard ls "$ADDR" | awk '$3 == "held"' | wc -l | tr -d ' ')
echo "  $LEFT shard(s) still held by the reader"
[ "$LEFT" = "4" ] \
  || fail "expected the corrupt shard to be gone, leaving 4, got $LEFT"

printf '\n\033[32mSHARD DEMO OK: four of six shards, one of them a liar, rebuilt the file.\033[0m\n'
