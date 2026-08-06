#!/usr/bin/env bash
# Throw random JSON at both implementations and demand identical answers.
#
# `differential.sh` checks a curated corpus -- the boundary cases somebody
# thought of. This checks the ones nobody thought of, which is the only way to
# find a disagreement that is not already understood. For each input both
# implementations must agree on three things: whether it parses at all, the
# canonical bytes if it does, and the digest of those bytes.
#
# The generator is weighted toward the places encoders actually differ rather
# than toward uniform noise: integers at type boundaries, strings full of
# control characters and astral-plane codepoints, keys that sort differently
# under a locale-aware comparison than under code point, deep nesting,
# duplicate keys, and the non-canonical number forms JSON permits on input.
#
#   scripts/fuzz-differential.sh [cases] [seed]
#
# The seed is printed and accepted, so a failure is reproducible: rerun with
# the same seed and the same case comes back. A fuzzer whose failures cannot
# be reproduced is a fuzzer nobody will act on.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
REF="${REF_BIN:-./reference/rust/target/release/proofwork-reference}"
CASES="${1:-${FUZZ_CASES:-2000}}"
SEED="${2:-${FUZZ_SEED:-}}"

[ -x "$RUST" ] || { echo "building the primary..." >&2; cargo build --release --locked; }
[ -x "$REF" ] || {
  echo "building the reference..." >&2
  cargo build --release --locked --manifest-path reference/rust/Cargo.toml
}

fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

WORK=$(mktemp -d /tmp/pw-fuzz-XXXXXX)
trap 'rm -rf "$WORK"' EXIT

printf '\n\033[1m== %s random values, both implementations\033[0m\n' "$CASES"

python3 - "$WORK" "$CASES" "$SEED" <<'PY'
import json, random, sys, pathlib

work, count = pathlib.Path(sys.argv[1]), int(sys.argv[2])
seed = int(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else random.randrange(2**32)
random.seed(seed)
(work / "seed").write_text(str(seed))
print(f"  seed {seed}  (rerun with: scripts/fuzz-differential.sh {count} {seed})")

# Integers at the boundaries that separate one implementation's integer type
# from another's. A format that says "integers, bounded to signed 128-bit" has
# to mean exactly that on both sides.
EDGE_INTS = [
    0, 1, -1, 127, 128, -128, 255, 256, 32767, 65535,
    2**31 - 1, 2**31, -(2**31), 2**32 - 1, 2**32,
    2**53 - 1, 2**53, 2**53 + 1,                       # float64 loses these
    2**63 - 1, 2**63, -(2**63),
    2**64 - 1, 2**64,                                  # the reward ceiling
    2**127 - 1, -(2**127),                             # the format's own edge
    2**127, -(2**127) - 1,                             # one past it: refused
]

# Strings chosen where escaping rules diverge: the five short forms, the
# \u00XX range, DEL and forward slash (escaped by some encoders and not by
# this format), astral-plane characters needing surrogate pairs on input, and
# combining marks that a normalizing implementation would silently alter.
EDGE_STRINGS = [
    "", " ", "\t", "\n", "\r", "\x08", "\x0c", "\x00", "\x01", "\x1f",
    "\x7f", "/", "\\", '"', "\\/", "a\\\"b",
    "é", "é", "日本語", "😀", "\U0001F600\U0001F601",
    " ", " ", "﻿", " ",
    "A", "a", "Z", "z", "_", "~", "0", "9", "{", "}",
    "sha256:" + "a" * 64,
]

def value(depth=0):
    roll = random.random()
    if depth > 3 or roll < 0.30:
        pick = random.random()
        if pick < 0.30:
            return random.choice(EDGE_INTS)
        if pick < 0.60:
            return random.choice(EDGE_STRINGS)
        if pick < 0.70:
            return random.choice([True, False])
        if pick < 0.78:
            return None
        if pick < 0.90:
            return random.randint(-(2**70), 2**70)
        return "".join(chr(random.randint(1, 0x2FFF)) for _ in range(random.randint(0, 12)))
    if roll < 0.65:
        return [value(depth + 1) for _ in range(random.randint(0, 5))]
    # Keys drawn from the same edge set: ordering is by code point, and an
    # implementation sorting by anything else disagrees here first.
    return {
        str(random.choice(EDGE_STRINGS)): value(depth + 1)
        for _ in range(random.randint(0, 5))
    }

for index in range(count):
    roll = random.random()
    if roll < 0.04:
        # Raw text rather than a generated structure: non-canonical numbers,
        # duplicate keys, deep nesting, truncation. Both must refuse -- or
        # accept -- identically.
        text = random.choice([
            "1.0", "1e3", "1E3", "-0", "-0.0", "01", "1.", ".5", "+1",
            "NaN", "Infinity", "-Infinity", "'single'", "undefined",
            '{"a":1,"a":2}', '{"a":1,}', "[1,]", "{", "[", '"unterminated',
            '"\\ud800"', '"\\udc00"', '"\\ud83d\\ude00"', '"\\q"', '"\\u00zz"',
            "[" * 200 + "]" * 200, "{" * 60, " ", "", "\n\t ",
            '{"a"  :  1 , "b":[ ] }',
            '"' + "\x01" + '"',
            str(2**200), "-" + str(2**200),
        ])
    else:
        text = json.dumps(value(), ensure_ascii=random.random() < 0.5)
    (work / f"case-{index:05d}.json").write_text(text, encoding="utf-8", errors="surrogatepass")
PY

SEED_USED=$(cat "$WORK/seed")
DISAGREED=0
PARSED=0
REFUSED=0

for file in "$WORK"/case-*.json; do
  PRIMARY=$("$RUST" canon --input "$file" 2>/dev/null | head -1 || true)
  REFERENCE=$("$REF" canon --input "$file" 2>/dev/null | head -1 || true)
  if [ "$PRIMARY" != "$REFERENCE" ]; then
    DISAGREED=$((DISAGREED + 1))
    if [ "$DISAGREED" -le 5 ]; then
      printf '\033[31m  DISAGREE\033[0m  %s\n' "$file"
      printf '    input     %s\n' "$(head -c 160 "$file")"
      printf '    primary   %s\n' "$(printf '%s' "${PRIMARY:-<none>}" | head -c 160)"
      printf '    reference %s\n' "$(printf '%s' "${REFERENCE:-<none>}" | head -c 160)"
      cp "$file" "./fuzz-failure-$(basename "$file")"
      printf '    saved to  ./fuzz-failure-%s\n' "$(basename "$file")"
    fi
  fi
  case "$PRIMARY" in
    ok\ *) PARSED=$((PARSED + 1)) ;;
    *) REFUSED=$((REFUSED + 1)) ;;
  esac
done

echo "  $PARSED parsed, $REFUSED refused"
# A run where nothing parsed, or nothing was refused, is a broken generator
# rather than a clean result.
[ "$PARSED" -gt 0 ] || fail "nothing parsed; the generator is producing only garbage"
[ "$REFUSED" -gt 0 ] || fail "nothing was refused; the generator is not reaching the refusal path"
[ "$DISAGREED" -eq 0 ] || fail "$DISAGREED disagreement(s) at seed $SEED_USED"

printf '\n\033[32mFUZZ OK: %s values, both implementations agreed on every one (seed %s)\033[0m\n' \
  "$CASES" "$SEED_USED"
