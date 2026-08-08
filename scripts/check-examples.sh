#!/usr/bin/env bash
# Every example objective must hold, not just the ones the demos post.
#
# Two checks per examples/**/objective*.json:
#
#   1. Every verifier pin resolves: the file named next to a `*_sha256` field
#      (or inside a nested `{path, sha256}` block, the `statistical` shape)
#      exists and hashes to the pinned value. A stale pin is worse than a
#      missing example -- it is an open bounty nobody can ever satisfy,
#      because the id covers the pin and the artifact can never verify.
#   2. `proofwork post` accepts it, so every example passes the published
#      schema -- the contract third parties implement against -- and not only
#      the three objectives the demo scripts happen to exercise.
#
# A pinned file that does not exist is a hard failure. No placeholder pins
# (all-zero hashes) exist in examples/ today; if one is ever introduced on
# purpose, teach this script about it then rather than pre-forgiving a class
# of typo now.
set -euo pipefail
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"

if [ ! -x "$RUST" ]; then
  echo "building release binary..." >&2
  cargo build --release --locked
fi

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

# JSON extraction is python3, not grep: the pin lives in a nested object and
# grep cannot pair a hash with the sibling path field it pins.
extract_pins() {
  python3 - "$1" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    verifier = json.load(f).get("verifier", {})

# One tab-separated "path<TAB>sha256" line per pin. Handles every shape in
# examples/ -- checker/checker_sha256, evaluator/evaluator_sha256, and the
# statistical kind's nested {"path": ..., "sha256": ...} -- generically, so a
# new verifier kind that follows either convention is covered without edits.
def walk(obj):
    if not isinstance(obj, dict):
        return
    for key, value in obj.items():
        if key.endswith("_sha256") and isinstance(value, str):
            path = obj.get(key[: -len("_sha256")])
            if isinstance(path, str):
                print(f"{path}\t{value}")
        elif isinstance(value, dict):
            if isinstance(value.get("path"), str) and isinstance(value.get("sha256"), str):
                print(f"{value['path']}\t{value['sha256']}")
            walk(value)

walk(verifier)
PY
}

TMP=$(mktemp -d /tmp/pw-examples-XXXXXX)
trap 'rm -rf "$TMP"' EXIT

CHECKED=0
PINS=0

while IFS= read -r objective; do
  rule "$objective"

  while IFS=$'\t' read -r path pinned; do
    [ -n "$path" ] || continue
    [ -f "$path" ] || fail "$objective pins $path, which does not exist"
    actual=$(sha256sum "$path" | awk '{print $1}')
    [ "$actual" = "$pinned" ] \
      || fail "$objective pins $path at $pinned but the file hashes to $actual"
    echo "  pin ok  $path"
    PINS=$((PINS + 1))
  done < <(extract_pins "$objective")

  # A fresh log per objective: this checks that each objective posts cleanly
  # on its own, not that the set happens to coexist in one log.
# Suffix appended after the call, not inside the template: BSD mktemp (macOS)
# only expands `XXXXXX` at the very end, so `-XXXXXX.jsonl` comes back literal
# and `-u` still calls mkstemp -- the first run creates a real file with X's in
# its name and every run after it dies on "File exists". GNU mktemp expands it,
# which is why CI never sees this and a second local run does.
  LOG="$(mktemp -u "$TMP/log-XXXXXX").jsonl"
  "$RUST" --log "$LOG" --root . post "$objective" \
    || fail "$objective was rejected by the schema / post rules"
  CHECKED=$((CHECKED + 1))
done < <(find examples -name 'objective*.json' | sort)

[ "$CHECKED" -gt 0 ] || fail "found no examples/**/objective*.json to check"

# --------------------------------------------------------------------------
# The objective in README.md is the first code anybody reads, and a reader
# copies it. It carries a real 64-hex pin for the same reason the examples do:
# `post` refuses an objective whose pin does not match the file, so an
# abbreviated digest there is a broken example rather than a tidy one. This
# extracts the block and posts it, and requires the id to equal the shipped
# objective's -- which catches a truncated hash, a drifted statement, and a
# stale reward in one assertion.
# --------------------------------------------------------------------------
rule "the objective snippet in README.md"

python3 - > "$TMP/readme-objective.json" <<'PY'
import json, re, sys

text = open("README.md").read()
blocks = [b for b in re.findall(r"```json\n(.*?)```", text, re.S) if "GOAL-capset" in b]
if len(blocks) != 1:
    sys.exit(f"expected exactly one capset objective block in README.md, found {len(blocks)}")
# Must parse as printed: a reader copies these bytes, not a repaired version.
json.loads(blocks[0])
sys.stdout.write(blocks[0].rstrip())
PY

README_LOG="$(mktemp -u "$TMP/readme-XXXXXX").jsonl"
README_ID=$("$RUST" --log "$README_LOG" --root . post "$TMP/readme-objective.json" 2>&1 | head -1 | awk '{print $2}') \
  || fail "the README objective snippet does not post; a reader copying it gets an error"
REAL_LOG="$(mktemp -u "$TMP/real-XXXXXX").jsonl"
REAL_ID=$("$RUST" --log "$REAL_LOG" --root . post examples/capset/objective.json | head -1 | awk '{print $2}')

[ -n "$README_ID" ] \
  || fail "the README objective snippet does not post; a reader copying it gets an error"
[ "$README_ID" = "$REAL_ID" ] \
  || fail "README snippet posts as $README_ID but examples/capset/objective.json is $REAL_ID"
echo "  posts cleanly, and is byte-equivalent to examples/capset/objective.json"

printf '\n\033[32mEXAMPLES OK: %d objectives posted, %d pins verified, README snippet matches.\033[0m\n' \
  "$CHECKED" "$PINS"
