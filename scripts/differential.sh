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
cd "$(dirname "$0")/.."

RUST="${RUST_BIN:-./target/release/proofwork}"
REF="${REF_BIN:-./reference/rust/target/release/proofwork-reference}"
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

printf '\n\033[32mDIFFERENTIAL OK: both implementations agree on every record in the corpus\033[0m\n'
