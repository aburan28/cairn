#!/usr/bin/env bash
set -euo pipefail

all='audit core examples interop ios jail macos msrv packaging reference tla ui'
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

check() {
  local name="$1" paths="$2" expected="$3" event="${4:-pull_request}"
  local base="${5:-1111111111111111111111111111111111111111}"
  : > "$tmp/output"
  GITHUB_OUTPUT="$tmp/output" GITHUB_EVENT_NAME="$event" \
    CI_BASE_SHA="$base" CI_HEAD_SHA=2222222222222222222222222222222222222222 \
    CI_CHANGED_PATHS="$paths" bash .github/scripts/ci-scope.sh
  local actual
  actual="$(sed -n 's/=true$//p' "$tmp/output" | sort | tr '\n' ' ' | sed 's/ $//')"
  if [[ "$actual" != "$expected" ]]; then
    printf 'scope case %s: expected [%s], got [%s]\n' "$name" "$expected" "$actual" >&2
    return 1
  fi
}

check docs-only 'docs/design.md' ''
check core 'src/canonical.rs' 'audit core examples interop jail msrv reference tla ui'
check rust-toolchain '.cargo/config.toml' 'audit core examples interop jail msrv reference tla ui'
check python-tools 'pyproject.toml' 'core examples interop'
check ecc2k-ingest-service 'examples/ecc2k-ingest-service/period_candidate_runner.py' 'examples'
check frozen-vectors 'conformance/vectors.json' 'interop reference'
check launch-evidence 'launch/cairn.jsonl' 'interop ui'
check ui 'ui/app/page.tsx' 'ui'
check ios 'gui/ios/Cairn.swift' 'ios'
check shared-native 'gui/shared/Sources/CairnNodeKit/Reports.swift' 'ios macos'
check workflow '.github/workflows/ci.yml' "$all"
check merge-group '' "$all" merge_group
check missing-base 'docs/design.md' "$all" pull_request missing

# Git's default rename detection reports only the destination. That would let
# renaming code into docs hide the source scope, so exercise a real repository
# diff with rename detection disabled.
repo="$tmp/repo"
origin="$tmp/origin.git"
mkdir -p "$repo/src"
git -C "$repo" init -q
git -C "$repo" config user.name 'CI scope test'
git -C "$repo" config user.email ci-scope@example.invalid
printf 'source\n' > "$repo/src/canonical.rs"
git -C "$repo" add src/canonical.rs
git -C "$repo" commit -qm base
base="$(git -C "$repo" rev-parse HEAD)"
git clone --bare -q "$repo" "$origin"
git -C "$repo" remote add origin "$origin"
mkdir -p "$repo/docs"
git -C "$repo" mv src/canonical.rs docs/canonical.md
git -C "$repo" commit -qm rename
head="$(git -C "$repo" rev-parse HEAD)"
: > "$tmp/output"
(cd "$repo" && env -u CI_CHANGED_PATHS GITHUB_OUTPUT="$tmp/output" \
  GITHUB_EVENT_NAME=pull_request CI_BASE_SHA="$base" CI_HEAD_SHA="$head" \
  bash "$script_dir/ci-scope.sh")
actual="$(sed -n 's/=true$//p' "$tmp/output" | sort | tr '\n' ' ' | sed 's/ $//')"
expected='audit core examples interop jail msrv reference tla ui'
if [[ "$actual" != "$expected" ]]; then
  printf 'rename diff: expected [%s], got [%s]\n' "$expected" "$actual" >&2
  exit 1
fi

# Every ordinary scoped gate uses an exact-false skip, and cancellation must
# stop stale work while detector failures and missing outputs keep gates live.
ci_workflow="$script_dir/../workflows/ci.yml"
ios_workflow="$script_dir/../workflows/ios-app.yml"
seed_workflow="$script_dir/../workflows/seed-pod.yml"
guard_count="$(grep -Fc "if: always() && !cancelled() && (needs.changes.result != 'success' || needs.changes.outputs." "$ci_workflow")"
[[ "$guard_count" == 12 ]]
exact_false_count="$(grep -Fc " != 'false')" "$ci_workflow")"
[[ "$exact_false_count" == 12 ]]

should_run_gate() {
  local result="$1" output="$2" cancelled="$3"
  [[ "$cancelled" != true && ( "$result" != success || "$output" != false ) ]]
}
should_run_gate success false false && exit 1
should_run_gate success true false
should_run_gate failure false false
should_run_gate success '' false
should_run_gate success invalid false
should_run_gate success false true && exit 1

# Keep the callable workflow's `gui-ios / app` context on every non-cancelled
# CI run, with a Linux no-op when the classifier explicitly says false.
grep -Fq 'if: always() && !cancelled()' "$ci_workflow"
grep -Fq 'run_build: ${{ needs.changes.result != '\''success'\'' || needs.changes.outputs.ios != '\''false'\'' }}' "$ci_workflow"
grep -Fq 'uses: ./.github/workflows/ios-app.yml' "$ci_workflow"
grep -Fq 'runs-on: ${{ inputs.run_build && '\''macos-latest'\'' || '\''ubuntu-latest'\'' }}' "$ios_workflow"
grep -Fq 'if: ${{ !inputs.run_build }}' "$ios_workflow"
grep -Fq 'timeout-minutes: 10' "$seed_workflow"

echo 'CI scope cases passed.'
