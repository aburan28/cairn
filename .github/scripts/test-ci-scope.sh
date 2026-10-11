#!/usr/bin/env bash
set -euo pipefail

all='audit core examples interop ios jail macos msrv packaging reference tla ui'
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
check frozen-vectors 'conformance/vectors.json' 'interop reference'
check launch-evidence 'launch/cairn.jsonl' 'interop ui'
check ui 'ui/app/page.tsx' 'ui'
check ios 'gui/ios/Cairn.swift' 'ios'
check workflow '.github/workflows/ci.yml' "$all"
check merge-group '' "$all" merge_group
check missing-base 'docs/design.md' "$all" pull_request missing

echo 'CI scope cases passed.'
