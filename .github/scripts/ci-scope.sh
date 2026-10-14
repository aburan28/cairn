#!/usr/bin/env bash
set -euo pipefail

# Emit conservative job scopes for ci.yml. A missing base, unavailable object,
# or unsupported event runs every gate; uncertainty must never turn into green.
all_scopes() {
  for scope in core reference jail msrv tla interop audit ui macos ios examples packaging; do
    printf '%s=true\n' "$scope" >> "$GITHUB_OUTPUT"
  done
}

if [[ "${GITHUB_EVENT_NAME:-}" == "merge_group" ]]; then
  all_scopes
  exit 0
fi

base="${CI_BASE_SHA:-}"
head="${CI_HEAD_SHA:-}"
if [[ ! "$base" =~ ^[0-9a-f]{40}$ || ! "$head" =~ ^[0-9a-f]{40}$ ]]; then
  all_scopes
  exit 0
fi

if [[ -n "${CI_CHANGED_PATHS+x}" ]]; then
  changed_paths="$CI_CHANGED_PATHS"
elif ! git fetch --no-tags --depth=1 origin "$base"; then
  echo "Could not fetch the base commit; enabling every CI scope." >&2
  all_scopes
  exit 0
elif ! changed_paths="$(git diff --no-renames --name-only "$base" "$head")"; then
  echo "Could not compute changed paths; enabling every CI scope." >&2
  all_scopes
  exit 0
fi

declare -A run=(
    [core]=false [reference]=false [jail]=false [msrv]=false [tla]=false
  [interop]=false [audit]=false [ui]=false [macos]=false [ios]=false
  [examples]=false [packaging]=false
)

while IFS= read -r path; do
  [[ -n "$path" ]] || continue

  # Workflow edits can change what a gate means, so all gates re-evaluate.
  if [[ "$path" == .github/workflows/* || "$path" == .github/scripts/* ]]; then
    all_scopes
    exit 0
  fi

  case "$path" in
    Cargo.toml|Cargo.lock|build.rs|src/*|tests/*|benches/*|scripts/*|Makefile|.cargo/*|rust-toolchain|rust-toolchain.toml)
      run[core]=true
      run[reference]=true
      run[jail]=true
      run[msrv]=true
      run[tla]=true
      run[interop]=true
      run[audit]=true
      run[examples]=true
      run[ui]=true
      ;;
  esac

  case "$path" in
    pyproject.toml|requirements*.txt|setup.py|setup.cfg|uv.lock|.python-version)
      run[core]=true
      run[interop]=true
      run[examples]=true
      ;;
    package.json|package-lock.json|pnpm-lock.yaml|bun.lock*)
      run[ui]=true
      ;;
  esac

  case "$path" in
    reference/rust/*|conformance/*)
      run[reference]=true
      run[interop]=true
      ;;
  esac

  case "$path" in
    model/*|spec/*|specs/*|scripts/tla.sh)
      run[tla]=true
      ;;
  esac

  case "$path" in
    ui/*|launch/*)
      run[ui]=true
      ;;
  esac

  if [[ "$path" == launch/* ]]; then
    run[interop]=true
  fi
  if [[ "$path" == Cargo.toml ]]; then
    run[packaging]=true
  fi
  if [[ "$path" == ui/lib/snapshot.json ]]; then
    run[ios]=true
  fi

  case "$path" in
    gui/macos/*|gui/macos-app/*|packaging/macos/*)
      run[macos]=true
      ;;
    gui/ios/*)
      run[ios]=true
      ;;
  esac

  case "$path" in
    examples/*)
      run[examples]=true
      ;;
    packaging/*|.github/release-please-config.json)
      run[packaging]=true
      ;;
  esac

  case "$path" in
    Cargo.toml|Cargo.lock)
      run[audit]=true
      run[msrv]=true
      ;;
  esac
done <<< "$changed_paths"

for scope in "${!run[@]}"; do
  printf '%s=%s\n' "$scope" "${run[$scope]}" >> "$GITHUB_OUTPUT"
done
