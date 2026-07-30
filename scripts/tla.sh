#!/usr/bin/env bash
# Model-check every TLA+ module in spec/tla with its .cfg.
#
# Exit status is three-valued on purpose, and the reason is the same one that
# governs `Status::Unavailable` in src/verifiers/mod.rs:
#
#   0  every module was checked and every property held
#   1  a module was checked and a property was violated  -- REJECT
#   3  nothing could be checked: no JDK and no cached jar -- UNAVAILABLE
#
# A missing toolchain says nothing about the specification, exactly as a missing
# Lean says nothing about a proof. Collapsing status 3 into 0 would turn "I could
# not check" into "I checked and it passed", which is the single failure mode
# this repository cannot afford; collapsing it into 1 would make an unrelated
# environment problem look like a design bug. So it gets its own number, and CI
# decides for itself whether a skip is acceptable on that runner.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_DIR="${REPO_ROOT}/spec/tla"
CACHE_DIR="${REPO_ROOT}/.local"
JAR="${TLA_TOOLS_JAR:-${CACHE_DIR}/tla2tools.jar}"
JAR_URL="https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar"

# TLC's own heap. The configurations here are small by design (see
# spec/tla/README.md), so this is generous rather than tuned.
TLC_HEAP="${TLC_HEAP:-2G}"
TLC_WORKERS="${TLC_WORKERS:-auto}"

# Modules in dependency-of-understanding order rather than alphabetical: read
# them in this order and each one uses vocabulary the previous one introduced.
MODULES=(
  Ledger
  Checkpoint
  CommitReveal
  Verification
  Frontier
  Attribution
  Gossip
  Sync
  Partition
  Proofwork
)

SKIP=3

say() { printf '%s\n' "$*"; }
skip() {
  say ""
  say "tla.sh: SKIPPED -- $*"
  say "tla.sh: this is a skip, not a pass. Nothing was checked."
  say "tla.sh: install a JDK (brew install openjdk@21) or place tla2tools.jar at ${JAR}."
  exit "${SKIP}"
}

# -- find a JDK -------------------------------------------------------------
#
# Order is JAVA_HOME, then Homebrew's keg-only openjdk@21, then PATH. PATH is
# last because on macOS `java` is a stub that exists, is executable, and fails
# with "Unable to locate a Java Runtime" -- so presence on PATH is not evidence
# that a JVM exists, and the candidate is probed by running it.
find_java() {
  local candidates=()
  [ -n "${JAVA_HOME:-}" ] && candidates+=("${JAVA_HOME}/bin/java")
  candidates+=(
    /opt/homebrew/opt/openjdk@21/bin/java
    /opt/homebrew/opt/openjdk/bin/java
    /usr/local/opt/openjdk@21/bin/java
  )
  local on_path
  on_path="$(command -v java 2>/dev/null || true)"
  [ -n "${on_path}" ] && candidates+=("${on_path}")

  local candidate
  for candidate in "${candidates[@]}"; do
    if [ -x "${candidate}" ] && "${candidate}" -version >/dev/null 2>&1; then
      printf '%s' "${candidate}"
      return 0
    fi
  done
  return 1
}

JAVA="$(find_java || true)"
[ -n "${JAVA}" ] || skip "no working JDK found (JAVA_HOME, /opt/homebrew/opt/openjdk@21, PATH all failed to run)"

# -- find or fetch tla2tools.jar -------------------------------------------
#
# Cached under .local/, which is already gitignored. A download failure is not
# fatal on its own: a previously cached jar is enough, and only the absence of
# both is a skip.
#
# Every step here is allowed to fail without taking the script with it. The
# only question that matters is whether a jar exists at the end, and a failed
# mkdir, a missing curl or a refused connection all have the same answer: skip,
# with status 3. Under `set -e` the obvious spelling of this loop exits 1 on a
# download failure instead, which would report an offline runner as a violated
# invariant -- the exact confusion the three-valued status exists to prevent.
if [ ! -f "${JAR}" ]; then
  if mkdir -p "$(dirname "${JAR}")" 2>/dev/null; then
    say "tla.sh: fetching tla2tools.jar into ${JAR}"
    if command -v curl >/dev/null 2>&1; then
      curl -sSL --fail --retry 2 -o "${JAR}.part" "${JAR_URL}" || rm -f "${JAR}.part"
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "${JAR}.part" "${JAR_URL}" || rm -f "${JAR}.part"
    else
      say "tla.sh: neither curl nor wget is available; cannot fetch the jar"
    fi
    if [ -f "${JAR}.part" ]; then
      mv "${JAR}.part" "${JAR}" || rm -f "${JAR}.part"
    fi
  else
    say "tla.sh: cannot create $(dirname "${JAR}")"
  fi
fi
[ -f "${JAR}" ] || skip "tla2tools.jar is absent and could not be downloaded from ${JAR_URL}"

say "tla.sh: java   ${JAVA}"
say "tla.sh: jar    ${JAR}"
say "tla.sh: specs  ${SPEC_DIR}"

# TLC writes states/ and metadata next to the spec; keep that out of the tree.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/proofwork-tlc.XXXXXX")"
trap 'rm -rf "${WORK_DIR}"' EXIT

failed=()
for module in "${MODULES[@]}"; do
  tla="${SPEC_DIR}/${module}.tla"
  cfg="${SPEC_DIR}/${module}.cfg"
  if [ ! -f "${tla}" ] || [ ! -f "${cfg}" ]; then
    say ""
    say "tla.sh: FAIL ${module} -- module or config is missing"
    failed+=("${module}")
    continue
  fi

  say ""
  say "=== ${module} ============================================================"
  log="${WORK_DIR}/${module}.out"
  # -deadlock: several modules reach terminal states by design (a bounded log
  # that is full, an epoch counter at its ceiling). Deadlock is not the property
  # under test in any of them, and leaving the check on would report an
  # exhausted bound as a failure.
  if "${JAVA}" -XX:+UseParallelGC "-Xmx${TLC_HEAP}" -cp "${JAR}" tlc2.TLC \
      -config "${cfg}" \
      -workers "${TLC_WORKERS}" \
      -metadir "${WORK_DIR}/${module}" \
      -deadlock \
      "${tla}" >"${log}" 2>&1; then
    grep -E '^[0-9]+ states generated|distinct states found|Model checking completed' "${log}" || true
    say "tla.sh: OK ${module}"
  else
    cat "${log}"
    say "tla.sh: FAIL ${module}"
    failed+=("${module}")
  fi
done

say ""
if [ ${#failed[@]} -eq 0 ]; then
  say "tla.sh: all ${#MODULES[@]} modules checked, no violations"
  exit 0
fi
say "tla.sh: violations in: ${failed[*]}"
exit 1
