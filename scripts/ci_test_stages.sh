#!/usr/bin/env bash
# The CI test job as one script — the single source of the five cargo test
# stages and the pebble environment contract they run under.
#
# Consumers (both run the SAME definition; no per-consumer copies to drift):
#   - .github/workflows/ci.yml `test` + `test-mesh-e2e` jobs: the jobs preset
#     INTERFLOW_PEBBLE (service container) and this script reuses it,
#     extracting the trust anchor itself. Each job selects its stage subset
#     by argument (`lib bins doc rest` / `mesh`).
#   - scripts/export_public.sh: before committing an export it runs this
#     script inside the exported tree (public-CI parity — the exported tree
#     must pass its own test job locally, or the export refuses to commit).
#     No service container there: the script starts its own pebble via
#     scripts/acme-pebble.sh (requires Docker). NO arguments = all five
#     stages, so the parity contract is exactly "the full suite".
#
# Stage selection: `ci_test_stages.sh [lib|bins|doc|mesh|rest]...` — no
# arguments runs all five.
#
# Mesh e2e is the timing-sensitive tier (wall-clock-bound assertions on real
# timers: idle timeouts, heartbeats, breaker cooldowns — the 2026-10-11
# starvation backlog). On constrained runners (<= 2 cores) the mesh stage
# caps nextest to one test at a time — wall-clock traded for isolation, so
# starved-runner flakes stop moving budgets. Multi-core dev machines (and
# the export-parity run on them) keep the default jobs = cores.
#
# Runner: cargo-nextest (per-test process isolation + cross-binary
# parallelism — the e2e suite is wall-clock-bound on real timers, measured
# ~4.6x faster than sequential libtest). Doc tests stay on libtest in their
# own stage: nextest does not run doctests. cargo-nextest must be installed
# on every machine that runs this script (checked up front; ci.yml installs
# it via taiki-e/install-action).
#
# Run from the tree under test (cwd = workspace root). Stage output goes
# straight through locally; under GitHub Actions each stage tees to a log
# and failures surface as ::error:: annotations (the anonymous-log-reader
# constraint that shaped the original workflow steps).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Stage selection (see header). Bash-3.2-safe: plain string, not an array.
STAGES_REQUESTED="${*:-}"
for s in $STAGES_REQUESTED; do
  case "$s" in
    lib|bins|doc|mesh|rest) ;;
    *) echo "FAIL: unknown stage '$s' (lib|bins|doc|mesh|rest)" >&2; exit 1 ;;
  esac
done
want_stage() {
  [ -z "$STAGES_REQUESTED" ] && return 0
  case " $STAGES_REQUESTED " in *" $1 "*) return 0 ;; esac
  return 1
}

# CPU count (macOS has no nproc; 0 = unknown → leave nextest at its default).
cpu_count() {
  if command -v nproc >/dev/null 2>&1; then nproc
  elif [ "$(uname -s)" = "Darwin" ]; then sysctl -n hw.ncpu
  else echo 0; fi
}
MESH_JOBS_FLAG=""
if [ "$(cpu_count)" -gt 0 ] && [ "$(cpu_count)" -le 2 ]; then
  MESH_JOBS_FLAG="--jobs 1"
fi

# Mirror the workflow job environment.
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

command -v cargo-nextest >/dev/null 2>&1 \
  || { echo "FAIL: cargo-nextest is required to run the test stages (brew install cargo-nextest / cargo install cargo-nextest --locked)" >&2; exit 1; }

SELF_STARTED_PEBBLE=0
cleanup() {
  if [ "$SELF_STARTED_PEBBLE" = 1 ]; then
    bash "$HERE/acme-pebble.sh" down || true
  fi
}
trap cleanup EXIT

if [ -z "${INTERFLOW_PEBBLE:-}" ]; then
  # No service container (local / export-parity run): manage our own pebble.
  command -v docker >/dev/null 2>&1 \
    || { echo "FAIL: Docker is required to run the test stages (pebble ACME fixture)" >&2; exit 1; }
  eval "$(bash "$HERE/acme-pebble.sh" up)"
  SELF_STARTED_PEBBLE=1
elif [ -z "${INTERFLOW_PEBBLE_CA:-}" ]; then
  # Service container given without a trust-anchor path: extract it.
  export INTERFLOW_PEBBLE_CA="$(bash "$HERE/acme-pebble.sh" ca)"
fi

# One test stage. Local: banner + direct output. GitHub: quiet log + error
# annotations (kept byte-compatible with the former per-step workflow form:
# `::error::<label>: <line>`). The grep pattern covers BOTH runners' failure
# vocabulary: libtest's `FAILED` / `failures:` blocks and nextest's
# `FAIL [ ... ]` result lines — both print `panicked at` from the test
# thread.
_stage_impl() {
  local label="$1"
  shift
  if [ -z "${GITHUB_ACTIONS:-}" ]; then
    echo "==> ${label}"
    "$@"
    return
  fi
  set +e
  "$@" >/tmp/t.log 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    grep -E 'FAIL |FAILED|panicked at|^failures:' -A2 /tmp/t.log | head -12 | sed 's/^ *//' |
      while read -r l; do [ -n "$l" ] && echo "::error::${label}: $l"; done
  fi
  return "$rc"
}

run_stage() { # libtest runner (doc tests)
  local label="$1"
  shift
  _stage_impl "$label" cargo test "$@"
}

run_stage_next() { # cargo-nextest runner (everything else)
  local label="$1"
  shift
  _stage_impl "$label" cargo nextest run "$@"
}

if want_stage lib; then
  run_stage_next "unit tests (lib)" \
    --workspace --exclude interflow-gui --all-features --lib
fi
if want_stage bins; then
  run_stage_next "unit tests (bins)" \
    --workspace --exclude interflow-gui --all-features --bins
fi
if want_stage doc; then
  run_stage "unit tests (doc)" \
    --workspace --exclude interflow-gui --all-features --no-fail-fast --doc
fi
if want_stage mesh; then
  # $MESH_JOBS_FLAG intentionally unquoted: empty on multi-core machines,
  # "--jobs 1" on <= 2-core runners (see header).
  # shellcheck disable=SC2086
  run_stage_next "e2e tests (mesh)" \
    -p interflow-mesh --all-features --test '*' $MESH_JOBS_FLAG
fi
if want_stage rest; then
  run_stage_next "e2e tests (rest)" \
    --workspace --exclude interflow-gui --exclude interflow-mesh --all-features --test '*'
fi

echo "==> all test stages passed"
