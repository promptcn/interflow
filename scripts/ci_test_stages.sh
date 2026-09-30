#!/usr/bin/env bash
# The CI test job as one script — the single source of the five cargo test
# stages and the pebble environment contract they run under.
#
# Consumers (both run the SAME definition; no per-consumer copies to drift):
#   - .github/workflows/ci.yml `test` job: the job env presets
#     INTERFLOW_PEBBLE (service container) and this script reuses it,
#     extracting the trust anchor itself.
#   - scripts/export_public.sh: before committing an export it runs this
#     script inside the exported tree (public-CI parity — the exported tree
#     must pass its own test job locally, or the export refuses to commit).
#     No service container there: the script starts its own pebble via
#     scripts/acme-pebble.sh (requires Docker).
#
# Run from the tree under test (cwd = workspace root). Stage output goes
# straight through locally; under GitHub Actions each stage tees to a log
# and failures surface as ::error:: annotations (the anonymous-log-reader
# constraint that shaped the original workflow steps).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

# Mirror the workflow job environment.
export RUSTFLAGS="${RUSTFLAGS:--D warnings}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"

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
# `::error::<label>: <line>`).
run_stage() {
  local label="$1"
  shift
  if [ -z "${GITHUB_ACTIONS:-}" ]; then
    echo "==> ${label}"
    cargo test "$@"
    return
  fi
  set +e
  cargo test "$@" >/tmp/t.log 2>&1
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    grep -E 'FAILED|panicked at|^failures:' -A2 /tmp/t.log | head -12 | sed 's/^ *//' |
      while read -r l; do [ -n "$l" ] && echo "::error::${label}: $l"; done
  fi
  return "$rc"
}

run_stage "unit tests (lib)" \
  --workspace --exclude interflow-gui --all-features --no-fail-fast --lib
run_stage "unit tests (bins)" \
  --workspace --exclude interflow-gui --all-features --no-fail-fast --bins
run_stage "unit tests (doc)" \
  --workspace --exclude interflow-gui --all-features --no-fail-fast --doc
run_stage "e2e tests (mesh)" \
  -p interflow-mesh --all-features --no-fail-fast --test '*'
run_stage "e2e tests (rest)" \
  --workspace --exclude interflow-gui --exclude interflow-mesh --all-features --no-fail-fast --test '*'

echo "==> all test stages passed"
