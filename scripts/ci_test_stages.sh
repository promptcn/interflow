#!/usr/bin/env bash
# The CI test job as one script — the single source of the six cargo test
# stages and the pebble environment contract they run under.
#
# Consumers (both run the SAME definition; no per-consumer copies to drift):
#   - .github/workflows/ci.yml `test` + `test-mesh-e2e` jobs: the jobs preset
#     INTERFLOW_PEBBLE (service container) and this script reuses it,
#     extracting the trust anchor itself. Each job selects its stage subset
#     by argument (`lib bins doc rest ambient-proxy` / `mesh`).
#   - scripts/export_public.sh: before committing an export it runs this
#     script inside the exported tree (public-CI parity — the exported tree
#     must pass its own test job locally, or the export refuses to commit).
#     No service container there: the script starts its own pebble via
#     scripts/acme-pebble.sh (requires Docker). NO arguments = all six
#     stages, so the parity contract is exactly "the full suite".
#
# Stage selection: `ci_test_stages.sh [lib|bins|doc|mesh|rest|ambient-proxy]...`
# — no arguments runs all six.
#
# Mesh e2e is the timing-sensitive tier (wall-clock-bound assertions on real
# timers: idle timeouts, heartbeats, breaker cooldowns — the 2026-10-11
# starvation backlog). On constrained runners (<= 2 cores) the mesh stage
# caps nextest to one test at a time — wall-clock traded for isolation, so
# starved-runner flakes stop moving budgets. Multi-core dev machines (and
# the export-parity run on them) keep the default jobs = cores.
#
# The ambient-proxy stage is an environment-class enforcement leg, not a
# feature test: it re-runs the identity-plane crates (registrar + renewal
# wholesale, plus the CLI renewal e2e) under an injected hostile proxy
# environment — unreachable proxies in every spelling reqwest reads, and an
# EMPTY no_proxy so loopback is not exempt. GitHub runners export no
# proxies, so a regression to proxy-honoring dials (dropping no_proxy() /
# direct_client) stays green in every functional stage and only reddens
# here. The stage carries its own fail-closed self-checks (see its block):
# an enforcement leg that silently lost its injection or its teeth must
# redden itself, not pass vacuously.
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
    lib|bins|doc|mesh|rest|ambient-proxy) ;;
    *) echo "FAIL: unknown stage '$s' (lib|bins|doc|mesh|rest|ambient-proxy)" >&2; exit 1 ;;
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
if want_stage ambient-proxy; then
  # Runs LAST so the build is warm from the rest stage (same job): the
  # leg pays only test runtime and re-uses the minutes the rest stage
  # already spent compiling.
  (
    export http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 \
           HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 \
           all_proxy=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 \
           no_proxy='' NO_PROXY=''
    # Self-check 1 — the injection itself (fail-closed): a refactor that
    # drops an export or the subshell scoping must redden the stage HERE,
    # not silently defang it. Port 9 sits in the privileged range: the
    # unprivileged CI runner user cannot bind it, so "unreachable" holds
    # by construction on Linux; the teeth self-check below covers any
    # other environment.
    for v in http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY; do
      if [ "${!v}" != "http://127.0.0.1:9" ]; then
        echo "FAIL: ambient-proxy stage lost its injection: $v='${!v:-<unset>}'" >&2
        exit 1
      fi
    done
    for v in no_proxy NO_PROXY; do
      if [ -n "${!v}" ]; then
        echo "FAIL: ambient-proxy stage lost its empty no_proxy: $v='${!v}'" >&2
        exit 1
      fi
    done
    # Self-check 2 — the teeth (fail-closed), at the layer the tests run
    # in: a shell-level view (self-check 1) cannot see what child
    # processes actually inherit, and a purely behavioral probe is
    # ambiguous on machines where clients fall back to system proxy
    # config when the environment is empty. So the probe asserts BOTH:
    # first that a forked child sees exactly the injected environment
    # (dead proxies, empty no_proxy), then that a known proxy-HONORING
    # client (python urllib) fails to reach a local server under it. If
    # it reaches the target, the injection defeats nothing and every
    # green below would be vacuous. This is the durable form of the
    # "remove no_proxy() and watch it go red" acceptance check, asserted
    # on every execution instead of performed once by hand.
    if ! python3 - <<'EOF'
import http.server, os, sys, threading, urllib.request

DEAD = "http://127.0.0.1:9"
for v in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
          "all_proxy", "ALL_PROXY"):
    if os.environ.get(v) != DEAD:
        print(f"child process sees {v}={os.environ.get(v)!r}, not the dead proxy")
        sys.exit(1)
for v in ("no_proxy", "NO_PROXY"):
    if os.environ.get(v, ""):
        print(f"child process sees {v}={os.environ.get(v)!r}, not empty")
        sys.exit(1)

quiet = type("Quiet", (http.server.BaseHTTPRequestHandler,),
             {"log_message": lambda self, *a: None})
server = http.server.HTTPServer(("127.0.0.1", 0), quiet)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3)
except Exception:
    sys.exit(0)  # forced through the dead proxy and died — teeth present
print("a proxy-honoring client reached its target despite the dead proxies")
sys.exit(1)  # no teeth
EOF
    then
      echo "FAIL: ambient-proxy teeth self-check failed (cause above) — the injection defeats nothing" >&2
      exit 1
    fi
    # Registrar + renewal run WHOLESALE: those two crates are the identity
    # plane, so any test added there later enrolls in this leg by default —
    # no list to keep current. The CLI stays cherry-picked to its renewal
    # e2e (the full production shape): re-running its wider e2e suite is
    # wall-clock the 45-minute budget discipline cannot buy twice.
    run_stage_next "e2e tests (registrar, ambient proxy)" \
      -p interflow-registrar --all-features
    run_stage_next "e2e tests (renewal, ambient proxy)" \
      -p interflow-renewal --all-features
    run_stage_next "e2e tests (cli renewal, ambient proxy)" \
      -p interflow-cli --all-features --test renewal
  )
fi

echo "==> all test stages passed"
