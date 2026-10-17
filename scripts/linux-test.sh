#!/usr/bin/env bash
# Linux-container test runner: reproduces CI's Linux behavior on a macOS
# host (the ad-hoc docker invocations of the 2026-10 era, now one script).
#
# Usage: scripts/linux-test.sh <cargo/nextest args...>
#   scripts/linux-test.sh cargo nextest run -p interflow-mesh --test '*'
#   RUST_LOG=interflow_mesh=debug scripts/linux-test.sh cargo nextest run ... --nocapture
#
# Repo is bind-mounted at /src; build/registry state lives in named volumes
# so the host target/ stays macOS-clean and container rebuilds stay warm.
# RUST_LOG passes through for deep-diving a single test.
#
# NOTE on load sensitivity: a multi-core container runs tests in parallel,
# which some serialized-tier budgets do not assume (see the derivation
# notes in crates/mesh/tests/e2e_target_breaker.rs) — for suite-wide runs
# that must mirror CI's <=2-core discipline, append --jobs 1.
#
# The container intentionally KEEPS any ambient proxy environment Docker
# Desktop injects: test clients must be immune to it by construction
# (interflow_testkit::http::direct_client / .no_proxy()), so a proxy-laden
# container is the stricter, more faithful environment.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm \
  -v "$REPO_ROOT":/src -w /src \
  -v interflow-target-linux:/target-linux \
  -v interflow-cargo-home:/usr/local/cargo \
  -v interflow-rustup-home:/usr/local/rustup \
  -e CARGO_TARGET_DIR=/target-linux \
  -e RUST_LOG \
  rust:slim bash -euo pipefail -c '
    export PATH=/usr/local/cargo/bin:$PATH
    if ! command -v cmake >/dev/null 2>&1; then
      apt-get update -qq >/dev/null
      apt-get install -y -qq --no-install-recommends \
        cmake build-essential pkg-config curl procps iproute2 >/dev/null
    fi
    if ! command -v cargo-nextest >/dev/null 2>&1; then
      arch=$(uname -m)
      nextest_arch=linux
      [ "$arch" = aarch64 ] && nextest_arch=linux-arm
      curl -LsSf "https://get.nexte.st/latest/$nextest_arch" \
        | tar zxf - -C /usr/local/cargo/bin
    fi
    exec "$@"
  ' -- "$@"
