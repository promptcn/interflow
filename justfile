# Justfile — common commands. Requires just: `cargo install just` or `brew install just`.
# Run `just` to list all targets.

default:
    @just --list

# Format all code
fmt:
    cargo fmt --all

# Check formatting (CI mode)
fmt-check:
    cargo fmt --all -- --check

# clippy
lint: _gc-target
    cargo clippy --workspace --all-targets -- -D warnings

# GC guard: keep target/ bounded. Runs before the heavy compile recipes:
# when target/ exceeds `threshold` GB (default 35), shrink it to `cap`
# (default 30GB) with cargo-sweep, oldest build fingerprints first —
# removed artifacts regenerate on demand at the next build. Degrades to
# an install hint when cargo-sweep is missing; the compile proceeds.
#
# Layering (2026-10-11): the hard invariant is [profile.dev]
# incremental = false in Cargo.toml — it killed the target/debug/incremental
# vector at every entry point, which this hook can never cover (RA, cargo
# aliases, tauri dev, raw cargo all bypass just). This guard only bounds the
# deps-fingerprint vector reachable from just recipes, and it converges
# precisely because incremental/ no longer exists (sweep --maxsize never
# touches it).
_gc-target threshold="35" cap="30GB":
    #!/usr/bin/env bash
    set -eu
    gb=$(du -sg target 2>/dev/null | cut -f1)
    gb=${gb:-0}
    [ "$gb" -gt {{threshold}} ] || exit 0
    echo "target/ at ${gb}GB (threshold {{threshold}}GB) — sweeping to {{cap}}"
    command -v cargo-sweep >/dev/null 2>&1 || {
        echo 'cargo-sweep missing: brew install cargo-sweep / cargo install cargo-sweep --locked — skipping GC' >&2
        exit 0
    }
    cargo sweep --maxsize "{{cap}}"

# Run all tests (cargo-nextest: per-test process isolation + cross-binary
# parallelism — the e2e suite is wall-clock-bound on timers, measured ~4.6x
# faster than a sequential libtest run. Install: brew install cargo-nextest
# or `cargo install cargo-nextest --locked`. Doc tests stay on libtest
# (nextest does not run them); --all-features matches the CI stages.)
test: _gc-target
    command -v cargo-nextest >/dev/null 2>&1 || { echo 'cargo-nextest missing: brew install cargo-nextest / cargo install cargo-nextest --locked'; exit 1; }
    cargo nextest run --workspace --all-features
    cargo test --workspace --all-features --doc --no-fail-fast

# Run integration tests only
test-e2e: _gc-target
    command -v cargo-nextest >/dev/null 2>&1 || { echo 'cargo-nextest missing: brew install cargo-nextest / cargo install cargo-nextest --locked'; exit 1; }
    cargo nextest run --workspace --all-features --test '*'

# QUIC vs h2 concurrent-stream loss comparison (scenario benchmark; see --help for options)
bench-loss:
    cargo bench -p interflow-mesh --bench loss_hol

# soak long-run guardrail (real process topology: soak-node hub/agent processes + impairment proxy + six assertions;
# run several rounds nightly / before releases. Smoke test: `just soak -- --quick`; see --help for options)
soak *args:
    cargo build --release -p interflow-testkit --features fault-injection --bin interflow-soak-node
    cargo run --release -p interflow-testkit --bin soak {{args}}

# Unused-dependency gate (cargo-machete; install: cargo install cargo-machete --locked)
machete:
    cargo machete

# Check dependencies for vulnerabilities
deny:
    cargo deny check 2>/dev/null || cargo install cargo-deny --locked && cargo deny check

version-contract:
    python3 scripts/check_version_contract.py

# Changelog accumulation guard: product-surface commits after the last
# version bump must be visible in CHANGELOG.md (entries under [Unreleased],
# or folded into the still-unreleased current section). Ships with the
# public export — the rule is diff-based and holds under both trees'
# history shapes (also in ci.yml and the export preflight).
changelog-debt:
    python3 scripts/check_changelog_debt.py


# User-facing language guard: product surfaces never speak in design
# generation numbers (the dated archive under docs/ is exempt).
product-language:
    python3 scripts/check_product_language.py

# Retired-surface guard: user-facing docs never mention CLI flags / binary
# names / config shapes that no longer exist (docs/ archives and ADRs are
# exempt). Ships with the public export; private-only paths are skipped.
doc-surfaces:
    python3 scripts/check_doc_surfaces.py

# Local CI-equivalent checks
ci: fmt-check lint test changelog-debt product-language doc-surfaces
    @echo "Local CI passed"

# Release build (produces the interflow-cli, interflow-mesh, interflow-registrar binaries)
build-release:
    cargo build --release --locked

# ===== Generic examples =====

# Scenario A: public domain → LAN service
example-public-domain-plan:
    cargo build --release --bin interflow-cli
    "{{justfile_directory()}}/target/release/interflow-cli" setup \
        --realm example \
        --control-endpoint 127.0.0.1:16666 \
        --registrar-endpoint https://127.0.0.1:18666 \
        --host app.example.com \
        --agent lan-agent \
        --service web \
        --service-address 127.0.0.1:3000 \
        --out "{{justfile_directory()}}/examples/public-domain-to-lan/interflow.local.toml"
    "{{justfile_directory()}}/target/release/interflow-cli" plan apply \
        --manifest "{{justfile_directory()}}/examples/public-domain-to-lan/interflow.local.toml" \
        --issuer "{{justfile_directory()}}/examples/public-domain-to-lan/issuer" \
        --out "{{justfile_directory()}}/examples/public-domain-to-lan/dist"

example-public-domain-ingress:
    cargo run --release --bin interflow-cli -- ingress run \
        --pack examples/public-domain-to-lan/dist/packs/ingress-edge

example-public-domain-agent:
    cargo run --release --bin interflow-cli -- agent run \
        --pack examples/public-domain-to-lan/dist/packs/agent-lan-agent

# ===== Common =====

# GUI DMG packaging (equivalent to ./scripts/build-dmg.sh, incl. fallback cleanup of create-dmg leaks)
dmg:
    bash scripts/build-dmg.sh

# Windows GUI NSIS installer, cross-compiled from this host (msvc ABI via cargo-xwin; no MSI off-Windows)
nsis:
    bash scripts/build-windows-gui.sh

# Shrink target/ below a size cap, oldest build fingerprints first
# (default 30GB, e.g. `just sweep 20GB`). Install: brew install cargo-sweep
# or `cargo install cargo-sweep --locked`.
sweep cap="30GB":
    command -v cargo-sweep >/dev/null 2>&1 || { echo 'cargo-sweep missing: brew install cargo-sweep / cargo install cargo-sweep --locked'; exit 1; }
    cargo sweep --maxsize {{cap}}

# Clean build artifacts
clean:
    cargo clean
