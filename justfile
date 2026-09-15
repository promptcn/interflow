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
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# Run all tests
test:
    cargo test --workspace --no-fail-fast

# Run integration tests only
test-e2e:
    cargo test --workspace --test '*' -- --test-threads=1

# QUIC vs h2 concurrent-stream loss comparison (scenario benchmark; see --help for options)
bench-loss:
    cargo bench -p interflow-mesh --bench loss_hol

# soak long-run guardrail (real process topology: hub/agent binaries + impairment proxy + six assertions;
# run several rounds nightly / before releases. Smoke test: `just soak -- --quick`; see --help for options)
soak:
    cargo build --release -p interflow-mesh
    cargo run --release -p interflow-testkit --bin soak

# Check dependencies for vulnerabilities
deny:
    cargo deny check 2>/dev/null || cargo install cargo-deny --locked && cargo deny check

# Local CI-equivalent checks
ci: fmt-check lint test
    @echo "Local CI passed"

# Release build (produces the interflow-mesh and interflow-expose binaries)
build-release:
    cargo build --release --locked

# ===== Scenario A: ngrok-style (public domain → LAN service) =====

# Start the public edge (for development; uses the shipped public example's
# routes table — the quickstart scenario from examples/reverse-tunnel-public/)
run-edge:
    cargo run --release -p interflow-expose -- edge \
        --listen 0.0.0.0:8443 \
        --hub-listen 127.0.0.1:16666 \
        --routes examples/reverse-tunnel-public/routes.toml \
        --token dev-token

# Start the local expose client
run-expose port='3000':
    cargo run --release -p interflow-expose -- expose {{ port }}

# Interactive initialization (generate certificates / write profile / print nginx snippet)
init:
    cargo run -p interflow-expose -- init

# ===== Scenario B: site-to-site (public hub + LAN agent) =====

# Start the hub
run-hub config='crates/mesh/examples/hub.toml':
    cargo run --release -p interflow-mesh -- hub --config {{ config }}

# Start the agent
run-agent config:
    cargo run --release -p interflow-mesh -- agent --config {{ config }}

# ===== Common =====

# GUI DMG packaging (equivalent to ./build-dmg.sh, incl. fallback cleanup of create-dmg leaks)
dmg:
    bash build-dmg.sh

# Clean build artifacts
clean:
    cargo clean
