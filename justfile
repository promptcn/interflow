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
    cargo build --release -p interflow-mesh --features fault-injection
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

# ===== Generic examples =====

# Scenario A: public domain → LAN service
example-public-domain-certs hub_dns='127.0.0.1':
    cargo build --release --bin interflow-mesh
    INTERFLOW_MESH_BIN="{{justfile_directory()}}/target/release/interflow-mesh" \
        "{{justfile_directory()}}/examples/public-domain-to-lan/generate-certs.sh" \
        --hub-dns "{{ hub_dns }}"

example-public-domain-edge:
    cargo run --release -p interflow-expose -- edge \
        --listen 0.0.0.0:8443 \
        --hub-listen 0.0.0.0:16666 \
        --routes examples/public-domain-to-lan/routes.toml \
        --client-ca demo=examples/public-domain-to-lan/certs/tenants/demo-ca.crt \
        --hub-cert examples/public-domain-to-lan/certs/hub.crt \
        --hub-key examples/public-domain-to-lan/certs/hub.key \
        --x-forwarded-for required \
        --audit-path /tmp/interflow-example-edge-audit.jsonl

example-public-domain-agent port='3000' hub_url='https://127.0.0.1:16666':
    cargo run --release -p interflow-expose -- expose {{ port }} \
        --hub {{ hub_url }} \
        --client-cert examples/public-domain-to-lan/certs/agents/lan-agent.crt \
        --client-key examples/public-domain-to-lan/certs/agents/lan-agent.key \
        --agent-id lan-agent \
        --ca-path examples/public-domain-to-lan/certs/tenants/demo-ca.crt

# Interactive initialization (generate certificates / write profile / print nginx snippet)
init:
    cargo run -p interflow-expose -- init

# Scenario B: LAN A ↔ LAN B
example-site-to-site-certs hub_dns='127.0.0.1':
    cargo build --release --bin interflow-mesh
    INTERFLOW_MESH_BIN="{{justfile_directory()}}/target/release/interflow-mesh" \
        "{{justfile_directory()}}/examples/site-to-site/generate-certs.sh" \
        --hub-dns "{{ hub_dns }}"

example-site-to-site-hub:
    cargo run --release -p interflow-mesh -- hub \
        --config examples/site-to-site/hub.toml

example-site-to-site-agent-a:
    cargo run --release -p interflow-mesh -- agent \
        --config examples/site-to-site/agent-lan-a.toml

example-site-to-site-agent-b:
    cargo run --release -p interflow-mesh -- agent \
        --config examples/site-to-site/agent-lan-b.toml

# ===== Common =====

# GUI DMG packaging (equivalent to ./scripts/build-dmg.sh, incl. fallback cleanup of create-dmg leaks)
dmg:
    bash scripts/build-dmg.sh

# Clean build artifacts
clean:
    cargo clean
