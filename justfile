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
    cargo test --workspace --test '*'

# QUIC vs h2 concurrent-stream loss comparison (scenario benchmark; see --help for options)
bench-loss:
    cargo bench -p interflow-mesh --bench loss_hol

# soak long-run guardrail (real process topology: soak-node hub/agent processes + impairment proxy + six assertions;
# run several rounds nightly / before releases. Smoke test: `just soak -- --quick`; see --help for options)
soak:
    cargo build --release -p interflow-testkit --features fault-injection --bin interflow-soak-node
    cargo run --release -p interflow-testkit --bin soak

# Unused-dependency gate (cargo-machete; install: cargo install cargo-machete --locked)
machete:
    cargo machete

# Check dependencies for vulnerabilities
deny:
    cargo deny check 2>/dev/null || cargo install cargo-deny --locked && cargo deny check

version-contract:
    python3 scripts/check_version_contract.py

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
ci: fmt-check lint test product-language doc-surfaces
    @echo "Local CI passed"

# Release build (produces the interflow, interflow-mesh, interflow-registrar binaries)
build-release:
    cargo build --release --locked

# ===== Generic examples =====

# Scenario A: public domain → LAN service
example-public-domain-plan:
    cargo build --release --bin interflow
    "{{justfile_directory()}}/target/release/interflow" setup \
        --realm example \
        --control-endpoint 127.0.0.1:16666 \
        --registrar-endpoint https://127.0.0.1:18666 \
        --host app.example.com \
        --agent lan-agent \
        --service web \
        --service-address 127.0.0.1:3000 \
        --out "{{justfile_directory()}}/examples/public-domain-to-lan/interflow.local.toml"
    "{{justfile_directory()}}/target/release/interflow" plan apply \
        --manifest "{{justfile_directory()}}/examples/public-domain-to-lan/interflow.local.toml" \
        --issuer "{{justfile_directory()}}/examples/public-domain-to-lan/issuer" \
        --out "{{justfile_directory()}}/examples/public-domain-to-lan/dist"

example-public-domain-ingress:
    cargo run --release --bin interflow -- ingress run \
        --pack examples/public-domain-to-lan/dist/packs/ingress-edge

example-public-domain-agent:
    cargo run --release --bin interflow -- agent run \
        --pack examples/public-domain-to-lan/dist/packs/agent-lan-agent

# ===== Common =====

# GUI DMG packaging (equivalent to ./scripts/build-dmg.sh, incl. fallback cleanup of create-dmg leaks)
dmg:
    bash scripts/build-dmg.sh

# Windows GUI NSIS installer, cross-compiled from this host (msvc ABI via cargo-xwin; no MSI off-Windows)
nsis:
    bash scripts/build-windows-gui.sh

# Clean build artifacts
clean:
    cargo clean
