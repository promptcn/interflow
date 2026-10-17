#!/bin/bash
set -e

# Cross-compile the CLI binaries for Windows. Note: zig cannot cross-compile
# to msvc, so this script produces the *-gnu ABI for local convenience; the
# authoritative release artifacts are msvc, built by the CI windows runner
# (.github/workflows/release.yml).
cd "$(dirname "$0")/.."

# Production-artifact tree discipline (refuse dirty; escape hatches leave
# marks). Runs before any tool check so refusal costs nothing.
source "$(dirname "$0")/lib/build_guard.sh"
build_guard_check "build-windows.sh" "$@"

# Check for cargo-zigbuild
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install cargo-zigbuild
fi

# Check for zig
if ! command -v zig &> /dev/null; then
    echo "Error: zig is not installed. Please install it first."
    exit 1
fi

# Check the rust target
if ! rustup target list --installed | grep -q x86_64-pc-windows-gnu; then
    echo "Installing rust target x86_64-pc-windows-gnu..."
    rustup target add x86_64-pc-windows-gnu
fi

echo "Starting build for x86_64-pc-windows-gnu using cargo-zigbuild..."
# cargo-zigbuild handles the cross-compilation setup automatically
cargo zigbuild --release --target x86_64-pc-windows-gnu \
    --bin interflow-cli --bin interflow-mesh --bin interflow-registrar

# Ship the artifacts through the guard: exact staging names, content gate
# (embedded BUILD_TAG must equal this tree's), provenance with sources.
# Dirty escapes carry the -dirty suffix in the name; the manifest records
# provenance either way.
mkdir -p artifacts
for BIN in interflow-cli interflow-mesh interflow-registrar; do
    OUTPUT_FILE="$(guard_ship_artifact \
        "target/x86_64-pc-windows-gnu/release/${BIN}.exe" \
        "artifacts/${BIN}-windows-x86_64.exe" raw)"
    echo "Built: $PWD/$OUTPUT_FILE"
    file "$OUTPUT_FILE"
done
build_guard_write_manifest "build-windows"
