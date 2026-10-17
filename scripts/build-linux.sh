#!/bin/bash
set -e

# Cross-compile the CLI binaries for Linux musl. Uses cargo-zigbuild + zig —
# the same mechanism as build-windows.sh and the CI release workflow.
#
# usage: build-linux.sh [x86_64|aarch64]   (default: x86_64)
ARCH="${1:-x86_64}"
case "$ARCH" in
    x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "usage: $0 [x86_64|aarch64] (default: x86_64)" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."

# Production-artifact tree discipline (refuse dirty; escape hatches leave
# marks). Runs before any tool check so refusal costs nothing.
source "$(dirname "$0")/lib/build_guard.sh"
build_guard_check "build-linux.sh" "$@"

# Check for zig
if ! command -v zig &> /dev/null; then
    echo "Error: zig is not installed. Please install it first (e.g., brew install zig)."
    exit 1
fi

# Check for cargo-zigbuild
if ! command -v cargo-zigbuild &> /dev/null; then
    echo "Installing cargo-zigbuild..."
    cargo install cargo-zigbuild
fi

# Check the rust target
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "Installing rust target $TARGET..."
    rustup target add "$TARGET"
fi

echo "Starting build for $TARGET..."

cargo zigbuild --release --target "$TARGET" \
    --bin interflow-cli --bin interflow-mesh --bin interflow-registrar

# Ship the artifacts through the guard: exact staging names, content gate
# (embedded BUILD_TAG must equal this tree's), provenance with sources.
# Dirty escapes carry the -dirty suffix in the name; the manifest records
# provenance either way.
mkdir -p artifacts
for BIN in interflow-cli interflow-mesh interflow-registrar; do
    OUTPUT_FILE="$(guard_ship_artifact \
        "target/${TARGET}/release/${BIN}" \
        "artifacts/${BIN}-linux-${ARCH}" raw)"
    echo "Built: $PWD/$OUTPUT_FILE"
    file "$OUTPUT_FILE"
done
build_guard_write_manifest "build-linux"
