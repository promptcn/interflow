#!/bin/bash
set -e

cd "$(dirname "$0")/.."

# Production-artifact tree discipline (refuse dirty; escape hatches leave
# marks). Runs before any tool check so refusal costs nothing.
source "$(dirname "$0")/lib/build_guard.sh"
build_guard_check "build-macos.sh" "$@"

# Detect architecture
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    TARGET_NAME="x86_64"
elif [ "$ARCH" = "arm64" ]; then
    TARGET_NAME="aarch64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

echo "Starting build for macos-$TARGET_NAME..."

# Build for release
cargo build --release --bin interflow-cli --bin interflow-mesh --bin interflow-registrar

# Ship the artifacts through the guard: exact staging names, content gate
# (embedded BUILD_TAG must equal this tree's), provenance with sources.
# Dirty escapes carry the -dirty suffix in the name; the manifest records
# provenance either way.
mkdir -p artifacts
for BIN in interflow-cli interflow-mesh interflow-registrar; do
    OUTPUT_FILE="$(guard_ship_artifact \
        "target/release/${BIN}" \
        "artifacts/${BIN}-macos-$TARGET_NAME" raw)"
    echo "Built: $PWD/$OUTPUT_FILE"
    file "$OUTPUT_FILE"
done
build_guard_write_manifest "build-macos"
