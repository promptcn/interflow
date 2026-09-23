#!/bin/bash
set -e

cd "$(dirname "$0")/.."

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
cargo build --release --bin interflow --bin interflow-mesh --bin interflow-registrar

# Copy the artifacts
mkdir -p artifacts
for BIN in interflow interflow-mesh interflow-registrar; do
    OUTPUT_FILE="artifacts/${BIN}-macos-$TARGET_NAME"
    if [ -f "target/release/${BIN}" ]; then
        cp "target/release/${BIN}" "$OUTPUT_FILE"
        echo "Built: $PWD/$OUTPUT_FILE"
        file "$OUTPUT_FILE"
    else
        echo "Error: Build failed or binary not found at target/release/${BIN}"
        exit 1
    fi
done
