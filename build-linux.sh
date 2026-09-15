#!/bin/bash
set -e

# Check whether zig is installed
if ! command -v zig &> /dev/null; then
    echo "Error: zig is not installed. Please install it first (e.g., brew install zig)."
    exit 1
fi

# Check the rust target
if ! rustup target list --installed | grep -q x86_64-unknown-linux-musl; then
    echo "Installing rust target x86_64-unknown-linux-musl..."
    rustup target add x86_64-unknown-linux-musl
fi

# Set up a temporary bin directory for the wrapper scripts
# Uses the project-local .bin directory to avoid polluting the global environment
WRAPPER_DIR="$PWD/.bin"
mkdir -p "$WRAPPER_DIR"

# Create the gcc wrapper
# The key point is filtering out the --target argument passed by cargo, since it may conflict with zig cc's -target or use an incompatible format
cat << 'EOF' > "$WRAPPER_DIR/x86_64-linux-musl-gcc"
#!/bin/bash
args=()
for arg in "$@"; do
    case "$arg" in
        --target=x86_64-unknown-linux-musl) ;;
        *) args+=("$arg") ;;
    esac
done
exec zig cc -target x86_64-linux-musl "${args[@]}"
EOF

# Create the g++ wrapper
cat << 'EOF' > "$WRAPPER_DIR/x86_64-linux-musl-g++"
#!/bin/bash
args=()
for arg in "$@"; do
    case "$arg" in
        --target=x86_64-unknown-linux-musl) ;;
        *) args+=("$arg") ;;
    esac
done
exec zig c++ -target x86_64-linux-musl "${args[@]}"
EOF

# Create the ar wrapper
cat << 'EOF' > "$WRAPPER_DIR/x86_64-linux-musl-ar"
#!/bin/bash
exec zig ar "$@"
EOF

chmod +x "$WRAPPER_DIR/"*

# Set environment variables and build
export PATH="$WRAPPER_DIR:$PATH"
export CC_x86_64_unknown_linux_musl=x86_64-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=x86_64-linux-musl-g++
export AR_x86_64_unknown_linux_musl=x86_64-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=x86_64-linux-musl-gcc

echo "Starting build for x86_64-unknown-linux-musl..."

# Use RUSTFLAGS="-C link-self-contained=no" to avoid musl library conflicts
# Without this, a duplicate-definition error for the _start symbol may occur
RUSTFLAGS="-C link-self-contained=no" cargo build --release --target x86_64-unknown-linux-musl \
    --bin interflow-mesh --bin interflow-expose

# Copy the artifacts
for BIN in interflow-mesh interflow-expose; do
    OUTPUT_FILE="${BIN}-linux-x86_64"
    cp "target/x86_64-unknown-linux-musl/release/${BIN}" "$OUTPUT_FILE"
    echo "Built: $PWD/$OUTPUT_FILE"
    file "$OUTPUT_FILE"
done
