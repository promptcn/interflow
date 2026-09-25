#!/bin/bash
set -e

# Cross-compile the Tauri GUI for Windows and bundle the NSIS installer.
#
# The GUI must use the msvc ABI (webview2-com has no GNU story, unlike the CLI
# binaries in build-windows.sh), so this rides cargo-xwin: clang-cl/lld-link
# plus the Windows SDK/CRT slices it downloads on first run. WiX only runs on
# Windows, so MSI is not possible here; the authoritative nsis+msi installers
# are still built by the CI windows runner (.github/workflows/release.yml) and
# the artifact this produces is unsigned (expect a SmartScreen prompt) — treat
# it as a local-iteration convenience build.
cd "$(dirname "$0")/.."

# Cargo-side tools (auto-install, same policy as build-windows.sh)
if ! command -v cargo-xwin &> /dev/null; then
    echo "Installing cargo-xwin..."
    cargo install cargo-xwin
fi
if ! command -v cargo-tauri &> /dev/null; then
    echo "Installing tauri-cli..."
    cargo install tauri-cli --locked
fi

# Homebrew's llvm/lld are keg-only; link their bin dirs in before the host checks.
for KEG in /opt/homebrew/opt/llvm /opt/homebrew/opt/lld /opt/homebrew/opt/lld@21; do
    [ -x "$KEG/bin" ] && export PATH="$KEG/bin:$PATH"
done

# Host-side tools: clang-cl/llvm-rc (C code + Windows resources), lld-link
# (msvc linker), nasm (aws-lc-sys asm), makensis (NSIS compiler)
MISSING=()
for TOOL in clang-cl llvm-rc lld-link nasm makensis; do
    command -v "$TOOL" &> /dev/null || MISSING+=("$TOOL")
done
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Error: missing host tools: ${MISSING[*]}"
    echo "Install them with: brew install llvm lld nasm nsis"
    exit 1
fi

if [ ! -x node_modules/.bin/vite ]; then
    echo "Error: frontend dependencies missing — run npm install first."
    exit 1
fi

# Check the rust target
if ! rustup target list --installed | grep -q x86_64-pc-windows-msvc; then
    echo "Installing rust target x86_64-pc-windows-msvc..."
    rustup target add x86_64-pc-windows-msvc
fi

echo "Preparing cargo-xwin environment (downloads Windows SDK/CRT slices on first run)..."
# cargo-xwin only wraps the standard cargo subcommands, so instead of wrapping
# the tauri-cli invocation we export its cross environment (CC/CFLAGS plus the
# CARGO_TARGET_*_LINKER/RUSTFLAGS env config pointing at the downloaded SDK).
# The nested cargo build tauri-cli spawns inherits all of it. grep keeps the
# eval to the export lines in case xwin prints progress to stdout.
eval "$(cargo xwin env --target x86_64-pc-windows-msvc | grep '^export ')"

echo "Building NSIS installer for x86_64-pc-windows-msvc..."
# --bundles nsis overrides the ["dmg","app"] targets in tauri.conf.json; the
# vite frontend build runs via beforeBuildCommand.
cargo tauri build --target x86_64-pc-windows-msvc --bundles nsis

# Copy the artifact. Tauri names it <product>_<version>_x64-setup.exe; the
# artifacts/ convention drops the version (cf. interflow-mesh-windows-x86_64.exe).
mkdir -p artifacts
for SETUP in target/x86_64-pc-windows-msvc/release/bundle/nsis/*-setup.exe; do
    OUTPUT_FILE="artifacts/interflow-gui-windows-x86_64-setup.exe"
    cp "$SETUP" "$OUTPUT_FILE"
    echo "Built: $PWD/$OUTPUT_FILE (from $(basename "$SETUP"))"
    file "$OUTPUT_FILE"
done
