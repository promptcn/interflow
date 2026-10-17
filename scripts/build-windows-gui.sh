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

# Production-artifact tree discipline (refuse dirty; escape hatches leave
# marks). Runs before any tool check so refusal costs nothing — this is the
# GUI's production packaging path (a raw `npm run tauri build` is a dev
# build and never lands in artifacts/).
source "$(dirname "$0")/lib/build_guard.sh"
build_guard_check "build-windows-gui.sh" "$@"

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
# 7z opens the finished NSIS archive for the content gate at the end.
if ! guard_sevenzip_bin > /dev/null; then
    MISSING+=(7z)
fi
if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Error: missing host tools: ${MISSING[*]}"
    echo "Install them with: brew install llvm lld nasm nsis p7zip"
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
# Reset the NSIS staging dir first: tauri names its setups by version and
# nothing else ever cleans them out, so the dir accumulates one setup per
# version ever built here. Selection below is exact-name and would survive
# the accumulation, but a clean staging makes any surprise visible as a
# build failure instead of a pile of unrelated history.
rm -rf target/x86_64-pc-windows-msvc/release/bundle/nsis
# --bundles nsis overrides the ["dmg","app"] targets in tauri.conf.json; the
# vite frontend build runs via beforeBuildCommand.
cargo tauri build --target x86_64-pc-windows-msvc --bundles nsis

# Select the installer by its exact tauri-generated name — never a glob.
# The staging dir used to be glob-copied (*-setup.exe, last lexicographic
# round wins) and from the first double-digit version on (0.10.0 < 0.8.0 <
# 0.9.0) that shipped a stale installer while the fresh one stayed behind.
# The version contract (scripts/check_version_contract.py) keeps
# package.json == the workspace == what tauri stamps into the name, so
# reading package.json is reading the name tauri just wrote.
APP_VERSION="$(node -p "require('./package.json').version")"
PRODUCT_NAME="$(node -p "require('./src-tauri/tauri.conf.json').productName")"
STAGED_SETUP="target/x86_64-pc-windows-msvc/release/bundle/nsis/${PRODUCT_NAME}_${APP_VERSION}_x64-setup.exe"
OUTPUT_FILE="$(guard_ship_artifact "$STAGED_SETUP" \
    "artifacts/interflow-gui-windows-x86_64-setup.exe" nsis interflow-gui.exe)"
echo "Built: $PWD/$OUTPUT_FILE (from $(basename "$STAGED_SETUP"))"
file "$OUTPUT_FILE"
build_guard_write_manifest "build-windows-gui"
