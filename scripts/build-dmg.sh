#!/bin/bash
# GUI DMG packaging entry point (vite build + tauri build).
#
# The create-dmg bundled inside tauri-bundler only cleans up temporary mounts and
# rw.*.dmg on the happy path: when detach retries are exhausted because Spotlight
# holds the volume, it exits with code 16 and skips the final rm; the script has
# no trap either, so an interrupted build also leaks (the /Volumes/dmg.* mounts
# make Spotlight surface duplicate copies of the App).
# A trap is used here to guarantee scripts/dmg-cleanup.sh runs as a fallback on
# success, failure, or interruption.
set -e
cd "$(dirname "$0")/.."

# Production-artifact tree discipline (refuse dirty; escape hatches leave
# marks). Runs before any tool check so refusal costs nothing.
source "$(dirname "$0")/lib/build_guard.sh"
build_guard_check "build-dmg.sh" "$@"

bash scripts/dmg-cleanup.sh   # clean up leftovers from a previous run first
trap 'bash scripts/dmg-cleanup.sh' EXIT

# Reset the DMG staging dir: tauri names its images by version and nothing
# else ever cleans them out, so the dir accumulates one image per version
# ever built here (same accumulation that shipped a stale NSIS installer).
rm -rf target/release/bundle/dmg
npm run tauri build

# Provenance for what this run produced: select the image by its exact
# tauri-generated name (never a glob), gate its content (the app binary
# inside must carry this tree's BUILD_TAG), and record it — the DMG stays
# where tauri put it; the manifest in artifacts/ records tree state +
# source + sha256 so an unsigned local DMG is still attributable after the
# fact. The version contract (scripts/check_version_contract.py) keeps
# package.json == what tauri stamps into the name; tauri spells the arch
# aarch64/x64 in DMG names.
APP_VERSION="$(node -p "require('./package.json').version")"
PRODUCT_NAME="$(node -p "require('./src-tauri/tauri.conf.json').productName")"
case "$(uname -m)" in
    arm64)  DMG_ARCH=aarch64 ;;
    x86_64) DMG_ARCH=x64 ;;
    *) echo "Error: unsupported architecture $(uname -m) for DMG naming." >&2; exit 1 ;;
esac
STAGED_DMG="target/release/bundle/dmg/${PRODUCT_NAME}_${APP_VERSION}_${DMG_ARCH}.dmg"
if [ ! -f "$STAGED_DMG" ]; then
    echo "Error: expected this build's image at $STAGED_DMG — not found." >&2
    ls -l target/release/bundle/dmg >&2 2>/dev/null || true
    exit 1
fi
guard_gate_tag dmg "$STAGED_DMG" "${PRODUCT_NAME}.app/Contents/MacOS/interflow-gui"
guard_record_artifact "$STAGED_DMG"
build_guard_write_manifest "build-dmg"
