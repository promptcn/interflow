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

bash scripts/dmg-cleanup.sh   # clean up leftovers from a previous run first
trap 'bash scripts/dmg-cleanup.sh' EXIT

npm run tauri build
