#!/bin/bash
# Cleanup of tauri DMG packaging leaks.
#
# The create-dmg script bundled inside tauri-bundler only cleans up on the happy path:
#   1) after hdiutil detach retries are exhausted it exits with code 16, skipping the
#      trailing rm — both the mount and rw.*.dmg are left behind
#      (the volume is often briefly held by Spotlight/mds, causing EBUSY);
#   2) the script has no trap, so an interrupted build (Ctrl+C) leaks too.
# @tauri-apps/cli is a prebuilt binary that cannot be patched locally, so this script
# is run before and after the packaging entry point (just dmg).
#
# Only images under this repository's bundle directory are handled: create-dmg's
# temporary mounts are identifiable by the /Volumes/dmg.* mount points produced by
# -mountrandom; /Volumes/Interflow* mounts created by the user double-clicking the
# final DMG are left untouched.
set -u

BUNDLE_DIR="$(cd "${1:-target/release/bundle}" 2>/dev/null && pwd)" || {
    echo "dmg-cleanup: bundle directory does not exist, nothing to clean up"
    exit 0
}

# 1. Detach leaked mounts of this repository's images (only the random /Volumes/dmg.* mount points)
hdiutil info | awk -v dir="$BUNDLE_DIR/" '
    /^image-path/ { mine = (index($0, dir) > 0) }
    mine && $1 ~ /^\/dev\// && $NF ~ /^\/Volumes\/dmg\./ { print $1 }
' | sort -u | while read -r dev; do
    echo "dmg-cleanup: detaching leaked mount $dev"
    # The temporary writable image has no concurrent writers, so a force detach is safe
    # when a plain detach fails (the volume is still being scanned by mds)
    hdiutil detach "$dev" >/dev/null 2>&1 || hdiutil detach -force "$dev" >/dev/null 2>&1
done

# 2. Delete leftover temporary writable images
rm -fv "$BUNDLE_DIR"/macos/rw.*.dmg

exit 0
