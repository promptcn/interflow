#!/bin/bash
# build_guard.sh — the production-build discipline, single-sourced.
#
# Two orthogonal axes, one library:
#
#   1. TREE discipline (build_guard_check): a production artifact leaves
#      this tree only from a PROVABLY clean one. The embedded BUILD_TAG
#      already marks a dirty build "after the fact" (crates/buildinfo) —
#      this guard is the "before the fact" half: it refuses to produce
#      artifacts at all, and every escape is forced to leave marks (a
#      -dirty artifact-name suffix AND a provenance manifest).
#
#   2. SHIPPING discipline (guard_ship_artifact / guard_gate_tag): what
#      lands in artifacts/ is selected by EXACT name and proves its content
#      identity — the artifact's embedded BUILD_TAG must equal this tree's
#      tag — before the build script may report success. The tree axis
#      answers "was the tree clean", the shipping axis answers "is the
#      content what this tree produced"; a clean tree shipping a stale
#      artifact is exactly the failure this half exists to prevent.
#      A staging-dir glob copy picked the lexicographically-last setup —
#      from the first double-digit version on, no longer the newest — and
#      shipped a stale installer with a spotless manifest.
#
# Fail-closed by design:
#   dirty git tree            -> refuse; --allow-dirty to proceed (suffixed)
#   not a git work tree       -> refuse; --allow-exported to proceed
#                                (the export flow's own porcelain
#                                discipline vouches for the tree)
#   clean tree                -> build; names unmodified
#   staging source missing    -> refuse (exact-name selection, no globs)
#   artifact tag mismatch     -> refuse ("installer content tag mismatch");
#                                the copied file is removed again
#
# Production surface definition: artifacts come out of scripts/build-*.sh
# only, and they enter artifacts/ (or get manifest-recorded) only through
# guard_ship_artifact / guard_record_artifact. A raw `npm run tauri build`
# / `cargo build` is a dev build — it never lands in artifacts/ and this
# guard does not apply to it.
#
# Usage in a build script (after cd to the repo root, BEFORE any tool
# checks so refusal costs nothing):
#
#   source "$(dirname "$0")/lib/build_guard.sh"
#   build_guard_check "build-<flavor>.sh" "$@"
#   ...build into target/...
#   OUTPUT_FILE="$(guard_ship_artifact "target/<exact-staging-path>" \
#       "artifacts/<name>" raw)"          # cp + content gate + provenance
#   build_guard_write_manifest "build-<flavor>"
#
# The check accepts --allow-dirty / --allow-exported among the script's
# own arguments, and leaves these shell variables for the manifest:
#   GUARD_TREE_STATE   clean | dirty | exported
#   GUARD_ESCAPE       "" | "--allow-dirty" | "--allow-exported"
#   GUARD_DIRTY_SUFFIX "" | "-dirty"      (also consumed by guard_artifact_name)
#   GUARD_GIT_DESCRIBE / GUARD_GIT_COMMIT (empty on an exported tree)
#
# Self-contained: bash + git only for the tree axis; the content gates use
# strings (binutils) always, 7z (p7zip/sevenzip) for NSIS installers and
# hdiutil for DMGs when those modes run. `--self-test` (below) is the CI
# guard job's fixture and needs python3 to validate the manifest JSON.
# (No `set -e`/`set -u` here on purpose: this file is sourced into build
# scripts whose shell options are their own contract; the functions manage
# their own error paths explicitly.)

# Provenance records queued by guard_ship_artifact/guard_record_artifact,
# tab-separated lines (artifact<TAB>source). Kept in a FILE, not a shell
# variable: scripts capture the shipped path through a command
# substitution, which runs the function in a subshell — in-memory records
# would silently vanish with it. Every build_guard_check resets the queue;
# build_guard_write_manifest serializes it.
GUARD_RECORDS="artifacts/.build-guard-records"

# Parses the escape hatches out of the caller's arguments and enforces the
# tree discipline. Returns non-zero (with the reason on stderr) on refusal.
build_guard_check() {
    local script="$1"
    shift
    local allow_dirty=0 allow_exported=0 arg
    for arg in "$@"; do
        case "$arg" in
            --allow-dirty) allow_dirty=1 ;;
            --allow-exported) allow_exported=1 ;;
        esac
    done

    rm -f "$GUARD_RECORDS"
    GUARD_DIRTY_SUFFIX=""
    GUARD_ESCAPE=""
    GUARD_TREE_STATE="clean"
    GUARD_GIT_DESCRIBE=""
    GUARD_GIT_COMMIT=""

    if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if [ "$allow_exported" -eq 1 ]; then
            GUARD_TREE_STATE="exported"
            GUARD_ESCAPE="--allow-exported"
            echo "build-guard: not a git work tree — building with --allow-exported; the manifest will record it." >&2
            return 0
        fi
        echo "Error: [$script] cannot verify tree cleanliness: not a git work tree." >&2
        echo "  Production artifacts build from a verifiable tree or not at all." >&2
        echo "  If this is an exported tree whose cleanliness is vouched for elsewhere, rerun with --allow-exported." >&2
        return 1
    fi

    GUARD_GIT_DESCRIBE="$(git describe --tags --always 2>/dev/null || true)"
    GUARD_GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || true)"

    local dirty count
    dirty="$(git status --porcelain)"
    if [ -z "$dirty" ]; then
        return 0
    fi
    count="$(printf '%s\n' "$dirty" | sed '/^$/d' | wc -l | tr -d ' ')"
    if [ "$allow_dirty" -eq 1 ]; then
        GUARD_TREE_STATE="dirty"
        GUARD_ESCAPE="--allow-dirty"
        GUARD_DIRTY_SUFFIX="-dirty"
        echo "build-guard: DIRTY TREE ($count entries) — building with --allow-dirty; every artifact name carries a -dirty suffix." >&2
        printf '%s\n' "$dirty" | sed '/^$/d' | head -5 | sed 's/^/    /' >&2
        [ "$count" -gt 5 ] && echo "    … ($((count - 5)) more)" >&2
        return 0
    fi
    echo "Error: [$script] refusing to build production artifacts from a dirty tree ($count entries)." >&2
    printf '%s\n' "$dirty" | sed '/^$/d' | head -5 | sed 's/^/    /' >&2
    [ "$count" -gt 5 ] && echo "    … ($((count - 5)) more)" >&2
    echo "  Commit or stash first. If this is intentional, rerun with --allow-dirty — every artifact will be suffixed -dirty and the manifest will say so." >&2
    return 1
}

# The single point where the dirty suffix meets a file name: inserted
# before the final extension (foo-setup.exe -> foo-setup-dirty.exe), or
# appended when there is none (interflow-cli-linux-x86_64 -> …-x86_64-dirty).
# Scripts never concatenate GUARD_DIRTY_SUFFIX by hand.
guard_artifact_name() {
    local name="$1"
    if [ -z "$GUARD_DIRTY_SUFFIX" ]; then
        printf '%s\n' "$name"
        return 0
    fi
    case "$name" in
        *.exe | *.dmg | *.msi | *.zip)
            printf '%s%s.%s\n' "${name%.*}" "$GUARD_DIRTY_SUFFIX" "${name##*.}"
            ;;
        *)
            printf '%s%s\n' "$name" "$GUARD_DIRTY_SUFFIX"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Content identity: the tag every Interflow binary embeds (buildinfo).
# ---------------------------------------------------------------------------

# Mirrors crates/buildinfo/build.rs EXACTLY: {commit-date}_{short-hash} plus
# -dirty when the porcelain is non-empty, or "unknown" off a git tree
# (build.rs anchors on .git/HEAD, so linked worktrees are "unknown" there
# too — mirrored by the same existence check). The mirror is fail-closed by
# construction: if build.rs ever changes the formula, the two disagree,
# every content gate fails, and the build stops — drift cannot pass
# silently. This function deliberately derives the tag itself and takes no
# parameter: the expected identity is never caller-supplied.
guard_expected_build_tag() {
    local root date hash
    root="$(git rev-parse --show-toplevel 2>/dev/null)" || { printf 'unknown\n'; return 0; }
    [ -e "$root/.git/HEAD" ] || { printf 'unknown\n'; return 0; }
    date="$(git -C "$root" log -1 --format=%cs 2>/dev/null)" || { printf 'unknown\n'; return 0; }
    hash="$(git -C "$root" rev-parse --short HEAD 2>/dev/null)" || { printf 'unknown\n'; return 0; }
    if [ -n "$(git -C "$root" status --porcelain 2>/dev/null)" ]; then
        printf '%s_%s-dirty\n' "$date" "$hash"
    else
        printf '%s_%s\n' "$date" "$hash"
    fi
}

# Any of the Homebrew spellings (p7zip's 7z, sevenzip's 7zz/7zzs) prints
# the binary path; non-zero when none is on PATH.
guard_sevenzip_bin() {
    local b
    for b in 7z 7zz 7zzs; do
        if command -v "$b" >/dev/null 2>&1; then
            command -v "$b"
            return 0
        fi
    done
    return 1
}

# strings + fixed-string equality against the expected tag. On mismatch the
# diagnostic names the expected tag and the best-effort found one (buildinfo
# embeds the tag inside "0.10.0 (2026-10-13_abc1234)" — the parenthesized
# form is distinctive enough to report).
_guard_grep_tag() {
    local probe="$1" expected="$2" display="$3" what="${4:-binary}" found
    if ! strings -a "$probe" | grep -qF -- "$expected"; then
        found="$(strings -a "$probe" \
            | grep -oE '\([0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9a-f]{7,40}(-dirty)?\)' | head -1)"
        echo "build-guard: ${what} content tag mismatch: expected $expected, found ${found:-no tag} — refusing to ship: $display" >&2
        return 1
    fi
    echo "build-guard: content gate passed: $display carries $expected" >&2
    return 0
}

# The content gate: demand THIS tree's BUILD_TAG from the artifact itself,
# so a stale or wrongly-selected artifact fails the build instead of
# shipping. Modes (explicit — never sniffed from the file name):
#   raw  <file>                     strings the file directly (PE/ELF/Mach-O)
#   nsis <installer> <inner-exe>    7z-extract <inner-exe>, then strings it
#                                   (the NSIS shell defeats a direct grep)
#   dmg  <image> <inner-relpath>    attach read-only, strings <inner-relpath>
# Off a git tree the embedded tag is "unknown" by design and carries no
# identity, so the gate degrades to open-only (extraction must still
# succeed) and says so loudly — grepping for the literal "unknown" would
# match nearly anything.
guard_gate_tag() {
    local mode="$1" file="$2" inner="${3:-}"
    local expected tmp bin rc mnt
    expected="$(guard_expected_build_tag)"

    case "$mode" in
        raw)
            if [ "$expected" = "unknown" ]; then
                echo "build-guard: content gate degraded (no git tree — tag carries no identity): $file opened as raw binary, tag equality skipped." >&2
                return 0
            fi
            _guard_grep_tag "$file" "$expected" "$file" binary
            return
            ;;
        nsis)
            if [ -z "$inner" ]; then
                echo "build-guard: guard_gate_tag nsis needs the inner exe name." >&2
                return 1
            fi
            bin="$(guard_sevenzip_bin)" || {
                echo "build-guard: nsis gate needs 7z (brew install p7zip) to open: $file" >&2
                return 1
            }
            tmp="$(mktemp -d)"
            # p7zip opens makensis output; a bare archive-root name is the
            # filter. The exit code is not trusted across NSIS dialects —
            # the extracted file is the gate.
            "$bin" x -y -o"$tmp" "$file" "$inner" >/dev/null 2>&1 || true
            if [ ! -f "$tmp/$inner" ]; then
                rm -rf "$tmp"
                echo "build-guard: nsis gate cannot extract '$inner' from: $file" >&2
                return 1
            fi
            if [ "$expected" = "unknown" ]; then
                echo "build-guard: content gate degraded (no git tree): $file opened, '$inner' present, tag equality skipped." >&2
                rm -rf "$tmp"
                return 0
            fi
            rc=0
            _guard_grep_tag "$tmp/$inner" "$expected" "$file" installer || rc=$?
            rm -rf "$tmp"
            return "$rc"
            ;;
        dmg)
            if [ -z "$inner" ]; then
                echo "build-guard: guard_gate_tag dmg needs the inner binary path." >&2
                return 1
            fi
            tmp="$(mktemp -d)"
            mnt="$tmp/mnt"
            mkdir -p "$mnt"
            if ! hdiutil attach -readonly -nobrowse -mountpoint "$mnt" "$file" >/dev/null 2>&1; then
                rm -rf "$tmp"
                echo "build-guard: dmg gate cannot attach: $file" >&2
                return 1
            fi
            if [ ! -f "$mnt/$inner" ]; then
                hdiutil detach "$mnt" >/dev/null 2>&1 || true
                rm -rf "$tmp"
                echo "build-guard: dmg gate: '$inner' not found in: $file" >&2
                return 1
            fi
            if [ "$expected" = "unknown" ]; then
                echo "build-guard: content gate degraded (no git tree): $file opened, '$inner' present, tag equality skipped." >&2
                hdiutil detach "$mnt" >/dev/null 2>&1 || true
                rm -rf "$tmp"
                return 0
            fi
            rc=0
            _guard_grep_tag "$mnt/$inner" "$expected" "$file" installer || rc=$?
            hdiutil detach "$mnt" >/dev/null 2>&1 || true
            rm -rf "$tmp"
            return "$rc"
            ;;
        *)
            echo "build-guard: guard_gate_tag: unknown mode '$mode' (raw|nsis|dmg)" >&2
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Shipping: the only sanctioned way a file enters artifacts/.
# ---------------------------------------------------------------------------

# Queue a provenance record (tab-separated pair; split again by the
# manifest writer — tabs cannot appear in these controlled paths). File-
# backed so records survive command-substitution subshells.
_guard_record() {
    mkdir -p "$(dirname "$GUARD_RECORDS")"
    printf '%s\t%s\n' "$1" "$2" >> "$GUARD_RECORDS"
}

# The front door for production artifacts: copy an EXACT staging path (no
# globs — cf. the bug doc) into artifacts/, gate the FINAL artifact's
# content (the copy is what ships, so the copy is what gets verified), and
# queue the provenance record. Prints the output path on stdout; on a gate
# failure the copied file is removed again so artifacts/ never holds
# unverified bytes. Optional gate modes are guard_gate_tag's (raw needs no
# inner argument).
guard_ship_artifact() {
    local src="$1" dst="$2" mode="${3:-}" inner="${4:-}" out
    if [ ! -f "$src" ]; then
        echo "build-guard: refusing to ship — staging source not found: $src" >&2
        echo "  Selection is by exact name; a missing source means the build did not produce what was expected." >&2
        return 1
    fi
    mkdir -p "$(dirname "$dst")"
    out="$(guard_artifact_name "$dst")"
    cp "$src" "$out" || return 1
    if [ -n "$mode" ]; then
        if ! guard_gate_tag "$mode" "$out" "$inner"; then
            rm -f "$out"
            return 1
        fi
    fi
    _guard_record "$out" "$src"
    printf '%s\n' "$out"
}

# Provenance without a copy (build-dmg keeps the DMG where tauri put it).
# Gate the file first when it carries content identity:
#   guard_gate_tag dmg "$STAGED" "<inner>"; guard_record_artifact "$STAGED"
guard_record_artifact() {
    local file="$1" source="${2:-$1}"
    if [ ! -f "$file" ]; then
        echo "build-guard: cannot record missing file: $file" >&2
        return 1
    fi
    _guard_record "$file" "$source"
}

# sha256 helper across the macOS/linux divide.
_guard_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Minimal JSON string escaping for the manifest's controlled values
# (script names, describe output, file names — no control characters by
# construction, but quotes and backslashes are escaped anyway).
_guard_json_str() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

_guard_json_str_or_null() {
    if [ -z "$1" ]; then
        printf 'null'
    else
        printf '"%s"' "$(_guard_json_str "$1")"
    fi
}

# Writes the provenance manifest for this build run:
# artifacts/build-manifest.<name>.json — one per script, additive, never
# merged (bash has no trustworthy JSON merge; a scattered-but-honest file
# beats a silently clobbered one). After-the-fact auditing pairs this with
# the embedded BUILD_TAG: the manifest answers "what tree, what escape,
# what source staged each artifact", the binary answers "what actually
# shipped". Schema 2: every artifact entry carries its staging SOURCE
# (schema 1 recorded only output basenames — a glob loop that overwrote
# one output three times looked indistinguishable from a clean ship).
build_guard_write_manifest() {
    local name="$1"
    if [ "$#" -ne 1 ]; then
        echo "build-guard: build_guard_write_manifest takes only the script name (schema 2); artifact records come from guard_ship_artifact / guard_record_artifact." >&2
        return 1
    fi
    if [ ! -s "$GUARD_RECORDS" ]; then
        echo "build-guard: nothing recorded — no manifest written (guard_ship_artifact / guard_record_artifact first)." >&2
        return 0
    fi
    local out="artifacts/build-manifest.${name}.json"
    mkdir -p artifacts
    local ts bytes sum artifact source first=1
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    {
        printf '{\n'
        printf '  "schema": 2,\n'
        printf '  "script": "%s",\n' "$(_guard_json_str "$name")"
        printf '  "timestamp_utc": "%s",\n' "$ts"
        printf '  "git": {\n'
        printf '    "describe": %s,\n' "$(_guard_json_str_or_null "$GUARD_GIT_DESCRIBE")"
        printf '    "commit": %s\n' "$(_guard_json_str_or_null "$GUARD_GIT_COMMIT")"
        printf '  },\n'
        printf '  "tree_state": "%s",\n' "$GUARD_TREE_STATE"
        printf '  "escape_hatch": %s,\n' "$(_guard_json_str_or_null "$GUARD_ESCAPE")"
        printf '  "artifacts": [\n'
        while IFS=$'\t' read -r artifact source; do
            [ -n "$artifact" ] || continue
            if [ ! -f "$artifact" ]; then
                echo "build-guard: manifest artifact missing: $artifact" >&2
                return 1
            fi
            bytes="$(wc -c < "$artifact" | tr -d ' ')"
            sum="$(_guard_sha256 "$artifact")"
            if [ "$first" -eq 1 ]; then
                first=0
            else
                printf ',\n'
            fi
            printf '    {"name": "%s", "source": "%s", "sha256": "%s", "bytes": %s}' \
                "$(_guard_json_str "$(basename "$artifact")")" \
                "$(_guard_json_str "$source")" "$sum" "$bytes"
        done < "$GUARD_RECORDS"
        printf '\n  ]\n}\n'
    } > "$out"
    echo "Manifest: $PWD/$out"
}

# ---------------------------------------------------------------------------
# Self-test: the CI build-guard job's fixture, runnable anywhere with
# bash + git (+ python3 for manifest validation; 7z/hdiutil gates are
# exercised when the tools are present and reported skipped otherwise).
# ---------------------------------------------------------------------------
_guard_selftest() {
    local tmp nogit failures=0
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    # A fresh git fixture: one commit (a .gitignore for artifacts/ and the
    # fixture scratch, like the real tree, so no untracked output can dirty
    # the reading — the gate re-derives the tag per call and a dirty
    # porcelain would flip every later fixture to -dirty), clean tree.
    (
        cd "$tmp" || exit 1
        git init -q .
        git config user.email guard@test && git config user.name guard
        {
            printf 'artifacts/\n'
            printf 'target/\n'
            printf 'raw-*.bin\n'
            printf '*.exe\n'
            printf '*.dmg\n'
            printf 'mnt-*/\n'
            printf '*.err\n'
        } > .gitignore
        echo base > tracked.txt
        git add .gitignore tracked.txt
        git commit -qm base
    ) || { echo "FAIL: git fixture setup"; return 1; }

    echo "self-test: clean tree"
    (
        cd "$tmp" || exit 1
        build_guard_check test-script
        [ "$GUARD_TREE_STATE" = "clean" ] && [ -z "$GUARD_DIRTY_SUFFIX" ] && [ -z "$GUARD_ESCAPE" ]
    ) || failures=$((failures + 1))

    echo "self-test: dirty tree refused, escape hatch named"
    (
        cd "$tmp" || exit 1
        echo dirt >> tracked.txt
        if build_guard_check test-script 2>/tmp/guard-dirty.err; then
            echo "dirty tree was NOT refused" >&2
            exit 1
        fi
        grep -q -- "--allow-dirty" /tmp/guard-dirty.err
    ) || failures=$((failures + 1))

    echo "self-test: --allow-dirty passes and marks everything"
    (
        cd "$tmp" || exit 1
        build_guard_check test-script --allow-dirty
        [ "$GUARD_TREE_STATE" = "dirty" ] \
            && [ "$GUARD_DIRTY_SUFFIX" = "-dirty" ] \
            && [ "$GUARD_ESCAPE" = "--allow-dirty" ]
    ) || failures=$((failures + 1))

    echo "self-test: artifact-name suffixing"
    (
        cd "$tmp" || exit 1
        build_guard_check test-script --allow-dirty
        [ "$(guard_artifact_name "artifacts/interflow-cli-linux-x86_64")" = "artifacts/interflow-cli-linux-x86_64-dirty" ] \
            && [ "$(guard_artifact_name "artifacts/interflow-gui-windows-x86_64-setup.exe")" = "artifacts/interflow-gui-windows-x86_64-setup-dirty.exe" ]
    ) || failures=$((failures + 1))
    (
        cd "$tmp" || exit 1
        git checkout -q -- tracked.txt
        build_guard_check test-script
        [ "$(guard_artifact_name "x.exe")" = "x.exe" ] \
            && [ "$(guard_artifact_name "x")" = "x" ]
    ) || failures=$((failures + 1))

    echo "self-test: non-git tree fail-closed, --allow-exported opens it"
    nogit="$(mktemp -d)"
    (
        cd "$nogit" || exit 1
        if build_guard_check test-script 2>"$nogit/guard-nogit.err"; then
            echo "non-git tree was NOT refused" >&2
            exit 1
        fi
        grep -q -- "--allow-exported" "$nogit/guard-nogit.err"
    ) || failures=$((failures + 1))
    (
        cd "$nogit" || exit 1
        build_guard_check test-script --allow-exported
        [ "$GUARD_TREE_STATE" = "exported" ] && [ -z "$GUARD_DIRTY_SUFFIX" ]
    ) || failures=$((failures + 1))

    echo "self-test: expected-tag mirror (clean/dirty/exported)"
    (
        cd "$tmp" || exit 1
        build_guard_check test-script
        exp="$(git log -1 --format=%cs)_$(git rev-parse --short HEAD)"
        [ "$(guard_expected_build_tag)" = "$exp" ]
    ) || failures=$((failures + 1))
    (
        cd "$tmp" || exit 1
        echo dirt >> tracked.txt
        exp="$(git log -1 --format=%cs)_$(git rev-parse --short HEAD)-dirty"
        [ "$(guard_expected_build_tag)" = "$exp" ]
        git checkout -q -- tracked.txt
    ) || failures=$((failures + 1))
    [ "$(cd "$nogit" && guard_expected_build_tag)" = "unknown" ] \
        || failures=$((failures + 1))
    rm -rf "$nogit"

    # From here on the fixtures embed the fixture tree's own tag; the gate
    # derives the expectation itself, so pass = same tag, fail = any other.
    local tag
    tag="$(cd "$tmp" && guard_expected_build_tag)"

    echo "self-test: raw content gate (pass / mismatch)"
    (
        cd "$tmp" || exit 1
        printf 'fixture-binary 0.10.0 (%s)\n' "$tag" > raw-ok.bin
        printf 'fixture-binary 0.9.0 (2026-01-01_deadbeef)\n' > raw-stale.bin
        guard_gate_tag raw raw-ok.bin \
            && ! guard_gate_tag raw raw-stale.bin 2>raw-stale.err \
            && grep -q "content tag mismatch" raw-stale.err \
            && grep -qF "2026-01-01_deadbeef" raw-stale.err
    ) || failures=$((failures + 1))

    echo "self-test: nsis content gate (pass / mismatch / unopenable)"
    local sevenzip
    if sevenzip="$(cd "$tmp" && guard_sevenzip_bin)"; then
        (
            cd "$tmp" || exit 1
            printf 'fixture-inner 0.10.0 (%s)\n' "$tag" > interflow-gui.exe
            "$sevenzip" a -y nsis-ok.exe interflow-gui.exe >/dev/null
            printf 'fixture-inner 0.9.0 (2026-01-01_deadbeef)\n' > interflow-gui.exe
            "$sevenzip" a -y nsis-stale.exe interflow-gui.exe >/dev/null
            head -c 2048 /dev/urandom > nsis-broken.exe
            guard_gate_tag nsis nsis-ok.exe interflow-gui.exe \
                && ! guard_gate_tag nsis nsis-stale.exe interflow-gui.exe 2>nsis-stale.err \
                && grep -q "installer content tag mismatch" nsis-stale.err \
                && ! guard_gate_tag nsis nsis-broken.exe interflow-gui.exe 2>nsis-broken.err \
                && grep -q "cannot extract" nsis-broken.err
        ) || failures=$((failures + 1))
    else
        echo "  SKIPPED: no 7z on PATH (brew install p7zip / apt p7zip-full)"
    fi

    echo "self-test: dmg content gate (pass / mismatch)"
    if command -v hdiutil >/dev/null 2>&1; then
        (
            cd "$tmp" || exit 1
            inner="Interflow.app/Contents/MacOS/interflow-gui"
            for variant in ok stale; do
                hdiutil create -size 4m -fs HFS+ -volname "Interflow-$variant" "dmg-$variant.dmg" >/dev/null 2>&1
                mkdir -p "mnt-$variant"
                hdiutil attach -mountpoint "mnt-$variant" -nobrowse "dmg-$variant.dmg" >/dev/null 2>&1
                mkdir -p "mnt-$variant/$(dirname "$inner")"
                if [ "$variant" = ok ]; then
                    printf 'fixture-app 0.10.0 (%s)\n' "$tag" > "mnt-$variant/$inner"
                else
                    printf 'fixture-app 0.9.0 (2026-01-01_deadbeef)\n' > "mnt-$variant/$inner"
                fi
                hdiutil detach "mnt-$variant" >/dev/null 2>&1
            done
            guard_gate_tag dmg dmg-ok.dmg "$inner" \
                && ! guard_gate_tag dmg dmg-stale.dmg "$inner" 2>dmg-stale.err \
                && grep -q "installer content tag mismatch" dmg-stale.err
        ) || failures=$((failures + 1))
    else
        echo "  SKIPPED: no hdiutil on PATH (exercised by every real build-dmg.sh run on macOS)"
    fi

    echo "self-test: ship refuses missing source, gates + records the real one"
    (
        cd "$tmp" || exit 1
        build_guard_check test-script
        ! guard_ship_artifact target/does-not-exist.bin artifacts/nope.bin 2>ship-missing.err \
            && grep -q "staging source not found" ship-missing.err \
            && mkdir -p target \
            && printf 'fixture-binary 0.10.0 (%s)\n' "$tag" > target/staged.bin \
            && out="$(guard_ship_artifact target/staged.bin artifacts/fake.bin raw)" \
            && [ "$out" = "artifacts/fake.bin" ] \
            && [ -f artifacts/fake.bin ]
    ) || failures=$((failures + 1))

    echo "self-test: ship gate failure removes the copy"
    (
        cd "$tmp" || exit 1
        printf 'fixture-binary 0.9.0 (2026-01-01_deadbeef)\n' > target/stale.bin
        ! guard_ship_artifact target/stale.bin artifacts/stale.bin raw 2>ship-stale.err \
            && [ ! -f artifacts/stale.bin ] \
            && grep -q "content tag mismatch" ship-stale.err
    ) || failures=$((failures + 1))

    echo "self-test: manifest records provenance with sources, parses as JSON"
    (
        cd "$tmp" || exit 1
        # Self-contained scenario: check (resets the record queue and fills
        # the git provenance), ship one (gated copy, captured through a
        # command substitution like real scripts do), record one (no copy).
        build_guard_check test-script
        out="$(guard_ship_artifact target/staged.bin artifacts/fake.bin raw)" \
            && [ "$out" = "artifacts/fake.bin" ]
        guard_record_artifact target/staged.bin target/staged.bin
        ! build_guard_write_manifest test artifacts/fake.bin 2>manifest-legacy.err \
            && grep -q "schema 2" manifest-legacy.err
        build_guard_write_manifest test
        python3 - "$tmp/artifacts/build-manifest.test.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc["schema"] == 2, doc
assert doc["tree_state"] == "clean", doc
assert doc["escape_hatch"] is None, doc
assert doc["git"]["commit"], doc
arts = doc["artifacts"]
assert len(arts) == 2, doc
by_name = {a["name"]: a for a in arts}
assert set(by_name) == {"fake.bin", "staged.bin"}, doc
assert by_name["fake.bin"]["source"] == "target/staged.bin", doc
assert by_name["staged.bin"]["source"] == "target/staged.bin", doc
import hashlib
raw = open("target/staged.bin", "rb").read()
assert by_name["staged.bin"]["sha256"] == hashlib.sha256(raw).hexdigest(), doc
assert by_name["staged.bin"]["bytes"] == len(raw), doc
PY
    ) || failures=$((failures + 1))

    if [ "$failures" -gt 0 ]; then
        echo "build_guard self-test: $failures FAILURE(S)"
        return 1
    fi
    echo "build_guard self-test: all cases passed"
    return 0
}

if [ "${1:-}" = "--self-test" ]; then
    _guard_selftest
    exit $?
fi
