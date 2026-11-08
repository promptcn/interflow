//! Compile-time build identity — one tag for every Interflow binary.
//!
//! `BUILD_TAG` is `<commit-date>_<git-short-hash>[-dirty]` (e.g.
//! `2026-09-25_5deb344-dirty`), computed once by this crate's build script
//! and consumed by every surface that names a build: every clap CLI's
//! `--version` flag (and the mesh CLI's `version` subcommand, its
//! byte-identical pre-flag spelling), the expose engine's startup log
//! line, and the GUI's machine header. One const, so a GUI screenshot, a
//! CLI printout and a log line always name the same build without
//! translation.
//!
//! Two properties are the contract, not accidents:
//! - **Deterministic**: the date is the commit date, never the build clock —
//!   the same commit produces the same tag regardless of when, where or how
//!   often it is rebuilt.
//! - **Fail-safe on dirtiness**: any uncommitted change (modified or
//!   untracked) flips the `-dirty` suffix. A dirty tag means "the builder
//!   had local changes — ask them what is in it", never the named commit.

/// The one build tag every Interflow surface prints. See the crate docs for
/// the shape and its guarantees.
pub const BUILD_TAG: &str = env!("INTERFLOW_BUILD_TAG");

/// Whether the build's working tree had uncommitted changes.
///
/// Modified **or** untracked — either way [`BUILD_TAG`] names a commit the
/// binary only partially matches. Consumers surface this prominently (the
/// GUI renders it amber): a dirty build must not be mistaken for the named
/// commit when comparing machines.
pub const DIRTY: bool = matches!(env!("INTERFLOW_DIRTY").as_bytes(), b"true");

/// `<semver> (<build tag>)`, the version body every binary prints after its
/// own name, e.g. `0.4.0 (2026-09-25_5deb344-dirty)`.
///
/// Composed here, not at consumers, because this crate is the only place
/// the composition can happen at compile time: the build script's
/// rustc-env is visible only inside this crate, and `concat!` takes
/// literals and nested `env!` but never a const path — so no consumer can
/// build this string from [`BUILD_TAG`] without a runtime `format!`. The
/// semver half stays single-sourced from the workspace (guarded by
/// `check_version_contract.py`), so this adds no second source of truth.
pub const VERSION_WITH_TAG: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("INTERFLOW_BUILD_TAG"),
    ")"
);

/// Scans raw bytes for build-tag-shaped strings and returns every
/// occurrence in order.
///
/// This is the Rust-side single source of the [`BUILD_TAG`] shape; the
/// bash-side mirror is guard's `_guard_grep_tag` regex. Both match the
/// same shape (`<date>_<7-40 lowercase hex>[-dirty]`, leftmost, greedy
/// hex run) and must stay in step.
///
/// `plan stage`'s content gate reads the tag out of artifact bytes instead
/// of executing `--version`: cross-built Linux binaries cannot run on the
/// staging machine, so the tag is scanned where it is embedded.
pub fn find_build_tags(bytes: &[u8]) -> Vec<String> {
    fn date_at(bytes: &[u8], i: usize) -> bool {
        let Some(d) = bytes.get(i..i + 10) else {
            return false;
        };
        d[0].is_ascii_digit()
            && d[1].is_ascii_digit()
            && d[2].is_ascii_digit()
            && d[3].is_ascii_digit()
            && d[4] == b'-'
            && d[5].is_ascii_digit()
            && d[6].is_ascii_digit()
            && d[7] == b'-'
            && d[8].is_ascii_digit()
            && d[9].is_ascii_digit()
    }
    let lower_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !date_at(bytes, i) || bytes.get(i + 10) != Some(&b'_') {
            i += 1;
            continue;
        }
        let hash_start = i + 11;
        let mut j = hash_start;
        while j < bytes.len() && lower_hex(bytes[j]) {
            j += 1;
        }
        if !(7..=40).contains(&(j - hash_start)) {
            i += 1;
            continue;
        }
        let end = if bytes.get(j..j + 6).is_some_and(|s| s == b"-dirty") {
            j + 6
        } else {
            j
        };
        found.push(String::from_utf8_lossy(&bytes[i..end]).into_owned());
        i = end;
    }
    found
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Shape guard: the tag is matched across surfaces (GUI header, engine
    /// logs, CLI version output) and by humans comparing machines — drift
    /// here breaks that matching silently. `unknown` is the no-git
    /// fallback; it asserts nothing else, by design.
    #[test]
    fn build_tag_shape() {
        if BUILD_TAG == "unknown" {
            return;
        }
        let (date, rest) = BUILD_TAG
            .split_once('_')
            .expect("tag must be <date>_<hash>[...]");
        assert_eq!(
            date.len(),
            10,
            "commit date must be YYYY-MM-DD: {BUILD_TAG}"
        );
        assert!(
            date.chars()
                .enumerate()
                .all(|(i, c)| c.is_ascii_digit() || (i == 4 || i == 7) && c == '-'),
            "commit date must be YYYY-MM-DD: {BUILD_TAG}"
        );
        let hash = rest.strip_suffix("-dirty").unwrap_or(rest);
        assert!(
            !hash.is_empty() && hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be lowercase hex: {BUILD_TAG}"
        );
    }

    /// DIRTY must agree with the suffix the tag itself carries — the two
    /// consts leave the build script together and must never disagree.
    #[test]
    fn dirty_flag_matches_tag_suffix() {
        assert_eq!(DIRTY, BUILD_TAG.ends_with("-dirty"));
    }

    /// The composed version body must equal its parts — `interflow-cli
    /// --version` and `interflow-mesh --version` (plus its `version`
    /// subcommand spelling) print this const verbatim, so a drift between
    /// it and [`BUILD_TAG`] would fork the build identity across surfaces
    /// silently.
    #[test]
    fn version_with_tag_matches_parts() {
        assert_eq!(
            VERSION_WITH_TAG,
            format!("{} ({})", env!("CARGO_PKG_VERSION"), BUILD_TAG)
        );
    }

    /// The scanner finds tags embedded in surrounding noise (how they sit
    /// inside real binaries) and stops at non-hex boundaries — the `-dirty`
    /// suffix is consumed only when the literal follows.
    #[test]
    fn scanner_finds_embedded_tags() {
        assert_eq!(
            find_build_tags(b"\x00\x01junk 2026-11-02_c8906cb tail\xff"),
            vec!["2026-11-02_c8906cb".to_owned()]
        );
        assert_eq!(
            find_build_tags(b"2026-10-13_a40c7d7-dirty later"),
            vec!["2026-10-13_a40c7d7-dirty".to_owned()]
        );
        // Greedy hex run: the boundary char ends the hash, `-dirt` is not
        // the suffix literal so the tag ends at the hash.
        assert_eq!(
            find_build_tags(b"2026-11-02_abcdef0-dirtzz"),
            vec!["2026-11-02_abcdef0".to_owned()]
        );
        // Two occurrences in one blob, in order.
        assert_eq!(
            find_build_tags(b"a 2026-01-02_0000001 b 2026-01-03_0000002 c"),
            vec![
                "2026-01-02_0000001".to_owned(),
                "2026-01-03_0000002".to_owned()
            ]
        );
    }

    /// Everything that is not the shape is not a tag — short or overlong
    /// hashes, uppercase hex, and malformed dates all miss, mirroring the
    /// guard regex char-for-char.
    #[test]
    fn scanner_rejects_non_shapes() {
        assert!(find_build_tags(b"2026-11-02_c8906c").is_empty(), "6 hex");
        assert!(
            find_build_tags(b"2026-11-02_00000000000000000000000000000000000000000").is_empty(),
            "41 hex"
        );
        assert!(
            find_build_tags(b"2026-11-02_ABCDEF0").is_empty(),
            "uppercase"
        );
        assert!(
            find_build_tags(b"202a-11-02_abcdef0").is_empty(),
            "bad date"
        );
        assert!(
            find_build_tags(b"2026-1102_abcdef0").is_empty(),
            "missing dash"
        );
        assert_eq!(find_build_tags(b"no tag here at all"), Vec::<String>::new());
    }
}
