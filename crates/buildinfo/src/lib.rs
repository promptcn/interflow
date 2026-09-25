//! Compile-time build identity — one tag for every Interflow binary.
//!
//! `BUILD_TAG` is `<commit-date>_<git-short-hash>[-dirty]` (e.g.
//! `2026-09-25_5deb344-dirty`), computed once by this crate's build script
//! and consumed by every surface that names a build: the mesh CLI's
//! `version` command, the expose engine's startup log line, and the GUI's
//! machine header. One const, so a GUI screenshot, a CLI printout and a log
//! line always name the same build without translation.
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

    /// The composed version body must equal its parts — `interflow
    /// --version` and `interflow-mesh version` print this const verbatim,
    /// so a drift between it and [`BUILD_TAG`] would fork the build
    /// identity across surfaces silently.
    #[test]
    fn version_with_tag_matches_parts() {
        assert_eq!(
            VERSION_WITH_TAG,
            format!("{} ({})", env!("CARGO_PKG_VERSION"), BUILD_TAG)
        );
    }
}
