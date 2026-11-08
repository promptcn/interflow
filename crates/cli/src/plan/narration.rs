//! The promise vocabulary — the one place the phrases that carry
//! commitment semantics live.
//!
//! `plan diff` predicts the next apply, `plan apply` executes it, and the
//! preview-honorability contract test
//! (`crates/cli/tests/plan_preview_contract.rs`) parses BOTH faces' output
//! with the constants below: rewording a line here reflows the test with
//! it, so the test can never silently drift from the faces it polices.
//! Three consumers, one vocabulary — the discipline `version_face` holds
//! for the version line, applied to the plan face.
//!
//! What belongs here: a phrase whose presence in the output IS a claim
//! about what apply does or did (`promise`), or evidence that it did it
//! (`action`), plus the line builders that embed them (so a promise and the
//! sentence around it cannot drift apart either). Plain narration without
//! commitment semantics stays at its call site.
//!
//! Backlog: (internal design notes)
//! and (internal design notes).

use super::{Divergence, PolicyWatermarks, TreeStale};
use std::path::Path;

/// What the read face (`plan diff`) promises about the next `plan apply`.
/// Each constant is one promise the contract test checks against apply's
/// actions.
pub mod promise {
    /// The first apply performs the full first render.
    pub const FULL_FIRST_RENDER: &str = "performs the full first render";
    /// Nothing remains to apply: the gate's true no-op.
    pub const NOTHING_TO_APPLY: &str = "nothing to apply";
    /// The policy-only fast path carries the next apply (a new generation
    /// publishes; no pack re-renders).
    pub const POLICY_ONLY_FAST_PATH: &str = "takes the policy-only fast path";
    /// Every pack re-renders (identity edits, a stale tree).
    pub const RERENDERS_EVERY_PACK: &str = "re-renders every pack";
    /// The pack-tree freshness probes fired.
    pub const PACK_TREE_IS_STALE: &str = "pack tree is stale";
    /// The re-render mints and publishes a generation above the watermarks.
    pub const PUBLISHES_ABOVE_THE_WATERMARKS: &str = "publishes above the watermarks";
    /// The watermark gate found a divergence.
    pub const WATERMARKS_DIVERGE: &str = "the watermarks diverge from the issuer bookkeeping";
    /// The same policy re-publishes above the watermarks to reconcile.
    pub const REPUBLISHES_ABOVE_THE_WATERMARKS: &str = "re-publishes above the watermarks";
    /// Pending policy edits ride the full re-render, not the fast path.
    pub const FAST_PATH_SUPERSEDED: &str = "the policy-only fast path does not apply";
    /// The boundary of the prediction: the hub's watermarks are live state.
    pub const HUB_WATERMARKS_REQUERIED: &str = "re-queried at apply time";
    /// The baseline digest cache heals in the bookkeeping alone.
    pub const BASELINE_CACHE_REFRESH: &str = "refreshes the baseline digest in the bookkeeping";
}

/// What the write face (`plan apply`) reports having done. Every line that
/// carries one of these must be justified by a promise the read face made
/// on the same state — the contract test's invariant.
pub mod action {
    /// A full render completed.
    pub const APPLIED: &str = "✔ applied";
    /// The policy-only fast path signed a generation.
    pub const POLICY_ONLY_CHANGE: &str = "✔ policy-only change";
    /// The no-op gate confirmed the live generation.
    pub const ALREADY_APPLIED: &str = "✔ manifest already applied";
    /// The true no-op's tail.
    pub const NOTHING_TO_DO: &str = "nothing to do";
    /// The bookkeeping-only cache refresh's tail.
    pub const RESTAMPED: &str = "baseline digest cache refreshed (no render, no publish)";
    /// A stale tree or diverged watermarks broke the no-op (the ✔'s head).
    pub const MANIFEST_UNCHANGED_BUT: &str = "✔ manifest unchanged, but";
    /// The stale-tree full render: packs re-render AND a generation
    /// publishes.
    pub const RERENDERING_AND_PUBLISHING: &str =
        "re-rendering every pack and publishing above the watermarks";
    /// The diverged-watermarks re-publish.
    pub const REPUBLISHING_ABOVE_THE_WATERMARKS: &str = "re-publishing above the watermarks";
    /// A generation landed on the hub.
    pub const PUBLISHED_TO_HUB: &str = "published to hub";
    /// The unreachable-hub degradation: a generation was signed for manual
    /// drop.
    pub const MANUAL_DISTRIBUTION: &str = "manual distribution";
    /// Offline packs re-embedded the issuer's current CRL snapshot.
    pub const EMBEDDED_REVOCATION_SNAPSHOT: &str = "embedded revocation snapshot";
    /// The issuer store's automatic backup was configured (a one-time
    /// infrastructure side effect of the first write — NOT a deployment
    /// action diff predicts; listed so the ✔-line scanner knows it).
    pub const BACKUP_CONFIGURED: &str = "✔ issuer store backup configured";
}

// ---------------------------------------------------------------------------
// Read face (`plan diff`) — the future tense.
// ---------------------------------------------------------------------------

pub(super) fn never_applied() -> String {
    format!(
        "never applied — the next `plan apply` {}",
        promise::FULL_FIRST_RENDER
    )
}

pub(super) fn applied_matches(generation: u64) -> String {
    format!(
        "the declaration matches the applied state (policy generation {generation}) — {}",
        promise::NOTHING_TO_APPLY
    )
}

pub(super) fn policy_edits_pending() -> String {
    format!(
        "policy-face edits pending — the next `plan apply` {} (no pack re-rendered, no \
         identity re-signed)",
        promise::POLICY_ONLY_FAST_PATH
    )
}

pub(super) fn identity_edits_pending() -> String {
    format!(
        "identity-face edits pending — the next `plan apply` {}",
        promise::RERENDERS_EVERY_PACK
    )
}

/// The stale-tree prediction: the probe's finding verbatim ([`TreeStale::fact`]),
/// then what apply does about it — render AND publish, the half the ✔ line
/// used to leave unsaid.
pub(super) fn pack_tree_stale_preview(stale: &TreeStale) -> String {
    format!(
        "{} — {} — the next `plan apply` {} and {} ({})",
        promise::PACK_TREE_IS_STALE,
        stale.fact(),
        promise::RERENDERS_EVERY_PACK,
        promise::PUBLISHES_ABOVE_THE_WATERMARKS,
        stale.consequence()
    )
}

/// Both faces say this on a stale tree with policy edits pending: the full
/// render carries the edits; the fast path is not taken.
pub(super) fn fast_path_superseded() -> String {
    format!(
        "ℹ policy-face edits are pending too — the full re-render carries them; {}",
        promise::FAST_PATH_SUPERSEDED
    )
}

pub(super) fn watermarks_diverged_preview(
    bookkeeping: u64,
    dist: u64,
    divergence: &Divergence,
) -> String {
    format!(
        "the declaration matches the applied state (policy generation {bookkeeping}), but {} \
         (bookkeeping {bookkeeping}, dist artifacts {dist}) — {} — the next `plan apply` {} to \
         reconcile",
        promise::WATERMARKS_DIVERGE,
        divergence.narrate(),
        promise::REPUBLISHES_ABOVE_THE_WATERMARKS
    )
}

/// The stale-cache ℹ, read-face tense: the recorded digest disagreed, the
/// declaration snapshot proved the face unchanged — the refresh is
/// bookkeeping alone (whatever else the fork does is its own headline).
pub(super) fn baseline_cache_refresh_preview() -> String {
    format!(
        "ℹ the recorded baseline digest is a stale cache of the unchanged declaration — \
         verified against the declaration snapshot; the next `plan apply` {}",
        promise::BASELINE_CACHE_REFRESH
    )
}

/// The no-op prediction's boundary, stated where it applies: the hub's own
/// watermarks are not read here.
pub(super) fn hub_watermarks_caveat() -> String {
    format!(
        "ℹ the hub's own watermarks are {} — a diverged hub still triggers the re-publish \
         above the watermarks",
        promise::HUB_WATERMARKS_REQUERIED
    )
}

// ---------------------------------------------------------------------------
// Write face (`plan apply`) — the present tense.
// ---------------------------------------------------------------------------

pub(super) fn force_rerender_notice() -> String {
    "⚠ --force-rerender: the no-op gate is skipped — every pack re-renders above the \
     watermarks (generation continuity preserved)"
        .to_owned()
}

/// The stale-cache ℹ, write-face tense: the snapshot arbitration just
/// proved the declaration unchanged, and this write refreshes the cache.
pub(super) fn baseline_cache_refresh_action() -> String {
    "ℹ the recorded baseline digest was a stale cache of the unchanged declaration — \
     verified against the declaration snapshot; refreshing it"
        .to_owned()
}

/// The stale-tree ✔ line — the same [`TreeStale::fact`] the preview embeds,
/// then the action in the present tense.
pub(super) fn pack_tree_stale_action(stale: &TreeStale) -> String {
    format!(
        "{} {} — {} ({})",
        action::MANIFEST_UNCHANGED_BUT,
        stale.fact(),
        action::RERENDERING_AND_PUBLISHING,
        stale.consequence()
    )
}

pub(super) fn already_applied_restamped(generation: u64) -> String {
    format!(
        "{} — policy generation {generation} is live; {}",
        action::ALREADY_APPLIED,
        action::RESTAMPED
    )
}

pub(super) fn already_applied_nothing_to_do(generation: u64) -> String {
    format!(
        "{} — policy generation {generation} is live, {}",
        action::ALREADY_APPLIED,
        action::NOTHING_TO_DO
    )
}

pub(super) fn watermarks_diverged_action(
    watermarks: &PolicyWatermarks,
    divergence: &Divergence,
) -> String {
    format!(
        "{} {} (bookkeeping {}, dist artifacts {}, hub floor {}, hub serving {}) — {} — {} to \
         reconcile",
        action::MANIFEST_UNCHANGED_BUT,
        promise::WATERMARKS_DIVERGE,
        watermarks.bookkeeping,
        watermarks.dist,
        watermarks
            .hub
            .map_or_else(|| "unreachable".to_string(), |hub| hub.floor.to_string()),
        watermarks.hub.map_or_else(
            || "unreachable".to_string(),
            |hub| hub
                .serving
                .map_or_else(|| "not reported".to_string(), |s| s.to_string())
        ),
        divergence.narrate(),
        action::REPUBLISHING_ABOVE_THE_WATERMARKS
    )
}

pub(super) fn policy_only_signed(generation: u64) -> String {
    format!(
        "{}: rules / services / routes moved, identity face unchanged — signed policy \
         generation {generation} (no pack re-rendered, no identity re-signed)",
        action::POLICY_ONLY_CHANGE
    )
}

pub(super) fn applied(manifest_path: &Path, out_root: &Path) -> String {
    format!(
        "{} {} → {}",
        action::APPLIED,
        manifest_path.display(),
        out_root.display()
    )
}

pub(super) fn published_to_hub(endpoint: &str, generation: u64) -> String {
    format!(
        "  {} {endpoint} → generation {generation}; online agents hot-apply",
        action::PUBLISHED_TO_HUB
    )
}

pub(super) fn manual_distribution(bundle_dir: &Path) -> String {
    format!(
        "  {}: copy {}/policy.toml + policy.sig into every node's <pack>/state/policy/ (the \
         reload watcher applies them, ≤10s)",
        action::MANUAL_DISTRIBUTION,
        bundle_dir.display()
    )
}

pub(super) fn embedded_revocation_snapshot() -> String {
    format!(
        "  {} in trust/crls/ of every pack (covers every issuer)",
        action::EMBEDDED_REVOCATION_SNAPSHOT
    )
}

// ---------------------------------------------------------------------------
// Stage face (`plan stage`) — packaging narration.
// ---------------------------------------------------------------------------

/// The stage drift sentinel: staging renders the nginx fragments fresh
/// from the current declaration with the current build, and this ℹ names
/// the gap whenever the dist tree's copies differ — an older build
/// rendered them, or the declaration moved since the last apply (the
/// policy-only fast path signs a generation without refreshing the
/// fragments). The next `plan apply` rewrites dist and the signal
/// disappears.
pub(super) fn stage_fragments_re_rendered(rels: &[String]) -> String {
    format!(
        "ℹ nginx fragments re-rendered from the current declaration — the dist copies differ \
         ({}); the next `plan apply` refreshes dist",
        rels.join(", ")
    )
}
