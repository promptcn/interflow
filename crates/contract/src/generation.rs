//! Generational handles: the single compare-before-mutate contract for every
//! rotation-guarded piece of shared state.
//!
//! Interflow has three ad-hoc "is my handle still the current one?"
//! disciplines — the policy generation watermark, the session channel
//! generation, and the circuit witness — each historically hand-written at
//! its own call sites.
//! They share one root cause ("pointer identity ≠ logical identity": a
//! registry entry can be reused in place while its logical epoch rotates)
//! and one discipline, expressed here once:
//!
//! > **Any handle held across an `await` or a `spawn` must carry the epoch it
//! > was armed at, and must pass it through [`GenerationalHandle`] before
//! > mutating what it points at.**
//!
//! The check itself still runs at runtime — Rust cannot push a dynamic
//! registry's epoch into the type system without giving up the dynamicity.
//! What this contract buys is that the check is one named, documented,
//! greppable pattern instead of N copies, and that a new guarded surface has
//! exactly one form to copy.
//!
//! Two epoch semantics, one type:
//! - **Equality** ([`GenerationalHandle::equal_epoch`]): any difference —
//!   older *or* newer — means the holder is stale. Used where rotation is
//!   unordered: the circuit token (random per registration) and the session
//!   channel generation (a counter that only ever moves away from you).
//! - **Watermark floor** ([`GenerationalHandle::floor_epoch`]): a handle
//!   below the persisted floor is stale; one at or above it is current.
//!   Used where epochs are a monotonic published lineage: the policy
//!   generation.

use std::cmp::PartialOrd;

/// The result of one compare-before-mutate check.
///
/// `Superseded` carries the epoch now current, so callers can log the
/// attribution pair (what the holder was armed at vs. what superseded it)
/// without a second read of shared state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<E> {
    /// The handle's epoch is still the one to act on.
    Current,
    /// The handle is stale; the epoch has moved on to the carried value.
    Superseded(E),
}

impl<E> Verdict<E> {
    /// Whether the holder may act (the common guard shape: act only on
    /// `Current`, otherwise stand down — never act on a stale handle).
    pub const fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }
}

/// A handle to rotation-guarded shared state: what it points at (`key`) and
/// the epoch it was armed at (`epoch`).
///
/// Construct this where the credential is **armed** — the moment a death
/// signal captures the registration it will speak for, a poll takes the
/// channels, a policy watcher records the generation it has applied — and
/// check it immediately before the mutation. The gap in between is exactly
/// where re-registration/rotation can slip in (the 2026-10-11 stale-watcher
/// incident: a watcher armed for registration A acted on the registry entry
/// that registration B had already rotated in place).
#[derive(Debug, Clone)]
pub struct GenerationalHandle<K, E> {
    /// The addressed entry's key (registry key, policy channel, …) — for
    /// attribution and logging; the check itself is over `epoch`.
    pub key: K,
    /// The epoch captured when the handle was armed.
    pub epoch: E,
}

impl<K, E> GenerationalHandle<K, E> {
    /// Arms a handle: binds a key to the epoch current at the capture point.
    pub const fn armed_at(key: K, epoch: E) -> Self {
        Self { key, epoch }
    }
}

/// Equality semantics: the armed epoch is current only if the live epoch is
/// still exactly the one captured at arming time.
///
/// Rotation here is unordered — a *newer* epoch supersedes the holder just
/// as hard as a different one (circuit token: random per registration;
/// channel generation: strictly increasing, so any difference means "not
/// yours anymore").
pub fn equal_epoch<E>(armed: &E, current: &E) -> Verdict<E>
where
    E: PartialEq + Clone,
{
    if armed == current {
        Verdict::Current
    } else {
        Verdict::Superseded(current.clone())
    }
}

/// Watermark-floor semantics: an armed epoch at or above the floor is
/// current; one below it is stale (rolled back).
///
/// For the policy generation: `floor` is the highest generation known
/// persisted; a holder still at an older generation must refuse to act
/// (serve/publish/apply) rather than roll the lineage back.
pub fn floor_epoch<E>(armed: &E, floor: &E) -> Verdict<E>
where
    E: PartialOrd + Clone,
{
    if armed >= floor {
        Verdict::Current
    } else {
        Verdict::Superseded(floor.clone())
    }
}

impl<K, E: PartialEq + Clone> GenerationalHandle<K, E> {
    /// [`equal_epoch`] over this handle's armed epoch.
    pub fn equal_epoch(&self, current: &E) -> Verdict<E> {
        equal_epoch(&self.epoch, current)
    }
}

impl<K, E: PartialOrd + Clone> GenerationalHandle<K, E> {
    /// [`floor_epoch`] over this handle's armed epoch.
    pub fn floor_epoch(&self, floor: &E) -> Verdict<E> {
        floor_epoch(&self.epoch, floor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_epoch_current_only_on_exact_match() {
        let h = GenerationalHandle::armed_at("agent", 7u64);
        assert_eq!(h.equal_epoch(&7), Verdict::Current);
        assert_eq!(h.equal_epoch(&8), Verdict::Superseded(8));
        // Newer live epoch also supersedes (rotation is unordered).
        assert_eq!(h.equal_epoch(&6), Verdict::Superseded(6));
    }

    #[test]
    fn floor_epoch_current_at_or_above_floor() {
        let h = GenerationalHandle::armed_at("policy", 4u64);
        assert_eq!(h.floor_epoch(&4), Verdict::Current);
        assert_eq!(h.floor_epoch(&3), Verdict::Current);
        assert_eq!(h.floor_epoch(&5), Verdict::Superseded(5));
    }
}
