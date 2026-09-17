//! Liveness budget family: one heartbeat cadence, every downstream timeout
//! derived from it.
//!
//! Before this module existed, the same formulas were hand-written in three
//! places (`mesh/src/negotiation.rs`, `mesh/src/hub/heartbeat.rs`,
//! `mesh/src/hub/quic.rs`) and the cross-layer inequality chain
//! (dead line < poll watchdog < edge recovery budget) was argued only in
//! comments — comments that had already drifted out of sync with the code
//! once (the `poll_grace_secs` "backoff tops out at 5s" claim). Deriving
//! everything from [`HeartbeatCadence`] makes the chain structural: it
//! cannot be broken by tuning one layer in isolation.
//!
//! The chain, top to bottom (defaults in parentheses):
//!
//! | Derivation | Formula | Default | Enforced by |
//! |---|---|---|---|
//! | [`HeartbeatCadence::dead_line`] | `interval * (max_missed + 1)` | 75s (hub evicts a Pong-silent agent) | construction |
//! | [`HeartbeatCadence::poll_watchdog`] | dead line + [`WATCHDOG_MARGIN_SECS`] | 105s (agent receive-side watchdog) | construction |
//! | [`HeartbeatCadence::task_stall`] | dead line | 75s (local critical-task stall timeout) | construction |
//! | [`recovery_budget`] | dead line + [`BACKOFF_CAP`] + [`RECOVERY_MARGIN_SECS`] | 120s (edge agent-recovery supervision) | construction + test |
//!
//! Related cross-references that live elsewhere but must stay consistent:
//! the hub's `poll_grace_secs` (mesh) is validated against [`BACKOFF_CAP`],
//! and the transport-layer keepalive timeouts ([`crate::config::params`]
//! transport profile) must stay strictly below the app-layer dead line.

use std::time::Duration;

/// Margin added to the dead line for the agent poll watchdog.
///
/// Tolerates a single tick of jitter / scheduling delay on top of the hub's
/// own aging window, so the hub always evicts before the agent gives up on
/// the poll stream (never the other way round).
pub const WATCHDOG_MARGIN_SECS: u64 = 30;

/// Margin on top of `dead_line + BACKOFF_CAP` for the edge recovery budget:
/// covers one full connect attempt (`connect_timeout_secs`, default 15s)
/// after the worst-case backoff elapses.
pub const RECOVERY_MARGIN_SECS: u64 = 15;

/// Fallback critical-task stall timeout when there is no heartbeat cadence
/// to derive from (heartbeat disabled): a wedged task must still be caught.
pub const TASK_STALL_FALLBACK_SECS: u64 = 30;

/// Upper bound of the agent supervisor's reconnect backoff (full jitter;
/// implementation in mesh `agent::handle::backoff_duration`).
///
/// The edge recovery budget and the hub `poll_grace_secs` validation both
/// reference this constant — the "grace must tolerate the backoff cap"
/// invariant is expressed against the same number the backoff actually uses.
pub const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Floor of the agent supervisor's reconnect backoff: never zero — a
/// hot-looping reconnect would hammer the hub and starve the session task
/// itself.
pub const BACKOFF_FLOOR: Duration = Duration::from_secs(1);

/// Poll period the hub heartbeat loop falls back to when `[heartbeat]` is
/// disabled (no Pings to send; the loop only re-reads config).
pub const HEARTBEAT_DISABLED_POLL: Duration = Duration::from_secs(30);

/// Target period of the heartbeat loop's aggregated summary log line (one
/// line per ~10 minutes at the default cadence).
pub const HEARTBEAT_SUMMARY_PERIOD: Duration = Duration::from_mins(10);

/// The hub heartbeat cadence.
///
/// The single knob the whole liveness chain derives from; mirrors the wire
/// advertisement (`HeartbeatAd` in the mesh negotiation module)
/// field-for-field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatCadence {
    /// Ping send interval in seconds.
    pub interval_secs: u64,
    /// Consecutive-miss threshold: no Pong for
    /// `interval_secs * (max_missed + 1)` seconds means the agent is dead.
    pub max_missed: u32,
}

impl HeartbeatCadence {
    /// Production default: 15s interval × 4 misses = 75s dead line.
    pub const DEFAULT: Self = Self {
        interval_secs: 15,
        max_missed: 4,
    };

    /// The agent-death line: silence longer than this and the hub evicts
    /// (`interval * (max_missed + 1)`). Shared by the h2 and QUIC eviction
    /// paths and by the agent-side derivations below.
    #[must_use]
    pub const fn dead_line(&self) -> Duration {
        Duration::from_secs(self.interval_secs * (self.max_missed as u64 + 1))
    }

    /// Agent receive-side poll watchdog: the hub's aging window plus a
    /// jitter margin. Strictly greater than [`Self::dead_line`] by
    /// construction, so the hub-side eviction always fires first.
    #[must_use]
    pub fn poll_watchdog(&self) -> Duration {
        self.dead_line() + Duration::from_secs(WATCHDOG_MARGIN_SECS)
    }

    /// Critical-task stall timeout: the hub's own aging window WITHOUT the
    /// watchdog's jitter margin — a local task's heartbeat carries none of
    /// the network delivery jitter that margin covers.
    #[must_use]
    pub const fn task_stall(&self) -> Duration {
        self.dead_line()
    }

    /// Tick count for one heartbeat-loop summary log period (see
    /// [`HEARTBEAT_SUMMARY_PERIOD`]); at least every tick.
    #[must_use]
    pub fn summary_ticks(&self) -> u32 {
        u32::try_from(
            HEARTBEAT_SUMMARY_PERIOD
                .as_secs()
                .div_ceil(self.interval_secs.max(1)),
        )
        .unwrap_or(u32::MAX)
        .max(1)
    }
}

impl Default for HeartbeatCadence {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Edge agent-recovery supervision budget.
///
/// Hub eviction ([`HeartbeatCadence::dead_line`]) + worst-case reconnect
/// backoff ([`BACKOFF_CAP`]) + one connect attempt
/// ([`RECOVERY_MARGIN_SECS`]). A struggling-but-healthy agent never gets
/// failed-fast by the edge while it is still inside its own recovery path;
/// this replaces the hand-picked 120s constant (whose justification lived in
/// a comment next to it).
#[must_use]
pub const fn recovery_budget(cadence: &HeartbeatCadence) -> Duration {
    // Written via as_secs addition: `Duration + Duration` is not const-stable.
    Duration::from_secs(
        cadence.dead_line().as_secs() + BACKOFF_CAP.as_secs() + RECOVERY_MARGIN_SECS,
    )
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The chain at the default cadence reproduces the exact values the
    /// three hand-written formulas produced before the unification — locking
    /// the migration to a behavior-preserving refactor.
    #[test]
    fn default_chain_matches_pre_unification_values() {
        let c = HeartbeatCadence::DEFAULT;
        assert_eq!(c.dead_line(), Duration::from_secs(75));
        assert_eq!(c.poll_watchdog(), Duration::from_secs(105));
        assert_eq!(c.task_stall(), Duration::from_secs(75));
        assert_eq!(c.summary_ticks(), 40);
        assert_eq!(recovery_budget(&c), Duration::from_mins(2));
    }

    /// The chain's ordering invariants hold for any sane cadence, not just
    /// the default: watchdog strictly after the dead line, stall exactly at
    /// it, and recovery covering eviction + backoff with margin to spare.
    #[test]
    fn chain_invariants_hold_across_cadences() {
        for &(interval, missed) in &[(1_u64, 0_u32), (1, 1), (5, 2), (15, 4), (30, 3), (60, 5)] {
            let c = HeartbeatCadence {
                interval_secs: interval,
                max_missed: missed,
            };
            let dead = c.dead_line();
            assert!(c.poll_watchdog() > dead, "watchdog must outlast dead line");
            assert_eq!(c.task_stall(), dead, "stall rides the dead line");
            assert!(
                recovery_budget(&c) > dead + BACKOFF_CAP,
                "recovery must cover eviction plus full backoff"
            );
            assert!(c.summary_ticks() >= 1);
        }
    }

    /// The stall fallback stays consistent with the derived values at the
    /// default cadence: shorter than any derived stall at sane cadences.
    #[test]
    fn stall_fallback_stays_stricter_than_derived_default() {
        let d = HeartbeatCadence::DEFAULT;
        assert!(
            Duration::from_secs(TASK_STALL_FALLBACK_SECS) < d.task_stall(),
            "stall fallback stays stricter than the derived default"
        );
    }
}
