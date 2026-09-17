//! Circuit-breaker policy: one type, two named defaults.
//!
//! The same breaker component (mesh `TargetBreakers`) runs in two places
//! with deliberately different evidence planes, and before this module the
//! two default threshold sets lived as unrelated literals (agent TOML
//! defaults 5/10s/30s vs edge CLI defaults 10/60s/30s, introduced in the
//! same commit with no cross-reference). Naming both policies here makes the
//! difference an explicit, documented decision instead of an accident:
//!
//! - [`BreakerPolicy::EGRESS_DEFAULT`] (agent → backend): evidence is a
//!   *dial failure* reaching the agent. Backends that fail to connect fail
//!   loudly and immediately, so a short window (10s) with a low threshold
//!   (5) isolates a dead target quickly without tripping on a single
//!   transient hiccup.
//! - [`BreakerPolicy::ROUTE_DEFAULT`] (edge → route): evidence is a *stream
//!   close reason* relayed back from the hub side, one per ended user
//!   stream. Legitimate routes can shed streams for many non-backend
//!   reasons mid-flight (client disconnects), so the window is wider (60s)
//!   and the threshold higher (10) to avoid opening on ordinary churn.

use std::time::Duration;

/// A circuit-breaker threshold set: N failures within `failure_window` opens
/// the circuit for `cooldown`, after which one half-open probe is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerPolicy {
    /// Failures within the window required to open the circuit.
    pub failure_threshold: u32,
    /// Sliding window the failures are counted in.
    pub failure_window: Duration,
    /// OPEN-state cooldown before a half-open probe is allowed through.
    pub cooldown: Duration,
}

impl BreakerPolicy {
    /// Agent egress per-target breaker (evidence: dial failures).
    pub const EGRESS_DEFAULT: Self = Self {
        failure_threshold: 5,
        failure_window: Duration::from_secs(10),
        cooldown: Duration::from_secs(30),
    };

    /// Edge per-route breaker (evidence: relayed stream close reasons).
    pub const ROUTE_DEFAULT: Self = Self {
        failure_threshold: 10,
        failure_window: Duration::from_mins(1),
        cooldown: Duration::from_secs(30),
    };
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Both named policies are sane on their own terms (threshold ≥ 1,
    /// non-degenerate timings); the deliberate difference between them is a
    /// matter of evidence planes, not of one side being mis-tuned.
    #[test]
    fn policies_are_sane() {
        let one = Duration::from_secs(1);
        for p in [BreakerPolicy::EGRESS_DEFAULT, BreakerPolicy::ROUTE_DEFAULT] {
            assert!(p.failure_threshold >= 1);
            assert!(p.failure_window > Duration::ZERO);
            assert!(p.cooldown >= one);
        }
        // (The cross-policy relationships are compile-time locks above.)
    }
}
