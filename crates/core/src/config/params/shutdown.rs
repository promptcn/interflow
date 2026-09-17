//! Session shutdown budget: the bounded wind-down discipline for a tunnel
//! session.
//!
//! Introduced with the supervise-unified recovery path (2026-09-16): a dying
//! session's handlers must be given a *bounded* chance to finish —
//! wind-down may never wait on a wedged task forever (the unbounded-wait
//! candidate root cause in the edge-self-dial postmortem). The three
//! constants below previously lived as bare literals in mesh
//! `agent/client.rs`; they are operational tuning (not protocol), so they
//! stay out of TOML — but single-sourced here so both the agent supervisor
//! and any embedder reference the same budget.

use std::time::Duration;

/// Bounded wind-down budget for one session teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownBudget {
    /// Upper bound for the session's own shutdown handshake.
    pub session_shutdown: Duration,
    /// Grace window for draining in-flight frames after shutdown begins.
    pub session_drain_grace: Duration,
    /// Grace window for joining session handler tasks before aborting them.
    pub handler_join: Duration,
}

impl ShutdownBudget {
    /// Production default: 1s shutdown + 5s drain + 1s join.
    pub const DEFAULT: Self = Self {
        session_shutdown: Duration::from_secs(1),
        session_drain_grace: Duration::from_secs(5),
        handler_join: Duration::from_secs(1),
    };
}

impl Default for ShutdownBudget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The whole budget stays at second scale — a wedged teardown must cost
    /// at most a few seconds, never approach any liveness-layer timeout.
    #[test]
    fn budget_stays_tight() {
        let b = ShutdownBudget::DEFAULT;
        assert!(b.session_shutdown <= Duration::from_secs(1));
        assert!(b.session_drain_grace <= Duration::from_secs(5));
        assert!(b.handler_join <= Duration::from_secs(1));
        assert!(
            b.session_shutdown + b.session_drain_grace + b.handler_join < Duration::from_secs(10)
        );
    }
}
