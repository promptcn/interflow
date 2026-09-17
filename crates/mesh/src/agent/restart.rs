//! Bounded restart policy for embedders facing a dead supervisor.
//!
//! The library guarantees the supervisor survives session-level panics
//! (every session attempt is a supervised child), but a panic in the
//! supervisor's *own* frame is the outermost in-process layer — nothing
//! above it exists to rebuild it. Recovery there belongs to the embedder:
//! the GUI restarts the agent (this policy), the edge process exits for
//! systemd (its own outer ring).
//!
//! The policy bounds the restart loop the way the agent supervisor bounds
//! its reconnect loop: exponential backoff, capped, and a maximum number of
//! consecutive attempts. A healthy stretch clears the attempt debt — a
//! supervisor that dies after an hour of Connected service is a fresh
//! incident, not a crash loop — so genuine long-running deployments never
//! exhaust the budget, while a supervisor that keeps dying within the
//! healthy window gives up visibly instead of spinning forever.

use std::time::Duration;

/// What to do after observing a supervisor death.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartDecision {
    /// Restart after this delay.
    RestartIn(Duration),
    /// The attempt budget is exhausted: surface the failure to the user
    /// instead of spinning.
    GiveUp,
}

/// Bounded restart budget (see the module doc). Pure logic — no I/O — so
/// the GUI keeps a thin adapter over it and the semantics stay testable.
#[derive(Debug, Clone)]
pub struct SupervisorRestartPolicy {
    max_attempts: u32,
    healthy_window: Duration,
    attempts: u32,
}

impl SupervisorRestartPolicy {
    /// Default shape: at most 3 consecutive restarts, 1s base backoff
    /// doubling to a 30s cap; a healthy Connected streak of 5 minutes
    /// clears the debt.
    pub const fn new() -> Self {
        Self {
            max_attempts: 3,
            healthy_window: Duration::from_mins(5),
            attempts: 0,
        }
    }

    /// Records a supervisor death and decides what to do about it.
    pub fn on_supervisor_death(&mut self) -> RestartDecision {
        if self.attempts >= self.max_attempts {
            return RestartDecision::GiveUp;
        }
        self.attempts += 1;
        // 1s, 2s, 4, 8, 16 — capped at 30s.
        let shift = (self.attempts - 1).min(5);
        let backoff = Duration::from_secs(1_u64 << shift).min(Duration::from_secs(30));
        RestartDecision::RestartIn(backoff)
    }

    /// Reports how long the agent has been continuously Connected; at or
    /// past the healthy window, the attempt debt is cleared.
    pub fn note_healthy_streak(&mut self, connected_for: Duration) {
        if connected_for >= self.healthy_window {
            self.attempts = 0;
        }
    }

    /// Consecutive deaths recorded so far in the current budget window.
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

impl Default for SupervisorRestartPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn backoff_doubles_then_caps() {
        let mut p = SupervisorRestartPolicy::new();
        assert_eq!(p.on_supervisor_death(), RestartDecision::RestartIn(S));
        assert_eq!(
            p.on_supervisor_death(),
            RestartDecision::RestartIn(Duration::from_secs(2))
        );
        assert_eq!(
            p.on_supervisor_death(),
            RestartDecision::RestartIn(Duration::from_secs(4))
        );
        // Budget exhausted at the default 3.
        assert_eq!(p.on_supervisor_death(), RestartDecision::GiveUp);
        assert_eq!(p.on_supervisor_death(), RestartDecision::GiveUp);
        assert_eq!(p.attempts(), 3);
    }

    #[test]
    fn healthy_streak_clears_the_debt() {
        let mut p = SupervisorRestartPolicy::new();
        p.on_supervisor_death();
        p.on_supervisor_death();
        // A short streak does not clear anything.
        p.note_healthy_streak(Duration::from_mins(1));
        assert_eq!(p.attempts(), 2);
        p.on_supervisor_death();
        assert_eq!(p.on_supervisor_death(), RestartDecision::GiveUp);

        // A full healthy window resets the budget for the next incident.
        p.note_healthy_streak(Duration::from_mins(5));
        assert_eq!(p.attempts(), 0);
        assert_eq!(p.on_supervisor_death(), RestartDecision::RestartIn(S));
    }

    #[test]
    fn backoff_caps_at_30s() {
        let mut p = SupervisorRestartPolicy {
            max_attempts: 8,
            ..SupervisorRestartPolicy::new()
        };
        for expect in [1, 2, 4, 8, 16, 30, 30, 30] {
            assert_eq!(
                p.on_supervisor_death(),
                RestartDecision::RestartIn(Duration::from_secs(expect))
            );
        }
    }
}
