//! Operational cadences shared across binaries (reload loops, restart
//! delays) — single-sourced so the hub's config reload and the edge's routes
//! reload cannot drift apart.

use std::time::Duration;

/// SIGHUP config-reload debounce: collapses editor / save-storm bursts into
/// one reload. Shared by the hub (whole-config reload) and the edge
/// (routes-table reload) — previously two mirrored literals.
pub const SIGHUP_RELOAD_DEBOUNCE: Duration = Duration::from_secs(5);

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Debounce stays at second scale: big enough to collapse bursts, small
    /// enough that an operator's SIGHUP feels immediate.
    #[test]
    fn reload_debounce_stays_tight() {
        assert!(SIGHUP_RELOAD_DEBOUNCE >= Duration::from_secs(1));
        assert!(SIGHUP_RELOAD_DEBOUNCE <= Duration::from_secs(10));
    }
}
