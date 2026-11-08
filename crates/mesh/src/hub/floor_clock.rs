//! The hub's floor version clock — the change signal behind
//! `GET /policy/floor/version`
//!
//! The floor read model (`GET /policy/floor`'s agents rows, watermarks,
//! paused-stream and maintenance faces) is assembled from several in-memory
//! ledgers that BOTH transport planes mutate (h2 handlers and QUIC frame
//! arms) — no single layer sees "the floor changed". This clock is that
//! signal: every mutation funnel that feeds the floor bumps it, and the
//! version endpoint holds a request until it advances (the Consul-style
//! blocking-query shape — push the invalidation, pull the payload).
//!
//! Discipline:
//!
//! - **Bump only on observable change.** Steady-state heartbeats — an
//!   agent's intent exchange re-reporting the same paused set, a repeat
//!   policy pull — must NOT bump: a clock that ticks on every watch
//!   interval degenerates the watch endpoint into polling.
//! - **Bump in the ledger layer, never in the h2 handler.** The QUIC arms
//!   mutate the same ledgers without passing through any HTTP handler; a
//!   handler-side bump is invisible to them.
//! - **In-memory and process-local.** The version resets on hub restart;
//!   the endpoint's `since != current` rule treats ANY divergence (ahead
//!   or behind) as a change, so a restarted hub wakes its watchers with a
//!   fresh read rather than wedging them.

use tokio::sync::watch;

/// A monotonic counter over the floor read model's inputs.
///
/// `Clone` shares the same counter (the ledgers hold clones; the endpoint
/// reads one). `bump()` is synchronous — callable under the ledgers'
/// `std::sync::Mutex` guards (lock order is always ledger → clock, never
/// the reverse).
#[derive(Clone)]
pub struct FloorClock {
    sender: watch::Sender<u64>,
}

impl FloorClock {
    /// A clock starting at version 0.
    pub fn new() -> Self {
        let (sender, _) = watch::channel(0);
        Self { sender }
    }

    /// The current version.
    pub fn version(&self) -> u64 {
        *self.sender.borrow()
    }

    /// Advances the version by one and wakes every held watch request.
    pub fn bump(&self) {
        self.sender.send_modify(|version| *version += 1);
    }

    /// A receiver that resolves on the NEXT `bump()` after subscribing
    /// (the current value is marked seen — `changed()` waits for the next
    /// one, exactly the endpoint's hold semantics).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.sender.subscribe()
    }
}

impl std::fmt::Debug for FloorClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FloorClock")
            .field("version", &self.version())
            .finish()
    }
}

impl Default for FloorClock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn subscribe_wakes_on_bump_only_for_later_changes() {
        let clock = FloorClock::new();
        assert_eq!(clock.version(), 0);
        // A bump BEFORE subscribing is already the receiver's seen value.
        clock.bump();
        assert_eq!(clock.version(), 1);
        let mut rx = clock.subscribe();
        // No wake without a further bump: the receiver still reads seen.
        assert!(!rx.has_changed().unwrap());
        clock.bump();
        assert!(rx.changed().await.is_ok());
        assert_eq!(*rx.borrow_and_update(), 2);
    }

    #[test]
    fn clones_share_the_counter() {
        let clock = FloorClock::new();
        let twin = clock.clone();
        twin.bump();
        assert_eq!(clock.version(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn held_watch_times_out_without_a_bump() {
        let clock = FloorClock::new();
        let mut rx = clock.subscribe();
        let woke = tokio::time::timeout(Duration::from_secs(30), rx.changed()).await;
        assert!(woke.is_err(), "no bump — the hold must run out, not wake");
    }
}
