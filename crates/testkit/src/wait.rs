//! Bounded wait-for-condition: the canonical poll primitive for "this must
//! become true eventually" claims in tests.
//!
//! Doctrine:
//! **the thing waited for is a condition, not a time**. An eventually claim
//! is the faithful shape when the code under test makes no promise about
//! WHEN a condition holds — a kernel's `/proc` presentation of a rename, fd
//! release racing a close-out counter (b6edc04's T4 sweep) — while a
//! point-in-time assert stays the shape for negative claims ("just started
//! is not stale") and for synchronous contracts. This is NOT the forbidden
//! threshold-moving (the b3 8s→30s→60s ladder): that inflates T inside a
//! promise "the condition arrives within T"; an eventually wait withdraws
//! an instantaneity that was never promised. The budget is the contract;
//! the poll period is an implementation detail.
//!
//! Two variants, same semantics: [`eventually`] for tokio tests,
//! [`eventually_sync`] for plain unit tests (an async runtime for a
//! filesystem/child-process probe would be ceremony, not structure).
//!
//! The probe is `FnMut() -> Result<T, E>`: `Ok` yields the awaited value
//! (the helper returns it — no re-probing to grab what the condition found),
//! and every miss yields an *observation* `E: Display`. The timeout panic
//! embeds the LAST observation — the exact context the old bool-flavored
//! helper could not carry, which is what forced the now-retired local fork
//! in `e2e_orphan_stream.rs` (metrics snapshot in the timeout message).
//! Observations are built lazily by the probe (e.g. `ok_or_else`), so a
//! passing test renders nothing.
//!
//! Fail-fast terminal states (a watch that reports a *definitive* failure,
//! not a not-yet) are a different species — express those by panicking
//! inside the probe; do not fold them into the budget.

use std::fmt::Display;
use std::time::Duration;

/// The poll period. Budgets are the contract; this is an implementation
/// detail — do not tune it per call site.
pub const POLL_PERIOD: Duration = Duration::from_millis(200);

/// Polls `probe` every [`POLL_PERIOD`] until it yields `Ok` (returning the
/// awaited value) or `budget` elapses; on timeout, panics with `what` and
/// the last observation.
///
/// ```no_run
/// # async fn demo() {
/// use std::time::Duration;
/// let v: u8 = interflow_testkit::wait::eventually(
///     "the counter to reach 3",
///     Duration::from_secs(10),
///     || {
///         let v = read_counter();
///         (v >= 3).then_some(v).ok_or_else(|| format!("counter at {v}"))
///     },
/// )
/// .await;
/// # }
/// # fn read_counter() -> u8 { 3 }
/// ```
pub async fn eventually<T, E, F>(what: &str, budget: Duration, mut probe: F) -> T
where
    F: FnMut() -> Result<T, E>,
    E: Display,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut last = None;
    loop {
        match probe() {
            Ok(v) => return v,
            Err(obs) => drop(last.replace(obs)),
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out after {budget:?} waiting for {what} (last observation: {})",
                observation(&last)
            );
        }
        tokio::time::sleep(POLL_PERIOD).await;
    }
}

/// The std twin of [`eventually`] for plain (non-async) unit tests:
/// `std::thread::sleep` between probes, same semantics and same timeout
/// message shape.
pub fn eventually_sync<T, E, F>(what: &str, budget: Duration, mut probe: F) -> T
where
    F: FnMut() -> Result<T, E>,
    E: Display,
{
    let deadline = std::time::Instant::now() + budget;
    let mut last = None;
    loop {
        match probe() {
            Ok(v) => return v,
            Err(obs) => drop(last.replace(obs)),
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out after {budget:?} waiting for {what} (last observation: {})",
                observation(&last)
            );
        }
        std::thread::sleep(POLL_PERIOD);
    }
}

/// Renders the last observation, with an unreachable-in-practice fallback
/// (the probe always runs before the deadline check).
fn observation<E: Display>(last: &Option<E>) -> String {
    last.as_ref()
        .map_or_else(|| "(no observation)".to_owned(), ToString::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Returns the awaited value once the probe is satisfied, after any
    /// number of misses.
    #[test]
    fn sync_returns_value_after_misses() {
        let misses = std::cell::Cell::new(0);
        let got = eventually_sync("the probe to be satisfied", Duration::from_secs(5), || {
            misses.set(misses.get() + 1);
            (misses.get() >= 2)
                .then_some(misses.get())
                .ok_or_else(|| format!("miss {}", misses.get()))
        });
        assert_eq!(got, 2);
        assert_eq!(misses.get(), 2);
    }

    /// A probe that stays unsatisfied exhausts the budget and the panic
    /// names what was waited for plus the LAST observation (not an earlier
    /// one, and never nothing).
    #[test]
    #[should_panic = "waiting for the impossible (last observation: attempt 2"]
    fn sync_timeout_embeds_last_observation() {
        let attempts = std::cell::Cell::new(0);
        let _ = eventually_sync("the impossible", Duration::from_millis(50), || {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(format!("attempt {}", attempts.get()))
        });
    }

    /// The async twin returns the awaited value with the same semantics.
    #[tokio::test]
    async fn async_returns_value_after_misses() {
        let misses = std::cell::Cell::new(0);
        let got: u8 = eventually("the probe to be satisfied", Duration::from_secs(5), || {
            misses.set(misses.get() + 1);
            (misses.get() >= 2)
                .then_some(7)
                .ok_or_else(|| format!("miss {}", misses.get()))
        })
        .await;
        assert_eq!(got, 7);
        assert_eq!(misses.get(), 2);
    }

    /// The async twin's timeout panic carries what and the last
    /// observation.
    #[tokio::test]
    #[should_panic = "waiting for the impossible (last observation: attempt 2"]
    async fn async_timeout_embeds_last_observation() {
        let attempts = std::cell::Cell::new(0);
        let _ = eventually("the impossible", Duration::from_millis(50), || {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(format!("attempt {}", attempts.get()))
        })
        .await;
    }
}
