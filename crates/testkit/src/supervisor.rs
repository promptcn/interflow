//! A systemd-style supervisor simulation for credential-lifecycle e2e.
//!
//! The production contract under test is lifecycle gap G4.
//! The renewal scheduler turns a completed rotation into a **clean process
//! exit**, and the installed unit restarts the node onto the newly selected
//! material.
//! [`restart_on_success`] is that unit's Restart=on-success semantics,
//! bounded — e2e observes the whole loop without a real init system.

use interflow_core::error::Result;
use std::future::Future;

/// Runs `segment` under bounded `Restart=on-success` semantics: a clean
/// exit restarts the segment (the renewal contract — exit onto the next
/// material), `max_restarts` clean exits exhaust the budget and the loop
/// returns how many restarts it performed, and any `Err` propagates
/// immediately (a failing segment fails the test, mirroring the units'
/// failure visibility rather than a restart-storm policy).
///
/// `segment` runs once more than the number of restarts: e.g.
/// `max_restarts = 1` runs the segment, restarts once, runs it again, and
/// returns `Ok(1)` when that second run also exits cleanly.
pub async fn restart_on_success<F, Fut>(mut segment: F, max_restarts: usize) -> Result<usize>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let mut restarts = 0;
    loop {
        segment().await?;
        if restarts >= max_restarts {
            return Ok(restarts);
        }
        restarts += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn clean_exits_restart_until_the_budget_is_spent() {
        let runs = AtomicUsize::new(0);
        let restarts = restart_on_success(
            || async {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            2,
        )
        .await
        .unwrap();
        assert_eq!(restarts, 2);
        assert_eq!(runs.load(Ordering::SeqCst), 3, "segments = restarts + 1");
    }

    #[tokio::test]
    async fn zero_budget_runs_once() {
        let runs = AtomicUsize::new(0);
        let restarts = restart_on_success(
            || async {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            0,
        )
        .await
        .unwrap();
        assert_eq!(restarts, 0);
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failing_segment_propagates_without_restart() {
        let runs = AtomicUsize::new(0);
        let result = restart_on_success(
            || async {
                if runs.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(interflow_core::error::InterflowError::config(
                        "segment failed",
                    ))
                } else {
                    panic!("must not restart after a failure");
                }
            },
            5,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }
}
