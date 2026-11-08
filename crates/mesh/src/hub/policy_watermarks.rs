//! Level-triggered policy-pull watermarks — the face material behind the
//! fleet faces' `seen_generation` + `last_pull_unix`
//!
//! The `policy_pulled` audit ledger is EDGE-triggered by doctrine (one row
//! per generation-reaching-an-agent; steady-state 304s are authentication
//! activity, not ledger material — see `state::SharedPolicyPullLedger`).
//! Rendering a LEVEL face from that ledger inherited the family defect: a
//! leg that pulls healthily but is up to date never lands a ledger row, so
//! `policy_seen` read `never` for exactly the healthiest legs, and a dead
//! watcher between publishes was invisible (the watermark froze at a value
//! that looked current). The correct material for a read face is the level
//! itself: the current value PLUS its last confirmation instant, recorded
//! on EVERY completed pull — that is this table.
//!
//! The recency half is not decoration: without `last_pull_unix`, a policy
//! watcher that dies during a long silent period between publishes keeps a
//! face that reads healthy forever. `record` keeps rows fresh; the sweep
//! below is what makes the *absence* observable:
//!
//! - `record` fires on every pull (both transport faces funnel through
//!   `serve_policy_conditional`), so a pulling leg is always fresh.
//! - A dead watcher produces no writes at all — no pull, no bump, nothing.
//!   The ONLY structural path for "the absence started" to reach the push
//!   contract (`GET /policy/floor/version`) is a hub-side transition
//!   detector: [`PolicyWatermarks::sweep`] marks rows whose recency crossed
//!   the silent threshold and bumps the floor clock on that class
//!   transition (fresh→silent, and silent→fresh on revival). Presence uses
//!   the same shape (`last_pong` + dead-line eviction): a level state plus
//!   edge-fired visibility.
//!
//! Bump discipline (see `hub::floor_clock`): first sighting of an agent, a
//! watermark that actually advances, or a recency class transition. A
//! steady-state re-pull at the same watermark updates `last_pull_unix` but
//! must NOT bump — a clock that ticks every watch interval degenerates the
//! floor watch into polling.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::agent::policy_watch::POLICY_SILENT_AFTER_SECS;

/// The sweep cadence — how often the hub re-classifies recency. Detection
/// latency for a fresh→silent transition is bounded by the silent threshold
/// plus one sweep; the cost is a lock-guarded scan of one row per agent that
/// ever pulled, with zero bumps in steady state.
const POLICY_FACE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// One agent's face row (the wire-visible level: value + confirmation
/// instant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyWatermark {
    /// The agent's reported-or-served watermark (`fetch_max` semantics —
    /// a regressing report never lowers it).
    pub seen_generation: u64,
    /// Unix seconds of the last completed pull by this agent.
    pub last_pull_unix: u64,
}

/// Internal row state (the recency class is face-derivable and never
/// serialized — consumers judge from `last_pull_unix` against their own
/// capture anchor).
#[derive(Debug)]
struct Row {
    seen_generation: u64,
    last_pull_unix: u64,
    /// Whether the sweep has already marked this row silent (one bump per
    /// class transition).
    silent: bool,
}

/// The shared watermark table.
///
/// In-memory by design — after a hub restart every online agent's next
/// pull re-populates its row within one watch interval, so no catch-up
/// bookkeeping is owed; the first-sighting bump makes that refill
/// push-visible to floor watchers.
pub struct PolicyWatermarks {
    inner: Mutex<HashMap<String, Row>>,
    floor: crate::hub::floor_clock::FloorClock,
}

impl PolicyWatermarks {
    pub fn new(floor: crate::hub::floor_clock::FloorClock) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            floor,
        }
    }

    /// Records one completed pull. `seen` is the watermark the pull implies:
    /// the caller's reported watermark on an UpToDate answer, the served
    /// generation on an Update (the pull hands the agent that generation).
    /// A pull is activity by definition, so the row leaves the silent class.
    ///
    /// Bumps the floor clock only on an observable face change: first
    /// sighting, an advancing watermark, or revival from silent.
    pub fn record(&self, agent: &str, seen: u64, now_unix: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let face_changed = if let Some(row) = inner.get_mut(agent) {
            let advanced = seen > row.seen_generation;
            row.seen_generation = row.seen_generation.max(seen);
            row.last_pull_unix = now_unix;
            let revived = row.silent;
            row.silent = false;
            advanced || revived
        } else {
            inner.insert(
                agent.to_owned(),
                Row {
                    seen_generation: seen,
                    last_pull_unix: now_unix,
                    silent: false,
                },
            );
            true
        };
        drop(inner);
        if face_changed {
            self.floor.bump();
        }
    }

    /// Re-classifies recency: rows whose last pull is older than the silent
    /// threshold enter the silent class (bumping the floor clock once per
    /// sweep that produced transitions — the watchers re-read the whole
    /// face, so one version advance covers a batch). Returns the number of
    /// transitions fired.
    pub fn sweep(&self, now_unix: u64) -> usize {
        let threshold = POLICY_SILENT_AFTER_SECS;
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transitions = inner
            .values_mut()
            .filter(|row| !row.silent && now_unix.saturating_sub(row.last_pull_unix) > threshold)
            .map(|row| {
                row.silent = true;
            })
            .count();
        drop(inner);
        if transitions > 0 {
            self.floor.bump();
            metrics::counter!("interflow_hub_policy_silent_transitions_total")
                .increment(u64::try_from(transitions).unwrap_or(u64::MAX));
        }
        transitions
    }

    /// The face: every agent that ever pulled this hub process, in
    /// deterministic order.
    pub fn face(&self) -> BTreeMap<String, PolicyWatermark> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .iter()
            .map(|(agent, row)| {
                (
                    agent.clone(),
                    PolicyWatermark {
                        seen_generation: row.seen_generation,
                        last_pull_unix: row.last_pull_unix,
                    },
                )
            })
            .collect()
    }
}

/// Managed entry point of the recency sweeper.
///
/// When the loop body exits abnormally (including a panic), log it, count
/// it, and restart — the heartbeat supervisor's discipline
/// (`hub::heartbeat`). A liveness detector that can silently vanish would
/// be its own bug class.
pub fn spawn_policy_watermark_sweeper(
    state: std::sync::Arc<crate::hub::state::HubState>,
    tasks: &TaskTracker,
    shutdown: CancellationToken,
) {
    tasks.spawn(async move {
        // Register at spawn: the row (and its first-sighting bump) exists
        // before the hub answers anything.
        state.watchdog.register(
            "policy_face_sweep",
            POLICY_FACE_SWEEP_INTERVAL.as_secs(),
            u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
        );
        loop {
            let inner = tokio::spawn(run_policy_watermark_sweeper(
                state.clone(),
                shutdown.clone(),
            ));
            match inner.await {
                Ok(()) => break,
                Err(e) => {
                    metrics::counter!("interflow_hub_policy_face_sweeper_restarts").increment(1);
                    tracing::error!(
                        "policy watermark sweeper exited abnormally ({e}), restarting after \
                         {POLICY_FACE_SWEEP_INTERVAL:?}"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(POLICY_FACE_SWEEP_INTERVAL) => {}
                    }
                }
            }
        }
    });
}

/// The sweep loop: every interval, re-classify recency. Steady state bumps
/// nothing; a fresh→silent crossing bumps exactly once.
async fn run_policy_watermark_sweeper(
    state: std::sync::Arc<crate::hub::state::HubState>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(POLICY_FACE_SWEEP_INTERVAL) => {}
        }
        state.watchdog.tick(
            "policy_face_sweep",
            POLICY_FACE_SWEEP_INTERVAL.as_secs(),
            u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
        );
        state
            .policy_watermarks
            .sweep(u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0));
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

    fn marks() -> (PolicyWatermarks, crate::hub::floor_clock::FloorClock) {
        let clock = crate::hub::floor_clock::FloorClock::new();
        (PolicyWatermarks::new(clock.clone()), clock)
    }

    #[test]
    fn bump_discipline_first_sighting_advance_and_steady() {
        let (marks, clock) = marks();
        marks.record("site/a", 15, 1_000);
        assert_eq!(clock.version(), 1, "first sighting is face-visible");
        // Steady-state re-pull at the same watermark: recency moves, the
        // clock must not.
        marks.record("site/a", 15, 1_010);
        assert_eq!(clock.version(), 1);
        // A regressing report never lowers the watermark and never bumps.
        marks.record("site/a", 9, 1_020);
        assert_eq!(clock.version(), 1);
        // An advancing watermark is face-visible.
        marks.record("site/a", 16, 1_030);
        assert_eq!(clock.version(), 2);
        let face = marks.face();
        let row = face.get("site/a").unwrap();
        assert_eq!(row.seen_generation, 16);
        assert_eq!(row.last_pull_unix, 1_030);
    }

    #[test]
    fn sweep_marks_silent_once_bumps_on_transition_and_revival_bumps() {
        let (marks, clock) = marks();
        marks.record("site/a", 15, 1_000);
        assert_eq!(clock.version(), 1);
        // Below/at the threshold: no transition (1-2 missed ticks are
        // session-rebuild transients, not the silent class).
        assert_eq!(
            marks.sweep(1_030),
            0,
            "exactly 3×interval is not yet silent"
        );
        assert_eq!(clock.version(), 1);
        // One second past the threshold: the crossing fires once.
        assert_eq!(marks.sweep(1_031), 1);
        assert_eq!(clock.version(), 2);
        // Staying silent is not news again.
        assert_eq!(marks.sweep(1_060), 0);
        assert_eq!(clock.version(), 2);
        // Revival: a pull is a class transition and re-freshens the row.
        marks.record("site/a", 15, 1_070);
        assert_eq!(clock.version(), 3);
        assert_eq!(marks.sweep(1_075), 0);
        let face = marks.face();
        assert_eq!(face.get("site/a").unwrap().last_pull_unix, 1_070);
    }

    #[test]
    fn sweep_bumps_once_per_batch_not_per_row() {
        let (marks, clock) = marks();
        marks.record("site/a", 15, 1_000);
        marks.record("site/b", 15, 1_002);
        assert_eq!(clock.version(), 2);
        // Both cross in the same sweep (ages 33s and 31s, both past the
        // 30s threshold): one version advance, one re-read.
        assert_eq!(marks.sweep(1_033), 2);
        assert_eq!(clock.version(), 3);
    }
}
