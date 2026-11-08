//! The hub's resident-task watchdog — the armed-assertion face behind the
//! fleet faces' `watchers` rows
//!
//! Every resident hub task logs `watcher armed` once at spawn — an EDGE,
//! and edges are invisible to every read face: a task that wedges without
//! erroring (a panic swallowed by the runtime, a loop stuck on a lock, a
//! spawn that never happened) leaves the faces looking exactly as before
//! until secondary symptoms (a watermark that stops advancing, sessions
//! that stop converging) accumulate. The CRL-restart-loop shape
//! (`ad2679a`) was found by scrolling journal lines until a pattern
//! emerged; this face turns "the process is alive but a task inside it
//! died" into a one-glance assertion.
//!
//! The shape is the level-triggered family's: each task registers its row
//! at spawn (`register`) and touches `last_tick_unix` every loop pass
//! (`touch`). Liveness is the LEVEL (the tick instants), not the armed
//! edge — the same armed→level discipline the policy face applies to
//! pulls. Every row carries its own cadence anchor (`interval_secs`), so
//! the silent judgment is "quieter than its own rhythm", never a global
//! threshold: [`WATCHER_SILENT_FACTOR`] multiples of the row's interval,
//! strictly greater (exactly N× is a slow pass, not silence).
//!
//! Bump discipline (see `hub::floor_clock`): ONLY class transitions —
//! a fresh→silent crossing found by the sweep, or a silent→fresh
//! revival on the task's next touch. Registration deliberately bumps
//! NOTHING: every row is born during hub boot, before the first accept,
//! so no floor watcher can hold a pre-row view the bump would refresh
//! (an idle hub keeps version 0 — the floor-watch contract's "nothing
//! has fed the read model" reading). Steady ticking likewise bumps
//! nothing — a clock that ticks every interval would degenerate the
//! floor watch into polling.
//!
//! Scope (the backlog's boundary): hub-process tasks only. Agent-side
//! task liveness rides the existing connection/heartbeat faces (offline
//! is absence, already a signal) — no duplicate machinery.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// A row reads silent when its tick went quiet for STRICTLY more than
/// this many multiples of its own interval.
///
/// One or two missed passes are scheduler jitter / a slow sweep — three
/// quiet cadences match no healthy loop. Single-sourced here; doctor and
/// the GUI read this constant (the overview self-reports it for the TS
/// classifier).
pub const WATCHER_SILENT_FACTOR: u64 = 3;

/// The sweep cadence — same shape as the sibling faces': detection latency
/// is bounded by the row's silent threshold plus one sweep; the cost is a
/// lock-guarded scan with zero bumps in steady state.
const WATCHDOG_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// One watcher row as the faces carry it (the wire-visible level: cadence
/// anchor + instants; presence in the table IS `armed` — rows never leave,
/// a dead task's row simply goes silent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherFaceRow {
    /// The task's registry name (stable across restarts; the journal's
    /// `watcher armed` lines use the same vocabulary).
    pub name: String,
    /// The task's own loop cadence, seconds — the silence judgment's
    /// anchor.
    pub interval_secs: u64,
    /// Unix seconds of this row's (re-)registration.
    pub started_unix: u64,
    /// Unix seconds of the last loop pass.
    pub last_tick_unix: u64,
}

/// Whether a row reads silent at `now_unix` — the classification shared by
/// the sweep, doctor, and the GUI (pure so all three stay one judgment).
pub const fn is_silent(row: &WatcherFaceRow, now_unix: u64) -> bool {
    let age = now_unix.saturating_sub(row.last_tick_unix);
    age > WATCHER_SILENT_FACTOR.saturating_mul(row.interval_secs)
}

/// Internal row state (the silent class is sweep-internal bookkeeping —
/// the face carries the raw instants, consumers classify).
#[derive(Debug)]
struct Row {
    interval_secs: u64,
    started_unix: u64,
    last_tick_unix: u64,
    /// Whether the sweep has already marked this row silent (one bump per
    /// class transition).
    silent: bool,
}

impl Row {
    fn face_row(&self, name: &str) -> WatcherFaceRow {
        WatcherFaceRow {
            name: name.to_owned(),
            interval_secs: self.interval_secs,
            started_unix: self.started_unix,
            last_tick_unix: self.last_tick_unix,
        }
    }
}

/// The shared registry.
///
/// In-memory by design: after a hub restart each task re-registers at
/// spawn, so the face refills by construction within one interval, and
/// the first-registration bump makes that refill push-visible to floor
/// watchers.
pub struct WatchdogRegistry {
    inner: Mutex<BTreeMap<String, Row>>,
    floor: crate::hub::floor_clock::FloorClock,
}

impl WatchdogRegistry {
    pub const fn new(floor: crate::hub::floor_clock::FloorClock) -> Self {
        Self {
            inner: Mutex::new(BTreeMap::new()),
            floor,
        }
    }

    /// Registers (or re-registers) one task's row. Re-registration with a
    /// changed interval (a config reload moved the cadence) updates the
    /// anchor. Neither path bumps — rows are born at boot before any
    /// reader exists (see the module docs); only class transitions bump.
    pub fn register(&self, name: &str, interval_secs: u64, now_unix: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match inner.get_mut(name) {
            Some(row) => row.interval_secs = interval_secs,
            None => {
                inner.insert(
                    name.to_owned(),
                    Row {
                        interval_secs,
                        started_unix: now_unix,
                        last_tick_unix: now_unix,
                        silent: false,
                    },
                );
            }
        }
    }

    /// Records one loop pass. A silent row's first touch again is a
    /// revival (face-visible: the assertion face going back to armed).
    /// Touching an unregistered name is a no-op — an unregistered task has
    /// no row to attest and `register` owns the row's birth.
    pub fn touch(&self, name: &str, now_unix: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let revived = inner.get_mut(name).is_some_and(|row| {
            let was_silent = row.silent;
            row.last_tick_unix = now_unix;
            row.silent = false;
            was_silent
        });
        drop(inner);
        if revived {
            self.floor.bump();
        }
    }

    /// The steady loop call: keep the row's cadence anchor current and
    /// attest one pass. Bumps only on the transitions above — never on a
    /// steady tick.
    pub fn tick(&self, name: &str, interval_secs: u64, now_unix: u64) {
        self.register(name, interval_secs, now_unix);
        self.touch(name, now_unix);
    }

    /// Re-classifies silence: rows whose last tick went quiet past their
    /// own threshold enter the silent class (bumping the floor clock once
    /// per sweep that produced transitions — the watchers re-read the
    /// whole face, so one version advance covers a batch). Returns the
    /// number of transitions fired.
    pub fn sweep(&self, now_unix: u64) -> usize {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let transitions = inner
            .iter_mut()
            .filter(|(name, row)| !row.silent && is_silent(&row.face_row(name), now_unix))
            .map(|(_, row)| row.silent = true)
            .count();
        drop(inner);
        if transitions > 0 {
            self.floor.bump();
            metrics::counter!("interflow_hub_watchdog_silent_transitions_total")
                .increment(u64::try_from(transitions).unwrap_or(u64::MAX));
        }
        transitions
    }

    /// The face: every registered task, in deterministic name order.
    pub fn face(&self) -> BTreeMap<String, WatcherFaceRow> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .iter()
            .map(|(name, row)| (name.clone(), row.face_row(name)))
            .collect()
    }

    /// The face as the snapshot/floor rows carry it (name-sorted vector).
    pub fn face_rows(&self) -> Vec<WatcherFaceRow> {
        self.face().into_values().collect()
    }
}

/// Managed entry point of the silence sweeper.
///
/// When the loop body exits abnormally (including a panic), log it, count
/// it, and restart — the heartbeat supervisor's discipline. A liveness
/// detector that can silently vanish would be its own bug class.
pub fn spawn_watchdog_sweeper(
    state: std::sync::Arc<crate::hub::state::HubState>,
    tasks: &TaskTracker,
    shutdown: CancellationToken,
) {
    tasks.spawn(async move {
        // Register at spawn (same discipline as the sibling rows).
        state.watchdog.register(
            "watchdog_sweep",
            WATCHDOG_SWEEP_INTERVAL.as_secs(),
            now_unix(),
        );
        loop {
            let inner = tokio::spawn(run_watchdog_sweeper(state.clone(), shutdown.clone()));
            match inner.await {
                Ok(()) => break,
                Err(e) => {
                    metrics::counter!("interflow_hub_watchdog_sweeper_restarts").increment(1);
                    tracing::error!(
                        "watchdog sweeper exited abnormally ({e}), restarting after \
                         {WATCHDOG_SWEEP_INTERVAL:?}"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(WATCHDOG_SWEEP_INTERVAL) => {}
                    }
                }
            }
        }
    });
}

/// The sweep loop: every interval, re-classify silence. Steady state bumps
/// nothing; a fresh→silent crossing bumps exactly once.
async fn run_watchdog_sweeper(
    state: std::sync::Arc<crate::hub::state::HubState>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(WATCHDOG_SWEEP_INTERVAL) => {}
        }
        state.watchdog.tick(
            "watchdog_sweep",
            WATCHDOG_SWEEP_INTERVAL.as_secs(),
            now_unix(),
        );
        state.watchdog.sweep(now_unix());
    }
}

/// The hub clock as this module reads it (one definition, one conversion).
fn now_unix() -> u64 {
    u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0)
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

    fn registry() -> (WatchdogRegistry, crate::hub::floor_clock::FloorClock) {
        let clock = crate::hub::floor_clock::FloorClock::new();
        (WatchdogRegistry::new(clock.clone()), clock)
    }

    #[test]
    fn registration_never_bumps_only_class_transitions_do() {
        let (watchdog, clock) = registry();
        // Rows are born at boot before any reader: an idle hub keeps
        // version 0 (the floor-watch contract's "nothing has fed the read
        // model" reading), no matter how many rows register.
        watchdog.register("heartbeat", 15, 1_000);
        watchdog.register("policy", 10, 1_000);
        assert_eq!(clock.version(), 0);
        // Steady ticks and idempotent re-registrations stay quiet.
        watchdog.tick("heartbeat", 15, 1_015);
        watchdog.tick("heartbeat", 15, 1_030);
        watchdog.register("heartbeat", 15, 1_031);
        assert_eq!(clock.version(), 0);
        // An interval change updates the anchor silently.
        watchdog.register("heartbeat", 30, 1_032);
        assert_eq!(clock.version(), 0);
        let face = watchdog.face();
        assert_eq!(face.get("heartbeat").unwrap().interval_secs, 30);
    }

    #[test]
    fn silence_is_strictly_past_factor_times_interval() {
        let row = WatcherFaceRow {
            name: "policy".to_owned(),
            interval_secs: 10,
            started_unix: 0,
            last_tick_unix: 1_000,
        };
        // Exactly N×interval: a slow pass, not silence.
        assert!(!is_silent(&row, 1_030));
        // One second past: silent.
        assert!(is_silent(&row, 1_031));
        // The anchor is the row's OWN cadence, not a global threshold:
        // a 1h task with the same tick age stays armed (its threshold is
        // 3×3600 = 10_800 past the 1_000 tick).
        let slow = WatcherFaceRow {
            interval_secs: 3600,
            ..row
        };
        assert!(!is_silent(&slow, 1_030));
        assert!(!is_silent(&slow, 11_799));
        assert!(is_silent(&slow, 11_801));
    }

    #[test]
    fn sweep_marks_silent_once_revival_bumps_and_stays_quiet() {
        let (watchdog, clock) = registry();
        watchdog.tick("a", 10, 1_000);
        watchdog.tick("b", 10, 1_002);
        assert_eq!(clock.version(), 0);
        // Both cross in the same sweep (ages 33 and 31, both past the 30s
        // threshold): one version advance per batch.
        assert_eq!(watchdog.sweep(1_033), 2);
        assert_eq!(clock.version(), 1);
        // Staying silent is not news again.
        assert_eq!(watchdog.sweep(1_060), 0);
        assert_eq!(clock.version(), 1);
        // Revival: the task's next pass is a class transition.
        watchdog.touch("a", 1_070);
        assert_eq!(clock.version(), 2);
        assert_eq!(watchdog.sweep(1_075), 0);
        // The revived row's level shows the fresh tick.
        let face = watchdog.face();
        assert_eq!(face.get("a").unwrap().last_tick_unix, 1_070);
    }

    #[test]
    fn touch_of_an_unregistered_name_is_a_no_op() {
        let (watchdog, clock) = registry();
        watchdog.touch("ghost", 1_000);
        assert_eq!(clock.version(), 0);
        assert!(!watchdog.face().contains_key("ghost"));
    }

    #[test]
    fn face_rows_are_name_sorted() {
        let (watchdog, _clock) = registry();
        watchdog.register("crl_face_sweep", 5, 1_000);
        watchdog.register("heartbeat", 15, 1_000);
        let rows = watchdog.face_rows();
        let names: Vec<&str> = rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, vec!["crl_face_sweep", "heartbeat"]);
    }
}
