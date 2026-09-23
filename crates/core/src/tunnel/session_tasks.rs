//! Session task supervision: the death contract and the stall heartbeat.
//!
//! Two invariants every session-critical task must satisfy (the panic
//! containment design):
//!
//! 1. **Death contract**: a critical task exiting — by returning, by
//!    panicking (the JoinError surfaces here), or by abort — ends the
//!    session: [`SessionTasks`] cancels the session token (the supervisor
//!    rebuilds), counts `interflow_agent_session_critical_task_exit_total
//!    {task, reason}`, and reports the exit over [`SessionTasks::exits`]
//!    so the session's select can attribute its end precisely. No critical
//!    task may be fire-and-forget.
//!
//! 2. **Stall heartbeat**: death is not the only abnormal exit — a task can
//!    *wedge* (alive, awaiting forever; the fault-injection `stall` points
//!    model this). A wedged critical task keeps its channels open (sends
//!    buffer as fake successes), so only the task itself can prove
//!    liveness: it beats periodically via [`Beat`], and a monitor ends the
//!    session when the beat goes silent past the stall timeout. Tasks
//!    without a provable idle cadence pass `None` and are only
//!    death-supervised.
//!
//! Panic containment uses tokio's native boundary: the inner future is
//! spawned first and its JoinHandle awaited by the wrapper (a task panic
//! becomes a JoinError the wrapper observes) — no `catch_unwind`.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::warn;

/// How a critical task exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskExitReason {
    /// The future returned normally.
    Returned,
    /// The task panicked (JoinError `is_panic`).
    Panicked,
    /// The task was aborted (JoinError cancelled).
    Aborted,
}

impl TaskExitReason {
    const fn name(self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Panicked => "panicked",
            Self::Aborted => "aborted",
        }
    }
}

/// A critical task's exit report, drained by the session's end-select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskExit {
    /// Which task (the `name` given to [`SessionTasks::spawn_critical`]).
    pub task: &'static str,
    /// How it exited.
    pub reason: TaskExitReason,
}

/// Shared liveness cell for one critical task: the beat timestamp plus the
/// clock epoch both the task and its monitor compute against (tokio
/// `Instant`, so paused-clock unit tests stay exact).
struct BeatState {
    epoch: tokio::time::Instant,
    /// Micros since `epoch` of the last beat; 0 = never.
    last_us: AtomicU64,
}

impl BeatState {
    fn now_us(&self) -> u64 {
        self.epoch
            .elapsed()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn since_last_beat(&self) -> Duration {
        let last = self.last_us.load(Ordering::Acquire);
        if last == 0 {
            return Duration::ZERO;
        }
        Duration::from_micros(self.now_us().saturating_sub(last))
    }
}

/// Liveness handle handed to a critical task: call [`Beat::beat`] from a
/// select tick arm (or any loop point) to prove the task is progressing.
#[derive(Clone)]
pub struct Beat {
    state: Arc<BeatState>,
}

impl Beat {
    /// Records a liveness beat ("this task is still progressing").
    pub fn beat(&self) {
        let now = self.state.now_us();
        // +1 keeps 0 meaning "never":
        self.state
            .last_us
            .store(now.saturating_add(1), Ordering::Release);
    }

    /// Awaits `fut` while beating at `every` — the composable form of a
    /// select tick arm, so long waits (frame reads, backoff sleeps,
    /// connection watchers) prove liveness without restructuring their
    /// surrounding selects. The beater never resolves; `fut`'s output (or
    /// its cancellation by an outer select) is the only way out.
    pub async fn during<F: Future>(&self, every: Duration, fut: F) -> F::Output {
        let beater = async {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                self.beat();
            }
        };
        tokio::select! {
            // The beater never resolves; pending::<F::Output> types the arm
            // without constraining F.
            () = beater => std::future::pending::<F::Output>().await,
            out = fut => out,
        }
    }
}

/// Tick cadence for [`Beat::during`] given a stall timeout.
///
/// A third of the timeout, clamped to [100ms, 1s]. A zero (disabled)
/// timeout still gets a 1s cadence — beats are cheap and keep the metric
/// meaningful if a monitor is attached later.
pub fn beat_interval(stall: Duration) -> Duration {
    if stall.is_zero() {
        return Duration::from_secs(1);
    }
    (stall / 3).clamp(Duration::from_millis(100), Duration::from_secs(1))
}

/// Per-session task supervisor: one per session, cloned into every spawn
/// site (h2/QUIC transports, mesh handlers, connection watchers).
///
/// Owns the session's [`TaskTracker`] (wind-down boundedness for critical
/// and auxiliary tasks alike) and cascades to the session token.
#[derive(Clone)]
pub struct SessionTasks {
    inner: Arc<Inner>,
}

struct Inner {
    token: CancellationToken,
    tracker: TaskTracker,
    exits_rx: Mutex<Option<mpsc::Receiver<TaskExit>>>,
    exits_tx: mpsc::Sender<TaskExit>,
    epoch: tokio::time::Instant,
}

impl SessionTasks {
    /// Creates the supervisor for a session. `token` is the session token
    /// whose cancellation tears the session down (the agent supervisor
    /// then rebuilds).
    pub fn new(token: CancellationToken) -> Self {
        let (exits_tx, exits_rx) = mpsc::channel(16);
        Self {
            inner: Arc::new(Inner {
                token,
                tracker: TaskTracker::new(),
                exits_rx: Mutex::new(Some(exits_rx)),
                exits_tx,
                epoch: tokio::time::Instant::now(),
            }),
        }
    }

    /// The session token this supervisor cascades to.
    pub fn token(&self) -> &CancellationToken {
        &self.inner.token
    }

    /// The underlying tracker — for spawning session children that are not
    /// critical (listeners, forwarders, pumps) so wind-down stays bounded.
    pub fn tracker(&self) -> &TaskTracker {
        &self.inner.tracker
    }

    /// Takes the critical-task exit receiver (once per session): the
    /// session's end-select awaits it to attribute `CriticalTaskExit`
    /// endings. Panics if called twice — one session, one select.
    pub async fn exits(&self) -> mpsc::Receiver<TaskExit> {
        self.inner
            .exits_rx
            .lock()
            .await
            .take()
            .expect("exits() called twice for one SessionTasks")
    }

    /// Spawns a session-critical task under the death contract.
    ///
    /// `build` receives the [`Beat`] handle so the future can prove
    /// liveness from inside (a select tick arm); with `stall_timeout` set
    /// (non-zero), a monitor ends the session when the beat goes silent
    /// that long. `None` (or zero) disables stall supervision
    /// (death-only).
    ///
    /// Any exit while the token is not yet cancelled cancels the token
    /// (idempotent), logs, counts, and reports over the exits channel.
    pub fn spawn_critical<B, F>(
        &self,
        name: &'static str,
        stall_timeout: Option<Duration>,
        build: B,
    ) -> tokio::task::JoinHandle<()>
    where
        B: FnOnce(Beat) -> F + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let beat = Beat {
            state: Arc::new(BeatState {
                epoch: self.inner.epoch,
                last_us: AtomicU64::new(0),
            }),
        };
        // Beat at construction: a task that dies immediately must not first
        // look like a stall (the monitor would race the death report).
        beat.beat();

        let token = self.inner.token.clone();
        let exits_tx = self.inner.exits_tx.clone();
        let state = beat.state.clone();

        let wrapper = self.inner.tracker.spawn(async move {
            // Inner spawn: tokio's panic boundary. The wrapper (this task)
            // observes the JoinError instead of dying with it.
            let inner = tokio::spawn(build(beat));
            let joined = inner.await;
            if token.is_cancelled() {
                return; // normal wind-down, or another task already ended the session
            }
            let reason = match joined {
                Ok(()) => TaskExitReason::Returned,
                Err(e) if e.is_cancelled() => TaskExitReason::Aborted,
                Err(_) => TaskExitReason::Panicked,
            };
            metrics::counter!(
                "interflow_agent_session_critical_task_exit_total",
                "task" => name,
                "reason" => reason.name()
            )
            .increment(1);
            warn!("critical task '{name}' exited ({reason:?}); ending the session for rebuild");
            let _ = exits_tx.try_send(TaskExit { task: name, reason });
            token.cancel();
        });

        let Some(timeout) = stall_timeout.filter(|t| !t.is_zero()) else {
            return wrapper;
        };
        let token = self.inner.token.clone();
        let check_every = (timeout / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
        self.inner.tracker.spawn(async move {
            let mut tick = tokio::time::interval(check_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    () = token.cancelled() => return,
                    _ = tick.tick() => {}
                }
                let silent_for = state.since_last_beat();
                if silent_for >= timeout {
                    metrics::counter!(
                        "interflow_agent_session_critical_task_stall_total",
                        "task" => name
                    )
                    .increment(1);
                    warn!(
                        "critical task '{name}' stalled (no beat for {silent_for:?} ≥ {timeout:?}); ending the session for rebuild"
                    );
                    token.cancel();
                    return;
                }
            }
        });
        wrapper
    }

    /// Spawns an auxiliary session task: tracker membership only (bounded
    /// wind-down), no death cascade — for tasks whose exit degrades but
    /// does not invalidate the session (pong answers, stats samplers).
    pub(crate) fn spawn_auxiliary<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.inner.tracker.spawn(future);
    }

    /// Bounded wind-down: close the tracker and wait out the grace,
    /// counting a metric when tasks ignore the token past it.
    pub async fn close_and_wait(&self, grace: Duration) {
        self.inner.tracker.close();
        if tokio::time::timeout(grace, self.inner.tracker.wait())
            .await
            .is_err()
        {
            metrics::counter!("interflow_agent_session_tasks_drain_timeout_total").increment(1);
            warn!("session task tracker did not drain within {grace:?}");
        }
    }
}

/// Last-resort guard for the session owner.
///
/// Cancels the session token on ANY exit from the owning frame — including
/// a panic unwind (dropping a child token does NOT cancel it; only
/// `cancel()` does, so an unguarded panic leaks the session's children).
/// Defense in depth under [`SessionTasks`]: if a future refactor bypasses
/// the supervisor, the children still get torn down.
pub struct SessionExitGuard(CancellationToken);

impl SessionExitGuard {
    /// Arms the guard; hold it for the whole session frame.
    pub const fn new(token: CancellationToken) -> Self {
        Self(token)
    }
}

impl Drop for SessionExitGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod tests {
    // panic_any is the mechanism under test (contained-panic semantics).
    #![allow(clippy::panic)]

    use super::*;
    use std::time::Duration;

    /// A critical task returning normally (while the token is live) cancels
    /// the token and reports `Returned`.
    #[tokio::test]
    async fn critical_task_return_cancels_and_reports() {
        let token = CancellationToken::new();
        let tasks = SessionTasks::new(token.clone());
        let mut exits = tasks.exits().await;
        tasks.spawn_critical("probe", None, |_beat| async {});
        token.cancelled().await;
        let exit = tokio::time::timeout(Duration::from_secs(5), exits.recv())
            .await
            .expect("exit report within deadline")
            .expect("channel open");
        assert_eq!(exit.task, "probe");
        assert_eq!(exit.reason, TaskExitReason::Returned);
    }

    /// A critical task PANICKING is contained: the wrapper survives, cancels
    /// the token, and reports `Panicked` — the supervisor-shaped guarantee.
    #[tokio::test]
    async fn critical_task_panic_is_contained() {
        let token = CancellationToken::new();
        let tasks = SessionTasks::new(token.clone());
        let mut exits = tasks.exits().await;
        tasks.spawn_critical("bomb", None, |_beat| async {
            std::panic::panic_any("boom");
        });
        token.cancelled().await;
        let exit = tokio::time::timeout(Duration::from_secs(5), exits.recv())
            .await
            .expect("exit report within deadline")
            .expect("channel open");
        assert_eq!(exit.reason, TaskExitReason::Panicked);
    }

    /// An already-cancelled token means normal wind-down: no exit report,
    /// no double-cancel side effects.
    #[tokio::test]
    async fn exit_during_wind_down_is_silent() {
        let token = CancellationToken::new();
        let tasks = SessionTasks::new(token.clone());
        let mut exits = tasks.exits().await;
        token.cancel();
        tasks.spawn_critical("orderly", None, |_beat| async {});
        tasks.close_and_wait(Duration::from_secs(5)).await;
        assert!(exits.try_recv().is_err(), "no exit report during wind-down");
    }

    /// A wedged task (never beats) trips the stall monitor; a beating task
    /// does not.
    #[tokio::test(start_paused = true)]
    async fn stall_monitor_trips_on_silent_beat() {
        let token = CancellationToken::new();
        let tasks = SessionTasks::new(token.clone());
        tasks.spawn_critical("wedged", Some(Duration::from_secs(10)), |_beat| {
            std::future::pending::<()>()
        });
        tasks.spawn_critical(
            "healthy",
            Some(Duration::from_secs(10)),
            |beat| async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    beat.beat();
                }
            },
        );
        // ~10s of virtual time: the wedged task's monitor fires, the healthy
        // one keeps beating.
        let _ = tokio::time::timeout(Duration::from_secs(30), token.cancelled()).await;
        assert!(token.is_cancelled(), "the wedged task must end the session");
        token.cancel();
        tasks.close_and_wait(Duration::from_secs(5)).await;
    }

    /// The stall monitor stays quiet while the task beats — 40s of virtual
    /// time past a 10s timeout with 1s beats must NOT cancel.
    #[tokio::test(start_paused = true)]
    async fn stall_monitor_quiet_while_beating() {
        let token = CancellationToken::new();
        let tasks = SessionTasks::new(token.clone());
        tasks.spawn_critical("steady", Some(Duration::from_secs(10)), |beat| async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                beat.beat();
            }
        });
        tokio::time::sleep(Duration::from_secs(40)).await;
        assert!(
            !token.is_cancelled(),
            "a beating task must not be judged stalled"
        );
        token.cancel();
        tasks.close_and_wait(Duration::from_secs(5)).await;
    }

    /// The session-exit guard cancels on drop — including panic unwind.
    #[tokio::test]
    async fn exit_guard_cancels_on_panic_unwind() {
        let token = CancellationToken::new();
        let handle = tokio::spawn({
            let token = token.clone();
            async move {
                let _guard = SessionExitGuard::new(token);
                std::panic::panic_any("session frame blew up");
            }
        });
        assert!(handle.await.is_err(), "the inner task must have panicked");
        assert!(
            token.is_cancelled(),
            "the guard must cancel despite the unwind"
        );
    }
}
