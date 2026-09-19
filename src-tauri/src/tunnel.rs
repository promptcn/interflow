//! TunnelManager: wraps AgentHandle for start/stop, state broadcasting, and
//! bounded auto-restart after an unexpected supervisor death.
//!
//! The state directly uses the library-level `AgentState` (single source of
//! truth); the GUI only maps it for display. UI side effects (frontend
//! event and tray refresh) are injected as a [`StateSink`] at construction —
//! this module has no dependency on the GUI framework and is testable as
//! plain domain logic.
//!
//! Concurrency design — the structural answer to the 2026-09-18 Stop
//! deadlock (`docs/bug/2026-09-18-gui-stop-deadlock-start-holds-handle-lock.md`):
//! all mutable state lives under ONE `std::sync::Mutex` and every critical
//! section is synchronous and sub-millisecond (`client::start` spawns the
//! supervisor and returns immediately; its one synchronous input check —
//! reading the client certificate for the agent-id/CN binding — touches two
//! small PEM files, and hub connectivity stays a background concern).
//! Nothing here ever needs to hold a lock across an `.await`, so
//! no async mutex exists to be held across one — tokio's `Mutex` is
//! non-reentrant, and a guard surviving into a nested `lock().await` parked
//! `stop`/`get_state` forever in every GUI build of 2026-09-17..18. Holding
//! a std guard across an await is now rejected compile-time workspace-wide
//! (`clippy::await_holding_lock` = deny).
//!
//! Dead-supervisor recovery (2026-09-16 panic-containment hardening): the
//! library guarantees the supervisor survives session-level panics, but a
//! panic in the supervisor's own frame is the outermost in-process layer —
//! nothing above it can rebuild it in-library. The state stream ending with
//! a final state that is neither `Stopped` nor `Failed` is that death
//! signal; this manager answers it with a bounded auto-restart
//! (`SupervisorRestartPolicy`: exponential backoff, attempt budget, healthy
//! streak clears the debt) and surfaces the exhaustion as `Failed` — the
//! user restarts manually from there.

use interflow_mesh::agent::{AgentHandle, AgentState, RestartDecision, SupervisorRestartPolicy};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

/// UI side-effect sink: frontend `tunnel-state` event + tray refresh, wired
/// in `lib.rs`; tests capture states with a Vec. Runs inside the manager's
/// critical section — must not call back into [`TunnelManager`] (that would
/// re-enter the mutex).
pub type StateSink = Arc<dyn Fn(&AgentState) + Send + Sync>;

/// Everything mutable the manager owns — one state machine under one lock:
/// `handle`/`args`/`policy` always transition as a group (a start sets all
/// three, a stop clears two, a restart attempt reads args and swaps the
/// handle), so there is no lock ordering to reason about and group
/// transitions are atomic.
struct Inner {
    handle: Option<AgentHandle>,
    /// The args of the last start — the restart path's input, cleared by a
    /// stop (the user's cancel of any pending restart).
    args: Option<interflow_expose::client::ExposeArgs>,
    policy: SupervisorRestartPolicy,
}

// The healthy-streak window (Connected this long clears the restart debt)
// lives inside SupervisorRestartPolicy — one source of truth.

#[derive(Clone)]
pub struct TunnelManager {
    inner: Arc<Mutex<Inner>>,
    on_state: StateSink,
}

impl TunnelManager {
    pub fn new(on_state: impl Fn(&AgentState) + Send + Sync + 'static) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                handle: None,
                args: None,
                policy: SupervisorRestartPolicy::new(),
            })),
            on_state: Arc::new(on_state),
        }
    }

    /// Poison-tolerant lock: a panic inside a critical section (contained by
    /// design elsewhere in this stack) must not wedge Start/Stop forever —
    /// a poisoned lock bricking the manager would recreate this bug's
    /// failure shape. The guarded values carry no panic-sensitive invariants.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Current state (treated as Stopped when there is no handle).
    pub fn state(&self) -> AgentState {
        match self.lock().handle.as_ref() {
            Some(h) => h.state(),
            None => AgentState::Stopped,
        }
    }

    /// Start the tunnel (user action): rejects a duplicate start only when
    /// the current agent is genuinely alive, resets the restart budget, and
    /// remembers the args for the auto-restart path. One synchronous
    /// critical section — the aliveness check and the handle store are
    /// atomic, so concurrent double-starts and half-started states cannot
    /// exist, and no lock is ever held across an await.
    pub fn start(&self, args: &interflow_expose::client::ExposeArgs) -> Result<(), String> {
        let mut inner = self.lock();
        if let Some(h) = inner.handle.as_ref() {
            // A supervisor that already ended (Stopped/Failed or a detected
            // death) never blocks a fresh start — pre-hardening this wedged
            // on "already running" forever.
            let alive = !matches!(h.state(), AgentState::Stopped | AgentState::Failed { .. })
                && !h.is_finished();
            if alive {
                return Err("tunnel is already running".into());
            }
        }
        inner.handle = None; // drop the ended handle
        inner.policy = SupervisorRestartPolicy::new();
        inner.args = Some(args.clone());
        self.start_locked(&mut inner, args)
    }

    /// The shared start path: build the agent, wire the state listener,
    /// store the handle. Called with the state lock held by [`Self::start`]
    /// (user) and by the dead-supervisor restart loop (keeps the attempt
    /// budget). Fully synchronous — `client::start` spawns the supervisor
    /// and returns immediately — and never locks the mutex itself; that is
    /// the invariant that makes holding the guard across it safe.
    fn start_locked(
        &self,
        inner: &mut Inner,
        args: &interflow_expose::client::ExposeArgs,
    ) -> Result<(), String> {
        let handle = interflow_expose::client::start(args).map_err(|e| e.to_string())?;

        // State listener: watch → sink + healthy-streak accounting; a dead
        // supervisor (stream end, final state ∉ {Stopped, Failed}) enters
        // the bounded restart loop.
        {
            let manager = self.clone();
            let mut rx = handle.subscribe_state();
            tokio::spawn(async move {
                let mut connected_since: Option<Instant> = None;
                loop {
                    let state = rx.borrow_and_update().clone();
                    if matches!(state, AgentState::Connected { .. }) {
                        connected_since.get_or_insert_with(Instant::now);
                        if let Some(since) = connected_since {
                            manager.lock().policy.note_healthy_streak(since.elapsed());
                        }
                    } else {
                        connected_since = None;
                    }
                    (manager.on_state)(&state);
                    // The supervisor ended and dropped the watch sender.
                    if rx.changed().await.is_err() {
                        let final_state = rx.borrow().clone();
                        if matches!(final_state, AgentState::Stopped | AgentState::Failed { .. }) {
                            (manager.on_state)(&final_state);
                            return; // legitimate end — nothing to recover
                        }
                        // Spawned as its own task to break the future
                        // recursion (listener → restart → start_locked
                        // → listener): a recursive async chain cannot
                        // prove `Send` for the spawn bound.
                        let manager2 = manager.clone();
                        tokio::spawn(async move {
                            manager2.restart_after_supervisor_death().await;
                        });
                        return;
                    }
                }
            });
        }

        (self.on_state)(&handle.state());
        inner.handle = Some(handle);
        Ok(())
    }

    /// Bounded auto-restart loop after a supervisor death: backoff → restart
    /// via the recorded args. Exhausting the budget surfaces as `Failed`
    /// (the tray/UI render it; the user owns any further restart).
    ///
    /// Returns a boxed future: the call graph is recursive (restart →
    /// start_locked → listener spawn → restart), and a concrete future
    /// type cannot prove `Send` through that cycle — the box erases it.
    fn restart_after_supervisor_death(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(self.restart_after_supervisor_death_inner())
    }

    async fn restart_after_supervisor_death_inner(&self) {
        loop {
            let decision = self.lock().policy.on_supervisor_death();
            match decision {
                RestartDecision::GiveUp => {
                    (self.on_state)(&AgentState::Failed {
                        error: "tunnel supervisor exited unexpectedly; \
                                automatic restart attempts exhausted"
                            .to_string(),
                    });
                    return;
                }
                RestartDecision::RestartIn(backoff) => {
                    (self.on_state)(&AgentState::Reconnecting {
                        reason: "supervisor exited unexpectedly; restarting".to_string(),
                        backoff_secs: backoff.as_secs(),
                    });
                    tokio::time::sleep(backoff).await;
                    // One synchronous attempt under one lock hold: read the
                    // recorded args, clear the dead handle, rebuild, store.
                    // A stop() that ran while we slept has cleared `args` —
                    // the user's cancel wins and the loop ends quietly (no
                    // budget burned, no spurious Failed). Doing build +
                    // store under the same hold also closes the window
                    // where a freshly built agent could slip past a
                    // concurrent stop and become unstoppable.
                    let mut inner = self.lock();
                    let Some(args) = inner.args.clone() else {
                        return;
                    };
                    inner.handle = None; // clear the dead handle
                    if self.start_locked(&mut inner, &args).is_ok() {
                        return; // fresh listener spawned by the new session
                    }
                    // Start itself failed (config/hub gone): loop for the
                    // next budgeted attempt or GiveUp.
                }
            }
        }
    }

    /// Stop the tunnel (graceful shutdown); no-op when no tunnel is running.
    /// Also the user's manual escape hatch from any auto-restart state.
    pub async fn stop(&self) -> Result<(), String> {
        let handle = {
            let mut inner = self.lock();
            inner.args = None; // a stop cancels any restart loop's input
            inner.handle.take()
        };
        if let Some(h) = handle {
            h.shutdown_graceful().await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TunnelManager;
    use interflow_mesh::agent::AgentState;
    use interflow_mesh::config::TransportKind;
    use interflow_testkit::{certs::TestCerts, hub_config, pick_ephemeral_port, spawn_hub};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    /// The regression gate for the 2026-09-18 deadlock: every GUI Start
    /// wedged `stop`/`get_state` forever (`start` held the state lock across
    /// an await that re-locked it). Start → Connected → Stop → Stopped must
    /// round-trip, five in a row, against a real in-process hub — the bug
    /// doc's acceptance criteria.
    #[tokio::test]
    async fn start_stop_round_trip() {
        let agent_id = "gui-tunnel-agent";
        let certs = TestCerts::generate("gui-tunnel", agent_id);
        let hub_port = pick_ephemeral_port();
        let hub = spawn_hub(hub_config(hub_port, &certs, Vec::new())).await;

        let events: Arc<Mutex<Vec<AgentState>>> = Arc::new(Mutex::new(Vec::new()));
        let sink_events = events.clone();
        let manager = TunnelManager::new(move |s| {
            sink_events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(s.clone());
        });

        const ROUNDS: usize = 5;
        for round in 0..ROUNDS {
            let (cert, key) = certs.client_paths();
            let args = interflow_expose::client::ExposeArgs {
                local_ports: vec![pick_ephemeral_port()],
                hub_url: format!("https://127.0.0.1:{hub_port}"),
                agent_id: agent_id.to_string(),
                client_cert: Some(cert.display().to_string()),
                client_key: Some(key.display().to_string()),
                ca_path: Some(certs.ca_path().display().to_string()),
                transport: TransportKind::H2,
                hub_quic_addr: None,
            };
            manager.start(&args).expect("round-trip start");

            // Poll until registered (Connected is set only after connect +
            // register complete).
            let deadline = Instant::now() + Duration::from_secs(10);
            while !matches!(manager.state(), AgentState::Connected { .. }) {
                assert!(
                    Instant::now() < deadline,
                    "round {round}: never Connected (state: {:?})",
                    manager.state()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            tokio::time::timeout(Duration::from_secs(10), manager.stop())
                .await
                .expect("stop() hung — the 2026-09-18 deadlock")
                .expect("graceful shutdown");
            assert!(
                matches!(manager.state(), AgentState::Stopped),
                "round {round}: state after stop: {:?}",
                manager.state()
            );
        }

        hub.shutdown().await.expect("hub shutdown");

        // The sink saw the full state sequences. The listener task emits the
        // final Stopped slightly after stop() returns, so poll for it.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let seen = events
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            let connected = seen
                .iter()
                .filter(|s| matches!(s, AgentState::Connected { .. }))
                .count();
            let stopped = seen
                .iter()
                .filter(|s| matches!(s, AgentState::Stopped))
                .count();
            if connected >= ROUNDS && stopped >= ROUNDS {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "sink never saw {ROUNDS} × Connected/Stopped (connected: {connected}, stopped: {stopped}, events: {seen:?})"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// `client::start` validates only its inputs synchronously (hub
    /// reachability is a background session concern; the CN binding check
    /// skips certificate-less configs like this one), so even an
    /// unreachable hub yields a handle and `start` returns. Pre-fix, the
    /// post-spawn handle store deadlocked and this never resolved; `stop`
    /// must then shut the failing agent down cleanly.
    #[tokio::test]
    async fn start_completes_without_reachable_hub() {
        let manager = TunnelManager::new(|_| {});
        let args = interflow_expose::client::ExposeArgs {
            local_ports: vec![pick_ephemeral_port()],
            hub_url: "https://127.0.0.1:1".to_string(),
            agent_id: "gui-hubless".to_string(),
            client_cert: None,
            client_key: None,
            ca_path: None,
            transport: TransportKind::H2,
            hub_quic_addr: None,
        };
        manager
            .start(&args)
            .expect("start returns without contacting the hub");

        // state() answers immediately (pre-fix: wedged behind the held lock).
        let _ = manager.state();

        tokio::time::timeout(Duration::from_secs(10), manager.stop())
            .await
            .expect("stop() hung — the 2026-09-18 deadlock")
            .expect("graceful shutdown of the failed agent");
        assert!(matches!(manager.state(), AgentState::Stopped));
    }

    // Not covered here: "stop during a restart backoff cancels the loop
    // quietly" — needs an injected supervisor death (testkit fault
    // injection); the semantics are enforced by the restart loop reading
    // `args` under the same lock the stop clears it with.
}
