//! TunnelManager: wraps AgentHandle for start/stop, state broadcasting, and
//! bounded auto-restart after an unexpected supervisor death.
//!
//! The state directly uses the library-level `AgentState` (single source of
//! truth); the GUI only maps it for display.
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
use std::sync::Arc;
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

// The healthy-streak window (Connected this long clears the restart debt)
// lives inside SupervisorRestartPolicy — one source of truth.

#[derive(Clone)]
pub struct TunnelManager {
    handle: Arc<Mutex<Option<AgentHandle>>>,
    /// The args of the last successful start — the restart path's input.
    args: Arc<Mutex<Option<interflow_expose::client::ExposeArgs>>>,
    policy: Arc<Mutex<SupervisorRestartPolicy>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            handle: Arc::new(Mutex::new(None)),
            args: Arc::new(Mutex::new(None)),
            policy: Arc::new(Mutex::new(SupervisorRestartPolicy::new())),
        }
    }

    /// Current state (treated as Stopped when there is no handle).
    pub async fn state(&self) -> AgentState {
        match self.handle.lock().await.as_ref() {
            Some(h) => h.state(),
            None => AgentState::Stopped,
        }
    }

    /// Start the tunnel (user action): rejects a duplicate start only when
    /// the current agent is genuinely alive, resets the restart budget, and
    /// remembers the args for the auto-restart path.
    pub async fn start(
        &self,
        app: &AppHandle,
        args: interflow_expose::client::ExposeArgs,
    ) -> Result<(), String> {
        let mut guard = self.handle.lock().await;
        if let Some(h) = guard.as_ref() {
            // A supervisor that already ended (Stopped/Failed or a detected
            // death) never blocks a fresh start — pre-hardening this wedged
            // on "already running" forever.
            let alive = !matches!(h.state(), AgentState::Stopped | AgentState::Failed { .. })
                && !h.is_finished();
            if alive {
                return Err("tunnel is already running".into());
            }
        }
        *guard = None; // drop the ended handle
        *self.policy.lock().await = SupervisorRestartPolicy::new();
        *self.args.lock().await = Some(args);
        self.start_internal(app).await
    }

    /// The shared start path: build the agent, wire the state listener,
    /// store the handle. Called by [`Self::start`] (user) and by the
    /// dead-supervisor restart loop (keeps the attempt budget).
    async fn start_internal(&self, app: &AppHandle) -> Result<(), String> {
        let args = {
            let guard = self.args.lock().await;
            guard
                .clone()
                .ok_or_else(|| "no start arguments recorded".to_string())?
        };
        let handle = interflow_expose::client::start(&args).map_err(|e| e.to_string())?;

        // State listener: watch → tunnel-state event + tray refresh; a
        // dead supervisor (stream end, final state ∉ {Stopped, Failed})
        // enters the bounded restart loop.
        {
            let app = app.clone();
            let manager = self.clone();
            let mut rx = handle.subscribe_state();
            tauri::async_runtime::spawn(async move {
                let mut connected_since: Option<Instant> = None;
                loop {
                    let state = rx.borrow_and_update().clone();
                    if matches!(state, AgentState::Connected { .. }) {
                        connected_since.get_or_insert_with(Instant::now);
                        if let Some(since) = connected_since {
                            manager
                                .policy
                                .lock()
                                .await
                                .note_healthy_streak(since.elapsed());
                        }
                    } else {
                        connected_since = None;
                    }
                    emit_state(&app, &state);
                    // The supervisor ended and dropped the watch sender.
                    if rx.changed().await.is_err() {
                        let final_state = rx.borrow().clone();
                        if matches!(final_state, AgentState::Stopped | AgentState::Failed { .. }) {
                            emit_state(&app, &final_state);
                            return; // legitimate end — nothing to recover
                        }
                        // Spawned as its own task to break the future
                        // recursion (listener → restart → start_internal
                        // → listener): a recursive async chain cannot
                        // prove `Send` for the spawn bound.
                        let manager2 = manager.clone();
                        let app2 = app.clone();
                        tauri::async_runtime::spawn(async move {
                            manager2.restart_after_supervisor_death(&app2).await;
                        });
                        return;
                    }
                }
            });
        }

        emit_state(app, &handle.state());
        *self.handle.lock().await = Some(handle);
        Ok(())
    }

    /// Bounded auto-restart loop after a supervisor death: backoff → clear
    /// the dead handle → restart via the recorded args. Exhausting the
    /// budget surfaces as `Failed` (the tray/UI render it; the user owns
    /// any further restart).
    ///
    /// Returns a boxed future: the call graph is recursive (restart →
    /// start_internal → listener spawn → restart), and a concrete future
    /// type cannot prove `Send` through that cycle — the box erases it.
    fn restart_after_supervisor_death<'a>(
        &'a self,
        app: &'a AppHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(self.restart_after_supervisor_death_inner(app))
    }

    async fn restart_after_supervisor_death_inner(&self, app: &AppHandle) {
        loop {
            let decision = self.policy.lock().await.on_supervisor_death();
            match decision {
                RestartDecision::GiveUp => {
                    emit_state(
                        app,
                        &AgentState::Failed {
                            error: "tunnel supervisor exited unexpectedly; \
                                    automatic restart attempts exhausted"
                                .to_string(),
                        },
                    );
                    return;
                }
                RestartDecision::RestartIn(backoff) => {
                    emit_state(
                        app,
                        &AgentState::Reconnecting {
                            reason: "supervisor exited unexpectedly; restarting".to_string(),
                            backoff_secs: backoff.as_secs(),
                        },
                    );
                    tokio::time::sleep(backoff).await;
                    *self.handle.lock().await = None; // clear the dead handle
                    if self.start_internal(app).await.is_ok() {
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
        *self.args.lock().await = None; // a stop cancels any restart loop's input
        let handle = self.handle.lock().await.take();
        if let Some(h) = handle {
            h.shutdown_graceful().await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

fn emit_state(app: &AppHandle, state: &AgentState) {
    let _ = app.emit("tunnel-state", state);
    if let Some(tray) = app.tray_by_id("main") {
        crate::tray::refresh(&tray, state);
    }
}
