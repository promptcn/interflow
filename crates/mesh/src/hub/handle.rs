//! `HubHandle` — the hub-side analogue of the agent's `AgentHandle`.
//!
//! The hub server itself is config-in/future-out ([`HubServer::run_until`]);
//! this wrapper gives embedders that host a hub next to other nodes (the GUI,
//! testkit) the same lifecycle vocabulary an agent has: a spawn that returns
//! immediately, a watch stream of lifecycle states, and a graceful shutdown
//! that resolves after the drain completes.
//!
//! State model: `Starting → Running → Stopping → Stopped`, with `Failed`
//! reachable from `Starting` (e.g. listen bind failure — the run future ends
//! before the readiness signal fires) and from `Running` (a hub that dies on
//! its own). There is no reconnect machinery to model: unlike an agent, a hub
//! that fails does not retry; the embedder owns any restart policy.

use crate::config::HubConfig;
use crate::hub::server::HubServer;
use interflow_core::error::{InterflowError, Result};
use serde::Serialize;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Lifecycle of a spawned hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum HubLifecycle {
    /// Spawned; listeners not yet bound.
    Starting,
    /// TCP (and QUIC, when enabled) listeners up; accepting agents.
    Running,
    /// Shutdown requested; draining connections (10s drain deadline).
    Stopping,
    /// Drained and stopped by request.
    Stopped,
    /// Failed to start or died on its own (e.g. listen port busy).
    Failed {
        /// Human-readable failure reason.
        error: String,
    },
}

/// A running in-process hub.
///
/// Dropping the handle does **not** stop the hub — call
/// [`HubHandle::shutdown_graceful`] for a clean drain (stop accepting →
/// QUIC CONNECTION_CLOSE → h2 GOAWAY → task-group close → audit flush).
pub struct HubHandle {
    state: watch::Receiver<HubLifecycle>,
    shutdown_token: CancellationToken,
    /// The run outcome, delivered by the monitor task when the hub ends
    /// (either path: user shutdown or self-failure).
    result: oneshot::Receiver<Result<()>>,
}

/// Maps a joined run future to the terminal lifecycle + result pair.
fn join_outcome(
    joined: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> (HubLifecycle, Result<()>) {
    match joined {
        Ok(Ok(())) => (HubLifecycle::Stopped, Ok(())),
        Ok(Err(e)) => (
            HubLifecycle::Failed {
                error: e.to_string(),
            },
            Err(e),
        ),
        Err(join_err) => {
            let error = format!("hub task join failed: {join_err}");
            (
                HubLifecycle::Failed {
                    error: error.clone(),
                },
                Err(InterflowError::connection(error)),
            )
        }
    }
}

impl HubHandle {
    /// Spawns a hub and returns immediately. Assembly failures (TLS plane,
    /// config validation) fail here; runtime failures (listen bind, a later
    /// death) surface asynchronously as [`HubLifecycle::Failed`] on the state
    /// stream — the same split the agent makes between `AgentClient::new`
    /// and the supervised connect loop.
    ///
    /// # Panics
    ///
    /// Must be called from within a Tokio runtime context (it spawns the run
    /// and monitor tasks); like `tokio::spawn`, it panics otherwise. Callers
    /// on threads without an ambient runtime must enter one first (e.g.
    /// `Handle::enter`).
    pub fn spawn(config: HubConfig) -> Result<Self> {
        let server = HubServer::new(config)?;
        let shutdown_token = CancellationToken::new();
        let (state_tx, state_rx) = watch::channel(HubLifecycle::Starting);
        let (result_tx, result_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();

        let run_token = shutdown_token.clone();
        let mut task: JoinHandle<Result<()>> =
            tokio::spawn(async move { server.run_until_signalled(run_token, ready_tx).await });

        // Monitor: drives the state watch and delivers the final result.
        // Owns the run task's JoinHandle; `shutdown_graceful` gets the
        // outcome through `result` instead of racing for the join.
        let monitor_token = shutdown_token.clone();
        tokio::spawn(async move {
            // Phase 1 — readiness: the run future fires `ready` once the
            // listeners are up, or ends first (bind failure drops the
            // ready sender before firing it).
            let ready = tokio::select! {
                ready = ready_rx => ready.is_ok(),
                joined = &mut task => {
                    let (lifecycle, result) = join_outcome(joined);
                    let _ = state_tx.send(lifecycle);
                    let _ = result_tx.send(result);
                    return;
                }
            };
            if !ready {
                // ready_rx resolved Err without the task ending: the server
                // dropped the sender without firing — treat as failure.
                let (lifecycle, result) = join_outcome(task.await);
                let _ = state_tx.send(lifecycle);
                let _ = result_tx.send(result);
                return;
            }
            let _ = state_tx.send(HubLifecycle::Running);

            // Phase 2 — run to completion: external shutdown (user) or a
            // self-failure (crash). Which one wins only decides whether the
            // intermediate `Stopping` is observable.
            let joined = tokio::select! {
                () = monitor_token.cancelled() => {
                    let _ = state_tx.send(HubLifecycle::Stopping);
                    task.await
                }
                joined = &mut task => joined,
            };
            let (lifecycle, result) = join_outcome(joined);
            let _ = state_tx.send(lifecycle);
            let _ = result_tx.send(result);
        });

        Ok(Self {
            state: state_rx,
            shutdown_token,
            result: result_rx,
        })
    }

    /// Current lifecycle snapshot.
    pub fn state(&self) -> HubLifecycle {
        self.state.borrow().clone()
    }

    /// Subscribes to lifecycle changes (fresh receivers start at the current
    /// value; `changed()` waits for the next transition).
    pub fn subscribe_state(&self) -> watch::Receiver<HubLifecycle> {
        self.state.clone()
    }

    /// True once the hub has reached a terminal lifecycle (`Stopped` /
    /// `Failed`) — the embedder's signal that a restart decision is due.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.state(),
            HubLifecycle::Stopped | HubLifecycle::Failed { .. }
        )
    }

    /// Requests shutdown and resolves after the drain completes, with the
    /// run outcome. Cancel/await are idempotent; calling it on an
    /// already-dead hub resolves immediately with its failure.
    pub async fn shutdown_graceful(self) -> Result<()> {
        self.shutdown_token.cancel();
        match self.result.await {
            Ok(result) => result,
            // The monitor task itself died (a bug — it has no fallible path
            // of its own); the run task's fate is then unknowable here.
            Err(_) => Err(InterflowError::connection(
                "hub monitor ended without delivering a result",
            )),
        }
    }
}

// Lifecycle tests live in `tests/hub_handle.rs`: exercising `spawn` needs a
// full hub config from the test kit, and mesh's unit-test target builds
// testkit against a second mesh instance (the supported dev-dependency
// cycle), so mesh types cannot cross that boundary in `#[cfg(test)]`.
