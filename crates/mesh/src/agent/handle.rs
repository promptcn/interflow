//! Agent runtime handle: a structured lifecycle API.
//!
//! Design goals (single source of truth):
//! - agent state (connecting/connected/reconnecting/stopped/failed) is
//!   expressed by [`AgentState`], broadcast via `watch`; consumers (CLI log
//!   derivation / GUI status bar) each subscribe on their own;
//! - fine-grained process events flow through the [`AgentEvent`] mpsc
//!   channel;
//! - shutdown is cooperative: `shutdown_graceful()` cancels the token then
//!   waits for all child tasks inside the `TaskTracker` to exit cleanly
//!   (TLS/TCP normal close), without aborting.

use interflow_core::error::Result;
use interflow_core::tunnel::{AgentTunnel, SessionSlot};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Agent lifecycle state (broadcast via watch; each change overwrites the
/// old value).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum AgentState {
    /// Establishing the connection to the hub (first or retry attempt).
    Connecting,
    /// Connected and registered successfully.
    Connected { agent_id: String },
    /// Session ended; waiting for the backoff before reconnecting.
    Reconnecting {
        reason: String,
        /// Backoff duration until the next attempt (seconds).
        backoff_secs: u64,
    },
    /// User-initiated graceful shutdown completed.
    Stopped,
    /// Unrecoverable error (e.g. a configuration error); the agent will not
    /// retry.
    Failed { error: String },
}

/// Fine-grained lifecycle events (mpsc stream, with transition details).
#[derive(Clone, Debug, Serialize)]
pub enum AgentEvent {
    /// State-machine transition.
    StateChanged(AgentState),
    /// A session was established (connect + register succeeded).
    SessionEstablished { agent_id: String },
    /// A session ended (disconnect / error / deliberate close).
    SessionEnded { reason: String },
}

/// Agent runtime handle: `AgentClient::start()` returns it immediately
/// without blocking the caller.
pub struct AgentHandle {
    state_rx: watch::Receiver<AgentState>,
    events_rx: Option<mpsc::Receiver<AgentEvent>>,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    slot: SessionSlot,
    join: JoinHandle<Result<()>>,
    established: Arc<AtomicU64>,
    ingress_ready: watch::Receiver<bool>,
}

/// Context used inside the supervisor to emit state/events.
#[derive(Clone)]
pub(crate) struct EventSink {
    pub(crate) state_tx: watch::Sender<AgentState>,
    pub(crate) event_tx: mpsc::Sender<AgentEvent>,
    /// Monotonic session-establishment count, mirrored to the handle.
    pub(crate) established: Arc<AtomicU64>,
}

impl EventSink {
    pub(crate) fn set_state(&self, state: AgentState) {
        if matches!(state, AgentState::Connected { .. }) {
            self.established.fetch_add(1, Ordering::Relaxed);
        }
        // watch's send only errors when every receiver is gone; a GUI/CLI
        // going away must not affect the agent itself.
        let _ = self.state_tx.send(state.clone());
        let _ = self.event_tx.try_send(AgentEvent::StateChanged(state));
    }

    pub(crate) fn emit(&self, event: AgentEvent) {
        let _ = self.event_tx.try_send(event);
    }
}

impl AgentHandle {
    pub(crate) const fn new(
        state_rx: watch::Receiver<AgentState>,
        events_rx: mpsc::Receiver<AgentEvent>,
        shutdown: CancellationToken,
        tracker: TaskTracker,
        slot: SessionSlot,
        join: JoinHandle<Result<()>>,
        established: Arc<AtomicU64>,
        ingress_ready: watch::Receiver<bool>,
    ) -> Self {
        Self {
            state_rx,
            events_rx: Some(events_rx),
            shutdown,
            tracker,
            slot,
            join,
            established,
            ingress_ready,
        }
    }

    /// Monotonic count of established sessions — one per completed connect
    /// (the initial session plus every supervisor rebuild).
    ///
    /// Observers that must not miss a rebuild read this instead of watching
    /// state transitions: a watch channel keeps only the latest value, so a
    /// fast Connected → Reconnecting → Connected cycle can be invisible to a
    /// state watcher that was not scheduled between the two transitions.
    /// The counter cannot miss it.
    pub fn sessions_established(&self) -> u64 {
        self.established.load(Ordering::Relaxed)
    }

    /// The embedder-facing tunnel: rides across session rebuilds.
    ///
    /// The returned [`AgentTunnel`] is backed by the session slot — the
    /// supervisor installs each freshly established session's transport into
    /// it and withdraws it during session wind-down. Embedders (expose edge
    /// etc.) hold this for their whole lifetime: sends during a reconnect gap
    /// fail fast instead of hanging, and the facade is live again as soon as
    /// the next session registers.
    pub fn tunnel(&self) -> AgentTunnel {
        self.slot.tunnel()
    }

    /// Snapshot of the current state.
    pub fn state(&self) -> AgentState {
        self.state_rx.borrow().clone()
    }

    /// Subscribe to state changes (multiple consumers can each clone).
    pub fn subscribe_state(&self) -> watch::Receiver<AgentState> {
        self.state_rx.clone()
    }

    /// Resolves once every configured ingress listener has been bound by a
    /// session (the agent's local-serving face), or `false` when the
    /// supervisor ended first (fatal error / shutdown) without ever getting
    /// there.
    ///
    /// This is the agent-side readiness signal: hub connectivity is
    /// supervised reconnect by design and never gates readiness — only the
    /// local listener surface does, the same condition `node install`'s
    /// now-removed TCP probes waited on. An agent with no ingress rules
    /// signals ready at its first session too (the watch starts `false` and
    /// the handler's empty snapshot trivially binds).
    pub async fn wait_ingress_ready(&self) -> bool {
        let mut rx = self.ingress_ready.clone();
        if *rx.borrow() {
            return true;
        }
        // `changed` errors when every sender is gone (the supervisor task
        // and its client clones dropped) — readiness can no longer turn on.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return true;
            }
        }
        false
    }

    /// Whether the supervisor task has ended (for any reason).
    ///
    /// The embedder dead-supervisor contract: the state watch stream ending
    /// (`changed()` erroring) means the supervisor is gone; the final
    /// state tells which case it was —
    /// - `Stopped` / `Failed { .. }`: a legitimate end (user shutdown /
    ///   fatal config); no recovery action.
    /// - anything else (typically frozen at `Connecting`/`Reconnecting`):
    ///   the supervisor died unexpectedly — the embedder owns recovery
    ///   (GUI: bounded auto-restart per [`SupervisorRestartPolicy`];
    ///   edge: process exit for systemd).
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }

    /// Event-stream receiving end (single consumer: the CLI event pump /
    /// GUI event pump).
    ///
    /// Returns an immediately closed empty stream once already taken
    /// (idempotent).
    pub fn take_events(&mut self) -> mpsc::Receiver<AgentEvent> {
        self.events_rx
            .take()
            .unwrap_or_else(|| mpsc::channel::<AgentEvent>(1).1)
    }

    /// Cooperative graceful shutdown: cancel -> wait for all child tasks in
    /// the tracker to exit -> wait for the supervisor to close out.
    ///
    /// Idempotent: safe to call multiple times. Consumes self; the handle
    /// is unusable afterwards.
    pub async fn shutdown_graceful(mut self) -> Result<()> {
        self.shutdown.cancel();
        self.tracker.close();
        self.tracker.wait().await;
        let res = (&mut self.join).await;
        match res {
            Ok(r) => r,
            // After the supervisor is cancelled, join returning Cancelled is
            // the normal path.
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) => Err(interflow_core::error::InterflowError::JoinError(e)),
        }
    }

    /// Wait for the supervisor to end naturally (without triggering
    /// shutdown) — for the CLI foreground-run semantics.
    pub async fn join(mut self) -> Result<()> {
        (&mut self.join)
            .await
            .map_err(interflow_core::error::InterflowError::JoinError)?
    }
}

/// Exponential backoff + full jitter, capped at [`BACKOFF_CAP`] (30s,
/// single-sourced in core params — the hub's `poll_grace_secs` validation
/// and the edge recovery budget are derived against the same constant).
/// After the n-th consecutive failure, sleep `rand(1..=min(2^n, 30))`
/// seconds.
///
/// "Consecutive" is maintained by the supervisor: `attempt` resets to 1
/// whenever a session was established before ending, and only grows while
/// connection attempts keep failing outright (see `AgentClient::supervise`).
pub(crate) fn backoff_duration(attempt: u32) -> Duration {
    use interflow_core::config::params::liveness::{BACKOFF_CAP, BACKOFF_FLOOR};
    use rand::Rng;

    let cap_secs = BACKOFF_CAP.as_secs();
    let exp = attempt.min(6); // 2^6 = 64 > 30; anything larger is capped anyway
    let max = cap_secs.min(1_u64 << exp).max(BACKOFF_FLOOR.as_secs());
    // Full jitter from the thread-local RNG: a uniform sample over
    // [floor, max] seconds with no modulo bias.
    let secs = rand::rng().random_range(BACKOFF_FLOOR.as_secs()..=max);
    Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape contract of the backoff distribution: for every attempt count,
    /// every sample lies in `[1s, min(2^attempt, 30s)]` — never zero, never
    /// above the cap. (The jitter source is `rand`'s thread-local RNG, so the
    /// bound is checked statistically over many samples.)
    #[test]
    fn backoff_duration_stays_within_exponential_cap() {
        for attempt in 1_u32..=12 {
            let cap = Duration::from_secs(30_u64.min(1_u64 << attempt.min(6)));
            let floor = Duration::from_secs(1);
            for _ in 0..200 {
                let d = backoff_duration(attempt);
                assert!(
                    d >= floor && d <= cap,
                    "backoff out of range for attempt {attempt}: {d:?} not in [{floor:?}, {cap:?}]"
                );
            }
        }
    }

    /// attempt = 0 degenerates to the 1s floor (max = 1 → rand mapped to 1);
    /// the supervisor never calls it this way, but the bound must hold.
    #[test]
    fn backoff_duration_floor_at_zero_attempts() {
        for _ in 0..50 {
            assert_eq!(backoff_duration(0), Duration::from_secs(1));
        }
    }
}
