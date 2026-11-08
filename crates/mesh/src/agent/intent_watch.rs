//! The agent engine's intrinsic stream-intent watcher — the node-side
//! half of stream pause/resume
//!
//! One loop, one job: keep the node's pause-intent truth converged with
//! the hub. Each pass reports the [`PausedStreams`] snapshot upstream
//! (`POST /streams/intent` on h2, the StreamIntent frame pair on QUIC —
//! the same control-plane carriage the policy pull rides) and applies
//! whatever pause/resume ops the operator queued for THIS agent. The
//! exchange is bidirectional by design: the agent's report IS the ack
//! (the hub clears an op the moment the reported set reflects it — set
//! membership instead of sequence numbers), and it IS the hub-side
//! observability face's source of truth (a hub restart repopulates its
//! face from the next report; the node's persisted set is the truth the
//! face re-derives from).
//!
//! Cadence mirrors the policy watcher's discipline: every
//! [`POLICY_WATCH_INTERVAL`](crate::agent::policy_watch::POLICY_WATCH_INTERVAL)
//! plus an immediate pass on session establishment. Ops are idempotent
//! set add/remove, so a re-delivered op after a restart is harmless and
//! no ack state needs persisting. Not gated on the policy plane — like
//! the peer plane, this is an engine-intrinsic capability every mesh
//! agent gets, so no embedding surface can forget to spawn it.
//!
//! Observability contract: a failing exchange channel warns once per
//! distinct reason and resets on recovery (the policy watcher's
//! 2026-10-07 lesson — a permanently-dead pull channel must not be
//! silent); the steady state stays at debug.

use std::sync::Arc;

use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::transport::{StreamIntentOp, StreamIntentReport};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::handle::AgentState;
use super::paused_streams::PausedStreams;
use crate::agent::policy_watch::POLICY_WATCH_INTERVAL;

/// Spawns the watcher on the agent's task tree. `tunnel` is the session
/// slot facade — an empty slot (mid-rebuild) surfaces as the usual
/// connection error and retries on the next tick.
pub(crate) fn spawn(
    log_name: String,
    tunnel: AgentTunnel,
    mut state_rx: tokio::sync::watch::Receiver<AgentState>,
    paused: Arc<PausedStreams>,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
) {
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        run(log_name, tunnel, &mut state_rx, paused, shutdown).await;
    });
}

async fn run(
    log_name: String,
    tunnel: AgentTunnel,
    state_rx: &mut tokio::sync::watch::Receiver<AgentState>,
    paused: Arc<PausedStreams>,
    shutdown: CancellationToken,
) {
    info!(
        node = %log_name,
        build = interflow_buildinfo::BUILD_TAG,
        interval_secs = POLICY_WATCH_INTERVAL.as_secs(),
        "stream-intent watcher armed (reports the pause set, applies operator ops)"
    );

    // An already-connected session exchanges immediately; later sessions
    // trigger on the Connected transition itself.
    let mut session_event = matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. });
    let mut next_tick = tokio::time::Instant::now() + POLICY_WATCH_INTERVAL;
    // Warn-once bookkeeping (the policy watcher's distinct-reason
    // discipline): a dead channel is news once, recovery re-arms it.
    let mut warned_error: Option<String> = None;

    loop {
        let due_now = session_event;
        session_event = false;
        if !due_now {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep_until(next_tick) => {}
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        return; // handle dropped — ride out with the agent
                    }
                    // borrow_and_update (not borrow): the change must be
                    // marked seen, else `changed()` re-fires on the same
                    // transition forever.
                    session_event =
                        matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. });
                    continue;
                }
            }
        }
        next_tick = tokio::time::Instant::now() + POLICY_WATCH_INTERVAL;

        // One convergence pass: exchange, apply, and — when ops were
        // applied — exchange once more so the hub sees the reflected set
        // immediately (the CLI's bounded face wait converges in one
        // round trip, not one interval).
        loop {
            let report = StreamIntentReport {
                paused: paused.snapshot(),
            };
            let ops = match tunnel.exchange_stream_intents(&report).await {
                Ok(ops) => ops,
                Err(e) => {
                    let reason = e.to_string();
                    if warned_error.as_deref() != Some(reason.as_str()) {
                        warn!(
                            node = %log_name,
                            error = %reason,
                            "stream-intent exchange failed (operator pause/resume ops will apply when the channel recovers)"
                        );
                        warned_error = Some(reason);
                    }
                    break;
                }
            };
            if warned_error.is_some() {
                info!(node = %log_name, "stream-intent exchange recovered");
                warned_error = None;
            }
            if ops.ops.is_empty() {
                debug!(node = %log_name, "stream-intent exchange clean (no pending ops)");
                break;
            }
            for op in ops.ops {
                match op {
                    StreamIntentOp::Pause { name } => {
                        info!(target: "audit", node = %log_name, stream = %name, "operator pause op applied");
                        paused.pause(&name);
                    }
                    StreamIntentOp::Resume { name } => {
                        info!(target: "audit", node = %log_name, stream = %name, "operator resume op applied");
                        paused.resume(&name);
                    }
                }
            }
        }
    }
}
