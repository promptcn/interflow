//! The agent engine's CRL-poll liveness reporter — the node-side half of
//! the fleet's "is the renewal loop alive" face
//!
//! One loop, one job: ship the renewal scheduler's
//! [`CrlPollFace`](interflow_renewal::CrlPollFace) level to the hub
//! (`POST /crls/liveness` on h2, the CrlLiveness frame pair on QUIC).
//! The report is the LEVEL, not a heartbeat: the face is read fresh at
//! send time, so a hung poll loop keeps producing reports whose
//! confirmation instant stays frozen — the hub-side recency sweeper is
//! the structural path that classifies exactly that freeze. This is why
//! the reporter deliberately shares nothing but the atomics with the
//! scheduler: its own health only affects sampling, never the level.
//!
//! Spawned only when the assembly handed the client a face — i.e. when
//! this node actually runs a CRL-polling renewal loop beside the engine
//! (the pack paths, the CLI agent, the GUI). An offline-identity node
//! never gets one (nothing polls, so nothing reports — a silent reading
//! must mean a hung poller, never "offline by design").
//!
//! Observability contract: a failing report channel warns once per
//! distinct reason and resets on recovery (the policy watcher's
//! 2026-10-07 lesson); the steady state stays quiet — a dropped sample
//! costs nothing, the level re-arrives next tick.

use std::sync::Arc;

use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::transport::CrlLivenessReport;
use interflow_renewal::CrlPollFace;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use super::handle::AgentState;

/// The report cadence: two samples per CRL poll
/// ([`CRL_POLL`](interflow_renewal::CRL_POLL) = 60s) bounds sample loss
/// well inside the silent threshold, at a rate no hub will notice.
const CRL_LIVENESS_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Converts the renewal crate's snapshot into the wire shape (field-for-
/// field identical; two types only so core's serde stays crate-local).
pub(crate) fn wire_report(face: &CrlPollFace) -> CrlLivenessReport {
    let snap = face.snapshot();
    CrlLivenessReport {
        last_success_unix: snap.last_success_unix,
        failures_total: snap.failures_total,
        renewal_backoff_failures: Some(snap.backoff_failures),
    }
}

/// Spawns the reporter on the agent's task tree. `tunnel` is the session
/// slot facade — an empty slot (mid-rebuild) surfaces as the usual
/// connection error and retries on the next tick.
pub(crate) fn spawn(
    log_name: String,
    tunnel: AgentTunnel,
    mut state_rx: tokio::sync::watch::Receiver<AgentState>,
    face: Arc<CrlPollFace>,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
) {
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        run(log_name, tunnel, &mut state_rx, face, shutdown).await;
    });
}

async fn run(
    log_name: String,
    tunnel: AgentTunnel,
    state_rx: &mut tokio::sync::watch::Receiver<AgentState>,
    face: Arc<CrlPollFace>,
    shutdown: CancellationToken,
) {
    info!(
        node = %log_name,
        interval_secs = CRL_LIVENESS_REPORT_INTERVAL.as_secs(),
        "CRL-liveness reporter armed (ships the renewal loop's poll level)"
    );

    // An already-connected session reports immediately; later sessions
    // trigger on the Connected transition itself.
    let mut session_event = matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. });
    let mut next_tick = tokio::time::Instant::now() + CRL_LIVENESS_REPORT_INTERVAL;
    // Warn-once bookkeeping (the distinct-reason discipline).
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
                    session_event =
                        matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. });
                    continue;
                }
            }
        }
        next_tick = tokio::time::Instant::now() + CRL_LIVENESS_REPORT_INTERVAL;

        if let Err(e) = tunnel.report_crl_liveness(&wire_report(&face)).await {
            metrics::counter!("interflow_agent_crl_liveness_report_failures_total").increment(1);
            let reason = e.to_string();
            if warned_error.as_deref() != Some(reason.as_str()) {
                warn!(
                    node = %log_name,
                    error = %reason,
                    "CRL-liveness report failed (the level re-arrives next tick)"
                );
                warned_error = Some(reason);
            }
            continue;
        }
        if warned_error.is_some() {
            info!(node = %log_name, "CRL-liveness report recovered");
            warned_error = None;
        }
    }
}
