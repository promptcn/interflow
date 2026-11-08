//! The agent engine's node-status reporter — the node-side half of the
//! fossil-stream face's carriage
//!
//! One loop, one job: ship the engine's own levels (per-stream byte
//! activity today; the connection-quality window stats ride this report
//! later) to the hub (`POST /node/status` on h2, the NodeStatus frame
//! pair on QUIC). The report is the LEVEL, not a heartbeat (the
//! CRL-liveness doctrine): the levels are read fresh at send time from
//! the engine's shared [`StreamActivity`] ledger, so a wedged engine's
//! reporter keeps shipping frozen `last_byte_unix` instants — which is
//! exactly the silence the consumers' recency judgments classify. This
//! is why the reporter deliberately shares nothing but the atomics with
//! the pumps: its own health only affects sampling, never the level.
//!
//! Engine-intrinsic like the intent watcher: every mesh agent reports,
//! no embedder wiring exists to forget. An offline-identity node is no
//! exception — this face is about the ENGINE, not the renewal loop.
//!
//! Observability contract: a failing report channel warns once per
//! distinct reason and resets on recovery (the policy watcher's
//! 2026-10-07 lesson); the steady state stays quiet — a dropped sample
//! costs nothing, the levels re-arrive next tick.

use std::sync::Arc;

use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::transport::NodeStatusReport;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use super::connection_quality::ConnectionRings;
use super::handle::AgentState;
use super::stream_activity::StreamActivity;

/// The report cadence: half the policy watch interval bounds sample loss
/// well inside any consumer's staleness window, at a rate no hub will
/// notice. A Connected transition re-arms the NEXT tick one interval out
/// — never inside the establishment burst (see `run`).
const NODE_STATUS_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawns the reporter on the agent's task tree. `tunnel` is the session
/// slot facade — an empty slot (mid-rebuild) surfaces as the usual
/// connection error and retries on the next tick.
pub(crate) fn spawn(
    log_name: String,
    tunnel: AgentTunnel,
    mut state_rx: tokio::sync::watch::Receiver<AgentState>,
    activity: Arc<StreamActivity>,
    connection: Arc<ConnectionRings>,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
) {
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        run(
            log_name,
            tunnel,
            &mut state_rx,
            activity,
            connection,
            shutdown,
        )
        .await;
    });
}

async fn run(
    log_name: String,
    tunnel: AgentTunnel,
    state_rx: &mut tokio::sync::watch::Receiver<AgentState>,
    activity: Arc<StreamActivity>,
    connection: Arc<ConnectionRings>,
    shutdown: CancellationToken,
) {
    info!(
        node = %log_name,
        interval_secs = NODE_STATUS_REPORT_INTERVAL.as_secs(),
        "node-status reporter armed (ships the engine's stream-activity levels)"
    );

    // A Connected transition re-anchors the NEXT tick one full interval
    // out — never inside the establishment burst. Establishment is a
    // request storm (register, intent exchange, peer list, the edge's
    // route leases) sharing the hub's per-client admission budget, and a
    // diagnostic-grade channel must not compete with load-bearing
    // traffic for it (the 2026-10-20 multi-workspace e2e lesson).
    let mut next_tick = tokio::time::Instant::now() + NODE_STATUS_REPORT_INTERVAL;
    // Warn-once bookkeeping (the distinct-reason discipline).
    let mut warned_error: Option<String> = None;

    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep_until(next_tick) => {}
            changed = state_rx.changed() => {
                if changed.is_err() {
                    return; // handle dropped — ride out with the agent
                }
                if matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. }) {
                    next_tick = tokio::time::Instant::now() + NODE_STATUS_REPORT_INTERVAL;
                }
                continue;
            }
        }
        next_tick = tokio::time::Instant::now() + NODE_STATUS_REPORT_INTERVAL;

        let now = u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0);
        let quality = connection.snapshot(now);
        let report = NodeStatusReport {
            connection: Some(interflow_core::tunnel::transport::ConnectionQualityWire {
                reconnects_last_hour: quality.reconnects_last_hour,
                rtt_p50_ms: quality.rtt_p50_ms,
                rtt_p99_ms: quality.rtt_p99_ms,
                rtt_timeouts: quality.rtt_timeouts,
                rtt_samples: quality.rtt_samples,
            }),
            streams: activity.snapshot(),
        };
        if let Err(e) = tunnel.report_node_status(&report).await {
            metrics::counter!("interflow_agent_node_status_report_failures_total").increment(1);
            let reason = e.to_string();
            if warned_error.as_deref() != Some(reason.as_str()) {
                warn!(
                    node = %log_name,
                    error = %reason,
                    "node-status report failed (the levels re-arrive next tick)"
                );
                warned_error = Some(reason);
            }
            continue;
        }
        if warned_error.is_some() {
            info!(node = %log_name, "node-status report recovered");
            warned_error = None;
        }
    }
}
