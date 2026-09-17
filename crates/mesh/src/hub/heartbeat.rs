//! Agent lifecycle management: unified eviction primitive, global heartbeat
//! supervision loop.
//!
//! Background (2026-09-11 permanent 502 incident + 2026-09-13 7.5-hour
//! data-plane stall): the old implementation spawned a stray heartbeat task
//! per agent (ownerless JoinHandle, zero logs on the happy path); once such a
//! task vanished nobody knew — `last_pong` stayed frozen at registration time
//! with nobody declaring death, and the hub fell silent for 7.5 hours
//! (docs/bug/2026-09-13, mechanism B). Now replaced with a **single global
//! supervision loop** hosted by the task group of
//! [`crate::hub::server::HubServer`], with an outer self-healing wrapper
//! guaranteeing that its death is always logged, counted, and restarted.
//!
//! Data-plane semantics of the heartbeat (root fix, 2026-09-13): Ping is
//! dispatched via `/poll` (the hub→agent data plane), and Pong travels back
//! as an uplink frame on `/stream/up` (the agent→hub data plane, see the
//! Pong branch in [`crate::hub::upload`]) — one heartbeat cycle proves both
//! data paths; a stall in either direction surfaces as loss-of-contact
//! eviction within `interval*(max_missed+1)`.
//!
//! This module remains the convergence point of the four death signals (data
//! send timeout / poll disconnect grace timeout / heartbeat loss / QUIC
//! disconnect); all of them complete cleanup through the single entry point
//! [`evict_agent`]:
//! 1. advance the generation + clear rx — residual poll streams end via the
//!    generation self-check; closing the channel unblocks every blocked
//!    `send().await` immediately;
//! 2. remove the entry from the registry (`Arc::ptr_eq` guards against
//!    deleting a new entry created by a re-registration in the meantime);
//! 3. sweep orphan streams + reset the per-agent count.
//!
//! An evicted agent's next `/poll` implicitly re-registers it (see
//! [`crate::hub::poll`]); the agent side self-heals with zero cooperation.

use crate::hub::service::HubService;
use crate::hub::state::{AgentSession, HubHandles, TunnelData};
use bytes::Bytes;
use interflow_core::protocol::FrameType;
use interflow_core::security::AuditKind;
use interflow_core::tunnel::FrameSource;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

// Poll interval while heartbeats are disabled and the summary-log period
// are single-sourced in core `config::params::liveness`
// (`HEARTBEAT_DISABLED_POLL` / `HEARTBEAT_SUMMARY_PERIOD`).
use interflow_core::config::params::liveness::{HEARTBEAT_DISABLED_POLL, HeartbeatCadence};

/// Restart delay after the supervision loop exits abnormally.
const HEARTBEAT_SUPERVISOR_RESTART_DELAY: Duration = Duration::from_secs(1);

/// Evicts an agent: the unified cleanup entry point for all death signals
/// (send timeout / poll grace timeout / heartbeat loss).
///
/// `expected` is the `AgentSession` Arc captured when the death signal was
/// observed; if the agent re-registered in the meantime (the entry replaced
/// by a new Arc), this eviction is voided and the new session is untouched.
pub(crate) async fn evict_agent(
    h: &HubHandles,
    agent_id: &str,
    expected: &Arc<tokio::sync::RwLock<AgentSession>>,
    reason: &'static str,
) {
    // 1. Sever the session entry (see [`AgentSession::terminate`]).
    expected.write().await.terminate();

    // 2. Remove the registry entry (only if it is still the same Arc, to
    //    avoid deleting a new entry from a re-registration).
    let removed = {
        let mut agents = h.agents.write().await;
        match agents.get(agent_id) {
            Some(cur) if Arc::ptr_eq(cur, expected) => {
                agents.remove(agent_id);
                metrics::gauge!("interflow_hub_agents_registered")
                    .set(crate::hub::state::count_as_f64(agents.len()));
                true
            }
            _ => false,
        }
    };
    if !removed {
        debug!(
            "agent {agent_id} eviction voided (entry already taken over by re-registration): reason={reason}"
        );
        return;
    }

    // 3. Sweep orphan streams + notify peers + reset the per-agent count
    //    (reuses the register sweep).
    HubService::sweep_agent_streams(&h.agents, &h.active_streams, &h.stream_counts, agent_id).await;

    metrics::counter!("interflow_hub_agent_evicted", "reason" => reason).increment(1);
    h.audit.record(
        AuditKind::AgentEvicted {
            agent_id: agent_id.to_string(),
            reason: reason.to_string(),
        },
        Some(agent_id.to_string()),
        None,
    );
    warn!("agent {agent_id} evicted (reason={reason}), orphan streams cleaned");
}

/// Managed entry point of the heartbeat supervision loop: when the loop body
/// exits abnormally (including a panic), log it, count it, and restart.
///
/// The single lifeline of the hub's only heartbeat task — without this layer,
/// defects of the "heartbeat task silently vanishes" kind (2026-09-13,
/// mechanism B) would have no structural point of exposure. Normal exit
/// happens only on shutdown.
pub fn spawn_heartbeat_supervisor(h: HubHandles, tasks: &TaskTracker, shutdown: CancellationToken) {
    tasks.spawn(async move {
        loop {
            let inner = tokio::spawn(run_heartbeat_supervisor(h.clone(), shutdown.clone()));
            match inner.await {
                // Normal return = shutdown fired (the supervision loop only
                // exits on shutdown)
                Ok(()) => break,
                Err(e) => {
                    metrics::counter!("interflow_hub_heartbeat_supervisor_restarts").increment(1);
                    error!(
                        "heartbeat supervisor loop exited abnormally ({e}), restarting after {HEARTBEAT_SUPERVISOR_RESTART_DELAY:?}"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(HEARTBEAT_SUPERVISOR_RESTART_DELAY) => {}
                    }
                }
            }
        }
    });
}

/// Global heartbeat loop: every tick iterates over all h2 agents, checks
/// liveness and dispatches Pings.
///
/// - Death is decided by `last_pong` (refresh points: registration / an
///   uplink Pong frame on `/stream/up`);
/// - QUIC sessions are skipped (control-stream Ping + quinn idle timeout
///   already cover them);
/// - Ping enqueue failure (poll channel full = direct evidence the poll
///   consumer has stalled) does not immediately declare death: once the
///   channel stays full for `max_missed` consecutive ticks, warn once
///   (episode style); the Pong outage itself ages out via `last_pong` and
///   goes through the normal eviction path.
async fn run_heartbeat_supervisor(h: HubHandles, shutdown: CancellationToken) {
    let mut tick: u64 = 0;
    // Per-agent consecutive-full counts (episode-style alerting; forgotten
    // once the agent disappears)
    let mut full_streaks: HashMap<String, u32> = HashMap::new();
    loop {
        // One config snapshot per tick: the interval decides the sleep and
        // the cadence decides the dead line — a torn read between two lock
        // acquisitions could pair values from different reloads.
        let cadence = {
            let cfg = h.config.read().await;
            cfg.heartbeat
                .enabled
                .then(|| HeartbeatCadence::from(&cfg.heartbeat))
        };
        let interval_secs = cadence.map_or(0, |c| c.interval_secs);
        let sleep_for = if interval_secs == 0 {
            HEARTBEAT_DISABLED_POLL
        } else {
            Duration::from_secs(interval_secs)
        };
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(sleep_for) => {}
        }
        let Some(cadence) = cadence else { continue };
        // The eviction dead line — the canonical derivation (single source
        // with the agent-side watchdog/stall derivations in core params).
        let deadline = cadence.dead_line();
        let summary_every = cadence.summary_ticks();
        tick += 1;

        // Process one by one after snapshotting: evict needs the registry
        // write lock, which cannot be held while holding the read lock
        let snapshot: Vec<(String, Arc<tokio::sync::RwLock<AgentSession>>)> = {
            let agents = h.agents.read().await;
            agents
                .iter()
                .map(|(id, st)| (id.clone(), st.clone()))
                .collect()
        };
        let mut pings = 0u64;
        let mut full = 0u64;
        let mut evicted = 0u64;
        for (agent_id, state) in &snapshot {
            let (alive, tx, is_quic) = {
                let st = state.read().await;
                (
                    st.last_pong.elapsed() <= deadline,
                    st.tx.clone(),
                    st.quic.is_some(),
                )
            };
            if is_quic {
                continue;
            }
            if !alive {
                warn!("agent {agent_id} heartbeat lost (no Pong for >{deadline:?}), evicting");
                full_streaks.remove(agent_id);
                evict_agent(&h, agent_id, state, "heartbeat_missed").await;
                evicted += 1;
                continue;
            }
            let ping = TunnelData {
                stream_id: String::new(),
                source: FrameSource::Ping,
                stream_type: FrameType::Ping,
                flags: 0,
                data: Bytes::new(),
            };
            match tx.try_send(ping) {
                Ok(()) => {
                    pings += 1;
                    metrics::counter!("interflow_hub_heartbeat_pings_sent").increment(1);
                    full_streaks.remove(agent_id);
                    debug!("agent {agent_id} heartbeat Ping enqueued");
                }
                Err(e) => {
                    full += 1;
                    metrics::counter!("interflow_hub_heartbeat_ping_enqueue_full").increment(1);
                    let streak = full_streaks.entry(agent_id.clone()).or_insert(0);
                    *streak += 1;
                    // Warn once when first reaching max_missed; sustained
                    // fullness is closed out by last_pong aging
                    if *streak == cadence.max_missed.max(1) {
                        warn!(
                            "agent {agent_id} heartbeat Ping failed to enqueue {streak} times in a row\
                             (poll channel full, consumer most likely stalled)"
                        );
                    }
                    debug!("agent {agent_id} heartbeat Ping enqueue failed: {e}");
                }
            }
        }
        if !full_streaks.is_empty() {
            full_streaks.retain(|id, _| snapshot.iter().any(|(sid, _)| sid == id));
        }
        if tick.is_multiple_of(u64::from(summary_every)) {
            info!(
                "heartbeat supervisor: agents={} ping={pings} full={full} evicted={evicted} (tick #{tick})",
                snapshot.len()
            );
        }
    }
}
