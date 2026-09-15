//! `/register` handling: identity binding + agent registration.

use crate::hub::service::{HubService, json_response, text_response};
use crate::hub::state::{AgentSession, HubResponseBody, SharedStreamCounts};
use crate::negotiation::{HeartbeatAd, RegisterResponse};
use hyper::{Response, StatusCode};
use interflow_core::error::Result;
use interflow_core::security::AuditKind;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, warn};

impl HubService {
    /// Handles a `/register` request.
    ///
    /// 1. Identity binding: if the connection is already bound to a different
    ///    agent_id, return 403; otherwise bind it.
    ///    (In mTLS mode connection_identity was preset to the client cert CN
    ///    at handshake time; here the x-agent-id header must equal the CN,
    ///    which prevents impersonation at the root.)
    /// 2. Create an mpsc data channel with capacity 256 (bounds the memory
    ///    peak under multi-stream concurrency for a single agent; when full,
    ///    hyper polling applies backpressure automatically, ultimately
    ///    triggering upstream TCP flow control).
    /// 3. Insert into the agent registry atomically under a single write lock.
    #[tracing::instrument(skip(self), fields(agent_id = %agent_id, peer = %self.peer_addr))]
    pub(crate) async fn handle_register(
        &self,
        agent_id: String,
    ) -> Result<Response<HubResponseBody>> {
        info!("Agent registered: {} from {}", agent_id, self.peer_addr);

        // Identity binding check
        {
            let mut identity = self.connection_identity.write().await;
            if let Some(existing_id) = &*identity {
                if existing_id != &agent_id {
                    warn!(
                        "identity mismatch: connection is bound to {}, but registration attempt is for {}",
                        existing_id, agent_id
                    );
                    metrics::counter!("interflow_hub_auth_failures", "reason" => "identity_mismatch").increment(1);
                    self.audit.record(
                        AuditKind::AgentRegisterDenied {
                            reason: format!(
                                "identity_mismatch: bound={existing_id}, claimed={agent_id}"
                            ),
                        },
                        Some(existing_id.clone()),
                        Some(self.peer_str()),
                    );
                    return Ok(text_response(StatusCode::FORBIDDEN, "Identity mismatch"));
                }
            } else {
                *identity = Some(agent_id.clone());
                debug!("Connection bound to identity: {}", agent_id);
            }
        }

        let (tx, rx) = mpsc::channel(256);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        let ctrl_backlog = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Single write lock: atomically insert or replace the channel in place.
        // Replacing in place (rather than overwriting the whole Arc) is
        // required: the old poll connection's RxStream holds the old Arc, and
        // Drop identifies a stale rx via the generation comparison — replacing
        // the whole Arc would make the comparison always hit the old Arc.
        let registered_count = {
            let mut agents = self.agents.write().await;
            if let Some(existing) = agents.get(&agent_id) {
                let mut state = existing.write().await;
                state.tx = tx;
                state.ctrl_tx = ctrl_tx;
                state.rx = Some(rx);
                state.ctrl_rx = Some(ctrl_rx);
                state.ctrl_backlog = ctrl_backlog;
                state.generation += 1;
                state.last_pong = Instant::now();
                // h2 re-registration overwrites the QUIC session (or vice
                // versa): the old relay connection closes itself out via its
                // connection-lost watcher
                state.quic = None;
                // Wake the old poll body: the generation has advanced, urging
                // it to end and yield to the new connection
                state.wake_poll();
                // The upload lease is invalidated together with the
                // generation: the old upload reader exits (its response body
                // ends, the agent side is taken over by the new session),
                // yielding to the new connection's upload
                if let Some(lease) = state.up_lease.take() {
                    lease.cancel();
                }
                agents.len()
            } else {
                let arc = Arc::new(RwLock::new(AgentSession {
                    tx,
                    ctrl_tx,
                    ctrl_backlog,
                    rx: Some(rx),
                    ctrl_rx: Some(ctrl_rx),
                    generation: 0,
                    last_pong: Instant::now(),
                    poll_waker: Arc::new(std::sync::Mutex::new(None)),
                    up_lease: None,
                    quic: None,
                }));
                agents.insert(agent_id.clone(), arc);
                agents.len()
            }
        };
        // Absolute value rather than increment: re-registration no longer
        // accumulates drift
        metrics::gauge!("interflow_hub_agents_registered")
            .set(crate::hub::state::count_as_f64(registered_count));

        // Clean up orphan streams left over from the agent's previous
        // connection and reset its counters to prevent drift.
        // Scenario: the agent disconnected abnormally without sending Close,
        // leaving old streams in active_streams; without cleanup on reconnect,
        // the per-agent count stays occupied forever and new streams are
        // rejected.
        Self::sweep_agent_streams(
            &self.agents,
            &self.active_streams,
            &self.stream_counts,
            &agent_id,
        )
        .await;

        self.audit.record(
            AuditKind::AgentRegistered {
                agent_id: agent_id.clone(),
            },
            Some(agent_id),
            Some(self.peer_str()),
        );

        // Capability negotiation: the response body carries the hub's
        // heartbeat cadence and upload Pong capability (old agents ignore the
        // body and only look at the status; new agents parse it and enable
        // the data-plane Pong + poll watchdog derivation, see
        // crate::negotiation).
        let caps = {
            let cfg = self.config.read().await;
            RegisterResponse {
                pong_via_upload: true,
                heartbeat: cfg.heartbeat.enabled.then_some(HeartbeatAd {
                    interval_secs: cfg.heartbeat.interval_secs,
                    max_missed: cfg.heartbeat.max_missed,
                }),
            }
        };
        // Serializing a plain scalar struct cannot fail; if it somehow does,
        // degrade to a minimal capability declaration
        let body = serde_json::to_string(&caps)
            .unwrap_or_else(|_| "{\"pong_via_upload\":true}".to_string());
        Ok(json_response(StatusCode::OK, body))
    }

    /// Implicit re-registration: when an agent that was evicted (poll grace /
    /// heartbeat loss / send timeout) still holds a healthy connection, its
    /// next `/poll` or `/stream/up` restores registration right here, without
    /// waiting for a disconnect to trigger reconnect and re-registration
    /// (edge processes never re-register and rely on this self-healing path
    /// in particular).
    ///
    /// The identity binding check must be completed before calling; the
    /// authentication level is equivalent to `/register`.
    pub(crate) async fn implicit_re_register(&self, agent_id: &str) -> Arc<RwLock<AgentSession>> {
        info!(
            "Agent {} not registered, implicitly re-registering",
            agent_id
        );
        let (tx, rx) = mpsc::channel(256);
        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
        let arc = Arc::new(RwLock::new(AgentSession {
            tx,
            ctrl_tx,
            ctrl_backlog: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            rx: Some(rx),
            ctrl_rx: Some(ctrl_rx),
            generation: 0,
            last_pong: Instant::now(),
            poll_waker: Arc::new(std::sync::Mutex::new(None)),
            up_lease: None,
            quic: None,
        }));
        {
            let mut agents = self.agents.write().await;
            agents.insert(agent_id.to_string(), arc.clone());
            metrics::gauge!("interflow_hub_agents_registered")
                .set(crate::hub::state::count_as_f64(agents.len()));
        }
        Self::sweep_agent_streams(
            &self.agents,
            &self.active_streams,
            &self.stream_counts,
            agent_id,
        )
        .await;
        self.audit.record(
            AuditKind::AgentRegistered {
                agent_id: agent_id.to_string(),
            },
            Some(agent_id.to_string()),
            Some(self.peer_str()),
        );
        // Heartbeats are served by the global supervision loop (see
        // hub/heartbeat.rs); re-registration needs no spawn
        arc
    }
}

impl HubService {
    /// Cleans up all orphan streams where `agent` is the source or target,
    /// resets its per-agent counter, and **produces a termination signal on
    /// the peer's dispatch plane**.
    ///
    /// Called on `/register` (h2 and QUIC) and by the eviction primitive
    /// (`evict_agent`): an agent reconnecting/being evicted means its previous
    /// connection is gone, so old streams are invalid even without receiving
    /// a Close. Not cleaning up leaks `active_streams` and drifts
    /// `stream_counts`; afterwards `max_streams_per_agent` stays occupied
    /// forever by old streams.
    ///
    /// The termination signal is dispatched by the peer's dispatch plane
    /// (2026-09-14 in-session root fix for orphan streams, see `hub::control`):
    /// - **poll plane** (h2 peer): the control channel guarantees delivery of
    ///   `_close_` (reason = `agent-evicted`) — otherwise the peer's
    ///   forwarder waits forever for a Close and the backend fd lingers for
    ///   the whole session (the EMFILE recurrence path);
    /// - **relay plane** (QUIC peer): removing the table entry itself drops
    ///   the relay senders, and the write task writes the outstanding
    ///   Close+FIN — no explicit notification needed.
    pub(crate) async fn sweep_agent_streams(
        agents: &crate::hub::state::SharedAgents,
        active_streams: &Arc<RwLock<HashMap<String, crate::hub::ActiveStream>>>,
        stream_counts: &SharedStreamCounts,
        agent_id: &str,
    ) {
        let mut removed_as_source = 0usize;
        let mut removed_total = 0usize;
        // Poll-plane peers needing explicit notification (the relay plane is
        // informed by the table-entry drop)
        let mut poll_peers: Vec<(String, String)> = Vec::new();
        {
            let mut streams = active_streams.write().await;
            streams.retain(|sid, s| {
                if s.source_agent == agent_id {
                    removed_as_source += 1;
                    removed_total += 1;
                    // The evicted party is the source: notify the target end.
                    // For a loopback stream (source == target) the peer is the
                    // evicted agent itself; no notification needed.
                    if !s.target.is_relay() && s.target_agent != agent_id {
                        poll_peers.push((s.target_agent.clone(), sid.clone()));
                    }
                    false
                } else if s.target_agent == agent_id {
                    // Being cleaned up as the target does not count toward
                    // the source count, but the gauge must be decremented
                    // accordingly
                    removed_total += 1;
                    if !s.source.is_relay() && s.source_agent != agent_id {
                        poll_peers.push((s.source_agent.clone(), sid.clone()));
                    }
                    false
                } else {
                    true
                }
            });
            if removed_total > 0 {
                metrics::gauge!("interflow_hub_streams_active")
                    .decrement(u32::try_from(removed_total).unwrap_or(u32::MAX));
                warn!(
                    "agent {agent_id} offline/reconnected: cleaned up {} orphan streams ({} of them needed poll-side peer notification)",
                    removed_total,
                    poll_peers.len()
                );
            }
        }
        // Reset the source count (only slots counted as source_agent)
        {
            let mut map = stream_counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if removed_as_source > 0 {
                map.remove(agent_id);
            }
        }
        // Guaranteed delivery outside the locks (eviction is a failure path;
        // termination takes priority over any tail data still queued)
        for (peer, sid) in poll_peers {
            if crate::hub::control::deliver_close_via_control(agents, &peer, &sid, "agent-evicted")
                .await
            {
                metrics::counter!("interflow_hub_sweep_peer_notified_total").increment(1);
            }
        }
    }
}
